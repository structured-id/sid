// SPDX-License-Identifier: AGPL-3.0-only
//! Pluggable Cluster KEK source.
//!
//! Server reads Cluster KEK from this source on demand. Implementations:
//!   - `EnvVarKekSource` — for self-hosted installations (env var, always-in-memory).
//!   - `K8sSecretKekSource` — for SaaS multi-tenant (lazy fetch + TTL cache + audit).
//!   - `HsmKekSource` (future) — KMS/HSM Decrypt operations, KEK never in memory.
//!
//! The trait yields `SecretBox<[u8; 32]>` which zeroizes on drop. Callers must
//! not persist the unboxed value across the cache TTL window.

use std::env;

use async_trait::async_trait;
use secrecy::SecretBox;

use crate::error::OrgCryptoError;

/// Source of Cluster KEK material.
///
/// Versioning supports KEK rotation: callers may need to fetch a specific past
/// version to unwrap a DEK whose `kek_version` is older than `current_version`.
#[async_trait]
pub trait KekSource: Send + Sync {
    /// Fetch the KEK for a given version (returns 32 bytes wrapped in SecretBox).
    async fn fetch_kek(&self, version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError>;

    /// Active version. Used for new wraps; old wraps need their stored version.
    async fn current_version(&self) -> Result<u32, OrgCryptoError>;

    /// Human-readable identifier for audit logs.
    fn kind(&self) -> &'static str;
}

/// KEK from environment variables — for self-hosted installations.
///
/// Reads:
///   - `SID_CLUSTER_KEK` (hex, 64 chars = 32 bytes)
///   - `SID_CLUSTER_KEK_VERSION` (u32, default 1)
///
/// Versioning: only the *current* version is held. KEK rotation requires
/// re-deploy with new env value; lazy migration of DEKs uses the current KEK
/// for both unwrap (passing version=1 returns same KEK) and re-wrap (next gen).
/// Multi-version unwrap is not supported by this source — operators must run
/// migration before retiring the old KEK file.
pub struct EnvVarKekSource {
    kek: [u8; 32],
    version: u32,
}

impl EnvVarKekSource {
    /// Read KEK from `SID_CLUSTER_KEK` and `SID_CLUSTER_KEK_VERSION` env vars.
    pub fn from_env() -> Result<Self, OrgCryptoError> {
        let hex_value = env::var("SID_CLUSTER_KEK")
            .map_err(|_| OrgCryptoError::KekUnavailable("SID_CLUSTER_KEK not set".into()))?;
        let bytes = hex::decode(hex_value.trim())?;
        if bytes.len() != 32 {
            return Err(OrgCryptoError::InvalidKekLength(bytes.len()));
        }
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&bytes);

        let version = env::var("SID_CLUSTER_KEK_VERSION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        Ok(Self { kek, version })
    }

    /// Construct directly (useful for tests / wired bootstrap).
    pub fn new(kek: [u8; 32], version: u32) -> Self {
        Self { kek, version }
    }
}

#[async_trait]
impl KekSource for EnvVarKekSource {
    async fn fetch_kek(&self, version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
        if version != self.version {
            return Err(OrgCryptoError::KekVersionMismatch {
                have: self.version,
                need: version,
            });
        }
        Ok(SecretBox::new(Box::new(self.kek)))
    }

    async fn current_version(&self) -> Result<u32, OrgCryptoError> {
        Ok(self.version)
    }

    fn kind(&self) -> &'static str {
        "env"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[tokio::test]
    async fn env_source_returns_kek() {
        let kek = [0xAB; 32];
        let src = EnvVarKekSource::new(kek, 7);
        assert_eq!(src.current_version().await.unwrap(), 7);
        let fetched = src.fetch_kek(7).await.unwrap();
        assert_eq!(fetched.expose_secret(), &kek);
        assert_eq!(src.kind(), "env");
    }

    #[tokio::test]
    async fn env_source_rejects_wrong_version() {
        let src = EnvVarKekSource::new([0u8; 32], 1);
        assert!(matches!(
            src.fetch_kek(2).await.unwrap_err(),
            OrgCryptoError::KekVersionMismatch { have: 1, need: 2 }
        ));
    }

    #[test]
    fn env_source_from_env_parses_hex() {
        // SAFETY: nextest runs each test in its own process and this test starts
        // no threads, so nothing reads the environment concurrently.
        unsafe {
            std::env::set_var(
                "SID_CLUSTER_KEK",
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            );
            std::env::set_var("SID_CLUSTER_KEK_VERSION", "3");
        }
        let src = EnvVarKekSource::from_env().unwrap();
        assert_eq!(src.version, 3);
        assert_eq!(src.kek[0], 0x01);
        assert_eq!(src.kek[31], 0x20);
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("SID_CLUSTER_KEK");
            std::env::remove_var("SID_CLUSTER_KEK_VERSION");
        }
    }

    #[test]
    fn env_source_rejects_missing() {
        // SAFETY: nextest runs each test in its own process and this test starts
        // no threads, so nothing reads the environment concurrently.
        unsafe { std::env::remove_var("SID_CLUSTER_KEK") };
        match EnvVarKekSource::from_env() {
            Err(OrgCryptoError::KekUnavailable(_)) => {}
            other => panic!("expected KekUnavailable, got {:?}", other.map(|_| ())),
        }
    }
}
