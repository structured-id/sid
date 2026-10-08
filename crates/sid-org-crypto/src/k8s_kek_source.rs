// SPDX-License-Identifier: AGPL-3.0-only
//! Kubernetes Secret-backed KEK source.
//!
//! Fetches the Cluster KEK lazily via the K8s API. ServiceAccount auth is
//! discovered from the in-cluster mount at `/var/run/secrets/kubernetes.io/`.
//! Each `fetch_kek` triggers a fresh `GET secret/<name>` against the API
//! server, leaving an audit trail (configure RequestResponse audit policy on
//! the supervisor for full visibility).
//!
//! Pair with [`KekCache`](crate::kek_cache::KekCache) for TTL-bounded caching.
//!
//! ### Secret schema
//!
//! ```yaml
//! apiVersion: v1
//! kind: Secret
//! metadata:
//!   name: sid-cluster-kek
//!   namespace: sid
//! type: Opaque
//! data:
//!   kek: <base64 of 32 raw bytes>           # required
//!   kek_version: <base64 of decimal ascii>  # optional, default "1"
//! ```
//!
//! Hex encoding also accepted for `kek` (auto-detected by length: 64 ASCII
//! hex chars vs 32 raw bytes after base64 decode).
//!
//! ### RBAC
//!
//! The pod's ServiceAccount needs:
//!
//! ```yaml
//! apiVersion: rbac.authorization.k8s.io/v1
//! kind: Role
//! rules:
//!   - apiGroups: [""]
//!     resources: ["secrets"]
//!     resourceNames: ["sid-cluster-kek"]
//!     verbs: ["get"]
//! ```

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::Api;
use secrecy::SecretBox;

use crate::error::OrgCryptoError;
use crate::kek_source::KekSource;

/// Default secret data key holding the KEK bytes.
pub const DEFAULT_KEK_KEY: &str = "kek";
/// Default secret data key holding the KEK version (decimal ASCII).
pub const DEFAULT_VERSION_KEY: &str = "kek_version";

/// K8s Secret-backed KEK source.
pub struct K8sSecretKekSource {
    client: Client,
    namespace: String,
    secret_name: String,
    kek_key: String,
    version_key: String,
}

impl K8sSecretKekSource {
    /// Construct using in-cluster ServiceAccount credentials.
    ///
    /// Reads from `<namespace>/<secret_name>`, looking up `data.kek` and
    /// `data.kek_version` keys.
    pub async fn new_in_cluster(
        namespace: impl Into<String>,
        secret_name: impl Into<String>,
    ) -> Result<Self, OrgCryptoError> {
        let client = Client::try_default()
            .await
            .map_err(|e| OrgCryptoError::KekUnavailable(format!("k8s client init: {e}")))?;
        Ok(Self {
            client,
            namespace: namespace.into(),
            secret_name: secret_name.into(),
            kek_key: DEFAULT_KEK_KEY.to_string(),
            version_key: DEFAULT_VERSION_KEY.to_string(),
        })
    }

    /// Construct with an explicit `Client` (for tests / non-default kubeconfig).
    pub fn with_client(
        client: Client,
        namespace: impl Into<String>,
        secret_name: impl Into<String>,
    ) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            secret_name: secret_name.into(),
            kek_key: DEFAULT_KEK_KEY.to_string(),
            version_key: DEFAULT_VERSION_KEY.to_string(),
        }
    }

    /// Override the data key holding the KEK material (default `"kek"`).
    pub fn with_kek_key(mut self, key: impl Into<String>) -> Self {
        self.kek_key = key.into();
        self
    }

    /// Override the data key holding the version (default `"kek_version"`).
    pub fn with_version_key(mut self, key: impl Into<String>) -> Self {
        self.version_key = key.into();
        self
    }

    async fn fetch_secret(&self) -> Result<Secret, OrgCryptoError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &self.namespace);
        let secret = api
            .get(&self.secret_name)
            .await
            .map_err(|e| OrgCryptoError::KekUnavailable(format!("get secret: {e}")))?;
        tracing::debug!(
            namespace = %self.namespace,
            secret = %self.secret_name,
            "fetched KEK from k8s Secret"
        );
        Ok(secret)
    }
}

/// Decode KEK bytes accepting either base64-decoded raw 32 bytes or hex (64 ascii chars).
fn decode_kek_bytes(value: &[u8]) -> Result<[u8; 32], OrgCryptoError> {
    if value.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(value);
        return Ok(arr);
    }
    // Maybe hex string (k8s decodes base64 of "01ab..." to 64 ASCII bytes).
    if value.len() == 64 && value.iter().all(|b| b.is_ascii_hexdigit()) {
        let bytes = hex::decode(value)?;
        if bytes.len() != 32 {
            return Err(OrgCryptoError::InvalidKekLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(arr);
    }
    Err(OrgCryptoError::InvalidKekLength(value.len()))
}

#[async_trait]
impl KekSource for K8sSecretKekSource {
    async fn fetch_kek(&self, version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
        let secret = self.fetch_secret().await?;
        let data = secret
            .data
            .as_ref()
            .ok_or_else(|| OrgCryptoError::KekUnavailable("secret has no data".into()))?;

        // Verify version matches what's stored (lazy migration entry-point would re-wrap here).
        let secret_version = data
            .get(&self.version_key)
            .map(|bs| {
                std::str::from_utf8(&bs.0)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1)
            })
            .unwrap_or(1);
        if secret_version != version {
            return Err(OrgCryptoError::KekVersionMismatch {
                have: secret_version,
                need: version,
            });
        }

        let kek_bytes = data.get(&self.kek_key).ok_or_else(|| {
            OrgCryptoError::KekUnavailable(format!("data['{}'] missing", self.kek_key))
        })?;
        let kek = decode_kek_bytes(&kek_bytes.0)?;

        Ok(SecretBox::new(Box::new(kek)))
    }

    async fn current_version(&self) -> Result<u32, OrgCryptoError> {
        let secret = self.fetch_secret().await?;
        let data = secret
            .data
            .as_ref()
            .ok_or_else(|| OrgCryptoError::KekUnavailable("secret has no data".into()))?;
        let v = data
            .get(&self.version_key)
            .and_then(|bs| std::str::from_utf8(&bs.0).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(1);
        Ok(v)
    }

    fn kind(&self) -> &'static str {
        "k8s-secret"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_raw_32_bytes() {
        let raw = [0xAB; 32];
        let decoded = decode_kek_bytes(&raw).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_hex_string() {
        let hex = b"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let decoded = decode_kek_bytes(hex).unwrap();
        assert_eq!(decoded[0], 0x01);
        assert_eq!(decoded[31], 0x20);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        match decode_kek_bytes(b"too short") {
            Err(OrgCryptoError::InvalidKekLength(9)) => {}
            other => panic!("unexpected: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn decode_rejects_non_hex_64_bytes() {
        let not_hex: &[u8] = &[b'z'; 64];
        match decode_kek_bytes(not_hex) {
            Err(OrgCryptoError::InvalidKekLength(64)) => {}
            other => panic!("unexpected: {:?}", other.map(|_| ())),
        }
    }
}
