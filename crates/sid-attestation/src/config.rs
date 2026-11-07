// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration for sid-attestation, loaded from environment variables.

use std::net::SocketAddr;

/// Attestation service configuration.
pub struct AttestationConfig {
    /// gRPC bind address.
    pub grpc_bind: SocketAddr,
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// The installation's master key file (`SID_MASTER_KEY_FILE`), the one
    /// the issuer mounts: with the stored key versions it seals the pending
    /// device-key ceremonies every replica reads.
    pub master_key_file: std::path::PathBuf,
    /// Where calls are admitted: the installation's account API resource,
    /// decided by its issuer (`crate::access`). From `SID_GRPC_UPSTREAM`,
    /// `SID_ISSUER_URL`, `SID_RECEIVER_RESOURCE`, `SID_RECEIVER_ORIGIN` and
    /// `SID_AUTHZ_CHECKER_*`.
    pub api: sid_auth::config::ReceiverConfig,
}

impl AttestationConfig {
    /// Load configuration from environment variables. The database and the
    /// receiver are required: device keys are bound only for an
    /// authenticated owner.
    pub fn from_env() -> anyhow::Result<Self> {
        let grpc_bind: SocketAddr = std::env::var("SID_ATTESTATION_BIND")
            .unwrap_or_else(|_| "127.0.0.1:50061".into())
            .parse()?;
        let required = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow::anyhow!("{name} is required"))
        };

        Ok(Self {
            grpc_bind,
            database_url: required("DATABASE_URL")?,
            master_key_file: required("SID_MASTER_KEY_FILE")?.into(),
            api: sid_auth::config::ReceiverConfig::from_env()?,
        })
    }

    /// Display-safe database URL (masks password).
    pub fn database_url_display(&self) -> String {
        if let Some(at_pos) = self.database_url.find('@')
            && let Some(colon_pos) = self.database_url[..at_pos].rfind(':')
        {
            return format!(
                "{}:***@{}",
                &self.database_url[..colon_pos],
                &self.database_url[at_pos + 1..]
            );
        }
        self.database_url.clone()
    }
}

#[cfg(test)]
mod tests;
