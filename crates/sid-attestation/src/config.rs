// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration for sid-attestation, loaded from environment variables.

use std::net::SocketAddr;

/// Attestation service configuration.
pub struct AttestationConfig {
    /// gRPC bind address.
    pub grpc_bind: SocketAddr,
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Ed25519 public key PEM path used to verify callers' tokens (the
    /// service never holds the signing key).
    pub jwt_public_key_path: String,
    /// Token issuer URL.
    pub jwt_issuer: String,
}

impl AttestationConfig {
    /// Load configuration from environment variables. The database and the
    /// token verifier are required: device keys are bound only for an
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
            jwt_public_key_path: required("SID_JWT_PUBLIC_KEY_PATH")?,
            jwt_issuer: required("SID_ISSUER")?,
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
mod tests {
    use super::*;

    #[test]
    fn test_database_url_display_masks_password() {
        let config = AttestationConfig {
            grpc_bind: "127.0.0.1:50061".parse().unwrap(),
            database_url: "postgres://sid:secret_pass@localhost:5432/sid".into(),
            jwt_public_key_path: String::new(),
            jwt_issuer: String::new(),
        };
        let display = config.database_url_display();
        assert!(!display.contains("secret_pass"));
        assert!(display.contains("***"));
        assert!(display.contains("localhost:5432/sid"));
    }

    #[test]
    fn test_database_url_display_no_password() {
        let config = AttestationConfig {
            grpc_bind: "127.0.0.1:50061".parse().unwrap(),
            database_url: "postgres://localhost:5432/sid".into(),
            jwt_public_key_path: String::new(),
            jwt_issuer: String::new(),
        };
        let display = config.database_url_display();
        assert_eq!(display, "postgres://localhost:5432/sid");
    }
}
