// SPDX-License-Identifier: AGPL-3.0-only
//! Migration provider adapters for importing users from legacy IdPs.
//!
//! Each adapter parses a provider-specific export format and normalizes
//! to `ImportedUser` records that the import pipeline can process.

pub mod auth0;
pub mod authentik;
pub mod keycloak;
pub mod ldif;
pub mod okta;
pub mod scim;
pub mod zitadel;

use serde::{Deserialize, Serialize};

/// A user record normalized from a legacy IdP export.
///
/// All provider adapters produce `Vec<ImportedUser>` regardless of source format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedUser {
    /// Username / login identifier from the legacy system.
    pub username: String,
    /// Primary email address.
    pub email: String,
    /// Whether the email was verified in the legacy system.
    pub email_verified: bool,
    /// Display name (full name).
    pub display_name: Option<String>,
    /// Given (first) name.
    pub first_name: Option<String>,
    /// Family (last) name.
    pub last_name: Option<String>,
    /// Phone number (E.164 format preferred).
    pub phone: Option<String>,
    /// Whether the account was enabled/active in the legacy system.
    pub enabled: bool,
    /// Legacy password hash (PHC format: $algorithm$params$salt$hash).
    pub password_hash: Option<String>,
    /// Detected hash algorithm (e.g., "bcrypt", "argon2id", "pbkdf2-sha256").
    pub hash_algorithm: Option<String>,
    /// TOTP seed (base32 encoded) — if TOTP was enrolled.
    pub totp_seed: Option<String>,
    /// Roles assigned in the legacy system.
    pub roles: Vec<String>,
    /// Groups assigned in the legacy system.
    pub groups: Vec<String>,
    /// Legacy system user ID (for reference/deduplication).
    pub external_id: String,
    /// Additional provider-specific attributes.
    pub attributes: std::collections::HashMap<String, String>,
}

/// Error during migration import.
#[derive(Debug, thiserror::Error)]
pub enum MigrationImportError {
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Trait for migration provider adapters.
///
/// Each adapter knows how to parse a specific export format
/// and produce normalized `ImportedUser` records.
pub trait MigrationAdapter {
    /// Provider name (e.g., "keycloak", "auth0", "okta").
    fn provider_name(&self) -> &'static str;

    /// Parse an export and return normalized user records.
    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError>;
}
