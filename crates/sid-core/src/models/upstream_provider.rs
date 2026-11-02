// SPDX-License-Identifier: AGPL-3.0-only
//! Upstream Identity Provider domain model.
//!
//! Stores configuration for external IdPs that users can authenticate through
//! (e.g., Google, Microsoft, GitHub). Each provider has encrypted client credentials,
//! OIDC discovery URL or manual endpoint configuration, and a trust category that
//! maps to the existing `AssuranceLevel` system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::principal_verification::AssuranceLevel;
use sid_keys::EncryptedField;

/// Unique identifier for an upstream provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpstreamProviderId(pub Uuid);

impl UpstreamProviderId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Binding context of this provider's client secret, the only context
    /// it is sealed and opened under.
    pub fn client_secret_context(self) -> String {
        format!("upstream:{}", self.0)
    }
}

impl Default for UpstreamProviderId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UpstreamProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Upstream IdP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// OpenID Connect (Discovery + UserInfo).
    Oidc,
    /// Plain OAuth2 (manual endpoint config, no discovery).
    OAuth2,
}

impl UpstreamProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::OAuth2 => "oauth2",
        }
    }
}

impl std::fmt::Display for UpstreamProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Trust category of the upstream provider.
///
/// Determines default assurance level for identities verified by this provider.
/// Integrates with `AssuranceLevel` (Loa0–Loa4) and Site Acceptance Policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrustCategory {
    /// Social login (Google, Facebook, GitHub) — user self-declared identity.
    #[default]
    Social,
    /// Corporate IdP (Okta, Azure AD, JumpCloud) — attested by employer.
    Corporate,
    /// Government IdP (eIDAS, DigiD, BankID) — verified by state authority.
    Government,
    /// Financial institution (bank login, brokerage) — regulated KYC.
    Financial,
}

impl ProviderTrustCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Social => "social",
            Self::Corporate => "corporate",
            Self::Government => "government",
            Self::Financial => "financial",
        }
    }

    /// Default assurance level for identities from this category.
    pub fn default_assurance(&self) -> AssuranceLevel {
        match self {
            Self::Social => AssuranceLevel::Loa1,
            Self::Corporate => AssuranceLevel::Loa2,
            Self::Government => AssuranceLevel::Loa4,
            Self::Financial => AssuranceLevel::Loa3,
        }
    }
}

parse_stored!(UpstreamProtocol, "upstream protocol", [Oidc, OAuth2]);
parse_stored!(
    ProviderTrustCategory,
    "provider trust category",
    [Social, Corporate, Government, Financial]
);

impl std::fmt::Display for ProviderTrustCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Upstream Identity Provider configuration.
///
/// Stores OAuth2/OIDC credentials, endpoints, and display settings.
/// The `client_secret` is encrypted via `KeyManager` with context binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProvider {
    pub id: UpstreamProviderId,

    /// Human-readable name (e.g., "Google", "Corporate Azure AD").
    pub name: String,

    /// Protocol (OIDC or OAuth2).
    pub protocol: UpstreamProtocol,

    /// Trust category — determines default assurance level.
    pub trust_category: ProviderTrustCategory,

    /// Whether this provider is enabled for login.
    pub enabled: bool,

    // === OAuth2/OIDC Configuration ===
    /// OAuth2 client_id (registered with upstream provider).
    pub client_id: String,

    /// OAuth2 client_secret (encrypted via KeyManager).
    pub client_secret: EncryptedField,

    /// OIDC discovery URL (e.g., "https://accounts.google.com/.well-known/openid-configuration").
    /// If present, authorization/token/userinfo endpoints are auto-discovered.
    pub discovery_url: Option<String>,

    /// OAuth2 authorization endpoint (manual config, or discovered from OIDC).
    pub authorization_endpoint: Option<String>,

    /// OAuth2 token endpoint (manual config, or discovered from OIDC).
    pub token_endpoint: Option<String>,

    /// OIDC UserInfo endpoint (discovered or manual).
    pub userinfo_endpoint: Option<String>,

    /// Scopes to request.
    pub scopes: Vec<String>,

    // === Display ===
    /// Show on login page.
    pub show_on_login: bool,

    /// Display order on login page (lower = earlier).
    pub display_order: i32,

    /// Provider logo URL (for login button).
    pub logo_url: Option<String>,

    /// Stored revision: 0 for a new provider, moved on by every update. An
    /// update applies only over the revision it was read at.
    pub revision: u64,

    // === Timestamps ===
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UpstreamProvider {
    /// Create a new upstream provider with minimal config.
    pub fn new(
        name: impl Into<String>,
        protocol: UpstreamProtocol,
        client_id: impl Into<String>,
        client_secret: EncryptedField,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: UpstreamProviderId::new(),
            name: name.into(),
            protocol,
            trust_category: ProviderTrustCategory::Social,
            enabled: true,
            client_id: client_id.into(),
            client_secret,
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            show_on_login: true,
            display_order: 0,
            logo_url: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set OIDC discovery URL.
    pub fn with_discovery_url(mut self, url: impl Into<String>) -> Self {
        self.discovery_url = Some(url.into());
        self
    }

    /// Set trust category.
    pub fn with_trust_category(mut self, category: ProviderTrustCategory) -> Self {
        self.trust_category = category;
        self
    }

    /// Whether this provider uses OIDC discovery.
    pub fn uses_discovery(&self) -> bool {
        self.discovery_url.is_some()
    }
}

#[cfg(test)]
mod tests;
