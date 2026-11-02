// SPDX-License-Identifier: AGPL-3.0-only
//! Upstream Identity domain model.
//!
//! Tracks which profiles have linked accounts with upstream IdPs.
//! Each profile can have multiple upstream identities (e.g., Google + GitHub).
//! Each upstream provider can have at most one identity per profile.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ProfileId, UpstreamProviderId};

/// Unique identifier for an upstream identity link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpstreamIdentityId(pub Uuid);

impl UpstreamIdentityId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for UpstreamIdentityId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UpstreamIdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Linked upstream identity.
///
/// Each profile can have multiple upstream identities (e.g., Google + GitHub).
/// Each upstream provider can have at most one identity per profile.
/// Each `(provider_id, upstream_subject)` pair is globally unique — prevents
/// two profiles from claiming the same upstream account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamIdentity {
    pub id: UpstreamIdentityId,

    /// The profile this upstream identity is linked to.
    pub profile_id: ProfileId,

    /// The upstream provider.
    pub provider_id: UpstreamProviderId,

    /// Upstream subject identifier (`sub` claim from provider).
    pub upstream_subject: String,

    /// Upstream issuer (`iss` claim, if OIDC).
    pub upstream_issuer: Option<String>,

    /// Cached email from upstream provider (denormalized for fast lookup).
    pub upstream_email: Option<String>,

    /// Cached display name from upstream provider.
    pub upstream_name: Option<String>,

    /// Cached profile picture URL from upstream provider.
    pub upstream_picture: Option<String>,

    /// When this identity was first linked.
    pub linked_at: DateTime<Utc>,

    /// When the user last authenticated via this upstream identity.
    pub last_login_at: Option<DateTime<Utc>>,

    /// Number of times this identity was used for login.
    pub login_count: u64,
}

/// A login through a linked upstream identity: the claims the provider just
/// returned replace the cached ones, and the login is counted.
#[derive(Debug, Clone)]
pub struct UpstreamLogin {
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub at: DateTime<Utc>,
}

impl UpstreamIdentity {
    /// Create a new upstream identity link.
    pub fn new(
        profile_id: ProfileId,
        provider_id: UpstreamProviderId,
        upstream_subject: impl Into<String>,
    ) -> Self {
        Self {
            id: UpstreamIdentityId::new(),
            profile_id,
            provider_id,
            upstream_subject: upstream_subject.into(),
            upstream_issuer: None,
            upstream_email: None,
            upstream_name: None,
            upstream_picture: None,
            linked_at: Utc::now(),
            last_login_at: None,
            login_count: 0,
        }
    }

    /// Set upstream issuer.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.upstream_issuer = Some(issuer.into());
        self
    }

    /// Update cached upstream claims after token exchange.
    pub fn update_claims(
        &mut self,
        email: Option<String>,
        name: Option<String>,
        picture: Option<String>,
    ) {
        self.upstream_email = email;
        self.upstream_name = name;
        self.upstream_picture = picture;
    }

    /// Record a login event.
    pub fn record_login(&mut self) {
        self.last_login_at = Some(Utc::now());
        self.login_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_identity_new() {
        let profile_id = ProfileId::generate();
        let provider_id = UpstreamProviderId::new();
        let identity = UpstreamIdentity::new(profile_id, provider_id, "google-user-123");

        assert_eq!(identity.profile_id, profile_id);
        assert_eq!(identity.provider_id, provider_id);
        assert_eq!(identity.upstream_subject, "google-user-123");
        assert!(identity.upstream_issuer.is_none());
        assert!(identity.upstream_email.is_none());
        assert!(identity.upstream_name.is_none());
        assert!(identity.upstream_picture.is_none());
        assert!(identity.last_login_at.is_none());
        assert_eq!(identity.login_count, 0);
    }

    #[test]
    fn test_with_issuer() {
        let identity =
            UpstreamIdentity::new(ProfileId::generate(), UpstreamProviderId::new(), "sub-123")
                .with_issuer("https://accounts.google.com");

        assert_eq!(
            identity.upstream_issuer.as_deref(),
            Some("https://accounts.google.com")
        );
    }

    #[test]
    fn test_update_claims() {
        let mut identity =
            UpstreamIdentity::new(ProfileId::generate(), UpstreamProviderId::new(), "sub-123");

        identity.update_claims(
            Some("alice@sid.example.com".into()),
            Some("Alice".into()),
            Some("https://sid.example.com/pic.jpg".into()),
        );

        assert_eq!(
            identity.upstream_email.as_deref(),
            Some("alice@sid.example.com")
        );
        assert_eq!(identity.upstream_name.as_deref(), Some("Alice"));
        assert_eq!(
            identity.upstream_picture.as_deref(),
            Some("https://sid.example.com/pic.jpg")
        );
    }

    #[test]
    fn test_update_claims_clears() {
        let mut identity =
            UpstreamIdentity::new(ProfileId::generate(), UpstreamProviderId::new(), "sub-123");
        identity.update_claims(Some("old@sid.example.com".into()), None, None);
        assert_eq!(
            identity.upstream_email.as_deref(),
            Some("old@sid.example.com")
        );

        identity.update_claims(None, None, None);
        assert!(identity.upstream_email.is_none());
    }

    #[test]
    fn test_record_login() {
        let mut identity =
            UpstreamIdentity::new(ProfileId::generate(), UpstreamProviderId::new(), "sub-456");

        assert_eq!(identity.login_count, 0);
        assert!(identity.last_login_at.is_none());

        identity.record_login();
        assert_eq!(identity.login_count, 1);
        assert!(identity.last_login_at.is_some());
        let first_login = identity.last_login_at.unwrap();

        identity.record_login();
        assert_eq!(identity.login_count, 2);
        assert!(identity.last_login_at.unwrap() >= first_login);
    }

    #[test]
    fn test_identity_id_unique() {
        let id1 = UpstreamIdentityId::new();
        let id2 = UpstreamIdentityId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_identity_serde_roundtrip() {
        let identity = UpstreamIdentity::new(
            ProfileId::generate(),
            UpstreamProviderId::new(),
            "google-sub-abc",
        )
        .with_issuer("https://accounts.google.com");

        let json = serde_json::to_string(&identity).unwrap();
        let parsed: UpstreamIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.upstream_subject, "google-sub-abc");
        assert_eq!(
            parsed.upstream_issuer.as_deref(),
            Some("https://accounts.google.com")
        );
        assert_eq!(parsed.login_count, 0);
    }
}
