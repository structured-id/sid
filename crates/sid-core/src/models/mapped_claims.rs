// SPDX-License-Identifier: AGPL-3.0-only
//! Mapped Claims domain model.
//!
//! Normalized representation of upstream IdP claims (OIDC, OAuth2, SAML).
//! Protocol-agnostic: regardless of upstream format, claims are mapped
//! to a standard structure for account resolution and JIT provisioning.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Normalized claims from upstream provider.
///
/// Extracted from OIDC id_token/UserInfo, OAuth2 userinfo endpoint, or SAML assertion.
/// Used for:
/// - Account resolution (find existing profile by upstream_subject or verified email)
/// - JIT provisioning (create new profile with imported claims)
/// - Upstream identity caching (store denormalized email/name/picture)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedClaims {
    /// Upstream subject identifier (`sub` in OIDC, NameID in SAML).
    pub upstream_subject: String,

    /// Upstream issuer (`iss` in OIDC, entity ID in SAML).
    pub upstream_issuer: Option<String>,

    /// Email address (verified or unverified, depending on provider).
    pub email: Option<String>,

    /// Whether the email is verified at the upstream provider.
    pub email_verified: Option<bool>,

    /// Display name (`name` in OIDC).
    pub name: Option<String>,

    /// Given name (`given_name` in OIDC).
    pub given_name: Option<String>,

    /// Family name (`family_name` in OIDC).
    pub family_name: Option<String>,

    /// Profile picture URL (`picture` in OIDC).
    pub picture: Option<String>,

    /// Locale (`locale` in OIDC).
    pub locale: Option<String>,

    /// Raw claims (protocol-specific, stored as opaque JSON).
    pub raw_claims: HashMap<String, serde_json::Value>,
}

impl MappedClaims {
    /// Create minimal mapped claims with just subject.
    pub fn new(upstream_subject: impl Into<String>) -> Self {
        Self {
            upstream_subject: upstream_subject.into(),
            upstream_issuer: None,
            email: None,
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            raw_claims: HashMap::new(),
        }
    }

    /// Build from OIDC UserInfo/id_token claims.
    pub fn from_oidc_userinfo(claims: &HashMap<String, serde_json::Value>) -> Self {
        let str_claim = |key: &str| -> Option<String> {
            claims.get(key).and_then(|v| v.as_str()).map(String::from)
        };
        let bool_claim = |key: &str| -> Option<bool> { claims.get(key).and_then(|v| v.as_bool()) };

        Self {
            upstream_subject: str_claim("sub").unwrap_or_default(),
            upstream_issuer: str_claim("iss"),
            email: str_claim("email"),
            email_verified: bool_claim("email_verified"),
            name: str_claim("name"),
            given_name: str_claim("given_name"),
            family_name: str_claim("family_name"),
            picture: str_claim("picture"),
            locale: str_claim("locale"),
            raw_claims: claims.clone(),
        }
    }

    /// Whether this has a verified email (both present and verified=true).
    pub fn has_verified_email(&self) -> bool {
        self.email.is_some() && self.email_verified.unwrap_or(false)
    }

    /// Set issuer.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.upstream_issuer = Some(issuer.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mapped_claims_new() {
        let claims = MappedClaims::new("sub-123");
        assert_eq!(claims.upstream_subject, "sub-123");
        assert!(claims.upstream_issuer.is_none());
        assert!(claims.email.is_none());
        assert!(claims.email_verified.is_none());
        assert!(claims.name.is_none());
        assert!(claims.raw_claims.is_empty());
    }

    #[test]
    fn test_from_oidc_userinfo_full() {
        let userinfo: HashMap<String, serde_json::Value> = serde_json::from_value(json!({
            "sub": "google-123",
            "iss": "https://accounts.google.com",
            "email": "alice@sid.example.com",
            "email_verified": true,
            "name": "Alice Wonderland",
            "given_name": "Alice",
            "family_name": "Wonderland",
            "picture": "https://sid.example.com/pic.jpg",
            "locale": "en-US"
        }))
        .unwrap();

        let claims = MappedClaims::from_oidc_userinfo(&userinfo);

        assert_eq!(claims.upstream_subject, "google-123");
        assert_eq!(
            claims.upstream_issuer.as_deref(),
            Some("https://accounts.google.com")
        );
        assert_eq!(claims.email.as_deref(), Some("alice@sid.example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Alice Wonderland"));
        assert_eq!(claims.given_name.as_deref(), Some("Alice"));
        assert_eq!(claims.family_name.as_deref(), Some("Wonderland"));
        assert_eq!(
            claims.picture.as_deref(),
            Some("https://sid.example.com/pic.jpg")
        );
        assert_eq!(claims.locale.as_deref(), Some("en-US"));
        assert!(claims.has_verified_email());
        assert!(!claims.raw_claims.is_empty());
    }

    #[test]
    fn test_from_oidc_userinfo_minimal() {
        let userinfo: HashMap<String, serde_json::Value> =
            serde_json::from_value(json!({"sub": "user-456"})).unwrap();

        let claims = MappedClaims::from_oidc_userinfo(&userinfo);
        assert_eq!(claims.upstream_subject, "user-456");
        assert!(claims.email.is_none());
        assert!(claims.name.is_none());
        assert!(!claims.has_verified_email());
    }

    #[test]
    fn test_from_oidc_userinfo_no_sub() {
        let userinfo: HashMap<String, serde_json::Value> =
            serde_json::from_value(json!({"email": "bob@sid.example.com"})).unwrap();

        let claims = MappedClaims::from_oidc_userinfo(&userinfo);
        assert_eq!(claims.upstream_subject, ""); // defaults to empty
    }

    #[test]
    fn test_has_verified_email_true() {
        let userinfo: HashMap<String, serde_json::Value> = serde_json::from_value(json!({
            "sub": "u1",
            "email": "alice@sid.example.com",
            "email_verified": true
        }))
        .unwrap();

        assert!(MappedClaims::from_oidc_userinfo(&userinfo).has_verified_email());
    }

    #[test]
    fn test_has_verified_email_false_when_unverified() {
        let userinfo: HashMap<String, serde_json::Value> = serde_json::from_value(json!({
            "sub": "u2",
            "email": "bob@sid.example.com",
            "email_verified": false
        }))
        .unwrap();

        assert!(!MappedClaims::from_oidc_userinfo(&userinfo).has_verified_email());
    }

    #[test]
    fn test_has_verified_email_false_when_missing_verified() {
        let userinfo: HashMap<String, serde_json::Value> = serde_json::from_value(json!({
            "sub": "u3",
            "email": "carol@sid.example.com"
        }))
        .unwrap();

        assert!(!MappedClaims::from_oidc_userinfo(&userinfo).has_verified_email());
    }

    #[test]
    fn test_has_verified_email_false_when_no_email() {
        let claims = MappedClaims::new("sub-789");
        assert!(!claims.has_verified_email());
    }

    #[test]
    fn test_with_issuer() {
        let claims = MappedClaims::new("sub-1").with_issuer("https://accounts.google.com");
        assert_eq!(
            claims.upstream_issuer.as_deref(),
            Some("https://accounts.google.com")
        );
    }

    #[test]
    fn test_mapped_claims_serde_roundtrip() {
        let mut raw = HashMap::new();
        raw.insert("custom".into(), json!("value"));

        let claims = MappedClaims {
            upstream_subject: "sub-rt".into(),
            upstream_issuer: Some("iss-rt".into()),
            email: Some("test@sid.example.com".into()),
            email_verified: Some(true),
            name: Some("Test User".into()),
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            raw_claims: raw,
        };

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: MappedClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.upstream_subject, "sub-rt");
        assert_eq!(parsed.email.as_deref(), Some("test@sid.example.com"));
        assert!(parsed.has_verified_email());
        assert_eq!(
            parsed.raw_claims.get("custom").and_then(|v| v.as_str()),
            Some("value")
        );
    }
}
