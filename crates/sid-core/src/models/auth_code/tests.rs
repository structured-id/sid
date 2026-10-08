use super::*;
use chrono::Duration;

use crate::models::{AuthLevel, SessionId};

/// A password sign-in an hour ago.
fn authentication() -> GrantAuthentication {
    GrantAuthentication {
        session: SessionId::generate(),
        authenticated_at: Utc::now() - Duration::hours(1),
        amr: vec!["pwd".into()],
        assurance_level: AuthLevel::Basic,
        elevation: None,
    }
}

fn make_code(expires_in: Duration, used: bool) -> AuthorizationCode {
    AuthorizationCode {
        code_hash: vec![10, 20, 30],
        profile_id: ProfileId::generate(),
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".into(), "email".into()],
        resource: ResourceId::generate(),
        code_challenge: Some("challenge-value".to_string()),
        nonce: None,
        authentication: authentication(),
        expires_at: Utc::now() + expires_in,
        created_at: Utc::now(),
        used,
        session_id: None,
    }
}

#[test]
fn test_valid_code() {
    let code = make_code(Duration::minutes(5), false);
    assert!(!code.is_expired());
    assert!(code.is_valid());
}

#[test]
fn test_expired_code() {
    let code = make_code(Duration::seconds(-1), false);
    assert!(code.is_expired());
    assert!(!code.is_valid());
}

#[test]
fn test_used_code() {
    let code = make_code(Duration::minutes(5), true);
    assert!(!code.is_expired());
    assert!(!code.is_valid());
}

#[test]
fn test_used_and_expired() {
    let code = make_code(Duration::seconds(-1), true);
    assert!(!code.is_valid());
}

#[test]
fn test_scopes_string() {
    let code = make_code(Duration::minutes(5), false);
    assert_eq!(code.scopes_string(), "openid email");
}

#[test]
fn test_code_without_pkce() {
    let mut code = make_code(Duration::minutes(5), false);
    code.code_challenge = None;
    assert!(code.code_challenge.is_none());
    assert!(code.is_valid());
}

// === Exchange (consume-self) tests ===

#[test]
fn test_exchange_valid_code_consumes_self() {
    let profile_id = ProfileId::generate();
    let resource = ResourceId::generate();
    let authentication = authentication();
    let code = AuthorizationCode {
        code_hash: vec![10, 20, 30],
        profile_id,
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".into(), "email".into()],
        resource,
        code_challenge: Some("challenge-value".to_string()),
        nonce: Some("n-0S6_WzA2Mj".to_string()),
        authentication: authentication.clone(),
        expires_at: Utc::now() + Duration::minutes(5),
        created_at: Utc::now(),
        used: false,
        session_id: None,
    };

    let exchanged = code.exchange().expect("exchange should succeed");
    // code is consumed: cannot be used again (compile error if attempted)

    assert_eq!(exchanged.profile_id(), profile_id);
    assert_eq!(exchanged.client_id(), "test-client");
    assert_eq!(
        exchanged.redirect_uri(),
        "https://app.sid.example.com/callback"
    );
    assert_eq!(exchanged.scopes(), &["openid", "email"]);
    assert_eq!(exchanged.resource(), resource);
    assert_eq!(exchanged.code_challenge(), Some("challenge-value"));
    assert_eq!(exchanged.nonce(), Some("n-0S6_WzA2Mj"));
    // The authorizing session's authentication reaches the redemption.
    assert_eq!(exchanged.authentication(), &authentication);
    assert_eq!(exchanged.code_hash(), &[10, 20, 30]);
    assert_eq!(exchanged.scopes_string(), "openid email");
}

#[test]
fn test_exchange_already_used_returns_error() {
    let code = make_code(Duration::minutes(5), true);
    let err = code.exchange().unwrap_err();
    assert_eq!(err, AuthCodeError::AlreadyUsed);
}

#[test]
fn test_exchange_expired_returns_error() {
    let code = make_code(Duration::seconds(-1), false);
    let err = code.exchange().unwrap_err();
    assert_eq!(err, AuthCodeError::Expired);
}

#[test]
fn test_exchange_used_and_expired_returns_already_used() {
    // AlreadyUsed is checked first (more specific: indicates replay attack)
    let code = make_code(Duration::seconds(-1), true);
    let err = code.exchange().unwrap_err();
    assert_eq!(err, AuthCodeError::AlreadyUsed);
}

#[test]
fn test_auth_code_error_display() {
    assert_eq!(
        AuthCodeError::AlreadyUsed.to_string(),
        "authorization code already used"
    );
    assert_eq!(
        AuthCodeError::Expired.to_string(),
        "authorization code expired"
    );
}
