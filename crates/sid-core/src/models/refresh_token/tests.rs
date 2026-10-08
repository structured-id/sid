use super::*;
use chrono::Duration;

fn make_token(expires_in: Duration, revoked: bool) -> RefreshToken {
    let id = Uuid::now_v7();
    RefreshToken {
        id,
        token_hash: vec![1, 2, 3],
        session_id: SessionId::generate(),
        profile_id: ProfileId::generate(),
        client_id: "test-client".to_string(),
        scopes: vec!["openid".into(), "profile".into()],
        resource: ResourceId::generate(),
        expires_at: Utc::now() + expires_in,
        created_at: Utc::now(),
        revoked,
        replaced_by: None,
        family_id: id,
        grace_expires_at: None,
        dpop_jkt: None,
    }
}

fn make_token_with_grace(expires_in: Duration, revoked: bool, grace_secs: i64) -> RefreshToken {
    let mut token = make_token(expires_in, revoked);
    token.grace_expires_at = Some(Utc::now() + Duration::seconds(grace_secs));
    token
}

#[test]
fn test_valid_token() {
    let token = make_token(Duration::days(30), false);
    assert!(!token.is_expired());
    assert!(token.is_valid());
}

#[test]
fn test_expired_token() {
    let token = make_token(Duration::seconds(-1), false);
    assert!(token.is_expired());
    assert!(!token.is_valid());
}

#[test]
fn test_revoked_token_no_grace() {
    let token = make_token(Duration::days(30), true);
    assert!(!token.is_expired());
    assert!(!token.is_valid());
    assert!(!token.is_within_grace_window());
}

#[test]
fn test_revoked_and_expired() {
    let token = make_token(Duration::seconds(-1), true);
    assert!(!token.is_valid());
}

#[test]
fn test_revoked_within_grace_window() {
    let token = make_token_with_grace(Duration::days(30), true, 30);
    assert!(token.is_within_grace_window());
    assert!(token.is_valid());
}

#[test]
fn test_revoked_grace_expired() {
    let token = make_token_with_grace(Duration::days(30), true, -5);
    assert!(!token.is_within_grace_window());
    assert!(!token.is_valid());
}

#[test]
fn test_active_token_with_grace_is_valid() {
    // Non-revoked token with grace_expires_at set should still be valid
    let token = make_token_with_grace(Duration::days(30), false, 30);
    assert!(token.is_valid());
}

#[test]
fn test_scopes_string() {
    let token = make_token(Duration::days(1), false);
    assert_eq!(token.scopes_string(), "openid profile");
}

#[test]
fn test_scopes_string_empty() {
    let mut token = make_token(Duration::days(1), false);
    token.scopes = vec![];
    assert_eq!(token.scopes_string(), "");
}

#[test]
fn test_family_id_default() {
    let token = make_token(Duration::days(1), false);
    assert_eq!(token.family_id, token.id, "first token: family_id == id");
}

// === Validate (consume-self) tests ===

#[test]
fn test_validate_valid_token_consumes_self() {
    let session_id = SessionId::generate();
    let profile_id = ProfileId::generate();
    let resource = ResourceId::generate();
    let id = Uuid::now_v7();
    let token = RefreshToken {
        id,
        token_hash: vec![1, 2, 3],
        session_id,
        profile_id,
        client_id: "test-client".to_string(),
        scopes: vec!["openid".into(), "profile".into()],
        resource,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: id,
        grace_expires_at: None,
        dpop_jkt: None,
    };

    let validated = token.validate().expect("validate should succeed");

    assert_eq!(validated.session_id(), session_id);
    assert_eq!(validated.profile_id(), profile_id);
    assert_eq!(validated.client_id(), "test-client");
    assert_eq!(validated.scopes(), &["openid", "profile"]);
    assert_eq!(validated.resource(), resource);
    assert_eq!(validated.token_hash(), &[1, 2, 3]);
    assert_eq!(validated.family_id(), id);
    assert!(!validated.is_grace_period());
    assert_eq!(validated.scopes_string(), "openid profile");
}

#[test]
fn test_validate_revoked_no_grace_returns_theft() {
    let session_id = SessionId::generate();
    let mut token = make_token(Duration::days(30), true);
    token.session_id = session_id;
    let family_id = token.family_id;

    let err = token.validate().unwrap_err();
    assert_eq!(
        err,
        RefreshTokenError::TheftDetected {
            session_id,
            family_id,
        }
    );
}

#[test]
fn test_validate_revoked_within_grace_succeeds() {
    let token = make_token_with_grace(Duration::days(30), true, 30);
    let validated = token
        .validate()
        .expect("should succeed within grace window");
    assert!(validated.is_grace_period());
}

#[test]
fn test_validate_revoked_grace_expired_returns_theft() {
    let token = make_token_with_grace(Duration::days(30), true, -5);
    let family_id = token.family_id;
    let session_id = token.session_id;

    let err = token.validate().unwrap_err();
    assert_eq!(
        err,
        RefreshTokenError::TheftDetected {
            session_id,
            family_id,
        }
    );
}

#[test]
fn test_validate_expired_returns_error() {
    let token = make_token(Duration::seconds(-1), false);
    let err = token.validate().unwrap_err();
    assert_eq!(err, RefreshTokenError::Expired);
}

#[test]
fn test_validate_expired_and_revoked_returns_expired() {
    // Expired is checked first: the token is unusable regardless of revocation
    let token = make_token(Duration::seconds(-1), true);
    let err = token.validate().unwrap_err();
    assert_eq!(err, RefreshTokenError::Expired);
}

#[test]
fn test_refresh_token_error_display() {
    let session_id = SessionId::generate();
    let family_id = Uuid::now_v7();
    assert_eq!(
        RefreshTokenError::Revoked {
            session_id,
            family_id,
        }
        .to_string(),
        "refresh token revoked"
    );
    assert_eq!(
        RefreshTokenError::Expired.to_string(),
        "refresh token expired"
    );
    assert_eq!(
        RefreshTokenError::TheftDetected {
            session_id,
            family_id,
        }
        .to_string(),
        "token theft detected"
    );
}
