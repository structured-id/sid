use super::*;
use sid_core::models::{DeviceAuthorizationCode, ProjectId};

fn make_pending_auth() -> DeviceAuthorizationCode {
    DeviceAuthorizationCode::new(
        "test_client".to_string(),
        vec![0u8; 32],
        "WDJB-MJHT".to_string(),
        Some("openid".to_string()),
        sid_core::models::ResourceId::generate(),
        ProjectId::new(),
    )
}

// ── User code generation ────────────────────────────────────

#[test]
fn test_generate_user_code_format() {
    let code = generate_user_code();
    assert_eq!(code.len(), 9); // 4 + hyphen + 4
    assert_eq!(&code[4..5], "-");

    // All chars should be consonants
    for c in code.chars().filter(|c| *c != '-') {
        assert!(USER_CODE_CHARS.contains(&(c as u8)), "unexpected char: {c}");
    }
}

#[test]
fn test_generate_user_code_unique() {
    let codes: std::collections::HashSet<String> = (0..100).map(|_| generate_user_code()).collect();
    // With 20^8 possibilities, 100 codes should all be unique
    assert_eq!(codes.len(), 100);
}

// ── Device code generation ──────────────────────────────────

#[test]
fn test_generate_device_code() {
    let (raw, hash) = generate_device_code();
    assert!(!raw.is_empty());
    assert_eq!(hash.len(), 32); // SHA-256

    // Hash should match
    let expected_hash = hash_device_code(&raw);
    assert_eq!(hash, expected_hash);
}

#[test]
fn test_device_code_unique() {
    let codes: Vec<(String, Vec<u8>)> = (0..10).map(|_| generate_device_code()).collect();
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(codes[i].0, codes[j].0);
        }
    }
}

// ── User code normalization ─────────────────────────────────

#[test]
fn test_normalize_user_code() {
    assert_eq!(normalize_user_code("wdjb-mjht"), "WDJBMJHT");
    assert_eq!(normalize_user_code("WDJB MJHT"), "WDJBMJHT");
    assert_eq!(normalize_user_code("wdjb mjht"), "WDJBMJHT");
    assert_eq!(normalize_user_code("WDJB-MJHT"), "WDJBMJHT");
}

#[test]
fn test_normalize_user_code_strips_numbers() {
    assert_eq!(normalize_user_code("W1D2J3B4"), "WDJB");
}

// ── Polling validation ──────────────────────────────────────

#[test]
fn test_validate_poll_pending() {
    let auth = make_pending_auth();
    assert!(matches!(
        validate_poll(&auth),
        Err(DeviceAuthError::AuthorizationPending)
    ));
}

#[test]
fn test_validate_poll_authorized() {
    let mut auth = make_pending_auth();
    auth.as_pending()
        .unwrap()
        .authorize(sid_core::models::ProfileId::generate());
    assert!(validate_poll(&auth).is_ok());
}

#[test]
fn test_validate_poll_denied() {
    let mut auth = make_pending_auth();
    auth.as_pending().unwrap().deny();
    assert!(matches!(
        validate_poll(&auth),
        Err(DeviceAuthError::AccessDenied)
    ));
}

#[test]
fn test_validate_poll_expired_status() {
    let mut auth = make_pending_auth();
    auth.as_pending().unwrap().expire();
    assert!(matches!(
        validate_poll(&auth),
        Err(DeviceAuthError::ExpiredToken)
    ));
}

#[test]
fn test_validate_poll_expired_by_time() {
    let mut auth = make_pending_auth();
    auth.expires_at = chrono::Utc::now() - chrono::Duration::seconds(10);
    assert!(matches!(
        validate_poll(&auth),
        Err(DeviceAuthError::ExpiredToken)
    ));
}

/// A redeemed code grants nothing more: invalid_grant.
#[test]
fn test_validate_poll_redeemed() {
    let mut auth = make_pending_auth();
    auth.status = sid_core::models::DeviceAuthStatus::Redeemed;
    let err = validate_poll(&auth).unwrap_err();
    assert!(matches!(err, DeviceAuthError::AlreadyRedeemed));
    assert_eq!(err.error_code(), "invalid_grant");
}

// ── Verification URI ────────────────────────────────────────

#[test]
fn test_build_verification_uri_complete() {
    let uri = build_verification_uri_complete("https://auth.sid.example.com/device", "WDJB-MJHT");
    assert_eq!(uri, "https://auth.sid.example.com/device?code=WDJB-MJHT");
}

// ── Error codes ─────────────────────────────────────────────

#[test]
fn test_error_codes() {
    assert_eq!(
        DeviceAuthError::AuthorizationPending.error_code(),
        "authorization_pending"
    );
    assert_eq!(DeviceAuthError::SlowDown.error_code(), "slow_down");
    assert_eq!(DeviceAuthError::ExpiredToken.error_code(), "expired_token");
    assert_eq!(DeviceAuthError::AccessDenied.error_code(), "access_denied");
    assert_eq!(
        DeviceAuthError::InvalidClient.error_code(),
        "invalid_client"
    );
}

// ── Hash device code ────────────────────────────────────────

#[test]
fn test_hash_device_code_deterministic() {
    let hash1 = hash_device_code("test_code_123");
    let hash2 = hash_device_code("test_code_123");
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
}

#[test]
fn test_hash_device_code_different_inputs() {
    let hash1 = hash_device_code("code_a");
    let hash2 = hash_device_code("code_b");
    assert_ne!(hash1, hash2);
}
