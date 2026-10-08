use super::*;

fn make_device_auth() -> DeviceAuthorizationCode {
    DeviceAuthorizationCode::new(
        "test_client".to_string(),
        vec![0u8; 32],
        "WDJB-MJHT".to_string(),
        Some("openid profile".to_string()),
        crate::models::ResourceId::generate(),
        ProjectId::new(),
    )
}

#[test]
fn test_new_defaults() {
    let da = make_device_auth();
    assert_eq!(da.status, DeviceAuthStatus::Pending);
    assert_eq!(da.client_id, "test_client");
    assert_eq!(da.user_code, "WDJB-MJHT");
    assert_eq!(da.interval, DEVICE_CODE_POLL_INTERVAL_SECS);
    assert!(da.authorized_by.is_none());
    assert!(da.authorized_at.is_none());
    assert!(!da.is_expired());
}

#[test]
fn test_as_pending_returns_some_for_pending() {
    let mut da = make_device_auth();
    assert!(da.as_pending().is_some());
}

#[test]
fn test_as_pending_returns_none_for_authorized() {
    let mut da = make_device_auth();
    da.as_pending()
        .unwrap()
        .authorize(super::super::ProfileId::generate());
    assert!(da.as_pending().is_none());
}

#[test]
fn test_as_pending_returns_none_for_denied() {
    let mut da = make_device_auth();
    da.as_pending().unwrap().deny();
    assert!(da.as_pending().is_none());
}

#[test]
fn test_as_pending_returns_none_for_expired() {
    let mut da = make_device_auth();
    da.as_pending().unwrap().expire();
    assert!(da.as_pending().is_none());
}

#[test]
fn test_authorize_via_gateway() {
    let mut da = make_device_auth();
    let profile_id = super::super::ProfileId::generate();
    da.as_pending().unwrap().authorize(profile_id);
    assert_eq!(da.status(), DeviceAuthStatus::Authorized);
    assert_eq!(da.authorized_by, Some(profile_id));
    assert!(da.authorized_at.is_some());
}

#[test]
fn test_deny_via_gateway() {
    let mut da = make_device_auth();
    da.as_pending().unwrap().deny();
    assert_eq!(da.status(), DeviceAuthStatus::Denied);
    assert!(da.authorized_by.is_none());
}

#[test]
fn test_expire_via_gateway() {
    let mut da = make_device_auth();
    da.as_pending().unwrap().expire();
    assert_eq!(da.status(), DeviceAuthStatus::Expired);
}

#[test]
fn test_gateway_inner_access() {
    let mut da = make_device_auth();
    let pending = da.as_pending().unwrap();
    assert_eq!(pending.inner().client_id, "test_client");
    assert_eq!(pending.inner().user_code, "WDJB-MJHT");
    pending.deny(); // consume
}

#[test]
fn test_status_is_terminal() {
    assert!(!DeviceAuthStatus::Pending.is_terminal());
    assert!(DeviceAuthStatus::Authorized.is_terminal());
    assert!(DeviceAuthStatus::Denied.is_terminal());
    assert!(DeviceAuthStatus::Expired.is_terminal());
    assert!(DeviceAuthStatus::Redeemed.is_terminal());
}

/// Every stored status reads back as written; anything else is refused,
/// never read as pending.
#[test]
fn test_status_parses_strictly() {
    for s in [
        DeviceAuthStatus::Pending,
        DeviceAuthStatus::Authorized,
        DeviceAuthStatus::Denied,
        DeviceAuthStatus::Expired,
        DeviceAuthStatus::Redeemed,
    ] {
        assert_eq!(s.as_str().parse::<DeviceAuthStatus>(), Ok(s));
    }
    assert!("used".parse::<DeviceAuthStatus>().is_err());
}

#[test]
fn test_status_display() {
    assert_eq!(DeviceAuthStatus::Pending.to_string(), "pending");
    assert_eq!(DeviceAuthStatus::Authorized.to_string(), "authorized");
    assert_eq!(DeviceAuthStatus::Denied.to_string(), "denied");
    assert_eq!(DeviceAuthStatus::Expired.to_string(), "expired");
}

#[test]
fn test_status_serde() {
    let s = DeviceAuthStatus::Authorized;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"authorized\"");
    let parsed: DeviceAuthStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, DeviceAuthStatus::Authorized);
}

#[test]
fn test_id_unique() {
    let id1 = DeviceAuthCodeId::new();
    let id2 = DeviceAuthCodeId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_serde_roundtrip() {
    let da = make_device_auth();
    let json = serde_json::to_string(&da).unwrap();
    let parsed: DeviceAuthorizationCode = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.client_id, "test_client");
    assert_eq!(parsed.user_code, "WDJB-MJHT");
    assert_eq!(parsed.status, DeviceAuthStatus::Pending);
}

#[test]
fn test_is_expired_with_past_expiry() {
    let mut da = make_device_auth();
    da.expires_at = Utc::now() - chrono::Duration::seconds(10);
    assert!(da.is_expired());
}

#[test]
fn test_constants() {
    assert_eq!(DEVICE_CODE_LIFETIME_SECS, 600);
    assert_eq!(DEVICE_CODE_POLL_INTERVAL_SECS, 5);
    assert_eq!(USER_CODE_LENGTH, 8);
}
