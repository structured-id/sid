use super::*;

fn make_pat() -> PersonalAccessToken {
    PersonalAccessToken::new(
        ProfileId::generate(),
        "CI deploy",
        "sha256_abc123",
        "sid_pat_",
        vec!["repos:read".into(), "packages:write".into()],
    )
}

#[test]
fn test_pat_new() {
    let pat = make_pat();
    assert_eq!(pat.name, "CI deploy");
    assert_eq!(pat.token_prefix, "sid_pat_");
    assert_eq!(pat.status, PatStatus::Active);
    assert!(pat.is_usable());
    assert!(!pat.is_expired());
    assert_eq!(pat.use_count, 0);
    assert!(pat.last_used_at.is_none());
}

#[test]
fn test_pat_has_scope() {
    let pat = make_pat();
    assert!(pat.has_scope("repos:read"));
    assert!(pat.has_scope("packages:write"));
    assert!(!pat.has_scope("admin:full"));
}

#[test]
fn test_pat_empty_scopes_means_all() {
    let pat = PersonalAccessToken::new(
        ProfileId::generate(),
        "full access",
        "hash",
        "sid_pat_",
        vec![],
    );
    assert!(pat.has_scope("anything"));
    assert!(pat.has_scope("admin:full"));
}

#[test]
fn test_pat_revoke() {
    let mut pat = make_pat();
    assert!(pat.is_usable());
    pat.as_active().unwrap().revoke(Some("admin-id".into()));
    assert_eq!(pat.status(), PatStatus::Revoked);
    assert!(!pat.is_usable());
    assert!(pat.revoked_at.is_some());
    assert_eq!(pat.revoked_by.as_deref(), Some("admin-id"));
}

#[test]
fn test_pat_expired() {
    let pat = make_pat().with_expires_at(Utc::now() - chrono::Duration::hours(1));
    assert!(pat.is_expired());
    assert!(!pat.is_usable());
}

#[test]
fn test_pat_not_expired() {
    let pat = make_pat().with_expires_at(Utc::now() + chrono::Duration::days(30));
    assert!(!pat.is_expired());
    assert!(pat.is_usable());
}

#[test]
fn test_pat_no_expiry_never_expires() {
    let pat = make_pat();
    assert!(pat.expires_at.is_none());
    assert!(!pat.is_expired());
}

#[test]
fn test_pat_record_use() {
    let mut pat = make_pat();
    assert_eq!(pat.use_count, 0);
    pat.record_use(Some("1.2.3.4".into()));
    assert_eq!(pat.use_count, 1);
    assert_eq!(pat.last_used_ip.as_deref(), Some("1.2.3.4"));
    assert!(pat.last_used_at.is_some());

    pat.record_use(None);
    assert_eq!(pat.use_count, 2);
    assert!(pat.last_used_ip.is_none());
}

#[test]
fn test_pat_id_unique() {
    let id1 = PatId::new();
    let id2 = PatId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_pat_status_serde_roundtrip() {
    let s = PatStatus::Revoked;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"revoked\"");
    let parsed: PatStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, PatStatus::Revoked);
}

/// A stored status parses back exactly; an unknown one is refused, never
/// read as a usable token.
#[test]
fn test_pat_status_parses_strictly() {
    for status in [PatStatus::Active, PatStatus::Revoked, PatStatus::Expired] {
        assert_eq!(status.as_str().parse::<PatStatus>(), Ok(status));
    }
    assert!("Revoked".parse::<PatStatus>().is_err());
    assert!("".parse::<PatStatus>().is_err());
}

#[test]
fn test_pat_serde_roundtrip() {
    let pat = make_pat();
    let json = serde_json::to_string(&pat).unwrap();
    let parsed: PersonalAccessToken = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "CI deploy");
    assert_eq!(parsed.scopes, vec!["repos:read", "packages:write"]);
    assert_eq!(parsed.profile_id, pat.profile_id);
}

#[test]
fn test_pat_token_prefix_constant() {
    assert_eq!(PAT_TOKEN_PREFIX, "sid_pat_");
}

#[test]
fn test_pat_model_default() {
    assert_eq!(PatModel::default(), PatModel::OpaqueJwtSwap);
}

#[test]
fn test_pat_model_serde() {
    let m = PatModel::OpaqueJwtSwap;
    let json = serde_json::to_string(&m).unwrap();
    assert_eq!(json, "\"opaque_jwt_swap\"");
    let parsed: PatModel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, PatModel::OpaqueJwtSwap);
}

#[test]
fn test_pat_policy_constants() {
    assert_eq!(PAT_MAX_ACTIVE_PER_USER, 20);
    assert_eq!(PAT_MAX_LIFETIME_DAYS, 365);
    assert_eq!(PAT_AUTO_REVOKE_UNUSED_DAYS, 90);
    assert_eq!(PAT_NOTIFY_BEFORE_EXPIRY_DAYS, 14);
    assert_eq!(PAT_SWAP_JWT_LIFETIME_SECONDS, 300);
}
