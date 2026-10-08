use super::*;

#[test]
fn test_invite_id_unique() {
    let id1 = InviteId::new();
    let id2 = InviteId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_invite_status_default() {
    assert_eq!(InviteStatus::default(), InviteStatus::Active);
}

#[test]
fn test_invite_status_serde() {
    let s = InviteStatus::Consumed;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"consumed\"");
    let parsed: InviteStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, InviteStatus::Consumed);
}

#[test]
fn test_invite_status_as_str() {
    assert_eq!(InviteStatus::Active.as_str(), "active");
    assert_eq!(InviteStatus::Consumed.as_str(), "consumed");
    assert_eq!(InviteStatus::Revoked.as_str(), "revoked");
    assert_eq!(InviteStatus::Expired.as_str(), "expired");
}

fn make_test_invite() -> Invite {
    Invite {
        id: InviteId::new(),
        code: "ABCD1234".to_string(),
        created_by: ProfileId::generate(),
        created_by_name: "Admin".to_string(),
        metadata: std::collections::HashMap::new(),
        max_uses: 1,
        use_count: 0,
        expires_at: None,
        active: true,
        created_at: Utc::now(),
    }
}

#[test]
fn test_invite_status_active() {
    let invite = make_test_invite();
    assert_eq!(invite.status(), InviteStatus::Active);
    assert!(invite.is_usable());
}

#[test]
fn test_invite_status_consumed() {
    let mut invite = make_test_invite();
    invite.use_count = 1;
    assert_eq!(invite.status(), InviteStatus::Consumed);
    assert!(!invite.is_usable());
}

#[test]
fn test_invite_status_consumed_unlimited() {
    let mut invite = make_test_invite();
    invite.max_uses = 0; // unlimited
    invite.use_count = 999;
    assert_eq!(invite.status(), InviteStatus::Active);
    assert!(invite.is_usable());
}

#[test]
fn test_invite_status_revoked() {
    let mut invite = make_test_invite();
    invite.revoke();
    assert_eq!(invite.status(), InviteStatus::Revoked);
    assert!(!invite.is_usable());
}

#[test]
fn test_invite_status_expired() {
    let mut invite = make_test_invite();
    invite.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    assert_eq!(invite.status(), InviteStatus::Expired);
    assert!(!invite.is_usable());
}

#[test]
fn test_invite_revoke_overrides_expiry() {
    let mut invite = make_test_invite();
    invite.expires_at = Some(Utc::now() + chrono::Duration::hours(24));
    invite.revoke();
    assert_eq!(invite.status(), InviteStatus::Revoked);
}

#[test]
fn test_invite_serde_roundtrip() {
    let invite = make_test_invite();
    let json = serde_json::to_string(&invite).unwrap();
    let parsed: Invite = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.id, invite.id);
    assert_eq!(parsed.code, "ABCD1234");
    assert_eq!(parsed.max_uses, 1);
    assert!(parsed.active);
}

#[test]
fn test_generate_invite_code_length() {
    let code = generate_invite_code();
    assert_eq!(code.len(), INVITE_CODE_LENGTH);
}

#[test]
fn test_generate_invite_code_alphabet() {
    for _ in 0..100 {
        let code = generate_invite_code();
        for ch in code.chars() {
            assert!(
                INVITE_ALPHABET.contains(&(ch as u8)),
                "unexpected char: {}",
                ch
            );
        }
    }
}

#[test]
fn test_generate_invite_code_uniqueness() {
    let codes: std::collections::HashSet<String> =
        (0..100).map(|_| generate_invite_code()).collect();
    assert!(codes.len() >= 95, "too many collisions: {}", codes.len());
}

#[test]
fn test_normalize_invite_code() {
    assert_eq!(normalize_invite_code("abcd1234"), "ABCD1234");
    assert_eq!(normalize_invite_code("  ABCD1234  "), "ABCD1234");
    assert_eq!(normalize_invite_code("AbCd1234"), "ABCD1234");
}

/// The search pattern is a substring match in which the text's own
/// wildcards and escape character match themselves: "50%" finds "50%",
/// never every text starting with "50".
#[test]
fn test_search_pattern_escapes_wildcards() {
    let filter = |s: &str| InviteFilter {
        status: None,
        search: Some(s.to_string()),
    };
    assert_eq!(filter("abc").search_pattern().as_deref(), Some("%abc%"));
    assert_eq!(filter("50%").search_pattern().as_deref(), Some("%50\\%%"));
    assert_eq!(filter("a_b").search_pattern().as_deref(), Some("%a\\_b%"));
    assert_eq!(filter("a\\b").search_pattern().as_deref(), Some("%a\\\\b%"));
    assert_eq!(InviteFilter::default().search_pattern(), None);
}
