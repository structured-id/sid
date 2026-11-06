use super::*;
use uuid::Uuid;

#[test]
fn test_generate_pat_token_format() {
    let (token, hash, prefix) = generate_pat_token();
    assert!(token.starts_with("sid_pat_"));
    assert_eq!(token.len(), 40); // "sid_pat_" (8) + 32 chars
    assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
    assert_eq!(prefix.len(), 16);
    assert!(prefix.starts_with("sid_pat_"));
}

#[test]
fn test_generate_pat_token_unique() {
    let (t1, _, _) = generate_pat_token();
    let (t2, _, _) = generate_pat_token();
    assert_ne!(t1, t2);
}

#[test]
fn test_generate_pat_token_hash_correctness() {
    let (token, hash, _) = generate_pat_token();
    let expected = sha256_hex(token.as_bytes());
    assert_eq!(hash, expected);
}

#[test]
fn test_generate_pat_token_prefix_is_token_start() {
    let (token, _, prefix) = generate_pat_token();
    assert!(token.starts_with(&prefix));
}

#[test]
fn test_sha256_hex_known_value() {
    // SHA-256 of empty string is well-known.
    let hash = sha256_hex(b"");
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha256_hex_length() {
    let hash = sha256_hex(b"test data");
    assert_eq!(hash.len(), 64);
    // Must be valid hex.
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_pat_to_proto_active() {
    let pat = PersonalAccessToken::new(
        ProfileId::generate(),
        "test-pat",
        "hash123",
        "sid_pat_abcdefgh",
        vec!["read".into()],
    );

    let proto = pat_to_proto(&pat);
    assert_eq!(proto.name, "test-pat");
    assert_eq!(proto.token_prefix, "sid_pat_abcdefgh");
    assert_eq!(proto.scopes, vec!["read"]);
    assert_eq!(proto.status, ProtoPatStatus::Active as i32);
    assert!(proto.created_at.is_some());
    assert!(proto.expires_at.is_none());
    assert!(proto.last_used_at.is_none());
    assert!(proto.revoked_at.is_none());
    assert_eq!(proto.use_count, 0);
}

#[test]
fn test_pat_to_proto_revoked() {
    let mut pat = PersonalAccessToken::new(
        ProfileId::generate(),
        "revoked-pat",
        "hash456",
        "sid_pat_12345678",
        vec!["write".into()],
    );
    pat.as_active().unwrap().revoke(Some("admin-user".into()));

    let proto = pat_to_proto(&pat);
    assert_eq!(proto.status, ProtoPatStatus::Revoked as i32);
    assert!(proto.revoked_at.is_some());
    assert_eq!(proto.revoked_by, "admin-user");
}

#[test]
fn test_pat_to_proto_with_optional_fields() {
    let mut pat = PersonalAccessToken::new(
        ProfileId::generate(),
        "detailed-pat",
        "hash789",
        "sid_pat_xyzw1234",
        vec!["admin".into()],
    )
    .with_expires_at(chrono::Utc::now() + chrono::Duration::days(30));

    pat.description = Some("CI/CD deployment key".into());
    pat.record_use(Some("10.0.0.1".into()));

    let proto = pat_to_proto(&pat);
    assert_eq!(proto.description, "CI/CD deployment key");
    assert!(proto.expires_at.is_some());
    assert!(proto.last_used_at.is_some());
    assert_eq!(proto.last_used_ip, "10.0.0.1");
    assert_eq!(proto.use_count, 1);
}

/// A token's identifier crosses the wire as its 16 bytes, both ways.
#[test]
fn test_pat_id_is_carried_as_bytes() {
    let id = PatId::generate();
    let wire: sid_ids_proto::PatId = id.into();
    assert_eq!(wire.value, id.as_bytes());
    assert_eq!(
        convert::wire_id(Some(&wire), "pat_id").unwrap(),
        id,
        "the identifier read back is the one sent"
    );
}

/// A malformed or absent identifier is refused on its field before any
/// lookup.
#[test]
fn test_pat_id_refused_on_its_field() {
    for wire in [
        Some(sid_ids_proto::PatId { value: vec![7; 15] }),
        Some(sid_ids_proto::PatId {
            value: Uuid::new_v4().as_bytes().to_vec(),
        }),
        None,
    ] {
        let status = convert::wire_id(wire.as_ref(), "pat_id").unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("pat_id"), "{}", status.message());
    }
}

#[test]
fn test_generate_pat_token_base62_chars_only() {
    let (token, _, _) = generate_pat_token();
    let random_part = &token[8..]; // skip "sid_pat_"
    assert!(random_part.chars().all(|c| c.is_ascii_alphanumeric()));
}
