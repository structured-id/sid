use super::*;

fn make_entry() -> AuditEntry {
    AuditEntry {
        actor_id: "prof_123".into(),
        actor_type: ActorType::User,
        action: "profile.email_changed".into(),
        resource: "prof_123".into(),
        outcome: AuditOutcome::Success,
        metadata: serde_json::json!({"field": "email"}),
        ip_address: Some("1.2.3.4".parse().unwrap()),
        device_id: None,
    }
}

fn make_record(chain_id: &str, seq: u64, prev_hash: AuditDigest) -> AuditRecord {
    let mut record = AuditRecord {
        id: format!("rec_{}", seq),
        timestamp: Timestamp::now(),
        chain_id: chain_id.into(),
        sequence: seq,
        actor_id: "actor".into(),
        actor_type: ActorType::User,
        action: "test.action".into(),
        resource: "resource".into(),
        outcome: AuditOutcome::Success,
        metadata: serde_json::Value::Null,
        ip_address: None,
        device_id: None,
        prev_hash,
        hash: AuditDigest::GENESIS,
    };
    record.hash = compute_record_hash(&record);
    record
}

#[test]
fn test_audit_entry_serde() {
    let entry = make_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.action, "profile.email_changed");
    assert_eq!(deserialized.actor_type, ActorType::User);
    assert_eq!(deserialized.outcome, AuditOutcome::Success);
}

#[test]
fn test_actor_type_display() {
    assert_eq!(ActorType::User.to_string(), "user");
    assert_eq!(ActorType::Admin.to_string(), "admin");
    assert_eq!(ActorType::Service.to_string(), "service");
    assert_eq!(ActorType::Machine.to_string(), "machine");
    assert_eq!(ActorType::Connector.to_string(), "connector");
    assert_eq!(ActorType::System.to_string(), "system");
}

#[test]
fn test_audit_entry_machine() {
    let entry = AuditEntry::machine("mu_client_123", "token.issue", "mu_client_123");
    assert_eq!(entry.actor_type, ActorType::Machine);
    assert_eq!(entry.actor_id, "mu_client_123");
    assert_eq!(entry.action, "token.issue");
}

/// A provisioning connector's entry names the connector as its actor and
/// keeps the display string and the stored form the same.
#[test]
fn test_audit_entry_connector() {
    let entry = AuditEntry::connector("conn_1", "scim.user.create", "prof_1");
    assert_eq!(entry.actor_type, ActorType::Connector);
    assert_eq!(entry.actor_id, "conn_1");
    assert_eq!(
        serde_json::to_value(ActorType::Connector).unwrap(),
        serde_json::json!("connector")
    );
}

#[test]
fn test_outcome_display() {
    assert_eq!(AuditOutcome::Success.to_string(), "success");
    assert_eq!(AuditOutcome::Failure.to_string(), "failure");
    assert_eq!(AuditOutcome::Denied.to_string(), "denied");
}

#[test]
fn test_compute_record_hash_deterministic() {
    let record = make_record("profile:prof_123", 1, AuditDigest::GENESIS);
    let hash1 = compute_record_hash(&record);
    let hash2 = compute_record_hash(&record);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_compute_record_hash_changes_with_data() {
    let r1 = make_record("profile:prof_123", 1, AuditDigest::GENESIS);
    let mut r2 = r1.clone();
    r2.action = "different.action".into();
    r2.hash = compute_record_hash(&r2);

    assert_ne!(r1.hash, r2.hash);
}

/// The digest covers the link: the same record linked to another
/// predecessor has another digest, so a record cannot be moved in a chain.
#[test]
fn test_compute_record_hash_covers_the_link() {
    let record = make_record("chain1", 2, AuditDigest([7; 32]));
    let mut relinked = record.clone();
    relinked.prev_hash = AuditDigest([8; 32]);
    assert_ne!(compute_record_hash(&record), compute_record_hash(&relinked));
}

/// A field's content cannot be read as the boundary of the next: moving text
/// from one field into its neighbour changes the digest, as joining the
/// fields with a separator did not.
#[test]
fn test_compute_record_hash_keeps_field_boundaries() {
    let mut a = make_record("chain1", 1, AuditDigest::GENESIS);
    a.actor_id = "alice|profile".into();
    a.action = "deleted".into();
    let mut b = a.clone();
    b.actor_id = "alice".into();
    b.action = "profile|deleted".into();
    assert_ne!(compute_record_hash(&a), compute_record_hash(&b));
}

#[test]
fn test_verify_record_hash_valid() {
    let record = make_record("chain1", 1, AuditDigest::GENESIS);
    assert!(verify_record_hash(&record));
}

#[test]
fn test_verify_record_hash_tampered() {
    let mut record = make_record("chain1", 1, AuditDigest::GENESIS);
    record.action = "tampered.action".into(); // Tamper without recomputing hash
    assert!(!verify_record_hash(&record));
}

/// A stored digest is exactly 32 bytes; any other length is a damaged
/// record, never read as some other digest.
#[test]
fn test_stored_digest_is_32_bytes() {
    let bytes = [9u8; 32];
    assert_eq!(
        AuditDigest::stored(&bytes, "hash").unwrap(),
        AuditDigest(bytes)
    );
    for len in [0, 31, 33, 64] {
        assert!(
            AuditDigest::stored(&vec![1u8; len], "hash").is_err(),
            "{len} bytes"
        );
    }
}

#[test]
fn test_chain_head_serde() {
    let head = ChainHead {
        chain_id: "profile:prof_123".into(),
        last_record_id: "rec_5".into(),
        last_hash: AuditDigest([3; 32]),
        sequence: 5,
    };

    let json = serde_json::to_string(&head).unwrap();
    let deserialized: ChainHead = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, head);
}

#[test]
fn test_audit_error_display() {
    let err = AuditError::IntegrityViolation {
        record_id: "rec_42".into(),
    };
    assert_eq!(
        err.to_string(),
        "chain integrity violation at record rec_42"
    );

    let err = AuditError::ChainNotFound("chain1".into());
    assert_eq!(err.to_string(), "chain not found: chain1");
}
