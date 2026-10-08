use super::*;

fn make_entry() -> AuditEntry {
    AuditEntry {
        actor_id: "prof_123".into(),
        actor_type: ActorType::User,
        action: "profile.email_changed".into(),
        resource: "prof_123".into(),
        outcome: AuditOutcome::Success,
        metadata: serde_json::json!({"field": "email"}),
        ip_address: Some("1.2.3.4".into()),
        device_id: None,
    }
}

fn make_record(chain_id: &str, seq: u64, prev_hash: &str) -> AuditRecord {
    let mut record = AuditRecord {
        id: format!("rec_{}", seq),
        timestamp: Utc::now(),
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
        prev_hash: prev_hash.into(),
        hash: String::new(),
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
    let record = make_record("profile:prof_123", 1, "genesis");
    let hash1 = compute_record_hash(&record);
    let hash2 = compute_record_hash(&record);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_compute_record_hash_changes_with_data() {
    let r1 = make_record("profile:prof_123", 1, "genesis");
    let mut r2 = r1.clone();
    r2.action = "different.action".into();
    r2.hash = compute_record_hash(&r2);

    assert_ne!(r1.hash, r2.hash);
}

#[test]
fn test_verify_record_hash_valid() {
    let record = make_record("chain1", 1, "genesis");
    assert!(verify_record_hash(&record));
}

#[test]
fn test_verify_record_hash_tampered() {
    let mut record = make_record("chain1", 1, "genesis");
    record.action = "tampered.action".into(); // Tamper without recomputing hash
    assert!(!verify_record_hash(&record));
}

#[test]
fn test_chain_head_serde() {
    let head = ChainHead {
        chain_id: "profile:prof_123".into(),
        last_record_id: "rec_5".into(),
        last_hash: "abc123".into(),
        sequence: 5,
    };

    let json = serde_json::to_string(&head).unwrap();
    let deserialized: ChainHead = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.chain_id, "profile:prof_123");
    assert_eq!(deserialized.sequence, 5);
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
