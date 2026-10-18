use super::*;

fn prepared() -> CaGeneration {
    CaGeneration {
        id: CaGenerationId::new(),
        scope: CaScope::Deployment,
        generation: 1,
        key: KeyCustody::Sealed(vec![1]),
        certificate: None,
        database_recovery: None,
        key_recovery: None,
        state: CaState::Prepared,
        revision: 1,
        last_serial: 0,
        prepared_at: Utc::now(),
    }
}

fn confirmation() -> RecoveryConfirmation {
    RecoveryConfirmation {
        reference: "backup-2026-10-18".into(),
        confirmed_by: "operator".into(),
        confirmed_at: Utc::now(),
    }
}

// Activation needs the certificate and both recovery confirmations, on a
// prepared generation; missing any one, it is not admitted.
#[test]
fn activatable_needs_certificate_and_both_confirmations() {
    let mut g = prepared();
    assert!(!g.activatable());
    g.certificate = Some(vec![0x30]);
    assert!(!g.activatable());
    g.database_recovery = Some(confirmation());
    assert!(!g.activatable());
    g.key_recovery = Some(confirmation());
    assert!(g.activatable());
    for state in [CaState::Current, CaState::Retired, CaState::Revoked] {
        g.state = state;
        assert!(!g.activatable(), "{state:?}");
    }
}

// The fingerprint is the SHA-256 of the stored DER, absent without one.
#[test]
fn certificate_fingerprint_is_its_sha256() {
    let mut g = prepared();
    assert_eq!(g.certificate_sha256(), None);
    g.certificate = Some(b"abc".to_vec());
    assert_eq!(
        hex::encode(g.certificate_sha256().unwrap()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// A confirmation read back at microsecond precision is the one given; a
// different instant, reference or confirmer is not.
#[test]
fn confirmation_identity_ignores_sub_microseconds() {
    use chrono::Timelike;
    let given = RecoveryConfirmation {
        confirmed_at: Utc::now().with_nanosecond(123_456_789).unwrap(),
        ..confirmation()
    };
    let stored = RecoveryConfirmation {
        confirmed_at: given.confirmed_at.with_nanosecond(123_456_000).unwrap(),
        ..given.clone()
    };
    assert!(stored.is_same(&given));
    let later = RecoveryConfirmation {
        confirmed_at: given.confirmed_at.with_nanosecond(123_457_000).unwrap(),
        ..given.clone()
    };
    assert!(!later.is_same(&given));
    let other = RecoveryConfirmation {
        reference: "other".into(),
        ..given.clone()
    };
    assert!(!other.is_same(&given));
}

// The retirement entry keeps the activation's actor and origin and names the
// retired generation and its successor.
#[test]
fn retirement_entry_names_retired_and_successor() {
    let activation = crate::models::AuditEntry {
        ip_address: Some("192.0.2.1".into()),
        ..crate::models::AuditEntry::system("ca", "ca_generation.activated")
    };
    let (retired, by) = (CaGenerationId::new(), CaGenerationId::new());
    let entry = ca_retirement_entry(&activation, retired, by);
    assert_eq!(entry.actor_id, activation.actor_id);
    assert_eq!(entry.ip_address.as_deref(), Some("192.0.2.1"));
    assert_eq!(entry.action, "ca_generation.retired");
    assert_eq!(entry.resource, retired.to_string());
    assert_eq!(entry.metadata["replaced_by"], by.to_string());
    assert_eq!(
        ca_generation_chain(retired),
        format!("ca_generation:{retired}")
    );
}

// Storage names round-trip and unknown names are refused.
#[test]
fn state_names_round_trip() {
    for state in [
        CaState::Prepared,
        CaState::Current,
        CaState::Retired,
        CaState::Revoked,
    ] {
        assert_eq!(CaState::parse(state.as_str()), Some(state));
    }
    assert_eq!(CaState::parse("active"), None);
}
