use super::*;

fn prepared() -> CaGeneration {
    CaGeneration {
        id: CaGenerationId::new(),
        scope: CaScope::Deployment,
        generation: 1,
        keys: CaKeys {
            classical: KeyCustody::Sealed(vec![1]),
            alternative: None,
        },
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
