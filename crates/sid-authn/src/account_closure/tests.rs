use super::*;

#[test]
fn test_hash_principal_deterministic() {
    let h1 = AccountClosureService::hash_principal("email", "alice@sid.example.com");
    let h2 = AccountClosureService::hash_principal("email", "alice@sid.example.com");
    assert_eq!(h1, h2);
}

#[test]
fn test_hash_principal_different_values() {
    let h1 = AccountClosureService::hash_principal("email", "alice@sid.example.com");
    let h2 = AccountClosureService::hash_principal("email", "bob@sid.example.com");
    assert_ne!(h1, h2);
}

#[test]
fn test_hash_principal_different_types() {
    let h1 = AccountClosureService::hash_principal("email", "test");
    let h2 = AccountClosureService::hash_principal("phone", "test");
    assert_ne!(h1, h2);
}

#[test]
fn test_hash_principal_length() {
    let h = AccountClosureService::hash_principal("email", "test@sid.example.com");
    assert_eq!(h.len(), 64); // SHA-256 hex = 64 chars.
}

#[test]
fn test_hash_principal_hex_format() {
    let h = AccountClosureService::hash_principal("email", "test@sid.example.com");
    // All characters must be lowercase hex.
    assert!(
        h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn test_hash_principal_type_prefix_prevents_collision() {
    // Same value but different types must produce different hashes.
    let h1 = AccountClosureService::hash_principal("email", "alice@sid.example.com");
    let h2 = AccountClosureService::hash_principal("phone", "alice@sid.example.com");
    assert_ne!(h1, h2);
}

#[test]
fn test_closure_mode_grace_periods() {
    assert_eq!(ClosureMode::Voluntary.max_grace_period_days(), 30);
    assert_eq!(ClosureMode::GdprErasure.max_grace_period_days(), 30);
    assert_eq!(ClosureMode::AdminTermination.max_grace_period_days(), 7);
    assert_eq!(ClosureMode::RegulatoryOrder.max_grace_period_days(), 0);
}

#[test]
fn test_closure_mode_cancellable() {
    assert!(ClosureMode::Voluntary.is_cancellable());
    assert!(ClosureMode::GdprErasure.is_cancellable());
    assert!(!ClosureMode::AdminTermination.is_cancellable());
    assert!(!ClosureMode::RegulatoryOrder.is_cancellable());
}

#[test]
fn test_profile_status_closing_states() {
    assert!(ProfileStatus::ClosureRequested.is_closing());
    assert!(ProfileStatus::ExportAvailable.is_closing());
    assert!(ProfileStatus::GracePeriod.is_closing());
    assert!(!ProfileStatus::Active.is_closing());
    assert!(!ProfileStatus::Closed.is_closing());
    assert!(!ProfileStatus::Purged.is_closing());
}

#[test]
fn test_profile_status_valid_transitions_to_closure() {
    assert!(
        ProfileStatus::Active
            .transition_to(ProfileStatus::ClosureRequested)
            .is_ok()
    );
    assert!(
        ProfileStatus::Suspended
            .transition_to(ProfileStatus::ClosureRequested)
            .is_ok()
    );
}

#[test]
fn test_profile_status_invalid_transitions_to_closure() {
    assert!(
        ProfileStatus::Closed
            .transition_to(ProfileStatus::ClosureRequested)
            .is_err()
    );
    assert!(
        ProfileStatus::Purged
            .transition_to(ProfileStatus::ClosureRequested)
            .is_err()
    );
}

#[test]
fn test_closure_request_with_grace_period() {
    let pid = ProfileId::generate();
    let req = ClosureRequest::new(pid, ClosureMode::Voluntary, pid).with_grace_period_days(30);
    assert!(req.grace_period_end.is_some());
    assert!(!req.grace_period_elapsed());
}

#[test]
fn test_closure_constants() {
    assert_eq!(MAX_CANCEL_CYCLES_PER_YEAR, 3);
    assert_eq!(IDENTIFIER_QUARANTINE_DAYS, 90);
}
