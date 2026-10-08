use super::*;
use sid_core::models::RevocationMode;

#[test]
fn test_revocation_request_profile_cascade_tracking() {
    let mut req = RevocationRequest::new(
        RevocationTarget::Profile,
        "profile-uuid-123",
        RevocationReason::Admin,
        "admin-uuid-456",
    );

    // Simulate cascade entries.
    req.add_cascade(
        RevocationTarget::Session,
        "session-1",
        CascadeTier::Immediate,
    );
    req.add_cascade(
        RevocationTarget::Session,
        "session-2",
        CascadeTier::Immediate,
    );
    req.add_cascade(RevocationTarget::Pat, "pat-1", CascadeTier::Fast);

    assert_eq!(req.cascade_entries.len(), 3);
    assert_eq!(req.total_revoked(), 4); // 1 primary + 3 cascade.
    assert!(!req.is_complete());

    req.complete();
    assert!(req.is_complete());
}

#[test]
fn test_revocation_request_session_cascade_tracking() {
    let mut req = RevocationRequest::new(
        RevocationTarget::Session,
        "session-uuid-123",
        RevocationReason::UserRequested,
        "profile-uuid-456",
    );

    req.add_cascade(
        RevocationTarget::RefreshToken,
        "session:session-uuid-123",
        CascadeTier::Immediate,
    );

    assert_eq!(req.cascade_entries.len(), 1);
    assert_eq!(req.total_revoked(), 2);
}

#[test]
fn test_revocation_request_machine_user_cascade_tracking() {
    let mut req = RevocationRequest::new(
        RevocationTarget::MachineUser,
        "mu-uuid-123",
        RevocationReason::Admin,
        "admin-uuid-456",
    );

    req.add_cascade(RevocationTarget::Credential, "kid-aaa", CascadeTier::Fast);
    req.add_cascade(RevocationTarget::Credential, "kid-bbb", CascadeTier::Fast);

    assert_eq!(req.cascade_entries.len(), 2);
    assert_eq!(req.total_revoked(), 3);

    // Verify cascade tiers.
    for entry in &req.cascade_entries {
        assert_eq!(entry.tier, CascadeTier::Fast);
        assert_eq!(entry.target, RevocationTarget::Credential);
    }
}

#[test]
fn test_revocation_request_pat_no_cascade() {
    let mut req = RevocationRequest::new(
        RevocationTarget::Pat,
        "pat-uuid-123",
        RevocationReason::UserRequested,
        "profile-uuid-456",
    );

    // PAT is a leaf node — no cascade entries.
    req.complete();
    assert!(req.cascade_entries.is_empty());
    assert_eq!(req.total_revoked(), 1);
    assert!(req.is_complete());
}

#[test]
fn test_emergency_revocation_uses_hard_mode() {
    let req = RevocationRequest::new(
        RevocationTarget::Profile,
        "profile-uuid",
        RevocationReason::Emergency,
        "system",
    );
    assert_eq!(req.mode, RevocationMode::Hard);
}

#[test]
fn test_user_requested_revocation_uses_graceful_mode() {
    let req = RevocationRequest::new(
        RevocationTarget::Session,
        "session-uuid",
        RevocationReason::UserRequested,
        "profile-uuid",
    );
    assert_eq!(req.mode, RevocationMode::Graceful);
}

#[test]
fn test_cascade_entries_have_timestamps() {
    let mut req = RevocationRequest::new(
        RevocationTarget::Profile,
        "profile-uuid",
        RevocationReason::Admin,
        "admin-uuid",
    );

    req.add_cascade(
        RevocationTarget::Session,
        "session-1",
        CascadeTier::Immediate,
    );

    let entry = &req.cascade_entries[0];
    // Timestamp should be recent (within last second).
    let elapsed = chrono::Utc::now() - entry.revoked_at;
    assert!(elapsed.num_seconds() < 2);
}
