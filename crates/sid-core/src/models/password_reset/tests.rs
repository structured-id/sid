use super::*;

#[test]
fn new_reset_session_defaults() {
    let pid = ProfileId::generate();
    let session = PasswordResetSession::new(pid, "a@b.com".into(), "hash123".into());

    assert_eq!(session.profile_id, pid);
    assert_eq!(session.email, "a@b.com");
    assert_eq!(session.status, ResetSessionStatus::Pending);
    assert!(!session.is_expired());
    assert!(session.verified_at.is_none());
    assert!(session.completed_at.is_none());
}

#[test]
fn reset_session_ttl() {
    assert_eq!(RESET_SESSION_TTL_SECS, 1800); // 30 minutes
}

#[test]
fn status_display() {
    assert_eq!(ResetSessionStatus::Pending.to_string(), "pending");
    assert_eq!(ResetSessionStatus::Verified.to_string(), "verified");
    assert_eq!(ResetSessionStatus::Completed.to_string(), "completed");
    assert_eq!(ResetSessionStatus::Expired.to_string(), "expired");
}

/// Every stored status reads back as itself; an unknown one is an error, not
/// `pending` (which would reopen a finished reset).
#[test]
fn status_parses_stored_names() {
    for s in [
        ResetSessionStatus::Pending,
        ResetSessionStatus::Verified,
        ResetSessionStatus::Completed,
        ResetSessionStatus::Expired,
    ] {
        assert_eq!(s.as_str().parse::<ResetSessionStatus>(), Ok(s));
    }
    assert!("done".parse::<ResetSessionStatus>().is_err());
}
