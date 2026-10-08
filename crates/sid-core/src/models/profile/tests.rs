use super::*;

#[test]
fn test_profile_new_defaults() {
    let profile = Profile::new(Some("alice"));
    assert_eq!(profile.username.as_deref(), Some("alice"));
    assert_eq!(profile.profile_type, ProfileType::Personal);
    assert_eq!(profile.status, ProfileStatus::Active);
    assert_eq!(profile.visibility, ProfileVisibility::Public);
    assert_eq!(profile.max_assurance, ProfileAssurance::Anonymous);
    // email/phone are now in profile_emails/profile_phones tables
    assert!(profile.given_name.is_none());
    assert!(profile.family_name.is_none());
    assert!(profile.formatted_name().is_none());
    assert!(profile.manager_id.is_none());
    assert!(profile.roles.is_empty());
}

#[test]
fn test_profile_new_from_string() {
    let name = String::from("bob");
    let profile = Profile::new(Some(name));
    assert_eq!(profile.username.as_deref(), Some("bob"));
}

#[test]
fn test_has_role() {
    let mut profile = Profile::new(Some("alice"));
    assert!(!profile.has_role("admin"));
    assert!(!profile.is_admin());

    profile.roles = vec!["admin".to_string()];
    assert!(profile.has_role("admin"));
    assert!(profile.is_admin());
    assert!(!profile.has_role("operator"));
}

#[test]
fn test_profile_id_unique() {
    let id1 = ProfileId::generate();
    let id2 = ProfileId::generate();
    assert_ne!(id1, id2);
}

#[test]
fn test_profile_type_as_str() {
    assert_eq!(ProfileType::Personal.as_str(), "personal");
    assert_eq!(ProfileType::Corporate.as_str(), "corporate");
}

#[test]
fn test_profile_type_default() {
    assert_eq!(ProfileType::default(), ProfileType::Personal);
}

#[test]
fn test_profile_type_serde_roundtrip() {
    let t = ProfileType::Corporate;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"corporate\"");
    let parsed: ProfileType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ProfileType::Corporate);
}

#[test]
fn test_profile_status_as_str() {
    assert_eq!(ProfileStatus::Active.as_str(), "active");
    assert_eq!(ProfileStatus::Suspended.as_str(), "suspended");
    assert_eq!(
        ProfileStatus::ClosureRequested.as_str(),
        "closure_requested"
    );
    assert_eq!(ProfileStatus::ExportAvailable.as_str(), "export_available");
    assert_eq!(ProfileStatus::GracePeriod.as_str(), "grace_period");
    assert_eq!(ProfileStatus::LegalHold.as_str(), "legal_hold");
    assert_eq!(ProfileStatus::Closed.as_str(), "closed");
    assert_eq!(ProfileStatus::Purged.as_str(), "purged");
}

#[test]
fn test_profile_status_is_active() {
    assert!(ProfileStatus::Active.is_active());
    assert!(!ProfileStatus::Suspended.is_active());
    assert!(!ProfileStatus::ClosureRequested.is_active());
    assert!(!ProfileStatus::Closed.is_active());
}

#[test]
fn test_profile_status_can_authenticate() {
    // Only Active allows new sessions per arch spec.
    assert!(ProfileStatus::Active.can_authenticate());
    assert!(!ProfileStatus::Suspended.can_authenticate());
    assert!(!ProfileStatus::ClosureRequested.can_authenticate());
    assert!(!ProfileStatus::ExportAvailable.can_authenticate());
    assert!(!ProfileStatus::GracePeriod.can_authenticate());
    assert!(!ProfileStatus::LegalHold.can_authenticate());
    assert!(!ProfileStatus::Closed.can_authenticate());
    assert!(!ProfileStatus::Purged.can_authenticate());
    // Provisioned profiles MUST NOT authenticate: the user must claim first.
    assert!(!ProfileStatus::Provisioned.can_authenticate());
}

#[test]
fn test_profile_status_can_access_read_only() {
    assert!(ProfileStatus::Active.can_access_read_only());
    assert!(ProfileStatus::ClosureRequested.can_access_read_only());
    assert!(ProfileStatus::ExportAvailable.can_access_read_only());
    assert!(ProfileStatus::GracePeriod.can_access_read_only());
    assert!(!ProfileStatus::Suspended.can_access_read_only());
    assert!(!ProfileStatus::LegalHold.can_access_read_only());
    assert!(!ProfileStatus::Closed.can_access_read_only());
    assert!(!ProfileStatus::Purged.can_access_read_only());
}

#[test]
fn test_profile_status_is_closing() {
    assert!(!ProfileStatus::Active.is_closing());
    assert!(ProfileStatus::ClosureRequested.is_closing());
    assert!(ProfileStatus::ExportAvailable.is_closing());
    assert!(ProfileStatus::GracePeriod.is_closing());
    assert!(!ProfileStatus::Closed.is_closing());
}

#[test]
fn test_profile_status_is_frozen() {
    assert!(ProfileStatus::LegalHold.is_frozen());
    assert!(!ProfileStatus::Active.is_frozen());
    assert!(!ProfileStatus::Closed.is_frozen());
}

#[test]
fn test_profile_status_is_terminal() {
    assert!(!ProfileStatus::Active.is_terminal());
    assert!(!ProfileStatus::Suspended.is_terminal());
    assert!(ProfileStatus::Closed.is_terminal());
    assert!(ProfileStatus::Purged.is_terminal());
}

#[test]
fn test_profile_status_default() {
    assert_eq!(ProfileStatus::default(), ProfileStatus::Active);
}

#[test]
fn test_profile_status_serde_roundtrip() {
    let s = ProfileStatus::Closed;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"closed\"");
    let parsed: ProfileStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ProfileStatus::Closed);
}

#[test]
fn test_profile_status_serde_closure_requested() {
    let s = ProfileStatus::ClosureRequested;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"closure_requested\"");
    let parsed: ProfileStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ProfileStatus::ClosureRequested);
}

// ── State transition tests ──────────────────────────────────

#[test]
fn test_transition_active_to_suspended() {
    assert!(
        ProfileStatus::Active
            .transition_to(ProfileStatus::Suspended)
            .is_ok()
    );
}

#[test]
fn test_transition_active_to_closure_requested() {
    assert!(
        ProfileStatus::Active
            .transition_to(ProfileStatus::ClosureRequested)
            .is_ok()
    );
}

#[test]
fn test_transition_suspended_to_active() {
    assert!(
        ProfileStatus::Suspended
            .transition_to(ProfileStatus::Active)
            .is_ok()
    );
}

#[test]
fn test_transition_closure_requested_cancel() {
    assert!(
        ProfileStatus::ClosureRequested
            .transition_to(ProfileStatus::Active)
            .is_ok()
    );
}

#[test]
fn test_transition_closure_requested_to_export() {
    assert!(
        ProfileStatus::ClosureRequested
            .transition_to(ProfileStatus::ExportAvailable)
            .is_ok()
    );
}

#[test]
fn test_transition_closure_requested_to_grace() {
    assert!(
        ProfileStatus::ClosureRequested
            .transition_to(ProfileStatus::GracePeriod)
            .is_ok()
    );
}

#[test]
fn test_transition_export_available_to_grace() {
    assert!(
        ProfileStatus::ExportAvailable
            .transition_to(ProfileStatus::GracePeriod)
            .is_ok()
    );
}

#[test]
fn test_transition_export_available_cancel() {
    assert!(
        ProfileStatus::ExportAvailable
            .transition_to(ProfileStatus::Active)
            .is_ok()
    );
}

#[test]
fn test_transition_to_legal_hold() {
    assert!(
        ProfileStatus::Active
            .transition_to(ProfileStatus::LegalHold)
            .is_ok()
    );
    assert!(
        ProfileStatus::GracePeriod
            .transition_to(ProfileStatus::LegalHold)
            .is_ok()
    );
    assert!(
        ProfileStatus::ClosureRequested
            .transition_to(ProfileStatus::LegalHold)
            .is_ok()
    );
    // Terminal states cannot transition to LegalHold.
    assert!(
        ProfileStatus::Closed
            .transition_to(ProfileStatus::LegalHold)
            .is_err()
    );
    assert!(
        ProfileStatus::Purged
            .transition_to(ProfileStatus::LegalHold)
            .is_err()
    );
}

#[test]
fn test_transition_from_legal_hold() {
    // Can restore to non-terminal states.
    assert!(
        ProfileStatus::LegalHold
            .transition_to(ProfileStatus::Active)
            .is_ok()
    );
    assert!(
        ProfileStatus::LegalHold
            .transition_to(ProfileStatus::GracePeriod)
            .is_ok()
    );
    // Cannot go directly to terminal from LegalHold.
    assert!(
        ProfileStatus::LegalHold
            .transition_to(ProfileStatus::Closed)
            .is_err()
    );
    assert!(
        ProfileStatus::LegalHold
            .transition_to(ProfileStatus::Purged)
            .is_err()
    );
}

#[test]
fn test_transition_grace_period_to_closed() {
    assert!(
        ProfileStatus::GracePeriod
            .transition_to(ProfileStatus::Closed)
            .is_ok()
    );
}

#[test]
fn test_transition_grace_period_cancel() {
    assert!(
        ProfileStatus::GracePeriod
            .transition_to(ProfileStatus::Active)
            .is_ok()
    );
}

#[test]
fn test_transition_closed_to_purged() {
    assert!(
        ProfileStatus::Closed
            .transition_to(ProfileStatus::Purged)
            .is_ok()
    );
}

#[test]
fn test_transition_invalid_active_to_closed() {
    assert!(
        ProfileStatus::Active
            .transition_to(ProfileStatus::Closed)
            .is_err()
    );
}

#[test]
fn test_transition_invalid_closed_to_active() {
    assert!(
        ProfileStatus::Closed
            .transition_to(ProfileStatus::Active)
            .is_err()
    );
}

#[test]
fn test_transition_invalid_purged_to_anything() {
    assert!(
        ProfileStatus::Purged
            .transition_to(ProfileStatus::Active)
            .is_err()
    );
    assert!(
        ProfileStatus::Purged
            .transition_to(ProfileStatus::Closed)
            .is_err()
    );
}

#[test]
fn test_transition_same_state_is_noop() {
    assert!(
        ProfileStatus::Active
            .transition_to(ProfileStatus::Active)
            .is_ok()
    );
    assert!(
        ProfileStatus::Closed
            .transition_to(ProfileStatus::Closed)
            .is_ok()
    );
}

// ── Closure mode tests ──────────────────────────────────────

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
fn test_closure_constants() {
    assert_eq!(MAX_CANCEL_CYCLES_PER_YEAR, 3);
    assert_eq!(IDENTIFIER_QUARANTINE_DAYS, 90);
}

#[test]
fn test_closure_mode_serde_roundtrip() {
    let m = ClosureMode::GdprErasure;
    let json = serde_json::to_string(&m).unwrap();
    assert_eq!(json, "\"gdpr_erasure\"");
    let parsed: ClosureMode = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ClosureMode::GdprErasure);
}

// ── ClosureRequest tests ────────────────────────────────────

#[test]
fn test_closure_request_new() {
    let pid = ProfileId::generate();
    let admin = ProfileId::generate();
    let req = ClosureRequest::new(pid, ClosureMode::Voluntary, admin);
    assert_eq!(req.profile_id, pid);
    assert_eq!(req.requested_by, admin);
    assert_eq!(req.mode, ClosureMode::Voluntary);
    assert_eq!(req.export_status, ExportStatus::NotStarted);
    assert!(req.legal_hold.is_none());
    assert!(req.closure_reason.is_none());
    assert_eq!(req.cancel_count, 0);
    assert!(req.grace_period_end.is_none());
    assert!(!req.grace_period_elapsed());
}

#[test]
fn test_closure_request_with_grace_period() {
    let pid = ProfileId::generate();
    let req = ClosureRequest::new(pid, ClosureMode::Voluntary, pid).with_grace_period_days(30);
    assert!(req.grace_period_end.is_some());
    assert!(!req.grace_period_elapsed());
}

#[test]
fn test_closure_request_grace_period_elapsed() {
    let pid = ProfileId::generate();
    let mut req = ClosureRequest::new(pid, ClosureMode::GdprErasure, pid);
    req.grace_period_end = Some(Utc::now() - chrono::Duration::seconds(1));
    assert!(req.grace_period_elapsed());
}

#[test]
fn test_profile_visibility_as_str() {
    assert_eq!(ProfileVisibility::Public.as_str(), "public");
    assert_eq!(ProfileVisibility::Private.as_str(), "private");
}

#[test]
fn test_profile_visibility_default() {
    assert_eq!(ProfileVisibility::default(), ProfileVisibility::Public);
}

#[test]
fn test_profile_visibility_serde_roundtrip() {
    let v = ProfileVisibility::Private;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"private\"");
    let parsed: ProfileVisibility = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ProfileVisibility::Private);
}

// ── ProfileAssurance tests ──────────────────────────────────

#[test]
fn test_profile_assurance_ordering() {
    assert!(ProfileAssurance::Anonymous < ProfileAssurance::SelfDeclared);
    assert!(ProfileAssurance::SelfDeclared < ProfileAssurance::Attested);
    assert!(ProfileAssurance::Attested < ProfileAssurance::Verified);
    assert!(ProfileAssurance::Verified < ProfileAssurance::Certified);
}

#[test]
fn test_profile_assurance_satisfies() {
    assert!(ProfileAssurance::Verified.satisfies(ProfileAssurance::Anonymous));
    assert!(ProfileAssurance::Verified.satisfies(ProfileAssurance::Verified));
    assert!(!ProfileAssurance::Attested.satisfies(ProfileAssurance::Verified));
    assert!(ProfileAssurance::Certified.satisfies(ProfileAssurance::Certified));
}

#[test]
fn test_profile_assurance_default() {
    assert_eq!(ProfileAssurance::default(), ProfileAssurance::Anonymous);
}

#[test]
fn test_profile_assurance_serde_roundtrip() {
    let a = ProfileAssurance::SelfDeclared;
    let json = serde_json::to_string(&a).unwrap();
    assert_eq!(json, "\"self_declared\"");
    let parsed: ProfileAssurance = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ProfileAssurance::SelfDeclared);
}

#[test]
fn test_profile_assurance_as_str() {
    assert_eq!(ProfileAssurance::Anonymous.as_str(), "anonymous");
    assert_eq!(ProfileAssurance::SelfDeclared.as_str(), "self_declared");
    assert_eq!(ProfileAssurance::Attested.as_str(), "attested");
    assert_eq!(ProfileAssurance::Verified.as_str(), "verified");
    assert_eq!(ProfileAssurance::Certified.as_str(), "certified");
}

// ── Transition Gateway tests ──────────────────────────────────

#[test]
fn test_as_active_returns_some_for_active() {
    let mut p = Profile::new(Some("alice"));
    assert!(p.as_active().is_some());
}

#[test]
fn test_as_active_returns_none_for_non_active() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::Suspended;
    assert!(p.as_active().is_none());
}

#[test]
fn test_active_gateway_suspend() {
    let mut p = Profile::new(Some("alice"));
    p.as_active().unwrap().suspend();
    assert_eq!(p.status, ProfileStatus::Suspended);
}

#[test]
fn test_active_gateway_request_closure() {
    let mut p = Profile::new(Some("alice"));
    p.as_active().unwrap().request_closure();
    assert_eq!(p.status, ProfileStatus::ClosureRequested);
}

#[test]
fn test_active_gateway_legal_hold() {
    let mut p = Profile::new(Some("alice"));
    p.as_active().unwrap().place_legal_hold();
    assert_eq!(p.status, ProfileStatus::LegalHold);
}

#[test]
fn test_suspended_gateway_reactivate() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::Suspended;
    p.as_suspended().unwrap().reactivate();
    assert_eq!(p.status, ProfileStatus::Active);
}

#[test]
fn test_suspended_gateway_request_closure() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::Suspended;
    p.as_suspended().unwrap().request_closure();
    assert_eq!(p.status, ProfileStatus::ClosureRequested);
}

#[test]
fn test_as_suspended_returns_none_for_active() {
    let mut p = Profile::new(Some("alice"));
    assert!(p.as_suspended().is_none());
}

#[test]
fn test_closing_gateway_cancel() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::ClosureRequested;
    p.as_closing().unwrap().cancel();
    assert_eq!(p.status, ProfileStatus::Active);
}

#[test]
fn test_closing_gateway_export_available() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::ClosureRequested;
    assert!(p.as_closing().unwrap().export_available().is_ok());
    assert_eq!(p.status, ProfileStatus::ExportAvailable);
}

#[test]
fn test_closing_gateway_start_grace_period() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::ClosureRequested;
    assert!(p.as_closing().unwrap().start_grace_period().is_ok());
    assert_eq!(p.status, ProfileStatus::GracePeriod);
}

#[test]
fn test_closing_gateway_close_from_grace() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::GracePeriod;
    assert!(p.as_closing().unwrap().close().is_ok());
    assert_eq!(p.status, ProfileStatus::Closed);
}

#[test]
fn test_closing_gateway_close_from_closure_requested_fails() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::ClosureRequested;
    // Cannot close directly from ClosureRequested — must go through GracePeriod
    assert!(p.as_closing().unwrap().close().is_err());
}

#[test]
fn test_as_closing_returns_none_for_active() {
    let mut p = Profile::new(Some("alice"));
    assert!(p.as_closing().is_none());
}

#[test]
fn test_closed_gateway_purge() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::Closed;
    p.as_closed().unwrap().purge();
    assert_eq!(p.status, ProfileStatus::Purged);
}

#[test]
fn test_as_closed_returns_none_for_active() {
    let mut p = Profile::new(Some("alice"));
    assert!(p.as_closed().is_none());
}

#[test]
fn test_transition_status_valid() {
    let mut p = Profile::new(Some("alice"));
    assert!(p.transition_status(ProfileStatus::Suspended).is_ok());
    assert_eq!(p.status, ProfileStatus::Suspended);
}

#[test]
fn test_transition_status_invalid() {
    let mut p = Profile::new(Some("alice"));
    // Active → Closed is not allowed (must go through closure flow)
    assert!(p.transition_status(ProfileStatus::Closed).is_err());
    assert_eq!(p.status, ProfileStatus::Active);
}

#[test]
fn test_transition_status_noop() {
    let mut p = Profile::new(Some("alice"));
    assert!(p.transition_status(ProfileStatus::Active).is_ok());
    assert_eq!(p.status, ProfileStatus::Active);
}

#[test]
fn test_gateway_updates_timestamp() {
    let mut p = Profile::new(Some("alice"));
    let before = p.updated_at;
    std::thread::sleep(std::time::Duration::from_millis(2));
    p.as_active().unwrap().suspend();
    assert!(p.updated_at > before);
}

#[test]
fn test_closing_gateway_legal_hold() {
    let mut p = Profile::new(Some("alice"));
    p.status = ProfileStatus::GracePeriod;
    p.as_closing().unwrap().place_legal_hold();
    assert_eq!(p.status, ProfileStatus::LegalHold);
}

#[test]
fn test_active_gateway_inner() {
    let mut p = Profile::new(Some("alice"));
    let active = p.as_active().unwrap();
    assert_eq!(active.inner().username.as_deref(), Some("alice"));
    active.suspend(); // consume
}

// ── Export job values ───────────────────────────────────────

/// Stored export values parse back exactly; anything else is refused rather
/// than read as some default.
#[test]
fn test_export_values_parse_strictly() {
    for status in [
        ExportStatus::NotStarted,
        ExportStatus::Preparing,
        ExportStatus::Ready,
        ExportStatus::Downloaded,
        ExportStatus::Expired,
    ] {
        assert_eq!(status.as_str().parse::<ExportStatus>(), Ok(status));
    }
    assert!("pending".parse::<ExportStatus>().is_err());
    assert!("".parse::<ExportStatus>().is_err());
    assert_eq!("json".parse::<ExportFormat>(), Ok(ExportFormat::Json));
    assert!("xml".parse::<ExportFormat>().is_err());
}

/// An unknown stored closure mode is refused: read as `voluntary` it would
/// make an administrative or regulatory closure cancellable.
#[test]
fn test_closure_mode_parses_strictly() {
    for mode in [
        ClosureMode::Voluntary,
        ClosureMode::GdprErasure,
        ClosureMode::AdminTermination,
        ClosureMode::RegulatoryOrder,
    ] {
        assert_eq!(mode.as_str().parse::<ClosureMode>(), Ok(mode));
    }
    assert!("termination".parse::<ClosureMode>().is_err());
}
