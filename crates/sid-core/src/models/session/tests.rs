use super::*;
use chrono::Duration;

fn make_session(expires_in: Duration) -> Session {
    Session::new(
        ProfileId::generate(),
        "127.0.0.1".to_string(),
        Utc::now() + expires_in,
    )
}

/// A session redeemed from a grant reports the authorizing session's
/// authentication, step-up included, not its own creation, and is linked
/// to that session.
#[test]
fn test_grant_authentication_carries_to_the_redeemed_session() {
    let mut idp = make_session(Duration::hours(8));
    idp.authenticated_at = Utc::now() - Duration::minutes(30);
    idp.amr = vec!["pwd".into(), "otp".into(), "mfa".into()];
    idp.assurance_level = AuthLevel::Standard;
    idp.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: Utc::now() + Duration::minutes(5),
    });
    let grant = idp.grant_authentication();
    assert_eq!(grant.session, idp.id);

    let app = make_session(Duration::hours(24)).with_grant_authentication(&grant);
    assert_eq!(app.authenticated_by, Some(idp.id));
    assert_eq!(app.authenticated_at, idp.authenticated_at);
    assert_eq!(app.amr, idp.amr);
    assert_eq!(app.assurance_level, AuthLevel::Standard);
    assert_eq!(app.elevation, idp.elevation);
}

/// A grant made from a redeemed session names the IdP session it reuses,
/// so every session of the chain ends with that one.
#[test]
fn test_grant_from_a_redeemed_session_names_the_idp_session() {
    let idp = make_session(Duration::hours(8));
    let app =
        make_session(Duration::hours(24)).with_grant_authentication(&idp.grant_authentication());
    assert_eq!(app.grant_authentication().session, idp.id);
}

#[test]
fn test_session_new_defaults() {
    let session = make_session(Duration::hours(1));
    assert!(session.client_id.is_none());
    assert!(session.device_id.is_none());
    assert!(session.user_agent.is_none());
    assert!(session.scopes.is_empty());
    assert!(session.last_activity_at.is_none());
    assert_eq!(session.ip_address, "127.0.0.1");
}

#[test]
fn test_session_not_expired() {
    let session = make_session(Duration::hours(1));
    assert!(!session.is_expired());
}

#[test]
fn test_session_expired() {
    let session = make_session(Duration::seconds(-1));
    assert!(session.is_expired());
}

#[test]
fn test_session_touch() {
    let mut session = make_session(Duration::hours(1));
    assert!(session.last_activity_at.is_none());
    session.touch();
    assert!(session.last_activity_at.is_some());
}

#[test]
fn test_scopes_string() {
    let mut session = make_session(Duration::hours(1));
    session.scopes = vec!["openid".into(), "profile".into(), "email".into()];
    assert_eq!(session.scopes_string(), "openid profile email");
}

#[test]
fn test_scopes_string_empty() {
    let session = make_session(Duration::hours(1));
    assert_eq!(session.scopes_string(), "");
}

#[test]
fn test_parse_scopes() {
    let scopes = Session::parse_scopes("openid profile email");
    assert_eq!(scopes, vec!["openid", "profile", "email"]);
}

#[test]
fn test_parse_scopes_extra_whitespace() {
    let scopes = Session::parse_scopes("  openid   profile  ");
    assert_eq!(scopes, vec!["openid", "profile"]);
}

#[test]
fn test_parse_scopes_empty() {
    let scopes = Session::parse_scopes("");
    assert!(scopes.is_empty());
}

#[test]
fn test_session_id_unique() {
    let id1 = SessionId::generate();
    let id2 = SessionId::generate();
    assert_ne!(id1, id2);
}

#[test]
fn test_session_default_assurance_level() {
    let session = make_session(Duration::hours(1));
    assert_eq!(session.assurance_level, AuthLevel::Basic);
}

#[test]
fn test_auth_level_ordering() {
    assert!(AuthLevel::Basic < AuthLevel::Standard);
    assert!(AuthLevel::Standard < AuthLevel::Elevated);
    assert!(AuthLevel::Elevated < AuthLevel::Critical);
}

#[test]
fn test_auth_level_as_str() {
    assert_eq!(AuthLevel::Basic.as_str(), "basic");
    assert_eq!(AuthLevel::Standard.as_str(), "standard");
    assert_eq!(AuthLevel::Elevated.as_str(), "elevated");
    assert_eq!(AuthLevel::Critical.as_str(), "critical");
}

#[test]
fn test_auth_level_serde_roundtrip() {
    let level = AuthLevel::Elevated;
    let json = serde_json::to_string(&level).unwrap();
    assert_eq!(json, "\"elevated\"");
    let parsed: AuthLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, AuthLevel::Elevated);
}

#[test]
fn test_provisional_session() {
    let session = Session::new_provisional(ProfileId::generate(), "10.0.0.1".to_string());
    assert!(session.is_provisional);
    assert!(session.passkey_prompt);
    assert_eq!(session.assurance_level, AuthLevel::Basic);
    assert!(session.has_scope("profile:read"));
    assert!(session.has_scope("profile:update"));
    assert!(session.has_scope("consent:manage"));
    assert!(session.has_scope("mfa:enroll"));
    assert!(!session.has_scope("admin:read"));
}

#[test]
fn test_has_scope() {
    let mut session = make_session(Duration::hours(1));
    session.scopes = vec!["openid".into(), "profile".into()];
    assert!(session.has_scope("openid"));
    assert!(session.has_scope("profile"));
    assert!(!session.has_scope("email"));
}

#[test]
fn test_session_elevate() {
    let mut session = make_session(Duration::hours(1));
    assert_eq!(session.assurance_level, AuthLevel::Basic);

    session.elevate(AuthLevel::Standard);
    assert_eq!(session.assurance_level, AuthLevel::Standard);

    // Cannot downgrade
    session.elevate(AuthLevel::Basic);
    assert_eq!(session.assurance_level, AuthLevel::Standard);

    session.elevate(AuthLevel::Elevated);
    assert_eq!(session.assurance_at(Utc::now()), AuthLevel::Elevated);
    assert_eq!(
        session.assurance_level,
        AuthLevel::Standard,
        "the step-up does not become the session's own level"
    );
}

/// A step-up to Elevated/Critical lapses after its TTL and the session falls
/// back to its own level; a lower later step-up does not shorten a higher one.
#[test]
fn test_elevation_lapses_after_ttl() {
    let mut session = make_session(Duration::hours(1));
    session.elevate(AuthLevel::Standard);
    session.elevate(AuthLevel::Critical);
    let until = session.elevation.expect("elevated").until;
    let ttl = Duration::minutes(ELEVATION_TTL_MINUTES);
    assert!(until <= Utc::now() + ttl);
    assert_eq!(
        session.assurance_at(until - Duration::seconds(1)),
        AuthLevel::Critical
    );
    assert_eq!(session.assurance_at(until), AuthLevel::Standard);
    assert_eq!(
        session.assurance_at(until + Duration::hours(3)),
        AuthLevel::Standard
    );

    session.elevate(AuthLevel::Elevated);
    assert_eq!(session.elevation.unwrap().level, AuthLevel::Critical);
}

#[test]
fn test_auth_level_acr_values_canonical() {
    // Canonical SID ACR URN format (urn:sid:acr:*)
    assert_eq!(AuthLevel::Basic.acr_value(), "urn:sid:acr:basic");
    assert_eq!(AuthLevel::Standard.acr_value(), "urn:sid:acr:standard");
    assert_eq!(AuthLevel::Elevated.acr_value(), "urn:sid:acr:elevated");
    assert_eq!(AuthLevel::Critical.acr_value(), "urn:sid:acr:critical");
}

#[test]
fn test_auth_level_from_acr_canonical() {
    assert_eq!(
        AuthLevel::from_acr_value("urn:sid:acr:basic"),
        Some(AuthLevel::Basic)
    );
    assert_eq!(
        AuthLevel::from_acr_value("urn:sid:acr:standard"),
        Some(AuthLevel::Standard)
    );
    assert_eq!(
        AuthLevel::from_acr_value("urn:sid:acr:elevated"),
        Some(AuthLevel::Elevated)
    );
    assert_eq!(
        AuthLevel::from_acr_value("urn:sid:acr:critical"),
        Some(AuthLevel::Critical)
    );
}

#[test]
fn test_auth_level_from_acr_plain_names() {
    assert_eq!(AuthLevel::from_acr_value("basic"), Some(AuthLevel::Basic));
    assert_eq!(
        AuthLevel::from_acr_value("standard"),
        Some(AuthLevel::Standard)
    );
    assert_eq!(
        AuthLevel::from_acr_value("elevated"),
        Some(AuthLevel::Elevated)
    );
    assert_eq!(
        AuthLevel::from_acr_value("critical"),
        Some(AuthLevel::Critical)
    );
}

#[test]
fn test_auth_level_from_acr_unknown() {
    assert_eq!(AuthLevel::from_acr_value("urn:unknown:foo"), None);
    assert_eq!(AuthLevel::from_acr_value(""), None);
}

#[test]
fn test_auth_level_acr_roundtrip() {
    // from_acr_value(acr_value()) == identity
    for level in [
        AuthLevel::Basic,
        AuthLevel::Standard,
        AuthLevel::Elevated,
        AuthLevel::Critical,
    ] {
        assert_eq!(AuthLevel::from_acr_value(level.acr_value()), Some(level));
    }
}

#[test]
fn test_session_authenticated_at() {
    let session = make_session(Duration::hours(1));
    // authenticated_at should be close to created_at.
    let diff = (session.authenticated_at - session.created_at)
        .num_milliseconds()
        .abs();
    assert!(diff < 100);
}

#[test]
fn test_session_amr_empty_by_default() {
    let session = make_session(Duration::hours(1));
    assert!(session.amr.is_empty());
}

#[test]
fn test_session_add_amr() {
    let mut session = make_session(Duration::hours(1));
    session.add_amr("pwd");
    session.add_amr("otp");
    assert_eq!(session.amr, vec!["pwd", "otp"]);

    // Deduplication.
    session.add_amr("pwd");
    assert_eq!(session.amr, vec!["pwd", "otp"]);
}

#[test]
fn test_provisional_session_amr() {
    let session = Session::new_provisional(ProfileId::generate(), "10.0.0.1".to_string());
    assert_eq!(session.amr, vec!["mca"]);
}

#[test]
fn test_session_decay_level_full() {
    let session = make_session(Duration::hours(8));
    // Just created → Full trust.
    assert_eq!(session.decay_level(), SessionDecayLevel::Full);
}

#[test]
fn test_session_decay_level_high() {
    let mut session = make_session(Duration::hours(8));
    session.authenticated_at = Utc::now() - Duration::hours(2);
    assert_eq!(session.decay_level(), SessionDecayLevel::High);
}

#[test]
fn test_session_decay_level_medium() {
    let mut session = make_session(Duration::hours(24));
    session.authenticated_at = Utc::now() - Duration::hours(6);
    assert_eq!(session.decay_level(), SessionDecayLevel::Medium);
}

#[test]
fn test_session_decay_level_low() {
    let mut session = make_session(Duration::hours(24));
    session.authenticated_at = Utc::now() - Duration::hours(13);
    assert_eq!(session.decay_level(), SessionDecayLevel::Low);
}

#[test]
fn test_session_refresh_authentication() {
    let mut session = make_session(Duration::hours(24));
    session.authenticated_at = Utc::now() - Duration::hours(13);
    assert_eq!(session.decay_level(), SessionDecayLevel::Low);

    session.refresh_authentication();
    assert_eq!(session.decay_level(), SessionDecayLevel::Full);
}

#[test]
fn test_decay_level_ordering() {
    assert!(SessionDecayLevel::Full < SessionDecayLevel::High);
    assert!(SessionDecayLevel::High < SessionDecayLevel::Medium);
    assert!(SessionDecayLevel::Medium < SessionDecayLevel::Low);
}

#[test]
fn test_decay_level_serde() {
    let level = SessionDecayLevel::Medium;
    let json = serde_json::to_string(&level).unwrap();
    assert_eq!(json, "\"medium\"");
    let parsed: SessionDecayLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SessionDecayLevel::Medium);
}

#[test]
fn test_decay_constants() {
    assert_eq!(FULL_TRUST_HOURS, 1);
    assert_eq!(HIGH_TRUST_HOURS, 4);
    assert_eq!(MEDIUM_TRUST_HOURS, 12);
}

// ── Policy grace tests ──────────────────────────────────────

#[test]
fn test_session_default_no_grace() {
    let session = make_session(Duration::hours(1));
    assert!(!session.policy_grace);
    assert!(session.grace_deadline.is_none());
    assert!(!session.grace_expired());
}

#[test]
fn test_session_enter_grace() {
    let mut session = make_session(Duration::hours(1));
    let deadline = Utc::now() + Duration::days(30);
    session.enter_grace(deadline);
    assert!(session.policy_grace);
    assert_eq!(session.grace_deadline, Some(deadline));
    assert!(!session.grace_expired());
}

#[test]
fn test_session_grace_expired() {
    let mut session = make_session(Duration::hours(1));
    session.enter_grace(Utc::now() - Duration::seconds(1));
    assert!(session.grace_expired());
}

#[test]
fn test_session_grace_not_expired() {
    let mut session = make_session(Duration::hours(1));
    session.enter_grace(Utc::now() + Duration::days(30));
    assert!(!session.grace_expired());
}

// ── ActiveSession gateway tests ──

#[test]
fn test_active_gateway_available_for_full_session() {
    let mut session = make_session(Duration::hours(1));
    assert!(session.as_active().is_some());
}

#[test]
fn test_active_gateway_unavailable_for_expired() {
    let mut session = make_session(Duration::hours(-1));
    assert!(session.as_active().is_none());
}

#[test]
fn test_active_gateway_unavailable_for_provisional() {
    let mut session = Session::new_provisional(ProfileId::generate(), "10.0.0.1".to_string());
    assert!(session.as_active().is_none());
}

#[test]
fn test_active_session_elevate() {
    let mut session = make_session(Duration::hours(1));
    assert_eq!(session.assurance_level, AuthLevel::Basic);

    session.as_active().unwrap().elevate(AuthLevel::Standard);
    assert_eq!(session.assurance_level, AuthLevel::Standard);
}

#[test]
fn test_active_session_elevate_no_downgrade() {
    let mut session = make_session(Duration::hours(1));
    session.as_active().unwrap().elevate(AuthLevel::Elevated);

    session.as_active().unwrap().elevate(AuthLevel::Basic);
    assert_eq!(session.assurance_at(Utc::now()), AuthLevel::Elevated); // unchanged
}

#[test]
fn test_active_session_enter_grace() {
    let mut session = make_session(Duration::hours(1));
    assert!(!session.policy_grace);

    let deadline = Utc::now() + Duration::days(30);
    session.as_active().unwrap().enter_grace(deadline);
    assert!(session.policy_grace);
    assert!(session.grace_deadline.is_some());
}

#[test]
fn test_active_session_add_amr() {
    let mut session = make_session(Duration::hours(1));
    assert!(session.amr.is_empty());

    let mut active = session.as_active().unwrap();
    active.add_amr("otp");
    active.add_amr("otp"); // duplicate ignored
    assert_eq!(active.inner().amr, vec!["otp".to_string()]);
}

#[test]
fn test_active_session_refresh_authentication() {
    let mut session = make_session(Duration::hours(1));
    let old_auth_at = session.authenticated_at;
    std::thread::sleep(std::time::Duration::from_millis(10));

    session.as_active().unwrap().refresh_authentication();
    assert!(session.authenticated_at > old_auth_at);
}

// ── ExpiredSession gateway tests ──

#[test]
fn test_expired_gateway_available_for_expired() {
    let session = make_session(Duration::hours(-1));
    assert!(session.as_expired().is_some());
}

#[test]
fn test_expired_gateway_unavailable_for_active() {
    let session = make_session(Duration::hours(1));
    assert!(session.as_expired().is_none());
}

#[test]
fn test_expired_session_inner_readonly() {
    let session = make_session(Duration::hours(-1));
    let expired = session.as_expired().unwrap();
    assert_eq!(expired.inner().ip_address, "127.0.0.1");
}

#[test]
fn test_expired_session_expired_since() {
    let session = make_session(Duration::hours(-2));
    let expired = session.as_expired().unwrap();
    // Should be roughly 2 hours.
    assert!(expired.expired_since().num_minutes() >= 119);
}
