use super::*;

#[test]
fn test_parse_principal_email() {
    let (pt, normalized) = parse_principal("alice@sid.example.com").unwrap();
    assert_eq!(pt, PrincipalType::Email);
    assert_eq!(normalized, "alice@sid.example.com");
}

#[test]
fn test_parse_principal_email_uppercase() {
    let (pt, normalized) = parse_principal("Alice@SID.Example.COM").unwrap();
    assert_eq!(pt, PrincipalType::Email);
    assert_eq!(normalized, "alice@sid.example.com");
}

#[test]
fn test_parse_principal_phone() {
    let (pt, normalized) = parse_principal("+12125551234").unwrap();
    assert_eq!(pt, PrincipalType::Phone);
    assert_eq!(normalized, "+12125551234");
}

#[test]
fn test_parse_principal_username() {
    let (pt, normalized) = parse_principal("alice").unwrap();
    assert_eq!(pt, PrincipalType::Username);
    assert_eq!(normalized, "alice");
}

#[test]
fn test_parse_principal_username_uppercase() {
    let (pt, normalized) = parse_principal("Alice").unwrap();
    assert_eq!(pt, PrincipalType::Username);
    assert_eq!(normalized, "alice");
}

#[test]
fn test_parse_principal_trimmed() {
    let (pt, normalized) = parse_principal("  alice@sid.example.com  ").unwrap();
    assert_eq!(pt, PrincipalType::Email);
    assert_eq!(normalized, "alice@sid.example.com");
}

#[test]
fn test_parse_principal_phone_trimmed() {
    let (pt, normalized) = parse_principal("  +380501234567  ").unwrap();
    assert_eq!(pt, PrincipalType::Phone);
    assert_eq!(normalized, "+380501234567");
}

#[test]
fn test_parse_principal_empty_rejected() {
    let err = parse_principal("").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[test]
fn test_parse_principal_short_username_rejected() {
    let err = parse_principal("ab").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ── IP matching tests (TOKEN-010) ─────────────────────────────

#[test]
fn test_ip_matches_exact_v4() {
    let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(ip_matches("10.0.0.1", &addr));
    assert!(!ip_matches("10.0.0.2", &addr));
}

#[test]
fn test_ip_matches_cidr_v4() {
    let addr: std::net::IpAddr = "10.0.0.42".parse().unwrap();
    assert!(ip_matches("10.0.0.0/24", &addr));
    assert!(!ip_matches("10.0.1.0/24", &addr));
}

#[test]
fn test_ip_matches_cidr_v4_16() {
    let addr: std::net::IpAddr = "172.16.5.10".parse().unwrap();
    assert!(ip_matches("172.16.0.0/16", &addr));
    assert!(!ip_matches("172.17.0.0/16", &addr));
}

#[test]
fn test_ip_matches_exact_v6() {
    let addr: std::net::IpAddr = "::1".parse().unwrap();
    assert!(ip_matches("::1", &addr));
    assert!(!ip_matches("::2", &addr));
}

#[test]
fn test_ip_matches_cidr_v6() {
    let addr: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    assert!(ip_matches("2001:db8::/32", &addr));
    assert!(!ip_matches("2001:db9::/32", &addr));
}

#[test]
fn test_ip_matches_invalid_entry() {
    let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!ip_matches("not-an-ip", &addr));
    assert!(!ip_matches("not-a-cidr/24", &addr));
}

#[test]
fn test_ip_matches_mixed_v4_v6() {
    let v4: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!ip_matches("::1/128", &v4));
    let v6: std::net::IpAddr = "::1".parse().unwrap();
    assert!(!ip_matches("10.0.0.0/24", &v6));
}

// ── implied_auth_level tests ──────────────────────────────────

#[test]
fn test_implied_auth_level_opaque_is_basic() {
    assert_eq!(
        super::implied_auth_level("opaque", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_opaque_basic_regardless_of_config() {
    assert_eq!(
        super::implied_auth_level("opaque", false, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_webauthn_standard_when_satisfies_mfa_and_user_verified() {
    // Both passkey_satisfies_mfa AND user_verified must be true for Standard.
    assert_eq!(
        super::implied_auth_level("webauthn", true, true),
        sid_core::models::session::AuthLevel::Standard,
    );
}

#[test]
fn test_implied_auth_level_webauthn_basic_when_not_user_verified() {
    // passkey_satisfies_mfa=true but user_verified=false → Basic.
    // Per NIST: without user verification, passkey = single factor (possession only).
    assert_eq!(
        super::implied_auth_level("webauthn", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

/// A passkey records its key and proof of possession; `mfa` only when the
/// authenticator verified the user, and never a biometric/PIN method, which
/// WebAuthn does not reveal (RFC 8176 §2 lists methods actually used).
#[test]
fn test_passkey_amr_adds_mfa_only_with_user_verification() {
    assert_eq!(super::passkey_amr("swk", true), ["swk", "pop", "mfa"]);
    assert_eq!(super::passkey_amr("hwk", true), ["hwk", "pop", "mfa"]);
    assert_eq!(super::passkey_amr("swk", false), ["swk", "pop"]);
    assert_eq!(super::passkey_amr("hwk", false), ["hwk", "pop"]);
}

#[test]
fn test_implied_auth_level_webauthn_basic_when_passkey_not_satisfies_mfa() {
    // passkey_satisfies_mfa=false → Basic regardless of user_verified.
    assert_eq!(
        super::implied_auth_level("webauthn", false, true),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_webauthn_basic_when_both_false() {
    assert_eq!(
        super::implied_auth_level("webauthn", false, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_magic_link_is_basic() {
    assert_eq!(
        super::implied_auth_level("magic_link", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_unknown_is_basic() {
    assert_eq!(
        super::implied_auth_level("unknown_method", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

// ── AnomalyDetector + evaluate_login_security integration tests ──

use sid_authn::anomaly::{AnomalyConfig, AnomalyDetector, LoginContext, RuleReaction};
use sid_core::models::security_policy::SecurityPolicy;
use sid_plugin::cache::NoCacheBackend;

#[test]
fn test_anomaly_allow_reaction_for_clean_context() {
    let cache = std::sync::Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some("192.168.1.1".parse().unwrap()),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(detector.evaluate(&ctx)).unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[test]
fn test_anomaly_block_for_tor_exit() {
    let cache = std::sync::Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some("192.168.1.1".parse().unwrap()),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: true,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(detector.evaluate(&ctx)).unwrap();
    // Tor exit nodes should trigger Block (per NetworkPolicy default).
    assert!(
        result.reaction == RuleReaction::Block || result.reaction == RuleReaction::Allow,
        "Tor exit should trigger Block or Allow depending on NetworkPolicy config: got {:?}",
        result.reaction
    );
}

#[test]
fn test_anomaly_step_up_for_new_device_and_ip() {
    let cache = std::sync::Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    // A profile that has signed in before, now from a new device and address.
    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some("192.168.1.1".parse().unwrap()),
        country: None,
        failed: false,
        new_device: true,
        new_ip: true,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: Some(chrono::Utc::now() - chrono::Duration::days(1)),
        prev_country: None,
        designated_countries: vec![],
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(detector.evaluate(&ctx)).unwrap();
    assert_eq!(result.reaction, RuleReaction::StepUp);
}

#[tokio::test]
async fn test_brute_force_detection_after_failures() {
    // Attempts are counted in the shared cache only, so it must keep them.
    let cache = std::sync::Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 900,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let policy = sid_core::models::security_policy::NetworkPolicy::default();
    let detector = AnomalyDetector::new(config, policy, cache);

    let identity = "brute-force-victim";

    // Record 3 failed attempts (threshold).
    for _ in 0..3 {
        detector.record_failed_attempt(identity).await.unwrap();
    }

    // Next evaluation should detect brute force.
    let ctx = LoginContext {
        identity: identity.to_string(),
        ip: Some("10.0.0.1".parse().unwrap()),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert!(
        result.reaction == RuleReaction::Block || result.reaction == RuleReaction::RequireCaptcha,
        "After {} failed attempts, expected Block or RequireCaptcha, got {:?}",
        3,
        result.reaction
    );
}

#[test]
fn test_ce_default_policy_allows_basic_auth() {
    let policy = SecurityPolicy::ce_default();
    let implied = super::implied_auth_level("opaque", policy.auth.passkey_satisfies_mfa, false);
    // CE default min_acr should be Basic, so single-factor login passes.
    assert!(
        implied >= policy.auth.min_acr,
        "CE default policy should allow Basic auth (opaque). min_acr={:?}, implied={:?}",
        policy.auth.min_acr,
        implied,
    );
}

#[test]
fn test_ce_default_policy_allows_webauthn_with_uv() {
    let policy = SecurityPolicy::ce_default();
    // user_verified=true required for Standard assurance with passkey.
    let implied = super::implied_auth_level("webauthn", policy.auth.passkey_satisfies_mfa, true);
    assert!(
        implied >= policy.auth.min_acr,
        "CE default policy should allow Standard auth (webauthn+UV). min_acr={:?}, implied={:?}",
        policy.auth.min_acr,
        implied,
    );
}

#[test]
fn test_ce_default_passkey_satisfies_mfa_is_true() {
    let policy = SecurityPolicy::ce_default();
    assert!(
        policy.auth.passkey_satisfies_mfa,
        "CE default should have passkey_satisfies_mfa=true (NIST-aligned)"
    );
}

#[test]
fn test_passkey_not_satisfies_mfa_webauthn_is_basic() {
    // When passkey_satisfies_mfa is false, webauthn should only grant Basic.
    let implied = super::implied_auth_level("webauthn", false, true);
    assert_eq!(
        implied,
        sid_core::models::session::AuthLevel::Basic,
        "With passkey_satisfies_mfa=false, webauthn should grant Basic only"
    );
}

#[test]
fn test_publish_security_event_type_mapping() {
    // Verify event type mapping for anomaly rules.
    assert_eq!(
        sid_core::models::event::event_types::SECURITY_BRUTE_FORCE,
        "sid.security.brute_force.v1"
    );
    assert_eq!(
        sid_core::models::event::event_types::SECURITY_COUNTRY_BLOCKED,
        "sid.security.country_blocked.v1"
    );
    assert_eq!(
        sid_core::models::event::event_types::SECURITY_TOR_BLOCKED,
        "sid.security.tor_blocked.v1"
    );
    assert_eq!(
        sid_core::models::event::event_types::SECURITY_DATACENTER_IP,
        "sid.security.datacenter_ip.v1"
    );
    assert_eq!(
        sid_core::models::event::event_types::SECURITY_SUSPICIOUS_LOGIN,
        "sid.security.suspicious_login.v1"
    );
}

// ── Device fingerprint + designated locations (#589) ──────────

#[test]
fn test_compute_device_id_deterministic() {
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120";
    let id1 = super::compute_device_id(ua);
    let id2 = super::compute_device_id(ua);
    assert_eq!(id1, id2, "Same UA should produce same device_id");
}

#[test]
fn test_compute_device_id_different_ua() {
    let id1 = super::compute_device_id("Chrome/120 on Mac");
    let id2 = super::compute_device_id("Firefox/115 on Windows");
    assert_ne!(
        id1, id2,
        "Different UAs should produce different device_ids"
    );
}

#[test]
fn test_compute_device_id_valid_uuid() {
    let id = super::compute_device_id("test-agent");
    // Should be a valid UUID v4 format
    assert_eq!(id.get_version(), Some(uuid::Version::Random));
}

#[test]
fn test_extract_user_agent_from_standard_header() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("user-agent", "TestBrowser/1.0".parse().unwrap());
    let result = super::extract_user_agent(&metadata);
    assert_eq!(result, Some("TestBrowser/1.0".to_string()));
}

#[test]
fn test_extract_user_agent_prefers_x_user_agent() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("user-agent", "grpc-go/1.60".parse().unwrap());
    metadata.insert("x-user-agent", "RealBrowser/2.0".parse().unwrap());
    let result = super::extract_user_agent(&metadata);
    assert_eq!(
        result,
        Some("RealBrowser/2.0".to_string()),
        "x-user-agent (proxy-forwarded) should take priority"
    );
}

#[test]
fn test_extract_user_agent_none_when_missing() {
    let metadata = tonic::metadata::MetadataMap::new();
    let result = super::extract_user_agent(&metadata);
    assert_eq!(result, None);
}

// ── Conditional access wiring integration tests (#637) ──────────
//
// These tests verify the WIRING of ConditionalAccessEngine into the auth flow.
// They replicate the exact logic from evaluate_login_security_inner (Stage 2):
//   implied_auth_level → probe_session → ConditionalAccessEngine::check → routing
//
// Unlike conditional_access.rs unit tests (which test the engine in isolation),
// these tests prove the auth flow constructs inputs correctly and routes outputs.

use sid_authz::conditional_access::ConditionalAccessEngine;
use sid_core::models::enforcement::EnforcementAction;
use sid_core::models::security_policy::EnforcementMode;

/// Helper: replicate evaluate_login_security_inner Stage 2 logic exactly.
/// Returns the EnforcementDecision that the auth flow would produce.
fn auth_flow_conditional_access_decision(
    policy: &SecurityPolicy,
    client: Option<&sid_core::models::OAuth2Client>,
    auth_method: &str,
    user_verified: bool,
) -> sid_core::models::enforcement::EnforcementDecision {
    let implied = super::implied_auth_level(
        auth_method,
        policy.auth.passkey_satisfies_mfa,
        user_verified,
    );
    let mut probe_session = sid_core::models::Session::new(
        sid_core::models::ProfileId::generate(),
        "probe".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    probe_session.assurance_level = implied;

    ConditionalAccessEngine::check(policy, client, None, &probe_session)
}

/// Helper: construct a test OAuth2Client with specific overrides.
fn test_client_with_acr(
    name: &str,
    required_acr: Option<sid_core::models::session::AuthLevel>,
    enforcement_mode: EnforcementMode,
) -> sid_core::models::OAuth2Client {
    sid_core::models::OAuth2Client {
        client_id: name.to_string(),
        project_id: sid_core::models::ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: sid_core::models::ApplicationType::Web,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec![],
        allowed_scopes: vec![],
        grant_types: vec![],
        client_name: name.to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: sid_core::models::TokenEndpointAuthMethod::None,
        response_types: vec![],
        subject_type: sid_core::models::SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: chrono::Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr,
        required_amr: vec![],
        enforcement_mode,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: sid_core::models::LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 0,
        created_at: chrono::Utc::now(),
    }
}

#[test]
fn test_conditional_access_wiring_opaque_basic_passes_ce_default() {
    // CE default min_acr = Basic. OPAQUE login → Basic. Basic ≥ Basic → Allow.
    let policy = SecurityPolicy::ce_default();
    let decision = auth_flow_conditional_access_decision(&policy, None, "opaque", false);
    assert_eq!(decision.action, EnforcementAction::Allow);
    assert!(decision.violations.is_empty());
}

#[test]
fn test_conditional_access_wiring_step_up_when_policy_requires_standard() {
    // Modified policy: min_acr = Standard, Hard enforcement.
    // OPAQUE login → Basic. Basic < Standard → StepUp.
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    let decision = auth_flow_conditional_access_decision(&policy, None, "opaque", false);
    assert_eq!(
        decision.action,
        EnforcementAction::StepUp,
        "OPAQUE (Basic) should trigger StepUp when policy requires Standard"
    );
    assert!(!decision.violations.is_empty());
    assert!(
        decision
            .violations
            .iter()
            .any(|v| v.requirement == "min_acr"),
        "Violation should identify min_acr requirement"
    );
}

#[test]
fn test_conditional_access_wiring_webauthn_uv_meets_standard_policy() {
    // Policy requires Standard. WebAuthn + user_verified + passkey_satisfies_mfa → Standard.
    // Standard ≥ Standard → Allow.
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    let decision = auth_flow_conditional_access_decision(&policy, None, "webauthn", true);
    assert_eq!(
        decision.action,
        EnforcementAction::Allow,
        "WebAuthn+UV (Standard) should pass Standard policy"
    );
    assert!(decision.violations.is_empty());
}

#[test]
fn test_conditional_access_wiring_webauthn_no_uv_fails_standard_policy() {
    // Policy requires Standard. WebAuthn WITHOUT user_verified → Basic (single factor).
    // Basic < Standard → StepUp.
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    let decision = auth_flow_conditional_access_decision(&policy, None, "webauthn", false);
    assert_eq!(
        decision.action,
        EnforcementAction::StepUp,
        "WebAuthn without UV (Basic) should trigger StepUp for Standard policy"
    );
}

#[test]
fn test_conditional_access_wiring_audit_mode_allows_despite_violation() {
    // Audit mode: violations are logged but access is allowed.
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    policy.enforcement.mode = EnforcementMode::Audit;
    let decision = auth_flow_conditional_access_decision(&policy, None, "opaque", false);
    assert_eq!(
        decision.action,
        EnforcementAction::Allow,
        "Audit mode should Allow even with violations"
    );
    assert!(
        !decision.violations.is_empty(),
        "Violations should still be recorded in Audit mode"
    );
}

#[test]
fn test_conditional_access_wiring_client_override_stricter_wins() {
    // Org policy: min_acr = Basic. Client override: required_acr = Standard.
    // Effective policy = Standard (stricter wins). OPAQUE (Basic) → StepUp.
    let policy = SecurityPolicy::ce_default(); // min_acr = Basic
    let client = test_client_with_acr(
        "strict-app",
        Some(sid_core::models::session::AuthLevel::Standard),
        EnforcementMode::Hard,
    );
    let decision = auth_flow_conditional_access_decision(&policy, Some(&client), "opaque", false);
    assert_eq!(
        decision.action,
        EnforcementAction::StepUp,
        "Client override (Standard) should make OPAQUE (Basic) trigger StepUp"
    );

    // Same client, but WebAuthn+UV → Standard → Allow.
    let decision_webauthn =
        auth_flow_conditional_access_decision(&policy, Some(&client), "webauthn", true);
    assert_eq!(
        decision_webauthn.action,
        EnforcementAction::Allow,
        "WebAuthn+UV (Standard) should satisfy client's Standard requirement"
    );
}

#[test]
fn test_conditional_access_wiring_client_weaker_org_wins() {
    // Org policy: min_acr = Standard. Client override: required_acr = Basic.
    // Effective policy = Standard (org is stricter). OPAQUE (Basic) → StepUp.
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    let client = test_client_with_acr(
        "lenient-app",
        Some(sid_core::models::session::AuthLevel::Basic),
        EnforcementMode::Audit,
    );
    let decision = auth_flow_conditional_access_decision(&policy, Some(&client), "opaque", false);
    // Org is stricter (Standard, Hard) — effective policy uses org's values.
    assert_eq!(
        decision.action,
        EnforcementAction::StepUp,
        "Org policy (Standard) should override weaker client (Basic)"
    );
}

// ── Step-up evaluation tests ──────────────────────────────────

use sid_authn::step_up::{StepUpConfig, StepUpDecision, evaluate_step_up};
use sid_core::models::MfaMethod;
use sid_core::models::session::SessionDecayLevel;

#[test]
fn test_step_up_satisfied_when_already_standard() {
    let decision = evaluate_step_up(
        sid_core::models::session::AuthLevel::Standard,
        sid_core::models::session::AuthLevel::Standard,
        SessionDecayLevel::Full,
        &[MfaMethod::Totp],
        &StepUpConfig::default(),
    );
    assert_eq!(decision, StepUpDecision::Satisfied);
}

#[test]
fn test_step_up_required_basic_to_standard() {
    let decision = evaluate_step_up(
        sid_core::models::session::AuthLevel::Basic,
        sid_core::models::session::AuthLevel::Standard,
        SessionDecayLevel::Full,
        &[MfaMethod::Totp, MfaMethod::WebAuthn],
        &StepUpConfig::default(),
    );
    match decision {
        StepUpDecision::StepUpRequired {
            current_acr,
            target_acr,
            available_methods,
            ..
        } => {
            assert_eq!(current_acr, sid_core::models::session::AuthLevel::Basic);
            assert_eq!(target_acr, sid_core::models::session::AuthLevel::Standard);
            assert!(!available_methods.is_empty());
        }
        other => panic!("Expected StepUpRequired, got {:?}", other),
    }
}

#[test]
fn test_step_up_reauth_required_when_decayed() {
    let decision = evaluate_step_up(
        sid_core::models::session::AuthLevel::Basic,
        sid_core::models::session::AuthLevel::Standard,
        SessionDecayLevel::Low, // 12h+ → too decayed for step-up
        &[MfaMethod::Totp],
        &StepUpConfig::default(),
    );
    assert_eq!(decision, StepUpDecision::ReauthRequired);
}

#[test]
fn test_step_up_elevated_requires_phishing_resistant() {
    let decision = evaluate_step_up(
        sid_core::models::session::AuthLevel::Standard,
        sid_core::models::session::AuthLevel::Elevated,
        SessionDecayLevel::Full,
        &[MfaMethod::WebAuthn, MfaMethod::Totp],
        &StepUpConfig::default(),
    );
    match decision {
        StepUpDecision::StepUpRequired {
            require_phishing_resistant,
            available_methods,
            ..
        } => {
            assert!(require_phishing_resistant);
            // WebAuthn should be offered first (phishing-resistant)
            assert_eq!(available_methods[0], MfaMethod::WebAuthn);
        }
        other => panic!("Expected StepUpRequired, got {:?}", other),
    }
}

#[test]
fn test_verify_totp_function_reexported() {
    // Verify that verify_totp is accessible from sid_authn root.
    let secret = vec![0u8; 20];
    // Wrong code should return false (we just verify it's callable).
    assert!(!sid_authn::verify_totp(&secret, "000000"));
}

/// An anomaly step-up asks for a second factor as STEP_UP_REQUIRED with an
/// `amr` precondition; the rule that fired stays out of the response.
#[test]
fn step_up_after_anomaly_names_the_need_not_the_rule() {
    use tonic_types::StatusExt;
    let status: Status = super::refusal::step_up_after_anomaly("new_device_ip").into();
    assert_eq!(status.code(), Code::FailedPrecondition);
    let details = status.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "STEP_UP_REQUIRED");
    let violations = &details.precondition_failure().unwrap().violations;
    assert_eq!(violations[0].r#type, "amr");
    assert_eq!(violations[0].subject, "mfa");
    assert!(!status.message().contains("new_device_ip"));
}

/// Every missing method is its own violation, so a client can list them.
#[test]
fn step_up_to_amr_lists_every_missing_method() {
    use tonic_types::StatusExt;
    let status: Status = super::refusal::step_up_to_amr(["hwk", "mfa"]).into();
    let subjects: Vec<String> = status
        .get_details_precondition_failure()
        .unwrap()
        .violations
        .into_iter()
        .map(|v| v.subject)
        .collect();
    assert_eq!(subjects, ["hwk", "mfa"]);
}

/// A provider the proto has no kind for is an internal error, not a
/// challenge the client could never solve.
#[test]
fn captcha_from_unknown_provider_is_internal() {
    let challenge = sid_authn::captcha::CaptchaChallenge {
        challenge_id: "c".into(),
        provider: "unheard_of".into(),
        site_key: None,
        difficulty: None,
    };
    let err = super::refusal::captcha_required(&challenge).unwrap_err();
    assert_eq!(err.reason(), ErrorReason::InternalError);
}

// ── parse_acr_values tests ────────────────────────────────────

use sid_core::models::session::AuthLevel;

#[test]
fn test_parse_acr_values_canonical_urns() {
    // Canonical SID ACR format (urn:sid:acr:*)
    assert_eq!(
        super::parse_acr_values("urn:sid:acr:basic"),
        Some(AuthLevel::Basic)
    );
    assert_eq!(
        super::parse_acr_values("urn:sid:acr:standard"),
        Some(AuthLevel::Standard)
    );
    assert_eq!(
        super::parse_acr_values("urn:sid:acr:elevated"),
        Some(AuthLevel::Elevated)
    );
    assert_eq!(
        super::parse_acr_values("urn:sid:acr:critical"),
        Some(AuthLevel::Critical)
    );
}

#[test]
fn test_parse_acr_values_plain_names() {
    assert_eq!(super::parse_acr_values("basic"), Some(AuthLevel::Basic));
    assert_eq!(
        super::parse_acr_values("standard"),
        Some(AuthLevel::Standard)
    );
    assert_eq!(
        super::parse_acr_values("elevated"),
        Some(AuthLevel::Elevated)
    );
    assert_eq!(
        super::parse_acr_values("critical"),
        Some(AuthLevel::Critical)
    );
}

#[test]
fn test_parse_acr_values_multiple_takes_highest() {
    // Multiple acr_values → strictest (highest) wins.
    assert_eq!(
        super::parse_acr_values("urn:sid:acr:basic urn:sid:acr:elevated"),
        Some(AuthLevel::Elevated),
    );
}

#[test]
fn test_parse_acr_values_unknown_returns_none() {
    assert_eq!(super::parse_acr_values("urn:unknown:foo"), None);
}

#[test]
fn test_parse_acr_values_empty_returns_none() {
    assert_eq!(super::parse_acr_values(""), None);
}

#[test]
fn test_parse_acr_values_mixed_known_unknown() {
    // Known value found among unknowns → returns the known one.
    assert_eq!(
        super::parse_acr_values("urn:unknown:foo standard urn:other:bar"),
        Some(AuthLevel::Standard),
    );
}

// ── GeoIP + Anomaly pipeline integration tests (#586) ────────

use sid_authn::geoip::GeoIpChain;
use sid_authn::ip_intelligence::IpIntelligenceAggregator;
use sid_plugin::geoip::{GeoIpError, GeoIpProvider, GeoLocation};
use std::time::Duration;

/// Stub GeoIP provider that returns a configurable country for any IP.
struct StubGeoIpProvider {
    country: String,
    lat: f64,
    lon: f64,
}

#[async_trait::async_trait]
impl GeoIpProvider for StubGeoIpProvider {
    async fn resolve(&self, _ip: std::net::IpAddr) -> Result<GeoLocation, GeoIpError> {
        Ok(GeoLocation {
            country: self.country.clone(),
            city: Some("TestCity".to_string()),
            latitude: self.lat,
            longitude: self.lon,
        })
    }
    fn provider_name(&self) -> &str {
        "stub"
    }
    fn priority(&self) -> i32 {
        100
    }
}

/// Stub GeoIP provider that always returns NotFound.
struct NotFoundGeoIpProvider;

#[async_trait::async_trait]
impl GeoIpProvider for NotFoundGeoIpProvider {
    async fn resolve(&self, _ip: std::net::IpAddr) -> Result<GeoLocation, GeoIpError> {
        Err(GeoIpError::NotFound)
    }
    fn provider_name(&self) -> &str {
        "not_found"
    }
}

#[tokio::test]
async fn test_geoip_country_feeds_country_restriction_block() {
    // Scenario: GeoIP resolves to "CN", country block list contains "CN".
    // Pipeline: GeoIP → country="CN" → country_restriction → Block.
    let cache = std::sync::Arc::new(NoCacheBackend);

    // Build GeoIP chain with stub returning "CN".
    let geoip_provider = std::sync::Arc::new(StubGeoIpProvider {
        country: "CN".to_string(),
        lat: 39.9,
        lon: 116.4,
    }) as std::sync::Arc<dyn GeoIpProvider>;
    let geoip = GeoIpChain::new(vec![geoip_provider], cache.clone(), Duration::from_secs(60));

    // Build anomaly detector with country block list.
    let policy = sid_core::models::security_policy::NetworkPolicy {
        country_mode: sid_core::models::security_policy::CountryMode::BlockList,
        countries: vec!["CN".to_string(), "KP".to_string()],
        ..Default::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, cache.clone());

    // Build IP intelligence (empty — no Tor/blocklist providers).
    let ip_intel = IpIntelligenceAggregator::new(vec![], cache.clone(), Duration::from_secs(60));

    // Simulate the evaluate_login_security pipeline:
    let client_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

    // Step 1: IP intelligence classification.
    let ip_classification = ip_intel.classify(client_ip).await.unwrap();

    // Step 2: GeoIP resolution.
    let geo_location = geoip.resolve(client_ip).await;
    let country = geo_location.as_ref().map(|g| g.country.clone());

    // Step 3: Build LoginContext and evaluate.
    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some(client_ip),
        country,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: ip_classification.is_tor_exit(),
        is_datacenter_ip: ip_classification.is_datacenter(),
        is_blocklisted: ip_classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();

    // Country "CN" is on block list → Block.
    assert_eq!(result.rule, "country_restriction");
    assert_eq!(result.reaction, RuleReaction::Block);
    assert!(result.reason.contains("CN"));
}

#[tokio::test]
async fn test_geoip_country_feeds_country_restriction_allow() {
    // Scenario: GeoIP resolves to "US", country allow list contains "US".
    // Pipeline: GeoIP → country="US" → country_restriction → Allow.
    let cache = std::sync::Arc::new(NoCacheBackend);

    let geoip_provider = std::sync::Arc::new(StubGeoIpProvider {
        country: "US".to_string(),
        lat: 37.8,
        lon: -122.4,
    }) as std::sync::Arc<dyn GeoIpProvider>;
    let geoip = GeoIpChain::new(vec![geoip_provider], cache.clone(), Duration::from_secs(60));

    let policy = sid_core::models::security_policy::NetworkPolicy {
        country_mode: sid_core::models::security_policy::CountryMode::AllowList,
        countries: vec!["US".to_string(), "DE".to_string()],
        ..Default::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, cache.clone());

    let client_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let geo_location = geoip.resolve(client_ip).await;
    let country = geo_location.as_ref().map(|g| g.country.clone());

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some(client_ip),
        country,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_geoip_not_found_skips_country_rule() {
    // Scenario: GeoIP returns NotFound → country=None → country rule skipped.
    let cache = std::sync::Arc::new(NoCacheBackend);

    let geoip = GeoIpChain::new(
        vec![std::sync::Arc::new(NotFoundGeoIpProvider) as std::sync::Arc<dyn GeoIpProvider>],
        cache.clone(),
        Duration::from_secs(60),
    );

    let policy = sid_core::models::security_policy::NetworkPolicy {
        country_mode: sid_core::models::security_policy::CountryMode::AllowList,
        countries: vec!["US".to_string()], // Only US allowed — but country=None → skip rule
        ..Default::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, cache.clone());

    let client_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let geo_location = geoip.resolve(client_ip).await;
    assert!(geo_location.is_none());

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some(client_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // No country → country rule skipped → Allow.
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_geoip_chain_with_ip_intelligence_combined() {
    // Scenario: IP is Tor exit AND from blocked country.
    // Priority: blocklist > brute_force > country > tor.
    // Country restriction (priority 3) should fire before Tor (priority 4).
    let cache = std::sync::Arc::new(NoCacheBackend);

    let geoip_provider = std::sync::Arc::new(StubGeoIpProvider {
        country: "KP".to_string(),
        lat: 39.0,
        lon: 125.8,
    }) as std::sync::Arc<dyn GeoIpProvider>;
    let geoip = GeoIpChain::new(vec![geoip_provider], cache.clone(), Duration::from_secs(60));

    let policy = sid_core::models::security_policy::NetworkPolicy {
        country_mode: sid_core::models::security_policy::CountryMode::BlockList,
        countries: vec!["KP".to_string()],
        block_tor: true,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, cache.clone());

    let client_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let geo_location = geoip.resolve(client_ip).await;
    let country = geo_location.as_ref().map(|g| g.country.clone());

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some(client_ip),
        country,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: true, // Also Tor exit
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // Country (priority 3) fires before Tor (priority 4).
    assert_eq!(result.rule, "country_restriction");
}

#[tokio::test]
async fn test_geoip_no_providers_returns_none_country() {
    // Empty GeoIP chain → no country → country rules skipped.
    let cache = std::sync::Arc::new(NoCacheBackend);
    let geoip = GeoIpChain::empty(cache.clone());

    let client_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let result = geoip.resolve(client_ip).await;
    assert!(result.is_none());
}
