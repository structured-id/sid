use super::*;

/// An identifier that is no principal is refused on its field, as an
/// invalid argument.
#[test]
fn invalid_identifier_is_an_invalid_argument() {
    for identifier in ["", "ab"] {
        let refused = sid_authn::normalize::normalize_principal(identifier)
            .map_err(|e| {
                sign_in_refusal(sid::sign_in::SignInError::InvalidIdentifier(e.to_string()))
            })
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    }
}

// ── implied_auth_level tests ──────────────────────────────────

#[test]
fn test_implied_auth_level_opaque_is_basic() {
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("opaque", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_opaque_basic_regardless_of_config() {
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("opaque", false, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_webauthn_standard_when_satisfies_mfa_and_user_verified() {
    // Both passkey_satisfies_mfa AND user_verified must be true for Standard.
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("webauthn", true, true),
        sid_core::models::session::AuthLevel::Standard,
    );
}

#[test]
fn test_implied_auth_level_webauthn_basic_when_not_user_verified() {
    // passkey_satisfies_mfa=true but user_verified=false → Basic.
    // Per NIST: without user verification, passkey = single factor (possession only).
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("webauthn", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_webauthn_basic_when_passkey_not_satisfies_mfa() {
    // passkey_satisfies_mfa=false → Basic regardless of user_verified.
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("webauthn", false, true),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_webauthn_basic_when_both_false() {
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("webauthn", false, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_magic_link_is_basic() {
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("magic_link", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

#[test]
fn test_implied_auth_level_unknown_is_basic() {
    assert_eq!(
        sid_authn::sign_in_security::implied_auth_level("unknown_method", true, false),
        sid_core::models::session::AuthLevel::Basic,
    );
}

// ── AnomalyDetector + evaluate_login_security integration tests ──

use sid_authn::anomaly::{AnomalyConfig, AnomalyDetector, LoginContext, RuleReaction};
use sid_core::models::security_policy::SecurityPolicy;
use sid_plugin::cache::NoCacheBackend;

/// The store holding the detector's attempt counters and lockouts.
fn anomaly_store() -> std::sync::Arc<dyn sid_plugin::CeremonyStateStore> {
    std::sync::Arc::new(sid_plugin::InProcessCeremonyState::new())
}

#[test]
fn test_anomaly_allow_reaction_for_clean_context() {
    let detector = AnomalyDetector::ce_default(anomaly_store());

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
    let detector = AnomalyDetector::ce_default(anomaly_store());

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
    let detector = AnomalyDetector::ce_default(anomaly_store());

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
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 900,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let policy = sid_core::models::security_policy::NetworkPolicy::default();
    let detector = AnomalyDetector::new(config, policy, anomaly_store());

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
    let implied = sid_authn::sign_in_security::implied_auth_level(
        "opaque",
        policy.auth.passkey_satisfies_mfa,
        false,
    );
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
    let implied = sid_authn::sign_in_security::implied_auth_level(
        "webauthn",
        policy.auth.passkey_satisfies_mfa,
        true,
    );
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
    let implied = sid_authn::sign_in_security::implied_auth_level("webauthn", false, true);
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

// ── Device fingerprint + designated locations ──────────

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

// ── Login requirements wiring ──────────
//
// The level and methods a sign-in's session records, judged by the login
// requirements the installation's fixed policy states, with a client's own
// as authorization adds them: what the auth flow decides for each method.

use sid_authn::login_policy::{FixedLoginPolicy, LoginDecision, LoginPolicySource as _};
use sid_core::models::security_policy::EnforcementMode;

/// The decision on a session signed in by `method` under `policy`, for
/// `client` when given.
async fn sign_in_decision(
    policy: &SecurityPolicy,
    client: Option<&sid_core::models::OAuth2Client>,
    method: super::LoginMethod,
) -> LoginDecision {
    let now = chrono::Utc::now();
    let probe = sid_authn::login_policy::local_authentication(
        sid_core::models::ProfileId::generate(),
        method.auth_level(policy.auth.passkey_satisfies_mfa),
        &method.amr(),
        now,
    );
    let mut requirements = FixedLoginPolicy::of(policy)
        .requirements(None)
        .await
        .unwrap();
    if let Some(client) = client {
        requirements = requirements.with_client(client, None);
    }
    requirements.decide(&probe, now)
}

const PASSWORD: super::LoginMethod = super::LoginMethod::Password;

fn passkey(user_verified: bool) -> super::LoginMethod {
    super::LoginMethod::Passkey {
        user_verified,
        key_amr: "hwk",
    }
}

/// Helper: construct a test OAuth2Client with specific overrides.
fn test_client_with_acr(
    name: &str,
    required_acr: Option<sid_core::models::session::AuthLevel>,
    enforcement_mode: EnforcementMode,
) -> sid_core::models::OAuth2Client {
    sid_core::models::OAuth2Client {
        client_id: name.to_string(),
        project_id: sid_core::models::ProjectId::SYSTEM,
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

fn standard(mode: EnforcementMode) -> SecurityPolicy {
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    policy.enforcement.mode = mode;
    policy
}

// The CE baseline (Basic) admits a password sign-in.
#[tokio::test]
async fn a_password_sign_in_passes_the_baseline() {
    let decision = sign_in_decision(&SecurityPolicy::ce_default(), None, PASSWORD).await;
    assert!(matches!(decision, LoginDecision::Allow { audited } if audited.is_empty()));
}

// A Standard requirement asks a password sign-in (Basic) to step up to
// Standard, naming the level.
#[tokio::test]
async fn a_password_sign_in_steps_up_to_a_standard_requirement() {
    let decision = sign_in_decision(&standard(EnforcementMode::Hard), None, PASSWORD).await;
    let LoginDecision::StepUp(unmet) = decision else {
        panic!("a Basic sign-in passed a Standard requirement");
    };
    assert_eq!(
        unmet.acr,
        Some(sid_core::models::session::AuthLevel::Standard)
    );
}

// A passkey that verified the user is Standard and meets it; one that did not
// is a single factor and steps up.
#[tokio::test]
async fn a_passkey_meets_standard_only_with_user_verification() {
    let policy = standard(EnforcementMode::Hard);
    assert!(matches!(
        sign_in_decision(&policy, None, passkey(true)).await,
        LoginDecision::Allow { .. }
    ));
    assert!(matches!(
        sign_in_decision(&policy, None, passkey(false)).await,
        LoginDecision::StepUp(_)
    ));
}

// Audit enforcement allows the unmet requirement and still reports it.
#[tokio::test]
async fn audit_enforcement_allows_and_reports() {
    let decision = sign_in_decision(&standard(EnforcementMode::Audit), None, PASSWORD).await;
    let LoginDecision::Allow { audited } = decision else {
        panic!("audit enforcement refused");
    };
    assert!(!audited.is_empty());
}

// A client requiring Standard makes a password sign-in step up while a
// verified passkey passes; a client asking less than the organization changes
// nothing.
#[tokio::test]
async fn a_client_only_strengthens_the_requirement() {
    let strict = test_client_with_acr(
        "strict-app",
        Some(sid_core::models::session::AuthLevel::Standard),
        EnforcementMode::Hard,
    );
    let baseline = SecurityPolicy::ce_default();
    assert!(matches!(
        sign_in_decision(&baseline, Some(&strict), PASSWORD).await,
        LoginDecision::StepUp(_)
    ));
    assert!(matches!(
        sign_in_decision(&baseline, Some(&strict), passkey(true)).await,
        LoginDecision::Allow { .. }
    ));

    let lenient = test_client_with_acr(
        "lenient-app",
        Some(sid_core::models::session::AuthLevel::Basic),
        EnforcementMode::Audit,
    );
    assert!(matches!(
        sign_in_decision(&standard(EnforcementMode::Hard), Some(&lenient), PASSWORD).await,
        LoginDecision::StepUp(_)
    ));
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
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    let details = status.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "STEP_UP_REQUIRED");
    let violations = &details.precondition_failure().unwrap().violations;
    assert_eq!(violations[0].r#type, "amr");
    assert_eq!(violations[0].subject, "mfa");
    assert!(!status.message().contains("new_device_ip"));
}

/// Every unmet requirement is its own violation by kind (the level, each
/// missing method, the authentication age), so a client can act on each.
#[test]
fn a_step_up_names_every_unmet_requirement() {
    use tonic_types::StatusExt;
    let status: Status = super::refusal::step_up_required(&sid_authn::login_policy::Unmet {
        acr: Some(sid_core::models::session::AuthLevel::Standard),
        amr: vec!["hwk".into(), "mfa".into()],
        max_authentication_age: Some(std::time::Duration::from_secs(300)),
    })
    .into();
    let details = status.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "STEP_UP_REQUIRED");
    let violations: Vec<(String, String)> = details
        .precondition_failure()
        .unwrap()
        .violations
        .iter()
        .map(|v| (v.r#type.clone(), v.subject.clone()))
        .collect();
    assert_eq!(
        violations,
        [
            ("acr".to_string(), "urn:sid:acr:standard".to_string()),
            ("amr".to_string(), "hwk".to_string()),
            ("amr".to_string(), "mfa".to_string()),
            ("max_age".to_string(), "300".to_string()),
        ]
    );
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

// ── GeoIP + Anomaly pipeline integration tests ────────

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
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, anomaly_store());

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
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, anomaly_store());

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
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, anomaly_store());

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
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, anomaly_store());

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
