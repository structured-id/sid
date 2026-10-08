use super::*;
use chrono::Utc;
use sid_core::models::ProjectId;
use sid_core::models::oauth2_client::{
    ApplicationType, LoginStrategy, SubjectType, TokenEndpointAuthMethod,
};
use sid_core::models::security_policy::SecurityPolicy;

fn ce_policy() -> SecurityPolicy {
    SecurityPolicy::ce_default()
}

fn session_with_level(level: AuthLevel) -> Session {
    let mut session = Session::new(
        sid_core::models::ProfileId::generate(),
        "127.0.0.1".to_string(),
        Utc::now() + chrono::Duration::hours(24),
    );
    session.assurance_level = level;
    session
}

/// A step-up counts while it lasts; once lapsed, a policy that needs it asks
/// for a step-up again.
#[test]
fn test_lapsed_step_up_no_longer_meets_policy() {
    use sid_core::models::session::Elevation;

    let policy = ConditionalAccessEngine::resolve_effective_policy(
        &ce_policy(),
        Some(&test_client()),
        Some(AuthLevel::Elevated),
    );
    let mut session = session_with_level(AuthLevel::Standard);
    session.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: Utc::now() + chrono::Duration::minutes(5),
    });
    assert!(!ConditionalAccessEngine::evaluate(&policy, &session).has_violations());

    session.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: Utc::now() - chrono::Duration::seconds(1),
    });
    assert!(ConditionalAccessEngine::evaluate(&policy, &session).has_violations());
}

fn test_client() -> OAuth2Client {
    OAuth2Client {
        client_id: "test-client".to_string(),
        project_id: ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec![],
        allowed_scopes: vec!["openid".into()],
        grant_types: vec!["authorization_code".into()],
        client_name: "Test".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Pairwise,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 0,
        created_at: Utc::now(),
    }
}

#[test]
fn test_allow_when_session_meets_policy() {
    let policy = ce_policy();
    let session = session_with_level(AuthLevel::Basic);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    assert_eq!(decision.action, EnforcementAction::Allow);
    assert!(decision.violations.is_empty());
    assert!(decision.is_access_granted());
}

#[test]
fn test_step_up_when_below_required() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Standard;
    policy.enforcement.mode = EnforcementMode::Hard;

    let session = session_with_level(AuthLevel::Basic);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    assert_eq!(decision.action, EnforcementAction::StepUp);
    assert_eq!(decision.violations.len(), 1);
    assert_eq!(decision.violations[0].requirement, "min_acr");
    assert!(!decision.is_access_granted());
}

#[test]
fn test_client_override_stricter() {
    let policy = ce_policy(); // min_acr = Basic
    let mut client = test_client();
    client.required_acr = Some(AuthLevel::Elevated);
    client.enforcement_mode = EnforcementMode::Hard;

    let session = session_with_level(AuthLevel::Standard);

    let decision = ConditionalAccessEngine::check(&policy, Some(&client), None, &session);

    assert_eq!(decision.action, EnforcementAction::StepUp);
    assert_eq!(decision.violations.len(), 1);
}

#[test]
fn test_client_override_no_effect_when_weaker() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Elevated;
    policy.enforcement.mode = EnforcementMode::Hard;

    let mut client = test_client();
    client.required_acr = Some(AuthLevel::Basic); // weaker than org
    client.enforcement_mode = EnforcementMode::Audit; // weaker than org

    let effective = ConditionalAccessEngine::resolve_effective_policy(&policy, Some(&client), None);

    // Strictest wins: org values prevail.
    assert_eq!(effective.min_acr, AuthLevel::Elevated);
    assert_eq!(effective.enforcement_mode, EnforcementMode::Hard);
}

/// A level the relying party asks for through `acr_values` raises the
/// requirement above the org and client levels.
#[test]
fn test_requested_acr_raises_requirement() {
    let policy = ce_policy();
    let mut client = test_client();
    client.required_acr = Some(AuthLevel::Standard);

    let effective = ConditionalAccessEngine::resolve_effective_policy(
        &policy,
        Some(&client),
        Some(AuthLevel::Elevated),
    );
    assert_eq!(effective.min_acr, AuthLevel::Elevated);

    let decision = ConditionalAccessEngine::check(
        &policy,
        Some(&client),
        Some(AuthLevel::Elevated),
        &session_with_level(AuthLevel::Standard),
    );
    assert_eq!(decision.action, EnforcementAction::StepUp);
}

/// A requested level below the configured one does not lower it.
#[test]
fn test_requested_acr_never_lowers_requirement() {
    let policy = ce_policy();
    let mut client = test_client();
    client.required_acr = Some(AuthLevel::Elevated);

    let effective = ConditionalAccessEngine::resolve_effective_policy(
        &policy,
        Some(&client),
        Some(AuthLevel::Basic),
    );
    assert_eq!(effective.min_acr, AuthLevel::Elevated);
}

/// The client's enforcement mode decides what an unmet requirement does:
/// with an org in audit mode, a client in audit mode is only logged, while
/// a client in hard mode must step up.
#[test]
fn test_client_enforcement_mode_is_honoured() {
    let mut policy = ce_policy();
    policy.enforcement.mode = EnforcementMode::Audit;
    let session = session_with_level(AuthLevel::Basic);

    let mut client = test_client();
    client.required_acr = Some(AuthLevel::Standard);
    client.enforcement_mode = EnforcementMode::Audit;
    let audited = ConditionalAccessEngine::check(&policy, Some(&client), None, &session);
    assert_eq!(audited.action, EnforcementAction::Allow);
    assert!(audited.has_violations());

    client.enforcement_mode = EnforcementMode::Hard;
    let enforced = ConditionalAccessEngine::check(&policy, Some(&client), None, &session);
    assert_eq!(enforced.action, EnforcementAction::StepUp);
}

#[test]
fn test_audit_mode_allows_with_violations() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Standard;
    policy.enforcement.mode = EnforcementMode::Audit;

    let session = session_with_level(AuthLevel::Basic);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    // Audit mode: allow but report violations.
    assert_eq!(decision.action, EnforcementAction::Allow);
    assert!(decision.is_access_granted());
    assert!(decision.has_violations());
    assert_eq!(decision.violations.len(), 1);
}

#[test]
fn test_soft_mode_step_up() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Standard;
    policy.enforcement.mode = EnforcementMode::Soft;

    let session = session_with_level(AuthLevel::Basic);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    // CE soft mode = step-up (no grace periods in CE).
    assert_eq!(decision.action, EnforcementAction::StepUp);
    assert!(!decision.is_access_granted());
}

#[test]
fn test_no_client_inherits_org() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Standard;

    let effective = ConditionalAccessEngine::resolve_effective_policy(&policy, None, None);

    assert_eq!(effective.min_acr, AuthLevel::Standard);
}

#[test]
fn test_client_none_acr_inherits_org() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Elevated;

    let client = test_client();
    // client.required_acr is None → inherit org.

    let effective = ConditionalAccessEngine::resolve_effective_policy(&policy, Some(&client), None);

    assert_eq!(effective.min_acr, AuthLevel::Elevated);
}

#[test]
fn test_elevated_session_passes_standard_requirement() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Standard;
    policy.enforcement.mode = EnforcementMode::Hard;

    let session = session_with_level(AuthLevel::Elevated);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    assert_eq!(decision.action, EnforcementAction::Allow);
    assert!(decision.is_access_granted());
}

#[test]
fn test_critical_passes_everything() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Critical;
    policy.enforcement.mode = EnforcementMode::Hard;

    let session = session_with_level(AuthLevel::Critical);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    assert_eq!(decision.action, EnforcementAction::Allow);
}

#[test]
fn test_required_actions_populated() {
    let mut policy = ce_policy();
    policy.auth.min_acr = AuthLevel::Standard;
    policy.enforcement.mode = EnforcementMode::Hard;

    let session = session_with_level(AuthLevel::Basic);

    let decision = ConditionalAccessEngine::check(&policy, None, None, &session);

    assert_eq!(decision.required_actions.len(), 1);
    if let RequiredAction::StepUpAuth { target_acr } = &decision.required_actions[0] {
        assert_eq!(*target_acr, AuthLevel::Standard);
    } else {
        panic!("expected StepUpAuth");
    }
}
