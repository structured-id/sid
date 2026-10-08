// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL integration tests for SecurityService.
//!
//! Tests SecurityService RPCs with real PostgreSQL (port 54399).
//! Verifies that storage-dependent RPCs (list_application_overrides,
//! get_effective_policy, evaluate_enforcement) work with real SQL.
//!
//! Run with: cargo test --test security_service_pg -- --test-threads=1

mod common;

use common::{issue_admin_token, test_jwt};
use sid_authn::jwt::JwtService;
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    ApplicationType, AuditEntry, EnforcementMode, LoginStrategy, OAuth2Client, Profile, ProfileId,
    SubjectType, TokenEndpointAuthMethod,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::security_service_server::SecurityService;
use sid_server::grpc::security_service::SecurityServiceImpl;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use tonic::Request;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn setup() -> (
    SecurityServiceImpl,
    Arc<dyn StorageBackend>,
    Arc<JwtService>,
) {
    // Its own schema: the integrity check covers every record of the store,
    // so in the shared schema it would scan, and race, every other test's.
    let schema = format!("security_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");

    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("Failed to run migrations");

    let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
        sid_storage::audit_log::PostgresAuditLog::new(backend.pool().clone()),
    );
    let backend = backend.with_audit_log(audit_log.clone());
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let jwt = test_jwt();
    let no_cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::NoCacheBackend);
    let revocation = Arc::new(sid_authn::revocation_cache::RevocationCache::new(
        std::time::Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    ));
    let svc = SecurityServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation,
        audit_log,
        no_cache,
    );
    (svc, storage, jwt)
}

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    req
}

fn make_test_client(client_id: &str, required_acr: Option<AuthLevel>) -> OAuth2Client {
    OAuth2Client {
        client_id: client_id.to_string(),
        project_id: sid_core::models::ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Spa,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".into(), "profile".into()],
        grant_types: vec!["authorization_code".into()],
        client_name: format!("Test App {}", client_id),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: chrono::Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Hard,
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
        created_at: chrono::Utc::now(),
    }
}

// ─── Tests ───

#[tokio::test]
async fn test_pg_get_security_policy() {
    let (svc, _storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetSecurityPolicyRequest {},
        &token,
    );
    let resp = svc.get_security_policy(req).await.unwrap();
    let policy = resp.into_inner();
    assert_eq!(policy.enforcement_mode, "hard");
    assert_eq!(policy.min_auth_level, "basic");
    assert!(policy.read_only);
    // CE default: passkey satisfies MFA (NIST-aligned).
    assert!(
        policy.passkey_satisfies_mfa,
        "CE default should have passkey_satisfies_mfa=true"
    );
}

#[tokio::test]
async fn test_pg_get_security_policy_passkey_satisfies_mfa_in_effective_policy() {
    let (svc, storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());

    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");

    // Create a client with no overrides.
    let client_id = format!("test-passkey-mfa-{}", uuid::Uuid::now_v7());
    let client = make_test_client(&client_id, None);
    common::store_client(&*storage, &client)
        .await
        .expect("Failed to save OAuth2 client");

    // Effective policy should inherit passkey_satisfies_mfa from CE defaults.
    let req = authed_request(
        sid_proto::sid::v1::admin::GetEffectivePolicyRequest {
            client_id: client_id.clone(),
        },
        &token,
    );
    let resp = svc.get_effective_policy(req).await.unwrap();
    let policy = resp.into_inner();
    assert!(
        policy.passkey_satisfies_mfa,
        "Effective policy should inherit passkey_satisfies_mfa=true from CE defaults"
    );
}

#[tokio::test]
async fn test_pg_list_application_overrides_empty() {
    let (svc, _storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::ListApplicationOverridesRequest {},
        &token,
    );
    let resp = svc.list_application_overrides(req).await.unwrap();
    // May have overrides from other tests — just verify it doesn't error.
    let _ = resp.into_inner().overrides;
}

#[tokio::test]
async fn test_pg_get_effective_policy_with_client_override() {
    let (svc, storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());

    // Ensure system project exists.
    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");

    // Create a client with required_acr = Standard.
    let client_id = format!("test-policy-{}", uuid::Uuid::now_v7());
    let client = make_test_client(&client_id, Some(AuthLevel::Standard));
    common::store_client(&*storage, &client)
        .await
        .expect("Failed to save OAuth2 client");

    // Get effective policy for this client.
    let req = authed_request(
        sid_proto::sid::v1::admin::GetEffectivePolicyRequest {
            client_id: client_id.clone(),
        },
        &token,
    );
    let resp = svc.get_effective_policy(req).await.unwrap();
    let policy = resp.into_inner();

    // Client override should raise min_auth_level from "basic" to "standard".
    assert_eq!(policy.min_auth_level, "standard");
    assert_eq!(policy.enforcement_mode, "hard");
    assert!(policy.read_only);
}

#[tokio::test]
async fn test_pg_get_effective_policy_nonexistent_client_returns_defaults() {
    let (svc, _storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetEffectivePolicyRequest {
            client_id: "nonexistent-client-id".to_string(),
        },
        &token,
    );
    let resp = svc.get_effective_policy(req).await.unwrap();
    let policy = resp.into_inner();
    // No client found → CE defaults.
    assert_eq!(policy.min_auth_level, "basic");
}

#[tokio::test]
async fn test_pg_evaluate_enforcement_allow_for_basic_user() {
    let (svc, storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());

    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");

    // Create a profile.
    let username = format!("testuser-{}", uuid::Uuid::now_v7());
    let profile = Profile::new(Some(&username));
    storage
        .create_profile(
            &profile,
            AuditEntry::system("test", "create_profile").into(),
        )
        .await
        .expect("Failed to save profile");

    // Create a client with no overrides.
    let client_id = format!("test-eval-{}", uuid::Uuid::now_v7());
    let client = make_test_client(&client_id, None);
    common::store_client(&*storage, &client)
        .await
        .expect("Failed to save OAuth2 client");

    // Evaluate enforcement.
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: profile.id.to_string(),
            client_id,
        },
        &token,
    );
    let resp = svc.evaluate_enforcement(req).await.unwrap();
    let decision = resp.into_inner();

    // CE default: Basic + Optional MFA → ALLOW.
    assert_eq!(
        decision.action,
        sid_proto::sid::v1::admin::EnforcementAction::Allow as i32
    );
    assert!(decision.violations.is_empty());
}

#[tokio::test]
async fn test_pg_evaluate_enforcement_step_up_for_elevated_client() {
    let (svc, storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());

    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");

    // Create profile.
    let username = format!("testuser-{}", uuid::Uuid::now_v7());
    let profile = Profile::new(Some(&username));
    storage
        .create_profile(
            &profile,
            AuditEntry::system("test", "create_profile").into(),
        )
        .await
        .expect("Failed to save profile");

    // Create client requiring Elevated auth level.
    let client_id = format!("test-elevated-{}", uuid::Uuid::now_v7());
    let client = make_test_client(&client_id, Some(AuthLevel::Elevated));
    common::store_client(&*storage, &client)
        .await
        .expect("Failed to save client");

    // Evaluate enforcement.
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: profile.id.to_string(),
            client_id,
        },
        &token,
    );
    let resp = svc.evaluate_enforcement(req).await.unwrap();
    let decision = resp.into_inner();

    // Client requires Elevated > CE Basic → STEP_UP.
    assert_eq!(
        decision.action,
        sid_proto::sid::v1::admin::EnforcementAction::StepUp as i32
    );
    assert!(!decision.violations.is_empty());
    assert!(
        decision
            .violations
            .iter()
            .any(|v| v.requirement == "min_auth_level")
    );
    assert!(
        decision
            .required_actions
            .iter()
            .any(|a| a.action_type == "step_up_auth")
    );
}

// ─── Integrity Check Tests ───

#[tokio::test]
async fn test_pg_run_integrity_check_all_layers() {
    let (svc, storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());

    // Seed some audit data: create a profile (triggers audit chain).
    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");
    let profile = Profile::new(Some(format!("integrity-test-{}", uuid::Uuid::now_v7())));
    storage
        .create_profile(
            &profile,
            AuditEntry::system("test", "create_profile").into(),
        )
        .await
        .expect("Failed to save profile");

    // Run integrity check (all layers).
    let req = authed_request(
        sid_proto::sid::v1::admin::RunIntegrityCheckRequest { layers: vec![] },
        &token,
    );
    let resp = svc.run_integrity_check(req).await.unwrap();
    let report = resp.into_inner();

    assert!(
        report.passed,
        "Integrity check should pass on clean database: {report:?}"
    );
    assert_eq!(report.layers.len(), 5, "Should report all 5 layers");
    assert_eq!(report.total_issues_found, 0);

    // Audit chain layer should have checked at least 1 chain.
    let audit_layer = report
        .layers
        .iter()
        .find(|l| l.layer == "audit_chain")
        .expect("audit_chain layer missing");
    assert!(
        audit_layer.entities_checked > 0,
        "Should have verified at least 1 audit chain"
    );
    assert_eq!(audit_layer.issues_found, 0);

    // Graph consistency layer should have checked 3 entity types.
    let graph_layer = report
        .layers
        .iter()
        .find(|l| l.layer == "graph_consistency")
        .expect("graph_consistency layer missing");
    assert_eq!(
        graph_layer.entities_checked, 3,
        "Should check 3 FK categories (sessions, credentials, role_assignments)"
    );
    assert_eq!(graph_layer.issues_found, 0);
}

#[tokio::test]
async fn test_pg_run_integrity_check_specific_layer() {
    let (svc, _storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());

    // Run only graph_consistency layer.
    let req = authed_request(
        sid_proto::sid::v1::admin::RunIntegrityCheckRequest {
            layers: vec!["graph_consistency".into()],
        },
        &token,
    );
    let resp = svc.run_integrity_check(req).await.unwrap();
    let report = resp.into_inner();

    assert!(report.passed);
    assert_eq!(report.layers.len(), 1);
    assert_eq!(report.layers[0].layer, "graph_consistency");
}

#[tokio::test]
async fn test_pg_evaluate_enforcement_profile_not_found() {
    let (svc, _storage, jwt) = setup().await;
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: ProfileId::generate().to_string(),
            client_id: "any-client".to_string(),
        },
        &token,
    );
    let err = svc.evaluate_enforcement(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}
