// SPDX-License-Identifier: AGPL-3.0-only
//! The error contract of every RPC this server serves: a refusal carries
//! `google.rpc.ErrorInfo` in the `structured.id` domain, whatever the method
//! and whoever calls it.
//!
//! Every service is mounted as the server mounts it and every method is
//! called with an empty request, without a token and as an administrator.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, test_key_manager};
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::grpc_error::DOMAIN_SID;
use sid_core::models::ProfileId;
use sid_proto::sid::v1::account_service_server::AccountServiceServer;
use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentServiceServer;
use sid_proto::sid::v1::admin::provisioning_service_server::ProvisioningServiceServer;
use sid_proto::sid::v1::admin::realm_service_server::RealmServiceServer;
use sid_proto::sid::v1::admin_service_server::AdminServiceServer;
use sid_proto::sid::v1::auth_service_server::AuthServiceServer;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorServiceServer;
use sid_proto::sid::v1::authz::governance_service_server::GovernanceServiceServer;
use sid_proto::sid::v1::authz_service_server::AuthzServiceServer;
use sid_proto::sid::v1::branding_service_server::BrandingServiceServer;
use sid_proto::sid::v1::events::event_stream_service_server::EventStreamServiceServer;
use sid_proto::sid::v1::flow_action_service_server::FlowActionServiceServer;
use sid_proto::sid::v1::flow_config_service_server::FlowConfigServiceServer;
use sid_proto::sid::v1::identity_service_server::IdentityServiceServer;
use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerServiceServer;
use sid_proto::sid::v1::oidc_provider_service_server::OidcProviderServiceServer;
use sid_proto::sid::v1::project_service_server::ProjectServiceServer;
use sid_proto::sid::v1::scim_service_server::ScimServiceServer;
use sid_proto::sid::v1::security_service_server::SecurityServiceServer;
use sid_proto::sid::v1::system_integration_service_server::SystemIntegrationServiceServer;
use sid_serve::error_contract::{Caller, probe};

/// The shared vocabulary handlers build (`sid_core::grpc_error::ErrorReason`)
/// and the one clients generate from (`sid.v1.common.ErrorReason`) name the
/// same reasons: a reason missing on either side is one a client cannot
/// switch on or a server cannot send.
#[test]
fn shared_vocabulary_matches_proto() {
    use std::collections::BTreeSet;
    let pool = prost_reflect::DescriptorPool::decode(sid_proto::FILE_DESCRIPTOR_SET)
        .expect("descriptor set");
    let proto: BTreeSet<String> = pool
        .get_enum_by_name("sid.v1.common.ErrorReason")
        .expect("sid.v1.common.ErrorReason")
        .values()
        .map(|value| value.name().to_owned())
        .filter(|name| name != "ERROR_REASON_UNSPECIFIED")
        .collect();
    let rust: BTreeSet<String> = sid_core::grpc_error::ErrorReason::ALL
        .iter()
        .map(|reason| reason.as_str().to_owned())
        .collect();
    assert_eq!(
        proto.difference(&rust).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "reasons in the proto without a Rust variant"
    );
    assert_eq!(
        rust.difference(&proto).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "Rust reasons the proto does not define"
    );
}

/// Every service of the CE server over `svc`, as the server mounts them.
async fn services(svc: TestServices) -> sid_serve::Services {
    let TestServices {
        admin,
        auth,
        evaluator,
        identity,
        project,
        flow_config,
        flow_action,
        security,
        account,
        storage,
        cache,
        jwt,
        event_bus,
        revocation_cache,
        issuer,
        issuers,
        oidc_issuer,
        ..
    } = svc;
    let scim_resource = sid_authn::issuer::ensure_scim_resource(storage.as_ref(), &issuer)
        .await
        .expect("SCIM resource");
    let scim_issuer = issuer.clone();
    let mut services = sid_serve::Services::new();
    services
        .add(IdentityServiceServer::from_arc(identity))
        .await
        .add(AuthServiceServer::from_arc(auth.clone()))
        .await
        .add(PasswordHistoryEvaluatorServiceServer::new(evaluator))
        .await
        .add(ProjectServiceServer::from_arc(project.clone()))
        .await
        .add(OidcIssuerServiceServer::new(oidc_issuer))
        .await
        .add(OidcProviderServiceServer::new(
            sid_server::grpc::oidc_provider_service::OidcProviderServiceImpl::new(
                issuers,
                storage.clone(),
                revocation_cache.clone(),
                cache.clone(),
                auth,
                project,
                None,
            ),
        ))
        .await
        .add(AuthzServiceServer::new(AuthzServiceImpl::new(
            Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
            storage.clone(),
            CedarService::new(),
            Arc::new(AtomicBool::new(false)),
            jwt.clone(),
            revocation_cache.clone(),
            common::RecordingAuditLog::shared(),
        )))
        .await
        .add(AdminServiceServer::new(admin))
        .await
        .add(BrandingServiceServer::new(
            sid_server::grpc::branding_service::BrandingServiceImpl::new(
                storage.clone(),
                jwt.clone(),
                revocation_cache.clone(),
            ),
        ))
        .await
        .add(FlowConfigServiceServer::new(flow_config))
        .await
        .add(FlowActionServiceServer::new(flow_action))
        .await
        .add(EnrollmentServiceServer::new(
            sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
                storage.clone(),
                jwt.clone(),
                revocation_cache.clone(),
            ),
        ))
        .await
        .add(SecurityServiceServer::new(security))
        .await
        .add(GovernanceServiceServer::new(
            sid_authz::governance_grpc::GovernanceServiceImpl::new(
                storage.clone(),
                jwt.clone(),
                revocation_cache.clone(),
            ),
        ))
        .await
        .add(EventStreamServiceServer::new(
            sid_server::grpc::event_stream_service::EventStreamServiceImpl::new(
                event_bus,
                jwt.clone(),
                revocation_cache.clone(),
            ),
        ))
        .await
        .add(AccountServiceServer::new(account))
        .await
        .add(SystemIntegrationServiceServer::new(
            sid_server::grpc::system_integration_service::SystemIntegrationServiceImpl::new(
                storage.clone(),
                issuer.canonical_url,
                cache,
            ),
        ))
        .await
        .add(ProvisioningServiceServer::new(
            sid_server::grpc::provisioning_service::ProvisioningServiceImpl::new(
                storage.clone(),
                jwt.clone(),
                revocation_cache.clone(),
                scim_issuer,
                scim_resource,
                "https://sid.example.com/scim/v2".into(),
            ),
        ))
        .await
        .add(ScimServiceServer::new(
            sid_scim::grpc::ScimServiceImpl::new(
                storage.clone(),
                sid_scim::mapping::ScimOrgContext {
                    org_domain: "corp.sid.example.com".into(),
                    project_id: sid_core::models::ProjectId::system(),
                },
                "https://sid.example.com".into(),
                sid_scim::grpc::ScimDirectory {
                    org: sid_core::models::OrgId::generate(),
                    resource: sid_core::models::ResourceId::generate(),
                },
                Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
                revocation_cache.clone(),
            ),
        ))
        .await
        .add(RealmServiceServer::new(
            sid_server::grpc::realm_service::RealmServiceImpl::new(
                storage,
                jwt,
                revocation_cache,
                test_key_manager(),
            ),
        ))
        .await;
    services
}

/// Every refusal of every served method, without a token and as an
/// administrator, carries ErrorInfo in the structured.id domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refusal_carries_error_info() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let (routes, health) = services(svc).await.into_parts();
    let report = probe(
        routes,
        health.names(),
        &[sid_proto::FILE_DESCRIPTOR_SET],
        &[DOMAIN_SID],
        &[
            Caller {
                name: "anonymous",
                token: None,
            },
            Caller {
                name: "admin",
                token: Some(&admin_token),
            },
        ],
    )
    .await;

    // Fewer than the 19 services' methods means the descriptor walk is broken.
    assert!(report.methods > 100, "only {} methods", report.methods);
    // An anonymous empty request is refused by nearly every method; far fewer
    // refusals means the calls never reached the handlers.
    assert!(
        report.refusals >= report.methods,
        "only {} refusals over {} methods",
        report.refusals,
        report.methods
    );
    assert!(
        report.violations.is_empty(),
        "{} refusals break the error contract:\n{}",
        report.violations.len(),
        report.violations.join("\n")
    );
}
