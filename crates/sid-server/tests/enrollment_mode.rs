// SPDX-License-Identifier: AGPL-3.0-only
//! The enrollment mode in force (enrollment-policy.md): an administrator
//! stores it, a deployment may pin it, and self-registration follows it at
//! its start and again at its commit.

mod common;

use common::mock_storage::MockStorage;
use common::opaque_client::try_register;
use common::{TestServices, fresh_token, zkpp_client};
use sid_core::models::{EnrollmentMode, PrincipalType, Profile};
use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;
use sid_proto::sid::v1::admin::{
    EnrollmentMode as ProtoMode, EnrollmentPolicy as ProtoPolicy, InviteConfig,
    UpdateEnrollmentPolicyRequest,
};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::{OpaqueZkppRegistrationFinishRequest, OpaqueZkppRegistrationStartRequest};
use sid_server::grpc::enrollment_service::EnrollmentServiceImpl;
use tonic::{Code, Request};
use tonic_types::StatusExt;

const PASSWORD: &[u8] = b"a long enough password for enrollment tests";

fn administrator() -> Profile {
    let mut admin = Profile::new(Some("enrollment_admin"));
    admin.roles.push("admin".to_string());
    admin
}

fn enrollment(svc: &TestServices, pinned: Option<EnrollmentMode>) -> EnrollmentServiceImpl {
    EnrollmentServiceImpl::new(
        svc.storage.clone(),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
    )
    .with_pinned_mode(pinned)
}

fn policy(mode: ProtoMode, domains: &[&str]) -> ProtoPolicy {
    ProtoPolicy {
        mode: mode.into(),
        invite: Some(InviteConfig {
            default_max_uses: 1,
            default_expiry_hours: 72,
        }),
        allowed_domains: domains.iter().map(|d| (*d).to_string()).collect(),
        track_source: true,
        mode_pinned: false,
    }
}

async fn update(
    svc: &TestServices,
    service: &EnrollmentServiceImpl,
    caller: &Profile,
    policy: ProtoPolicy,
) -> Result<ProtoPolicy, tonic::Status> {
    let mut request = Request::new(UpdateEnrollmentPolicyRequest {
        policy: Some(policy),
    });
    let bearer = fresh_token(svc, caller).await;
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    service
        .update_enrollment_policy(request)
        .await
        .map(|r| r.into_inner())
}

async fn registered(svc: &TestServices, principal: &str) -> bool {
    svc.storage
        .get_principal_by_value(PrincipalType::Username, principal)
        .await
        .unwrap()
        .is_some()
}

/// The refusal names the requirement the registration missed.
fn requirement(err: &tonic::Status) -> String {
    let details = err.get_error_details();
    let info = details.error_info().expect("ErrorInfo");
    assert_eq!(info.reason, "REGISTRATION_RESTRICTED");
    info.metadata
        .get("requirement")
        .cloned()
        .expect("requirement")
}

/// A deployment pinning `admin_only` closes self-registration whatever an
/// administrator stored, reports the mode as pinned, and refuses an update
/// that would change it, storing nothing.
#[tokio::test]
async fn pinned_admin_only_closes_self_registration() {
    let admin = administrator();
    let svc = TestServices::with_enrollment_pin(
        MockStorage::new().with_profile(admin.clone()),
        EnrollmentMode::AdminOnly,
    );
    let service = enrollment(&svc, Some(EnrollmentMode::AdminOnly));

    let err = try_register(&svc, &svc, "walk_in", PASSWORD, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{}", err.message());
    assert_eq!(requirement(&err), "admin_only");
    assert!(!registered(&svc, "walk_in").await);

    let current = service
        .get_enrollment_policy(Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(current.mode(), ProtoMode::AdminOnly);
    assert!(current.mode_pinned);

    let err = update(&svc, &service, &admin, policy(ProtoMode::Open, &[]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition, "{}", err.message());
    assert_eq!(
        err.get_error_details().error_info().unwrap().reason,
        "INVALID_STATE"
    );
    assert_eq!(svc.storage.enrollment_policy().await.unwrap(), None);
    let err = try_register(&svc, &svc, "walk_in", PASSWORD, None)
        .await
        .unwrap_err();
    assert_eq!(requirement(&err), "admin_only");
}

/// An administrator's stored mode applies to the next registration on every
/// replica sharing the store, and opening it again admits registration.
#[tokio::test]
async fn stored_mode_applies_to_registration() {
    let admin = administrator();
    let svc = TestServices::new(MockStorage::new().with_profile(admin.clone()));
    let service = enrollment(&svc, None);

    let stored = update(&svc, &service, &admin, policy(ProtoMode::AdminOnly, &[]))
        .await
        .unwrap();
    assert_eq!(stored.mode(), ProtoMode::AdminOnly);
    assert!(!stored.mode_pinned);
    let replica = svc.restarted().await;
    let err = try_register(&replica, &replica, "early", PASSWORD, None)
        .await
        .unwrap_err();
    assert_eq!(requirement(&err), "admin_only");

    update(&svc, &service, &admin, policy(ProtoMode::Open, &[]))
        .await
        .unwrap();
    try_register(&replica, &replica, "later", PASSWORD, None)
        .await
        .unwrap();
    assert!(registered(&svc, "later").await);
}

/// A registration started while open is not committed once the mode is
/// closed before it finishes: the policy is checked again at the commit.
#[tokio::test]
async fn mode_closed_mid_registration_refuses_its_commit() {
    let admin = administrator();
    let svc = TestServices::new(MockStorage::new().with_profile(admin.clone()));
    let service = enrollment(&svc, None);

    let started = zkpp_client::start(PASSWORD);
    let prepared = svc
        .auth
        .opaque_zkpp_registration_start(Request::new(OpaqueZkppRegistrationStartRequest {
            principal: "in_flight".to_string(),
            registration_request: started.request.clone(),
            claim_token: None,
        }))
        .await
        .unwrap()
        .into_inner();

    update(&svc, &service, &admin, policy(ProtoMode::AdminOnly, &[]))
        .await
        .unwrap();

    let err = svc
        .auth
        .opaque_zkpp_registration_finish(Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: prepared.history.unwrap().operation_id,
            registration_record: zkpp_client::finish(
                started,
                PASSWORD,
                &prepared.registration_response,
            ),
            proof: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(requirement(&err), "admin_only");
    assert!(!registered(&svc, "in_flight").await);
}

/// Only an administrator stores a policy; a domain-restricted policy needs a
/// valid domain, and domains are stored as registration compares them.
#[tokio::test]
async fn update_is_an_administrator_action_and_validated() {
    let admin = administrator();
    let member = Profile::new(Some("enrollment_member"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(admin.clone())
            .with_profile(member.clone()),
    );
    let service = enrollment(&svc, None);

    let err = update(&svc, &service, &member, policy(ProtoMode::AdminOnly, &[]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{}", err.message());
    let err = service
        .update_enrollment_policy(Request::new(UpdateEnrollmentPolicyRequest {
            policy: Some(policy(ProtoMode::AdminOnly, &[])),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(svc.storage.enrollment_policy().await.unwrap(), None);

    for bad in [
        policy(ProtoMode::DomainRestricted, &[]),
        policy(ProtoMode::DomainRestricted, &["not a domain"]),
        policy(ProtoMode::Unspecified, &[]),
        ProtoPolicy {
            invite: None,
            ..policy(ProtoMode::Open, &[])
        },
    ] {
        let err = update(&svc, &service, &admin, bad.clone())
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "{bad:?}: {}",
            err.message()
        );
    }
    assert_eq!(svc.storage.enrollment_policy().await.unwrap(), None);

    let stored = update(
        &svc,
        &service,
        &admin,
        policy(
            ProtoMode::DomainRestricted,
            &[" Acme.Example ", "acme.example"],
        ),
    )
    .await
    .unwrap();
    assert_eq!(stored.allowed_domains, vec!["acme.example"]);
}
