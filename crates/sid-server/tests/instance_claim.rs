// SPDX-License-Identifier: AGPL-3.0-only
//! First administrator through the instance claim (enrollment-policy.md,
//! First Administrator): while an installation has no administrator, the only
//! registration accepted presents the claim token from the service log, and it
//! makes the registrant administrator; a signed-in profile may claim instead.

mod common;

use common::mock_storage::MockStorage;
use common::opaque_client::try_register;
use common::{TestServices, fresh_token, test_key_manager};
use secrecy::{ExposeSecret, SecretString};
use sid_core::models::Profile;
use sid_proto::sid::v1::ClaimInstanceRequest;
use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;
use sid_proto::sid::v1::admin_service_server::AdminService;
use sid_server::grpc::enrollment_service::EnrollmentServiceImpl;
use tonic::{Code, Request};

const PASSWORD: &[u8] = b"a long enough first administrator password";

async fn claim_token(svc: &TestServices) -> SecretString {
    sid_authn::admin_claim::open_claim(svc.storage.as_ref(), test_key_manager().as_ref())
        .await
        .unwrap()
        .expect("an unclaimed installation opens a claim")
}

async fn is_admin(svc: &TestServices, principal: &str) -> bool {
    let profile_id = svc
        .storage
        .get_principal_by_value(sid_core::models::PrincipalType::Username, principal)
        .await
        .unwrap()
        .and_then(|p| p.assigned_profile_id)
        .expect("registered");
    svc.storage
        .get_profile(profile_id)
        .await
        .unwrap()
        .unwrap()
        .is_admin()
}

async fn claimed(svc: &TestServices) -> bool {
    let enrollment = EnrollmentServiceImpl::new(
        svc.storage.clone(),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
    );
    enrollment
        .get_instance_status(Request::new(()))
        .await
        .unwrap()
        .into_inner()
        .claimed
}

/// Before the claim nobody registers, whatever the mode; the claim token makes
/// the registrant administrator once; afterwards registration is ordinary and
/// the spent token grants nothing.
#[tokio::test]
async fn unclaimed_installation_registers_only_its_first_administrator() {
    let svc = TestServices::new(MockStorage::unclaimed());
    let token = claim_token(&svc).await;
    assert!(!claimed(&svc).await);

    let err = try_register(&svc, &svc, "squatter", PASSWORD, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{}", err.message());

    let err = try_register(&svc, &svc, "guesser", PASSWORD, Some("sidclaim_guess"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{}", err.message());

    try_register(&svc, &svc, "owner", PASSWORD, Some(token.expose_secret()))
        .await
        .unwrap();
    assert!(is_admin(&svc, "owner").await);
    assert!(claimed(&svc).await);

    try_register(&svc, &svc, "member", PASSWORD, None)
        .await
        .unwrap();
    assert!(!is_admin(&svc, "member").await);
    try_register(&svc, &svc, "late", PASSWORD, Some(token.expose_secret()))
        .await
        .unwrap();
    assert!(
        !is_admin(&svc, "late").await,
        "a spent claim made an administrator"
    );
}

/// A signed-in profile claims with the token, once; a wrong token and an
/// anonymous caller get nothing.
#[tokio::test]
async fn signed_in_profile_claims_the_installation() {
    let alice = Profile::new(Some("alice"));
    let bob = Profile::new(Some("bob"));
    let storage = MockStorage::unclaimed()
        .with_profile(alice.clone())
        .with_profile(bob.clone());
    let svc = TestServices::new(storage);
    let token = claim_token(&svc).await;
    let request = |bearer: Option<&str>, claim: &str| {
        let mut req = Request::new(ClaimInstanceRequest {
            claim_token: claim.to_string(),
        });
        if let Some(bearer) = bearer {
            req.metadata_mut()
                .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
        }
        req
    };

    let err = svc
        .admin
        .claim_instance(request(None, token.expose_secret()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    let bob_token = fresh_token(&svc, &bob).await;
    let err = svc
        .admin
        .claim_instance(request(Some(&bob_token), "sidclaim_guess"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    let alice_token = fresh_token(&svc, &alice).await;
    svc.admin
        .claim_instance(request(Some(&alice_token), token.expose_secret()))
        .await
        .unwrap();
    let alice_now = svc.storage.get_profile(alice.id).await.unwrap().unwrap();
    assert!(alice_now.is_admin());

    let err = svc
        .admin
        .claim_instance(request(Some(&bob_token), token.expose_secret()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        !svc.storage
            .get_profile(bob.id)
            .await
            .unwrap()
            .unwrap()
            .is_admin()
    );
}
