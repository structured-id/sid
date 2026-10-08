// SPDX-License-Identifier: AGPL-3.0-only
//! Administrator provisioning (`CreateProfile`) stores a new account whole or
//! not at all: profile, signup principal and contact rows in one write, the
//! principal linked to the contact row it came from.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token};
use sid_core::models::principal::{Principal, PrincipalId, PrincipalType};
use sid_core::models::{AuditEntry, ProfileId};
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use tonic::Request;

fn create(svc: &TestServices, msg: CreateProfileRequest) -> Request<CreateProfileRequest> {
    let mut request = Request::new(msg);
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn request(
    username: Option<&str>,
    email: Option<&str>,
    phone: Option<&str>,
) -> CreateProfileRequest {
    CreateProfileRequest {
        username: username.map(String::from),
        email: email.map(String::from),
        phone: phone.map(String::from),
        ..Default::default()
    }
}

/// A username another account already holds as its login handle is refused
/// and nothing is stored (before, the profile was created and the duplicate
/// login handle was only logged).
#[tokio::test]
async fn taken_username_stores_nothing() {
    let holder = ProfileId::generate();
    let now = chrono::Utc::now();
    let svc = TestServices::new(MockStorage::new());
    svc.storage
        .save_principal(
            &Principal {
                id: PrincipalId::new(),
                profile_id: holder,
                principal_type: PrincipalType::Username,
                value: "bob".into(),
                verified: true,
                verified_at: Some(now),
                verification_expires: None,
                assigned_profile_id: Some(holder),
                assignment_revision: 1,
                email_policy_revision: None,
                is_primary: true,
                source_field: Some("username".into()),
                source_email_id: None,
                source_phone_id: None,
                created_at: now,
                updated_at: now,
            },
            AuditEntry::system("test", "holder").into(),
        )
        .await
        .unwrap();

    let err = svc
        .identity
        .create_profile(create(&svc, request(Some("bob"), None, None)))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::AlreadyExists);
    assert!(
        svc.storage
            .get_profile_by_username("bob")
            .await
            .unwrap()
            .is_none()
    );
}

/// Regression: provisioning stored the email as typed as the login handle
/// (so a differently spelled sign-in found nothing) and looked it up raw. The
/// principal holds the resolution key, the contact the spelling given, and an
/// equivalent spelling is refused as the same handle.
#[tokio::test]
async fn provisioned_email_is_keyed_and_keeps_its_spelling() {
    let svc = TestServices::new(MockStorage::new());
    let created = svc
        .identity
        .create_profile(create(
            &svc,
            request(None, Some("Ann.Smith+work@SID.example.com"), None),
        ))
        .await
        .expect("provisioned")
        .into_inner();
    let profile = svc
        .storage
        .get_profile_by_principal(PrincipalType::Email, "annsmith@sid.example.com")
        .await
        .unwrap()
        .expect("the key finds the account");
    assert_eq!(Some(profile.id.to_string()), created.profile.map(|p| p.id));
    let emails = svc.storage.list_profile_emails(profile.id).await.unwrap();
    assert_eq!(emails[0].email, "Ann.Smith+work@sid.example.com");

    let err = svc
        .identity
        .create_profile(create(
            &svc,
            request(None, Some("annsmith@sid.example.com"), None),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{err:?}");
}

/// A malformed phone number is refused instead of storing a login handle
/// with no contact row behind it.
#[tokio::test]
async fn malformed_phone_is_refused() {
    let svc = TestServices::new(MockStorage::new());

    let err = svc
        .identity
        .create_profile(create(&svc, request(None, None, Some("not-a-number"))))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        svc.storage
            .get_principal_by_value(PrincipalType::Phone, "not-a-number")
            .await
            .unwrap()
            .is_none()
    );
}

/// A referrer that is not a profile id, or names no profile, is refused and
/// nothing is stored (before, a malformed one was dropped and the account was
/// created with its source misattributed).
#[tokio::test]
async fn unknown_referrer_is_refused() {
    let svc = TestServices::new(MockStorage::new());
    for referrer in ["not-a-profile", &ProfileId::generate().to_string()] {
        let mut msg = request(Some("dave"), None, None);
        msg.referrer_id = Some(referrer.to_string());
        let err = svc
            .identity
            .create_profile(create(&svc, msg))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{referrer}");
    }
    assert!(
        svc.storage
            .get_profile_by_username("dave")
            .await
            .unwrap()
            .is_none()
    );
}

/// The email login handle points at the email contact row created with it.
#[tokio::test]
async fn email_principal_links_its_contact_row() {
    let svc = TestServices::new(MockStorage::new());

    let profile = svc
        .identity
        .create_profile(create(
            &svc,
            request(None, Some("carol@sid.example.com"), None),
        ))
        .await
        .unwrap()
        .into_inner()
        .profile
        .unwrap();

    let profile_id = ProfileId::parse(&profile.id).unwrap();
    let principals = svc
        .storage
        .get_principals_by_profile(profile_id)
        .await
        .unwrap();
    let principal = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Email)
        .expect("email principal stored");
    let email = svc
        .storage
        .get_primary_profile_email(profile_id)
        .await
        .unwrap()
        .expect("email contact stored");
    assert_eq!(principal.source_email_id, Some(email.id));
}
