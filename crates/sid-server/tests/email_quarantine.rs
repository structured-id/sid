// SPDX-License-Identifier: AGPL-3.0-only
//! An email key carried from before email policy revisions is quarantined:
//! the holder keeps the account, but the handle routes no password sign-in,
//! email code, or password reset, for any spelling, and every answer reads
//! exactly as for an address nobody holds. An administrator repairs it on an
//! address they assert; the owner alone cannot without confirming it.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::opaque_client::{login, register};
use common::{issue_admin_token, issue_token};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use tonic::Request;

type PrincipalType = sid_core::models::PrincipalType;

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut request = Request::new(msg);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn add_email(profile: sid_core::models::ProfileId, address: &str) -> AddPrincipalRequest {
    AddPrincipalRequest {
        profile_id: profile.to_string(),
        r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
        value: address.to_string(),
    }
}

const PASSWORD: &[u8] = b"quarantine-strong-password-2026";

/// A registered account whose email key is then quarantined, and its id.
async fn quarantined(svc: &TestServices, address: &str) -> sid_core::models::ProfileId {
    register(svc, svc, address, PASSWORD).await;
    let profile = svc
        .storage
        .get_profile_by_principal(PrincipalType::Email, address)
        .await
        .unwrap()
        .expect("registered");
    svc.mock_storage.quarantine_email_key(address);
    profile.id
}

/// The right password does not sign in through a quarantined handle, under
/// its own spelling or an equivalent one, and the refusal is the one an
/// unknown address gets.
#[tokio::test]
async fn password_sign_in_refuses_a_quarantined_handle() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    quarantined(&svc, "ann@sid.example.com").await;

    let unknown = login(&svc, "nobody@sid.example.com", PASSWORD)
        .await
        .unwrap_err();
    for spelling in ["ann@sid.example.com", "A.n.n+x@SID.example.com"] {
        let err = login(&svc, spelling, PASSWORD).await.unwrap_err();
        assert_eq!(err.code(), unknown.code(), "{spelling}");
        assert_eq!(err.message(), unknown.message(), "{spelling}");
    }
}

/// A correct emailed code for a quarantined address opens nothing and reads
/// like a wrong code.
#[tokio::test]
async fn email_code_refuses_a_quarantined_handle() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let profile = quarantined(&svc, "bea@sid.example.com").await;

    let (pending, code) = sid_authn::otp::OtpService::new(svc.cache.clone())
        .request_otp("bea@sid.example.com")
        .await
        .unwrap();
    let verified = svc
        .auth
        .verify_otp(Request::new(VerifyOtpRequest {
            code,
            session_id: Some(pending.session_id.to_string()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(verified, VerifyOtpResponse::default());
    assert!(
        svc.storage
            .list_sessions_by_profile(profile)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A magic link is neither sent to a quarantined address nor, if one was
/// mailed before, accepted for it; the request reads as for any address.
#[tokio::test]
async fn magic_link_refuses_a_quarantined_handle() {
    let address = "corp-quarantined@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new().with_system_project());
    let mut corporate = sid_core::models::Profile::new(Some("corp-quarantined"));
    corporate.profile_type = sid_core::models::ProfileType::Corporate;
    svc.storage
        .create_profile(
            &corporate,
            sid_core::models::AuditEntry::system("t", "p").into(),
        )
        .await
        .unwrap();
    svc.storage
        .save_principal(
            &sid_core::models::Principal::new_email(corporate.id, address),
            sid_core::models::AuditEntry::system("t", "p").into(),
        )
        .await
        .unwrap();
    let (link, token) = sid_authn::magic_link::MagicLinkService::new(svc.storage.clone())
        .request_magic_link(address)
        .await
        .unwrap();
    svc.mock_storage.quarantine_email_key(address);

    let answer = svc
        .auth
        .request_magic_link(Request::new(RequestMagicLinkRequest {
            principal: address.to_string(),
            ..Default::default()
        }))
        .await
        .expect("uniform answer")
        .into_inner();
    assert_eq!(answer.expires_in, 900);
    assert_eq!(
        svc.storage
            .count_active_magic_links_for_email(address)
            .await
            .unwrap(),
        1,
        "only the link issued before the quarantine"
    );

    let err = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: link.session_id.to_string(),
            token,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(
        svc.storage
            .list_sessions_by_profile(corporate.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A reset requested for a quarantined address starts nothing: no reset
/// session, no mail to the uncertain destination, and the answer an unknown
/// address gets.
#[tokio::test]
async fn password_reset_refuses_a_quarantined_handle() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let profile = quarantined(&svc, "cid@sid.example.com").await;

    let reset = |principal: &str| {
        svc.auth
            .request_password_reset(Request::new(RequestPasswordResetRequest {
                principal: principal.to_string(),
                ..Default::default()
            }))
    };
    let held = reset("cid@sid.example.com").await.unwrap().into_inner();
    let unknown = reset("nobody@sid.example.com").await.unwrap().into_inner();
    assert_eq!(held, unknown);
    assert_eq!(
        svc.storage
            .count_active_reset_sessions(profile)
            .await
            .unwrap(),
        0
    );
}

/// An administrator asserting the account's address brings the handle back:
/// it routes the password sign-in again, linked to a contact in the spelling
/// the administrator gave, unverified (an assertion is not a delivered code).
#[tokio::test]
async fn administrator_repairs_a_quarantined_handle() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let profile = quarantined(&svc, "dora@sid.example.com").await;
    let admin = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let listed = |token: String| {
        let identity = svc.identity.clone();
        async move {
            identity
                .list_principals(authed(
                    ListPrincipalsRequest {
                        profile_id: profile.to_string(),
                    },
                    &token,
                ))
                .await
                .unwrap()
                .into_inner()
                .principals
                .into_iter()
                .find(|p| p.value == "dora@sid.example.com")
                .unwrap()
        }
    };
    assert!(
        listed(admin.clone()).await.needs_address_confirmation,
        "the quarantine is shown"
    );

    let repaired = svc
        .identity
        .add_principal(authed(
            add_email(profile, "Dora+inbox@sid.example.com"),
            &admin,
        ))
        .await
        .expect("repaired")
        .into_inner()
        .principal
        .unwrap();
    assert_eq!(repaired.value, "dora@sid.example.com");

    login(&svc, "dora@sid.example.com", PASSWORD)
        .await
        .expect("the handle routes again");
    let claim = svc
        .storage
        .get_principals_by_profile(profile)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.value == "dora@sid.example.com")
        .unwrap();
    let contact = svc
        .storage
        .get_profile_email(claim.source_email_id.expect("linked to its contact"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(contact.email, "Dora+inbox@sid.example.com");
    assert!(!contact.verified);
    let shown = listed(admin).await;
    assert!(!shown.needs_address_confirmation);
    assert_eq!(shown.source_email_id, Some(contact.id.0.to_string()));
}

/// The owner adding the address again does not repair the handle: an
/// owner's own claim is no evidence of the address. The refusal says the
/// address must be confirmed, and the handle stays out of routing.
#[tokio::test]
async fn owner_alone_cannot_repair_a_quarantined_handle() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let profile_id = quarantined(&svc, "eve@sid.example.com").await;
    let profile = svc.storage.get_profile(profile_id).await.unwrap().unwrap();
    let own = issue_token(&svc.jwt, &profile, &[]);

    let err = svc
        .identity
        .add_principal(authed(add_email(profile_id, "eve@sid.example.com"), &own))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
    login(&svc, "eve@sid.example.com", PASSWORD)
        .await
        .expect_err("still quarantined");
}

/// Adding an email handle keeps the address as given: the principal holds
/// the key, linked to a contact in the given spelling.
#[tokio::test]
async fn added_email_handle_keeps_its_address() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    register(&svc, &svc, "fay@sid.example.com", PASSWORD).await;
    let profile = svc
        .storage
        .get_profile_by_principal(PrincipalType::Email, "fay@sid.example.com")
        .await
        .unwrap()
        .unwrap();
    let own = issue_token(&svc.jwt, &profile, &[]);

    svc.identity
        .add_principal(authed(
            add_email(profile.id, "Fay.Work+x@sid.example.com"),
            &own,
        ))
        .await
        .expect("added");
    let claim = svc
        .storage
        .get_principals_by_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.value == "faywork@sid.example.com")
        .expect("the key");
    let contact = svc
        .storage
        .get_profile_email(claim.source_email_id.expect("linked"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(contact.email, "Fay.Work+x@sid.example.com");
}
