// SPDX-License-Identifier: AGPL-3.0-only
//! Email OTP sign-in: an unknown address takes the same path as a known one,
//! and a verified code signs in the profile the address routes to.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_core::models::{
    AuditEntry, EmailLabel, Principal, PrincipalType, Profile, ProfileEmail, ProfileEmailId,
};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

async fn request(svc: &TestServices, address: &str) -> RequestOtpResponse {
    svc.auth
        .request_otp(Request::new(RequestOtpRequest {
            principal: address.to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
}

/// An address nobody holds gets a real pending code like any other: resend
/// and a wrong code answer exactly as for a held address, so neither tells
/// whether an account exists.
#[tokio::test]
async fn unknown_address_takes_the_same_path() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let pending = request(&svc, "nobody@sid.example.com").await;

    svc.auth
        .resend_otp(Request::new(ResendOtpRequest {
            session_id: Some(pending.otp_session_id.clone()),
        }))
        .await
        .expect("resend answers as for a held address");
    let verified = svc
        .auth
        .verify_otp(Request::new(VerifyOtpRequest {
            code: "00000000".to_string(),
            session_id: Some(pending.otp_session_id),
        }))
        .await
        .expect("a wrong code answers as for a held address");
    // A refused code opens nothing and delivers no credential.
    assert!(verified.metadata().get("authorization").is_none());
    assert!(verified.metadata().get("set-cookie").is_none());
    let verified = verified.into_inner();
    assert!(!verified.verified);
    assert_eq!(verified.session_id, None);
    assert_eq!(verified.expires_in, None);
}

/// Bind the email key `key` to `holder` as registration does: with the
/// contact holding `mailbox`, the spelling login mail goes to.
async fn bind_mailbox(svc: &TestServices, holder: &Profile, key: &str, mailbox: &str) {
    let contact = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: holder.id,
        email: mailbox.to_string(),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: Some(chrono::Utc::now()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    svc.storage
        .create_profile_email(&contact, AuditEntry::system("test", "contact").into())
        .await
        .unwrap();
    let mut principal = Principal::new(holder.id, PrincipalType::Email, key);
    principal.source_email_id = Some(contact.id);
    svc.storage
        .save_principal(&principal, AuditEntry::system("test", "principal").into())
        .await
        .unwrap();
}

/// The code mails the storage owes now.
async fn owed_code_mails(svc: &TestServices) -> Vec<sid_core::models::ClaimedWork> {
    svc.storage
        .claim_work(
            &[sid_core::models::WorkKind::new(sid_authn::otp::OTP_EMAIL_KIND).unwrap()],
            "test",
            100,
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap()
}

/// The code mail an RPC request is owed, as any replica reads it: the
/// mailbox and code it would send, or `None` when it sends nothing.
async fn pending_mail(
    svc: &TestServices,
    pending: &RequestOtpResponse,
    owed: &sid_core::models::ClaimedWork,
) -> Option<sid_authn::otp::PendingCode> {
    sid_authn::otp::OtpService::new(
        svc.storage.clone(),
        sid_authn::otp::CodeDelivery {
            keys: common::test_key_manager(),
            work: svc.storage.clone(),
            capacity: 10,
        },
    )
    .pending_delivery(
        pending.otp_session_id.parse().unwrap(),
        uuid::Uuid::from_slice(&owed.payload[16..]).unwrap(),
        chrono::Utc::now(),
    )
    .await
    .unwrap()
}

/// Every request is owed one code mail naming its session, held address or
/// not, so neither the answer nor the work tells them apart; only the held
/// address's mail sends anything (before, no request was owed any email:
/// the code was dropped).
#[tokio::test]
async fn only_an_account_gets_its_code_mail() {
    let address = "mail@sid.example.com";
    let holder = Profile::new(Some("mail"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone()),
    );
    bind_mailbox(&svc, &holder, address, address).await;

    let unknown = request(&svc, "nobody@sid.example.com").await;
    let unknown_owed = owed_code_mails(&svc).await;
    let held = request(&svc, address).await;
    let held_owed = owed_code_mails(&svc).await;

    assert_eq!((unknown_owed.len(), held_owed.len()), (1, 1));
    assert_eq!(
        uuid::Uuid::from_slice(&held_owed[0].payload[..16])
            .unwrap()
            .to_string(),
        held.otp_session_id
    );
    assert!(
        pending_mail(&svc, &unknown, &unknown_owed[0])
            .await
            .is_none()
    );
    let mail = pending_mail(&svc, &held, &held_owed[0]).await.unwrap();
    assert_eq!(mail.destination, address);
    // Both answers have the same shape.
    assert_eq!(unknown.code_length, held.code_length);
    assert_eq!(unknown.expires_in_seconds, held.expires_in_seconds);
}

/// A code goes to the mailbox the account bound its address with, whatever
/// spelling requests it: the resolution key folds dots, tags and case, so
/// mailing the key (or the caller's spelling) could hand the code to
/// another mailbox the key equates with the account's.
#[tokio::test]
async fn code_goes_to_the_bound_mailbox_not_the_key() {
    let mailbox = "John.Smith+id@sid.example.com";
    let holder = Profile::new(Some("john"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone()),
    );
    bind_mailbox(&svc, &holder, "johnsmith@sid.example.com", mailbox).await;

    let pending = request(&svc, "J.O.H.N.Smith@sid.example.com").await;

    let owed = owed_code_mails(&svc).await;
    assert_eq!(owed.len(), 1);
    let mail = pending_mail(&svc, &pending, &owed[0])
        .await
        .expect("the code waits for its mail");
    assert_eq!(mail.destination, mailbox);
}

/// An account whose binding records no mailbox spelling gets no code mail:
/// the lost spelling is not rebuilt from the key.
#[tokio::test]
async fn no_recorded_mailbox_means_no_code_mail() {
    let holder = Profile::new(Some("nomail"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone()),
    );
    svc.storage
        .save_principal(
            &Principal::new(holder.id, PrincipalType::Email, "nomail@sid.example.com"),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();

    let pending = request(&svc, "nomail@sid.example.com").await;

    let owed = owed_code_mails(&svc).await;
    assert_eq!(owed.len(), 1);
    assert!(pending_mail(&svc, &pending, &owed[0]).await.is_none());
}

/// A resent code is verified against the session the client already holds
/// (it once went to a new session the client never learned).
#[tokio::test]
async fn resent_code_verifies_in_the_original_session() {
    let address = "resend@sid.example.com";
    let holder = Profile::new(Some("resend"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone()),
    );
    bind_mailbox(&svc, &holder, address, address).await;
    let pending = request(&svc, address).await;
    owed_code_mails(&svc).await;

    svc.auth
        .resend_otp(Request::new(ResendOtpRequest {
            session_id: Some(pending.otp_session_id.clone()),
        }))
        .await
        .unwrap();

    // The resent code's mail names the original session.
    let owed = owed_code_mails(&svc).await;
    assert_eq!(owed.len(), 1);
    let session = uuid::Uuid::from_slice(&owed[0].payload[..16]).unwrap();
    assert_eq!(session.to_string(), pending.otp_session_id);
}

/// The profile signed in is the one the address routes to: a claimant that
/// merely lists the address as a contact does not get the session.
#[tokio::test]
async fn code_signs_in_the_assigned_holder() {
    let address = "held@sid.example.com";
    let holder = Profile::new(Some("holder"));
    let claimant = Profile::new(Some("claimant"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone())
            .with_profile(claimant.clone()),
    );
    for profile in [&holder, &claimant] {
        svc.storage
            .save_principal(
                &Principal::new(profile.id, PrincipalType::Email, address),
                AuditEntry::system("test", "principal").into(),
            )
            .await
            .unwrap();
    }
    // The claimant's contact row is the one a lookup by contact email finds.
    svc.storage
        .create_profile_email(
            &ProfileEmail {
                id: ProfileEmailId::new(),
                profile_id: claimant.id,
                email: address.to_string(),
                label: EmailLabel::Personal,
                custom_label: None,
                is_primary: true,
                verified: false,
                verified_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            AuditEntry::system("test", "contact").into(),
        )
        .await
        .unwrap();

    // The mailbox reader's code, issued the way RequestOtp issues it.
    let (pending, code) = common::issue_code(&svc.storage, address).await;
    let verified = svc
        .auth
        .verify_otp(Request::new(VerifyOtpRequest {
            code,
            session_id: Some(pending.session_id.to_string()),
        }))
        .await
        .unwrap();
    // A native client gets the session's token in metadata.
    let token = common::opaque_client::bearer(&verified);
    let verified = verified.into_inner();
    assert!(verified.verified);

    let holder_sessions = svc.storage.list_sessions(&holder.id).await.unwrap();
    let claimant_sessions = svc.storage.list_sessions(&claimant.id).await.unwrap();
    assert_eq!(holder_sessions.len(), 1, "the holder was not signed in");
    assert!(claimant_sessions.is_empty(), "the claimant was signed in");
    // An emailed code is confirmation over a second channel: `mca`
    // (RFC 8176 §2), the value the passwordless flow names.
    assert_eq!(holder_sessions[0].amr, ["mca"]);
    // The caller receives the session the code opened, so the sign-in can
    // continue; before, it was created and its token thrown away.
    assert_eq!(
        verified.session_id.as_deref(),
        Some(holder_sessions[0].id.to_string().as_str())
    );
    let claims = svc.jwt.validate_access_token(&token).unwrap();
    assert_eq!(claims.sid, holder_sessions[0].id.to_string());
    assert!(verified.expires_in.is_some_and(|secs| secs > 0));
}

/// Sign-in risk rules that cannot read the profile's sign-in history refuse
/// the sign-in rather than run on a history that looks empty (a failed read
/// once skipped impossible-travel and designated-location checks).
#[tokio::test]
async fn unreadable_sign_in_history_refuses_the_sign_in() {
    let address = "history@sid.example.com";
    let holder = Profile::new(Some("history"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone())
            .with_failing_login_history(),
    );
    svc.storage
        .save_principal(
            &Principal::new(holder.id, PrincipalType::Email, address),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();

    let (pending, code) = common::issue_code(&svc.storage, address).await;
    let err = svc
        .auth
        .verify_otp(Request::new(VerifyOtpRequest {
            code,
            session_id: Some(pending.session_id.to_string()),
        }))
        .await
        .expect_err("a sign-in was allowed without its history");
    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert!(
        svc.storage
            .list_sessions(&holder.id)
            .await
            .unwrap()
            .is_empty()
    );
}
