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

/// A held address's request is owed one code email; an address nobody holds
/// is answered alike and owed none (before, no request was owed any email:
/// the code was dropped).
#[tokio::test]
async fn only_an_account_is_owed_its_code_email() {
    let address = "mail@sid.example.com";
    let holder = Profile::new(Some("mail"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone()),
    );
    svc.storage
        .save_principal(
            &Principal::new(holder.id, PrincipalType::Email, address),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();

    let unknown = request(&svc, "nobody@sid.example.com").await;
    assert!(owed_code_mails(&svc).await.is_empty());
    let held = request(&svc, address).await;
    let owed = owed_code_mails(&svc).await;

    assert_eq!(owed.len(), 1);
    assert_eq!(
        uuid::Uuid::from_slice(&owed[0].payload[..16])
            .unwrap()
            .to_string(),
        held.otp_session_id
    );
    // Both answers have the same shape.
    assert_eq!(unknown.code_length, held.code_length);
    assert_eq!(unknown.expires_in_seconds, held.expires_in_seconds);
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
    svc.storage
        .save_principal(
            &Principal::new(holder.id, PrincipalType::Email, address),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();
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
