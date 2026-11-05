// SPDX-License-Identifier: AGPL-3.0-only
//! The references of the sign-in path are binary identifiers: each one is
//! validated before anything is looked up, and an absent or malformed one is
//! refused as that field, never answered as an unknown or expired ceremony.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};

/// The field a refusal names in its `BadRequest` detail.
fn violated_field(status: &Status) -> Option<String> {
    tonic_types::StatusExt::get_details_bad_request(status)
        .and_then(|b| b.field_violations.into_iter().next())
        .map(|v| v.field)
}

fn assert_refused_on(status: &Status, field: &str) {
    assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
    assert_eq!(violated_field(status).as_deref(), Some(field), "{status:?}");
}

/// Bytes that are not an identifier: one byte short.
fn short() -> Vec<u8> {
    vec![0x01; 15]
}

#[tokio::test]
async fn email_code_references_are_refused_on_their_field() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    for otp_session_id in [None, Some(sid_ids_proto::OtpSessionId { value: short() })] {
        let err = svc
            .auth
            .verify_otp(Request::new(VerifyOtpRequest {
                code: "12345678".into(),
                otp_session_id: otp_session_id.clone(),
            }))
            .await
            .unwrap_err();
        assert_refused_on(&err, "otp_session_id");
        let err = svc
            .auth
            .resend_otp(Request::new(ResendOtpRequest { otp_session_id }))
            .await
            .unwrap_err();
        assert_refused_on(&err, "otp_session_id");
    }
}

#[tokio::test]
async fn a_magic_link_reference_is_refused_on_its_field() {
    let svc = TestServices::with_magic_links(MockStorage::new());
    for magic_link_id in [None, Some(sid_ids_proto::MagicLinkId { value: short() })] {
        let err = svc
            .auth
            .verify_magic_link(Request::new(VerifyMagicLinkRequest {
                magic_link_id,
                token: "token".into(),
            }))
            .await
            .unwrap_err();
        assert_refused_on(&err, "magic_link_id");
    }
}

#[tokio::test]
async fn a_reset_reference_is_refused_on_its_field() {
    let svc = TestServices::new(MockStorage::new());
    for reset_session_id in [None, Some(sid_ids_proto::ResetSessionId { value: short() })] {
        let err = svc
            .auth
            .verify_password_reset(Request::new(VerifyPasswordResetRequest {
                reset_session_id,
                token: "token".into(),
            }))
            .await
            .unwrap_err();
        assert_refused_on(&err, "reset_session_id");
    }
}

#[tokio::test]
async fn an_imported_password_upgrade_reference_is_refused_on_its_field() {
    let svc = TestServices::new(MockStorage::new());
    for upgrade_id in [
        None,
        Some(sid_ids_proto::ImportedPasswordUpgradeId { value: short() }),
    ] {
        let err = svc
            .auth
            .legacy_migrate_finish(Request::new(LegacyMigrateFinishRequest {
                upgrade_id,
                opaque_registration_record: vec![],
            }))
            .await
            .unwrap_err();
        assert_refused_on(&err, "upgrade_id");
    }
}

#[tokio::test]
async fn a_credential_and_a_session_reference_are_refused_on_their_field() {
    let profile = common::test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let token = common::fresh_token(&svc, &profile).await;
    let authed = |message| {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    };
    for credential_id in [None, Some(sid_ids_proto::CredentialId { value: short() })] {
        let err = svc
            .auth
            .password_change_challenge(authed(PasswordChangeChallengeRequest {
                credential_id,
                credential_request: vec![],
                registration_request: vec![],
            }))
            .await
            .unwrap_err();
        assert_refused_on(&err, "credential_id");
    }
    for session_id in [None, Some(sid_ids_proto::SessionId { value: short() })] {
        let mut request = Request::new(ValidateSessionRequest { session_id });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let err = svc.auth.validate_session(request).await.unwrap_err();
        assert_refused_on(&err, "session_id");
    }
}
