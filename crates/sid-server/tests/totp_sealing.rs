// SPDX-License-Identifier: AGPL-3.0-only
//! TOTP seeds are stored only sealed under the key manager.
//!
//! A TOTP seed is a shared symmetric secret: whoever reads it generates valid
//! codes. These tests pin that the database holds no usable seed, that a
//! sealed seed moved to another profile's row is useless there, and that
//! seeds stored before sealing are sealed on start.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token_with_session, test_profile};
use sid_core::models::session::Session;
use sid_core::models::{AuditEntry, Credential, CredentialData, CredentialType, Profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

fn authed<T>(body: T, bearer: &str) -> Request<T> {
    let mut req = Request::new(body);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    req
}

/// A signed-in bearer for `profile` whose session is stored.
async fn signed_in(svc: &TestServices, profile: &Profile) -> String {
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        issue_token_with_session(&svc.jwt, profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(profile.id.to_string(), "test", session.id.to_string()).into(),
        )
        .await
        .unwrap();
    bearer
}

async fn stored_totp(svc: &TestServices, profile: &Profile) -> Credential {
    svc.storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Totp))
        .await
        .unwrap()
        .pop()
        .expect("TOTP credential stored")
}

/// Enrollment stores the seed sealed: the stored bytes do not contain it and
/// only the key manager, for this profile, reads it back.
#[tokio::test]
async fn enrolled_seed_is_stored_sealed() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let bearer = signed_in(&svc, &profile).await;

    let challenge = svc
        .auth
        .start_totp_enrollment(authed(StartTotpEnrollmentRequest {}, &bearer))
        .await
        .unwrap()
        .into_inner();
    let seed = sid_authn::base32_decode(&challenge.secret).unwrap();
    svc.auth
        .finish_totp_enrollment(authed(
            FinishTotpEnrollmentRequest {
                code: sid_authn::generate_current_totp(&seed),
            },
            &bearer,
        ))
        .await
        .unwrap();

    let stored = stored_totp(&svc, &profile).await;
    let data = stored.data.expose();
    assert!(
        !data.windows(seed.len()).any(|w| w == seed.as_slice()),
        "the database row must not hold the seed"
    );
    assert!(sid_authn::sealed_secret::is_sealed(data));
    let opened = sid_authn::sealed_secret::open(
        common::test_key_manager().as_ref(),
        &sid_authn::sealed_secret::totp_context(profile.id),
        data,
    )
    .await
    .unwrap();
    assert_eq!(opened.secret.as_slice(), seed.as_slice());
}

/// A victim's sealed seed copied onto the attacker's credential row does not
/// verify the victim's codes for the attacker.
#[tokio::test]
async fn sealed_seed_moved_to_another_profile_is_refused() {
    let victim = test_profile();
    let attacker = sid_core::models::Profile::new(Some("mallory"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(victim.clone())
            .with_profile(attacker.clone()),
    );
    let bearer = signed_in(&svc, &attacker).await;

    let seed = sid_authn::generate_secret();
    let victim_sealed = common::sealed_totp_seed(victim.id, &seed).await;
    let planted = Credential::new(
        attacker.id,
        CredentialType::Totp,
        CredentialData::new(victim_sealed),
        None,
    );
    svc.storage
        .create_credential(&planted, AuditEntry::system("test", "plant").into())
        .await
        .unwrap();

    let err = svc
        .auth
        .verify_totp(authed(
            VerifyTotpRequest {
                code: sid_authn::generate_current_totp(&seed),
            },
            &bearer,
        ))
        .await
        .unwrap_err();
    assert_ne!(err.code(), tonic::Code::Ok);
}

/// Seeds stored in plain form before sealing are sealed by the start-up pass
/// and keep working; a second pass changes nothing.
#[tokio::test]
async fn plaintext_seeds_are_sealed_on_start() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let bearer = signed_in(&svc, &profile).await;
    let seed = sid_authn::generate_secret();
    let legacy = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(seed.clone()),
        None,
    );
    svc.storage
        .create_credential(&legacy, AuditEntry::system("test", "legacy").into())
        .await
        .unwrap();

    let km = common::test_key_manager();
    let sealed = sid_authn::sealed_secret::seal_plaintext_credentials(
        svc.storage.as_ref(),
        km.as_ref(),
        CredentialType::Totp,
        |c| sid_authn::sealed_secret::totp_context(c.profile_id),
    )
    .await
    .unwrap();
    assert_eq!(sealed, 1);
    let again = sid_authn::sealed_secret::seal_plaintext_credentials(
        svc.storage.as_ref(),
        km.as_ref(),
        CredentialType::Totp,
        |c| sid_authn::sealed_secret::totp_context(c.profile_id),
    )
    .await
    .unwrap();
    assert_eq!(again, 0);

    let stored = stored_totp(&svc, &profile).await;
    assert!(sid_authn::sealed_secret::is_sealed(stored.data.expose()));
    svc.auth
        .verify_totp(authed(
            VerifyTotpRequest {
                code: sid_authn::generate_current_totp(&seed),
            },
            &bearer,
        ))
        .await
        .unwrap();
}
