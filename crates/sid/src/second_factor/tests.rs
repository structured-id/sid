use std::sync::Arc;

use sid_core::models::{AuditEntry, Credential, CredentialData};
use sid_plugin::storage::StorageBackend;

use super::*;
use crate::test_support::{keys, sign_in, storage, stored_profile};

fn second_factors(storage: Arc<dyn StorageBackend>) -> SecondFactors {
    let origin = url::Url::parse("https://sid.example.com").unwrap();
    let webauthn = WebAuthnServer::new("sid.example.com", &origin, storage.clone(), keys())
        .expect("WebAuthn relying party");
    SecondFactors::new(
        Arc::new(webauthn),
        "https://sid.example.com".to_string(),
        storage,
        keys(),
    )
}

/// A recovery code set holding the hashes of `codes`.
async fn stored_recovery_codes(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
    codes: &[&str],
) {
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| sid_authn::hash_code(&sid_authn::normalize_code(code)))
        .collect();
    let set = Credential::new(
        profile_id,
        CredentialType::Recovery,
        CredentialData::new(serde_json::to_vec(&hashes).unwrap()),
        None,
    );
    storage
        .create_credential(&set, AuditEntry::system("test", "recovery").into())
        .await
        .unwrap();
}

/// A TOTP code is exactly six ASCII digits; anything else is a malformed
/// request, refused on its field rather than counted as a wrong code.
#[test]
fn totp_code_is_six_digits() {
    require_totp_code_format("123456").unwrap();
    for malformed in ["12345", "1234567", "12345a", "", "１２３４５６"] {
        assert!(matches!(
            require_totp_code_format(malformed),
            Err(SecondFactorError::InvalidField { field: "code", .. })
        ));
    }
}

/// A recovery code is spent once: the set shrinks by one, the same code
/// then fails like a wrong one, and an account without a set has none to
/// spend.
#[tokio::test]
async fn recovery_code_is_spent_once() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    assert!(matches!(
        factors
            .consume_recovery_code(&sign_in, alice, "AAAA-BBBB")
            .await,
        Err(SecondFactorError::NotEnrolled("recovery code set"))
    ));
    stored_recovery_codes(storage.as_ref(), alice, &["AAAA-BBBB", "CCCC-DDDD"]).await;
    assert_eq!(
        factors
            .consume_recovery_code(&sign_in, alice, "AAAA-BBBB")
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        factors
            .consume_recovery_code(&sign_in, alice, "AAAA-BBBB")
            .await,
        Err(SecondFactorError::AuthenticationFailed)
    ));
    assert!(matches!(
        factors
            .consume_recovery_code(&sign_in, alice, "EEEE-FFFF")
            .await,
        Err(SecondFactorError::AuthenticationFailed)
    ));
}

/// The TOTP seed is stored sealed and opens to the enrolled secret; an
/// account without an active authenticator has none.
#[tokio::test]
async fn totp_seed_opens_sealed() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    assert!(
        factors
            .active_totp_seed(&sign_in, alice)
            .await
            .unwrap()
            .is_none()
    );
    let secret = sid_authn::generate_secret();
    let sealed = sid_authn::sealed_secret::seal(
        keys().as_ref(),
        &sid_authn::sealed_secret::totp_context(alice),
        &secret,
    )
    .await
    .unwrap();
    let totp = Credential::new(
        alice,
        CredentialType::Totp,
        CredentialData::new(sealed),
        None,
    );
    storage
        .create_credential(&totp, AuditEntry::system("test", "totp").into())
        .await
        .unwrap();
    let (found, opened) = factors
        .active_totp_seed(&sign_in, alice)
        .await
        .unwrap()
        .expect("the enrolled authenticator");
    assert_eq!(found.id, totp.id);
    assert_eq!(opened.secret.as_slice(), secret.as_slice());
}

/// A finish with no enrollment of the caller's own started answers as
/// expired; a malformed code is refused before any enrollment is consumed.
#[tokio::test]
async fn totp_enrollment_finish_needs_a_started_enrollment() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let enroller = Enroller::SignIn(Box::new(sign_in.new_session(alice, None)));
    assert!(matches!(
        factors
            .totp_enrollment_finish(&sign_in, &enroller, "12x456")
            .await,
        Err(SecondFactorError::InvalidField { field: "code", .. })
    ));
    assert!(matches!(
        factors
            .totp_enrollment_finish(&sign_in, &enroller, "123456")
            .await,
        Err(SecondFactorError::Expired("TOTP enrollment"))
    ));
}

/// A step-up's passkey ceremony is kept under its session and challenge, so
/// a completion on another session never consumes it.
#[test]
fn step_up_ceremony_is_bound_to_its_session() {
    assert_ne!(step_up_key("session-a", "c"), step_up_key("session-b", "c"));
    assert_ne!(
        step_up_key("session-a", "c1"),
        step_up_key("session-a", "c2")
    );
}
