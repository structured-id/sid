use std::sync::Arc;

use super::*;

async fn storage() -> Arc<dyn StorageBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    )
}

fn keys() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

fn registration(storage: Arc<dyn StorageBackend>) -> (Registration, Arc<dyn sid_keys::KeyManager>) {
    let keys = keys();
    (
        Registration::new(storage, keys.clone(), "https://sid.example.com".to_string()),
        keys,
    )
}

fn password(profile_id: ProfileId) -> Credential {
    Credential::new(
        profile_id,
        CredentialType::Opaque,
        CredentialData::new(b"password file".to_vec()),
        None,
    )
}

/// While the installation has no administrator, a registration without the
/// claim token is refused before its identifier is looked up.
#[tokio::test]
async fn open_claim_requires_its_token() {
    let (registration, _) = registration(storage().await);
    assert!(matches!(
        registration
            .begin("alice@example.com", None, None, true)
            .await,
        Err(RegistrationError::Restricted("instance_claim"))
    ));
    assert!(matches!(
        registration
            .begin("alice@example.com", Some("sidclaim_wrong"), None, true)
            .await,
        Err(RegistrationError::Restricted("instance_claim"))
    ));
}

/// The claim registration commits the first account with its sealed
/// password; afterwards the same identifier starts only a held decoy, which
/// the finish refuses as already registered, and with registration switched
/// off any start is refused alike.
#[tokio::test]
async fn claim_registration_commits_then_identifier_is_held() {
    let storage = storage().await;
    let (registration, keys) = registration(storage.clone());
    let token = sid_authn::admin_claim::open_claim(storage.as_ref(), keys.as_ref())
        .await
        .unwrap()
        .expect("an open claim");
    let pending = registration
        .begin(
            "Alice@Example.com",
            Some(secrecy::ExposeSecret::expose_secret(&token)),
            None,
            false,
        )
        .await
        .unwrap();
    let PendingRegistration::NewAccount {
        profile_id,
        ref instance_claim,
        ..
    } = pending
    else {
        panic!("a new account");
    };
    assert!(instance_claim.is_some());
    let (committed, credential_id) = registration
        .commit(pending.clone(), password(profile_id), None, None, false)
        .await
        .unwrap();
    assert_eq!(committed, profile_id);
    let stored = storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, credential_id);
    assert_ne!(stored[0].data.expose(), b"password file");

    assert!(matches!(
        registration
            .begin("alice@example.com", None, None, false)
            .await,
        Err(RegistrationError::NotEnabled)
    ));
    let held = registration
        .begin("alice@example.com", None, None, true)
        .await
        .unwrap();
    assert!(matches!(
        held,
        PendingRegistration::ExistingAccount {
            principal_type: PrincipalType::Email,
            by_claim: false,
            ..
        }
    ));
    assert!(matches!(
        registration
            .commit(held, password(ProfileId::generate()), None, None, true)
            .await,
        Err(RegistrationError::AlreadyRegistered(PrincipalType::Email))
    ));
}

/// A held identifier's finish under a policy now closed is refused as the
/// policy refuses a free one, telling no more than the start did; one
/// started by the claim is answered as already registered.
#[tokio::test]
async fn held_finish_follows_policy_in_force() {
    let (registration, _) = registration(storage().await);
    let held = |by_claim| PendingRegistration::ExistingAccount {
        principal_type: PrincipalType::Username,
        value: "alice".to_string(),
        invite_code: None,
        by_claim,
    };
    assert!(matches!(
        registration.refuse_held(&held(false), false).await,
        RegistrationError::NotEnabled
    ));
    assert!(matches!(
        registration.refuse_held(&held(true), false).await,
        RegistrationError::AlreadyRegistered(PrincipalType::Username)
    ));
}

/// An identifier that is no principal is refused as invalid.
#[tokio::test]
async fn invalid_identifier_is_refused() {
    let (registration, _) = registration(storage().await);
    assert!(matches!(
        registration.begin("", None, None, true).await,
        Err(RegistrationError::InvalidIdentifier(_))
    ));
}

/// Each enrollment denial names the requirement the client must meet; an
/// invalid invite asks for a valid one, as a missing invite does.
#[test]
fn denial_names_requirement() {
    assert_eq!(
        requirement(&EnrollmentDenialReason::AdminOnly),
        "admin_only"
    );
    assert_eq!(
        requirement(&EnrollmentDenialReason::InviteRequired),
        "invite"
    );
    assert_eq!(
        requirement(&EnrollmentDenialReason::InviteInvalid),
        "invite"
    );
    assert_eq!(requirement(&EnrollmentDenialReason::EmailRequired), "email");
}
