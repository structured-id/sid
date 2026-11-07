use std::sync::Arc;

use sid_core::models::{AuditEntry, CredentialData, Profile};
use sid_plugin::storage::StorageBackend;

use super::*;
use crate::sign_in::SignInParts;

async fn storage() -> Arc<sid_storage::sqlite::SqliteBackend> {
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

fn sign_in(storage: Arc<dyn StorageBackend>) -> SignIn {
    use sid_plugin::crypto::OpaqueOperations;
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
    let jwt = sid_authn::jwt::JwtService::new(
        include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
        include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".to_string(),
    )
    .unwrap();
    let primary = Box::new(sid_authn::opaque::PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: std::collections::HashMap<
        sid_plugin::crypto::CurveId,
        Box<dyn OpaqueOperations>,
    > = std::collections::HashMap::new();
    verifiers.insert(
        sid_plugin::crypto::CurveId::Pallas,
        Box::new(sid_authn::opaque::PallasOpaque::new()),
    );
    SignIn::new(SignInParts {
        storage,
        jwt: Arc::new(jwt),
        revocation: Arc::new(sid_authn::revocation_cache::RevocationCache::new(
            std::time::Duration::from_secs(900),
            cache.clone(),
        )),
        issuer: "https://sid.example.com".to_string(),
        anomaly: Arc::new(sid_authn::anomaly::AnomalyDetector::ce_default(
            ceremonies.clone(),
        )),
        ip_intelligence: Arc::new(sid_authn::ip_intelligence::IpIntelligenceAggregator::new(
            vec![],
            cache.clone(),
            std::time::Duration::from_secs(60),
        )),
        geoip: Arc::new(sid_authn::geoip::GeoIpChain::empty(cache)),
        captcha_gate: sid_authn::captcha::CaptchaGate::new(ceremonies, keys()),
        captcha_provider: Arc::new(sid_authn::captcha::SidPowProvider::new([0u8; 32], 4, 300)),
        opaque: Arc::new(sid_authn::opaque::OpaqueRouter::new(
            primary, verifiers, setup,
        )),
        keys: keys(),
    })
}

fn operations(backend: &Arc<sid_storage::sqlite::SqliteBackend>) -> PasswordOperations {
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = backend.clone();
    PasswordOperations::with_authority(
        storage,
        ceremonies,
        keys(),
        sid_core::models::OrgId::generate(),
        sid_authn::password_operation::PasswordHistoryAuthority::InProcess {
            store: Arc::new(backend.history_keys()),
            history_keys: keys(),
        },
    )
    .0
}

async fn stored_profile(storage: &dyn StorageBackend, username: &str) -> ProfileId {
    let profile = Profile::new(Some(username));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile.id
}

async fn stored_credential(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
    credential_type: CredentialType,
) -> Credential {
    let credential = Credential::new(
        profile_id,
        credential_type,
        CredentialData::new(b"password file".to_vec()),
        None,
    );
    storage
        .create_credential(&credential, AuditEntry::system("test", "credential").into())
        .await
        .unwrap();
    credential
}

fn wire(id: CredentialId) -> sid_ids_proto::CredentialId {
    sid_ids::CredentialId::try_from(id.0).unwrap().into()
}

/// A change reaches only the caller's own active password: a credential that
/// is absent, another profile's, not a password or revoked answers alike as
/// not found, so a foreign id tells nothing; an id that is no identifier is
/// refused before any lookup.
#[tokio::test]
async fn change_reaches_only_own_active_password() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let sign_in = sign_in(storage.clone());
    let operations = operations(&backend);
    let passwords = Passwords::new(&sign_in, &operations);
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let bob = stored_profile(storage.as_ref(), "bob").await;

    let own = stored_credential(storage.as_ref(), alice, CredentialType::Opaque).await;
    let found = passwords
        .own_password(Some(&wire(own.id)), alice)
        .await
        .unwrap();
    assert_eq!(found.id, own.id);

    assert!(matches!(
        passwords.own_password(Some(&wire(own.id)), bob).await,
        Err(PasswordError::CredentialNotFound(id)) if id == own.id
    ));
    let absent = CredentialId(uuid::Uuid::now_v7());
    assert!(matches!(
        passwords.own_password(Some(&wire(absent)), alice).await,
        Err(PasswordError::CredentialNotFound(id)) if id == absent
    ));
    let passkey = stored_credential(storage.as_ref(), alice, CredentialType::WebAuthn).await;
    assert!(matches!(
        passwords.own_password(Some(&wire(passkey.id)), alice).await,
        Err(PasswordError::CredentialNotFound(id)) if id == passkey.id
    ));
    // A profile keeps one password; its passkey lets the password be revoked.
    let carol = stored_profile(storage.as_ref(), "carol").await;
    stored_credential(storage.as_ref(), carol, CredentialType::WebAuthn).await;
    let revoked = stored_credential(storage.as_ref(), carol, CredentialType::Opaque).await;
    storage
        .revoke_credential(revoked.id, AuditEntry::system("test", "revoke").into())
        .await
        .unwrap();
    assert!(matches!(
        passwords.own_password(Some(&wire(revoked.id)), carol).await,
        Err(PasswordError::CredentialNotFound(id)) if id == revoked.id
    ));
    assert!(matches!(
        passwords.own_password(None, alice).await,
        Err(PasswordError::InvalidField {
            field: "credential_id",
            ..
        })
    ));
}

fn fixed_policy() -> sid_authn::login_policy::FixedLoginPolicy {
    sid_authn::login_policy::FixedLoginPolicy::of(
        &sid_core::models::security_policy::SecurityPolicy::ce_default(),
    )
}

/// Without the page a reset link opens, or without a mail provider, every
/// reset request is refused alike, before any address is looked up.
#[tokio::test]
async fn reset_needs_its_page_and_mail() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let sign_in = sign_in(storage.clone());
    let operations = operations(&backend);
    let policy = fixed_policy();
    let none = PasswordResets::new(&sign_in, &operations, &policy, None);
    assert!(matches!(
        none.request("alice@example.com").await,
        Err(PasswordError::NotConfigured("password_reset"))
    ));
    let service = PasswordResetService::new(storage.clone(), keys());
    let resets = PasswordResets::new(&sign_in, &operations, &policy, Some(&service));
    assert!(matches!(
        resets.request("not-an-account@example.com").await,
        Err(PasswordError::NotConfigured("email_provider"))
    ));
}

/// A reset goes on only while its session is verified and unexpired: an
/// unknown one answers as expired (the reset starts again from the email),
/// one whose link is not verified yet is refused as unverified.
#[tokio::test]
async fn reset_steps_need_a_verified_session() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let sign_in = sign_in(storage.clone());
    let operations = operations(&backend);
    let policy = fixed_policy();
    let service = PasswordResetService::new(storage.clone(), keys());
    let resets = PasswordResets::new(&sign_in, &operations, &policy, Some(&service));
    assert!(matches!(
        resets
            .verified_session(ResetSessionId(uuid::Uuid::now_v7()))
            .await,
        Err(PasswordError::ResetExpired)
    ));
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let pending = service
        .request(alice, "alice@example.com", "alice@example.com")
        .await
        .unwrap();
    assert!(matches!(
        resets.verified_session(pending).await,
        Err(PasswordError::ResetUnverified(subject)) if subject == pending.0.to_string()
    ));
}

/// A reset's sign-in passes the organization's login requirements: under
/// the baseline a password sign-in is admitted, with the policy's fence.
#[tokio::test]
async fn reset_sign_in_follows_login_requirements() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let sign_in = sign_in(storage);
    let operations = operations(&backend);
    let policy = fixed_policy();
    let resets = PasswordResets::new(&sign_in, &operations, &policy, None);
    let method = LoginMethod::Password;
    assert!(
        resets
            .admitted(
                ProfileId::generate(),
                method.auth_level(false),
                &method.amr()
            )
            .await
            .is_some()
    );
}

/// The current password's guesses during changes are counted apart from the
/// account's sign-in budget: a change cannot lock the owner's sign-in, and a
/// sign-in lockout does not reuse the change's count.
#[test]
fn change_guesses_have_their_own_counter() {
    let profile = ProfileId::generate();
    assert_ne!(current_password_guesses(profile), profile.to_string());
    assert!(current_password_guesses(profile).ends_with(&profile.to_string()));
}
