use std::sync::Arc;

use sid_plugin::storage::StorageBackend;

use super::*;
use crate::test_support::{
    fixed_policy, keys, sign_in, storage, stored_credential, stored_profile,
};

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

/// An imported-password upgrade for a principal nobody holds answers as a
/// wrong password and is counted like any failed guess, so the answer tells
/// nothing about the account.
#[tokio::test]
async fn upgrade_of_unknown_principal_fails_like_a_wrong_password() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let sign_in = sign_in(storage.clone());
    let upgrades = ImportedPasswordUpgrades::new(storage, keys());
    for _ in 0..5 {
        assert!(matches!(
            upgrades
                .start(
                    &sign_in,
                    None,
                    LegacyMigrateStartRequest {
                        principal: "nobody@example.com".to_string(),
                        password: "guess".to_string(),
                        ..Default::default()
                    },
                )
                .await,
            Err(PasswordError::AuthenticationFailed)
        ));
    }
    assert!(matches!(
        sign_in.refuse_if_locked("nobody@example.com").await,
        Err(SignInError::Rules(SignInRefusal::TooManyAttempts(_)))
    ));
}

/// A finish of an upgrade that was never started, or names none, completes
/// nothing: an unknown one answers as expired, a missing id as invalid.
#[tokio::test]
async fn upgrade_finish_needs_a_started_upgrade() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend.clone();
    let sign_in = sign_in(storage.clone());
    let upgrades = ImportedPasswordUpgrades::new(storage, keys());
    let policy = fixed_policy();
    let finish = |upgrade_id| {
        upgrades.finish(
            &sign_in,
            &policy,
            CeremonyClient::Native,
            None,
            AttemptContext::default(),
            LegacyMigrateFinishRequest {
                upgrade_id,
                opaque_registration_record: vec![1, 2, 3],
            },
        )
    };
    assert!(matches!(
        finish(Some(sid_ids::ImportedPasswordUpgradeId::generate().into())).await,
        Err(PasswordError::UpgradeExpired)
    ));
    assert!(matches!(
        finish(None).await,
        Err(PasswordError::InvalidField {
            field: "upgrade_id",
            ..
        })
    ));
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
