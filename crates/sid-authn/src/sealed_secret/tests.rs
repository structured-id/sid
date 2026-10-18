// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use secrecy::SecretBox;
use sid_core::models::ProfileId;
use sid_keys::{KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
use std::sync::Arc;

fn manager(master: u8, versions: &[u32]) -> SoftwareKeyManager {
    let params = versions
        .iter()
        .map(|v| KeyVersionParams::new(*v, vec![*v as u8; 16], format!("key-v{v}")))
        .collect();
    SoftwareKeyManager::new(
        SecretBox::new(Box::new([master; 32])),
        params,
        Arc::new(RustCryptoPrimitives::new()),
    )
    .unwrap()
}

fn pid() -> ProfileId {
    ProfileId::parse("0192b1e0-7c3a-7f4e-8a5d-3c2b1a0f9e8d").unwrap()
}

/// Inspection is metadata-only: it exposes ciphertext and its key reference,
/// refuses another record and plaintext, and does not pretend to authenticate
/// corrupted ciphertext without the independent key manager.
#[tokio::test]
async fn inspection_preserves_the_sealed_context_boundary() {
    let context = totp_context(pid());
    let stored = seal(&manager(7, &[1]), &context, b"seed").await.unwrap();
    let field = inspect(&context, &stored).unwrap();
    assert_eq!(field.key_version, 1);
    assert_eq!(field.context, context);
    assert_eq!(field.ciphertext.len(), 4 + 16);
    assert!(matches!(
        inspect("another-record", &stored),
        Err(SealedSecretError::ContextMismatch)
    ));
    assert!(matches!(
        inspect(&context, b"plaintext"),
        Err(SealedSecretError::NotSealed)
    ));
}

/// A sealed secret reads back only for its own record.
#[tokio::test]
async fn sealed_secret_opens_for_its_own_context() {
    let km = manager(7, &[1]);
    let stored = seal(&km, &totp_context(pid()), b"seed-seed-seed-seed!")
        .await
        .unwrap();
    assert!(is_sealed(&stored));
    assert!(!stored.windows(20).any(|w| w == b"seed-seed-seed-seed!"));

    let opened = open(&km, &totp_context(pid()), &stored).await.unwrap();
    assert_eq!(opened.secret.as_slice(), b"seed-seed-seed-seed!");
    assert!(opened.resealed.is_none());
}

/// A sealed value copied onto another profile's row is refused, not decrypted
/// as that other profile's seed.
#[tokio::test]
async fn sealed_secret_moved_to_another_record_is_refused() {
    let km = manager(7, &[1]);
    let stored = seal(&km, &totp_context(pid()), b"victim-seed")
        .await
        .unwrap();
    let other = ProfileId::generate();
    let err = open(&km, &totp_context(other), &stored).await.unwrap_err();
    assert!(matches!(err, SealedSecretError::ContextMismatch), "{err:?}");
}

/// A value stored before sealing (the bare seed) is never used as a secret.
#[tokio::test]
async fn plaintext_value_is_not_opened() {
    let km = manager(7, &[1]);
    let err = open(&km, &totp_context(pid()), &[0x42; 20])
        .await
        .unwrap_err();
    assert!(matches!(err, SealedSecretError::NotSealed), "{err:?}");
}

/// Without the master secret the stored value cannot be read.
#[tokio::test]
async fn another_master_cannot_open() {
    let stored = seal(&manager(7, &[1]), &totp_context(pid()), b"seed")
        .await
        .unwrap();
    let err = open(&manager(8, &[1]), &totp_context(pid()), &stored)
        .await
        .unwrap_err();
    assert!(matches!(err, SealedSecretError::KeyManager(_)), "{err:?}");
}

/// The contexts bind a sealed value to its owner's stable UUID, whatever the
/// owner's type: a Profile's contexts are the ones stored values were sealed
/// under, and a value sealed for one owner does not open under another
/// owner's context. A presentation form could be shared by two owners or
/// change, so it never names the owner.
#[tokio::test]
async fn contexts_bind_the_owner_id() {
    let profile = pid();
    assert_eq!(opaque_context(profile), format!("opaque:{profile}"));
    assert_eq!(totp_context(profile), format!("totp:{profile}"));

    let (a, b) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    assert_eq!(opaque_context(a), format!("opaque:{}", a.hyphenated()));
    assert_eq!(totp_context(a), format!("totp:{}", a.hyphenated()));

    let km = manager(7, &[1]);
    let stored = seal(&km, &opaque_context(a), b"record").await.unwrap();
    assert!(open(&km, &opaque_context(b), &stored).await.is_err());
}

fn ctx() -> sid_core::models::MutationContext {
    AuditEntry::system("test", "sealed_secret").into()
}

/// A store holding one OPAQUE record of a new Profile, sealed by `km` under
/// that Profile's context, recorded with `curve`.
async fn stored_record(
    km: &SoftwareKeyManager,
    curve: Option<u8>,
) -> (sid_storage::sqlite::SqliteBackend, Credential) {
    use sid_plugin::{CredentialStore, StorageBackend};
    let store = sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .unwrap();
    let profile = sid_core::models::Profile::new(Some("alice"));
    store.create_profile(&profile, ctx()).await.unwrap();
    let sealed = seal(km, &opaque_context(profile.id), b"password file")
        .await
        .unwrap();
    let mut credential = Credential::new(profile.id, CredentialType::Opaque, sealed, None);
    credential.opaque_curve = curve;
    store.create_credential(&credential, ctx()).await.unwrap();
    (store, credential)
}

/// A record opens to its password file, with the curve it records.
#[tokio::test]
async fn password_record_opens_with_its_curve() {
    let km = manager(7, &[1]);
    let (store, credential) = stored_record(&km, Some(1)).await;
    let opened = stored_password(&km, &store, &credential).await.unwrap();
    assert_eq!(opened.curve, sid_plugin::crypto::CurveId::Ristretto255);
    assert_eq!(opened.data, b"password file");
}

/// A record without its curve, or with one this build does not know, is
/// refused: it never signs in under the deployment's current curve.
#[tokio::test]
async fn password_record_without_known_curve_is_refused() {
    let km = manager(7, &[1]);
    let (store, credential) = stored_record(&km, None).await;
    let err = stored_password(&km, &store, &credential).await.unwrap_err();
    assert!(
        matches!(err, StoredPasswordError::NoCurve(id) if id == credential.id.0),
        "{err:?}"
    );

    let (store, credential) = stored_record(&km, Some(200)).await;
    let err = stored_password(&km, &store, &credential).await.unwrap_err();
    assert!(
        matches!(err, StoredPasswordError::UnknownCurve { raw: 200, .. }),
        "{err:?}"
    );
}

/// An envelope copied onto another owner's record does not open.
#[tokio::test]
async fn password_record_of_another_owner_is_refused() {
    let km = manager(7, &[1]);
    let (store, mut credential) = stored_record(&km, Some(1)).await;
    credential.profile_id = ProfileId::generate();
    let err = stored_password(&km, &store, &credential).await.unwrap_err();
    assert!(
        matches!(
            err,
            StoredPasswordError::Sealed(SealedSecretError::ContextMismatch)
        ),
        "{err:?}"
    );
}

/// A record sealed under an older key version is written back under the
/// current one, and opens without another reseal afterwards.
#[tokio::test]
async fn password_record_under_old_version_is_resealed_in_store() {
    use sid_plugin::CredentialStore;
    let (store, credential) = stored_record(&manager(7, &[1]), Some(1)).await;
    let current = manager(7, &[1, 2]);
    let opened = stored_password(&current, &store, &credential)
        .await
        .unwrap();
    assert_eq!(opened.data, b"password file");

    let rewritten = store.get_credential(credential.id).await.unwrap().unwrap();
    let field = inspect(
        &opaque_context(credential.profile_id),
        rewritten.data.expose(),
    )
    .unwrap();
    assert_eq!(field.key_version, 2);
    let again = open(
        &current,
        &opaque_context(credential.profile_id),
        rewritten.data.expose(),
    )
    .await
    .unwrap();
    assert!(again.resealed.is_none());
}

/// A value under an older key version is returned re-sealed under the current one.
#[tokio::test]
async fn old_version_is_resealed_on_open() {
    let old = manager(7, &[1]);
    let stored = seal(&old, &totp_context(pid()), b"seed").await.unwrap();
    let current = manager(7, &[1, 2]);
    let opened = open(&current, &totp_context(pid()), &stored).await.unwrap();
    assert_eq!(opened.secret.as_slice(), b"seed");
    let resealed = opened.resealed.expect("older version must be resealed");
    let field = EncryptedField::from_bytes(&resealed[SEALED_PREFIX.len()..]).unwrap();
    assert_eq!(field.key_version, 2);
    let again = open(&current, &totp_context(pid()), &resealed)
        .await
        .unwrap();
    assert!(again.resealed.is_none());
}
