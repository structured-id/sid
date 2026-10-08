// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support::key_manager;
use sid_core::models::Profile;
use sid_storage::sqlite::SqliteBackend;

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

async fn profile(storage: &SqliteBackend, username: &str, roles: &[&str]) -> ProfileId {
    let mut profile = Profile::new(Some(username));
    profile.roles = roles.iter().map(|r| r.to_string()).collect();
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile.id
}

async fn is_admin(storage: &SqliteBackend, id: ProfileId) -> bool {
    storage.get_profile(id).await.unwrap().unwrap().is_admin()
}

/// A fresh instance opens one claim; every start sees the same token until
/// it is claimed.
#[tokio::test]
async fn fresh_instance_keeps_one_claim_across_starts() {
    let (storage, keys) = (storage().await, key_manager());
    let first = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    let again = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    assert!(first.expose_secret().starts_with(TOKEN_PREFIX));
    assert_eq!(first.expose_secret(), again.expose_secret());
}

/// Presenting the token makes the caller administrator and closes the claim:
/// the token grants nothing a second time and no new one is opened.
#[tokio::test]
async fn claiming_makes_the_first_admin_once() {
    let (storage, keys) = (storage().await, key_manager());
    let token = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    let alice = profile(&storage, "alice", &[]).await;
    let bob = profile(&storage, "bob", &[]).await;

    claim(&storage, keys.as_ref(), alice, &token).await.unwrap();
    assert!(is_admin(&storage, alice).await);

    let err = claim(&storage, keys.as_ref(), bob, &token)
        .await
        .unwrap_err();
    assert!(matches!(err, ClaimError::NotOpen));
    assert!(!is_admin(&storage, bob).await);
    assert!(open_claim(&storage, keys.as_ref()).await.unwrap().is_none());
}

/// A wrong token is refused and leaves the claim open.
#[tokio::test]
async fn wrong_token_is_refused() {
    let (storage, keys) = (storage().await, key_manager());
    let token = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    let mallory = profile(&storage, "mallory", &[]).await;

    let guess = SecretString::from(format!("{TOKEN_PREFIX}guess"));
    let err = claim(&storage, keys.as_ref(), mallory, &guess)
        .await
        .unwrap_err();
    assert!(matches!(err, ClaimError::Mismatch));
    assert!(!is_admin(&storage, mallory).await);
    claim(&storage, keys.as_ref(), mallory, &token)
        .await
        .unwrap();
}

/// An instance that already has an administrator opens no claim.
#[tokio::test]
async fn instance_with_admin_opens_no_claim() {
    let (storage, keys) = (storage().await, key_manager());
    profile(&storage, "root", &["admin"]).await;
    assert!(open_claim(&storage, keys.as_ref()).await.unwrap().is_none());
    assert!(
        storage
            .get_instance_secret(InstanceSecret::AdminClaim)
            .await
            .unwrap()
            .is_none()
    );
}

/// A claim left beside an administrator (opened by a replica that started
/// just before the claim was taken) grants nothing and is removed.
#[tokio::test]
async fn claim_left_beside_an_admin_grants_nothing() {
    let (storage, keys) = (storage().await, key_manager());
    let token = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    profile(&storage, "root", &["admin"]).await;
    let eve = profile(&storage, "eve", &[]).await;

    let err = claim(&storage, keys.as_ref(), eve, &token)
        .await
        .unwrap_err();
    assert!(matches!(err, ClaimError::NotOpen));
    assert!(!is_admin(&storage, eve).await);
    assert!(
        storage
            .get_instance_secret(InstanceSecret::AdminClaim)
            .await
            .unwrap()
            .is_none()
    );
}

/// Two holders racing with the token: exactly one becomes administrator.
#[tokio::test]
async fn concurrent_claims_make_one_admin() {
    let (storage, keys) = (storage().await, key_manager());
    let token = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    let a = profile(&storage, "a", &[]).await;
    let b = profile(&storage, "b", &[]).await;

    let (ra, rb) = tokio::join!(
        claim(&storage, keys.as_ref(), a, &token),
        claim(&storage, keys.as_ref(), b, &token),
    );
    assert_eq!(usize::from(ra.is_ok()) + usize::from(rb.is_ok()), 1);
    assert_ne!(is_admin(&storage, a).await, is_admin(&storage, b).await);
}

/// A registrant proving the token gets the stored sealed claim to consume with
/// the registration; a wrong token or a claimed instance gets nothing.
#[tokio::test]
async fn verify_returns_the_stored_claim_only_for_the_token() {
    let (storage, keys) = (storage().await, key_manager());
    assert!(matches!(
        verify(
            &storage,
            keys.as_ref(),
            &SecretString::from("sidclaim_x".to_string())
        )
        .await,
        Ok(None)
    ));
    let token = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    let stored = storage
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await
        .unwrap()
        .unwrap();

    let proved = verify(&storage, keys.as_ref(), &token).await.unwrap();
    assert_eq!(proved, Some(stored));

    let guess = SecretString::from(format!("{TOKEN_PREFIX}guess"));
    let err = verify(&storage, keys.as_ref(), &guess).await.unwrap_err();
    assert!(matches!(err, ClaimError::Mismatch));

    profile(&storage, "root", &["admin"]).await;
    assert!(matches!(
        verify(&storage, keys.as_ref(), &token).await,
        Ok(None)
    ));
}

/// The token is stored only sealed.
#[tokio::test]
async fn token_is_stored_sealed() {
    let (storage, keys) = (storage().await, key_manager());
    let token = open_claim(&storage, keys.as_ref()).await.unwrap().unwrap();
    let stored = storage
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await
        .unwrap()
        .unwrap();
    assert!(sealed_secret::is_sealed(&stored));
    let plain = token.expose_secret().as_bytes();
    assert!(!stored.windows(plain.len()).any(|w| w == plain));
}
