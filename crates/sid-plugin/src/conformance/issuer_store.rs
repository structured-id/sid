// SPDX-License-Identifier: AGPL-3.0-only
//! [`IssuerStore`] scenarios: one issuer per authority and recipient
//! organization, found by its handle, stored with its first signing key.

use async_trait::async_trait;
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    AuditEntry, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, MutationContext,
    OidcIssuer, OrgId,
};

use crate::IssuerStore;

/// What a backend's harness supplies to the scenarios.
#[async_trait]
pub trait IssuerHarness: Send + Sync {
    fn store(&self) -> &dyn IssuerStore;

    /// An organization the store accepts as a recipient, without an issuer
    /// yet. A store that keeps a single installation organization gives it,
    /// so its harness runs each scenario on a fresh store.
    async fn organization(&self) -> OrgId;
}

fn ctx() -> MutationContext {
    AuditEntry::system("conformance", "issuer_store").into()
}

/// A new local issuer of `org` with its generation-1 key, its times at the
/// millisecond precision every store keeps.
fn issuer(org: OrgId) -> (OidcIssuer, IssuerSigningKey) {
    let now = Utc::now().trunc_subsecs(3);
    let id = IssuerId::generate();
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id,
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org,
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: id,
        generation: 1,
        key_id: format!("kid-{id}"),
        public_key: [9; 32],
        sealed_private_key: vec![1, 2, 3, 4],
        created_at: now,
    };
    (issuer, key)
}

/// Provisioners racing for one context store exactly one issuer, found by its
/// authority and organization and by its handle, with its first key; the
/// loser's handle names nothing, and a later provisioning writes nothing.
pub async fn issuer_provisioned_once<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let org = h.organization().await;
    assert!(
        store
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
            .unwrap()
            .is_none()
    );

    let ((a, a_key), (b, b_key)) = (issuer(org), issuer(org));
    let (ra, rb) = tokio::join!(
        store.insert_oidc_issuer(&a, &a_key, ctx()),
        store.insert_oidc_issuer(&b, &b_key, ctx()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "inserts: {ra} {rb}");
    let (winner, winner_key, loser) = if ra {
        (&a, &a_key, &b)
    } else {
        (&b, &b_key, &a)
    };

    let stored = store
        .oidc_issuer_for(IssuerAuthority::Local, org)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&stored, winner);
    assert_eq!(
        store
            .oidc_issuer_by_handle(&winner.handle)
            .await
            .unwrap()
            .as_ref(),
        Some(winner)
    );
    assert!(
        store
            .oidc_issuer_by_handle(&loser.handle)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .oidc_issuer_signing_keys(loser.id)
            .await
            .unwrap()
            .is_empty()
    );

    let keys = store.oidc_issuer_signing_keys(winner.id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].generation, 1);
    assert_eq!(keys[0].key_id, winner_key.key_id);
    assert_eq!(keys[0].public_key, winner_key.public_key);
    assert_eq!(keys[0].sealed_private_key, winner_key.sealed_private_key);
    assert_eq!(keys[0].created_at, winner_key.created_at);

    let (again, again_key) = issuer(org);
    assert!(
        !store
            .insert_oidc_issuer(&again, &again_key, ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
            .unwrap()
            .unwrap()
            .id,
        winner.id
    );
}

/// A first key that belongs to another issuer, or is not generation 1, is
/// refused and nothing is stored.
pub async fn foreign_first_key_refused<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let org = h.organization().await;
    let (issuer_a, _) = issuer(org);
    let (_, foreign_key) = issuer(org);
    assert!(
        store
            .insert_oidc_issuer(&issuer_a, &foreign_key, ctx())
            .await
            .is_err()
    );
    let (issuer_b, mut second_generation) = issuer(org);
    second_generation.generation = 2;
    assert!(
        store
            .insert_oidc_issuer(&issuer_b, &second_generation, ctx())
            .await
            .is_err()
    );
    assert!(
        store
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
            .unwrap()
            .is_none()
    );
}

/// A handle no issuer holds names nothing, and an issuer without keys has
/// none: the store never falls back to another issuer or a default.
pub async fn unknown_handle_names_nothing<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let (stored, key) = issuer(h.organization().await);
    assert!(
        store
            .insert_oidc_issuer(&stored, &key, ctx())
            .await
            .unwrap()
    );
    assert!(
        store
            .oidc_issuer_by_handle(&IssuerHandle::generate())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .oidc_issuer_signing_keys(IssuerId::generate())
            .await
            .unwrap()
            .is_empty()
    );
}

/// A restored issuer keeps its identity and every key generation as sealed
/// at the source; restoring exactly the same again writes nothing, and the
/// store lists it.
pub async fn issuer_restored_as_stored<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let org = h.organization().await;
    let (restored, first) = issuer(org);
    let mut second = first.clone();
    second.generation = 2;
    second.key_id = format!("kid-2-{}", restored.id);
    second.sealed_private_key = vec![5, 6, 7];
    let keys = [first, second];

    assert!(
        store
            .import_oidc_issuer(&restored, &keys, ctx())
            .await
            .unwrap()
    );
    assert!(
        !store
            .import_oidc_issuer(&restored, &keys, ctx())
            .await
            .unwrap(),
        "an exact repeat writes nothing"
    );

    assert_eq!(
        store
            .oidc_issuer_by_handle(&restored.handle)
            .await
            .unwrap()
            .as_ref(),
        Some(&restored)
    );
    assert_eq!(
        store.oidc_issuer_signing_keys(restored.id).await.unwrap(),
        keys
    );
    assert!(store.list_oidc_issuers().await.unwrap().contains(&restored));
}

/// A restore never replaces what is stored: an issuer of the same id that
/// differs in a key, or in its URL, is a conflict and changes nothing; a key
/// history that skips a generation or names another issuer is refused.
pub async fn issuer_restore_never_replaces<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let org = h.organization().await;
    let (restored, key) = issuer(org);
    assert!(
        store
            .import_oidc_issuer(&restored, std::slice::from_ref(&key), ctx())
            .await
            .unwrap()
    );

    let mut other_key = key.clone();
    other_key.sealed_private_key = vec![9, 9];
    let changed_key = store
        .import_oidc_issuer(&restored, &[other_key], ctx())
        .await
        .expect_err("a different key under a stored issuer");
    assert!(
        matches!(changed_key, sid_core::Error::Conflict(_)),
        "{changed_key:?}"
    );
    let mut moved = restored.clone();
    moved.canonical_url = "https://other.example.com/i/x".into();
    let changed_url = store
        .import_oidc_issuer(&moved, std::slice::from_ref(&key), ctx())
        .await
        .expect_err("a different URL under a stored issuer");
    assert!(
        matches!(changed_url, sid_core::Error::Conflict(_)),
        "{changed_url:?}"
    );
    assert_eq!(
        store.oidc_issuer_signing_keys(restored.id).await.unwrap(),
        [key]
    );

    let (gap, gap_key) = issuer(h.organization().await);
    let mut third = gap_key.clone();
    third.generation = 3;
    assert!(
        store
            .import_oidc_issuer(&gap, &[gap_key, third], ctx())
            .await
            .is_err()
    );
    let (foreign, _) = issuer(h.organization().await);
    let (_, foreign_key) = issuer(org);
    assert!(
        store
            .import_oidc_issuer(&foreign, &[foreign_key], ctx())
            .await
            .is_err()
    );
    assert!(
        store
            .oidc_issuer_by_handle(&gap.handle)
            .await
            .unwrap()
            .is_none()
    );
}

/// An issuer serves an organization the store knows.
pub async fn unknown_organization_refused<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let (unknown, key) = issuer(OrgId::generate());
    assert!(
        store
            .insert_oidc_issuer(&unknown, &key, ctx())
            .await
            .is_err()
    );
    assert!(
        store
            .oidc_issuer_by_handle(&unknown.handle)
            .await
            .unwrap()
            .is_none()
    );
}
