// SPDX-License-Identifier: AGPL-3.0-only
//! [`IssuerStore`] scenarios: one issuer per authority and recipient, found
//! by its handle, stored with its first signing key. They hold for any
//! recipient type; what a recipient must be (an organization the store
//! knows, or the host's own recipient) is the adapter's own test.

use async_trait::async_trait;
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    AuditEntry, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, MutationContext,
    OidcIssuer,
};

use crate::IssuerStore;

/// What a backend's harness supplies to the scenarios.
#[async_trait]
pub trait IssuerHarness: Send + Sync {
    /// The store's recipient type.
    type Recipient: Clone + PartialEq + std::fmt::Debug + Send + Sync + 'static;

    fn store(&self) -> &dyn IssuerStore<Self::Recipient>;

    /// A recipient the store accepts, without an issuer yet. A store that
    /// keeps a single installation recipient gives it, so its harness runs
    /// each scenario on a fresh store.
    async fn recipient(&self) -> Self::Recipient;
}

fn ctx() -> MutationContext {
    AuditEntry::system("conformance", "issuer_store").into()
}

/// A new local issuer of `recipient` with its generation-1 key, its times at
/// the millisecond precision every store keeps.
fn issuer<R>(recipient: R) -> (OidcIssuer<R>, IssuerSigningKey) {
    let now = Utc::now().trunc_subsecs(3);
    let id = IssuerId::generate();
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id,
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient,
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
/// authority and recipient and by its handle, with its first key; the loser's
/// handle names nothing, and a later provisioning writes nothing.
pub async fn issuer_provisioned_once<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let recipient = h.recipient().await;
    assert!(
        store
            .oidc_issuer_for(IssuerAuthority::Local, &recipient)
            .await
            .unwrap()
            .is_none()
    );

    let ((a, a_key), (b, b_key)) = (issuer(recipient.clone()), issuer(recipient.clone()));
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
        .oidc_issuer_for(IssuerAuthority::Local, &recipient)
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

    let (again, again_key) = issuer(recipient.clone());
    assert!(
        !store
            .insert_oidc_issuer(&again, &again_key, ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .oidc_issuer_for(IssuerAuthority::Local, &recipient)
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
    let recipient = h.recipient().await;
    let (issuer_a, _) = issuer(recipient.clone());
    let (_, foreign_key) = issuer(recipient.clone());
    assert!(
        store
            .insert_oidc_issuer(&issuer_a, &foreign_key, ctx())
            .await
            .is_err()
    );
    let (issuer_b, mut second_generation) = issuer(recipient.clone());
    second_generation.generation = 2;
    assert!(
        store
            .insert_oidc_issuer(&issuer_b, &second_generation, ctx())
            .await
            .is_err()
    );
    assert!(
        store
            .oidc_issuer_for(IssuerAuthority::Local, &recipient)
            .await
            .unwrap()
            .is_none()
    );
}

/// A handle no issuer holds names nothing, and an issuer without keys has
/// none: the store never falls back to another issuer or a default.
pub async fn unknown_handle_names_nothing<H: IssuerHarness>(h: &H) {
    let store = h.store();
    let recipient = h.recipient().await;
    let (stored, key) = issuer(recipient);
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
