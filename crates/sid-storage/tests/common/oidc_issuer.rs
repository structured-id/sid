// SPDX-License-Identifier: AGPL-3.0-only
//! The OIDC issuer registry: one issuer per authority and recipient
//! organization, found by its handle, stored with its first signing key.
//!
//! Needs a backend of its own (an isolated schema or a fresh database): the
//! installation organization has exactly one local issuer.

use super::{instance_org, test_audit};
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, OidcIssuer, OrgId,
};
use sid_plugin::storage::StorageBackend;

fn issuer(org: OrgId) -> (OidcIssuer, IssuerSigningKey) {
    // Millisecond precision: the coarsest any backend stores, so the values
    // read back equal these exactly.
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

pub async fn test_oidc_issuer_registry(backend: &dyn StorageBackend) {
    let org = instance_org(backend).await;
    assert!(
        backend
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
            .unwrap()
            .is_none()
    );

    // Provisioners racing for one context: exactly one issuer is stored.
    let ((a, a_key), (b, b_key)) = (issuer(org), issuer(org));
    let (ra, rb) = tokio::join!(
        backend.insert_oidc_issuer(&a, &a_key, test_audit()),
        backend.insert_oidc_issuer(&b, &b_key, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "inserts: {ra} {rb}");
    let (winner, winner_key, loser) = if ra {
        (&a, &a_key, &b)
    } else {
        (&b, &b_key, &a)
    };

    let stored = backend
        .oidc_issuer_for(IssuerAuthority::Local, org)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&stored, winner);
    assert_eq!(
        backend
            .oidc_issuer_by_handle(&winner.handle)
            .await
            .unwrap()
            .as_ref(),
        Some(winner)
    );
    // The losing provisioner's handle names nothing.
    assert!(
        backend
            .oidc_issuer_by_handle(&loser.handle)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .oidc_issuer_signing_keys(loser.id)
            .await
            .unwrap()
            .is_empty()
    );

    let keys = backend.oidc_issuer_signing_keys(winner.id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].generation, 1);
    assert_eq!(keys[0].key_id, winner_key.key_id);
    assert_eq!(keys[0].public_key, winner_key.public_key);
    assert_eq!(keys[0].sealed_private_key, winner_key.sealed_private_key);
    assert_eq!(keys[0].created_at, winner_key.created_at);

    // A later provisioning of the same context writes nothing.
    let (again, again_key) = issuer(org);
    assert!(
        !backend
            .insert_oidc_issuer(&again, &again_key, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend
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
pub async fn test_oidc_issuer_refuses_a_foreign_first_key(backend: &dyn StorageBackend) {
    let org = instance_org(backend).await;
    let (issuer_a, _) = issuer(org);
    let (_, foreign_key) = issuer(org);
    assert!(
        backend
            .insert_oidc_issuer(&issuer_a, &foreign_key, test_audit())
            .await
            .is_err()
    );
    let (issuer_b, mut second_generation) = issuer(org);
    second_generation.generation = 2;
    assert!(
        backend
            .insert_oidc_issuer(&issuer_b, &second_generation, test_audit())
            .await
            .is_err()
    );
    assert!(
        backend
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
            .unwrap()
            .is_none()
    );
}

/// An issuer serves an organization that exists.
pub async fn test_oidc_issuer_requires_its_organization(backend: &dyn StorageBackend) {
    let (unknown, key) = issuer(OrgId::generate());
    assert!(
        backend
            .insert_oidc_issuer(&unknown, &key, test_audit())
            .await
            .is_err()
    );
    assert!(
        backend
            .oidc_issuer_by_handle(&unknown.handle)
            .await
            .unwrap()
            .is_none()
    );
}
