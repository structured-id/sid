// SPDX-License-Identifier: AGPL-3.0-only
//! The installation organization and the clients that belong to it.
//!
//! Needs a backend of its own (an isolated schema or a fresh database): it
//! is about the installation's single organization and assigns every
//! client without one.

use super::application::store_client;
use super::{create_test_oauth2_client, test_audit};
use sid_core::models::{OrgStatus, OrgType, Organization};
use sid_plugin::storage::StorageBackend;

pub async fn test_instance_organization_and_clients(backend: &dyn StorageBackend) {
    assert!(backend.instance_organization().await.unwrap().is_none());

    // Starters racing: exactly one organization is stored and read back.
    let (a, b) = (
        Organization::implicit_community("id.sid.example.com"),
        Organization::implicit_community("id.sid.example.com"),
    );
    let (ra, rb) = tokio::join!(
        backend.insert_instance_organization(&a, test_audit()),
        backend.insert_instance_organization(&b, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "inserts: {ra} {rb}");
    let stored = backend.instance_organization().await.unwrap().unwrap();
    let winner = if ra { &a } else { &b };
    assert_eq!(stored.id, winner.id);
    assert_eq!(stored.canonical_domain, winner.canonical_domain);
    assert_eq!(stored.org_type, OrgType::Community);
    assert_eq!(stored.status, OrgStatus::Active);
    assert!(
        !backend
            .insert_instance_organization(
                &Organization::implicit_community("x.sid.example.com"),
                test_audit()
            )
            .await
            .unwrap()
    );

    // Clients without an organization join it; a client in one keeps it.
    backend.ensure_system_project(test_audit()).await.unwrap();
    let mut unowned = create_test_oauth2_client(&format!("unowned-{}", uuid::Uuid::now_v7()));
    unowned.org_id = None;
    store_client(backend, &unowned, test_audit()).await.unwrap();
    let mut owned = create_test_oauth2_client(&format!("owned-{}", uuid::Uuid::now_v7()));
    owned.org_id = Some(stored.id);
    store_client(backend, &owned, test_audit()).await.unwrap();

    assert_eq!(
        backend
            .assign_unowned_clients(stored.id, test_audit())
            .await
            .unwrap(),
        1
    );
    let unowned_now = backend
        .get_oauth2_client(&unowned.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unowned_now.org_id, Some(stored.id));
    assert_eq!(
        unowned_now.revision,
        unowned.revision + 1,
        "the assignment is a write"
    );
    let owned_now = backend
        .get_oauth2_client(&owned.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owned_now.revision, owned.revision);

    // Idempotent: nothing is left to assign.
    assert_eq!(
        backend
            .assign_unowned_clients(stored.id, test_audit())
            .await
            .unwrap(),
        0
    );
}
