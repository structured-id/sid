// SPDX-License-Identifier: AGPL-3.0-only
//! Service bindings: one stable pairwise identity per (profile, scope).

use sid_core::models::{BindingScope, Profile};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

fn scope() -> BindingScope {
    BindingScope::try_from(format!("org-{}", Uuid::now_v7().simple())).unwrap()
}

async fn profile(backend: &dyn StorageBackend) -> Profile {
    let profile = create_test_profile("binding");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile
}

/// The first use allocates a binding; later uses get the same one.
pub async fn test_binding_is_stable(backend: &dyn StorageBackend) {
    let holder = profile(backend).await;
    let scope = scope();
    assert!(
        backend
            .find_service_binding(holder.id, &scope)
            .await
            .unwrap()
            .is_none()
    );

    let first = backend
        .service_binding(holder.id, &scope, test_audit())
        .await
        .unwrap();
    let again = backend
        .service_binding(holder.id, &scope, test_audit())
        .await
        .unwrap();
    assert_eq!(first.binding_id, again.binding_id);
    assert_eq!(first.binding_index, again.binding_index);
    assert_eq!(first.profile_id, holder.id);
    assert_eq!(first.scope, scope);
    assert!(again.last_used_at >= first.last_used_at);

    let found = backend
        .find_service_binding(holder.id, &scope)
        .await
        .unwrap()
        .expect("allocated binding is found");
    assert_eq!(found.binding_id, first.binding_id);
}

/// Different scopes of one profile get different bindings with distinct
/// indexes; the same scope of different profiles gets different bindings.
pub async fn test_bindings_are_pairwise(backend: &dyn StorageBackend) {
    let alice = profile(backend).await;
    let bob = profile(backend).await;
    let (shop, bank) = (scope(), scope());

    let alice_shop = backend
        .service_binding(alice.id, &shop, test_audit())
        .await
        .unwrap();
    let alice_bank = backend
        .service_binding(alice.id, &bank, test_audit())
        .await
        .unwrap();
    let bob_shop = backend
        .service_binding(bob.id, &shop, test_audit())
        .await
        .unwrap();

    assert_ne!(alice_shop.binding_id, alice_bank.binding_id);
    assert_ne!(alice_shop.binding_id, bob_shop.binding_id);
    assert_ne!(alice_shop.binding_index, alice_bank.binding_index);
}

/// Concurrent first uses of one scope allocate once: every caller gets the
/// same binding.
pub async fn test_concurrent_first_use_allocates_once(backend: &dyn StorageBackend) {
    let holder = profile(backend).await;
    let scope = scope();
    let first_use = || backend.service_binding(holder.id, &scope, test_audit());
    let (a, b, c, d) = tokio::join!(first_use(), first_use(), first_use(), first_use());
    let ids: std::collections::HashSet<_> = [a, b, c, d]
        .into_iter()
        .map(|r| r.unwrap().binding_id)
        .collect();
    assert_eq!(ids.len(), 1, "one binding per profile and scope");
}

/// Concurrent first uses of different scopes of one profile get distinct
/// indexes: an index never belongs to two bindings of a profile.
pub async fn test_concurrent_scopes_get_distinct_indexes(backend: &dyn StorageBackend) {
    let holder = profile(backend).await;
    let (s1, s2, s3, s4) = (scope(), scope(), scope(), scope());
    let first_use = |s| backend.service_binding(holder.id, s, test_audit());
    let (a, b, c, d) = tokio::join!(
        first_use(&s1),
        first_use(&s2),
        first_use(&s3),
        first_use(&s4)
    );
    let indexes: std::collections::HashSet<_> = [a, b, c, d]
        .into_iter()
        .map(|r| r.unwrap().binding_index)
        .collect();
    assert_eq!(indexes.len(), 4);
}

/// Bindings exported from another instance keep their ids and indexes when
/// imported, so every client keeps its `sub`; importing again changes nothing,
/// the export lists them in index order and a new scope continues after them.
pub async fn test_binding_import_keeps_identity(backend: &dyn StorageBackend) {
    let holder = profile(backend).await;
    let now = chrono::Utc::now();
    let exported: Vec<_> = [3u32, 7]
        .into_iter()
        .map(|binding_index| sid_core::models::ServiceBinding {
            binding_id: sid_core::models::BindingId::generate(),
            profile_id: holder.id,
            scope: scope(),
            binding_index,
            created_at: now,
            last_used_at: now,
        })
        .collect();
    for binding in exported.iter().rev() {
        assert!(
            backend
                .import_service_binding(binding, test_audit())
                .await
                .unwrap()
        );
        assert!(
            !backend
                .import_service_binding(binding, test_audit())
                .await
                .unwrap(),
            "a repeated import is a no-op"
        );
    }

    let listed: Vec<_> = backend
        .list_service_bindings(holder.id)
        .await
        .unwrap()
        .into_iter()
        .map(|b| (b.binding_id, b.binding_index))
        .collect();
    let expected: Vec<_> = exported
        .iter()
        .map(|b| (b.binding_id, b.binding_index))
        .collect();
    assert_eq!(listed, expected);

    for binding in &exported {
        let moved = backend
            .service_binding(holder.id, &binding.scope, test_audit())
            .await
            .unwrap();
        assert_eq!(moved.binding_id, binding.binding_id);
        assert_eq!(moved.binding_index, binding.binding_index);
    }
    let next = backend
        .service_binding(holder.id, &scope(), test_audit())
        .await
        .unwrap();
    assert_eq!(next.binding_index, 8);
}

/// An imported binding that clashes with a stored one (same profile and scope
/// under another id) is refused and writes nothing.
pub async fn test_binding_import_conflict(backend: &dyn StorageBackend) {
    let holder = profile(backend).await;
    let scope = scope();
    let stored = backend
        .service_binding(holder.id, &scope, test_audit())
        .await
        .unwrap();
    let mut other = stored.clone();
    other.binding_id = sid_core::models::BindingId::generate();

    let err = backend
        .import_service_binding(&other, test_audit())
        .await
        .unwrap_err();
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert_eq!(
        backend.list_service_bindings(holder.id).await.unwrap(),
        vec![
            backend
                .find_service_binding(holder.id, &scope)
                .await
                .unwrap()
                .unwrap()
        ]
    );
}

/// A binding is allocated only for a profile that exists.
pub async fn test_binding_needs_profile(backend: &dyn StorageBackend) {
    let err = backend
        .service_binding(
            sid_core::models::ProfileId::generate(),
            &scope(),
            test_audit(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, sid_core::Error::NotFound(_)), "{err:?}");
}
