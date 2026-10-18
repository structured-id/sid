// SPDX-License-Identifier: AGPL-3.0-only
//! [`CaRegistry`] scenarios: the lifecycle and the activation gate every
//! backend enforces, under concurrency. Each scenario uses an organization
//! scope of its own, so scenarios share a store without seeing each other.

use chrono::{Timelike, Utc};
use sid_core::Error;
use sid_core::models::{
    AuditEntry, CaGeneration, CaGenerationId, CaScope, CaState, KeyCustody, MutationContext,
    NewCaGeneration, OrgId, RecoveryConfirmation,
};

use crate::CaRegistry;

fn ctx() -> MutationContext {
    AuditEntry::system("conformance", "ca_registry").into()
}

fn scope() -> CaScope {
    CaScope::Organization(OrgId::generate())
}

/// Odd keys are sealed, even keys external: both custodies round-trip.
fn new_generation(scope: CaScope, key: u8) -> NewCaGeneration {
    NewCaGeneration {
        id: CaGenerationId::new(),
        scope,
        key: if key % 2 == 1 {
            KeyCustody::Sealed(vec![key; 8])
        } else {
            KeyCustody::External(format!("hsm:key-{key}"))
        },
    }
}

fn confirmation(reference: &str) -> RecoveryConfirmation {
    RecoveryConfirmation {
        reference: reference.into(),
        confirmed_by: "operator".into(),
        // Nanoseconds no engine keeps: a retry of this exact confirmation is
        // still the same confirmation.
        confirmed_at: Utc::now().with_nanosecond(123_456_789).unwrap(),
    }
}

/// A prepared generation carried to activatable: certificate, then both
/// confirmations, each naming the revision it found.
async fn activatable(store: &dyn CaRegistry, scope: CaScope, key: u8) -> CaGeneration {
    let g = store
        .prepare_generation(&new_generation(scope, key), ctx())
        .await
        .unwrap();
    let g = store
        .record_ca_certificate(g.id, g.revision, &[0x30, key], ctx())
        .await
        .unwrap();
    let g = store
        .confirm_database_recovery(g.id, g.revision, &confirmation("db-point"), ctx())
        .await
        .unwrap();
    store
        .confirm_key_recovery(g.id, g.revision, &confirmation("key-copy"), ctx())
        .await
        .unwrap()
}

/// Generations of a scope are numbered from 1, prepared and not issuing; an
/// exact retry returns the stored generation and the same id with other
/// content is a conflict.
pub async fn prepare_numbers_generations(store: &dyn CaRegistry) {
    let scope = scope();
    let first = new_generation(scope, 1);
    let g1 = store.prepare_generation(&first, ctx()).await.unwrap();
    assert_eq!(
        (g1.generation, g1.state, g1.last_serial),
        (1, CaState::Prepared, 0)
    );
    assert_eq!(g1.key, first.key);
    assert_eq!(store.prepare_generation(&first, ctx()).await.unwrap(), g1);
    let altered = NewCaGeneration {
        key: new_generation(scope, 9).key,
        ..first.clone()
    };
    assert!(matches!(
        store.prepare_generation(&altered, ctx()).await,
        Err(Error::Conflict(_))
    ));
    let g2 = store
        .prepare_generation(&new_generation(scope, 2), ctx())
        .await
        .unwrap();
    assert_eq!(g2.generation, 2);
    assert!(matches!(g2.key, KeyCustody::External(_)));
    assert_eq!(store.ca_generation(g1.id).await.unwrap(), Some(g1));
    assert_eq!(store.current_ca_generation(scope).await.unwrap(), None);
}

/// One id prepared concurrently in two scopes: one preparation is stored, the
/// other is a conflict, never a storage failure.
pub async fn concurrent_prepares_of_one_id_conflict(store: &dyn CaRegistry) {
    let first = new_generation(scope(), 1);
    let second = NewCaGeneration {
        scope: scope(),
        ..first.clone()
    };
    let (a, b) = tokio::join!(
        store.prepare_generation(&first, ctx()),
        store.prepare_generation(&second, ctx()),
    );
    let outcomes = [&a, &b];
    assert_eq!(
        outcomes.iter().filter(|r| r.is_ok()).count(),
        1,
        "{a:?} {b:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|r| matches!(r, Err(Error::Conflict(_)))),
        "{a:?} {b:?}"
    );
}

/// Activation needs the certificate and both recovery confirmations; each
/// missing piece is refused and nothing becomes current.
pub async fn activation_requires_certificate_and_both_confirmations(store: &dyn CaRegistry) {
    let scope = scope();
    let g = store
        .prepare_generation(&new_generation(scope, 1), ctx())
        .await
        .unwrap();
    assert!(matches!(
        store.activate_ca_generation(g.id, g.revision, ctx()).await,
        Err(Error::Conflict(_))
    ));
    // A confirmation before the certificate binds nothing: refused.
    assert!(matches!(
        store
            .confirm_database_recovery(g.id, g.revision, &confirmation("db"), ctx())
            .await,
        Err(Error::Conflict(_))
    ));
    let g = store
        .record_ca_certificate(g.id, g.revision, &[0x30, 1], ctx())
        .await
        .unwrap();
    assert!(matches!(
        store.activate_ca_generation(g.id, g.revision, ctx()).await,
        Err(Error::Conflict(_))
    ));
    let g = store
        .confirm_database_recovery(g.id, g.revision, &confirmation("db"), ctx())
        .await
        .unwrap();
    assert!(matches!(
        store.activate_ca_generation(g.id, g.revision, ctx()).await,
        Err(Error::Conflict(_))
    ));
    assert_eq!(store.current_ca_generation(scope).await.unwrap(), None);
    let g = store
        .confirm_key_recovery(g.id, g.revision, &confirmation("keys"), ctx())
        .await
        .unwrap();
    assert!(g.activatable());
    let current = store
        .activate_ca_generation(g.id, g.revision, ctx())
        .await
        .unwrap();
    assert_eq!(current.state, CaState::Current);
    assert_eq!(
        store.current_ca_generation(scope).await.unwrap(),
        Some(current.clone())
    );
    // Repeating the completed activation returns it.
    assert_eq!(
        store
            .activate_ca_generation(g.id, g.revision, ctx())
            .await
            .unwrap(),
        current
    );
}

/// The certificate is fixed once confirmations bind it, and every transition
/// names the revision it found: a stale revision is a conflict.
pub async fn certified_material_and_revisions_are_fixed(store: &dyn CaRegistry) {
    let scope = scope();
    let g = store
        .prepare_generation(&new_generation(scope, 1), ctx())
        .await
        .unwrap();
    let stale = g.revision;
    let g = store
        .record_ca_certificate(g.id, g.revision, &[0x30, 1], ctx())
        .await
        .unwrap();
    assert!(g.revision > stale);
    // The same certificate again is a retry; another one is a conflict.
    assert_eq!(
        store
            .record_ca_certificate(g.id, stale, &[0x30, 1], ctx())
            .await
            .unwrap(),
        g
    );
    assert!(matches!(
        store
            .record_ca_certificate(g.id, g.revision, &[0x30, 2], ctx())
            .await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        store
            .confirm_database_recovery(g.id, stale, &confirmation("db"), ctx())
            .await,
        Err(Error::Conflict(_))
    ));
    let db = confirmation("db");
    let g = store
        .confirm_database_recovery(g.id, g.revision, &db, ctx())
        .await
        .unwrap();
    assert!(matches!(
        store
            .record_ca_certificate(g.id, g.revision, &[0x30, 3], ctx())
            .await,
        Err(Error::Conflict(_))
    ));
    // The same confirmation again is a retry, even at the revision it moved
    // past; another one replaces nothing.
    assert_eq!(
        store
            .confirm_database_recovery(g.id, g.revision - 1, &db, ctx())
            .await
            .unwrap(),
        g
    );
    assert!(matches!(
        store
            .confirm_database_recovery(g.id, g.revision, &confirmation("other"), ctx())
            .await,
        Err(Error::Conflict(_))
    ));
    let keys = confirmation("keys");
    let g = store
        .confirm_key_recovery(g.id, g.revision, &keys, ctx())
        .await
        .unwrap();
    assert_eq!(
        store
            .confirm_key_recovery(g.id, g.revision - 1, &keys, ctx())
            .await
            .unwrap(),
        g
    );
}

/// A newly activated generation retires the scope's previous current one.
pub async fn activation_retires_the_previous_generation(store: &dyn CaRegistry) {
    let scope = scope();
    let first = activatable(store, scope, 1).await;
    let first = store
        .activate_ca_generation(first.id, first.revision, ctx())
        .await
        .unwrap();
    let second = activatable(store, scope, 2).await;
    let second = store
        .activate_ca_generation(second.id, second.revision, ctx())
        .await
        .unwrap();
    assert_eq!(
        store.ca_generation(first.id).await.unwrap().unwrap().state,
        CaState::Retired
    );
    assert_eq!(
        store.current_ca_generation(scope).await.unwrap(),
        Some(second)
    );
}

/// The generation an activation retires has its own audit record of it.
/// `audited(chain)` is the harness's count of audit records on a chain, named
/// `ca_generation:{id}`; the trait cannot express it.
pub async fn retirement_is_audited<F, Fut>(store: &dyn CaRegistry, audited: F)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = u64>,
{
    let scope = scope();
    let first = activatable(store, scope, 1).await;
    let first = store
        .activate_ca_generation(first.id, first.revision, ctx())
        .await
        .unwrap();
    let chain = format!("ca_generation:{}", first.id);
    let before = audited(chain.clone()).await;
    let second = activatable(store, scope, 2).await;
    store
        .activate_ca_generation(second.id, second.revision, ctx())
        .await
        .unwrap();
    assert_eq!(audited(chain).await, before + 1);
}

/// Two replicas activating two prepared generations of one scope together
/// leave exactly one current.
pub async fn concurrent_activations_leave_one_current(store: &dyn CaRegistry) {
    let scope = scope();
    let a = activatable(store, scope, 1).await;
    let b = activatable(store, scope, 2).await;
    let (ra, rb) = tokio::join!(
        store.activate_ca_generation(a.id, a.revision, ctx()),
        store.activate_ca_generation(b.id, b.revision, ctx()),
    );
    assert!(ra.is_ok() || rb.is_ok());
    let current = store.current_ca_generation(scope).await.unwrap().unwrap();
    let states = [
        store.ca_generation(a.id).await.unwrap().unwrap().state,
        store.ca_generation(b.id).await.unwrap().unwrap().state,
    ];
    assert_eq!(
        states.iter().filter(|s| **s == CaState::Current).count(),
        1,
        "{states:?}"
    );
    assert!(current.id == a.id || current.id == b.id);
}

/// Serials of the current generation are distinct and increasing under
/// concurrency; a generation not current allocates none.
pub async fn serials_are_unique_and_only_current_allocates(store: &dyn CaRegistry) {
    let scope = scope();
    let g = activatable(store, scope, 1).await;
    assert!(matches!(
        store.allocate_ca_serial(g.id, g.revision).await,
        Err(Error::Conflict(_))
    ));
    let prepared_revision = g.revision;
    let g = store
        .activate_ca_generation(g.id, g.revision, ctx())
        .await
        .unwrap();
    // The revision the caller decided on, not only the state, is checked.
    assert!(matches!(
        store.allocate_ca_serial(g.id, prepared_revision).await,
        Err(Error::Conflict(_))
    ));
    let allocations =
        futures::future::join_all((0..8).map(|_| store.allocate_ca_serial(g.id, g.revision))).await;
    let mut serials: Vec<u64> = allocations
        .into_iter()
        .map(|a| {
            let a = a.unwrap();
            assert_eq!((a.generation, a.revision), (g.id, g.revision));
            a.serial
        })
        .collect();
    serials.sort_unstable();
    assert_eq!(serials, (1..=8).collect::<Vec<u64>>());
    assert_eq!(
        store
            .ca_generation(g.id)
            .await
            .unwrap()
            .unwrap()
            .last_serial,
        8
    );
}

/// Revocation withdraws a generation at once from any state: it allocates no
/// serial and is not current; repeating it is harmless.
pub async fn revocation_stops_issuance(store: &dyn CaRegistry) {
    let scope = scope();
    let g = activatable(store, scope, 1).await;
    let g = store
        .activate_ca_generation(g.id, g.revision, ctx())
        .await
        .unwrap();
    let revoked = store.revoke_ca_generation(g.id, ctx()).await.unwrap();
    assert_eq!(revoked.state, CaState::Revoked);
    assert!(revoked.revision > g.revision);
    assert_eq!(store.current_ca_generation(scope).await.unwrap(), None);
    assert!(matches!(
        store.allocate_ca_serial(g.id, g.revision).await,
        Err(Error::Conflict(_))
    ));
    assert_eq!(
        store.revoke_ca_generation(g.id, ctx()).await.unwrap(),
        revoked
    );
    // A revoked generation is never activated again.
    assert!(matches!(
        store
            .activate_ca_generation(g.id, revoked.revision, ctx())
            .await,
        Err(Error::Conflict(_))
    ));
    // A prepared one can be revoked too.
    let p = store
        .prepare_generation(&new_generation(scope, 2), ctx())
        .await
        .unwrap();
    assert_eq!(
        store.revoke_ca_generation(p.id, ctx()).await.unwrap().state,
        CaState::Revoked
    );
}

/// Unknown generations are not found.
pub async fn unknown_generation_is_not_found(store: &dyn CaRegistry) {
    let id = CaGenerationId::new();
    assert_eq!(store.ca_generation(id).await.unwrap(), None);
    assert!(matches!(
        store.record_ca_certificate(id, 1, &[0x30], ctx()).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        store.allocate_ca_serial(id, 1).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        store.revoke_ca_generation(id, ctx()).await,
        Err(Error::NotFound(_))
    ));
}
