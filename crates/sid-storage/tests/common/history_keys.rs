// SPDX-License-Identifier: AGPL-3.0-only
//! The history evaluator's key store contract, run against every backend:
//! keys are durable before first use, one owner domain never sees or resets
//! another's keys, rotations and preparations agree under concurrency, and
//! the lifecycle the credential service reports retires a replaced key only
//! when no newer live set or pending operation still needs it. Retirement
//! keeps the sealed key.

use chrono::Utc;
use sid_core::models::{
    HistoryEpochId, HistoryEpochUse, HistoryKsf, HistoryLiveSet, HistoryPreparation, HistorySuite,
    KeyArchive, KeyEpoch, NewKeyEpoch, WrappedHistoryKey, history_key_context,
};
use sid_plugin::history_keys::HistoryKeyStore;
use uuid::Uuid;

use super::test_audit;

fn audit() -> sid_core::models::AuditEntry {
    test_audit().audit
}

/// A fresh owner domain.
fn owner() -> [u8; 32] {
    let mut domain = [0u8; 32];
    domain[..16].copy_from_slice(Uuid::now_v7().as_bytes());
    domain
}

/// A new active epoch of `owner_domain` with a key sealed for it.
fn new_epoch(owner_domain: [u8; 32], key: u8) -> NewKeyEpoch {
    let id = HistoryEpochId::generate();
    NewKeyEpoch {
        epoch: KeyEpoch {
            id,
            owner_domain,
            suite: HistorySuite::PallasPoseidonV1,
            public_key: [key; 32],
            ksf: HistoryKsf::DEFAULT,
            ksf_salt: [key.wrapping_add(1); 32],
            status: HistoryEpochUse::Active,
            // Stored at microsecond precision by every backend.
            created_at: chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
                .unwrap(),
        },
        key: WrappedHistoryKey(
            sid_keys::EncryptedField {
                key_version: 1,
                nonce: [0; 12],
                context: history_key_context(id, &owner_domain),
                ciphertext: vec![key; 48],
            }
            .to_bytes(),
        ),
    }
}

/// The live set at `revision` naming `live`.
fn live(revision: i64, live: &[HistoryEpochId], settled: &[Uuid]) -> HistoryLiveSet {
    let mut live = live.to_vec();
    live.sort_unstable();
    HistoryLiveSet {
        revision,
        live,
        settled: settled.to_vec(),
    }
}

async fn prepare(
    store: &dyn HistoryKeyStore,
    owner_domain: [u8; 32],
    live: HistoryLiveSet,
    operation: Uuid,
    expires_at: chrono::DateTime<Utc>,
) -> sid_core::Result<Vec<HistoryEpochId>> {
    store
        .prepare_epochs(
            &HistoryPreparation {
                owner_domain,
                live,
                operation,
                expires_at,
                now: Utc::now(),
            },
            audit(),
        )
        .await
        .map(|selected| selected.iter().map(|e| e.id).collect())
}

async fn epoch_ids(store: &dyn HistoryKeyStore, owner_domain: [u8; 32]) -> Vec<HistoryEpochId> {
    store
        .get_key_epochs(&owner_domain)
        .await
        .unwrap()
        .epochs
        .iter()
        .map(|e| e.id)
        .collect()
}

/// A new owner's first key is stored before any use and readable by epoch;
/// an exact retry returns it; any other first epoch for that owner is a
/// conflict, so a new-owner preparation never resets or forks a history.
pub async fn test_first_epoch_never_resets_a_history(store: &dyn HistoryKeyStore) {
    let domain = owner();
    let first = new_epoch(domain, 1);
    let operation = Uuid::now_v7();
    assert_eq!(
        store
            .create_first_epoch(&first, operation, audit())
            .await
            .unwrap(),
        first.epoch
    );
    assert_eq!(
        store.get_epoch_key(first.epoch.id).await.unwrap(),
        Some(first.key.clone())
    );
    assert_eq!(
        store
            .create_first_epoch(&first, operation, audit())
            .await
            .unwrap(),
        first.epoch,
        "an exact retry"
    );
    let err = store
        .create_first_epoch(&new_epoch(domain, 2), Uuid::now_v7(), audit())
        .await
        .expect_err("a second first epoch");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert_eq!(epoch_ids(store, domain).await, vec![first.epoch.id]);

    // Concurrent first epochs of one owner: exactly one is stored.
    let racing = owner();
    let (a, b) = (new_epoch(racing, 3), new_epoch(racing, 4));
    let (ra, rb) = tokio::join!(
        store.create_first_epoch(&a, Uuid::now_v7(), audit()),
        store.create_first_epoch(&b, Uuid::now_v7(), audit()),
    );
    assert!(ra.is_ok() ^ rb.is_ok(), "{ra:?} {rb:?}");
    assert_eq!(epoch_ids(store, racing).await.len(), 1);
    assert_eq!(
        store
            .get_epoch_key(HistoryEpochId::generate())
            .await
            .unwrap(),
        None
    );
}

/// Ensuring an epoch writes it once; a second or a concurrent one gets the
/// stored epoch back, so every operation of the owner uses one key.
pub async fn test_epoch_is_ensured_once(store: &dyn HistoryKeyStore) {
    let domain = owner();
    let (a, b) = (new_epoch(domain, 5), new_epoch(domain, 6));
    let (ra, rb) = tokio::join!(
        store.ensure_epoch(&a, audit()),
        store.ensure_epoch(&b, audit())
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.id, rb.id, "concurrent ensures agree on one epoch");
    let again = store
        .ensure_epoch(&new_epoch(domain, 7), audit())
        .await
        .unwrap();
    assert_eq!(again.id, ra.id, "a stored epoch is never replaced");
    assert_eq!(epoch_ids(store, domain).await, vec![ra.id]);
}

/// Owner domains are separate namespaces: one owner's keys are invisible to
/// another, and a live set naming another owner's epoch is refused.
pub async fn test_owner_domains_are_separate(store: &dyn HistoryKeyStore) {
    let (mine, theirs) = (owner(), owner());
    let my_epoch = store
        .ensure_epoch(&new_epoch(mine, 8), audit())
        .await
        .unwrap();
    let their_epoch = store
        .ensure_epoch(&new_epoch(theirs, 9), audit())
        .await
        .unwrap();
    assert_eq!(epoch_ids(store, mine).await, vec![my_epoch.id]);
    assert_eq!(epoch_ids(store, theirs).await, vec![their_epoch.id]);
    let err = prepare(
        store,
        mine,
        live(1, &[their_epoch.id], &[]),
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .expect_err("another owner's epoch");
    assert!(matches!(err, sid_core::Error::Validation(_)), "{err:?}");
    // A rotation of another owner's epoch from this owner's domain replaces
    // nothing of theirs.
    let rotated = store
        .rotate_epoch(&new_epoch(mine, 10), their_epoch.id, 1, audit())
        .await
        .unwrap();
    assert_eq!(rotated.id, my_epoch.id, "nothing of theirs was rotated");
    assert_eq!(epoch_ids(store, theirs).await, vec![their_epoch.id]);
}

/// Rotation replaces the active epoch: the replaced one becomes
/// compare-only; concurrent rotations from one epoch agree on one
/// replacement; a stale rotation writes nothing.
pub async fn test_epoch_rotation(store: &dyn HistoryKeyStore) {
    let domain = owner();
    let old = store
        .ensure_epoch(&new_epoch(domain, 11), audit())
        .await
        .unwrap();
    let (a, b) = (new_epoch(domain, 12), new_epoch(domain, 13));
    let (ra, rb) = tokio::join!(
        store.rotate_epoch(&a, old.id, 3, audit()),
        store.rotate_epoch(&b, old.id, 3, audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.id, rb.id, "concurrent rotations agree on one epoch");
    let epochs = store.get_key_epochs(&domain).await.unwrap();
    assert_eq!(epochs.active_epoch().map(|e| e.id), Some(ra.id));
    assert_eq!(
        epochs
            .epochs
            .iter()
            .find(|e| e.id == old.id)
            .map(|e| e.status),
        Some(HistoryEpochUse::CompareOnly)
    );
    let late = store
        .rotate_epoch(&new_epoch(domain, 14), old.id, 3, audit())
        .await
        .unwrap();
    assert_eq!(
        late.id, ra.id,
        "a rotation naming a replaced epoch changes nothing"
    );
    assert_eq!(store.get_key_epochs(&domain).await.unwrap().epochs.len(), 2);
}

/// The lifecycle the credential service's live sets drive:
/// - one revision has one live set: another set for it is a conflict;
/// - an older live set changes nothing and retires nothing;
/// - an epoch a prepared operation uses is retired only once that operation
///   is named settled or has expired; retirement keeps the key.
pub async fn test_lifecycle_follows_the_live_set(store: &dyn HistoryKeyStore) {
    let domain = owner();
    let first = store
        .ensure_epoch(&new_epoch(domain, 41), audit())
        .await
        .unwrap();
    let later = Utc::now() + chrono::Duration::minutes(15);
    // At revision 1 `first` holds an entry; it is then replaced, effective
    // from revision 2.
    let before_rotation = live(1, &[first.id], &[]);
    let second = store
        .rotate_epoch(&new_epoch(domain, 42), first.id, 2, audit())
        .await
        .unwrap();

    // Concurrent preparations with the same live set agree; operation `a`
    // now uses both epochs.
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    let (ra, rb) = tokio::join!(
        prepare(store, domain, before_rotation.clone(), a, later),
        prepare(store, domain, before_rotation.clone(), b, Utc::now()),
    );
    assert_eq!(ra.unwrap(), vec![second.id, first.id]);
    assert_eq!(rb.unwrap(), vec![second.id, first.id]);

    // The same revision with another set is a conflict.
    let err = prepare(store, domain, live(1, &[], &[]), Uuid::now_v7(), later)
        .await
        .expect_err("one revision, one live set");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    // Revision 2: an entry under `second` emptied `first`. `a` still uses
    // `first`, so it is not retired.
    let emptied = live(2, &[second.id], &[]);
    let selected = prepare(store, domain, emptied.clone(), Uuid::now_v7(), later)
        .await
        .unwrap();
    assert_eq!(selected, vec![second.id]);
    assert!(epoch_ids(store, domain).await.contains(&first.id));

    // An older live set changes nothing: it neither retires nor rolls back.
    prepare(store, domain, before_rotation, Uuid::now_v7(), Utc::now())
        .await
        .unwrap();
    assert!(epoch_ids(store, domain).await.contains(&first.id));

    // Naming `a` settled releases it; `b` expired already. `first` is
    // retired, its key kept.
    let key = store.get_epoch_key(first.id).await.unwrap();
    let selected = prepare(
        store,
        domain,
        live(3, &[second.id], &[a]),
        Uuid::now_v7(),
        later,
    )
    .await
    .unwrap();
    assert_eq!(selected, vec![second.id]);
    assert!(
        !epoch_ids(store, domain).await.contains(&first.id),
        "retired"
    );
    assert_eq!(store.get_epoch_key(first.id).await.unwrap(), key);
}

/// A live set older than an epoch's replacement cannot retire it: when it was
/// read the epoch could still take entries.
pub async fn test_stale_live_set_cannot_retire(store: &dyn HistoryKeyStore) {
    let domain = owner();
    let first = store
        .ensure_epoch(&new_epoch(domain, 51), audit())
        .await
        .unwrap();
    // Replaced effective from revision 2; the delayed set was read at 1,
    // with no entry anywhere.
    let second = store
        .rotate_epoch(&new_epoch(domain, 52), first.id, 2, audit())
        .await
        .unwrap();
    let selected = prepare(store, domain, live(1, &[], &[]), Uuid::now_v7(), Utc::now())
        .await
        .unwrap();
    assert_eq!(selected, vec![second.id]);
    assert!(
        epoch_ids(store, domain).await.contains(&first.id),
        "not retired"
    );
    let selected = prepare(
        store,
        domain,
        live(2, &[first.id], &[]),
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(selected, vec![second.id, first.id]);
}

/// The evaluator's write cutoff is unset until raised, shared by every
/// handle on the store, and only rises: an equal or earlier raise (a retry
/// after a lost acknowledgement, a replica with an older setting) changes
/// nothing and reports the cutoff in force.
pub async fn test_write_cutoff_only_rises(store: &dyn HistoryKeyStore) {
    let at = |offset_ms: i64| {
        chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
            + chrono::Duration::milliseconds(offset_ms)
    };
    let first = at(-1000);
    let raised = store.raise_write_cutoff(first, audit()).await.unwrap();
    assert!(raised >= first);
    assert_eq!(store.write_cutoff().await.unwrap(), Some(raised));
    assert_eq!(
        store.raise_write_cutoff(first, audit()).await.unwrap(),
        raised
    );
    assert_eq!(
        store.raise_write_cutoff(at(-5000), audit()).await.unwrap(),
        raised
    );
    let later = at(1000);
    assert_eq!(
        store.raise_write_cutoff(later, audit()).await.unwrap(),
        later
    );
    assert_eq!(store.write_cutoff().await.unwrap(), Some(later));
    // A finer instant is kept rounded up, never down.
    let fine = later + chrono::Duration::nanoseconds(1500);
    let kept = store.raise_write_cutoff(fine, audit()).await.unwrap();
    assert!(kept >= fine);
}

/// An aborted first enrollment loses the key it created, and only that key:
/// the cleanup fences the operation, so a preparation that arrives after it
/// creates nothing; repeating the cleanup is harmless; a key the operation
/// did not create, or one its owner's lifecycle or another operation still
/// needs, is kept.
pub async fn test_abandoned_enrollment_is_reclaimed(store: &dyn HistoryKeyStore) {
    // Created, then aborted: the key goes, and a late retry creates nothing.
    let domain = owner();
    let operation = Uuid::now_v7();
    let first = new_epoch(domain, 71);
    store
        .create_first_epoch(&first, operation, audit())
        .await
        .unwrap();
    assert_eq!(
        store
            .abandon_enrollment(&domain, operation, audit())
            .await
            .unwrap(),
        sid_core::models::EnrollmentCleanup::Reclaimed
    );
    assert_eq!(store.get_epoch_key(first.epoch.id).await.unwrap(), None);
    assert!(epoch_ids(store, domain).await.is_empty());
    assert!(store.enrollment_abandoned(operation).await.unwrap());
    let late = store
        .create_first_epoch(&first, operation, audit())
        .await
        .expect_err("a preparation after the cleanup");
    assert!(matches!(late, sid_core::Error::Fenced(_)), "{late:?}");
    assert_eq!(
        store
            .abandon_enrollment(&domain, operation, audit())
            .await
            .unwrap(),
        sid_core::models::EnrollmentCleanup::NothingCreated,
        "a repeated cleanup"
    );

    // Aborted before its preparation ran: nothing to reclaim, and the
    // delayed preparation is refused.
    let (early_domain, early) = (owner(), Uuid::now_v7());
    assert_eq!(
        store
            .abandon_enrollment(&early_domain, early, audit())
            .await
            .unwrap(),
        sid_core::models::EnrollmentCleanup::NothingCreated
    );
    let delayed = store
        .create_first_epoch(&new_epoch(early_domain, 72), early, audit())
        .await
        .expect_err("a preparation delayed past its cleanup");
    assert!(matches!(delayed, sid_core::Error::Fenced(_)), "{delayed:?}");
    assert!(epoch_ids(store, early_domain).await.is_empty());

    // Another operation's key is never touched.
    let (kept_domain, creator) = (owner(), Uuid::now_v7());
    let kept = new_epoch(kept_domain, 73);
    store
        .create_first_epoch(&kept, creator, audit())
        .await
        .unwrap();
    assert_eq!(
        store
            .abandon_enrollment(&kept_domain, Uuid::now_v7(), audit())
            .await
            .unwrap(),
        sid_core::models::EnrollmentCleanup::NothingCreated
    );
    assert_eq!(
        store.get_epoch_key(kept.epoch.id).await.unwrap(),
        Some(kept.key.clone())
    );

    // An owner with a recorded lifecycle (it committed and prepared again)
    // keeps its key even if told its first enrollment was aborted.
    prepare(
        store,
        kept_domain,
        live(1, &[kept.epoch.id], &[]),
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .unwrap();
    let retained = store
        .abandon_enrollment(&kept_domain, creator, audit())
        .await
        .unwrap();
    assert!(
        matches!(retained, sid_core::models::EnrollmentCleanup::Retained(_)),
        "{retained:?}"
    );
    assert_eq!(
        store.get_epoch_key(kept.epoch.id).await.unwrap(),
        Some(kept.key)
    );
}

/// A cleanup racing its operation's preparation: either the key was created
/// first and is reclaimed, or the preparation is fenced; never a key left
/// behind for an aborted operation.
pub async fn test_cleanup_races_preparation(store: &dyn HistoryKeyStore) {
    for key in 80..84 {
        let (domain, operation) = (owner(), Uuid::now_v7());
        let new = new_epoch(domain, key);
        let (created, cleaned) = tokio::join!(
            store.create_first_epoch(&new, operation, audit()),
            store.abandon_enrollment(&domain, operation, audit()),
        );
        let cleaned = cleaned.unwrap();
        match created {
            Ok(_) => assert!(
                matches!(
                    cleaned,
                    sid_core::models::EnrollmentCleanup::Reclaimed
                        | sid_core::models::EnrollmentCleanup::NothingCreated
                ),
                "{cleaned:?}"
            ),
            Err(e) => assert!(matches!(e, sid_core::Error::Fenced(_)), "{e:?}"),
        }
        // Whichever came first, a repeated cleanup leaves no key.
        store
            .abandon_enrollment(&domain, operation, audit())
            .await
            .unwrap();
        assert!(epoch_ids(store, domain).await.is_empty(), "key {key} left");
        assert_eq!(store.get_epoch_key(new.epoch.id).await.unwrap(), None);
    }
}

/// A deleted owner's purge destroys its keys, replacements, uses and
/// lifecycle, and only its own; a preparation still in flight for it creates,
/// imports or selects nothing afterwards. Repeating the purge is harmless,
/// and its fence is compacted like an abandoned enrollment's.
pub async fn test_purged_owner_keeps_nothing(store: &dyn HistoryKeyStore) {
    let (purged, kept) = (owner(), owner());
    let first = new_epoch(purged, 1);
    store
        .create_first_epoch(&first, Uuid::now_v7(), audit())
        .await
        .unwrap();
    let operation = Uuid::now_v7();
    let expires = Utc::now() + chrono::Duration::minutes(5);
    prepare(
        store,
        purged,
        live(1, &[first.epoch.id], &[]),
        operation,
        expires,
    )
    .await
    .unwrap();
    store
        .rotate_epoch(&new_epoch(purged, 2), first.epoch.id, 2, audit())
        .await
        .unwrap();
    let archive = store.export_keys(&purged).await.unwrap().unwrap();
    store
        .create_first_epoch(&new_epoch(kept, 3), Uuid::now_v7(), audit())
        .await
        .unwrap();

    assert_eq!(store.purge_owner(&purged, audit()).await.unwrap(), 2);
    assert!(epoch_ids(store, purged).await.is_empty());
    assert!(store.export_keys(&purged).await.unwrap().is_none());
    assert!(store.get_epoch_key(first.epoch.id).await.unwrap().is_none());
    assert_eq!(epoch_ids(store, kept).await.len(), 1, "another owner's key");

    fn fenced<T>(r: sid_core::Result<T>) -> bool {
        matches!(r, Err(sid_core::Error::Fenced(_)))
    }
    assert!(fenced(
        store
            .create_first_epoch(&new_epoch(purged, 4), Uuid::now_v7(), audit())
            .await
    ));
    assert!(fenced(
        store.ensure_epoch(&new_epoch(purged, 5), audit()).await
    ));
    assert!(fenced(
        prepare(store, purged, live(3, &[], &[]), operation, expires)
            .await
            .map(|_| ())
    ));
    assert!(fenced(store.import_keys(&archive, audit()).await));
    assert!(epoch_ids(store, purged).await.is_empty());
    assert_eq!(store.purge_owner(&purged, audit()).await.unwrap(), 0);

    assert_eq!(
        store
            .compact_abandoned(Utc::now() - chrono::Duration::hours(1), audit())
            .await
            .unwrap(),
        0
    );
    assert!(
        store
            .compact_abandoned(Utc::now() + chrono::Duration::seconds(5), audit())
            .await
            .unwrap()
            >= 1
    );
    store
        .ensure_epoch(&new_epoch(purged, 6), audit())
        .await
        .expect("a compacted fence no longer refuses");
}

/// The evaluator's key versions are its own record: inserted once, never
/// replaced, listed in version order.
pub async fn test_history_key_versions_are_insert_only(store: &dyn HistoryKeyStore) {
    // The store may be shared with other scenarios: above its newest version.
    let base = store
        .list_key_versions()
        .await
        .unwrap()
        .iter()
        .map(|v| v.version)
        .max()
        .unwrap_or(0);
    let v1 = sid_keys::KeyVersionParams::new(base + 1, vec![1; 16], "history-v1");
    let v2 = sid_keys::KeyVersionParams::new(base + 2, vec![2; 16], "history-v2");
    assert!(store.insert_key_version(&v2, audit()).await.unwrap());
    assert!(store.insert_key_version(&v1, audit()).await.unwrap());
    let other = sid_keys::KeyVersionParams::new(base + 1, vec![9; 16], "replaced");
    assert!(!store.insert_key_version(&other, audit()).await.unwrap());
    let listed = store.list_key_versions().await.unwrap();
    assert!(listed.windows(2).all(|w| w[0].version < w[1].version));
    assert_eq!(&listed[listed.len() - 2..], &[v1, v2]);
}

/// A fence is dropped only once older than asked; until then it still
/// refuses its operation's preparation.
pub async fn test_abandoned_fences_are_compacted(store: &dyn HistoryKeyStore) {
    let (domain, operation) = (owner(), Uuid::now_v7());
    store
        .abandon_enrollment(&domain, operation, audit())
        .await
        .unwrap();
    assert_eq!(
        store
            .compact_abandoned(Utc::now() - chrono::Duration::hours(1), audit())
            .await
            .unwrap(),
        0
    );
    assert!(store.enrollment_abandoned(operation).await.unwrap());
    let fenced = store
        .create_first_epoch(&new_epoch(domain, 90), operation, audit())
        .await
        .expect_err("still fenced");
    assert!(matches!(fenced, sid_core::Error::Fenced(_)), "{fenced:?}");

    assert!(
        store
            .compact_abandoned(Utc::now() + chrono::Duration::seconds(5), audit())
            .await
            .unwrap()
            >= 1
    );
    assert!(!store.enrollment_abandoned(operation).await.unwrap());
}

/// A key transfer preserves every epoch, sealed key and replacement; exact
/// repeats add nothing; a conflicting or malformed archive mutates nothing.
pub async fn test_key_archive_round_trip(store: &dyn HistoryKeyStore) {
    let domain = owner();
    let now = chrono::DateTime::from_timestamp_micros(1_790_000_000_123_456).unwrap();
    let mut active = new_epoch(domain, 61);
    let mut replaced = new_epoch(domain, 62);
    active.epoch.created_at = now;
    replaced.epoch.created_at = now;
    replaced.epoch.status = HistoryEpochUse::CompareOnly;
    let mut epochs = vec![active, replaced.clone()];
    epochs.sort_by_key(|e| (e.epoch.created_at, e.epoch.id));
    let archive = KeyArchive {
        owner_domain: domain,
        epochs,
        replaced: vec![(replaced.epoch.id, 4)],
    };
    assert!(store.import_keys(&archive, audit()).await.unwrap());
    assert_eq!(
        store.export_keys(&domain).await.unwrap(),
        Some(archive.clone())
    );
    assert!(!store.import_keys(&archive, audit()).await.unwrap());
    let mut conflicting = archive.clone();
    conflicting.replaced[0].1 = 5;
    assert!(matches!(
        store.import_keys(&conflicting, audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    // A key sealed for another owner is refused before any write.
    let mut misbound = archive.clone();
    misbound.owner_domain = owner();
    for e in &mut misbound.epochs {
        e.epoch.owner_domain = misbound.owner_domain;
    }
    assert!(matches!(
        store.import_keys(&misbound, audit()).await,
        Err(sid_core::Error::Validation(_))
    ));
    assert_eq!(
        store.export_keys(&misbound.owner_domain).await.unwrap(),
        None
    );
    assert_eq!(store.export_keys(&domain).await.unwrap(), Some(archive));
}
