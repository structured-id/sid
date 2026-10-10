// SPDX-License-Identifier: AGPL-3.0-only
//! Password history contract, run against
//! every backend: epochs are prepared once per owner, entries are written only
//! with the credential that earned them, a commit made against a stale read
//! writes nothing, and retention keeps the newest accepted passwords.

use chrono::Utc;
use sid_core::models::{
    Credential, CredentialData, CredentialType, HistoryCommit, HistoryEpoch, HistoryEpochId,
    HistoryEpochUse, HistoryEvidence, HistoryKsf, HistoryLiveSet, HistoryPreparation, HistorySuite,
    NewHistoryEpoch, NewRegistration, PasswordResetSession, ProfileId, WrappedHistoryKey,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit, test_session_end};

fn new_epoch(owner: ProfileId, key: u8) -> NewHistoryEpoch {
    let id = HistoryEpochId::generate();
    NewHistoryEpoch {
        epoch: HistoryEpoch {
            id,
            owner,
            suite: HistorySuite::PallasPoseidonV1,
            public_key: [key; 32],
            ksf: HistoryKsf::DEFAULT,
            ksf_salt: [key.wrapping_add(1); 32],
            status: HistoryEpochUse::Active,
            // Stored at millisecond precision by every backend.
            created_at: chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
                .unwrap(),
        },
        key: WrappedHistoryKey(
            sid_keys::EncryptedField {
                key_version: 1,
                nonce: [0; 12],
                context: format!("password-history-key:{}:{owner}", id.0),
                ciphertext: vec![key; 48],
            }
            .to_bytes(),
        ),
    }
}

fn commit(
    owner: ProfileId,
    expected_revision: i64,
    epoch: HistoryEpochId,
    entry: u8,
    depth: u32,
) -> HistoryCommit {
    HistoryCommit {
        owner,
        expected_revision,
        new_epoch: None,
        entries: vec![(epoch, [entry; 32])],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        depth,
    }
}

async fn profile_with_password(
    backend: &dyn StorageBackend,
    name: &str,
) -> (ProfileId, Credential) {
    let profile = create_test_profile(name);
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, b"p0".to_vec(), None);
    backend
        .create_credential(&password, test_audit())
        .await
        .unwrap();
    (profile.id, password)
}

fn next(password: &Credential, data: &[u8]) -> Credential {
    let mut new = password.clone();
    new.data = CredentialData::new(data.to_vec());
    new.policy_evidence = sid_core::models::PolicyEvidence::Verified {
        policy_version: 1,
        artifact: [1; 32],
    };
    new
}

/// The evaluator's view of `owner` is the history's revision and epochs, with
/// no entry.
async fn assert_epoch_view(backend: &dyn StorageBackend, owner: ProfileId) {
    let history = backend.get_password_history(owner).await.unwrap();
    let view = backend.get_history_epochs(owner).await.unwrap();
    assert_eq!(view.revision, history.revision);
    assert_eq!(view.epochs, history.epochs);
}

/// The evaluator's preparation of `operation` for `owner` under `live`,
/// usable by the operation until `expires_at`.
async fn prepare(
    backend: &dyn StorageBackend,
    owner: ProfileId,
    live: HistoryLiveSet,
    operation: Uuid,
    expires_at: chrono::DateTime<Utc>,
) -> sid_core::Result<Vec<HistoryEpochId>> {
    backend
        .prepare_history_epochs(
            &HistoryPreparation {
                owner,
                live,
                operation,
                expires_at,
                now: Utc::now(),
            },
            test_audit(),
        )
        .await
        .map(|selected| selected.iter().map(|e| e.id).collect())
}

/// The live set the credential service reads for `owner` now.
async fn live_now(backend: &dyn StorageBackend, owner: ProfileId) -> HistoryLiveSet {
    HistoryLiveSet::of(&backend.get_password_history(owner).await.unwrap())
}

/// The transfer preserves entries, sealed keys and retired provenance; exact
/// repeats add nothing, conflicting or malformed archives never mutate history.
pub async fn test_history_archive_preserves_lifecycle(backend: &dyn StorageBackend) {
    use sid_core::models::{HistoryArchive, HistoryEntry};
    let (owner, _) = profile_with_password(backend, "hist_archive").await;
    let mut active = new_epoch(owner, 21);
    let mut compared = new_epoch(owner, 22);
    let mut retired = new_epoch(owner, 23);
    compared.epoch.status = HistoryEpochUse::CompareOnly;
    retired.epoch.status = HistoryEpochUse::Retired;
    // Eligible key destruction does not erase retired epoch provenance.
    retired.key = WrappedHistoryKey(Vec::new());
    // Preserve PostgreSQL's full microsecond precision across SQLite transfer;
    // millisecond formatting loses provenance and breaks an exact retry.
    let now = chrono::DateTime::from_timestamp_micros(1_790_000_000_123_456).unwrap();
    compared.epoch.created_at = now;
    retired.epoch.created_at = now;
    active.epoch.created_at = now;
    let entries = vec![
        HistoryEntry {
            epoch: active.epoch.id,
            seq: 2,
            entry: [31; 32],
            evidence: HistoryEvidence {
                operation: Uuid::now_v7(),
                policy_version: 1,
            },
            created_at: now,
        },
        HistoryEntry {
            epoch: compared.epoch.id,
            seq: 1,
            entry: [30; 32],
            evidence: HistoryEvidence {
                operation: Uuid::now_v7(),
                policy_version: 1,
            },
            created_at: now,
        },
    ];
    let mut archive = HistoryArchive {
        owner,
        revision: 7,
        epochs: vec![active.clone(), compared, retired.clone()],
        entries,
    };
    archive
        .epochs
        .sort_by_key(|e| (e.epoch.created_at, e.epoch.id));
    assert!(
        backend
            .import_password_history(&archive, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend.export_password_history(owner).await.unwrap(),
        Some(archive.clone())
    );
    assert!(
        !backend
            .import_password_history(&archive, test_audit())
            .await
            .unwrap()
    );
    let view = backend.get_password_history(owner).await.unwrap();
    assert_eq!(view.revision, 7);
    assert_eq!(view.entries.len(), 2);
    assert!(!view.epochs.iter().any(|e| e.id == retired.epoch.id));
    assert_epoch_view(backend, owner).await;
    assert_eq!(
        backend
            .get_history_epoch_key(retired.epoch.id)
            .await
            .unwrap(),
        Some(retired.key)
    );
    let mut stale = archive.clone();
    stale.revision -= 1;
    assert!(matches!(
        backend.import_password_history(&stale, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    // Reject noncanonical input before writing: otherwise a successful first
    // import is sorted on export and the same input falsely conflicts on retry.
    let mut reordered = archive.clone();
    reordered.epochs.reverse();
    assert!(matches!(
        backend
            .import_password_history(&reordered, test_audit())
            .await,
        Err(sid_core::Error::Validation(_))
    ));
    let mut invalid = archive.clone();
    invalid.entries[0].epoch = HistoryEpochId::generate();
    assert!(matches!(
        backend
            .import_password_history(&invalid, test_audit())
            .await,
        Err(sid_core::Error::Validation(_))
    ));
    assert_eq!(
        backend.export_password_history(owner).await.unwrap(),
        Some(archive)
    );

    // The same serialized contract is accepted by an independent SQLite
    // backend: PostgreSQL UUID/timestamp encodings must not change its meaning.
    #[cfg(feature = "storage-sqlite")]
    {
        let sqlite = sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap();
        let profile = backend.get_profile(owner).await.unwrap().unwrap();
        sqlite.create_profile(&profile, test_audit()).await.unwrap();
        let exported = backend
            .export_password_history(owner)
            .await
            .unwrap()
            .unwrap();
        let bytes = serde_json::to_vec(&exported).unwrap();
        let decoded: HistoryArchive = serde_json::from_slice(&bytes).unwrap();
        assert!(
            sqlite
                .import_password_history(&decoded, test_audit())
                .await
                .unwrap()
        );
        assert_eq!(
            sqlite.export_password_history(owner).await.unwrap(),
            Some(decoded.clone())
        );
        // Files written before microsecond-preserving transfer used three
        // fractional digits. SQL text order differs from timestamp order when
        // those rows coexist with six-digit timestamps in the same millisecond.
        let mut expected = decoded.clone();
        let old = expected.epochs[0]
            .epoch
            .created_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        sqlx::query("UPDATE password_history_epochs SET created_at = ? WHERE id = ?")
            .bind(&old)
            .bind(expected.epochs[0].epoch.id.0.to_string())
            .execute(sqlite.pool())
            .await
            .unwrap();
        expected.epochs[0].epoch.created_at = chrono::DateTime::parse_from_rfc3339(&old)
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            sqlite.export_password_history(owner).await.unwrap(),
            Some(expected)
        );
    }
}

/// An owner without history reads as revision 0 with nothing in it: the
/// first commit is made against 0.
pub async fn test_history_is_empty_until_written(backend: &dyn StorageBackend) {
    let (owner, _) = profile_with_password(backend, "hist_empty").await;
    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.revision, 0);
    assert!(history.epochs.is_empty() && history.entries.is_empty());
    assert_epoch_view(backend, owner).await;
}

/// Preparing an epoch writes it and its sealed key once. A second or a
/// concurrent preparation gets the stored epoch back, so every operation of
/// the owner uses one key; the key is readable by epoch id, and an owner
/// that does not exist gets `NotFound`.
pub async fn test_history_epoch_is_prepared_once(backend: &dyn StorageBackend) {
    let (owner, _) = profile_with_password(backend, "hist_epoch").await;
    let (a, b) = (new_epoch(owner, 1), new_epoch(owner, 2));
    let (ra, rb) = tokio::join!(
        backend.ensure_history_epoch(&a, test_audit()),
        backend.ensure_history_epoch(&b, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.id, rb.id, "concurrent preparations agree on one epoch");
    let winner = if ra.id == a.epoch.id { &a } else { &b };
    assert_eq!(ra, winner.epoch);

    let again = backend
        .ensure_history_epoch(&new_epoch(owner, 3), test_audit())
        .await
        .unwrap();
    assert_eq!(
        again.id, winner.epoch.id,
        "a stored epoch is never replaced"
    );

    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.revision, 2, "created row, then the epoch");
    assert_eq!(history.epochs, vec![winner.epoch.clone()]);
    assert_eq!(
        backend
            .get_history_epoch_key(winner.epoch.id)
            .await
            .unwrap(),
        Some(winner.key.clone())
    );
    assert_eq!(
        backend
            .get_history_epoch_key(HistoryEpochId::generate())
            .await
            .unwrap(),
        None
    );

    let err = backend
        .ensure_history_epoch(&new_epoch(ProfileId::generate(), 4), test_audit())
        .await
        .expect_err("no profile, no history");
    assert!(matches!(err, sid_core::Error::NotFound(_)), "{err:?}");
}

/// Rotation replaces the active epoch: the replaced one stops taking entries
/// but stays comparable while it retains one, and is retired, its sealed key
/// kept, by the first preparation after retention removed its last entry.
/// Concurrent rotations from one epoch agree on one replacement; a stale
/// rotation writes nothing.
pub async fn test_history_epoch_rotation(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_rotate").await;
    let old = backend
        .ensure_history_epoch(&new_epoch(owner, 11), test_audit())
        .await
        .unwrap();
    let read = backend.get_password_history(owner).await.unwrap();
    assert!(
        backend
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&commit(owner, read.revision, old.id, 0x11, 1)),
                test_audit()
            )
            .await
            .unwrap()
    );
    let before = backend.get_password_history(owner).await.unwrap();

    let (a, b) = (new_epoch(owner, 12), new_epoch(owner, 13));
    let (ra, rb) = tokio::join!(
        backend.rotate_history_epoch(&a, old.id, test_audit()),
        backend.rotate_history_epoch(&b, old.id, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.id, rb.id, "concurrent rotations agree on one epoch");
    let replacement = ra;
    let rotated = backend.get_password_history(owner).await.unwrap();
    assert_eq!(rotated.revision, before.revision + 1, "one rotation wrote");
    assert_eq!(rotated.active_epoch().map(|e| e.id), Some(replacement.id));
    let required: Vec<HistoryEpochId> = rotated.required_epochs().iter().map(|e| e.id).collect();
    assert_eq!(
        required,
        vec![replacement.id, old.id],
        "the replaced epoch still holds an entry and stays required"
    );
    assert_eq!(
        rotated
            .epochs
            .iter()
            .find(|e| e.id == old.id)
            .map(|e| e.status),
        Some(HistoryEpochUse::CompareOnly)
    );
    assert_epoch_view(backend, owner).await;

    // A rotation naming an epoch no longer active changes nothing.
    let late = backend
        .rotate_history_epoch(&new_epoch(owner, 14), old.id, test_audit())
        .await
        .unwrap();
    assert_eq!(late.id, replacement.id);
    assert_eq!(
        backend.get_password_history(owner).await.unwrap().revision,
        rotated.revision
    );

    // The replaced epoch takes no new entry: the whole change is refused.
    assert!(
        !backend
            .change_password(
                password.id,
                b"p1",
                &next(&password, b"p2"),
                Some(&commit(owner, rotated.revision, old.id, 0x12, 1)),
                test_audit()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        backend
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"p1"
    );

    // An entry under the replacement empties the replaced epoch. The commit
    // does not retire it: the evaluator does, at the next preparation whose
    // live set no longer names it; its sealed key is kept.
    let old_key = backend.get_history_epoch_key(old.id).await.unwrap();
    assert!(
        backend
            .change_password(
                password.id,
                b"p1",
                &next(&password, b"p2"),
                Some(&commit(owner, rotated.revision, replacement.id, 0x13, 1)),
                test_audit()
            )
            .await
            .unwrap()
    );
    let emptied = backend.get_password_history(owner).await.unwrap();
    assert_epoch_view(backend, owner).await;
    assert_eq!(emptied.entries.len(), 1);
    assert_eq!(emptied.entries[0].epoch, replacement.id);
    assert_eq!(
        emptied
            .required_epochs()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![replacement.id],
        "an emptied epoch is no longer required"
    );
    let selected = prepare(
        backend,
        owner,
        live_now(backend, owner).await,
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(selected, vec![replacement.id]);
    let after = backend.get_password_history(owner).await.unwrap();
    assert_epoch_view(backend, owner).await;
    assert_eq!(after.epochs, vec![replacement.clone()], "retired");
    assert_eq!(
        backend.get_history_epoch_key(old.id).await.unwrap(),
        old_key,
        "retirement keeps the sealed key"
    );

    // An epoch that never held an entry is retired by the next preparation
    // once it is replaced.
    let (fresh_owner, _) = profile_with_password(backend, "hist_rotate_empty").await;
    let unused = backend
        .ensure_history_epoch(&new_epoch(fresh_owner, 15), test_audit())
        .await
        .unwrap();
    let next_epoch = backend
        .rotate_history_epoch(&new_epoch(fresh_owner, 16), unused.id, test_audit())
        .await
        .unwrap();
    let selected = prepare(
        backend,
        fresh_owner,
        live_now(backend, fresh_owner).await,
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(selected, vec![next_epoch.id]);
    let view = backend.get_password_history(fresh_owner).await.unwrap();
    assert_eq!(view.epochs, vec![next_epoch]);
    assert_epoch_view(backend, fresh_owner).await;
    assert_ne!(
        backend.get_history_epoch_key(unused.id).await.unwrap(),
        Some(WrappedHistoryKey(Vec::new()))
    );

    let err = backend
        .rotate_history_epoch(
            &new_epoch(ProfileId::generate(), 17),
            HistoryEpochId::generate(),
            test_audit(),
        )
        .await
        .expect_err("no profile, no history");
    assert!(matches!(err, sid_core::Error::NotFound(_)), "{err:?}");
}

/// A registration with an accepted proof writes the profile, its first
/// epoch and its first entry in one commit.
pub async fn test_registration_writes_first_history(backend: &dyn StorageBackend) {
    let profile = create_test_profile("hist_reg");
    let owner = profile.id;
    let credential = Credential::new(owner, CredentialType::Opaque, b"p0".to_vec(), None);
    let epoch = new_epoch(owner, 5);
    let mut first = commit(owner, 0, epoch.epoch.id, 0xa1, 1);
    first.new_epoch = Some(epoch.clone());
    let registration = NewRegistration::new(
        profile.clone(),
        sid_core::models::SignupIdentifier::Username(profile.username.as_deref().unwrap()),
        Some(credential),
    )
    .unwrap()
    .with_history(first)
    .unwrap();
    backend
        .register_profile(&registration, test_audit())
        .await
        .unwrap();

    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.revision, 1);
    assert_eq!(history.epochs, vec![epoch.epoch.clone()]);
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.entries[0].entry, [0xa1; 32]);
    assert_eq!(history.entries[0].epoch, epoch.epoch.id);
    assert_eq!(
        backend.get_history_epoch_key(epoch.epoch.id).await.unwrap(),
        Some(epoch.key)
    );
}

/// A change whose history read is stale writes nothing, credential
/// included; the one made against the current revision applies. Of two
/// concurrent changes from one revision exactly one applies.
pub async fn test_history_commit_is_compare_and_swap(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_cas").await;
    let epoch = backend
        .ensure_history_epoch(&new_epoch(owner, 6), test_audit())
        .await
        .unwrap();
    let read = backend.get_password_history(owner).await.unwrap();

    let stale = commit(owner, read.revision - 1, epoch.id, 1, 3);
    assert!(
        !backend
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&stale),
                test_audit()
            )
            .await
            .unwrap()
    );
    let stored = backend.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(
        stored.data.expose(),
        b"p0",
        "a refused history kept the password"
    );
    assert!(
        backend
            .get_password_history(owner)
            .await
            .unwrap()
            .entries
            .is_empty()
    );

    let current = commit(owner, read.revision, epoch.id, 1, 3);
    assert!(
        backend
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&current),
                test_audit()
            )
            .await
            .unwrap()
    );
    let after = backend.get_password_history(owner).await.unwrap();
    assert_eq!(after.revision, read.revision + 1);
    assert_eq!(after.entries.len(), 1);
    assert_eq!(after.entries[0].evidence, current.evidence);

    // Two changes from the same credential state and history revision.
    let (to_a, to_b) = (next(&password, b"a"), next(&password, b"b"));
    let (ca, cb) = (
        commit(owner, after.revision, epoch.id, 2, 3),
        commit(owner, after.revision, epoch.id, 3, 3),
    );
    let (a, b) = tokio::join!(
        backend.change_password(password.id, b"p1", &to_a, Some(&ca), test_audit()),
        backend.change_password(password.id, b"p1", &to_b, Some(&cb), test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one concurrent change applies: {a} {b}");
    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.entries.len(), 2);
    let winner = if a { [2u8; 32] } else { [3u8; 32] };
    assert_eq!(history.entries[0].entry, winner, "newest first");
}

/// Retention keeps the newest `depth` accepted passwords: five changes with
/// depth 3 leave the last three, newest first.
pub async fn test_history_retains_depth(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_depth").await;
    let epoch = backend
        .ensure_history_epoch(&new_epoch(owner, 7), test_audit())
        .await
        .unwrap();
    let mut current = b"p0".to_vec();
    for i in 1..=5u8 {
        let revision = backend.get_password_history(owner).await.unwrap().revision;
        let data = vec![b'p', b'0' + i];
        assert!(
            backend
                .change_password(
                    password.id,
                    &current,
                    &next(&password, &data),
                    Some(&commit(owner, revision, epoch.id, i, 3)),
                    test_audit()
                )
                .await
                .unwrap()
        );
        current = data;
    }
    let entries: Vec<[u8; 32]> = backend
        .get_password_history(owner)
        .await
        .unwrap()
        .entries
        .iter()
        .map(|e| e.entry)
        .collect();
    assert_eq!(entries, vec![[5u8; 32], [4u8; 32], [3u8; 32]]);
}

/// A reset whose history read is stale completes nothing: the reset stays
/// verified, the old password stays, no session ends. One made against the
/// current revision completes with its entry.
pub async fn test_reset_history_is_compare_and_swap(backend: &dyn StorageBackend) {
    let (owner, old) = profile_with_password(backend, "hist_reset").await;
    let epoch = backend
        .ensure_history_epoch(&new_epoch(owner, 8), test_audit())
        .await
        .unwrap();
    let reset = PasswordResetSession::new(owner, "h@sid.example.com".into(), "hash".into());
    backend
        .create_reset_session(&reset, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .verify_reset_session(reset.id, test_audit())
            .await
            .unwrap()
    );
    let read = backend.get_password_history(owner).await.unwrap();
    let replacement = Credential::new(owner, CredentialType::Opaque, b"r1".to_vec(), None);

    let stale = commit(owner, read.revision + 7, epoch.id, 9, 1);
    assert!(
        backend
            .complete_password_reset(
                reset.id,
                &replacement,
                Some(&stale),
                &test_session_end(),
                test_audit()
            )
            .await
            .unwrap()
            .is_none()
    );
    let passwords = backend
        .get_credentials_by_profile(owner, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].id, old.id, "the old password stayed");

    let current = commit(owner, read.revision, epoch.id, 9, 1);
    assert!(
        backend
            .complete_password_reset(
                reset.id,
                &replacement,
                Some(&current),
                &test_session_end(),
                test_audit()
            )
            .await
            .unwrap()
            .is_some()
    );
    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.entries[0].entry, [9u8; 32]);
}

/// The evaluator's lifecycle record, as the credential service's live sets
/// drive it:
/// - one revision has one live set: another set for it is a conflict, the same
///   one again (or concurrently) is accepted;
/// - an older live set changes nothing and retires nothing;
/// - a live set read before an epoch was replaced cannot retire it, even if
///   it does not name it;
/// - an epoch a prepared operation uses is retired only once that operation
///   is named settled or has expired;
/// - a live set naming another owner's epoch is refused.
pub async fn test_history_lifecycle_follows_the_live_set(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_lifecycle").await;
    let first = backend
        .ensure_history_epoch(&new_epoch(owner, 41), test_audit())
        .await
        .unwrap();
    let read = backend.get_password_history(owner).await.unwrap();
    assert!(
        backend
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&commit(owner, read.revision, first.id, 0x41, 1)),
                test_audit()
            )
            .await
            .unwrap()
    );
    let later = Utc::now() + chrono::Duration::minutes(15);

    // The live set read while `first` was active and held the entry.
    let before_rotation = live_now(backend, owner).await;
    assert_eq!(before_rotation.live, vec![first.id]);
    let second = backend
        .rotate_history_epoch(&new_epoch(owner, 42), first.id, test_audit())
        .await
        .unwrap();

    // Concurrent preparations with the same live set agree; operation `a`
    // now uses both epochs.
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    let (ra, rb) = tokio::join!(
        prepare(backend, owner, before_rotation.clone(), a, later),
        prepare(backend, owner, before_rotation.clone(), b, Utc::now()),
    );
    assert_eq!(ra.unwrap(), vec![second.id, first.id]);
    assert_eq!(rb.unwrap(), vec![second.id, first.id]);

    // The same revision with another set is a conflict and changes nothing.
    let mut other = before_rotation.clone();
    other.live.clear();
    let err = prepare(backend, owner, other, Uuid::now_v7(), later)
        .await
        .expect_err("one revision, one live set");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    // A change under the new epoch empties `first`.
    let current = backend.get_password_history(owner).await.unwrap();
    assert!(
        backend
            .change_password(
                password.id,
                b"p1",
                &next(&password, b"p2"),
                Some(&commit(owner, current.revision, second.id, 0x42, 1)),
                test_audit()
            )
            .await
            .unwrap()
    );
    let emptied = live_now(backend, owner).await;
    assert_eq!(emptied.live, vec![second.id]);

    // `a` still uses `first`: the newer live set does not retire it.
    let selected = prepare(backend, owner, emptied.clone(), Uuid::now_v7(), later)
        .await
        .unwrap();
    assert_eq!(selected, vec![second.id]);
    let view = backend.get_history_epochs(owner).await.unwrap();
    assert!(
        view.epochs.iter().any(|e| e.id == first.id),
        "an epoch an operation uses is not retired"
    );

    // An older live set changes nothing: it neither retires nor rolls back.
    // (Its own operation expires at once, so it holds nothing.)
    prepare(
        backend,
        owner,
        before_rotation.clone(),
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(
        backend
            .get_history_epochs(owner)
            .await
            .unwrap()
            .epochs
            .iter()
            .any(|e| e.id == first.id)
    );

    // Naming `a` settled releases it; `b` expired already. `first` is
    // retired, its key kept.
    let key = backend.get_history_epoch_key(first.id).await.unwrap();
    let mut settled = emptied.clone();
    settled.settled = vec![a];
    let selected = prepare(backend, owner, settled, Uuid::now_v7(), later)
        .await
        .unwrap();
    assert_eq!(selected, vec![second.id]);
    let view = backend.get_history_epochs(owner).await.unwrap();
    assert!(!view.epochs.iter().any(|e| e.id == first.id), "retired");
    assert_eq!(backend.get_history_epoch_key(first.id).await.unwrap(), key);

    // Another owner's epoch in the live set is refused.
    let (stranger, _) = profile_with_password(backend, "hist_lifecycle_other").await;
    let theirs = backend
        .ensure_history_epoch(&new_epoch(stranger, 43), test_audit())
        .await
        .unwrap();
    let mut foreign = emptied.clone();
    foreign.revision += 1;
    foreign.live = vec![theirs.id];
    let err = prepare(backend, owner, foreign, Uuid::now_v7(), later)
        .await
        .expect_err("another owner's epoch");
    assert!(matches!(err, sid_core::Error::Validation(_)), "{err:?}");
}

/// A live set read before an epoch was replaced, arriving after it, cannot
/// retire it: when it was read the epoch could still take entries.
pub async fn test_history_stale_live_set_cannot_retire(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_stale_live").await;
    let first = backend
        .ensure_history_epoch(&new_epoch(owner, 51), test_audit())
        .await
        .unwrap();
    // Read with no entry anywhere.
    let stale = live_now(backend, owner).await;
    assert!(stale.live.is_empty());
    // `first` then takes an entry and is replaced.
    let read = backend.get_password_history(owner).await.unwrap();
    assert!(
        backend
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&commit(owner, read.revision, first.id, 0x51, 1)),
                test_audit()
            )
            .await
            .unwrap()
    );
    let second = backend
        .rotate_history_epoch(&new_epoch(owner, 52), first.id, test_audit())
        .await
        .unwrap();
    // The stale, empty set is the first the evaluator records: it is older
    // than the replacement, so `first` and its entry stay.
    let selected = prepare(backend, owner, stale, Uuid::now_v7(), Utc::now())
        .await
        .unwrap();
    assert_eq!(selected, vec![second.id]);
    let view = backend.get_history_epochs(owner).await.unwrap();
    assert!(view.epochs.iter().any(|e| e.id == first.id), "not retired");
    let current = live_now(backend, owner).await;
    assert_eq!(current.live, vec![first.id]);
    let selected = prepare(backend, owner, current, Uuid::now_v7(), Utc::now())
        .await
        .unwrap();
    assert_eq!(selected, vec![second.id, first.id]);
}

/// History is written only for the credential's own profile.
pub async fn test_history_of_another_owner_is_refused(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_owner").await;
    let (other, _) = profile_with_password(backend, "hist_other").await;
    let epoch = backend
        .ensure_history_epoch(&new_epoch(other, 10), test_audit())
        .await
        .unwrap();
    let revision = backend.get_password_history(other).await.unwrap().revision;
    let err = backend
        .change_password(
            password.id,
            b"p0",
            &next(&password, b"p1"),
            Some(&commit(other, revision, epoch.id, 1, 1)),
            test_audit(),
        )
        .await
        .expect_err("another owner's history");
    assert!(matches!(err, sid_core::Error::Validation(_)), "{err:?}");
    assert_eq!(
        backend
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"p0"
    );
    assert!(
        backend
            .get_password_history(owner)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
}
