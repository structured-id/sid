// SPDX-License-Identifier: AGPL-3.0-only
//! Password history contract of the credential service's store, run against
//! every backend: an operation's epoch descriptors are published with its
//! entries, a recorded descriptor never changes, entries are written only
//! with the credential that earned them, a commit made against a stale read
//! writes nothing, and retention keeps the newest accepted passwords.

use chrono::Utc;
use sid_core::models::{
    Credential, CredentialData, CredentialType, HistoryCommit, HistoryEpochDescriptor,
    HistoryEpochId, HistoryEpochUse, HistoryEvidence, HistoryKsf, HistorySuite, NewRegistration,
    PasswordResetSession, ProfileId,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit, test_session_end};

/// A descriptor as the evaluator issues one.
fn descriptor(key: u8) -> HistoryEpochDescriptor {
    HistoryEpochDescriptor {
        id: HistoryEpochId::generate(),
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [key; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [key.wrapping_add(1); 32],
        // Stored to the microsecond by every backend.
        created_at: chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
            .unwrap(),
    }
}

/// A commit of one entry under `epochs[0]`, the operation's selection.
fn commit(
    owner: ProfileId,
    expected_revision: i64,
    epochs: &[HistoryEpochDescriptor],
    entry: u8,
    depth: u32,
) -> HistoryCommit {
    HistoryCommit {
        owner,
        expected_revision,
        epochs: epochs.to_vec(),
        entries: vec![(epochs[0].id, [entry; 32])],
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

/// Change `password` from `from` to `to` with one entry under `epochs[0]`
/// against the current revision; whether it applied.
async fn change(
    backend: &dyn StorageBackend,
    owner: ProfileId,
    password: &Credential,
    (from, to): (&[u8], &[u8]),
    epochs: &[HistoryEpochDescriptor],
    entry: u8,
    depth: u32,
) -> sid_core::Result<bool> {
    let revision = backend.get_password_history(owner).await?.revision;
    backend
        .change_password(
            password.id,
            from,
            &next(password, to),
            Some(&commit(owner, revision, epochs, entry, depth)),
            test_audit(),
        )
        .await
}

/// The transfer preserves descriptors (retired ones included) and entries;
/// exact repeats add nothing, conflicting or malformed archives never
/// mutate history.
pub async fn test_history_archive_preserves_lifecycle(backend: &dyn StorageBackend) {
    use sid_core::models::{HistoryArchive, HistoryEntry, HistoryEpoch};
    let (owner, _) = profile_with_password(backend, "hist_archive").await;
    // Preserve PostgreSQL's full microsecond precision across SQLite transfer;
    // millisecond formatting loses provenance and breaks an exact retry.
    let now = chrono::DateTime::from_timestamp_micros(1_790_000_000_123_456).unwrap();
    let epoch = |key: u8, status| {
        let d = descriptor(key);
        HistoryEpoch {
            id: d.id,
            owner,
            suite: d.suite,
            public_key: d.public_key,
            ksf: d.ksf,
            ksf_salt: d.ksf_salt,
            status,
            created_at: now,
        }
    };
    let active = epoch(21, HistoryEpochUse::Active);
    let compared = epoch(22, HistoryEpochUse::CompareOnly);
    let retired = epoch(23, HistoryEpochUse::Retired);
    let entries = vec![
        HistoryEntry {
            epoch: active.id,
            seq: 2,
            entry: [31; 32],
            evidence: HistoryEvidence {
                operation: Uuid::now_v7(),
                policy_version: 1,
            },
            created_at: now,
        },
        HistoryEntry {
            epoch: compared.id,
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
    archive.epochs.sort_by_key(|e| (e.created_at, e.id));
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
    assert!(!view.epochs.iter().any(|e| e.id == retired.id));
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
            .created_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        sqlx::query("UPDATE password_history_epochs SET created_at = ? WHERE id = ?")
            .bind(&old)
            .bind(expected.epochs[0].id.0.to_string())
            .execute(sqlite.pool())
            .await
            .unwrap();
        expected.epochs[0].created_at = chrono::DateTime::parse_from_rfc3339(&old)
            .unwrap()
            .with_timezone(&chrono::Utc);
        expected.epochs.sort_by_key(|e| (e.created_at, e.id));
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
}

/// A registration with an accepted proof writes the profile, its first
/// epoch's descriptor and its first entry in one commit; no key is stored.
pub async fn test_registration_writes_first_history(backend: &dyn StorageBackend) {
    let profile = create_test_profile("hist_reg");
    let owner = profile.id;
    let credential = Credential::new(owner, CredentialType::Opaque, b"p0".to_vec(), None);
    let first = descriptor(5);
    let registration = NewRegistration::new(
        profile.clone(),
        sid_core::models::SignupIdentifier::Username(profile.username.as_deref().unwrap()),
        Some(credential),
    )
    .unwrap()
    .with_history(commit(owner, 0, &[first], 0xa1, 1))
    .unwrap();
    backend
        .register_profile(&registration, test_audit())
        .await
        .unwrap();

    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.revision, 1);
    assert_eq!(history.epochs.len(), 1);
    assert_eq!(history.epochs[0].descriptor(), first);
    assert_eq!(history.epochs[0].owner, owner);
    assert_eq!(history.epochs[0].status, HistoryEpochUse::Active);
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.entries[0].entry, [0xa1; 32]);
    assert_eq!(history.entries[0].epoch, first.id);
}

/// A rotation the evaluator prepared is published by the commit that uses
/// it: the new epoch becomes the one active epoch, the replaced one stays
/// comparable while it retains an entry and leaves the required set once
/// retention empties it.
pub async fn test_history_rotation_is_published_by_its_commit(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_rotate").await;
    let old = descriptor(11);
    assert!(
        change(backend, owner, &password, (b"p0", b"p1"), &[old], 0x11, 2)
            .await
            .unwrap()
    );
    let new = descriptor(12);
    assert!(
        change(
            backend,
            owner,
            &password,
            (b"p1", b"p2"),
            &[new, old],
            0x12,
            2
        )
        .await
        .unwrap()
    );
    let rotated = backend.get_password_history(owner).await.unwrap();
    assert_eq!(rotated.active_epoch().map(|e| e.id), Some(new.id));
    assert_eq!(
        rotated
            .required_epochs()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![new.id, old.id],
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
    // Depth 1: the next commit's retention removes the old epoch's entry.
    assert!(
        change(
            backend,
            owner,
            &password,
            (b"p2", b"p3"),
            &[new, old],
            0x13,
            1
        )
        .await
        .unwrap()
    );
    let emptied = backend.get_password_history(owner).await.unwrap();
    assert_eq!(
        emptied
            .required_epochs()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![new.id],
        "an emptied epoch is no longer required"
    );
}

/// A descriptor once recorded never changes: a commit naming its epoch with
/// another public key, salt or KSF, or naming another owner's epoch, is a
/// conflict and writes nothing, credential included.
pub async fn test_history_descriptor_conflict_writes_nothing(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_descriptor").await;
    let first = descriptor(31);
    assert!(
        change(backend, owner, &password, (b"p0", b"p1"), &[first], 0x31, 3)
            .await
            .unwrap()
    );
    for tamper in [
        |d: &mut HistoryEpochDescriptor| d.public_key[0] ^= 1,
        |d: &mut HistoryEpochDescriptor| d.ksf_salt[0] ^= 1,
        |d: &mut HistoryEpochDescriptor| d.ksf.passes += 1,
    ] {
        let mut other = first;
        tamper(&mut other);
        let err = change(backend, owner, &password, (b"p1", b"p2"), &[other], 0x32, 3)
            .await
            .expect_err("a conflicting descriptor");
        assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    }
    let (stranger, theirs) = profile_with_password(backend, "hist_descriptor_other").await;
    let foreign = descriptor(33);
    assert!(
        change(
            backend,
            stranger,
            &theirs,
            (b"p0", b"p1"),
            &[foreign],
            0x33,
            3
        )
        .await
        .unwrap()
    );
    let err = change(
        backend,
        owner,
        &password,
        (b"p1", b"p2"),
        &[foreign],
        0x34,
        3,
    )
    .await
    .expect_err("another owner's epoch");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    let stored = backend.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(
        stored.data.expose(),
        b"p1",
        "the refused changes kept the password"
    );
    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.epochs.len(), 1);
    assert_eq!(history.epochs[0].descriptor(), first);
}

/// A change whose history read is stale writes nothing, credential
/// included; the one made against the current revision applies. Of two
/// concurrent changes from one revision exactly one applies.
pub async fn test_history_commit_is_compare_and_swap(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_cas").await;
    let epoch = descriptor(6);
    let read = backend.get_password_history(owner).await.unwrap();

    let stale = commit(owner, read.revision + 1, &[epoch], 1, 3);
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
    let empty = backend.get_password_history(owner).await.unwrap();
    assert!(empty.entries.is_empty() && empty.epochs.is_empty());

    let current = commit(owner, read.revision, &[epoch], 1, 3);
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
        commit(owner, after.revision, &[epoch], 2, 3),
        commit(owner, after.revision, &[epoch], 3, 3),
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
    let epoch = descriptor(7);
    let mut current = b"p0".to_vec();
    for i in 1..=5u8 {
        let data = vec![b'p', b'0' + i];
        assert!(
            change(backend, owner, &password, (&current, &data), &[epoch], i, 3)
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
    let epoch = descriptor(8);
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

    let stale = commit(owner, read.revision + 7, &[epoch], 9, 1);
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

    let current = commit(owner, read.revision, &[epoch], 9, 1);
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

/// The history write cutoff fences commits in the owning transaction: an
/// entry under an epoch created before it is refused with the whole change
/// (credential, history, reset) left as it was, on the first entry too; a
/// commit made before the cutoff stays; a stale selection cannot make a
/// barred epoch active again; comparison epochs named after the written one
/// are not barred; the cutoff only rises, and a repeated raise is a no-op.
pub async fn test_history_write_cutoff_fences_commits(backend: &dyn StorageBackend) {
    let at = |offset_ms: i64| {
        chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
            + chrono::Duration::milliseconds(offset_ms)
    };
    let created = |key: u8, created_at| HistoryEpochDescriptor {
        created_at,
        ..descriptor(key)
    };
    let (owner, password) = profile_with_password(backend, "hist_cutoff").await;
    let old = created(61, at(-60_000));
    // Committed before the cutoff: it stays.
    assert!(
        change(backend, owner, &password, (b"p0", b"p1"), &[old], 0x61, 3)
            .await
            .unwrap()
    );
    let cutoff = at(-30_000);
    let ctx = || test_audit();
    assert_eq!(
        backend
            .raise_history_write_cutoff(cutoff, ctx())
            .await
            .unwrap(),
        cutoff
    );
    // Lost acknowledgement: the same raise again, and an older one, change
    // nothing and report the cutoff in force.
    assert_eq!(
        backend
            .raise_history_write_cutoff(cutoff, ctx())
            .await
            .unwrap(),
        cutoff
    );
    assert_eq!(
        backend
            .raise_history_write_cutoff(at(-90_000), ctx())
            .await
            .unwrap(),
        cutoff
    );
    let before = backend.get_password_history(owner).await.unwrap();

    let err = change(backend, owner, &password, (b"p1", b"p2"), &[old], 0x62, 3)
        .await
        .expect_err("an entry under a barred epoch");
    assert!(matches!(err, sid_core::Error::Fenced(_)), "{err:?}");
    assert_eq!(
        backend
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"p1",
        "the whole change was refused"
    );
    assert_eq!(backend.get_password_history(owner).await.unwrap(), before);

    // Under an epoch created after the cutoff, comparing with the barred
    // one, the change applies.
    let new = created(63, at(0));
    assert!(
        change(
            backend,
            owner,
            &password,
            (b"p1", b"p2"),
            &[new, old],
            0x63,
            3
        )
        .await
        .unwrap()
    );
    // A stale selection naming the barred epoch first cannot make it active
    // again.
    let err = change(
        backend,
        owner,
        &password,
        (b"p2", b"p3"),
        &[old, new],
        0x64,
        3,
    )
    .await
    .expect_err("reactivating a barred epoch");
    assert!(matches!(err, sid_core::Error::Fenced(_)), "{err:?}");
    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.active_epoch().map(|e| e.id), Some(new.id));

    // The first entry of a new owner is fenced too: no profile is created.
    let profile = create_test_profile("hist_cutoff_reg");
    let registration = NewRegistration::new(
        profile.clone(),
        sid_core::models::SignupIdentifier::Username(profile.username.as_deref().unwrap()),
        Some(Credential::new(
            profile.id,
            CredentialType::Opaque,
            b"r0".to_vec(),
            None,
        )),
    )
    .unwrap()
    .with_history(commit(profile.id, 0, &[created(65, at(-45_000))], 0x65, 1))
    .unwrap();
    let err = backend
        .register_profile(&registration, test_audit())
        .await
        .expect_err("a first entry under a barred epoch");
    assert!(matches!(err, sid_core::Error::Fenced(_)), "{err:?}");
    assert!(backend.get_profile(profile.id).await.unwrap().is_none());

    // And a reset: it stays verified, the old password stays.
    let (reset_owner, reset_password) = profile_with_password(backend, "hist_cutoff_reset").await;
    let reset = PasswordResetSession::new(reset_owner, "c@sid.example.com".into(), "hash".into());
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
    let replacement = Credential::new(reset_owner, CredentialType::Opaque, b"r1".to_vec(), None);
    let err = backend
        .complete_password_reset(
            reset.id,
            &replacement,
            Some(&commit(reset_owner, 0, &[old], 0x66, 1)),
            &test_session_end(),
            test_audit(),
        )
        .await
        .expect_err("a reset under a barred epoch");
    assert!(matches!(err, sid_core::Error::Fenced(_)), "{err:?}");
    let passwords = backend
        .get_credentials_by_profile(reset_owner, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].id, reset_password.id);
}

/// A raise of the cutoff and a commit racing it are serialized: the commit
/// either applied before the cutoff (and stays) or was refused whole; the
/// cutoff is in force either way.
pub async fn test_history_write_cutoff_races_a_commit(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_cutoff_race").await;
    let epoch = HistoryEpochDescriptor {
        created_at: chrono::DateTime::from_timestamp_micros(
            (Utc::now() - chrono::Duration::minutes(1)).timestamp_micros(),
        )
        .unwrap(),
        ..descriptor(71)
    };
    let cutoff = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let selection = [epoch];
    let (changed, raised) = tokio::join!(
        change(
            backend,
            owner,
            &password,
            (b"p0", b"p1"),
            &selection,
            0x71,
            3
        ),
        backend.raise_history_write_cutoff(cutoff, test_audit()),
    );
    assert!(raised.unwrap() >= cutoff);
    let stored = backend.get_credential(password.id).await.unwrap().unwrap();
    let history = backend.get_password_history(owner).await.unwrap();
    match changed {
        Ok(true) => {
            assert_eq!(stored.data.expose(), b"p1");
            assert_eq!(history.entries.len(), 1);
        }
        Err(sid_core::Error::Fenced(_)) => {
            assert_eq!(stored.data.expose(), b"p0");
            assert!(history.entries.is_empty() && history.epochs.is_empty());
        }
        other => panic!("{other:?}"),
    }
    // After the raise no commit under the epoch applies.
    let err = change(
        backend,
        owner,
        &password,
        (stored.data.expose(), b"p2"),
        &[epoch],
        0x72,
        3,
    )
    .await
    .expect_err("after the cutoff");
    assert!(matches!(err, sid_core::Error::Fenced(_)), "{err:?}");
}

/// History is written only for the credential's own profile.
pub async fn test_history_of_another_owner_is_refused(backend: &dyn StorageBackend) {
    let (owner, password) = profile_with_password(backend, "hist_owner").await;
    let (other, _) = profile_with_password(backend, "hist_other").await;
    let revision = backend.get_password_history(other).await.unwrap().revision;
    let err = backend
        .change_password(
            password.id,
            b"p0",
            &next(&password, b"p1"),
            Some(&commit(other, revision, &[descriptor(10)], 1, 1)),
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
