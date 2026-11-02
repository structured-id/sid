// SPDX-License-Identifier: AGPL-3.0-only
//! Password history through the operations outside the credential store
//! capability, run against every backend: archive transfer, the first
//! history of a registration, a password reset's commit, age retention over
//! imported entries and the write cutoff fencing registrations and resets.
//! The capability's own scenarios are `sid_plugin::conformance::credential_store`.

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
        public_key: super::history_public_key(key),
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
        max_age_days: 0,
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

/// Age retention, measured from each entry's acceptance and decided per
/// owner: a commit drops that owner's entries accepted more than
/// `max_age_days` ago, keeps younger ones (several sharing one epoch
/// included) and always keeps its own, the newest. Another owner's history
/// is untouched, a commit without age drops nothing, and a commit that loses
/// its revision race drops nothing either.
pub async fn test_history_age_retention(backend: &dyn StorageBackend) {
    use sid_core::models::{HistoryArchive, HistoryEntry, HistoryEpoch};
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let days = |n: i64| now - chrono::Duration::days(n);
    let seeded = |name: &'static str, key: u8, ages: Vec<i64>| async move {
        let (owner, password) = profile_with_password(backend, name).await;
        let d = HistoryEpochDescriptor {
            created_at: days(400),
            ..descriptor(key)
        };
        let epoch = HistoryEpoch {
            id: d.id,
            owner,
            suite: d.suite,
            public_key: d.public_key,
            ksf: d.ksf,
            ksf_salt: d.ksf_salt,
            status: HistoryEpochUse::Active,
            created_at: d.created_at,
        };
        let count = ages.len() as i64;
        let entries = ages
            .into_iter()
            .enumerate()
            .map(|(i, age)| HistoryEntry {
                epoch: d.id,
                seq: count - i as i64,
                entry: [key.wrapping_add(i as u8); 32],
                evidence: HistoryEvidence {
                    operation: Uuid::now_v7(),
                    policy_version: 1,
                },
                created_at: days(age),
            })
            .collect();
        let archive = HistoryArchive {
            owner,
            revision: count,
            epochs: vec![epoch],
            entries,
        };
        assert!(
            backend
                .import_password_history(&archive, test_audit())
                .await
                .unwrap()
        );
        (owner, password, d)
    };
    let seqs = async |owner| -> Vec<i64> {
        let mut seqs: Vec<i64> = backend
            .get_password_history(owner)
            .await
            .unwrap()
            .entries
            .iter()
            .map(|e| e.seq)
            .collect();
        seqs.sort_unstable();
        seqs
    };
    let aged = |owner, revision, epoch, max_age_days| HistoryCommit {
        max_age_days,
        ..commit(owner, revision, &[epoch], 90, 24)
    };

    // Entries 100 and 300 days old under one epoch: a six-month commit drops
    // only the older; the new one is seq 3.
    let (mine, password, epoch) = seeded("hist_age_mine", 40, vec![100, 300]).await;
    let (theirs, _, _) = seeded("hist_age_theirs", 50, vec![300]).await;
    assert!(
        backend
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&aged(mine, 2, epoch, 183)),
                test_audit(),
            )
            .await
            .unwrap()
    );
    assert_eq!(seqs(mine).await, vec![2, 3]);
    assert_eq!(seqs(theirs).await, vec![1], "another owner is untouched");

    // A commit whose revision moved drops nothing.
    let stale = backend
        .change_password(
            password.id,
            b"p1",
            &next(&password, b"p2"),
            Some(&aged(mine, 2, epoch, 1)),
            test_audit(),
        )
        .await
        .unwrap();
    assert!(!stale);
    assert_eq!(seqs(mine).await, vec![2, 3]);

    // Without age every entry depth keeps stays, however old.
    let (kept, kept_password, kept_epoch) = seeded("hist_age_kept", 60, vec![300]).await;
    assert!(
        backend
            .change_password(
                kept_password.id,
                b"p0",
                &next(&kept_password, b"p1"),
                Some(&aged(kept, 1, kept_epoch, 0)),
                test_audit(),
            )
            .await
            .unwrap()
    );
    assert_eq!(seqs(kept).await, vec![1, 2]);

    // Every entry older than the limit: only the new one remains.
    let (alone, alone_password, alone_epoch) = seeded("hist_age_alone", 70, vec![200, 250]).await;
    assert!(
        backend
            .change_password(
                alone_password.id,
                b"p0",
                &next(&alone_password, b"p1"),
                Some(&aged(alone, 2, alone_epoch, 183)),
                test_audit(),
            )
            .await
            .unwrap()
    );
    assert_eq!(seqs(alone).await, vec![3], "the newest always stays");
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

/// The history write cutoff fences the history a registration or a reset
/// commits: under an epoch created before it the registration creates no
/// profile, and the reset stays verified with the old password kept. Raises
/// the store-wide cutoff.
pub async fn test_history_write_cutoff_fences_registration_and_reset(backend: &dyn StorageBackend) {
    let at = |offset_ms: i64| {
        chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
            + chrono::Duration::milliseconds(offset_ms)
    };
    let created = |key: u8, created_at| HistoryEpochDescriptor {
        created_at,
        ..descriptor(key)
    };
    let old = created(61, at(-60_000));
    let cutoff = at(-30_000);
    assert_eq!(
        backend
            .raise_history_write_cutoff(cutoff, test_audit())
            .await
            .unwrap(),
        cutoff
    );

    // The first entry of a new owner is fenced: no profile is created.
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
