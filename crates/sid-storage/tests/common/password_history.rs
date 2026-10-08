// SPDX-License-Identifier: AGPL-3.0-only
//! Password history contract, run against
//! every backend: epochs are prepared once per owner, entries are written only
//! with the credential that earned them, a commit made against a stale read
//! writes nothing, and retention keeps the newest accepted passwords.

use chrono::Utc;
use sid_core::models::{
    Credential, CredentialData, CredentialType, HistoryCommit, HistoryEpoch, HistoryEpochId,
    HistoryEpochUse, HistoryEvidence, HistoryKsf, HistorySuite, NewHistoryEpoch, NewRegistration,
    PasswordResetSession, ProfileId, WrappedHistoryKey,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit, test_session_end};

fn new_epoch(owner: ProfileId, key: u8) -> NewHistoryEpoch {
    NewHistoryEpoch {
        epoch: HistoryEpoch {
            id: HistoryEpochId::generate(),
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
        key: WrappedHistoryKey(vec![key; 48]),
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
    new.zkpp_verified = true;
    new.policy_version = Some(1);
    new
}

/// An owner without history reads as revision 0 with nothing in it: the
/// first commit is made against 0.
pub async fn test_history_is_empty_until_written(backend: &dyn StorageBackend) {
    let (owner, _) = profile_with_password(backend, "hist_empty").await;
    let history = backend.get_password_history(owner).await.unwrap();
    assert_eq!(history.revision, 0);
    assert!(history.epochs.is_empty() && history.entries.is_empty());
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
