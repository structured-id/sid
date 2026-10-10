use super::*;

fn owner() -> ProfileId {
    ProfileId::generate()
}

/// A valid evaluator public key: the Pallas generator, compressed.
fn public_key() -> [u8; 32] {
    use group::{Curve, Group, GroupEncoding};
    pasta_curves::pallas::Point::generator()
        .to_affine()
        .to_bytes()
}

fn epoch(owner: ProfileId, status: HistoryEpochUse) -> HistoryEpoch {
    HistoryEpoch {
        id: HistoryEpochId::generate(),
        owner,
        suite: HistorySuite::PallasPoseidonV1,
        public_key: public_key(),
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [9; 32],
        status,
        // An epoch is created at microsecond precision, as every backend stores it.
        created_at: DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap(),
    }
}

fn entry(epoch: HistoryEpochId, seq: i64) -> HistoryEntry {
    HistoryEntry {
        epoch,
        seq,
        entry: [seq as u8; 32],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        created_at: DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap(),
    }
}

/// A first enrollment commits until its deadline, its expiry plus the finish
/// grace, and its cleanup is due only after that deadline and the replicas'
/// clock skew: a finish that took the operation before its expiry and is
/// still verifying its proof is never overtaken by the abort.
#[test]
fn an_enrollment_cleanup_waits_for_its_commit_deadline() {
    let expires_at = DateTime::from_timestamp_micros(1_790_000_000_000_000).unwrap();
    let deadline = commit_deadline(expires_at);
    assert_eq!(deadline, expires_at + ENROLLMENT_FINISH_GRACE);
    let work = EnrollmentAdmission {
        operation: Uuid::now_v7(),
        owner_domain: [1; 32],
        expires_at,
    }
    .work();
    assert!(
        work.not_before.expect("due at a set time") > deadline,
        "the cleanup is due after every commit it could overtake"
    );
}

/// A transferred history must accept its next write: a revision that cannot
/// move once more would refuse every later password of its owner.
#[test]
fn an_archive_whose_revision_cannot_advance_is_refused() {
    let o = owner();
    let active = epoch(o, HistoryEpochUse::Active);
    let archive = |revision| HistoryArchive {
        owner: o,
        revision,
        epochs: vec![active.clone()],
        entries: vec![entry(active.id, 1)],
    };
    assert!(archive(1).validate().is_ok());
    assert!(archive(i64::MAX - 1).validate().is_ok());
    assert!(archive(i64::MAX).validate().is_err());
    assert!(archive(0).validate().is_err());
}

/// The next accepted password takes the sequence after the newest entry: an
/// entry at the top of the range would refuse every later password of its
/// owner.
#[test]
fn an_archive_entry_whose_sequence_cannot_advance_is_refused() {
    let o = owner();
    let active = epoch(o, HistoryEpochUse::Active);
    let archive = |seq| HistoryArchive {
        owner: o,
        revision: 1,
        epochs: vec![active.clone()],
        entries: vec![entry(active.id, seq)],
    };
    assert!(archive(i64::MAX - 1).validate().is_ok());
    assert!(archive(i64::MAX).validate().is_err());
}

/// An epoch's KSF work is bounded like its memory: an archive whose epoch
/// would hold a checker for unbounded time is refused before import.
#[test]
fn an_archive_with_unbounded_ksf_work_is_refused() {
    let o = owner();
    let mut active = epoch(o, HistoryEpochUse::Active);
    let archive = |active: &HistoryEpoch| HistoryArchive {
        owner: o,
        revision: 1,
        epochs: vec![active.clone()],
        entries: vec![entry(active.id, 1)],
    };
    active.ksf.passes = MAX_HISTORY_KSF_PASSES;
    assert!(archive(&active).validate().is_ok());
    active.ksf.passes = MAX_HISTORY_KSF_PASSES + 1;
    assert!(archive(&active).validate().is_err());
}

/// An epoch's public key must be a usable Pallas point: one that does not
/// decode, or the identity, would be imported and then refuse every later
/// password operation of its owner. The import refuses it instead, in the
/// credential service's archive and in the evaluator's.
#[test]
fn an_archive_with_an_unusable_public_key_is_refused() {
    let o = owner();
    let mut active = epoch(o, HistoryEpochUse::Active);
    let history = |active: &HistoryEpoch| HistoryArchive {
        owner: o,
        revision: 1,
        epochs: vec![active.clone()],
        entries: vec![entry(active.id, 1)],
    };
    let domain = [4; 32];
    let keys = |active: &HistoryEpoch| KeyArchive {
        owner_domain: domain,
        epochs: vec![NewKeyEpoch {
            epoch: KeyEpoch {
                id: active.id,
                owner_domain: domain,
                suite: active.suite,
                public_key: active.public_key,
                ksf: active.ksf,
                ksf_salt: active.ksf_salt,
                status: active.status,
                created_at: active.created_at,
            },
            key: sealed_key(active.id, &domain),
        }],
        replaced: Vec::new(),
    };
    assert!(history(&active).validate().is_ok());
    assert!(keys(&active).validate().is_ok());
    // The identity's compressed form, and bytes that are no point at all.
    for unusable in [[0; 32], [0xff; 32]] {
        active.public_key = unusable;
        assert!(history(&active).validate().is_err(), "{unusable:?}");
        assert!(keys(&active).validate().is_err(), "{unusable:?}");
    }
}

/// A history key sealed for `epoch` of `owner_domain`, as the evaluator
/// seals it: the binding is checked, the ciphertext is opaque here.
fn sealed_key(epoch: HistoryEpochId, owner_domain: &[u8; 32]) -> WrappedHistoryKey {
    let field = sid_keys::EncryptedField {
        key_version: 1,
        nonce: [5; 12],
        context: history_key_context(epoch, owner_domain),
        ciphertext: vec![6; 48],
    };
    WrappedHistoryKey(field.to_bytes())
}

/// The active epoch comes first, compare-only epochs that still retain an
/// entry follow, and an emptied or retired epoch is not required: a password
/// is never compared in a domain that holds nothing, and never skips one
/// that does.
#[test]
fn required_epochs_are_the_active_one_then_those_still_holding_entries() {
    let o = owner();
    let active = epoch(o, HistoryEpochUse::Active);
    let rotated = epoch(o, HistoryEpochUse::CompareOnly);
    let emptied = epoch(o, HistoryEpochUse::CompareOnly);
    let retired = epoch(o, HistoryEpochUse::Retired);
    let history = PasswordHistory {
        revision: 3,
        epochs: vec![
            rotated.clone(),
            retired.clone(),
            active.clone(),
            emptied.clone(),
        ],
        entries: vec![
            entry(rotated.id, 1),
            entry(retired.id, 1),
            entry(active.id, 2),
        ],
    };
    let ids: Vec<_> = history.required_epochs().iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![active.id, rotated.id]);
    assert_eq!(history.active_epoch().map(|e| e.id), Some(active.id));
    assert_eq!(history.entries_of(rotated.id).count(), 1);
}

/// An owner without an active epoch (first installation, or every epoch
/// rotated out) requires no comparison until one is created.
#[test]
fn an_owner_without_an_active_epoch_has_none_required() {
    let history = PasswordHistory::default();
    assert!(history.active_epoch().is_none());
    assert!(history.required_epochs().is_empty());
}

fn commit(depth: u32) -> HistoryCommit {
    let o = owner();
    let active = epoch(o, HistoryEpochUse::Active).descriptor();
    let replaced = epoch(o, HistoryEpochUse::CompareOnly).descriptor();
    HistoryCommit {
        owner: o,
        expected_revision: 0,
        epochs: vec![active, replaced],
        entries: vec![(active.id, [5; 32])],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        depth,
        max_age_days: 0,
    }
}

/// Age drops nothing unless set, and then everything accepted before the
/// given number of days ago.
#[test]
fn age_retention_is_off_by_default() {
    let now = Utc::now();
    let mut c = commit(1);
    assert_eq!(c.expires_before(now), None);
    c.max_age_days = 183;
    assert_eq!(
        c.expires_before(now),
        Some(now - chrono::Duration::days(183))
    );
}

/// Depth outside 1..=24, a commit without an entry, without its epochs or
/// with more than a proof holds, an epoch named twice or with an invalid KSF,
/// and an entry outside the selected active epoch are refused before
/// anything is written.
#[test]
fn a_commit_that_cannot_be_stored_as_stated_is_refused() {
    assert!(commit(1).validate().is_ok());
    assert!(commit(24).validate().is_ok());
    assert!(commit(0).validate().is_err());
    assert!(commit(25).validate().is_err());

    let mut empty = commit(1);
    empty.entries.clear();
    assert!(empty.validate().is_err());

    let mut unnamed = commit(1);
    unnamed.epochs.clear();
    assert!(unnamed.validate().is_err());

    let mut crowded = commit(1);
    while crowded.epochs.len() <= MAX_HISTORY_DOMAINS {
        let more = epoch(crowded.owner, HistoryEpochUse::CompareOnly).descriptor();
        crowded.epochs.push(more);
    }
    assert!(crowded.validate().is_err());

    let mut twice = commit(1);
    twice.epochs[1] = twice.epochs[0];
    assert!(twice.validate().is_err());

    let mut weak = commit(1);
    weak.epochs[1].ksf.memory_kib = 0;
    assert!(weak.validate().is_err());

    let mut misplaced = commit(1);
    misplaced.entries[0].0 = misplaced.epochs[1].id;
    assert!(misplaced.validate().is_err());
}

#[test]
fn stored_names_round_trip() {
    for status in [
        HistoryEpochUse::Active,
        HistoryEpochUse::CompareOnly,
        HistoryEpochUse::Retired,
    ] {
        assert_eq!(HistoryEpochUse::parse(status.as_str()).unwrap(), status);
    }
    let suite = HistorySuite::PallasPoseidonV1;
    assert_eq!(HistorySuite::parse(suite.as_str()).unwrap(), suite);
    assert!(HistorySuite::parse("pallas-poseidon-v0").is_err());
    assert!(HistoryEpochUse::parse("frozen").is_err());
}

/// The sealed key never appears in debug output or logs.
#[test]
fn a_wrapped_key_is_redacted_in_debug() {
    let key = WrappedHistoryKey(vec![0xde, 0xad]);
    assert_eq!(format!("{key:?}"), "WrappedHistoryKey([REDACTED])");
}
