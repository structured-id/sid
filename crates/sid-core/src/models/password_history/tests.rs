use super::*;

fn owner() -> ProfileId {
    ProfileId::generate()
}

fn epoch(owner: ProfileId, status: HistoryEpochUse) -> HistoryEpoch {
    HistoryEpoch {
        id: HistoryEpochId::generate(),
        owner,
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [7; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [9; 32],
        status,
        created_at: Utc::now(),
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
        created_at: Utc::now(),
    }
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
    let e = epoch(o, HistoryEpochUse::Active);
    HistoryCommit {
        owner: o,
        expected_revision: 0,
        new_epoch: Some(NewHistoryEpoch {
            epoch: e.clone(),
            key: WrappedHistoryKey(vec![1, 2, 3]),
        }),
        entries: vec![(e.id, [5; 32])],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        depth,
    }
}

/// Depth outside 1..=24, a commit without an entry, and a new epoch of
/// another owner are refused before anything is written.
#[test]
fn a_commit_that_cannot_be_stored_as_stated_is_refused() {
    assert!(commit(1).validate().is_ok());
    assert!(commit(24).validate().is_ok());
    assert!(commit(0).validate().is_err());
    assert!(commit(25).validate().is_err());

    let mut empty = commit(1);
    empty.entries.clear();
    assert!(empty.validate().is_err());

    let mut foreign = commit(1);
    foreign.new_epoch.as_mut().unwrap().epoch.owner = owner();
    assert!(foreign.validate().is_err());
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
