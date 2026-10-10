// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// Evidence written to the columns reads back unchanged.
#[test]
fn evidence_round_trips_through_its_columns() {
    for evidence in [
        PolicyEvidence::Unverified,
        PolicyEvidence::Verified {
            policy_version: 1,
            artifact: [9; 32],
        },
    ] {
        let (verified, version, artifact) = columns(&evidence).unwrap();
        assert_eq!(from_columns(verified, version, artifact).unwrap(), evidence);
    }
}

/// A verdict missing its policy or artifact, an artifact of another length,
/// a negative version or leftovers on an unverified row are refused: none of
/// them may read as verified, nor drop a recorded verdict silently.
#[test]
fn disagreeing_columns_are_refused() {
    for (verified, version, artifact) in [
        (true, None, Some(vec![1; 32])),
        (true, Some(1), None),
        (true, Some(1), Some(vec![1; 31])),
        (true, Some(-1), Some(vec![1; 32])),
        (false, Some(1), None),
        (false, None, Some(vec![1; 32])),
    ] {
        assert!(
            matches!(
                from_columns(verified, version, artifact.clone()),
                Err(SidError::Storage(_))
            ),
            "{verified} {version:?} {artifact:?}"
        );
    }
}

/// A policy version beyond the integer column is refused, never truncated.
#[test]
fn an_out_of_range_version_is_refused() {
    let evidence = PolicyEvidence::Verified {
        policy_version: u32::MAX,
        artifact: [0; 32],
    };
    assert!(matches!(columns(&evidence), Err(SidError::Validation(_))));
}
