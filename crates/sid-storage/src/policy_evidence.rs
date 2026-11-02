// SPDX-License-Identifier: AGPL-3.0-only
//! A password's policy evidence in its credential columns: `zkpp_verified`,
//! `policy_version` and `zkpp_artifact`. Both backends store and read it here.

use sid_core::models::PolicyEvidence;
use sid_core::{Error as SidError, Result as SidResult};

/// The column values of `evidence`: verified, policy version, artifact.
pub(crate) type Columns = (bool, Option<i32>, Option<Vec<u8>>);

/// The column values of `evidence`; a policy version beyond the column is
/// refused.
pub(crate) fn columns(evidence: &PolicyEvidence) -> SidResult<Columns> {
    match *evidence {
        PolicyEvidence::Unverified => Ok((false, None, None)),
        PolicyEvidence::Verified {
            policy_version,
            artifact,
        } => Ok((
            true,
            Some(
                i32::try_from(policy_version)
                    .map_err(|_| SidError::Validation("policy version out of range".into()))?,
            ),
            Some(artifact.to_vec()),
        )),
    }
}

/// The evidence stored in these columns. A row claiming a verdict without
/// the policy and artifact that gave it, or the reverse, is refused rather
/// than read as verified or silently as unverified.
pub(crate) fn from_columns(
    verified: bool,
    policy_version: Option<i32>,
    artifact: Option<Vec<u8>>,
) -> SidResult<PolicyEvidence> {
    match (verified, policy_version, artifact) {
        (false, None, None) => Ok(PolicyEvidence::Unverified),
        (true, Some(version), Some(artifact)) => Ok(PolicyEvidence::Verified {
            policy_version: u32::try_from(version)
                .map_err(|_| SidError::Storage("column policy_version: negative".into()))?,
            artifact: artifact
                .try_into()
                .map_err(|_| SidError::Storage("column zkpp_artifact: not 32 bytes".into()))?,
        }),
        _ => Err(SidError::Storage(
            "credential policy evidence columns disagree".into(),
        )),
    }
}

#[cfg(test)]
mod tests;
