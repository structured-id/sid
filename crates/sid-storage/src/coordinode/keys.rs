// SPDX-License-Identifier: AGPL-3.0-only
//! Key version parameters in CoordiNode: one node per version, written once
//! and never changed. Each key custody keeps its versions under its own
//! label.

use coordinode_core::graph::types::Value;
use sid_core::models::MutationContext;
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Statements, finalize, get_bytes, get_int, get_text,
};

/// The label of the field-encryption key versions.
const FIELD: &str = "SidKeyVersion";

/// The label of the history evaluator's key versions: its own key custody.
pub(super) const HISTORY: &str = "SidHistoryKeyVersion";

/// The versions under `label`, oldest first, read in `tx`.
pub(super) fn list(tx: &Statements<'_>, label: &str) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
    let rows = tx.run(
        &format!(
            "MATCH (k:{label}) RETURN k.version AS version, k.salt AS salt,
                k.algorithm AS algorithm, k.context AS context"
        ),
        Params::default(),
    )?;
    let mut versions = rows
        .iter()
        .map(|row| {
            let version = get_int(row, "version")?;
            let version = u32::try_from(version)
                .map_err(|_| SidError::Storage(format!("key version {version}")))?;
            crate::key_versions::key_version_params(
                version,
                get_bytes(row, "salt")?,
                &get_text(row, "algorithm")?,
                get_text(row, "context")?,
            )
        })
        .collect::<SidResult<Vec<_>>>()?;
    versions.sort_by_key(|v| v.version);
    Ok(versions)
}

/// Store `params` under `label` unless its version exists: `false` then,
/// and nothing changes. The chain entry `chain` records the insert.
pub(super) fn insert(
    tx: &Statements<'_>,
    label: &str,
    params: &sid_keys::KeyVersionParams,
    chain: &str,
    ctx: MutationContext,
) -> SidResult<Decision<bool>> {
    let version = Value::Int(i64::from(params.version));
    let found = tx.run(
        &format!("MATCH (k:{label}) WHERE k.version = $version RETURN k.version AS version"),
        Params::default().with("version", version.clone()),
    )?;
    if !found.is_empty() {
        return Ok(Decision::Abandon(false));
    }
    tx.run(
        &format!(
            "CREATE (k:{label} {{version: $version, salt: $salt, algorithm: $algorithm,
                context: $context}})"
        ),
        Params::default()
            .with("version", version)
            .with("salt", Value::Binary(params.salt.clone()))
            .with(
                "algorithm",
                Value::String(crate::key_versions::key_derivation_name(params.algorithm).into()),
            )
            .with("context", Value::String(params.context.clone())),
    )?;
    finalize(tx, chain, ctx)?;
    Ok(Decision::Commit(true))
}

impl CoordinodeBackend {
    pub(super) async fn list_key_versions(&self) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
        self.read(|tx| list(tx, FIELD)).await
    }

    pub(super) async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let params = params.clone();
        let chain = format!("key_version:{}", params.version);
        self.transaction(move |tx| insert(tx, FIELD, &params, &chain, ctx.clone()))
            .await
    }
}
