// SPDX-License-Identifier: AGPL-3.0-only
//! Pairwise service bindings in CoordiNode: one `SidBinding` per (profile,
//! scope), allocated on first use with the profile's next index.
//!
//! An allocation or import takes the profile's `binding_turn`, so concurrent
//! first uses of one profile apply one after the other: a scope gets one
//! binding and an index never belongs to two bindings of a profile.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::{BindingId, BindingScope, MutationContext, ProfileId, ServiceBinding};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_int, get_text, get_time,
    get_uuid, key, profile::profile_value, time, uuid,
};

const BINDING: &str = "b.binding_id AS binding_id, b.profile_id AS profile_id, b.scope AS scope,
    b.binding_index AS binding_index, b.created_at AS created_at,
    b.last_used_at AS last_used_at";

fn binding(row: &Row) -> SidResult<ServiceBinding> {
    let index = get_int(row, "binding_index")?;
    Ok(ServiceBinding {
        binding_id: BindingId::from_uuid(get_uuid(row, "binding_id")?)
            .map_err(|e| SidError::Storage(format!("binding id: {e}")))?,
        profile_id: ProfileId::from_uuid(get_uuid(row, "profile_id")?)
            .map_err(|e| SidError::Storage(format!("binding profile: {e}")))?,
        scope: BindingScope::try_from(get_text(row, "scope")?)
            .map_err(|e| SidError::Storage(format!("binding scope: {e}")))?,
        binding_index: u32::try_from(index)
            .map_err(|_| SidError::Storage(format!("binding index {index}")))?,
        created_at: get_time(row, "created_at")?,
        last_used_at: get_time(row, "last_used_at")?,
    })
}

fn pair(profile: ProfileId, scope: &BindingScope) -> SidResult<Value> {
    key(&[profile.as_uuid().as_bytes(), scope.as_str().as_bytes()])
}

fn slot(profile: ProfileId, index: u32) -> SidResult<Value> {
    key(&[profile.as_uuid().as_bytes(), &index.to_be_bytes()])
}

fn find(
    tx: &Statements<'_>,
    profile: ProfileId,
    scope: &BindingScope,
) -> SidResult<Option<ServiceBinding>> {
    let rows = tx.run(
        &format!("MATCH (b:SidBinding) WHERE b.pair = $pair RETURN {BINDING}"),
        Params::default().with("pair", pair(profile, scope)?),
    )?;
    rows.first().map(binding).transpose()
}

fn list(tx: &Statements<'_>, profile: ProfileId) -> SidResult<Vec<ServiceBinding>> {
    let rows = tx.run(
        &format!("MATCH (b:SidBinding) WHERE b.profile_id = $id RETURN {BINDING}"),
        Params::default().with("id", profile_value(profile)),
    )?;
    let mut bindings = rows.iter().map(binding).collect::<SidResult<Vec<_>>>()?;
    bindings.sort_by_key(|b| b.binding_index);
    Ok(bindings)
}

/// Take `profile`'s turn at allocating bindings; `NotFound` when it is gone.
/// The unique keys alone would refuse a second allocation of a scope or an
/// index as a `Conflict` instead of answering it with the committed binding.
fn binding_turn(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (p:SidProfile) WHERE p.id = $id
         SET p.binding_turn = coalesce(p.binding_turn, 0) + 1
         RETURN p.id AS id",
        Params::default().with("id", profile_value(profile)),
    )?;
    if rows.is_empty() {
        return Err(SidError::NotFound(format!("profile {profile}")));
    }
    Ok(())
}

fn insert(tx: &Statements<'_>, b: &ServiceBinding) -> SidResult<()> {
    tx.run(
        "CREATE (b:SidBinding {binding_id: $binding_id, profile_id: $profile_id, scope: $scope,
            pair: $pair, slot: $slot, binding_index: $binding_index,
            created_at: $created_at, last_used_at: $last_used_at})",
        Params::default()
            .with("binding_id", uuid(b.binding_id.as_uuid()))
            .with("profile_id", profile_value(b.profile_id))
            .with("scope", Value::String(b.scope.as_str().into()))
            .with("pair", pair(b.profile_id, &b.scope)?)
            .with("slot", slot(b.profile_id, b.binding_index)?)
            .with("binding_index", Value::Int(i64::from(b.binding_index)))
            .with("created_at", time(b.created_at))
            .with("last_used_at", time(b.last_used_at)),
    )?;
    Ok(())
}

/// Delete in `tx` the bindings of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    tx.run(
        "MATCH (b:SidBinding) WHERE b.profile_id = $id DETACH DELETE b",
        Params::default().with("id", profile_value(profile)),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    /// Touch the existing binding, or allocate one with the profile's next
    /// index.
    pub(super) async fn service_binding(
        &self,
        profile: ProfileId,
        scope: &BindingScope,
        ctx: MutationContext,
    ) -> SidResult<ServiceBinding> {
        let scope = scope.clone();
        self.transaction(move |tx| {
            let now = Utc::now();
            if let Some(mut existing) = find(tx, profile, &scope)? {
                // Recording the use is not a change of the binding: no audit.
                tx.run(
                    "MATCH (b:SidBinding) WHERE b.pair = $pair SET b.last_used_at = $now",
                    Params::default()
                        .with("pair", pair(profile, &scope)?)
                        .with("now", time(now)),
                )?;
                existing.last_used_at = now;
                return Ok(Decision::Commit(existing));
            }
            binding_turn(tx, profile)?;
            let next = list(tx, profile)?
                .last()
                .map(|b| {
                    b.binding_index
                        .checked_add(1)
                        .ok_or_else(|| SidError::Storage("binding indexes exhausted".into()))
                })
                .transpose()?
                .unwrap_or(0);
            let allocated = ServiceBinding {
                binding_id: BindingId::generate(),
                profile_id: profile,
                scope: scope.clone(),
                binding_index: next,
                created_at: now,
                last_used_at: now,
            };
            insert(tx, &allocated)?;
            finalize(
                tx,
                &format!("service_binding:{}", allocated.binding_id),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(allocated))
        })
        .await
    }

    pub(super) async fn find_service_binding(
        &self,
        profile: ProfileId,
        scope: &BindingScope,
    ) -> SidResult<Option<ServiceBinding>> {
        let scope = scope.clone();
        self.read(move |tx| find(tx, profile, &scope)).await
    }

    pub(super) async fn list_service_bindings(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<ServiceBinding>> {
        self.read(move |tx| list(tx, profile)).await
    }

    /// Store an exported binding with its id and index. The same binding
    /// again is a no-op; one that collides with a stored binding by id,
    /// scope or index is a `Conflict` and writes nothing.
    pub(super) async fn import_service_binding(
        &self,
        imported: &ServiceBinding,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let imported = imported.clone();
        self.transaction(move |tx| {
            binding_turn(tx, imported.profile_id)?;
            let rows = tx.run(
                &format!("MATCH (b:SidBinding) WHERE b.binding_id = $id RETURN {BINDING}"),
                Params::default().with("id", uuid(imported.binding_id.as_uuid())),
            )?;
            if let Some(stored) = rows.first().map(binding).transpose()? {
                if stored.profile_id == imported.profile_id
                    && stored.scope == imported.scope
                    && stored.binding_index == imported.binding_index
                {
                    return Ok(Decision::Abandon(false));
                }
                return Err(collision(&imported));
            }
            let taken = list(tx, imported.profile_id)?
                .into_iter()
                .any(|b| b.scope == imported.scope || b.binding_index == imported.binding_index);
            if taken {
                return Err(collision(&imported));
            }
            insert(tx, &imported)?;
            finalize(
                tx,
                &format!("service_binding:{}", imported.binding_id),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}

fn collision(imported: &ServiceBinding) -> SidError {
    SidError::Conflict(format!(
        "binding {} collides with a stored binding",
        imported.binding_id
    ))
}
