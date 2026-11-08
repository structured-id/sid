// SPDX-License-Identifier: AGPL-3.0-only
//! The history evaluator's key store in CoordiNode: its own labels in the
//! host's database, apart from the credential service's records.
//!
//! One `SidHistoryOwner` node per owner domain carries the owner's purge
//! fence and recorded lifecycle; every write for an owner takes its `turn`,
//! so an owner's writes (first epoch, rotation, preparation, cleanup, purge,
//! import) apply one after another. Epochs are `SidHistoryKeyEpoch` nodes,
//! an operation's use of an epoch a `SidHistoryKeyUse`, an aborted first
//! enrollment's fence a `SidHistoryAbandoned`.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::{
    AbandonedEnrollment, AuditEntry, EnrollmentCleanup, HistoryEpochId, HistoryEpochUse,
    HistoryKsf, HistoryPreparation, HistorySuite, KeyArchive, KeyEpoch, KeyEpochs, KeyLifecycle,
    KeyStoreRecords, KeyUse, MutationContext, NewKeyEpoch, PurgedOwner, WrappedHistoryKey,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::history_keys::HistoryKeyStore;
use uuid::Uuid;

use super::credential::{Cutoff, fixed32, raise_cutoff, read_cutoff};
use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, document, finalize, get_bytes,
    get_document, get_int, get_opt_time, get_opt_uuid, get_text, get_time, get_uuid, keys, time,
    uuid,
};

const EPOCH: &str = "e.id AS id, e.owner_domain AS owner_domain, e.suite AS suite,
    e.public_key AS public_key, e.ksf_memory_kib AS ksf_memory_kib, e.ksf_passes AS ksf_passes,
    e.ksf_lanes AS ksf_lanes, e.ksf_salt AS ksf_salt, e.status AS status,
    e.created_at AS created_at, e.created_by AS created_by, e.replaced_at AS replaced_at";

/// The audit chain of store-wide changes (cutoff, compaction, versions).
const STORE_CHAIN: &str = "history_keys";

/// The history evaluator's store over a [`CoordinodeBackend`]'s database.
#[derive(Clone)]
pub struct CoordinodeHistoryKeyStore {
    backend: CoordinodeBackend,
}

impl CoordinodeBackend {
    /// The history evaluator's key store in this database, for a host that
    /// runs the evaluator in the same process.
    pub fn history_keys(&self) -> CoordinodeHistoryKeyStore {
        CoordinodeHistoryKeyStore {
            backend: self.clone(),
        }
    }
}

/// One stored epoch with what only the store records about it.
struct Stored {
    epoch: KeyEpoch,
    created_by: Option<Uuid>,
    replaced_at: Option<i64>,
}

/// An owner's state, as its turn reads it.
struct Owner {
    purged: bool,
    /// The recorded lifecycle: its revision and live set.
    lifecycle: Option<(i64, Vec<HistoryEpochId>)>,
}

fn domain_value(domain: &[u8; 32]) -> Value {
    Value::Binary(domain.to_vec())
}

fn owner_chain(domain: &[u8; 32]) -> String {
    let mut chain = String::with_capacity(13 + 64);
    chain.push_str("history_keys:");
    for b in domain {
        chain.push_str(&format!("{b:02x}"));
    }
    chain
}

fn audited(tx: &Statements<'_>, chain: &str, audit: AuditEntry) -> SidResult<()> {
    finalize(tx, chain, MutationContext::from(audit))
}

fn stored(row: &Row) -> SidResult<Stored> {
    let positive = |name: &str| -> SidResult<u32> {
        let value = get_int(row, name)?;
        u32::try_from(value)
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| SidError::Storage(format!("{name}: not positive")))
    };
    let owner_domain: [u8; 32] = get_bytes(row, "owner_domain")?
        .try_into()
        .map_err(|_| SidError::Storage("owner domain is not 32 bytes".into()))?;
    let replaced_at = match row.get("replaced_at") {
        None | Some(Value::Null) => None,
        Some(_) => Some(get_int(row, "replaced_at")?),
    };
    Ok(Stored {
        epoch: KeyEpoch {
            id: HistoryEpochId(get_uuid(row, "id")?),
            owner_domain,
            suite: HistorySuite::parse(&get_text(row, "suite")?)?,
            public_key: fixed32(row, "public_key")?,
            ksf: HistoryKsf {
                memory_kib: positive("ksf_memory_kib")?,
                passes: positive("ksf_passes")?,
                lanes: positive("ksf_lanes")?,
            },
            ksf_salt: fixed32(row, "ksf_salt")?,
            status: HistoryEpochUse::parse(&get_text(row, "status")?)?,
            created_at: get_time(row, "created_at")?,
        },
        created_by: get_opt_uuid(row, "created_by")?,
        replaced_at,
    })
}

/// Every epoch of `domain`, retired ones too, by creation.
fn owner_epochs(tx: &Statements<'_>, domain: &[u8; 32]) -> SidResult<Vec<Stored>> {
    let rows = tx.run(
        &format!("MATCH (e:SidHistoryKeyEpoch) WHERE e.owner_domain = $d RETURN {EPOCH}"),
        Params::default().with("d", domain_value(domain)),
    )?;
    let mut epochs = rows.iter().map(stored).collect::<SidResult<Vec<_>>>()?;
    epochs.sort_by_key(|s| (s.epoch.created_at, s.epoch.id));
    Ok(epochs)
}

fn not_retired(epochs: Vec<Stored>) -> Vec<KeyEpoch> {
    epochs
        .into_iter()
        .map(|s| s.epoch)
        .filter(|e| e.status != HistoryEpochUse::Retired)
        .collect()
}

/// Take `domain`'s turn, creating its owner node on the first write.
fn owner_turn(tx: &Statements<'_>, domain: &[u8; 32]) -> SidResult<Owner> {
    let params = Params::default().with("d", domain_value(domain));
    let rows = tx.run(
        "MATCH (o:SidHistoryOwner) WHERE o.domain = $d
         SET o.turn = o.turn + 1
         RETURN o.purged_at AS purged_at, o.revision AS revision, o.live AS live",
        params.clone(),
    )?;
    let Some(row) = rows.first() else {
        // Concurrent first writers meet on the unique domain.
        tx.run(
            "CREATE (o:SidHistoryOwner {domain: $d, turn: 1, purged_at: null, revision: null,
                live: null})",
            params,
        )?;
        return Ok(Owner {
            purged: false,
            lifecycle: None,
        });
    };
    let lifecycle = match row.get("revision") {
        None | Some(Value::Null) => None,
        Some(_) => Some((get_int(row, "revision")?, get_document(row, "live")?)),
    };
    Ok(Owner {
        purged: get_opt_time(row, "purged_at")?.is_some(),
        lifecycle,
    })
}

/// Refuse a purged owner: nothing is created, imported or selected for it.
fn refuse_purged(owner: &Owner) -> SidResult<()> {
    if owner.purged {
        return Err(SidError::Fenced("the history owner was deleted".into()));
    }
    Ok(())
}

fn require_active(new: &NewKeyEpoch) -> SidResult<()> {
    if new.epoch.status != HistoryEpochUse::Active {
        return Err(SidError::Validation(
            "a prepared history epoch is active".into(),
        ));
    }
    Ok(())
}

fn abandoned_domain(tx: &Statements<'_>, operation: Uuid) -> SidResult<Option<Vec<u8>>> {
    let rows = tx.run(
        "MATCH (a:SidHistoryAbandoned) WHERE a.operation = $op RETURN a.owner_domain AS d",
        Params::default().with("op", uuid(&operation)),
    )?;
    rows.first().map(|row| get_bytes(row, "d")).transpose()
}

fn insert_epoch(
    tx: &Statements<'_>,
    new: &NewKeyEpoch,
    created_by: Option<Uuid>,
    replaced_at: Option<i64>,
) -> SidResult<()> {
    let e = &new.epoch;
    tx.run(
        "CREATE (e:SidHistoryKeyEpoch {id: $id, owner_domain: $d, suite: $suite,
            public_key: $public_key, wrapped_key: $wrapped_key, ksf_memory_kib: $memory,
            ksf_passes: $passes, ksf_lanes: $lanes, ksf_salt: $salt, status: $status,
            created_at: $created_at, created_by: $created_by, replaced_at: $replaced_at})",
        Params::default()
            .with("id", uuid(&e.id.0))
            .with("d", domain_value(&e.owner_domain))
            .with("suite", Value::String(e.suite.as_str().into()))
            .with("public_key", Value::Binary(e.public_key.to_vec()))
            .with("wrapped_key", Value::Binary(new.key.0.clone()))
            .with("memory", Value::Int(i64::from(e.ksf.memory_kib)))
            .with("passes", Value::Int(i64::from(e.ksf.passes)))
            .with("lanes", Value::Int(i64::from(e.ksf.lanes)))
            .with("salt", Value::Binary(e.ksf_salt.to_vec()))
            .with("status", Value::String(e.status.as_str().into()))
            .with("created_at", time(e.created_at))
            .with("created_by", created_by.as_ref().map_or(Value::Null, uuid))
            .with("replaced_at", replaced_at.map_or(Value::Null, Value::Int)),
    )?;
    Ok(())
}

fn set_status(tx: &Statements<'_>, id: HistoryEpochId, status: HistoryEpochUse) -> SidResult<()> {
    tx.run(
        "MATCH (e:SidHistoryKeyEpoch) WHERE e.id = $id SET e.status = $status",
        Params::default()
            .with("id", uuid(&id.0))
            .with("status", Value::String(status.as_str().into())),
    )?;
    Ok(())
}

/// The owner's uses: (operation, epoch, expiry).
fn owner_uses(
    tx: &Statements<'_>,
    domain: &[u8; 32],
) -> SidResult<Vec<(Uuid, HistoryEpochId, DateTime<Utc>)>> {
    let rows = tx.run(
        "MATCH (u:SidHistoryKeyUse) WHERE u.owner_domain = $d
         RETURN u.operation AS operation, u.epoch_id AS epoch_id, u.expires_at AS expires_at",
        Params::default().with("d", domain_value(domain)),
    )?;
    rows.iter()
        .map(|row| {
            Ok((
                get_uuid(row, "operation")?,
                HistoryEpochId(get_uuid(row, "epoch_id")?),
                get_time(row, "expires_at")?,
            ))
        })
        .collect()
}

fn delete_use(tx: &Statements<'_>, operation: Uuid, epoch: HistoryEpochId) -> SidResult<()> {
    tx.run(
        "MATCH (u:SidHistoryKeyUse) WHERE u.pair = $pair DETACH DELETE u",
        Params::default().with("pair", use_key(operation, epoch)?),
    )?;
    Ok(())
}

fn use_key(operation: Uuid, epoch: HistoryEpochId) -> SidResult<Value> {
    super::key(&[operation.as_bytes(), epoch.0.as_bytes()])
}

fn read_archive(tx: &Statements<'_>, domain: &[u8; 32]) -> SidResult<Option<KeyArchive>> {
    let epochs = owner_epochs(tx, domain)?;
    let lifecycle = owner_lifecycle(tx, domain)?;
    if epochs.is_empty() && lifecycle.is_none() {
        return Ok(None);
    }
    let mut uses = owner_uses(tx, domain)?
        .into_iter()
        .map(|(operation, epoch, expires_at)| KeyUse {
            operation,
            epoch,
            expires_at,
        })
        .collect::<Vec<_>>();
    uses.sort_unstable_by_key(|u| (u.operation, u.epoch));
    let mut with_keys = Vec::with_capacity(epochs.len());
    let mut replaced = Vec::new();
    let mut created_by = Vec::new();
    for s in epochs {
        let key = epoch_key(tx, s.epoch.id)?
            .ok_or_else(|| SidError::Storage("history epoch without its key".into()))?;
        if let Some(revision) = s.replaced_at {
            replaced.push((s.epoch.id, revision));
        }
        if let Some(op) = s.created_by {
            created_by.push((s.epoch.id, op));
        }
        with_keys.push(NewKeyEpoch {
            epoch: s.epoch,
            key,
        });
    }
    replaced.sort_unstable();
    created_by.sort_unstable();
    let archive = KeyArchive {
        owner_domain: *domain,
        epochs: with_keys,
        replaced,
        created_by,
        lifecycle,
        uses,
    };
    archive.validate()?;
    Ok(Some(archive))
}

/// The lifecycle recorded for `domain`, read without taking its turn.
fn owner_lifecycle(tx: &Statements<'_>, domain: &[u8; 32]) -> SidResult<Option<KeyLifecycle>> {
    let rows = tx.run(
        "MATCH (o:SidHistoryOwner) WHERE o.domain = $d RETURN o.revision AS revision, o.live AS live",
        Params::default().with("d", domain_value(domain)),
    )?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    match row.get("revision") {
        None | Some(Value::Null) => Ok(None),
        Some(_) => {
            let mut live: Vec<HistoryEpochId> = get_document(row, "live")?;
            live.sort_unstable();
            Ok(Some(KeyLifecycle {
                revision: get_int(row, "revision")?,
                live,
            }))
        }
    }
}

fn read_records(tx: &Statements<'_>) -> SidResult<KeyStoreRecords> {
    let rows = tx.run(
        "MATCH (a:SidHistoryAbandoned)
         RETURN a.operation AS operation, a.owner_domain AS d, a.abandoned_at AS at",
        Params::default(),
    )?;
    let mut abandoned = rows
        .iter()
        .map(|row| {
            Ok(AbandonedEnrollment {
                operation: get_uuid(row, "operation")?,
                owner_domain: bytes32(row, "d")?,
                at: get_time(row, "at")?,
            })
        })
        .collect::<SidResult<Vec<_>>>()?;
    abandoned.sort_unstable_by_key(|a| a.operation);
    let rows = tx.run(
        "MATCH (o:SidHistoryOwner) WHERE o.purged_at IS NOT NULL
         RETURN o.domain AS d, o.purged_at AS at",
        Params::default(),
    )?;
    let mut purged = rows
        .iter()
        .map(|row| {
            Ok(PurgedOwner {
                owner_domain: bytes32(row, "d")?,
                at: get_time(row, "at")?,
            })
        })
        .collect::<SidResult<Vec<_>>>()?;
    purged.sort_unstable_by_key(|p| p.owner_domain);
    // This store's audit trail lives in the database's audit chains and
    // moves with them.
    Ok(KeyStoreRecords {
        abandoned,
        purged,
        audit: Vec::new(),
    })
}

fn bytes32(row: &Row, name: &str) -> SidResult<[u8; 32]> {
    get_bytes(row, name)?
        .try_into()
        .map_err(|_| SidError::Storage(format!("{name}: not 32 bytes")))
}

fn epoch_key(tx: &Statements<'_>, epoch: HistoryEpochId) -> SidResult<Option<WrappedHistoryKey>> {
    let rows = tx.run(
        "MATCH (e:SidHistoryKeyEpoch) WHERE e.id = $id RETURN e.wrapped_key AS k",
        Params::default().with("id", uuid(&epoch.0)),
    )?;
    rows.first()
        .map(|row| get_bytes(row, "k").map(WrappedHistoryKey))
        .transpose()
}

#[async_trait]
impl HistoryKeyStore for CoordinodeHistoryKeyStore {
    async fn get_key_epochs(&self, owner_domain: &[u8; 32]) -> SidResult<KeyEpochs> {
        let domain = *owner_domain;
        self.backend
            .read(move |tx| {
                Ok(KeyEpochs {
                    epochs: not_retired(owner_epochs(tx, &domain)?),
                })
            })
            .await
    }

    async fn create_first_epoch(
        &self,
        new: &NewKeyEpoch,
        operation: Uuid,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        require_active(new)?;
        let new = new.clone();
        self.backend
            .transaction(move |tx| {
                let domain = new.epoch.owner_domain;
                refuse_purged(&owner_turn(tx, &domain)?)?;
                // The owner's turn serializes this with the cleanup: a
                // preparation that arrives after its operation was abandoned
                // creates nothing.
                if abandoned_domain(tx, operation)?.is_some() {
                    return Err(SidError::Fenced(format!(
                        "first enrollment {operation} was aborted"
                    )));
                }
                let existing = owner_epochs(tx, &domain)?;
                if let [only] = existing.as_slice()
                    && only.epoch == new.epoch
                {
                    return Ok(Decision::Abandon(only.epoch.clone()));
                }
                if !existing.is_empty() {
                    return Err(SidError::Conflict(
                        "the owner already has a history epoch".into(),
                    ));
                }
                insert_epoch(tx, &new, Some(operation), None)?;
                audited(tx, &owner_chain(&domain), audit.clone())?;
                Ok(Decision::Commit(new.epoch.clone()))
            })
            .await
    }

    async fn ensure_epoch(&self, new: &NewKeyEpoch, audit: AuditEntry) -> SidResult<KeyEpoch> {
        require_active(new)?;
        let new = new.clone();
        self.backend
            .transaction(move |tx| {
                let domain = new.epoch.owner_domain;
                refuse_purged(&owner_turn(tx, &domain)?)?;
                if let Some(active) = not_retired(owner_epochs(tx, &domain)?)
                    .into_iter()
                    .find(|e| e.status == HistoryEpochUse::Active)
                {
                    return Ok(Decision::Abandon(active));
                }
                insert_epoch(tx, &new, None, None)?;
                audited(tx, &owner_chain(&domain), audit.clone())?;
                Ok(Decision::Commit(new.epoch.clone()))
            })
            .await
    }

    async fn rotate_epoch(
        &self,
        new: &NewKeyEpoch,
        replaces: HistoryEpochId,
        replaced_at_revision: i64,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        require_active(new)?;
        if replaced_at_revision <= 0 {
            return Err(SidError::Validation(
                "a replacement revision is positive".into(),
            ));
        }
        let new = new.clone();
        self.backend
            .transaction(move |tx| {
                let domain = new.epoch.owner_domain;
                refuse_purged(&owner_turn(tx, &domain)?)?;
                let existing = owner_epochs(tx, &domain)?;
                if let Some(current) = existing.iter().find(|s| {
                    s.epoch.status == HistoryEpochUse::Active
                })
                    && current.epoch.id != replaces
                {
                    return Ok(Decision::Abandon(current.epoch.clone()));
                }
                // Only the owner's own epoch is replaced; its first
                // replacement revision is kept.
                if let Some(old) = existing.iter().find(|s| s.epoch.id == replaces) {
                    if old.epoch.status == HistoryEpochUse::Active {
                        set_status(tx, replaces, HistoryEpochUse::CompareOnly)?;
                    }
                    if old.replaced_at.is_none() {
                        tx.run(
                            "MATCH (e:SidHistoryKeyEpoch) WHERE e.id = $id SET e.replaced_at = $rev",
                            Params::default()
                                .with("id", uuid(&replaces.0))
                                .with("rev", Value::Int(replaced_at_revision)),
                        )?;
                    }
                }
                insert_epoch(tx, &new, None, None)?;
                audited(tx, &owner_chain(&domain), audit.clone())?;
                Ok(Decision::Commit(new.epoch.clone()))
            })
            .await
    }

    async fn prepare_epochs(
        &self,
        prep: &HistoryPreparation,
        audit: AuditEntry,
    ) -> SidResult<Vec<KeyEpoch>> {
        let prep = prep.clone();
        self.backend
            .transaction(move |tx| {
                let domain = prep.owner_domain;
                let owner = owner_turn(tx, &domain)?;
                refuse_purged(&owner)?;
                let epochs = owner_epochs(tx, &domain)?;
                let owned: BTreeSet<HistoryEpochId> = epochs.iter().map(|s| s.epoch.id).collect();
                if prep.live.live.iter().any(|e| !owned.contains(e)) {
                    return Err(SidError::Validation(
                        "the live set names an epoch that is not the owner's".into(),
                    ));
                }
                // The recorded lifecycle moves only forward.
                let (revision, recorded_live) = match owner.lifecycle {
                    Some((recorded, live)) if recorded > prep.live.revision => (recorded, live),
                    Some((recorded, live)) if recorded == prep.live.revision => {
                        if live != prep.live.live {
                            return Err(SidError::Conflict(format!(
                                "history revision {recorded} already has another live set"
                            )));
                        }
                        (recorded, live)
                    }
                    _ => {
                        tx.run(
                            "MATCH (o:SidHistoryOwner) WHERE o.domain = $d
                             SET o.revision = $revision, o.live = $live",
                            Params::default()
                                .with("d", domain_value(&domain))
                                .with("revision", Value::Int(prep.live.revision))
                                .with("live", document(&prep.live.live, "live set")?),
                        )?;
                        (prep.live.revision, prep.live.live.clone())
                    }
                };
                // Release the uses of settled and of expired operations.
                let settled: BTreeSet<Uuid> = prep.live.settled.iter().copied().collect();
                let mut in_use = BTreeSet::new();
                for (operation, epoch, expires_at) in owner_uses(tx, &domain)? {
                    if expires_at <= prep.now || settled.contains(&operation) {
                        delete_use(tx, operation, epoch)?;
                    } else {
                        in_use.insert(epoch);
                    }
                }
                // Retire what no live set at or after its replacement and no
                // pending operation still needs; its key is kept.
                let recorded_live: BTreeSet<HistoryEpochId> = recorded_live.into_iter().collect();
                let live: BTreeSet<HistoryEpochId> = prep.live.live.iter().copied().collect();
                let mut selected = Vec::new();
                for s in epochs {
                    let mut epoch = s.epoch;
                    if epoch.status == HistoryEpochUse::CompareOnly
                        && s.replaced_at.is_some_and(|at| at <= revision)
                        && !recorded_live.contains(&epoch.id)
                        && !in_use.contains(&epoch.id)
                    {
                        set_status(tx, epoch.id, HistoryEpochUse::Retired)?;
                        epoch.status = HistoryEpochUse::Retired;
                    }
                    let chosen = match epoch.status {
                        HistoryEpochUse::Active => true,
                        HistoryEpochUse::CompareOnly => live.contains(&epoch.id),
                        HistoryEpochUse::Retired => false,
                    };
                    if chosen {
                        selected.push(epoch);
                    }
                }
                // Active first, then by creation.
                selected.sort_by_key(|e| (e.status != HistoryEpochUse::Active, e.created_at, e.id));
                for epoch in &selected {
                    let pair = use_key(prep.operation, epoch.id)?;
                    let params = Params::default()
                        .with("pair", pair)
                        .with("operation", uuid(&prep.operation))
                        .with("epoch_id", uuid(&epoch.id.0))
                        .with("d", domain_value(&domain))
                        .with("expires_at", time(prep.expires_at));
                    let updated = tx.run(
                        "MATCH (u:SidHistoryKeyUse) WHERE u.pair = $pair
                         SET u.expires_at = $expires_at RETURN u.pair AS pair",
                        params.clone(),
                    )?;
                    if updated.is_empty() {
                        tx.run(
                            "CREATE (u:SidHistoryKeyUse {pair: $pair, operation: $operation,
                                epoch_id: $epoch_id, owner_domain: $d, expires_at: $expires_at})",
                            params,
                        )?;
                    }
                }
                audited(tx, &owner_chain(&domain), audit.clone())?;
                Ok(Decision::Commit(selected))
            })
            .await
    }

    async fn abandon_enrollment(
        &self,
        owner_domain: &[u8; 32],
        operation: Uuid,
        audit: AuditEntry,
    ) -> SidResult<EnrollmentCleanup> {
        let domain = *owner_domain;
        self.backend
            .transaction(move |tx| {
                let owner = owner_turn(tx, &domain)?;
                match abandoned_domain(tx, operation)? {
                    Some(fenced) if fenced != domain => {
                        return Err(SidError::Validation(
                            "the aborted enrollment was recorded for another owner".into(),
                        ));
                    }
                    Some(_) => {}
                    None => {
                        tx.run(
                            "CREATE (a:SidHistoryAbandoned {operation: $op, owner_domain: $d,
                                abandoned_at: $at})",
                            Params::default()
                                .with("op", uuid(&operation))
                                .with("d", domain_value(&domain))
                                .with("at", time(Utc::now())),
                        )?;
                    }
                }
                let epochs = owner_epochs(tx, &domain)?;
                let (created, others): (Vec<_>, Vec<_>) = epochs
                    .into_iter()
                    .partition(|s| s.created_by == Some(operation));
                let outcome = if created.is_empty() {
                    EnrollmentCleanup::NothingCreated
                } else {
                    // A committed owner is what a lifecycle, another epoch or
                    // another operation's use shows; any of them keeps the key.
                    let uses = owner_uses(tx, &domain)?;
                    let other_uses = uses.iter().filter(|(op, _, _)| *op != operation).count();
                    if owner.lifecycle.is_some() || !others.is_empty() || other_uses > 0 {
                        EnrollmentCleanup::Retained(format!(
                            "lifecycle recorded: {}, other epochs: {}, other uses: {other_uses}",
                            owner.lifecycle.is_some(),
                            others.len()
                        ))
                    } else {
                        for (op, epoch, _) in uses {
                            delete_use(tx, op, epoch)?;
                        }
                        for s in created {
                            tx.run(
                                "MATCH (e:SidHistoryKeyEpoch) WHERE e.id = $id DETACH DELETE e",
                                Params::default().with("id", uuid(&s.epoch.id.0)),
                            )?;
                        }
                        EnrollmentCleanup::Reclaimed
                    }
                };
                audited(tx, &owner_chain(&domain), audit.clone())?;
                Ok(Decision::Commit(outcome))
            })
            .await
    }

    async fn enrollment_abandoned(&self, operation: Uuid) -> SidResult<bool> {
        self.backend
            .read(move |tx| Ok(abandoned_domain(tx, operation)?.is_some()))
            .await
    }

    async fn purge_owner(&self, owner_domain: &[u8; 32], audit: AuditEntry) -> SidResult<u64> {
        let domain = *owner_domain;
        self.backend
            .transaction(move |tx| {
                let owner = owner_turn(tx, &domain)?;
                let params = Params::default()
                    .with("d", domain_value(&domain))
                    .with("at", time(Utc::now()));
                // The fence keeps the time of the first purge.
                let fence = if owner.purged {
                    "MATCH (o:SidHistoryOwner) WHERE o.domain = $d
                     SET o.revision = null, o.live = null"
                } else {
                    "MATCH (o:SidHistoryOwner) WHERE o.domain = $d
                     SET o.purged_at = $at, o.revision = null, o.live = null"
                };
                tx.run(fence, params.clone())?;
                for (op, epoch, _) in owner_uses(tx, &domain)? {
                    delete_use(tx, op, epoch)?;
                }
                let destroyed = owner_epochs(tx, &domain)?.len();
                tx.run(
                    "MATCH (e:SidHistoryKeyEpoch) WHERE e.owner_domain = $d DETACH DELETE e",
                    params,
                )?;
                audited(tx, &owner_chain(&domain), audit.clone())?;
                let destroyed = u64::try_from(destroyed)
                    .map_err(|_| SidError::Storage("destroyed key count".into()))?;
                Ok(Decision::Commit(destroyed))
            })
            .await
    }

    async fn compact_abandoned(&self, before: DateTime<Utc>, audit: AuditEntry) -> SidResult<u64> {
        self.backend
            .transaction(move |tx| {
                let mut dropped = 0u64;
                let fences = tx.run(
                    "MATCH (a:SidHistoryAbandoned)
                     RETURN a.operation AS operation, a.abandoned_at AS at",
                    Params::default(),
                )?;
                for row in &fences {
                    if get_time(row, "at")? < before {
                        tx.run(
                            "MATCH (a:SidHistoryAbandoned) WHERE a.operation = $op DETACH DELETE a",
                            Params::default().with("op", uuid(&get_uuid(row, "operation")?)),
                        )?;
                        dropped += 1;
                    }
                }
                let owners = tx.run(
                    "MATCH (o:SidHistoryOwner) RETURN o.domain AS d, o.purged_at AS purged_at",
                    Params::default(),
                )?;
                for row in &owners {
                    if get_opt_time(row, "purged_at")?.is_some_and(|at| at < before) {
                        tx.run(
                            "MATCH (o:SidHistoryOwner) WHERE o.domain = $d SET o.purged_at = null",
                            Params::default().with("d", Value::Binary(get_bytes(row, "d")?)),
                        )?;
                        dropped += 1;
                    }
                }
                if dropped == 0 {
                    return Ok(Decision::Abandon(0));
                }
                audited(tx, STORE_CHAIN, audit.clone())?;
                Ok(Decision::Commit(dropped))
            })
            .await
    }

    async fn get_epoch_key(&self, epoch: HistoryEpochId) -> SidResult<Option<WrappedHistoryKey>> {
        self.backend.read(move |tx| epoch_key(tx, epoch)).await
    }

    async fn write_cutoff(&self) -> SidResult<Option<DateTime<Utc>>> {
        self.backend
            .read(|tx| read_cutoff(tx, Cutoff::Evaluator))
            .await
    }

    async fn raise_write_cutoff(
        &self,
        not_before: DateTime<Utc>,
        audit: AuditEntry,
    ) -> SidResult<DateTime<Utc>> {
        self.backend
            .transaction(move |tx| {
                let (cutoff, moved) = raise_cutoff(tx, Cutoff::Evaluator, not_before)?;
                if !moved {
                    return Ok(Decision::Abandon(cutoff));
                }
                audited(tx, STORE_CHAIN, audit.clone())?;
                Ok(Decision::Commit(cutoff))
            })
            .await
    }

    async fn list_key_versions(&self) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
        self.backend.read(|tx| keys::list(tx, keys::HISTORY)).await
    }

    async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        audit: AuditEntry,
    ) -> SidResult<bool> {
        let params = params.clone();
        self.backend
            .transaction(move |tx| {
                keys::insert(
                    tx,
                    keys::HISTORY,
                    &params,
                    STORE_CHAIN,
                    MutationContext::from(audit.clone()),
                )
            })
            .await
    }

    async fn export_keys(&self, owner_domain: &[u8; 32]) -> SidResult<Option<KeyArchive>> {
        let domain = *owner_domain;
        self.backend.read(move |tx| read_archive(tx, &domain)).await
    }

    async fn import_keys(&self, archive: &KeyArchive, audit: AuditEntry) -> SidResult<bool> {
        archive.validate()?;
        let archive = archive.clone();
        self.backend
            .transaction(move |tx| {
                let domain = archive.owner_domain;
                refuse_purged(&owner_turn(tx, &domain)?)?;
                if let Some(existing) = read_archive(tx, &domain)? {
                    if existing == archive {
                        return Ok(Decision::Abandon(false));
                    }
                    return Err(SidError::Conflict(
                        "existing history keys differ from archive".into(),
                    ));
                }
                let replaced: BTreeMap<HistoryEpochId, i64> =
                    archive.replaced.iter().copied().collect();
                let created_by: BTreeMap<HistoryEpochId, Uuid> =
                    archive.created_by.iter().copied().collect();
                for epoch in &archive.epochs {
                    insert_epoch(
                        tx,
                        epoch,
                        created_by.get(&epoch.epoch.id).copied(),
                        replaced.get(&epoch.epoch.id).copied(),
                    )?;
                }
                if let Some(lifecycle) = &archive.lifecycle {
                    tx.run(
                        "MATCH (o:SidHistoryOwner) WHERE o.domain = $d
                         SET o.revision = $revision, o.live = $live",
                        Params::default()
                            .with("d", domain_value(&domain))
                            .with("revision", Value::Int(lifecycle.revision))
                            .with("live", document(&lifecycle.live, "live set")?),
                    )?;
                }
                for u in &archive.uses {
                    tx.run(
                        "CREATE (u:SidHistoryKeyUse {pair: $pair, operation: $operation,
                            epoch_id: $epoch_id, owner_domain: $d, expires_at: $expires_at})",
                        Params::default()
                            .with("pair", use_key(u.operation, u.epoch)?)
                            .with("operation", uuid(&u.operation))
                            .with("epoch_id", uuid(&u.epoch.0))
                            .with("d", domain_value(&domain))
                            .with("expires_at", time(u.expires_at)),
                    )?;
                }
                audited(tx, &owner_chain(&domain), audit.clone())?;
                Ok(Decision::Commit(true))
            })
            .await
    }

    async fn export_key_records(&self) -> SidResult<KeyStoreRecords> {
        self.backend.read(read_records).await
    }

    async fn import_key_records(
        &self,
        records: &KeyStoreRecords,
        audit: AuditEntry,
    ) -> SidResult<bool> {
        records.validate()?;
        if !records.audit.is_empty() {
            // The trail of this engine is the audit chains, which carry
            // their own transfer; a separate store trail has no place here.
            return Err(SidError::Validation(
                "this history key store keeps its audit trail in the audit chains".into(),
            ));
        }
        let records = records.clone();
        self.backend
            .transaction(move |tx| {
                // Every fenced owner's turn first: its writes stay ordered.
                for p in &records.purged {
                    owner_turn(tx, &p.owner_domain)?;
                }
                for a in &records.abandoned {
                    owner_turn(tx, &a.owner_domain)?;
                }
                let existing = read_records(tx)?;
                if existing == records {
                    return Ok(Decision::Abandon(false));
                }
                if !existing.abandoned.is_empty() || !existing.purged.is_empty() {
                    return Err(SidError::Conflict(
                        "the history key store already holds other records".into(),
                    ));
                }
                for a in &records.abandoned {
                    tx.run(
                        "CREATE (a:SidHistoryAbandoned {operation: $op, owner_domain: $d,
                            abandoned_at: $at})",
                        Params::default()
                            .with("op", uuid(&a.operation))
                            .with("d", domain_value(&a.owner_domain))
                            .with("at", time(a.at)),
                    )?;
                }
                for p in &records.purged {
                    tx.run(
                        "MATCH (o:SidHistoryOwner) WHERE o.domain = $d SET o.purged_at = $at",
                        Params::default()
                            .with("d", domain_value(&p.owner_domain))
                            .with("at", time(p.at)),
                    )?;
                }
                audited(tx, STORE_CHAIN, audit.clone())?;
                Ok(Decision::Commit(true))
            })
            .await
    }
}
