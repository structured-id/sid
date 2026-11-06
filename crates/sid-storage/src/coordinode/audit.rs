// SPDX-License-Identifier: AGPL-3.0-only
//! The audit chains in CoordiNode: one `SidAuditRecord` node per record and
//! one `SidAuditHead` per chain. Every append writes its chain's head, so
//! concurrent appenders of one chain conflict and append one after another
//! instead of forking the chain from one head.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, SubsecRound, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::audit::{AuditEntry, AuditError, AuditRecord, compute_record_hash};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::audit::{AuditLog, VerifyResult};
use uuid::Uuid;

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, get_bytes, get_int, get_opt_bytes,
    get_opt_text, get_text, get_time, opt_text, time,
};

/// Every property of a record node, as `RETURN` lists them.
const FIELDS: &str = "r.id AS id, r.at AS at, r.chain AS chain, r.sequence AS sequence,
    r.actor_id AS actor_id, r.actor_type AS actor_type, r.action AS action,
    r.resource AS resource, r.outcome AS outcome, r.metadata AS metadata, r.ip AS ip,
    r.device_id AS device_id, r.prev_hash AS prev_hash, r.hash AS hash";

/// Append `entry` to `chain` in the open transaction `tx`, stamped `at`.
pub(super) fn append(
    tx: &Statements<'_>,
    chain: &str,
    entry: AuditEntry,
    at: DateTime<Utc>,
) -> SidResult<AuditRecord> {
    let chain_value = || Value::String(chain.to_owned());
    let head = tx.run(
        "MATCH (h:SidAuditHead) WHERE h.chain = $chain
         RETURN h.last_hash AS last_hash, h.sequence AS sequence",
        Params::default().with("chain", chain_value()),
    )?;
    let (prev_hash, sequence) = match head.first() {
        Some(row) => (get_text(row, "last_hash")?, get_int(row, "sequence")?),
        None => ("genesis".to_owned(), 0),
    };
    let sequence = sequence
        .checked_add(1)
        .ok_or_else(|| SidError::Storage(format!("audit chain {chain} is full")))?;
    // The hash covers the timestamp, so it is taken at the resolution the
    // record keeps (microseconds): one read back hashes the same digits.
    let mut record = AuditRecord {
        id: Uuid::now_v7().to_string(),
        timestamp: at.trunc_subsecs(6),
        chain_id: chain.to_owned(),
        sequence: u64::try_from(sequence).map_err(|_| SidError::Storage("sequence".into()))?,
        actor_id: entry.actor_id,
        actor_type: entry.actor_type,
        action: entry.action,
        resource: entry.resource,
        outcome: entry.outcome,
        metadata: entry.metadata,
        ip_address: entry.ip_address,
        device_id: entry.device_id,
        prev_hash,
        hash: String::new(),
    };
    record.hash = compute_record_hash(&record);
    let id = Uuid::parse_str(&record.id).map_err(|e| SidError::Internal(e.to_string()))?;
    tx.run(
        "CREATE (r:SidAuditRecord {id: $id, at: $at, chain: $chain, sequence: $sequence,
            actor_id: $actor_id, actor_type: $actor_type, action: $action,
            resource: $resource, outcome: $outcome, metadata: $metadata, ip: $ip,
            device_id: $device_id, prev_hash: $prev_hash, hash: $hash})",
        Params::default()
            .with("id", Value::Binary(id.as_bytes().to_vec()))
            .with("at", time(record.timestamp))
            .with("chain", chain_value())
            .with("sequence", Value::Int(sequence))
            .with("actor_id", Value::String(record.actor_id.clone()))
            .with("actor_type", Value::String(record.actor_type.to_string()))
            .with("action", Value::String(record.action.clone()))
            .with("resource", Value::String(record.resource.clone()))
            .with("outcome", Value::String(record.outcome.to_string()))
            .with("metadata", Value::String(record.metadata.to_string()))
            .with("ip", record.ip_address.map_or(Value::Null, ip_value))
            .with("device_id", opt_text(record.device_id.as_deref()))
            .with("prev_hash", Value::String(record.prev_hash.clone()))
            .with("hash", Value::String(record.hash.clone())),
    )?;
    // The head moves to this record; a chain's first record creates it, and
    // concurrent first appenders meet on its unique chain.
    let head_query = if head.is_empty() {
        "CREATE (h:SidAuditHead {chain: $chain, last_hash: $hash, sequence: $sequence})"
    } else {
        "MATCH (h:SidAuditHead) WHERE h.chain = $chain
         SET h.last_hash = $hash, h.sequence = $sequence"
    };
    tx.run(
        head_query,
        Params::default()
            .with("chain", chain_value())
            .with("hash", Value::String(record.hash.clone()))
            .with("sequence", Value::Int(sequence)),
    )?;
    Ok(record)
}

/// An address as its octets: 4 for IPv4, 16 for IPv6.
pub(super) fn ip_value(ip: IpAddr) -> Value {
    Value::Binary(match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    })
}

pub(super) fn ip_of(octets: &[u8]) -> SidResult<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(octets) {
        return Ok(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(octets)
        .map(IpAddr::from)
        .map_err(|_| SidError::Storage(format!("bad address of {} bytes", octets.len())))
}

/// A stored name of a serialized enum (actor type, outcome).
fn named<T: serde::de::DeserializeOwned>(row: &Row, name: &str) -> SidResult<T> {
    let text = get_text(row, name)?;
    serde_json::from_value(serde_json::Value::String(text.clone()))
        .map_err(|e| SidError::Storage(format!("{name} {text}: {e}")))
}

/// The audit record `row` holds.
fn record(row: &Row) -> SidResult<AuditRecord> {
    let id = Uuid::from_slice(&get_bytes(row, "id")?)
        .map_err(|e| SidError::Storage(format!("bad audit record id: {e}")))?;
    let metadata = get_text(row, "metadata")?;
    Ok(AuditRecord {
        id: id.to_string(),
        timestamp: get_time(row, "at")?,
        chain_id: get_text(row, "chain")?,
        sequence: u64::try_from(get_int(row, "sequence")?)
            .map_err(|_| SidError::Storage("bad audit sequence".into()))?,
        actor_id: get_text(row, "actor_id")?,
        actor_type: named(row, "actor_type")?,
        action: get_text(row, "action")?,
        resource: get_text(row, "resource")?,
        outcome: named(row, "outcome")?,
        metadata: serde_json::from_str(&metadata)
            .map_err(|e| SidError::Storage(format!("audit metadata: {e}")))?,
        ip_address: get_opt_bytes(row, "ip")?
            .as_deref()
            .map(ip_of)
            .transpose()?,
        device_id: get_opt_text(row, "device_id")?,
        prev_hash: get_text(row, "prev_hash")?,
        hash: get_text(row, "hash")?,
    })
}

fn audit_error(e: SidError) -> AuditError {
    AuditError::Other(e.to_string())
}

#[async_trait]
impl AuditLog for CoordinodeBackend {
    async fn log(&self, chain_id: &str, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        let chain = chain_id.to_owned();
        self.transaction(move |tx| {
            append(tx, &chain, entry.clone(), Utc::now()).map(Decision::Commit)
        })
        .await
        .map_err(|e| AuditError::WriteFailed(e.to_string()))
    }

    async fn query(
        &self,
        chain_id: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let chain = chain_id.to_owned();
        self.transaction(move |tx| {
            // Each bound is its own statement shape: no comparison with an
            // absent parameter.
            let mut query = String::from("MATCH (r:SidAuditRecord) WHERE r.chain = $chain");
            let mut params = Params::default().with("chain", Value::String(chain.clone()));
            if let Some(from) = from {
                query.push_str(" AND r.at >= $from");
                params = params.with("from", time(from));
            }
            if let Some(to) = to {
                query.push_str(" AND r.at <= $to");
                params = params.with("to", time(to));
            }
            query.push_str(&format!(" RETURN {FIELDS} ORDER BY r.sequence"));
            let rows = tx.run(&query, params)?;
            Ok(Decision::Abandon(
                rows.iter().map(record).collect::<SidResult<Vec<_>>>()?,
            ))
        })
        .await
        .map_err(audit_error)
    }

    async fn verify_chain(&self, chain_id: &str) -> Result<VerifyResult, AuditError> {
        let chain = chain_id.to_owned();
        let records = self
            .transaction(move |tx| {
                let rows = tx.run(
                    &format!(
                        "MATCH (r:SidAuditRecord) WHERE r.chain = $chain
                         RETURN {FIELDS} ORDER BY r.sequence"
                    ),
                    Params::default().with("chain", Value::String(chain.clone())),
                )?;
                Ok(Decision::Abandon(
                    rows.iter().map(record).collect::<SidResult<Vec<_>>>()?,
                ))
            })
            .await
            .map_err(audit_error)?;
        Ok(sid_plugin::audit::verify_records(
            &records,
            "genesis".to_owned(),
        ))
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, AuditError> {
        self.transaction(|tx| {
            let rows = tx.run(
                "MATCH (h:SidAuditHead) RETURN h.chain AS chain",
                Params::default(),
            )?;
            Ok(Decision::Abandon(
                rows.iter()
                    .map(|row| get_text(row, "chain"))
                    .collect::<SidResult<Vec<_>>>()?,
            ))
        })
        .await
        .map_err(audit_error)
    }
}
