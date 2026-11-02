// SPDX-License-Identifier: AGPL-3.0-only
//! Audit retention removes whole months that ended before the cut, never a
//! month still running on it, and leaves each chain verifiable from the
//! checkpoint of its last removed record.

use std::future::Future;

use chrono::{DateTime, NaiveDate, Utc};
use sid_core::models::audit::{ActorType, AuditOutcome, AuditRecord, compute_record_hash};
use sid_plugin::AuditLog;
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

/// A record of `chain` at `timestamp`, linked to `prev_hash`.
fn record(chain: &str, sequence: u64, timestamp: &str, prev_hash: &str) -> AuditRecord {
    let mut r = AuditRecord {
        id: Uuid::now_v7().to_string(),
        timestamp: at(timestamp),
        chain_id: chain.to_string(),
        sequence,
        actor_id: "system".into(),
        actor_type: ActorType::System,
        action: "test.retention".into(),
        resource: chain.to_string(),
        outcome: AuditOutcome::Success,
        metadata: serde_json::json!({}),
        ip_address: None,
        device_id: None,
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
    };
    r.hash = compute_record_hash(&r);
    r
}

/// Every actor type is read back as written: an audit trail that reports an
/// administrator or a provisioning connector as a user misattributes the act.
pub async fn test_audit_actor_types_round_trip(log: &dyn AuditLog) {
    use sid_core::models::audit::AuditEntry;
    let chain = format!("test:actors:{}", Uuid::now_v7());
    let written = [
        ActorType::User,
        ActorType::Admin,
        ActorType::Service,
        ActorType::Machine,
        ActorType::Connector,
        ActorType::System,
    ];
    for actor_type in written {
        let mut entry = AuditEntry::system("test.actor", &chain);
        entry.actor_type = actor_type;
        log.log(&chain, entry).await.unwrap();
    }
    let read: Vec<ActorType> = log
        .query(&chain, None, None)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.actor_type)
        .collect();
    assert_eq!(read, written);
}

/// `insert` stores a record as it stands (the harness writes the row: no
/// operation records the past).
pub async fn test_audit_retention_keeps_chains_verifiable<Ins, Fut>(
    backend: &dyn StorageBackend,
    log: &dyn AuditLog,
    insert: Ins,
) where
    Ins: Fn(AuditRecord) -> Fut,
    Fut: Future<Output = ()>,
{
    assert!(matches!(
        backend
            .ensure_audit_partition(NaiveDate::from_ymd_opt(2001, 1, 15).unwrap())
            .await,
        Err(sid_core::Error::Validation(_))
    ));
    for month in [1, 3] {
        backend
            .ensure_audit_partition(NaiveDate::from_ymd_opt(2001, month, 1).unwrap())
            .await
            .unwrap();
    }

    let chain = format!("test:retention:{}", Uuid::now_v7());
    let r1 = record(&chain, 1, "2001-01-10T08:00:00Z", "genesis");
    let r2 = record(&chain, 2, "2001-01-20T08:00:00Z", &r1.hash);
    let r3 = record(&chain, 3, "2001-03-05T08:00:00Z", &r2.hash);
    for r in [r1, r2, r3.clone()] {
        insert(r).await;
    }
    let before = log.verify_chain(&chain).await.unwrap();
    assert!(before.valid, "{before:?}");
    assert_eq!(before.records_verified, 3);

    // A cut in mid-February removes January, which ended before it.
    assert_eq!(
        backend
            .drop_expired_audit_records(at("2001-02-15T00:00:00Z"), test_audit())
            .await
            .unwrap(),
        2
    );
    let remaining = log.query(&chain, None, None).await.unwrap();
    assert_eq!(
        remaining.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        vec![r3.id.clone()]
    );
    let after = log.verify_chain(&chain).await.unwrap();
    assert!(after.valid, "the cut chain no longer verifies: {after:?}");
    assert_eq!(after.records_verified, 1);

    // A cut inside March keeps March: the month is still running on it.
    assert_eq!(
        backend
            .drop_expired_audit_records(at("2001-03-20T00:00:00Z"), test_audit())
            .await
            .unwrap(),
        0,
        "records of a month still running on the cut were removed"
    );
    assert_eq!(log.query(&chain, None, None).await.unwrap().len(), 1);
    assert!(log.verify_chain(&chain).await.unwrap().valid);
}
