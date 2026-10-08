// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use chrono::Utc;
use sid_core::models::audit::{ActorType, AuditOutcome, ChainHead, compute_record_hash};
use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory audit log for testing.
struct InMemoryAuditLog {
    records: Mutex<Vec<AuditRecord>>,
    heads: Mutex<HashMap<String, ChainHead>>,
}

impl InMemoryAuditLog {
    fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            heads: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AuditLog for InMemoryAuditLog {
    async fn log(&self, chain_id: &str, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        let mut records = self.records.lock().unwrap();
        let mut heads = self.heads.lock().unwrap();

        let head = heads.get(chain_id);
        let (prev_hash, sequence) = match head {
            Some(h) => (h.last_hash.clone(), h.sequence + 1),
            None => ("genesis".to_string(), 1),
        };

        let id = format!("audit_{}", records.len() + 1);
        let mut record = AuditRecord {
            id: id.clone(),
            timestamp: Utc::now(),
            chain_id: chain_id.to_string(),
            sequence,
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

        heads.insert(
            chain_id.to_string(),
            ChainHead {
                chain_id: chain_id.to_string(),
                last_record_id: id,
                last_hash: record.hash.clone(),
                sequence,
            },
        );

        records.push(record.clone());
        Ok(record)
    }

    async fn query(
        &self,
        chain_id: &str,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let records = self.records.lock().unwrap();
        Ok(records
            .iter()
            .filter(|r| {
                r.chain_id == chain_id
                    && from.is_none_or(|f| r.timestamp >= f)
                    && to.is_none_or(|t| r.timestamp <= t)
            })
            .cloned()
            .collect())
    }

    async fn verify_chain(&self, chain_id: &str) -> Result<VerifyResult, AuditError> {
        let records = self.query(chain_id, None, None).await?;
        Ok(verify_records(&records, "genesis".to_string()))
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, AuditError> {
        let heads = self.heads.lock().unwrap();
        Ok(heads.keys().cloned().collect())
    }
}

fn test_entry(action: &str) -> AuditEntry {
    AuditEntry {
        actor_id: "prof_123".into(),
        actor_type: ActorType::User,
        action: action.into(),
        resource: "prof_123".into(),
        outcome: AuditOutcome::Success,
        metadata: serde_json::json!({}),
        ip_address: Some("1.2.3.4".into()),
        device_id: None,
    }
}

#[tokio::test]
async fn test_log_first_record() {
    let log = InMemoryAuditLog::new();
    let record = log
        .log("profile:prof_123", test_entry("profile.created"))
        .await
        .unwrap();

    assert_eq!(record.chain_id, "profile:prof_123");
    assert_eq!(record.sequence, 1);
    assert_eq!(record.prev_hash, "genesis");
    assert!(!record.hash.is_empty());
}

#[tokio::test]
async fn test_log_chain_linkage() {
    let log = InMemoryAuditLog::new();

    let r1 = log
        .log("profile:prof_123", test_entry("profile.created"))
        .await
        .unwrap();
    let r2 = log
        .log("profile:prof_123", test_entry("profile.email_changed"))
        .await
        .unwrap();
    let r3 = log
        .log("profile:prof_123", test_entry("profile.claim_changed"))
        .await
        .unwrap();

    assert_eq!(r1.sequence, 1);
    assert_eq!(r2.sequence, 2);
    assert_eq!(r3.sequence, 3);

    // Chain linkage
    assert_eq!(r2.prev_hash, r1.hash);
    assert_eq!(r3.prev_hash, r2.hash);
}

#[tokio::test]
async fn test_parallel_chains_independent() {
    let log = InMemoryAuditLog::new();

    let ra = log
        .log("profile:prof_A", test_entry("login"))
        .await
        .unwrap();
    let rb = log
        .log("profile:prof_B", test_entry("login"))
        .await
        .unwrap();

    // Both start at sequence 1
    assert_eq!(ra.sequence, 1);
    assert_eq!(rb.sequence, 1);

    // Both link to genesis
    assert_eq!(ra.prev_hash, "genesis");
    assert_eq!(rb.prev_hash, "genesis");
}

#[tokio::test]
async fn test_verify_chain_valid() {
    let log = InMemoryAuditLog::new();

    log.log("chain1", test_entry("action1")).await.unwrap();
    log.log("chain1", test_entry("action2")).await.unwrap();
    log.log("chain1", test_entry("action3")).await.unwrap();

    let result = log.verify_chain("chain1").await.unwrap();
    assert!(result.valid);
    assert_eq!(result.records_verified, 3);
    assert!(result.first_broken_record.is_none());
}

#[tokio::test]
async fn test_verify_empty_chain() {
    let log = InMemoryAuditLog::new();

    let result = log.verify_chain("nonexistent").await.unwrap();
    assert!(result.valid);
    assert_eq!(result.records_verified, 0);
}

#[tokio::test]
async fn test_query_returns_chain_records() {
    let log = InMemoryAuditLog::new();

    log.log("chain_A", test_entry("a1")).await.unwrap();
    log.log("chain_B", test_entry("b1")).await.unwrap();
    log.log("chain_A", test_entry("a2")).await.unwrap();

    let chain_a = log.query("chain_A", None, None).await.unwrap();
    assert_eq!(chain_a.len(), 2);
    assert_eq!(chain_a[0].action, "a1");
    assert_eq!(chain_a[1].action, "a2");
}

#[tokio::test]
async fn test_audit_log_object_safety() {
    let log: Box<dyn AuditLog> = Box::new(InMemoryAuditLog::new());
    log.log("chain", test_entry("test")).await.unwrap();
    let result = log.verify_chain("chain").await.unwrap();
    assert!(result.valid);
}

#[tokio::test]
async fn test_audit_log_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InMemoryAuditLog>();
}

/// Three linked records of one chain, starting from `start`.
async fn three_records() -> Vec<AuditRecord> {
    let log = InMemoryAuditLog::new();
    for action in ["a1", "a2", "a3"] {
        log.log("chain", test_entry(action)).await.unwrap();
    }
    log.query("chain", None, None).await.unwrap()
}

/// A chain whose first records were removed does not verify from genesis:
/// deleting the oldest records is detected.
#[tokio::test]
async fn verify_records_detects_a_missing_start() {
    let records = three_records().await;
    let result = verify_records(&records[1..], "genesis".to_string());
    assert!(!result.valid);
    assert_eq!(
        result.first_broken_record.as_deref(),
        Some(records[1].id.as_str())
    );
    assert_eq!(result.records_verified, 0);
}

/// A chain cut by retention verifies from the checkpoint the cut left.
#[tokio::test]
async fn verify_records_resumes_from_a_checkpoint() {
    let records = three_records().await;
    let result = verify_records(&records[1..], records[0].hash.clone());
    assert!(result.valid);
    assert_eq!(result.records_verified, 2);
}

/// A broken link or a tampered record stops verification at that record.
#[tokio::test]
async fn verify_records_stops_at_a_broken_record() {
    let mut records = three_records().await;
    records[1].outcome = AuditOutcome::Denied;
    let result = verify_records(&records, "genesis".to_string());
    assert!(!result.valid);
    assert_eq!(result.records_verified, 1);
    assert_eq!(
        result.first_broken_record.as_deref(),
        Some(records[1].id.as_str())
    );

    let mut relinked = three_records().await;
    relinked[2].prev_hash = "other".into();
    relinked[2].hash = compute_record_hash(&relinked[2]);
    let result = verify_records(&relinked, "genesis".to_string());
    assert!(!result.valid);
    assert_eq!(result.records_verified, 2);
}
