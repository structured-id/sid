// SPDX-License-Identifier: AGPL-3.0-only
//! The audit chain: each record links the one before it, chains are
//! independent, and a mutation's record commits with the mutation.

use sid_core::models::audit::{AuditEntry, compute_record_hash};
use sid_plugin::AuditLog;
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::create_test_profile;

fn chain(name: &str) -> String {
    format!("test:{name}:{}", Uuid::now_v7())
}

/// Each record of a chain carries the hash of the one before it, its own
/// hash covers what it says, and the chain verifies.
pub async fn test_audit_chain_links_records(log: &dyn AuditLog) {
    let chain = chain("links");
    let first = log
        .log(&chain, AuditEntry::system("profile.created", &chain))
        .await
        .unwrap();
    assert_eq!(first.sequence, 1);
    assert_eq!(first.prev_hash, "genesis");
    let second = log
        .log(&chain, AuditEntry::system("profile.updated", &chain))
        .await
        .unwrap();
    assert_eq!(second.sequence, 2);
    assert_eq!(second.prev_hash, first.hash);

    let records = log.query(&chain, None, None).await.unwrap();
    assert_eq!(
        records
            .iter()
            .map(|r| r.action.as_str())
            .collect::<Vec<_>>(),
        ["profile.created", "profile.updated"]
    );
    for record in &records {
        assert_eq!(
            record.hash,
            compute_record_hash(record),
            "record {} reads back other than it was hashed",
            record.sequence
        );
    }
    let verified = log.verify_chain(&chain).await.unwrap();
    assert!(verified.valid, "{verified:?}");
    assert_eq!(verified.records_verified, 2);
}

/// A new chain starts at its own genesis, whatever other chains hold.
pub async fn test_audit_chains_are_independent(log: &dyn AuditLog) {
    let (a, b) = (chain("a"), chain("b"));
    let first_a = log.log(&a, AuditEntry::system("a1", &a)).await.unwrap();
    let first_b = log.log(&b, AuditEntry::system("b1", &b)).await.unwrap();
    for first in [first_a, first_b] {
        assert_eq!(first.sequence, 1);
        assert_eq!(first.prev_hash, "genesis");
    }
}

/// A profile's mutations each leave one record on the profile's chain, in
/// order, and that chain verifies: the record is written with the data, so
/// neither commits without the other.
pub async fn test_mutations_leave_their_audit_chain(
    backend: &dyn StorageBackend,
    log: &dyn AuditLog,
) {
    let mut profile = create_test_profile("audit");
    backend
        .create_profile(&profile, AuditEntry::system("create", "audit-chain").into())
        .await
        .unwrap();
    let chain = format!("profile:{}", profile.id);
    assert!(backend.get_profile(profile.id).await.unwrap().is_some());
    assert_eq!(log.query(&chain, None, None).await.unwrap().len(), 1);

    profile.given_name = Some("Updated".into());
    assert!(
        backend
            .update_profile(&profile, AuditEntry::system("update", "audit-chain").into())
            .await
            .unwrap()
    );
    backend
        .delete_profile(
            profile.id,
            AuditEntry::system("delete", "audit-chain").into(),
        )
        .await
        .unwrap();

    let records = log.query(&chain, None, None).await.unwrap();
    assert_eq!(
        records
            .iter()
            .map(|r| r.action.as_str())
            .collect::<Vec<_>>(),
        ["create", "update", "delete"]
    );
    let verified = log.verify_chain(&chain).await.unwrap();
    assert!(verified.valid, "{verified:?}");
    assert_eq!(verified.records_verified, 3);
}
