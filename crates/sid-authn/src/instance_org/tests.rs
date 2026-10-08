// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{OrgStatus, OrgType};
use sid_storage::sqlite::SqliteBackend;

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

/// The first start creates the active Community organization; later starts
/// get the same one back, even with another domain configured.
#[tokio::test]
async fn first_start_creates_later_starts_reuse() {
    let storage = storage().await;
    let first = ensure(&storage, "id.sid.example.com").await.unwrap();
    assert_eq!(first.org_type, OrgType::Community);
    assert_eq!(first.status, OrgStatus::Active);
    assert_eq!(first.canonical_domain, "id.sid.example.com");

    let again = ensure(&storage, "other.sid.example.com").await.unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(again.canonical_domain, "id.sid.example.com");
}

/// Replicas starting together end up with one organization.
#[tokio::test]
async fn concurrent_starts_agree() {
    let storage = storage().await;
    let (a, b) = tokio::join!(
        ensure(&storage, "id.sid.example.com"),
        ensure(&storage, "id.sid.example.com"),
    );
    assert_eq!(a.unwrap().id, b.unwrap().id);
}
