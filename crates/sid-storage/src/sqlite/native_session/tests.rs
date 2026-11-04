// SPDX-License-Identifier: AGPL-3.0-only

use super::super::SqliteBackend;

/// Every rotation finds its generation's predecessor by `successor_id` under
/// the database write lock: the lookup goes through an index, never a scan
/// of every generation the installation keeps.
#[tokio::test]
async fn the_predecessor_lookup_uses_an_index() {
    let backend = SqliteBackend::new_in_memory().await.unwrap();
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN UPDATE native_generations SET sealed = NULL WHERE successor_id = ?",
    )
    .bind("01a1a7eb-ee8b-70b9-9ee8-ce52f436b464")
    .fetch_all(&backend.pool)
    .await
    .unwrap();
    let details: Vec<&str> = plan.iter().map(|row| row.3.as_str()).collect();
    assert!(
        details
            .iter()
            .any(|d| d.contains("USING INDEX idx_native_generations_successor")),
        "{details:?}"
    );
    assert!(
        !details.iter().any(|d| d.starts_with("SCAN")),
        "{details:?}"
    );
}
