// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// The detail lines of `sql`'s query plan with `params` bound in order (the
/// plan is not executed, so text stands for every value).
async fn plan(backend: &SqliteBackend, sql: &str, params: &[&str]) -> Vec<String> {
    // Built from this module's own statement constants, no outside input.
    let explained = sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}"));
    let mut query = sqlx::query_as::<_, (i64, i64, i64, String)>(explained);
    for param in params {
        query = query.bind(*param);
    }
    query
        .fetch_all(&backend.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.3)
        .collect()
}

/// Every statement a claim runs reads only open work through the open-work
/// index, never the whole table: ended work stays in the table until its
/// retention ends, and the claim holds the write lock. The due read and the
/// abandoned sweep once scanned the table, so each claim read every ended
/// item and a backlog drained ever slower.
#[tokio::test]
async fn a_claim_reads_open_work_through_its_index() {
    let backend = SqliteBackend::new_in_memory().await.unwrap();
    let (now, kinds) = ("2026-01-01T00:00:00Z", r#"["kind.a"]"#);
    for (name, sql, params) in [
        ("expire", EXPIRE_SQL, [now, kinds, now, ""]),
        ("abandoned", ABANDONED_SQL, [now, kinds, now, ""]),
        ("due", DUE_SQL, [kinds, now, now, "32"]),
    ] {
        let params: Vec<&str> = params.into_iter().filter(|p| !p.is_empty()).collect();
        let details = plan(&backend, sql, &params).await;
        assert!(
            details
                .iter()
                .any(|d| d.contains("durable_work USING INDEX idx_durable_work_open")),
            "{name}: {details:?}"
        );
        assert!(
            !details.iter().any(|d| d == "SCAN durable_work"),
            "{name}: {details:?}"
        );
    }
}
