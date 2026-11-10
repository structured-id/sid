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

/// Every statement a claim runs searches its own index by kind and time,
/// never reading the open backlog or the whole table: the claim holds the
/// write lock, and reading every open item made each claim as slow as the
/// backlog was long. The due and lapsed reads come from the index in order,
/// with no sort of the matching items.
#[tokio::test]
async fn a_claim_reads_only_due_work_through_its_indexes() {
    let backend = SqliteBackend::new_in_memory().await.unwrap();
    let (now, kinds) = ("2026-01-01T00:00:00Z", r#"["kind.a"]"#);
    for (name, sql, params, index) in [
        (
            "expire",
            EXPIRE_SQL,
            vec![now, kinds, now],
            "idx_durable_work_expiry (kind=? AND expires_at",
        ),
        (
            "abandoned",
            ABANDONED_SQL,
            vec![now, kinds, now],
            "idx_durable_work_lease (kind=? AND lease_until",
        ),
        (
            "due",
            DUE_SQL,
            vec!["kind.a", now, "32"],
            "idx_durable_work_due (kind=? AND not_before",
        ),
        (
            "lapsed",
            LAPSED_SQL,
            vec!["kind.a", now, "32"],
            "idx_durable_work_lease (kind=? AND lease_until",
        ),
    ] {
        let details = plan(&backend, sql, &params).await;
        assert!(
            details.iter().any(|d| d.contains(index)),
            "{name}: {details:?}"
        );
        assert!(
            !details.iter().any(|d| d == "SCAN durable_work"),
            "{name}: {details:?}"
        );
        assert!(
            !details.iter().any(|d| d.contains("TEMP B-TREE")),
            "{name}: {details:?}"
        );
    }
}
