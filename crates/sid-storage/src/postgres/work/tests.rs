// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;

use super::*;

fn database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_storage_test".to_string())
}

async fn pool() -> PgPool {
    let pool = PgPool::connect(&database_url())
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    crate::migrator::run_migrations(&pool, None)
        .await
        .expect("Failed to run migrations");
    pool
}

/// A kind no other test uses.
fn fresh_kind() -> WorkKind {
    WorkKind::new(&format!("test.work_{}", uuid::Uuid::now_v7().simple())).unwrap()
}

/// Mutations owing work of one kind do not wait on each other: while one is
/// still uncommitted, another owing the same kind commits at once. Admission
/// under a per-kind lock made every writer of a kind wait for the one ahead
/// of it to commit, and the waiters held the pool's connections.
#[tokio::test]
async fn mutations_owing_one_kind_commit_independently() {
    let pool = pool().await;
    let kind = fresh_kind();

    let mut first = pool.begin().await.unwrap();
    insert_owed_work_in_tx(&mut first, &[NewWork::new(kind.clone(), vec![])])
        .await
        .unwrap();
    let second = NewWork::new(kind.clone(), vec![]);
    let committed = tokio::time::timeout(Duration::from_secs(5), async {
        let mut tx = pool.begin().await.unwrap();
        insert_owed_work_in_tx(&mut tx, std::slice::from_ref(&second)).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))
    })
    .await;
    assert!(
        matches!(committed, Ok(Ok(()))),
        "the second mutation waited for the first: {committed:?}"
    );
    first.commit().await.unwrap();

    let store = PgWorkStore::new(pool);
    assert!(store.get_work(second.id).await.unwrap().is_some());
}

/// The plan of `sql` with the claim's parameters bound for `kinds`.
async fn plan(pool: &PgPool, sql: &str, kinds: &[&str]) -> String {
    // Built from this module's own statement constants, no outside input.
    let explained = sqlx::AssertSqlSafe(format!("EXPLAIN {sql}"));
    let mut query = sqlx::query_scalar::<_, String>(explained).bind(kinds);
    if sql.contains("$2") {
        query = query.bind("worker").bind(60.0_f64).bind(32_i64);
    }
    query.fetch_all(pool).await.unwrap().join("\n")
}

/// Every statement a claim runs reads its own index by kind and time, not
/// every open item: with thousands of items owed, the sweeps read each open
/// row and the due read sorted them all to take 32, so the claim loop slowed
/// with the backlog and bounded the drain.
#[tokio::test]
async fn a_claim_reads_only_due_work_through_its_indexes() {
    let pool = pool().await;
    let kinds = [fresh_kind(), fresh_kind()];
    for kind in &kinds {
        sqlx::query(
            "INSERT INTO durable_work (id, kind, payload, max_attempts, not_before)
             SELECT gen_random_uuid(), $1, '\\x00', 7, NOW() - (g || ' ms')::interval
             FROM generate_series(1, 3000) g",
        )
        .bind(kind.as_str())
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("ANALYZE durable_work")
        .execute(&pool)
        .await
        .unwrap();
    let kinds: Vec<&str> = kinds.iter().map(WorkKind::as_str).collect();
    for (name, sql, index) in [
        ("expire", EXPIRE_SQL, "idx_durable_work_expiry"),
        ("abandoned", ABANDONED_SQL, "idx_durable_work_lease"),
        ("due", CLAIM_SQL, "idx_durable_work_due"),
    ] {
        let plan = plan(&pool, sql, &kinds).await;
        assert!(plan.contains(index), "{name}: {plan}");
        assert!(!plan.contains("Seq Scan on durable_work"), "{name}: {plan}");
    }
    let claim = plan(&pool, CLAIM_SQL, &kinds).await;
    assert!(claim.contains("idx_durable_work_lease"), "{claim}");
    let sweep = plan(&pool, SWEEP_DUE_SQL, &kinds).await;
    for index in ["idx_durable_work_expiry", "idx_durable_work_lease"] {
        assert!(sweep.contains(index), "{sweep}");
    }
    assert!(!sweep.contains("Seq Scan on durable_work"), "{sweep}");
}

/// The claim statement itself never hands out work past its last attempt or
/// past its validity: such work can lapse after the sweeps ran and before
/// the claim, which runs as its own statement with a later clock. It once
/// relied on the sweeps, and so ran a last attempt again and claimed
/// expired work.
#[tokio::test]
async fn the_claim_skips_exhausted_and_expired_work_itself() {
    let pool = pool().await;
    let kind = fresh_kind();
    let rows = [
        // A last attempt whose lease ran out.
        "INSERT INTO durable_work (id, kind, payload, max_attempts, attempts, state,
             lease_until, not_before)
         VALUES (gen_random_uuid(), $1, '\\x00', 1, 1, 'claimed',
             NOW() - interval '1 second', NOW() - interval '1 minute')",
        // Due, but past its validity.
        "INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at)
         VALUES (gen_random_uuid(), $1, '\\x00', 3, NOW() - interval '1 minute',
             NOW() - interval '1 second')",
        // A lapsed lease, not yet past its validity, an attempt left: claimable.
        "INSERT INTO durable_work (id, kind, payload, max_attempts, attempts, state,
             lease_until, not_before, expires_at)
         VALUES (gen_random_uuid(), $1, '\\x00', 3, 1, 'claimed',
             NOW() - interval '1 second', NOW() - interval '1 minute',
             NOW() + interval '1 hour')",
    ];
    for sql in rows {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(kind.as_str())
            .execute(&pool)
            .await
            .unwrap();
    }
    let claimed = sqlx::query(CLAIM_SQL)
        .bind(vec![kind.as_str()])
        .bind("w")
        .bind(60.0_f64)
        .bind(10_i64)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "exhausted or expired work was claimed");
    let attempts: i32 = claimed[0].try_get("attempts").unwrap();
    assert_eq!(attempts, 2);
}

/// A host's own state change and the work it owes commit together through
/// `owe_in_tx`: rolled back, neither is stored; committed, the work is.
#[tokio::test]
async fn owed_work_commits_with_the_host_transaction() {
    let pool = pool().await;
    let kind = fresh_kind();
    let dropped = NewWork::new(kind.clone(), vec![1]);
    let mut tx = pool.begin().await.unwrap();
    PgWorkStore::owe_in_tx(&mut tx, std::slice::from_ref(&dropped))
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let kept = NewWork::new(kind, vec![2]);
    let mut tx = pool.begin().await.unwrap();
    PgWorkStore::owe_in_tx(&mut tx, std::slice::from_ref(&kept))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let store = PgWorkStore::new(pool);
    assert!(store.get_work(dropped.id).await.unwrap().is_none());
    assert!(store.get_work(kept.id).await.unwrap().is_some());
}

/// Two mutations owing the same kinds, named in opposite orders, both commit
/// while both are open: inserts of distinct work never wait on each other.
#[tokio::test]
async fn owed_work_of_several_kinds_does_not_deadlock() {
    let pool = pool().await;
    let (a, b) = (fresh_kind(), fresh_kind());
    let owe = |kinds: Vec<WorkKind>| {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            let works: Vec<NewWork> = kinds.into_iter().map(|k| NewWork::new(k, vec![])).collect();
            insert_owed_work_in_tx(&mut tx, &works).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            tx.commit()
                .await
                .map_err(|e| SidError::Storage(e.to_string()))
        })
    };
    let first = owe(vec![a.clone(), b.clone()]);
    let second = owe(vec![b, a]);
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
}

/// Work owed twice in one batch, or already stored, is stored once: the
/// batch insert keeps the first and skips the rest.
#[tokio::test]
async fn owed_work_already_stored_is_kept_once() {
    let pool = pool().await;
    let kind = fresh_kind();
    let item = NewWork::new(kind, vec![3]);
    let store = PgWorkStore::new(pool.clone());
    assert!(store.enqueue_work(&item).await.unwrap());
    let mut tx = pool.begin().await.unwrap();
    insert_owed_work_in_tx(&mut tx, &[item.clone(), item.clone()])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM durable_work WHERE id = $1")
        .bind(item.id.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);
}
