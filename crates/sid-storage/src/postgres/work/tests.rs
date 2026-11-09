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
    WorkKind::new(&format!("test.capacity_{}", uuid::Uuid::now_v7().simple())).unwrap()
}

/// Work a business mutation owes is admitted under the same per-kind bound
/// as a standalone enqueue: while one mutation that filled the last place
/// is uncommitted, a concurrent one waits for it and is then refused, so
/// independent mutations never pass the capacity between them.
#[tokio::test]
async fn owed_work_of_concurrent_mutations_respects_its_capacity() {
    let pool = pool().await;
    let kind = fresh_kind();
    let capacity = 1;

    let mut first = pool.begin().await.unwrap();
    insert_owed_work_in_tx(&mut first, &[NewWork::new(kind.clone(), vec![])], capacity)
        .await
        .unwrap();
    let second = {
        let pool = pool.clone();
        let kind = kind.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            let admitted =
                insert_owed_work_in_tx(&mut tx, &[NewWork::new(kind, vec![])], capacity).await;
            if admitted.is_ok() {
                tx.commit().await.unwrap();
            }
            admitted
        })
    };
    // The second mutation has its insert in flight before the first commits.
    tokio::time::sleep(Duration::from_millis(300)).await;
    first.commit().await.unwrap();

    let second = second.await.unwrap();
    assert!(
        matches!(second, Err(SidError::ResourceExhausted(_))),
        "the second mutation passed the capacity: {second:?}"
    );
    let open: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM durable_work WHERE kind = $1 AND state IN ('pending', 'claimed')",
    )
    .bind(kind.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(open, 1);
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
}

/// The open count admission reads follows every transition of the work:
/// claimed and retried work stays open, completed, failed and expired work
/// leaves it, so capacity is admitted without counting the rows.
#[tokio::test]
async fn the_open_count_follows_each_transition() {
    let pool = pool().await;
    let store = PgWorkStore::new(pool.clone());
    let kind = fresh_kind();
    let open = async || -> i64 {
        sqlx::query_scalar(
            "SELECT COALESCE(SUM(open), 0)::BIGINT FROM durable_work_open WHERE kind = $1",
        )
        .bind(kind.as_str())
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let lease = Duration::from_secs(60);
    for _ in 0..4 {
        store
            .enqueue_work(&NewWork::new(kind.clone(), vec![]), 100)
            .await
            .unwrap();
    }
    let mut expiring = NewWork::new(kind.clone(), vec![]);
    expiring.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    store.enqueue_work(&expiring, 100).await.unwrap();
    assert_eq!(open().await, 5);

    // The expired one leaves at the claim's sweep; claimed ones stay open.
    let claimed = store
        .claim_work(std::slice::from_ref(&kind), "w", 4, lease)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 4);
    assert_eq!(open().await, 4);

    let retry = WorkFailure {
        error: "retry".into(),
        retry_at: Some(chrono::Utc::now()),
        ambiguous: false,
        on_dead: None,
    };
    assert!(
        store
            .fail_work(claimed[0].id, claimed[0].generation, &retry)
            .await
            .unwrap()
    );
    assert_eq!(open().await, 4, "a retried item stays open");
    let dead = WorkFailure {
        retry_at: None,
        ..retry
    };
    assert!(
        store
            .fail_work(claimed[1].id, claimed[1].generation, &dead)
            .await
            .unwrap()
    );
    assert!(
        store
            .complete_work(claimed[2].id, claimed[2].generation, None)
            .await
            .unwrap()
    );
    assert_eq!(open().await, 2);
    // A repeated outcome under a stale generation changes nothing.
    assert!(
        !store
            .complete_work(claimed[2].id, claimed[2].generation, None)
            .await
            .unwrap()
    );
    assert_eq!(open().await, 2);
}

/// A completion owing work of its own kind takes the kind's admission lock
/// before its state change touches the open count, the order an enqueue
/// takes them: an enqueue holding the lock whose item falls in the
/// completed item's count shard and the completion both commit. Taken the
/// other way, the completion held the shard while waiting for the lock the
/// enqueue held while waiting for the shard, and one of them was aborted as
/// a deadlock.
#[tokio::test]
async fn a_completion_owing_its_kind_beside_an_enqueue_commits_both() {
    let pool = pool().await;
    let store = PgWorkStore::new(pool.clone());
    let kind = fresh_kind();
    let parent = NewWork::new(kind.clone(), vec![]);
    store.enqueue_work(&parent, 100).await.unwrap();
    let claimed = store
        .claim_work(std::slice::from_ref(&kind), "w", 1, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);

    // The enqueue holds the kind's lock first, as it does before inserting.
    let mut enqueue = pool.begin().await.unwrap();
    lock_kind(&mut enqueue, &kind).await.unwrap();
    let completion = {
        let store = PgWorkStore::new(pool.clone());
        let (id, generation) = (claimed[0].id, claimed[0].generation);
        let child = NewWork::new(kind.clone(), vec![]);
        tokio::spawn(async move {
            store
                .complete_work_owing(id, generation, None, &[child], 100)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    // An item in the parent's count shard.
    let mut bytes = *uuid::Uuid::now_v7().as_bytes();
    bytes[15] = parent.id.0.as_bytes()[15];
    let mut same_shard = NewWork::new(kind.clone(), vec![]);
    same_shard.id = WorkId(uuid::Uuid::from_bytes(bytes));
    insert_work_in_tx(&mut enqueue, &same_shard, 100)
        .await
        .expect("the enqueue commits");
    enqueue.commit().await.unwrap();
    assert!(
        completion.await.unwrap().expect("the completion commits"),
        "the completion was fenced"
    );
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

/// A mutation owing work of several kinds takes their admission locks in one
/// order, so two mutations owing the same kinds in opposite orders both
/// commit instead of deadlocking.
#[tokio::test]
async fn owed_work_of_several_kinds_does_not_deadlock() {
    let pool = pool().await;
    let (a, b) = (fresh_kind(), fresh_kind());
    let owe = |kinds: Vec<WorkKind>| {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            let works: Vec<NewWork> = kinds.into_iter().map(|k| NewWork::new(k, vec![])).collect();
            insert_owed_work_in_tx(&mut tx, &works, 10).await?;
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
