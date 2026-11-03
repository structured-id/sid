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
