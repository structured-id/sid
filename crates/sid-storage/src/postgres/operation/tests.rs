// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration as StdDuration;

use super::*;

fn database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// A host operation store in a schema of its own, with a capacity of 32
/// (one completion per place), and a pool whose connections see only it.
async fn store() -> (PgOperationStore, PgPool, String) {
    let schema = format!("ops_{}", Uuid::now_v7().simple());
    let admin = PgPool::connect(&database_url())
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let url = database_url();
    let separator = if url.contains('?') { '&' } else { '?' };
    let pool = PgPool::connect(&format!(
        "{url}{separator}options=-c%20search_path%3D{schema}"
    ))
    .await
    .unwrap();
    let store = PgOperationStore::new(pool.clone());
    store.ensure_schema().await.unwrap();
    sqlx::query("UPDATE operation_period_state SET capacity = 32")
        .execute(&pool)
        .await
        .unwrap();
    (store, pool, schema)
}

/// A completion under `period` whose inputs' digest names `place` first.
fn completion_in(place: i16, period: OperationPeriod) -> OperationCompletion {
    (0u32..)
        .map(|i| {
            OperationCompletion::new(
                "places",
                OperationKey::parse(&Uuid::new_v4().to_string()).unwrap(),
                "keyed",
                format!("inputs-{i}").as_bytes(),
                b"done".to_vec(),
            )
            .in_period(period)
        })
        .find(|c| place_of(&c.fingerprint) == place)
        .expect("some inputs name every place")
}

/// Regression: a commit whose first place was being filled by another one
/// waited for it, kept that place locked once it found it full, and then
/// took every place in order behind a commit already holding place 0 and
/// waiting for its place: PostgreSQL aborted one of them as a deadlock.
/// Here A waits on place 1 behind X, B already holds place 0 and waits on
/// place 1; once X commits, both find room and commit.
#[tokio::test]
async fn a_full_first_place_is_released_before_every_place_is_taken() {
    let (store, pool, schema) = store().await;
    let period = store
        .current_operation_period(Utc::now(), Duration::minutes(5))
        .await
        .unwrap()
        .period;
    let number = column(period).unwrap();
    // Place 2 is full, so B's commit takes every place in order.
    sqlx::query("UPDATE operation_period_places SET recorded = 1 WHERE period = $1 AND place = 2")
        .bind(number)
        .execute(&pool)
        .await
        .unwrap();

    let mut x = pool.begin().await.unwrap();
    record_in_tx(&mut x, &completion_in(1, period))
        .await
        .unwrap();
    let commit = |c: OperationCompletion| {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            record_in_tx(&mut tx, &c).await?;
            tx.commit()
                .await
                .map_err(|e| SidError::Storage(e.to_string()))
        })
    };
    let a = commit(completion_in(1, period));
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    let b = commit(completion_in(2, period));
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    x.commit().await.unwrap();

    let outcomes = tokio::time::timeout(StdDuration::from_secs(20), async {
        (a.await.unwrap(), b.await.unwrap())
    })
    .await
    .expect("both commits finish");
    pool.close().await;
    let admin = PgPool::connect(&database_url()).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
    outcomes.0.expect("the commit that found its place full");
    outcomes.1.expect("the commit holding place 0");
}
