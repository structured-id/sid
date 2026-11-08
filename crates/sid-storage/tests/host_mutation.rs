// SPDX-License-Identifier: AGPL-3.0-only
//! A host's own table beside CE's in one SQL database: its mutation is
//! finalized like every storage mutation, in its own transaction. Its row
//! commits only together with the audit record, the operation completion
//! and the fence check, or not at all.
//!
//! PostgreSQL needs the SID test stack (port 54399, or
//! `SID_STORAGE_TEST_DATABASE_URL`); SQLite runs in memory.
#![cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]

use sid_core::Error;
use sid_core::models::{
    ActorFence, AuditEntry, MutationContext, OperationCompletion, OperationKey,
    ProvisioningConnectorId, ProvisioningCredentialId,
};
use sid_plugin::AuditLog;
use uuid::Uuid;

/// The host table the scenarios write.
const CREATE_HOST_TABLE: &str =
    "CREATE TABLE IF NOT EXISTS host_mutation_items (id TEXT PRIMARY KEY)";

fn chain() -> String {
    format!("host:{}", Uuid::now_v7())
}

fn audit(id: &str) -> MutationContext {
    AuditEntry::system("host.item_created", id).into()
}

fn keyed(id: &str, namespace: &str, key: &OperationKey) -> MutationContext {
    audit(id).with_operation(OperationCompletion::new(
        namespace,
        key.clone(),
        "host.item_created",
        b"inputs",
        id.as_bytes().to_vec(),
    ))
}

/// A fence of a connector that does not exist: it never holds.
fn stale_fence() -> ActorFence {
    ActorFence::Connector {
        connector: ProvisioningConnectorId::generate(),
        revision: 0,
        credential: ProvisioningCredentialId::generate(),
    }
}

#[cfg(feature = "storage-pg")]
mod postgres {
    use super::*;
    use sid_storage::PostgresBackend;
    use sid_storage::audit_log::PostgresAuditLog;
    use sqlx::PgPool;

    async fn backend() -> PostgresBackend {
        let url = std::env::var("SID_STORAGE_TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://sid:sid_dev@localhost:54399/sid_storage_test".to_string()
        });
        let backend = PostgresBackend::new(&url, None)
            .await
            .expect("the SID test PostgreSQL on port 54399");
        sid_storage::migrator::run_migrations(backend.pool(), None)
            .await
            .expect("migrations");
        backend
    }

    async fn pool() -> PgPool {
        let pool = backend().await.pool().clone();
        // Concurrent `CREATE TABLE IF NOT EXISTS` races on PostgreSQL's
        // catalog: the scenarios create the table one at a time.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(7262)")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(CREATE_HOST_TABLE)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        pool
    }

    /// Insert host row `id` and finalize the transaction under `ctx`.
    async fn write(
        pool: &PgPool,
        chain: &str,
        id: &str,
        ctx: MutationContext,
    ) -> Result<(), Error> {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO host_mutation_items (id) VALUES ($1)")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        PostgresBackend::audit_in_tx(&mut tx, chain, ctx).await?;
        tx.commit().await.unwrap();
        Ok(())
    }

    async fn exists(pool: &PgPool, id: &str) -> bool {
        sqlx::query("SELECT 1 FROM host_mutation_items WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .is_some()
    }

    // The host row commits with its audit record, which reads back and
    // verifies in its chain.
    #[tokio::test]
    async fn a_host_mutation_commits_with_its_audit() {
        let pool = pool().await;
        let (chain, id) = (chain(), Uuid::now_v7().to_string());
        write(&pool, &chain, &id, audit(&id)).await.unwrap();
        assert!(exists(&pool, &id).await);
        let log = PostgresAuditLog::new(pool.clone());
        let records = log.query(&chain, None, None).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "host.item_created");
        assert!(log.verify_chain(&chain).await.unwrap().valid);
    }

    // Regression guard: a retry under a completed operation key and a write
    // whose fence no longer holds commit neither the host row nor an audit
    // record.
    #[tokio::test]
    async fn a_refused_finalization_rolls_the_host_row_back() {
        let pool = pool().await;
        let (chain, namespace) = (chain(), format!("host:{}", Uuid::now_v7()));
        let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
        let first = Uuid::now_v7().to_string();
        write(&pool, &chain, &first, keyed(&first, &namespace, &key))
            .await
            .unwrap();
        let retry = Uuid::now_v7().to_string();
        let refused = write(&pool, &chain, &retry, keyed(&retry, &namespace, &key)).await;
        assert!(
            matches!(refused, Err(Error::OperationCompleted(_))),
            "{refused:?}"
        );
        assert!(!exists(&pool, &retry).await);

        let fenced = Uuid::now_v7().to_string();
        let refused = write(
            &pool,
            &chain,
            &fenced,
            audit(&fenced).fenced_by(stale_fence()),
        )
        .await;
        assert!(refused.is_err(), "a stale fence committed");
        assert!(!exists(&pool, &fenced).await);

        let log = PostgresAuditLog::new(pool.clone());
        assert_eq!(log.query(&chain, None, None).await.unwrap().len(), 1);
        assert!(log.verify_chain(&chain).await.unwrap().valid);
    }

    // Regression: a sign-in that expires while its mutation waits for the
    // session row's lock fences the mutation. Its transaction began while
    // the sign-in was live, so the expiry is compared with the clock once
    // the lock is held, not with the transaction's start.
    #[tokio::test]
    async fn a_sign_in_expiring_during_a_lock_wait_fences_the_mutation() {
        use sid_core::models::{Profile, Session};
        use sid_plugin::storage::StorageBackend;

        let backend = backend().await;
        let pool = pool().await;
        let profile = Profile::new(Some(&format!("fenced-{}", Uuid::now_v7().simple())));
        backend
            .create_profile(&profile, audit("profile"))
            .await
            .unwrap();
        let session = Session::new(
            profile.id,
            None,
            chrono::Utc::now() + chrono::Duration::seconds(2),
        );
        backend
            .create_session(&session, audit("session"))
            .await
            .unwrap();

        // Another transaction holds the session row.
        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM sessions WHERE id = $1 FOR UPDATE")
            .bind(session.id)
            .execute(&mut *holder)
            .await
            .unwrap();
        let (chain, id) = (chain(), Uuid::now_v7().to_string());
        let fence = ActorFence::Session {
            session: session.id,
            profile: profile.id,
            fresh_until: None,
        };
        let writer = {
            let (pool, chain, id) = (pool.clone(), chain.clone(), id.clone());
            tokio::spawn(
                async move { write(&pool, &chain, &id, audit(&id).fenced_by(fence)).await },
            )
        };
        // The writer begins while the sign-in is live and waits for the
        // lock until after it expires.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        holder.commit().await.unwrap();

        let refused = writer.await.unwrap();
        assert!(matches!(refused, Err(Error::Fenced(_))), "{refused:?}");
        assert!(!exists(&pool, &id).await);
    }

    // Writers of one chain at once, on separate connections: each record
    // follows the one before it and the chain verifies, never forked from
    // one head.
    #[tokio::test]
    async fn concurrent_host_writers_extend_one_chain() {
        let pool = pool().await;
        let chain = chain();
        let ids: Vec<String> = (0..8).map(|_| Uuid::now_v7().to_string()).collect();
        let writes = ids.iter().map(|id| write(&pool, &chain, id, audit(id)));
        for result in futures::future::join_all(writes).await {
            result.unwrap();
        }
        let log = PostgresAuditLog::new(pool.clone());
        let records = log.query(&chain, None, None).await.unwrap();
        assert_eq!(records.len(), ids.len());
        let sequences: Vec<u64> = records.iter().map(|r| r.sequence).collect();
        assert_eq!(sequences, (1..=ids.len() as u64).collect::<Vec<_>>());
        assert!(log.verify_chain(&chain).await.unwrap().valid);
    }
}

#[cfg(feature = "storage-sqlite")]
mod sqlite {
    use super::*;
    use sid_storage::sqlite::{SqliteAuditLog, SqliteBackend};
    use sqlx::SqlitePool;

    async fn pool() -> SqlitePool {
        let backend = SqliteBackend::new_in_memory().await.unwrap();
        let pool = backend.pool().clone();
        sqlx::query(CREATE_HOST_TABLE).execute(&pool).await.unwrap();
        pool
    }

    async fn write(
        pool: &SqlitePool,
        chain: &str,
        id: &str,
        ctx: MutationContext,
    ) -> Result<(), Error> {
        let mut tx = SqliteBackend::begin_write_on(pool).await?;
        sqlx::query("INSERT INTO host_mutation_items (id) VALUES (?)")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        SqliteBackend::commit_mutation(tx, chain, ctx).await
    }

    async fn exists(pool: &SqlitePool, id: &str) -> bool {
        sqlx::query("SELECT 1 FROM host_mutation_items WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .is_some()
    }

    // The host row commits with its audit record, which reads back and
    // verifies in its chain.
    #[tokio::test]
    async fn a_host_mutation_commits_with_its_audit() {
        let pool = pool().await;
        let (chain, id) = (chain(), Uuid::now_v7().to_string());
        write(&pool, &chain, &id, audit(&id)).await.unwrap();
        assert!(exists(&pool, &id).await);
        let log = SqliteAuditLog::new(pool.clone());
        let records = log.query(&chain, None, None).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "host.item_created");
        assert!(log.verify_chain(&chain).await.unwrap().valid);
    }

    // Regression guard: a retry under a completed operation key and a write
    // whose fence no longer holds commit neither the host row nor an audit
    // record.
    #[tokio::test]
    async fn a_refused_finalization_rolls_the_host_row_back() {
        let pool = pool().await;
        let (chain, namespace) = (chain(), format!("host:{}", Uuid::now_v7()));
        let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
        let first = Uuid::now_v7().to_string();
        write(&pool, &chain, &first, keyed(&first, &namespace, &key))
            .await
            .unwrap();
        let retry = Uuid::now_v7().to_string();
        let refused = write(&pool, &chain, &retry, keyed(&retry, &namespace, &key)).await;
        assert!(
            matches!(refused, Err(Error::OperationCompleted(_))),
            "{refused:?}"
        );
        assert!(!exists(&pool, &retry).await);

        let fenced = Uuid::now_v7().to_string();
        let refused = write(
            &pool,
            &chain,
            &fenced,
            audit(&fenced).fenced_by(stale_fence()),
        )
        .await;
        assert!(refused.is_err(), "a stale fence committed");
        assert!(!exists(&pool, &fenced).await);

        let log = SqliteAuditLog::new(pool.clone());
        assert_eq!(log.query(&chain, None, None).await.unwrap().len(), 1);
        assert!(log.verify_chain(&chain).await.unwrap().valid);
    }
}
