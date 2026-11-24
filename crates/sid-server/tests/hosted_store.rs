// SPDX-License-Identifier: AGPL-3.0-only
//! An installation opened over a store its host opened: the process names no
//! storage setting, and the installation keeps its records where the host
//! put them.
#![cfg(all(feature = "ui", feature = "storage-pg"))]

#[path = "common/hosted.rs"]
mod hosted;

use std::sync::Arc;

use hosted::{ISSUER, configure, database_url, free_address, get};
use sid_server::init::{CeHost, HostStore, init_ce_with};

/// A host's SQLite file that another server already serves on a durable bus
/// is refused to an installation with the in-process bus: that bus reaches
/// its own process only, so work the other server addresses would be claimed
/// here and never delivered.
/// Bug prevented: the file's bus lock skipped because the host, not the
/// server, opened the store.
async fn a_sqlite_file_another_server_serves_is_refused(data: &std::path::Path) {
    let file = data.join("host.db");
    let backend = sid_storage::sqlite::SqliteBackend::new(file.to_str().unwrap())
        .await
        .unwrap();
    // The lock a server on a durable bus holds on the file.
    let mut lock = file.clone().into_os_string();
    lock.push(".bus.lock");
    let other = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock)
        .unwrap();
    other.try_lock_shared().unwrap();

    let refused = init_ce_with(CeHost {
        store: Some(HostStore {
            audit_log: Arc::new(sid_storage::sqlite::SqliteAuditLog::new(
                backend.writer().clone(),
            )),
            history_keys: Arc::new(backend.history_keys()),
            storage: Arc::new(backend),
            sqlite_file: Some(file),
        }),
        ..Default::default()
    })
    .await;
    let Err(why) = refused else {
        panic!("the installation opened beside another server on the file");
    };
    assert!(
        format!("{why:#}").contains("the in-process bus serves one process"),
        "{why:#}"
    );
}

/// A host opens the database itself, prepares its schema and hands the open
/// store to the installation: the installation is opened over that store,
/// answers through the hosted service, and its records are in the host's
/// schema.
/// Bug prevented: an installation that can only connect to a database it is
/// told the address of, so a host cannot keep SID's records in the store it
/// already holds.
async fn the_installation_keeps_its_records_in_the_hosts_store() {
    let schema = format!("hosted_{}", uuid::Uuid::new_v4().simple());
    let backend =
        sid_storage::PostgresBackend::connect(&database_url(), Some(schema.clone()), None)
            .await
            .expect("the test PostgreSQL is running");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .unwrap();
    let history = sid_storage::PgHistoryKeyStore::new(backend.pool().clone());
    history.migrate().await.unwrap();
    let pool = backend.pool().clone();

    let c = init_ce_with(CeHost {
        store: Some(HostStore {
            audit_log: Arc::new(sid_storage::audit_log::PostgresAuditLog::new(pool.clone())),
            history_keys: Arc::new(history),
            storage: Arc::new(backend),
            sqlite_file: None,
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    let services = sid_server::serve::CeServices::new(&c, Default::default())
        .await
        .unwrap();
    let hosted = sid_server::serve::hosted(c, services, serde_json::json!({})).unwrap();

    let discovery = get(&hosted.http, "/.well-known/openid-configuration").await;
    assert_eq!(discovery["issuer"], ISSUER);
    // The installation's issuer is recorded in the host's schema, which the
    // host's pool resolves unqualified names in.
    let (resolved, issuers): (String, i64) =
        sqlx::query_as("SELECT current_schema()::text, (SELECT count(*) FROM oidc_issuers)")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(resolved, schema);
    assert!(issuers > 0);
    hosted.background.drain().await.unwrap();
}

/// The scenarios of a host-given store, under one set of process settings:
/// no storage setting, the in-process bus.
#[test]
fn a_host_gives_the_installation_its_store() {
    let data = tempfile::tempdir().unwrap();
    configure(&[
        ("SID_DATA_DIR", data.path().to_str().unwrap().to_owned()),
        ("SID_ISSUER", ISSUER.to_owned()),
        ("SID_GRPC_BIND", free_address().to_string()),
        ("SID_NATS_URL", "in-process".to_owned()),
    ]);
    assert!(std::env::var_os("SID_DATABASE_URL").is_none());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        a_sqlite_file_another_server_serves_is_refused(data.path()).await;
        the_installation_keeps_its_records_in_the_hosts_store().await;
    });
    runtime.shutdown_background();
}
