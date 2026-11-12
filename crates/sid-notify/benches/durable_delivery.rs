// SPDX-License-Identifier: AGPL-3.0-only
//! Durable delivery cost ([`sid_notify::bench`]) on file-backed SQLite
//! (embedded), PostgreSQL (a fresh `sid_notify_bench` on the server
//! `SID_BENCH_POSTGRES_URL`) and JetStream handoff into PostgreSQL.
//!
//! `cargo bench -p sid-notify --bench durable_delivery`

use std::sync::Arc;

use sid_notify::bench;

/// The modes `SID_BENCH_MODES` names (comma-separated: `sqlite`, `postgres`,
/// `jetstream`), all of them when unset.
fn modes() -> Vec<String> {
    match std::env::var("SID_BENCH_MODES") {
        Ok(list) => list.split(',').map(|m| m.trim().to_string()).collect(),
        Err(_) => vec!["sqlite".into(), "postgres".into(), "jetstream".into()],
    }
}

#[tokio::main]
async fn main() {
    if let Ok(phase) = std::env::var("CXBR_BENCHMARK_PHASE") {
        // The measurement host's quiet window: everything below is measured.
        std::process::Command::new(&phase)
            .arg("begin")
            .status()
            .unwrap();
    }
    for mode in modes() {
        match mode.as_str() {
            "sqlite" => {
                let dir = tempfile::tempdir().unwrap();
                let file = dir.path().join("work.db");
                let sqlite =
                    sid_storage::sqlite::SqliteBackend::new(&format!("sqlite:{}", file.display()))
                        .await
                        .unwrap();
                bench::store_modes("sqlite", Arc::new(sqlite), None).await;
            }
            "postgres" => {
                let (store, pool) = bench::postgres().await;
                bench::durability(&pool).await;
                bench::store_modes("postgres", store, Some(&pool)).await;
            }
            "jetstream" => bench::handoff(bench::postgres().await.0).await,
            other => panic!("unknown mode {other}: sqlite, postgres or jetstream"),
        }
    }
    if let Ok(phase) = std::env::var("CXBR_BENCHMARK_PHASE") {
        std::process::Command::new(&phase)
            .arg("end")
            .status()
            .unwrap();
    }
}
