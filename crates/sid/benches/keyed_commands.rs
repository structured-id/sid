// SPDX-License-Identifier: AGPL-3.0-only
//! Cost of keyed commands through the engine, on the store's real commit
//! path (state, audit and completion in one write), with `CreateProject` as
//! the command:
//!
//! - `original`: P50/P99/P999 of a new command, one at a time;
//! - `retry`: a retry of a completed command, answered from its record;
//! - `conflict`: the same key with other inputs, refused before any effect;
//! - `parallel`: `WRITERS` callers committing new commands at once, which
//!   all count into one period: per-command latency and the rate;
//! - `hot`: `HOT_ATTEMPTS` attempts of one command at once, `HOT_ROUNDS`
//!   times: per-attempt latency, and one project per round;
//! - `growth`: the store's bytes per completed command;
//!
//! on file-backed SQLite (embedded) and PostgreSQL (a fresh schema on
//! `SID_BENCH_POSTGRES_URL`, the server without a database, default port
//! 54399). `SID_BENCH_MODES` (comma-separated `sqlite`, `postgres`) picks
//! the stores, both when unset.
//!
//! `cargo bench -p structured-id --bench keyed_commands`

use std::sync::Arc;
use std::time::{Duration, Instant};

use sid::projects::{ProjectError, Projects};
use sid_authn::caller::Caller;
use sid_core::models::{AuditEntry, OperationContext, OperationKey, OperationPeriod};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::CreateProjectRequest;

/// Commands measured one at a time for `original`, `retry` and `conflict`.
const SINGLES: usize = 2_000;
/// Concurrent callers of `parallel`, and the commands each commits.
const WRITERS: usize = 32;
const PER_WRITER: usize = 100;
/// Concurrent attempts of one command for `hot`, and how many commands.
const HOT_ATTEMPTS: usize = 64;
const HOT_ROUNDS: usize = 50;

/// P50, P99 and P999 of `samples`.
fn report(mode: &str, what: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let at = |q: usize| samples[(samples.len() * q / 1000).min(samples.len() - 1)];
    println!(
        "{mode:<9} {what:<9} n={:<6} p50={:>9.3?} p99={:>9.3?} p999={:>9.3?} max={:>9.3?}",
        samples.len(),
        at(500),
        at(990),
        at(999),
        samples[samples.len() - 1],
    );
}

/// An installation administrator, as a verified token describes one.
fn administrator() -> Caller {
    let now = chrono::Utc::now().timestamp();
    let profile = uuid::Uuid::now_v7().to_string();
    Caller::from_claims(&sid_authn::jwt::AccessTokenClaims {
        sub: profile.clone(),
        pid: Some(profile),
        iss: "https://sid.example.com".into(),
        aud: vec!["https://sid.example.com".into()],
        client_id: None,
        exp: now + 3_600,
        iat: now,
        auth_time: now,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: sid_authn::account_roles::ADMIN_ROLE_CLAIM.into(),
        sid: uuid::Uuid::now_v7().to_string(),
        amr: vec!["pwd".into()],
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
    })
    .expect("administrator claims")
}

fn keys() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .expect("bench key manager"),
    )
}

/// The engine's project operations over `storage`, prepared as an
/// installation prepares them.
async fn projects(storage: Arc<dyn StorageBackend>) -> Projects {
    storage
        .ensure_system_project(AuditEntry::system("project.ensure_system", "system").into())
        .await
        .unwrap();
    let organization = sid_authn::instance_org::ensure(storage.as_ref(), "sid.example.com")
        .await
        .unwrap();
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys().as_ref(),
        &url::Url::parse("https://sid.example.com").unwrap(),
        organization.id,
    )
    .await
    .unwrap();
    Projects::new(storage, issuer)
}

/// A new command's context under `period`.
fn command(period: OperationPeriod) -> OperationContext {
    OperationContext::new(
        OperationKey::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        period,
    )
}

fn create(name: &str) -> CreateProjectRequest {
    CreateProjectRequest {
        name: name.to_string(),
        ..Default::default()
    }
}

/// How many bytes the store holds now, as `size` reads it.
type Size = Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send>>>;

async fn run(mode: &str, storage: Arc<dyn StorageBackend>, size: Size) {
    let projects = Arc::new(projects(storage.clone()).await);
    let caller = administrator();
    let period = storage
        .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
        .await
        .unwrap()
        .period;

    let before = size().await;
    let mut originals = Vec::with_capacity(SINGLES);
    let mut samples = Vec::with_capacity(SINGLES);
    for i in 0..SINGLES {
        let context = command(period);
        let started = Instant::now();
        projects
            .create_project(&caller, context.clone(), create(&format!("p{i}")))
            .await
            .unwrap();
        samples.push(started.elapsed());
        originals.push((context, i));
    }
    let grown = size().await - before;
    report(mode, "original", samples);
    println!(
        "{mode:<9} growth    {} commands, {grown} bytes, {} bytes per command",
        SINGLES,
        grown / SINGLES as u64
    );

    let mut samples = Vec::with_capacity(SINGLES);
    for (context, i) in &originals {
        let started = Instant::now();
        projects
            .create_project(&caller, context.clone(), create(&format!("p{i}")))
            .await
            .unwrap();
        samples.push(started.elapsed());
    }
    report(mode, "retry", samples);

    let mut samples = Vec::with_capacity(SINGLES);
    for (context, i) in &originals {
        let started = Instant::now();
        let refused = projects
            .create_project(&caller, context.clone(), create(&format!("other{i}")))
            .await;
        samples.push(started.elapsed());
        assert!(
            matches!(refused, Err(ProjectError::Operation(_))),
            "another input under a used key was not refused as a conflict"
        );
    }
    report(mode, "conflict", samples);

    let started = Instant::now();
    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (projects, caller) = (projects.clone(), caller.clone());
            tokio::spawn(async move {
                let mut samples = Vec::with_capacity(PER_WRITER);
                for i in 0..PER_WRITER {
                    let started = Instant::now();
                    projects
                        .create_project(&caller, command(period), create(&format!("w{w}-{i}")))
                        .await
                        .unwrap();
                    samples.push(started.elapsed());
                }
                samples
            })
        })
        .collect();
    let mut samples = Vec::with_capacity(WRITERS * PER_WRITER);
    for writer in writers {
        samples.extend(writer.await.unwrap());
    }
    let took = started.elapsed();
    report(mode, "parallel", samples);
    println!(
        "{mode:<9} parallel  {} commands by {WRITERS} writers in {took:.3?}: {:.0}/s",
        WRITERS * PER_WRITER,
        (WRITERS * PER_WRITER) as f64 / took.as_secs_f64()
    );

    let mut samples = Vec::with_capacity(HOT_ATTEMPTS * HOT_ROUNDS);
    for round in 0..HOT_ROUNDS {
        let context = command(period);
        let attempts: Vec<_> = (0..HOT_ATTEMPTS)
            .map(|_| {
                let (projects, caller, context) =
                    (projects.clone(), caller.clone(), context.clone());
                tokio::spawn(async move {
                    let started = Instant::now();
                    let answer = projects
                        .create_project(&caller, context, create(&format!("hot{round}")))
                        .await;
                    (started.elapsed(), answer)
                })
            })
            .collect();
        let mut ids = std::collections::HashSet::new();
        for attempt in attempts {
            let (took, answer) = attempt.await.unwrap();
            samples.push(took);
            ids.insert(
                answer
                    .expect("every attempt answers")
                    .id
                    .expect("project id")
                    .value,
            );
        }
        assert_eq!(ids.len(), 1, "one command answered with several projects");
    }
    report(mode, "hot", samples);
}

/// The PostgreSQL server, without a database.
fn postgres_url() -> String {
    std::env::var("SID_BENCH_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399".into())
}

async fn postgres() {
    let schema = format!("keyed_bench_{}", uuid::Uuid::now_v7().simple());
    let backend =
        sid_storage::PostgresBackend::new(&format!("{}/sid", postgres_url()), Some(schema.clone()))
            .await
            .expect("bench PostgreSQL unreachable; start docker-compose.test.yml");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .unwrap();
    let pool = backend.pool().clone();
    let size: Size = {
        let schema = schema.clone();
        Box::new(move || {
            let (pool, schema) = (pool.clone(), schema.clone());
            Box::pin(async move {
                let bytes: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(sum(pg_total_relation_size(c.oid)), 0)::bigint \
                     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = $1 AND c.relkind = 'r'",
                )
                .bind(&schema)
                .fetch_one(&pool)
                .await
                .unwrap();
                u64::try_from(bytes).expect("a relation size is not negative")
            })
        })
    };
    run("postgres", Arc::new(backend), size).await;
}

async fn sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("sid.db");
    let backend = sid_storage::sqlite::SqliteBackend::new(&format!("sqlite:{}", file.display()))
        .await
        .unwrap();
    let size: Size = {
        let file = file.clone();
        Box::new(move || {
            let file = file.clone();
            Box::pin(async move {
                // The main file and its write-ahead log hold every committed page.
                let wal = file.with_extension("db-wal");
                std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0)
                    + std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0)
            })
        })
    };
    run("sqlite", Arc::new(backend), size).await;
}

fn modes() -> Vec<String> {
    match std::env::var("SID_BENCH_MODES") {
        Ok(list) => list.split(',').map(|m| m.trim().to_string()).collect(),
        Err(_) => vec!["sqlite".into(), "postgres".into()],
    }
}

#[tokio::main]
async fn main() {
    for mode in modes() {
        match mode.as_str() {
            "sqlite" => sqlite().await,
            "postgres" => postgres().await,
            other => panic!("unknown mode {other}: sqlite or postgres"),
        }
    }
}
