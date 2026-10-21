// SPDX-License-Identifier: AGPL-3.0-only
//! Permission check cost of the CE engine on SQLite (in memory) and
//! PostgreSQL (port 54399): P50/P99 and heap allocations per call of
//!
//! - `check allow`: a role assignment grants the action;
//! - `check deny`: no assignment grants it;
//! - `batch 16`: one batch of 16 questions, half allowed;
//!
//! and the throughput of `concurrent`: 32 tasks checking at once.
//!
//! `cargo bench -p sid-authz --bench check_latency`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sid_authz::AuthzCheckRequest;
use sid_core::models::{
    AuditEntry, MutationContext, Profile, ProfileId, ProjectId, Role, RoleAssignment,
    RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;

/// Counts heap allocations, so a call's allocations can be read off.
struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards every call to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract for `alloc` is passed on as is.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above, i.e. from `System`.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `ptr` came from this allocator, which is `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const CHECKS: usize = 2_000;
const BATCHES: usize = 500;
const BATCH: usize = 16;
const TASKS: usize = 32;
const PER_TASK: usize = 200;

fn audit() -> MutationContext {
    AuditEntry::system("bench", "check-latency").into()
}

async fn profile(storage: &Arc<dyn StorageBackend>) -> ProfileId {
    let profile = Profile::new(Some(format!("p{}", uuid::Uuid::now_v7().simple())));
    storage.create_profile(&profile, audit()).await.unwrap();
    profile.id
}

fn question(who: ProfileId, action: &str) -> AuthzCheckRequest {
    AuthzCheckRequest {
        subject: format!("user:{who}"),
        action: action.to_string(),
        resource: format!("project:{}", ProjectId::system().0),
        context: Default::default(),
    }
}

/// P50, P99 and allocations per call of `samples`.
fn report(engine: &str, what: &str, mut samples: Vec<Duration>, allocations: u64) {
    samples.sort_unstable();
    let at = |q: usize| samples[(samples.len() * q / 100).min(samples.len() - 1)];
    println!(
        "{engine:<9} {what:<12} n={:<5} p50={:>9.1?} p99={:>9.1?} allocs/call={:>6.1}",
        samples.len(),
        at(50),
        at(99),
        allocations as f64 / samples.len() as f64,
    );
}

async fn run(engine: &str, storage: Arc<dyn StorageBackend>) {
    storage.ensure_system_project(audit()).await.unwrap();
    let mut role = Role::new(ProjectId::system(), "reader", "Reader");
    role.permissions = vec!["ledger.read".into()];
    storage.create_role(&role, audit()).await.unwrap();
    let worker = profile(&storage).await;
    storage
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), role.id),
            audit(),
        )
        .await
        .unwrap();

    let authz = Arc::new(sid_authz::CeAuthzEngine::new(storage.clone()));
    let allowed = question(worker, "ledger.read");
    let denied = question(worker, "ledger.write");
    assert!(authz.check(&allowed).await.unwrap().is_allowed());
    assert!(!authz.check(&denied).await.unwrap().is_allowed());

    for (what, q) in [("check allow", &allowed), ("check deny", &denied)] {
        let mut samples = Vec::with_capacity(CHECKS);
        let before = ALLOCATIONS.load(Ordering::Relaxed);
        for _ in 0..CHECKS {
            let started = Instant::now();
            let decision = authz.check(q).await.unwrap();
            samples.push(started.elapsed());
            std::hint::black_box(decision);
        }
        let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
        report(engine, what, samples, allocations);
    }

    let batch: Vec<AuthzCheckRequest> = (0..BATCH)
        .map(|i| {
            if i % 2 == 0 {
                allowed.clone()
            } else {
                denied.clone()
            }
        })
        .collect();
    let mut samples = Vec::with_capacity(BATCHES);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..BATCHES {
        let started = Instant::now();
        let decisions = authz.batch_check(&batch).await.unwrap();
        samples.push(started.elapsed());
        assert_eq!(decisions.len(), BATCH);
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
    report(engine, "batch 16", samples, allocations);

    let started = Instant::now();
    let tasks: Vec<_> = (0..TASKS)
        .map(|_| {
            let (authz, q) = (authz.clone(), allowed.clone());
            tokio::spawn(async move {
                for _ in 0..PER_TASK {
                    assert!(authz.check(&q).await.unwrap().is_allowed());
                }
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed();
    println!(
        "{engine:<9} {:<12} {TASKS} tasks x {PER_TASK}: {:>8.0} checks/s",
        "concurrent",
        (TASKS * PER_TASK) as f64 / elapsed.as_secs_f64()
    );
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let sqlite: Arc<dyn StorageBackend> = Arc::new(
            sid_storage::sqlite::SqliteBackend::new_in_memory()
                .await
                .expect("in-memory SQLite"),
        );
        run("sqlite", sqlite).await;

        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into());
        let postgres = sid_storage::PostgresBackend::new(&url, None)
            .await
            .expect("PostgreSQL on port 54399 (sid-test-postgres)");
        sid_storage::migrator::run_migrations(postgres.pool(), None)
            .await
            .expect("migrations");
        run("postgres", Arc::new(postgres)).await;
    });
}
