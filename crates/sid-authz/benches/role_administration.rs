// SPDX-License-Identifier: AGPL-3.0-only
//! Latency of constrained role administration (D050 B), P50 and P99, on
//! SQLite (in memory) and PostgreSQL (port 54399):
//!
//! - `check`: a permission check of a working role an envelope granted;
//! - `assign`: a holder of several bounded envelopes assigns a role;
//! - `assign under edits`: the same while the root keeps editing the role,
//!   each fenced refusal retried until the assignment commits.
//!
//! `cargo bench -p sid-server --bench role_administration`

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sid_authz::admin::{Administrator, RoleAdministration};
use sid_core::models::{
    AdminEnvelope, AdminOperation, AuditEntry, AuthzPrincipal, MutationContext, Profile, ProfileId,
    ProjectId, RecipientKind, Role, RoleAssignment, RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;
use sid_plugin::authz::{AuthzCheckRequest, AuthzEngine};

const CHECKS: usize = 2_000;
const ASSIGNS: usize = 500;
const CONTENDED: usize = 300;
/// Bounded grant sources the holder carries, one envelope per role.
const SOURCES: usize = 5;

fn audit() -> MutationContext {
    AuditEntry::system("bench", "role-administration").into()
}

fn tag() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

async fn profile(storage: &Arc<dyn StorageBackend>) -> ProfileId {
    let profile = Profile::new(Some(format!("p{}", tag())));
    storage.create_profile(&profile, audit()).await.unwrap();
    profile.id
}

async fn role(storage: &Arc<dyn StorageBackend>, permissions: &[&str]) -> Role {
    let t = tag();
    let mut role = Role::new(ProjectId::system(), format!("k{t}"), format!("n{t}"));
    role.permissions = permissions.iter().map(|p| p.to_string()).collect();
    storage.create_role(&role, audit()).await.unwrap();
    storage.get_role(role.id).await.unwrap().unwrap()
}

/// P50 and P99 of `samples`.
fn report(engine: &str, what: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let at = |q: usize| samples[(samples.len() * q / 100).min(samples.len() - 1)];
    println!(
        "{engine:<10} {what:<20} n={:<5} p50={:>9.1?} p99={:>9.1?}",
        samples.len(),
        at(50),
        at(99)
    );
}

struct Setup {
    storage: Arc<dyn StorageBackend>,
    core: Arc<RoleAdministration>,
    holder: Administrator,
    roles: Vec<Role>,
    root: Administrator,
}

async fn setup(storage: Arc<dyn StorageBackend>) -> Setup {
    storage.ensure_system_project(audit()).await.unwrap();
    let core = Arc::new(RoleAdministration::new(storage.clone()));
    let root = Administrator::Root(AuthzPrincipal::Profile(profile(&storage).await));
    let administrator_role = role(&storage, &["roles.administer"]).await;
    let holder = profile(&storage).await;
    let mut roles = Vec::with_capacity(SOURCES);
    for i in 0..SOURCES {
        let read = format!("ledger{i}.read");
        let working = role(&storage, &[read.as_str()]).await;
        core.assign(
            &root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(holder),
                administrator_role.id,
            )
            .administering(AdminEnvelope {
                operations: [AdminOperation::Assign, AdminOperation::Revoke].into(),
                roles: [working.id].into(),
                permission_ceiling: [read].into(),
                recipient_kinds: [RecipientKind::Profile].into(),
                recipient_group: None,
                max_validity_secs: 30 * 86_400,
            }),
            audit(),
        )
        .await
        .unwrap();
        roles.push(working);
    }
    Setup {
        storage,
        core,
        holder: Administrator::Holder(AuthzPrincipal::Profile(holder)),
        roles,
        root,
    }
}

fn grant(role: &Role, to: ProfileId) -> RoleAssignment {
    RoleAssignment::new(RoleAssignmentPrincipal::Profile(to), role.id)
        .with_expiry(chrono::Utc::now() + chrono::Duration::days(5))
}

async fn run(engine: &str, storage: Arc<dyn StorageBackend>) {
    let s = setup(storage).await;
    // The last envelope covers the measured role: every other one is
    // examined first.
    let measured = s.roles.last().expect("roles").clone();

    // check
    let worker = profile(&s.storage).await;
    s.core
        .assign(&s.holder, grant(&measured, worker), audit())
        .await
        .unwrap();
    let authz = sid_authz::CeAuthzEngine::new(s.storage.clone());
    let question = AuthzCheckRequest {
        subject: format!("user:{worker}"),
        action: measured.permissions[0].clone(),
        resource: format!("project:{}", ProjectId::system().0),
        context: Default::default(),
    };
    let mut samples = Vec::with_capacity(CHECKS);
    for _ in 0..CHECKS {
        let started = Instant::now();
        let decision = authz.check(&question).await.unwrap();
        samples.push(started.elapsed());
        assert!(decision.is_allowed());
    }
    report(engine, "check", samples);

    // assign
    let mut workers = Vec::with_capacity(ASSIGNS);
    for _ in 0..ASSIGNS {
        workers.push(profile(&s.storage).await);
    }
    let mut samples = Vec::with_capacity(ASSIGNS);
    for worker in workers {
        let started = Instant::now();
        s.core
            .assign(&s.holder, grant(&measured, worker), audit())
            .await
            .unwrap();
        samples.push(started.elapsed());
    }
    report(engine, "assign", samples);

    // assign under edits
    let editing = Arc::new(AtomicBool::new(true));
    let editor = {
        let (core, storage, root, role_id, editing) = (
            s.core.clone(),
            s.storage.clone(),
            s.root.clone(),
            measured.id,
            editing.clone(),
        );
        tokio::spawn(async move {
            let mut edits = 0usize;
            while editing.load(Ordering::Relaxed) {
                let mut role = storage.get_role(role_id).await.unwrap().unwrap();
                role.description = Some(format!("edit {edits}"));
                // A concurrent grant may move nothing the edit depends on;
                // a stale read only means another round.
                if core.edit_role(&root, &role, audit()).await.unwrap() {
                    edits += 1;
                }
            }
            edits
        })
    };
    let mut workers = Vec::with_capacity(CONTENDED);
    for _ in 0..CONTENDED {
        workers.push(profile(&s.storage).await);
    }
    let mut samples = Vec::with_capacity(CONTENDED);
    let mut retries = 0usize;
    for worker in workers {
        let started = Instant::now();
        loop {
            match s
                .core
                .assign(&s.holder, grant(&measured, worker), audit())
                .await
            {
                Ok(_) => break,
                Err(sid_core::Error::Fenced(_)) => retries += 1,
                Err(other) => panic!("unexpected refusal {other:?}"),
            }
        }
        samples.push(started.elapsed());
    }
    editing.store(false, Ordering::Relaxed);
    let edits = editor.await.unwrap();
    report(engine, "assign under edits", samples);
    println!(
        "{engine:<10} {:<20} edits={edits} fenced retries={retries}",
        ""
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
