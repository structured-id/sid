// SPDX-License-Identifier: AGPL-3.0-only
//! An application embedding the engine decides permissions in its own
//! process: no listener, no service hop. The installation it opens on its
//! store answers with the fixed CE RBAC/ABAC decision, the same one the
//! service uses, on a SQLite file and on PostgreSQL (port 54399,
//! docker-compose.test.yml).
//!
//! Each scenario runs on both stores: a role grant allows, an explicit forbid
//! denies whatever the role grants, no grant denies, a role grants only in
//! its own project, a removed or expired assignment grants nothing, a
//! malformed subject is an error, and a batch answers in order. A decision
//! also holds after the installation is reopened on the same file.

use std::path::PathBuf;
use std::sync::Arc;

use sid::{Installation, InstallationSettings};
use sid_authn::jwt::AccessTokenTtl;
use sid_authz::{AuthzCheckRequest, AuthzCheckResponse, AuthzError};
use sid_core::models::{
    AuditEntry, CedarPolicy, MutationContext, PolicyEffect, PolicyScope, Profile, ProfileId,
    Project, ProjectId, Role, RoleAssignment, RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;

/// A directory of its own for the master key and the SQLite file, removed
/// at the end.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("sid-authorization-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn master_key(&self) -> PathBuf {
        self.0.join("master.key")
    }

    fn database(&self) -> String {
        format!("sqlite://{}", self.0.join("sid.db").display())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn open(storage: Arc<dyn StorageBackend>, scratch: &Scratch) -> Installation {
    Installation::open(
        storage,
        InstallationSettings {
            issuer: url::Url::parse("https://id.sid.example.com").unwrap(),
            master_key: scratch.master_key(),
            crypto: Arc::new(sid_crypto::RustCryptoPrimitives::new()),
            cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
            access_token_ttl: AccessTokenTtl::default(),
            management: None,
        },
    )
    .await
    .expect("the installation opens")
}

async fn sqlite(scratch: &Scratch) -> Arc<dyn StorageBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new(&scratch.database())
            .await
            .expect("a SQLite file"),
    )
}

/// A migrated store in a schema of its own: the installation it holds is
/// sealed under this run's master key, which no later run has.
async fn postgres(schema: &str) -> Arc<sid_storage::PostgresBackend> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string());
    let backend = sid_storage::PostgresBackend::new(&url, Some(schema.to_owned()))
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), Some(schema))
        .await
        .expect("migrations");
    Arc::new(backend)
}

fn audit() -> MutationContext {
    AuditEntry::system("test", "in-process authorization").into()
}

/// A project of its own, so decisions of concurrent tests on the shared
/// PostgreSQL never meet.
async fn project(storage: &Arc<dyn StorageBackend>) -> ProjectId {
    let project = Project::new(format!("authz-{}", uuid::Uuid::now_v7().simple()), None);
    storage.create_project(&project, audit()).await.unwrap();
    project.id
}

async fn profile(storage: &Arc<dyn StorageBackend>) -> ProfileId {
    let profile = Profile::new(Some(format!("p{}", uuid::Uuid::now_v7().simple())));
    storage.create_profile(&profile, audit()).await.unwrap();
    profile.id
}

/// A Profile holding a role of `project` that grants `action`, with the
/// assignment that grants it.
async fn granted(
    storage: &Arc<dyn StorageBackend>,
    project: ProjectId,
    action: &str,
) -> (ProfileId, RoleAssignment) {
    let who = profile(storage).await;
    let mut role = Role::new(project, "editor", "Editor");
    role.permissions = vec![action.to_string()];
    storage.create_role(&role, audit()).await.unwrap();
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(who), role.id);
    storage
        .create_role_assignment(&assignment, audit())
        .await
        .unwrap();
    (who, assignment)
}

fn question(who: ProfileId, action: &str, project: ProjectId) -> AuthzCheckRequest {
    AuthzCheckRequest {
        subject: format!("user:{who}"),
        action: action.to_string(),
        resource: format!("project:{project}"),
        context: Default::default(),
    }
}

async fn allowed(installation: &Installation, request: &AuthzCheckRequest) -> bool {
    installation
        .authorization
        .check(request)
        .await
        .expect("a decision")
        .is_allowed()
}

/// Every scenario on the installation `installation` opened.
async fn scenarios(installation: &Installation) {
    let storage = &installation.storage;

    // A role grant allows; the same Profile is denied an action no role
    // grants.
    let project_a = project(storage).await;
    let (editor, assignment) = granted(storage, project_a, "documents:write").await;
    assert!(
        allowed(
            installation,
            &question(editor, "documents:write", project_a)
        )
        .await
    );
    assert!(
        !allowed(
            installation,
            &question(editor, "documents:delete", project_a)
        )
        .await
    );

    // A Profile without any grant is denied.
    let stranger = profile(storage).await;
    assert!(
        !allowed(
            installation,
            &question(stranger, "documents:write", project_a)
        )
        .await
    );

    // A role grants only in its own project.
    let project_b = project(storage).await;
    assert!(
        !allowed(
            installation,
            &question(editor, "documents:write", project_b)
        )
        .await
    );

    // An explicit forbid of the project denies whatever the role grants.
    let project_c = project(storage).await;
    let (forbidden, _) = granted(storage, project_c, "documents:write").await;
    storage
        .create_cedar_policy(
            &CedarPolicy::new(
                PolicyScope::Project(project_c),
                "no-writes",
                r#"forbid(principal, action == Action::"documents:write", resource);"#,
                PolicyEffect::Forbid,
            ),
            audit(),
        )
        .await
        .unwrap();
    match installation
        .authorization
        .check(&question(forbidden, "documents:write", project_c))
        .await
        .expect("a decision")
    {
        AuthzCheckResponse::Deny { reason } => assert!(reason.contains("forbid"), "{reason}"),
        other => panic!("a forbid let the grant through: {other:?}"),
    }

    // An expired assignment grants nothing.
    let project_d = project(storage).await;
    let lapsed = profile(storage).await;
    let mut role = Role::new(project_d, "temporary", "Temporary");
    role.permissions = vec!["documents:write".into()];
    storage.create_role(&role, audit()).await.unwrap();
    let mut expired = RoleAssignment::new(RoleAssignmentPrincipal::Profile(lapsed), role.id);
    expired.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    storage
        .create_role_assignment(&expired, audit())
        .await
        .unwrap();
    assert!(
        !allowed(
            installation,
            &question(lapsed, "documents:write", project_d)
        )
        .await
    );

    // A batch answers each question in order.
    let answers = installation
        .authorization
        .batch_check(&[
            question(editor, "documents:write", project_a),
            question(stranger, "documents:write", project_a),
            question(editor, "documents:write", project_b),
        ])
        .await
        .expect("decisions");
    assert_eq!(
        answers
            .iter()
            .map(AuthzCheckResponse::is_allowed)
            .collect::<Vec<_>>(),
        [true, false, false]
    );

    // A malformed subject is an error, never a decision.
    assert!(matches!(
        installation
            .authorization
            .check(&AuthzCheckRequest {
                subject: "not-a-profile".into(),
                action: "documents:write".into(),
                resource: format!("project:{project_a}"),
                context: Default::default(),
            })
            .await,
        Err(AuthzError::InvalidSubject(_))
    ));

    // A removed assignment grants nothing from then on.
    storage
        .delete_role_assignment(assignment.id, audit())
        .await
        .unwrap();
    assert!(
        !allowed(
            installation,
            &question(editor, "documents:write", project_a)
        )
        .await
    );
}

#[tokio::test]
async fn an_embedded_installation_decides_on_a_sqlite_file() {
    let scratch = Scratch::new();
    let installation = open(sqlite(&scratch).await, &scratch).await;
    scenarios(&installation).await;
}

#[tokio::test]
async fn an_embedded_installation_decides_on_postgres() {
    let scratch = Scratch::new();
    let schema = format!("authz_{}", uuid::Uuid::now_v7().simple());
    let backend = postgres(&schema).await;
    let installation = open(backend.clone(), &scratch).await;
    scenarios(&installation).await;
    // The schema goes with the master key that sealed it.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(backend.pool())
    .await
    .unwrap();
}

/// A grant committed to the file is decided the same way by the
/// installation reopened on it, as after a restart of the host.
#[tokio::test]
async fn a_grant_holds_after_the_installation_is_reopened() {
    let scratch = Scratch::new();
    let (who, project_id) = {
        let installation = open(sqlite(&scratch).await, &scratch).await;
        let project_id = project(&installation.storage).await;
        let (who, _) = granted(&installation.storage, project_id, "documents:read").await;
        assert!(allowed(&installation, &question(who, "documents:read", project_id)).await);
        (who, project_id)
    };
    let reopened = open(sqlite(&scratch).await, &scratch).await;
    assert!(allowed(&reopened, &question(who, "documents:read", project_id)).await);
    assert!(!allowed(&reopened, &question(who, "documents:write", project_id)).await);
}
