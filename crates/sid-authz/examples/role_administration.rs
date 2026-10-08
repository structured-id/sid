// SPDX-License-Identifier: AGPL-3.0-only
//! Constrained role administration in an embedding application.
//!
//! The installation's administrator lets an access administrator assign the
//! Accountant role. The access administrator gives it to a worker without
//! ever holding it: the worker can then read the ledger, the access
//! administrator still cannot, and nothing outside the envelope is allowed.
//! Revoking the grant ends the worker's access.
//!
//! `cargo run -p sid-authz --example role_administration`

use std::sync::Arc;

use sid_authz::CeAuthzEngine;
use sid_authz::admin::{Administrator, RoleAdministration};
use sid_core::models::{
    AdminEnvelope, AdminOperation, AuditEntry, AuthzPrincipal, MutationContext, Profile, ProfileId,
    ProjectId, RecipientKind, Role, RoleAssignment, RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;
use sid_plugin::authz::{AuthzCheckRequest, AuthzEngine};

fn audit() -> MutationContext {
    AuditEntry::system("example", "role-administration").into()
}

async fn profile(storage: &Arc<dyn StorageBackend>, name: &str) -> ProfileId {
    let profile = Profile::new(Some(name));
    storage.create_profile(&profile, audit()).await.unwrap();
    profile.id
}

async fn role(storage: &Arc<dyn StorageBackend>, key: &str, permissions: &[&str]) -> Role {
    let mut role = Role::new(ProjectId::system(), key, key);
    role.permissions = permissions.iter().map(|p| p.to_string()).collect();
    storage.create_role(&role, audit()).await.unwrap();
    storage.get_role(role.id).await.unwrap().unwrap()
}

/// Whether `who` may read the ledger.
async fn reads_ledger(engine: &CeAuthzEngine<dyn StorageBackend>, who: ProfileId) -> bool {
    engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{who}"),
            action: "ledger.read".into(),
            resource: format!("project:{}", ProjectId::system().0),
            context: Default::default(),
        })
        .await
        .unwrap()
        .is_allowed()
}

#[tokio::main]
async fn main() {
    let storage: Arc<dyn StorageBackend> = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    );
    storage.ensure_system_project(audit()).await.unwrap();
    let engine = CeAuthzEngine::new(storage.clone());
    let core = RoleAdministration::new(storage.clone());

    let accountant = role(&storage, "accountant", &["ledger.read", "ledger.post"]).await;
    let access_admin_role = role(&storage, "access-admin", &["roles.administer"]).await;
    let root = Administrator::Root(AuthzPrincipal::Profile(
        profile(&storage, "installation-admin").await,
    ));
    let access_admin = profile(&storage, "access-admin").await;
    let worker = profile(&storage, "worker").await;

    // 1. The root grants the right to assign Accountant to Profiles, for at
    //    most 90 days, while Accountant holds no more than these permissions.
    core.assign(
        &root,
        RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(access_admin),
            access_admin_role.id,
        )
        .administering(AdminEnvelope {
            operations: [AdminOperation::Assign, AdminOperation::Revoke].into(),
            roles: [accountant.id].into(),
            permission_ceiling: ["ledger.read".to_string(), "ledger.post".to_string()].into(),
            recipient_kinds: [RecipientKind::Profile].into(),
            recipient_group: None,
            max_validity_secs: 90 * 86_400,
        }),
        audit(),
    )
    .await
    .expect("the root grants the envelope");

    // 2. The access administrator assigns Accountant to the worker.
    let holder = Administrator::Holder(AuthzPrincipal::Profile(access_admin));
    let granted = core
        .assign(
            &holder,
            RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), accountant.id)
                .with_expiry(chrono::Utc::now() + chrono::Duration::days(30)),
            audit(),
        )
        .await
        .expect("covered by the envelope");
    println!("granted {:?}", granted.provenance);

    // 3. The worker uses it; the access administrator never gained it.
    assert!(reads_ledger(&engine, worker).await);
    assert!(!reads_ledger(&engine, access_admin).await);

    // 4. Outside the envelope: to itself, without an expiry, beyond 90 days.
    for refused in [
        RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(access_admin),
            accountant.id,
        )
        .with_expiry(chrono::Utc::now() + chrono::Duration::days(1)),
        RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), accountant.id),
        RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), accountant.id)
            .with_expiry(chrono::Utc::now() + chrono::Duration::days(120)),
    ] {
        let err = core.assign(&holder, refused, audit()).await.unwrap_err();
        assert!(
            matches!(err, sid_core::Error::AuthorizationDenied(_)),
            "{err:?}"
        );
    }

    // 5. Revoking the grant ends the worker's access.
    assert!(core.revoke(&holder, granted.id, audit()).await.unwrap());
    assert!(!reads_ledger(&engine, worker).await);
    println!("grant, use, refusal and revocation behaved as the envelope allows");
}
