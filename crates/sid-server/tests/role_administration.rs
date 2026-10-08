// SPDX-License-Identifier: AGPL-3.0-only
//! Constrained role administration (D050 B) through the one mutation core,
//! on PostgreSQL (port 54399) and SQLite. Using a role and granting it are
//! independent rights; one administrative envelope must cover a whole
//! change; redelegation only narrows and ends with its source.

use std::sync::Arc;

use sid_authz::admin::{Administrator, RoleAdministration};
use sid_core::Error;
use sid_core::models::{
    AdminEnvelope, AdminOperation, AuditEntry, AuthzPrincipal, Group, GroupMember, MutationContext,
    Profile, ProfileId, ProjectId, RecipientKind, Role, RoleAssignment, RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;
use uuid::Uuid;

fn audit() -> MutationContext {
    AuditEntry::system("test", "role-administration").into()
}

async fn postgres() -> Arc<dyn StorageBackend> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    Arc::new(backend)
}

async fn sqlite() -> Arc<dyn StorageBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    )
}

/// An installation with an Accountant role, an administrative role, an
/// access administrator holding an envelope for Accountant, and workers.
struct Office {
    storage: Arc<dyn StorageBackend>,
    core: RoleAdministration,
    accountant: Role,
    auditor: Role,
    administrator_role: Role,
    root: Administrator,
    access_admin: ProfileId,
    access_admin_grant: RoleAssignment,
}

fn tag() -> String {
    Uuid::now_v7().simple().to_string()
}

async fn profile(storage: &Arc<dyn StorageBackend>) -> ProfileId {
    let profile = Profile::new(Some(format!("p{}", tag())));
    storage.create_profile(&profile, audit()).await.unwrap();
    profile.id
}

async fn role(storage: &Arc<dyn StorageBackend>, permissions: &[&str]) -> Role {
    storage.ensure_system_project(audit()).await.unwrap();
    let t = tag();
    let mut role = Role::new(ProjectId::system(), format!("k{t}"), format!("n{t}"));
    role.permissions = permissions.iter().map(|p| p.to_string()).collect();
    storage.create_role(&role, audit()).await.unwrap();
    storage.get_role(role.id).await.unwrap().unwrap()
}

fn envelope(roles: &[&Role], ceiling: &[&str], kinds: &[RecipientKind]) -> AdminEnvelope {
    AdminEnvelope {
        operations: [AdminOperation::Assign, AdminOperation::Revoke].into(),
        roles: roles.iter().map(|r| r.id).collect(),
        permission_ceiling: ceiling.iter().map(|p| p.to_string()).collect(),
        recipient_kinds: kinds.iter().copied().collect(),
        recipient_group: None,
        max_validity_secs: 90 * 86_400,
    }
}

fn in_days(days: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::days(days)
}

impl Office {
    async fn new(storage: Arc<dyn StorageBackend>) -> Self {
        let accountant = role(&storage, &["ledger.read", "ledger.post"]).await;
        let auditor = role(&storage, &["ledger.read"]).await;
        let administrator_role = role(&storage, &["roles.administer"]).await;
        let installation_admin = profile(&storage).await;
        let root = Administrator::Root(AuthzPrincipal::Profile(installation_admin));
        let core = RoleAdministration::new(storage.clone());
        let access_admin = profile(&storage).await;
        let access_admin_grant = core
            .assign(
                &root,
                RoleAssignment::new(
                    RoleAssignmentPrincipal::Profile(access_admin),
                    administrator_role.id,
                )
                .administering(envelope(
                    &[&accountant],
                    &["ledger.read", "ledger.post"],
                    &[RecipientKind::Profile],
                )),
                audit(),
            )
            .await
            .unwrap();
        Self {
            storage,
            core,
            accountant,
            auditor,
            administrator_role,
            root,
            access_admin,
            access_admin_grant,
        }
    }

    fn admin(&self) -> Administrator {
        Administrator::Holder(AuthzPrincipal::Profile(self.access_admin))
    }

    fn accountant_for(&self, worker: ProfileId, days: i64) -> RoleAssignment {
        RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), self.accountant.id)
            .with_expiry(in_days(days))
    }

    async fn holds_through_groups(&self, who: ProfileId) -> bool {
        !self
            .storage
            .list_groups_for_profile(who)
            .await
            .unwrap()
            .is_empty()
    }

    async fn holds(&self, who: ProfileId, role: &Role) -> bool {
        self.storage
            .list_role_assignments_for_profile(who)
            .await
            .unwrap()
            .iter()
            .any(|a| a.role_id == role.id)
    }
}

fn denied(result: sid_core::Result<impl std::fmt::Debug>) {
    let err = result.expect_err("not covered");
    assert!(matches!(err, Error::AuthorizationDenied(_)), "{err:?}");
}

/// The access administrator assigns Accountant to an eligible worker
/// without holding Accountant, and the record names the administrator and
/// the authorizing assignment; a worker holding Accountant cannot grant it.
async fn administration_is_independent_of_use(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let worker = profile(&o.storage).await;
    let granted = o
        .core
        .assign(&o.admin(), o.accountant_for(worker, 30), audit())
        .await
        .unwrap();
    assert!(o.holds(worker, &o.accountant).await);
    assert!(!o.holds(o.access_admin, &o.accountant).await);
    let provenance = granted.provenance.expect("provenance");
    assert_eq!(provenance.granted_by, format!("user:{}", o.access_admin));
    assert_eq!(provenance.basis, Some(o.access_admin_grant.id));
    assert_eq!(provenance.depends_on, None);

    let colleague = profile(&o.storage).await;
    denied(
        o.core
            .assign(
                &Administrator::Holder(AuthzPrincipal::Profile(worker)),
                o.accountant_for(colleague, 1),
                audit(),
            )
            .await,
    );
    assert!(!o.holds(colleague, &o.accountant).await);
}

/// Every bound refuses on its own, before anything is written: another
/// role, a recipient kind not permitted, another scope, no expiry or one
/// beyond the maximum, and the same role id after its content grew.
async fn every_bound_refuses(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let worker = profile(&o.storage).await;
    denied(
        o.core
            .assign(
                &o.admin(),
                RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), o.auditor.id)
                    .with_expiry(in_days(1)),
                audit(),
            )
            .await,
    );
    let group = Group::new(ProjectId::system(), format!("g{}", tag()));
    o.storage.create_group(&group, audit()).await.unwrap();
    denied(
        o.core
            .assign(
                &o.admin(),
                RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), o.accountant.id)
                    .with_expiry(in_days(1)),
                audit(),
            )
            .await,
    );
    let mut scoped = o.accountant_for(worker, 1);
    scoped.scope = Some(format!("project:{}", Uuid::now_v7()));
    denied(o.core.assign(&o.admin(), scoped, audit()).await);
    denied(
        o.core
            .assign(
                &o.admin(),
                RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), o.accountant.id),
                audit(),
            )
            .await,
    );
    denied(
        o.core
            .assign(&o.admin(), o.accountant_for(worker, 91), audit())
            .await,
    );
    let mut grown = o.accountant.clone();
    grown.permissions.push("payroll.read".into());
    assert!(o.storage.update_role(&grown, audit()).await.unwrap());
    denied(
        o.core
            .assign(&o.admin(), o.accountant_for(worker, 1), audit())
            .await,
    );
    assert!(!o.holds(worker, &o.accountant).await, "nothing written");
}

/// An administrator cannot assign to itself, directly or through a group
/// it belongs to: the envelope does not imply self-assignment.
async fn self_assignment_is_refused(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    denied(
        o.core
            .assign(&o.admin(), o.accountant_for(o.access_admin, 1), audit())
            .await,
    );
    assert!(!o.holds(o.access_admin, &o.accountant).await);
}

/// Two envelopes are never combined: one grants Accountant to Profiles,
/// another Auditor to Groups; Accountant to a Group and Auditor to a
/// Profile are each covered by neither.
async fn envelopes_are_not_combined(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    o.core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(o.access_admin),
                o.administrator_role.id,
            )
            .administering(envelope(
                &[&o.auditor],
                &["ledger.read"],
                &[RecipientKind::Group],
            )),
            audit(),
        )
        .await
        .unwrap();
    let group = Group::new(ProjectId::system(), format!("g{}", tag()));
    o.storage.create_group(&group, audit()).await.unwrap();
    let worker = profile(&o.storage).await;
    denied(
        o.core
            .assign(
                &o.admin(),
                RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), o.accountant.id)
                    .with_expiry(in_days(1)),
                audit(),
            )
            .await,
    );
    denied(
        o.core
            .assign(
                &o.admin(),
                RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), o.auditor.id)
                    .with_expiry(in_days(1)),
                audit(),
            )
            .await,
    );
    o.core
        .assign(
            &o.admin(),
            RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), o.auditor.id)
                .with_expiry(in_days(1)),
            audit(),
        )
        .await
        .expect("the second envelope covers this one whole");
}

/// A recipient group restriction admits only its members, and a member
/// removed before the commit is refused by the fence.
async fn a_recipient_group_admits_members_only(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let group = Group::new(ProjectId::system(), format!("g{}", tag()));
    o.storage.create_group(&group, audit()).await.unwrap();
    let member = profile(&o.storage).await;
    o.storage
        .add_to_group(&GroupMember::new(group.id, member), audit())
        .await
        .unwrap();
    let outsider = profile(&o.storage).await;
    let mut restricted = envelope(&[&o.auditor], &["ledger.read"], &[RecipientKind::Profile]);
    restricted.recipient_group = Some(group.id);
    let department_admin = profile(&o.storage).await;
    o.core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(department_admin),
                o.administrator_role.id,
            )
            .administering(restricted),
            audit(),
        )
        .await
        .unwrap();
    let admin = Administrator::Holder(AuthzPrincipal::Profile(department_admin));
    let auditor_for = |who| {
        RoleAssignment::new(RoleAssignmentPrincipal::Profile(who), o.auditor.id)
            .with_expiry(in_days(1))
    };
    denied(o.core.assign(&admin, auditor_for(outsider), audit()).await);
    o.core
        .assign(&admin, auditor_for(member), audit())
        .await
        .expect("a member is eligible");
}

/// Revocation needs its own right on the role; a working role holder
/// cannot revoke.
async fn revocation_needs_its_right(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let worker = profile(&o.storage).await;
    let granted = o
        .core
        .assign(&o.admin(), o.accountant_for(worker, 30), audit())
        .await
        .unwrap();
    denied(
        o.core
            .revoke(
                &Administrator::Holder(AuthzPrincipal::Profile(worker)),
                granted.id,
                audit(),
            )
            .await,
    );
    assert!(
        o.core
            .revoke(&o.admin(), granted.id, audit())
            .await
            .unwrap()
    );
    assert!(!o.holds(worker, &o.accountant).await);
    // A holder is not told whether an assignment exists; the root is.
    denied(o.core.revoke(&o.admin(), granted.id, audit()).await);
    assert!(
        !o.core.revoke(&o.root, granted.id, audit()).await.unwrap(),
        "already gone"
    );
}

/// Redelegation needs its right and only narrows; the redelegated
/// administrator's authority ends with its source, while assignments made
/// under the source as ordinary grants remain.
async fn redelegation_narrows_and_depends(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let mut delegable = envelope(
        &[&o.accountant],
        &["ledger.read", "ledger.post"],
        &[RecipientKind::Profile],
    );
    delegable.operations.insert(AdminOperation::Redelegate);
    let lead = profile(&o.storage).await;
    let lead_grant = o
        .core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(lead),
                o.administrator_role.id,
            )
            .administering(delegable.clone())
            .with_expiry(in_days(60)),
            audit(),
        )
        .await
        .unwrap();
    let lead_admin = Administrator::Holder(AuthzPrincipal::Profile(lead));
    let deputy = profile(&o.storage).await;
    let mut narrower = delegable.clone();
    narrower.operations = [AdminOperation::Assign].into();
    let redelegate = |env: AdminEnvelope| {
        RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(deputy),
            o.administrator_role.id,
        )
        .administering(env)
        .with_expiry(in_days(30))
    };

    // The plain access administrator has no redelegation right.
    denied(
        o.core
            .assign(&o.admin(), redelegate(narrower.clone()), audit())
            .await,
    );
    // Wider than the source: refused.
    let mut wider = narrower.clone();
    wider.permission_ceiling.insert("payroll.read".into());
    denied(o.core.assign(&lead_admin, redelegate(wider), audit()).await);

    let deputy_grant = o
        .core
        .assign(&lead_admin, redelegate(narrower), audit())
        .await
        .unwrap();
    let provenance = deputy_grant.provenance.clone().unwrap();
    assert_eq!(provenance.depends_on, Some(lead_grant.id));

    let deputy_admin = Administrator::Holder(AuthzPrincipal::Profile(deputy));
    let worker = profile(&o.storage).await;
    o.core
        .assign(&lead_admin, o.accountant_for(worker, 10), audit())
        .await
        .unwrap();
    let other = profile(&o.storage).await;
    o.core
        .assign(&deputy_admin, o.accountant_for(other, 10), audit())
        .await
        .unwrap();

    assert!(
        o.core
            .revoke(&o.root, lead_grant.id, audit())
            .await
            .unwrap()
    );
    assert!(
        o.storage
            .get_role_assignment(deputy_grant.id)
            .await
            .unwrap()
            .is_none(),
        "the redelegated authority ended with its source"
    );
    assert!(
        o.holds(worker, &o.accountant).await,
        "ordinary grants remain"
    );
    assert!(
        o.holds(other, &o.accountant).await,
        "ordinary grants remain"
    );
    let late = profile(&o.storage).await;
    denied(
        o.core
            .assign(&deputy_admin, o.accountant_for(late, 1), audit())
            .await,
    );
}

/// A provisioning connector keeps its purpose limits: no one, not even the
/// root, makes it an administrator.
async fn a_connector_never_administers(storage: Arc<dyn StorageBackend>) {
    use sid_core::models::{OrgId, ProvisioningConnector, ProvisioningDirection};
    let o = Office::new(storage).await;
    let hr = ProvisioningConnector::new(OrgId::generate(), ProvisioningDirection::Inbound, "HR");
    o.storage
        .create_provisioning_connector(&hr, audit())
        .await
        .unwrap();
    let connector = hr.id;
    let err = o
        .core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::ProvisioningConnector(connector),
                o.administrator_role.id,
            )
            .administering(envelope(
                &[&o.auditor],
                &["ledger.read"],
                &[RecipientKind::Profile],
            )),
            audit(),
        )
        .await
        .expect_err("a connector never administers");
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(
        o.storage
            .list_role_assignments_for_provisioning_connector(connector)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn current(o: &Office, role: &Role) -> Role {
    o.storage.get_role(role.id).await.unwrap().unwrap()
}

/// A role never outgrows the ceiling an envelope approved one of its
/// assignments under, even after the approving administrator left: the
/// root's widening edit is refused until that assignment is reauthorized;
/// narrowing is always possible.
async fn a_role_never_outgrows_an_approved_ceiling(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let worker = profile(&o.storage).await;
    let granted = o
        .core
        .assign(&o.admin(), o.accountant_for(worker, 30), audit())
        .await
        .unwrap();
    assert_eq!(
        granted.provenance.as_ref().and_then(|p| p.ceiling.clone()),
        Some(["ledger.post".to_string(), "ledger.read".to_string()].into())
    );
    // The access administrator leaves; the grant and its bound remain.
    assert!(
        o.core
            .revoke(&o.root, o.access_admin_grant.id, audit())
            .await
            .unwrap()
    );

    let mut grown = current(&o, &o.accountant).await;
    grown.permissions.push("payroll.read".into());
    let err = o
        .core
        .edit_role(&o.root, &grown, audit())
        .await
        .expect_err("past the approved ceiling");
    assert!(matches!(err, Error::InvalidState(_)), "{err:?}");
    assert!(
        !current(&o, &o.accountant)
            .await
            .has_permission("payroll.read")
    );

    let mut narrowed = current(&o, &o.accountant).await;
    narrowed.permissions = vec!["ledger.read".into()];
    assert!(o.core.edit_role(&o.root, &narrowed, audit()).await.unwrap());

    // Reauthorized by the root, the assignment no longer binds the role.
    o.core
        .assign(&o.root, o.accountant_for(worker, 30), audit())
        .await
        .unwrap();
    assert!(o.core.revoke(&o.root, granted.id, audit()).await.unwrap());
    let mut grown = current(&o, &o.accountant).await;
    grown.permissions.push("payroll.read".into());
    assert!(o.core.edit_role(&o.root, &grown, audit()).await.unwrap());
    assert!(
        current(&o, &o.accountant)
            .await
            .has_permission("payroll.read")
    );
}

/// Editing a role is its own right: an assigner cannot edit, an editor
/// edits only its envelope's roles and only within its ceiling.
async fn role_editing_is_its_own_right(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let mut narrowed = current(&o, &o.accountant).await;
    narrowed.permissions = vec!["ledger.read".into()];
    denied(o.core.edit_role(&o.admin(), &narrowed, audit()).await);

    let editor = profile(&o.storage).await;
    let mut edits = envelope(
        &[&o.accountant],
        &["ledger.read", "ledger.post"],
        &[RecipientKind::Profile],
    );
    edits.operations = [AdminOperation::EditRole].into();
    o.core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(editor),
                o.administrator_role.id,
            )
            .administering(edits),
            audit(),
        )
        .await
        .unwrap();
    let as_editor = Administrator::Holder(AuthzPrincipal::Profile(editor));
    assert!(
        o.core
            .edit_role(&as_editor, &narrowed, audit())
            .await
            .unwrap()
    );
    let mut past = current(&o, &o.accountant).await;
    past.permissions.push("payroll.read".into());
    denied(o.core.edit_role(&as_editor, &past, audit()).await);
    let mut other = current(&o, &o.auditor).await;
    other.description = Some("another role".into());
    denied(o.core.edit_role(&as_editor, &other, audit()).await);
    assert!(
        !current(&o, &o.accountant)
            .await
            .has_permission("payroll.read")
    );
}

/// An administrator that granted a group a role can never join that group
/// afterwards: the grant would reach its own grantor.
async fn a_grantor_never_joins_the_group_it_granted(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let team_admin = profile(&o.storage).await;
    o.core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(team_admin),
                o.administrator_role.id,
            )
            .administering(envelope(
                &[&o.auditor],
                &["ledger.read"],
                &[RecipientKind::Group],
            )),
            audit(),
        )
        .await
        .unwrap();
    let team = Group::new(ProjectId::system(), format!("g{}", tag()));
    o.storage.create_group(&team, audit()).await.unwrap();
    o.core
        .assign(
            &Administrator::Holder(AuthzPrincipal::Profile(team_admin)),
            RoleAssignment::new(RoleAssignmentPrincipal::Group(team.id), o.auditor.id)
                .with_expiry(in_days(5)),
            audit(),
        )
        .await
        .unwrap();
    let err = o
        .storage
        .add_to_group(&GroupMember::new(team.id, team_admin), audit())
        .await
        .expect_err("the grantor joins its own grant");
    assert!(matches!(err, Error::PolicyViolation(_)), "{err:?}");
    assert!(!o.holds_through_groups(team_admin).await);
}

/// A redelegation never outlives its source: it may not run past the
/// source's expiry, nor go without one, so an expired source leaves no
/// dependent authority behind. An ordinary grant is bounded the same way.
async fn a_redelegation_never_outlives_its_source(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let mut delegable = envelope(
        &[&o.accountant],
        &["ledger.read", "ledger.post"],
        &[RecipientKind::Profile],
    );
    delegable.operations.insert(AdminOperation::Redelegate);
    let lead = profile(&o.storage).await;
    o.core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(lead),
                o.administrator_role.id,
            )
            .administering(delegable.clone())
            .with_expiry(in_days(10)),
            audit(),
        )
        .await
        .unwrap();
    let lead_admin = Administrator::Holder(AuthzPrincipal::Profile(lead));
    let deputy = profile(&o.storage).await;
    let mut narrower = delegable.clone();
    narrower.operations = [AdminOperation::Assign].into();
    let redelegate = |until: Option<i64>| {
        let assignment = RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(deputy),
            o.administrator_role.id,
        )
        .administering(narrower.clone());
        match until {
            Some(days) => assignment.with_expiry(in_days(days)),
            None => assignment,
        }
    };
    denied(
        o.core
            .assign(&lead_admin, redelegate(Some(20)), audit())
            .await,
    );
    denied(o.core.assign(&lead_admin, redelegate(None), audit()).await);
    let worker = profile(&o.storage).await;
    denied(
        o.core
            .assign(&lead_admin, o.accountant_for(worker, 20), audit())
            .await,
    );
    o.core
        .assign(&lead_admin, redelegate(Some(9)), audit())
        .await
        .expect("within the source's validity");
}

const RACES: usize = 100;

/// How long the second side of race `round` waits: fine steps first for an
/// in-memory engine's microsecond windows, then coarse ones for a networked
/// engine's millisecond windows.
fn stagger(round: usize) -> std::time::Duration {
    let micros = if round < 20 {
        5 * round
    } else {
        60 * (round - 20)
    };
    std::time::Duration::from_micros(micros as u64)
}

/// A widening role edit racing an approved grant never leaves the role
/// past the grant's ceiling: one of them gives way every time.
async fn a_role_edit_racing_a_grant_keeps_the_ceiling(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    for round in 0..RACES {
        let worker = profile(&o.storage).await;
        let mut grown = current(&o, &o.accountant).await;
        grown.permissions = vec![
            "ledger.read".into(),
            "ledger.post".into(),
            format!("extra.{}", tag()),
        ];
        let admin = o.admin();
        // The edit starts a little later each round, so its check lands at
        // every point of the grant's checks and transaction.
        let delay = stagger(round);
        let (granted, edited) = tokio::join!(
            o.core.assign(&admin, o.accountant_for(worker, 5), audit()),
            async {
                tokio::time::sleep(delay).await;
                o.core.edit_role(&o.root, &grown, audit()).await
            },
        );
        let role = current(&o, &o.accountant).await;
        let bound = o
            .storage
            .list_role_assignments_for_role(o.accountant.id)
            .await
            .unwrap();
        for a in &bound {
            if let Some(ceiling) = a.provenance.as_ref().and_then(|p| p.ceiling.as_ref()) {
                assert!(
                    role.permissions.iter().all(|p| ceiling.contains(p)),
                    "role {:?} past ceiling {ceiling:?} (grant {granted:?}, edit {edited:?})",
                    role.permissions
                );
            }
        }
        // Reset for the next round: narrow back, drop the grants.
        for a in bound {
            o.core.revoke(&o.root, a.id, audit()).await.unwrap();
        }
        let mut reset = current(&o, &o.accountant).await;
        reset.permissions = vec!["ledger.read".into(), "ledger.post".into()];
        assert!(o.core.edit_role(&o.root, &reset, audit()).await.unwrap());
    }
}

/// A grant to a group racing its grantor joining that group never ends
/// with both: the grant reaching its own grantor.
async fn a_membership_racing_a_grant_never_reaches_the_grantor(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    let team_admin = profile(&o.storage).await;
    o.core
        .assign(
            &o.root,
            RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(team_admin),
                o.administrator_role.id,
            )
            .administering(envelope(
                &[&o.auditor],
                &["ledger.read"],
                &[RecipientKind::Group],
            )),
            audit(),
        )
        .await
        .unwrap();
    let as_team_admin = Administrator::Holder(AuthzPrincipal::Profile(team_admin));
    for round in 0..RACES {
        let team = Group::new(ProjectId::system(), format!("g{}", tag()));
        o.storage.create_group(&team, audit()).await.unwrap();
        let joining = GroupMember::new(team.id, team_admin);
        let delay = stagger(round);
        let (granted, joined) = tokio::join!(
            o.core.assign(
                &as_team_admin,
                RoleAssignment::new(RoleAssignmentPrincipal::Group(team.id), o.auditor.id)
                    .with_expiry(in_days(5)),
                audit(),
            ),
            async {
                tokio::time::sleep(delay).await;
                o.storage.add_to_group(&joining, audit()).await
            },
        );
        let member = o
            .storage
            .list_group_members(team.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.profile_id == team_admin);
        let held = !o
            .storage
            .list_role_assignments_for_group(team.id)
            .await
            .unwrap()
            .is_empty();
        assert!(
            !(member && held),
            "the grant reached its grantor (grant {granted:?}, join {joined:?})"
        );
        assert_eq!(member, joined.is_ok());
        assert_eq!(held, granted.is_ok());
    }
}

/// A grant racing the revocation of its basis is either committed whole
/// (an ordinary grant outlives its basis) or refused as no longer covered,
/// writing nothing; the revocation always applies.
async fn a_revocation_racing_a_grant_leaves_no_orphan(storage: Arc<dyn StorageBackend>) {
    let o = Office::new(storage).await;
    for round in 0..RACES {
        let admin = profile(&o.storage).await;
        let basis = o
            .core
            .assign(
                &o.root,
                RoleAssignment::new(
                    RoleAssignmentPrincipal::Profile(admin),
                    o.administrator_role.id,
                )
                .administering(envelope(
                    &[&o.auditor],
                    &["ledger.read"],
                    &[RecipientKind::Profile],
                )),
                audit(),
            )
            .await
            .unwrap();
        let worker = profile(&o.storage).await;
        let holder = Administrator::Holder(AuthzPrincipal::Profile(admin));
        let (granted, revoked) = tokio::join!(
            o.core.assign(
                &holder,
                RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), o.auditor.id)
                    .with_expiry(in_days(5)),
                audit(),
            ),
            async {
                tokio::time::sleep(stagger(round)).await;
                o.core.revoke(&o.root, basis.id, audit()).await
            },
        );
        assert!(revoked.unwrap(), "the root's revocation always applies");
        match granted {
            Ok(_) => assert!(o.holds(worker, &o.auditor).await),
            Err(Error::Fenced(_) | Error::AuthorizationDenied(_)) => {
                assert!(!o.holds(worker, &o.auditor).await, "nothing written");
            }
            Err(other) => panic!("unexpected refusal {other:?}"),
        }
    }
}

macro_rules! on_both_engines {
    ($($scenario:ident),* $(,)?) => {
        mod on_postgres {
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario(super::postgres().await).await;
                }
            )*
        }
        mod on_sqlite {
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario(super::sqlite().await).await;
                }
            )*
        }
    };
}

on_both_engines!(
    administration_is_independent_of_use,
    every_bound_refuses,
    self_assignment_is_refused,
    envelopes_are_not_combined,
    a_recipient_group_admits_members_only,
    revocation_needs_its_right,
    redelegation_narrows_and_depends,
    a_connector_never_administers,
    a_role_never_outgrows_an_approved_ceiling,
    role_editing_is_its_own_right,
    a_grantor_never_joins_the_group_it_granted,
    a_redelegation_never_outlives_its_source,
    a_role_edit_racing_a_grant_keeps_the_ceiling,
    a_membership_racing_a_grant_never_reaches_the_grantor,
    a_revocation_racing_a_grant_leaves_no_orphan,
);
