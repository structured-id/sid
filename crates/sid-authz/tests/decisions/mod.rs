// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine's decisions over a real store, called in process with no
//! listener: what each storage engine must give the fixed RBAC + Cedar
//! decision. Each harness runs every scenario against its backend.

use std::sync::Arc;

use jiff::{SignedDuration, Timestamp};
use sid_authz::{AuthzCheckRequest, AuthzError, CeAuthzEngine};
use sid_core::models::{
    AuditEntry, CedarPolicy, Group, GroupMember, MutationContext, PolicyEffect, PolicyScope,
    ProfileId, Project, ProjectId, ResourceId, Role, RoleAssignment, RoleAssignmentPrincipal,
    TOKEN_INTROSPECT,
};
use sid_plugin::StorageBackend;
use sid_plugin::conformance::backend::application::{application, instance_issuer, resource};
use sid_plugin::conformance::backend::create_test_profile;

type Store = Arc<dyn StorageBackend>;
type Engine = CeAuthzEngine<dyn StorageBackend>;

const FORBID_ALL: &str = "forbid(principal, action, resource);";
const PERMIT_ALL: &str = "permit(principal, action, resource);";

fn audit() -> MutationContext {
    AuditEntry::system("test", "authz-decisions").into()
}

/// A project with a registered protected resource, a stored user and a
/// role of the project granting `orders.cancel`, assigned to nobody yet.
struct World {
    storage: Store,
    engine: Engine,
    project: ProjectId,
    resource: ResourceId,
    user: ProfileId,
    role: Role,
}

async fn world(storage: Store) -> World {
    let project = Project::new(format!("decisions {}", uuid::Uuid::now_v7()), None);
    storage.create_project(&project, audit()).await.unwrap();
    let mut role = Role::new(
        project.id,
        format!("canceller_{}", uuid::Uuid::now_v7().simple()),
        "Canceller",
    );
    role.permissions = vec!["orders.cancel".into()];
    storage.create_role(&role, audit()).await.unwrap();
    let user = create_test_profile("decider");
    storage.create_profile(&user, audit()).await.unwrap();
    let issuer = instance_issuer(storage.as_ref()).await;
    let app = application(project.id, "Orders");
    let target = resource(&app, issuer);
    storage
        .create_application(&app, None, Some(&target), audit())
        .await
        .unwrap();
    World {
        engine: CeAuthzEngine::new(storage.clone()),
        storage,
        project: project.id,
        resource: target.id,
        user: user.id,
        role,
    }
}

impl World {
    /// Assign the role to `principal`, on the resource or across the project.
    async fn assign(
        &self,
        principal: RoleAssignmentPrincipal,
        on_resource: bool,
    ) -> RoleAssignment {
        let mut assignment = RoleAssignment::new(principal, self.role.id);
        if on_resource {
            assignment = assignment.on_resource(self.resource);
        }
        self.storage
            .create_role_assignment(&assignment, audit())
            .await
            .unwrap();
        assignment
    }

    async fn policy(&self, scope: PolicyScope, effect: PolicyEffect, text: &str) -> CedarPolicy {
        let policy = CedarPolicy::new(
            scope,
            format!("p-{}", uuid::Uuid::now_v7().simple()),
            text,
            effect,
        );
        self.storage
            .create_cedar_policy(&policy, audit())
            .await
            .unwrap();
        policy
    }

    fn on_resource(&self, user: ProfileId, action: &str) -> AuthzCheckRequest {
        AuthzCheckRequest {
            subject: format!("user:{user}"),
            action: action.into(),
            resource: format!("oauth_resource:{}", self.resource),
            context: Default::default(),
        }
    }

    fn on_project(&self, project: ProjectId, action: &str) -> AuthzCheckRequest {
        AuthzCheckRequest {
            subject: format!("user:{}", self.user),
            action: action.into(),
            resource: format!("project:{project}"),
            context: Default::default(),
        }
    }

    async fn allowed(&self, engine: &Engine, request: &AuthzCheckRequest) -> bool {
        engine.check(request).await.unwrap().is_allowed()
    }

    /// Whether the user may cancel on the resource, by this world's engine.
    async fn cancels(&self) -> bool {
        self.allowed(&self.engine, &self.on_resource(self.user, "orders.cancel"))
            .await
    }
}

/// A project role grants its own actions in its own project, nothing else
/// and nowhere else.
pub async fn a_project_grant_allows_its_action_only(storage: Store) {
    let w = world(storage).await;
    let cancel = w.on_project(w.project, "orders.cancel");
    assert!(!w.allowed(&w.engine, &cancel).await, "nothing assigned yet");
    w.assign(RoleAssignmentPrincipal::Profile(w.user), false)
        .await;
    assert!(w.allowed(&w.engine, &cancel).await, "the role's action");
    assert!(
        !w.allowed(&w.engine, &w.on_project(w.project, "orders.delete"))
            .await,
        "an action the role does not hold"
    );
    let other = Project::new(format!("other {}", uuid::Uuid::now_v7()), None);
    w.storage.create_project(&other, audit()).await.unwrap();
    assert!(
        !w.allowed(&w.engine, &w.on_project(other.id, "orders.cancel"))
            .await,
        "another project"
    );
}

/// A resource grant is denied by a forbid of the installation, of the
/// resource's parent project and of the resource itself, and works again
/// once the forbid is deleted or disabled: the engine's compiled sets follow
/// the stored policies.
pub async fn a_forbid_at_every_scope_denies_a_grant_while_it_stands(storage: Store) {
    let w = world(storage).await;
    w.assign(RoleAssignmentPrincipal::Profile(w.user), true)
        .await;
    assert!(w.cancels().await, "the grant alone");
    for scope in [
        PolicyScope::Installation,
        PolicyScope::Project(w.project),
        PolicyScope::Resource(w.resource),
    ] {
        let forbid = w.policy(scope, PolicyEffect::Forbid, FORBID_ALL).await;
        assert!(!w.cancels().await, "{scope:?} forbid");
        w.storage
            .delete_cedar_policy(forbid.id, audit())
            .await
            .unwrap();
        assert!(w.cancels().await, "{scope:?} forbid deleted");
    }
    let mut forbid = w
        .policy(
            PolicyScope::Resource(w.resource),
            PolicyEffect::Forbid,
            FORBID_ALL,
        )
        .await;
    assert!(!w.cancels().await, "forbid enabled");
    forbid.enabled = false;
    assert!(
        w.storage
            .update_cedar_policy(&forbid, audit())
            .await
            .unwrap()
    );
    assert!(w.cancels().await, "forbid disabled");
}

/// A permit of a narrower scope does not override a forbid of a wider one,
/// and policies of another project or resource do not reach this one.
pub async fn scopes_apply_only_where_they_belong(storage: Store) {
    let w = world(storage).await;
    w.assign(RoleAssignmentPrincipal::Profile(w.user), true)
        .await;
    let other = world(w.storage.clone()).await;
    other
        .policy(
            PolicyScope::Project(other.project),
            PolicyEffect::Forbid,
            FORBID_ALL,
        )
        .await;
    other
        .policy(
            PolicyScope::Resource(other.resource),
            PolicyEffect::Forbid,
            FORBID_ALL,
        )
        .await;
    assert!(
        w.cancels().await,
        "another project's and resource's forbids"
    );
    w.policy(
        PolicyScope::Project(w.project),
        PolicyEffect::Forbid,
        FORBID_ALL,
    )
    .await;
    w.policy(
        PolicyScope::Resource(w.resource),
        PolicyEffect::Permit,
        PERMIT_ALL,
    )
    .await;
    assert!(
        !w.cancels().await,
        "a local permit under an inherited forbid"
    );
}

/// A deleted assignment and an expired one grant nothing.
pub async fn a_revoked_or_expired_assignment_grants_nothing(storage: Store) {
    let w = world(storage).await;
    let assignment = w
        .assign(RoleAssignmentPrincipal::Profile(w.user), true)
        .await;
    assert!(w.cancels().await, "assigned");
    w.storage
        .delete_role_assignment(assignment.id, audit())
        .await
        .unwrap();
    assert!(!w.cancels().await, "revoked");

    let mut expired = RoleAssignment::new(RoleAssignmentPrincipal::Profile(w.user), w.role.id)
        .on_resource(w.resource);
    expired.expires_at = Some(Timestamp::now() - SignedDuration::from_mins(1));
    w.storage
        .create_role_assignment(&expired, audit())
        .await
        .unwrap();
    assert!(!w.cancels().await, "expired");
}

/// A group's role grants its members while they are members.
pub async fn a_group_grants_its_members_while_they_belong(storage: Store) {
    let w = world(storage).await;
    let group = Group::new(w.project, format!("cancellers {}", uuid::Uuid::now_v7()));
    w.storage.create_group(&group, audit()).await.unwrap();
    w.assign(RoleAssignmentPrincipal::Group(group.id), true)
        .await;
    assert!(!w.cancels().await, "not a member");
    w.storage
        .add_to_group(&GroupMember::new(group.id, w.user), audit())
        .await
        .unwrap();
    assert!(w.cancels().await, "a member");
    w.storage
        .remove_from_group(group.id, w.user, audit())
        .await
        .unwrap();
    assert!(!w.cancels().await, "removed");
}

/// Two engines over one store, as two replicas: a policy stored after both
/// decided changes both decisions.
pub async fn another_engine_over_the_store_decides_the_same(storage: Store) {
    let w = world(storage).await;
    let replica: Engine = CeAuthzEngine::new(w.storage.clone());
    w.assign(RoleAssignmentPrincipal::Profile(w.user), true)
        .await;
    let cancel = w.on_resource(w.user, "orders.cancel");
    assert!(w.allowed(&w.engine, &cancel).await);
    assert!(w.allowed(&replica, &cancel).await);
    w.policy(
        PolicyScope::Resource(w.resource),
        PolicyEffect::Forbid,
        FORBID_ALL,
    )
    .await;
    assert!(!w.allowed(&w.engine, &cancel).await, "this engine");
    assert!(!w.allowed(&replica, &cancel).await, "the replica");
}

/// A malformed subject or target, or a resource that is not registered, is
/// an error, never a decision.
pub async fn malformed_questions_are_errors(storage: Store) {
    let w = world(storage).await;
    let mut bad_subject = w.on_resource(w.user, "orders.cancel");
    bad_subject.subject = "user:not-a-profile".into();
    assert!(matches!(
        w.engine.check(&bad_subject).await,
        Err(AuthzError::InvalidSubject(_))
    ));
    let mut bad_target = w.on_resource(w.user, "orders.cancel");
    bad_target.resource = "oauth_resource:not-a-resource".into();
    assert!(matches!(
        w.engine.check(&bad_target).await,
        Err(AuthzError::InvalidResource(_))
    ));
    let mut unregistered = w.on_resource(w.user, "orders.cancel");
    unregistered.resource = format!("oauth_resource:{}", ResourceId::generate());
    assert!(matches!(
        w.engine.check(&unregistered).await,
        Err(AuthzError::InvalidResource(_))
    ));
}

/// A batch answers each question in its place; one question that cannot be
/// decided fails the batch.
pub async fn a_batch_answers_in_order(storage: Store) {
    let w = world(storage).await;
    w.assign(RoleAssignmentPrincipal::Profile(w.user), true)
        .await;
    let allowed = w.on_resource(w.user, "orders.cancel");
    let denied = w.on_resource(w.user, "orders.delete");
    let answers = w
        .engine
        .batch_check(&[allowed.clone(), denied.clone(), allowed.clone()])
        .await
        .unwrap();
    let decided: Vec<bool> = answers.iter().map(|a| a.is_allowed()).collect();
    assert_eq!(decided, [true, false, true]);
    let mut broken = allowed.clone();
    broken.subject = "user:not-a-profile".into();
    assert!(
        w.engine
            .batch_check(&[allowed, broken, denied])
            .await
            .is_err()
    );
}

/// A broad permit allows an ordinary action without a role, but never token
/// inspection, which needs its own live assignment on the exact resource.
pub async fn a_permit_does_not_replace_a_mandatory_assignment(storage: Store) {
    let w = world(storage).await;
    w.policy(PolicyScope::Installation, PolicyEffect::Permit, PERMIT_ALL)
        .await;
    assert!(
        w.allowed(&w.engine, &w.on_resource(w.user, "orders.read"))
            .await,
        "an ordinary action by permit"
    );
    let inspect = AuthzCheckRequest {
        subject: "oauth_client:anyone".into(),
        action: TOKEN_INTROSPECT.into(),
        resource: format!("oauth_resource:{}", w.resource),
        context: Default::default(),
    };
    assert!(
        !w.allowed(&w.engine, &inspect).await,
        "inspection by permit"
    );
}

/// A store that can no longer be read answers an error, never an allow.
/// `unreachable` makes `storage` unreadable; a harness whose store cannot be
/// cut off in process does not run it.
#[allow(dead_code)]
pub async fn an_unreachable_store_never_allows(
    storage: Store,
    unreachable: impl std::future::Future<Output = ()>,
) {
    let w = world(storage).await;
    w.assign(RoleAssignmentPrincipal::Profile(w.user), true)
        .await;
    assert!(w.cancels().await);
    unreachable.await;
    assert!(matches!(
        w.engine
            .check(&w.on_resource(w.user, "orders.cancel"))
            .await,
        Err(AuthzError::Storage(_))
    ));
}

/// Every scenario but the unreachable store, one test each over `$store`.
#[macro_export]
macro_rules! decision_scenarios {
    ($store:expr) => {
        $crate::decision_scenarios!(@each $store;
            a_project_grant_allows_its_action_only,
            a_forbid_at_every_scope_denies_a_grant_while_it_stands,
            scopes_apply_only_where_they_belong,
            a_revoked_or_expired_assignment_grants_nothing,
            a_group_grants_its_members_while_they_belong,
            another_engine_over_the_store_decides_the_same,
            malformed_questions_are_errors,
            a_batch_answers_in_order,
            a_permit_does_not_replace_a_mandatory_assignment,
        );
    };
    (@each $store:expr; $($scenario:ident),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $scenario() {
                $store(|storage| decisions::$scenario(storage)).await;
            }
        )+
    };
}
