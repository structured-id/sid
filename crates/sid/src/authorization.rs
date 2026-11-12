// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization management: roles, their assignments, groups and their
//! members, and the Cedar policies of the fixed CE engine, with policy
//! evaluation, validation, separation-of-duties checks and simulation. The
//! same operations for the service and an embedding application.
//!
//! Who acts is an [`Actor`]: a Profile by its own installation credential or
//! a service by its own token for the authorization API. Operations only the
//! installation's administrator runs take an [`InstallationAdministrator`];
//! the others decide the actor's delegated authority themselves. A keyed
//! operation takes the caller's operation context, commits its state, audit
//! and completion together and answers a retry with what the first attempt
//! recorded.

use std::sync::Arc;

use prost::Message;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_authz::admin::{Administrator, RoleAdministration, SetRequest};
use sid_authz::cedar::{CedarEffect, CedarError, CedarService};
use sid_core::Error as SidError;
use sid_core::models::audit::ActorType;
use sid_core::models::{
    AUTHZ_CHECK, ActorFence, AssignmentSet, AuditEntry, AuthzPrincipal, CedarPolicy, CedarPolicyId,
    ConnectorState, Group, GroupId, GroupMember, MachineUserId, MutationContext, OperationContext,
    PolicyOperation, PolicyScope, ProjectId, ProvisioningConnectorId, ResourceId, ResourceState,
    Role, RoleAssignment, RoleAssignmentPrincipal, TOKEN_INTROSPECT,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::authz::authz_service as keyed;
use sid_proto::sid::v1::authz::*;
use tracing::info;

use crate::wire::{FieldError, to_timestamp, wire_id};

mod governance;
mod view;

use view::{
    assignment_to_proto, envelope_from_proto, group_to_proto, policy_authority_from_proto,
    policy_effect, policy_scope_from_proto, policy_to_proto, role_to_proto,
};

/// Who administers authorization.
#[derive(Debug, Clone)]
pub enum Actor {
    /// A Profile, by its own installation credential.
    Profile(Caller),
    /// A service, by its own token for the authorization API, as this engine
    /// subject.
    Service(String),
}

impl Actor {
    /// The actor's own engine subject.
    pub fn subject(&self) -> String {
        match self {
            Self::Profile(caller) => format!("user:{}", caller.profile_id),
            Self::Service(subject) => subject.clone(),
        }
    }

    /// The actor as an audit record's actor.
    pub fn audit_actor(&self) -> (String, ActorType) {
        match self {
            Self::Profile(caller) if caller.is_admin() => {
                (caller.profile_id.to_string(), ActorType::Admin)
            }
            Self::Profile(caller) => (caller.profile_id.to_string(), ActorType::User),
            Self::Service(subject) => match subject.split_once(':') {
                Some(("machine", id)) => (id.to_owned(), ActorType::Machine),
                Some((_, id)) => (id.to_owned(), ActorType::Service),
                None => (subject.clone(), ActorType::Service),
            },
        }
    }

    /// The actor as an administrator of role assignments: the installation's
    /// administrator is the root of its scope, anyone else administers only
    /// through its own administrative assignments.
    pub fn administrator(&self) -> Result<Administrator, AuthorizationError> {
        Ok(match self {
            Self::Profile(caller) if caller.is_admin() => {
                Administrator::Root(AuthzPrincipal::Profile(caller.profile_id))
            }
            Self::Profile(caller) => {
                Administrator::Holder(AuthzPrincipal::Profile(caller.profile_id))
            }
            Self::Service(subject) => match subject.split_once(':') {
                Some(("machine", id)) => Administrator::Holder(AuthzPrincipal::MachineUser(
                    MachineUserId::parse(id)
                        .map_err(|_| internal("administrator", "unparsable machine subject"))?,
                )),
                Some(("oauth_client", id)) => {
                    Administrator::Holder(AuthzPrincipal::OAuthClient(id.to_owned()))
                }
                _ => return Err(internal("administrator", "unknown service subject")),
            },
        })
    }

    /// An audit entry naming the actor as the actor of `action`.
    fn audit(&self, action: &str, resource: String) -> AuditEntry {
        let (actor, kind) = self.audit_actor();
        AuditEntry::by_actor(actor, kind, action, resource)
    }
}

/// A Profile verified to be the installation's administrator: what the
/// operations only it runs take ([`Authorization::installation_administrator`]).
#[derive(Debug, Clone)]
pub struct InstallationAdministrator {
    caller: Caller,
}

impl InstallationAdministrator {
    /// The administrator's own installation credential.
    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// The key namespace of the administrator's commands.
    fn namespace(&self) -> String {
        format!("authz:user:{}", self.caller.profile_id)
    }

    fn audit(&self, action: &str, resource: String) -> AuditEntry {
        AuditEntry::admin(self.caller.profile_id.to_string(), action, resource)
    }
}

/// A shape of role assignment the engine refuses: it would make an authority
/// the claim, the guards or the token do not see, or one no entry point
/// admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentRule {
    /// The installation administrator role goes only to a Profile.
    AdministratorToProfile,
    /// The installation scope holds the installation administrator role
    /// only, and that role holds only it.
    InstallationScope,
    /// Token inspection and permission queries go to a service identity.
    ServicePrincipal,
    /// Token inspection and permission queries are held on one resource.
    ServiceResource,
    /// Invite actions go to a machine user.
    InvitePrincipal,
    /// Invite actions are held on one resource.
    InviteResource,
    /// A provisioning connector's role is held on one resource.
    ConnectorResource,
}

impl AssignmentRule {
    /// What the refusal says.
    pub fn message(self) -> &'static str {
        match self {
            Self::AdministratorToProfile => {
                "the installation administrator role is assigned to a Profile"
            }
            Self::InstallationScope => {
                "the installation scope holds the installation administrator role only, and that role holds only it"
            }
            Self::ServicePrincipal => {
                "token inspection and permission queries are assigned to a machine user or an OAuth client"
            }
            Self::ServiceResource => {
                "token inspection and permission queries are assigned on one protected resource"
            }
            Self::InvitePrincipal => "invite actions are assigned to a machine user",
            Self::InviteResource => "invite actions are assigned on one protected resource",
            Self::ConnectorResource => {
                "a provisioning connector's role is assigned on one protected resource"
            }
        }
    }

    /// The request field the refusal names, and what is wrong with it.
    pub fn violation(self) -> (&'static str, &'static str) {
        match self {
            Self::AdministratorToProfile => ("principal", "not a Profile"),
            Self::InstallationScope => (
                "scope",
                "expected installation for the administrator role only",
            ),
            Self::ServicePrincipal => ("principal", "not a service identity"),
            Self::InvitePrincipal => ("principal", "not a machine user"),
            Self::ServiceResource | Self::InviteResource | Self::ConnectorResource => {
                ("scope", "expected oauth_resource:<resource_id>")
            }
        }
    }
}

/// Why an authorization management operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation (a broken invariant); its cause is in
    /// the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// No role has this identifier or name.
    #[error("role {0} not found")]
    RoleNotFound(String),
    /// No group has this identifier or name.
    #[error("group {0} not found")]
    GroupNotFound(String),
    #[error("policy {0} not found")]
    PolicyNotFound(CedarPolicyId),
    /// The project a policy scope names does not exist.
    #[error("project {0} not found")]
    ProjectNotFound(ProjectId),
    /// The protected resource a policy scope names does not exist.
    #[error("resource {0} not found")]
    ScopeResourceNotFound(ResourceId),
    /// The protected resource an assignment is held on does not exist.
    #[error("protected resource {0} not found")]
    ResourceNotFound(ResourceId),
    #[error("protected resource {0} is retired")]
    ResourceRetired(ResourceId),
    #[error("provisioning connector {0} not found")]
    ConnectorNotFound(ProvisioningConnectorId),
    #[error("provisioning connector {0} is retired")]
    ConnectorRetired(ProvisioningConnectorId),
    /// No OAuth client has this identifier.
    #[error("OAuth client {0} not found")]
    ClientNotFound(String),
    /// A public client has no credential to act with.
    #[error("a public client cannot hold roles: it has no credential")]
    PublicClient,
    /// The project already has a role of this name.
    #[error("the project already has role {0}")]
    RoleTaken(String),
    /// The project already has a group of this name.
    #[error("the project already has group {0}")]
    GroupTaken(String),
    /// The scope already has a policy of this name.
    #[error("the scope already has policy {0}")]
    PolicyTaken(String),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
    /// The assignment set is no longer at the revision the replacement was
    /// decided against.
    #[error("the role assignment set changed: it is at revision {current}")]
    AssignmentSetChanged { current: u64 },
    /// No administrative assignment of the actor covers the change.
    #[error("no administrative assignment of the caller covers this change")]
    Denied,
    /// The authority the change was admitted under changed before its commit.
    #[error("the administering authority changed")]
    AuthorityChanged,
    /// The assignment the change would make is invalid.
    #[error("assignment: {0}")]
    InvalidAssignment(String),
    /// The edit would widen an assignment past its approved ceiling.
    #[error("the edit would widen an assignment past its approved ceiling: {0}")]
    CeilingExceeded(String),
    /// The installation's last administrator assignment is kept.
    #[error("the installation's last administrator assignment is kept: {0}")]
    LastAdministrator(String),
    /// A role assignment of a shape the engine refuses.
    #[error("{}", .0.message())]
    Assignment(AssignmentRule),
    /// The Profile granted the group a role and cannot join it.
    #[error("the profile granted this group a role and cannot join it: {0}")]
    GrantorOutsideGroup(String),
    /// The request needs what this build does not include.
    #[error("{0} is not in this build")]
    NotInThisBuild(&'static str),
    #[error("profile {0} not found")]
    ProfileNotFound(sid_core::models::ProfileId),
    #[error("access request {0} not found")]
    AccessRequestNotFound(sid_core::models::AccessRequestId),
    /// The access request is no longer pending.
    #[error("access request {0} was already decided")]
    AlreadyDecided(sid_core::models::AccessRequestId),
    /// The role an access request asked for no longer exists.
    #[error("the requested role {0} no longer exists")]
    RequestedRoleDeleted(String),
}

impl From<AuthorizationError> for Effect<AuthorizationError> {
    fn from(e: AuthorizationError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<AuthorizationError>> for AuthorizationError {
    fn from(e: CommandError<AuthorizationError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for AuthorizationError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn invalid_field(field: &'static str, reason: impl Into<String>) -> AuthorizationError {
    AuthorizationError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> AuthorizationError {
    tracing::error!(operation, error = %cause, "internal failure");
    AuthorizationError::Internal
}

/// Why role administration refused or failed: no covering authority, an
/// authority that changed before the commit, or an invalid change.
pub fn administration(error: SidError) -> AuthorizationError {
    match error {
        SidError::AuthorizationDenied(_) => AuthorizationError::Denied,
        SidError::Fenced(_) => AuthorizationError::AuthorityChanged,
        SidError::Validation(why) => AuthorizationError::InvalidAssignment(why),
        // Only the root receives this: an approved ceiling binds the role.
        SidError::InvalidState(why) => AuthorizationError::CeilingExceeded(why),
        SidError::NotFound(what) => AuthorizationError::RoleNotFound(what),
        other => AuthorizationError::Store(other),
    }
}

/// Why revoking an assignment was refused: removing the last installation
/// administrator assignment, otherwise as [`administration`].
fn revocation(error: SidError) -> AuthorizationError {
    match error {
        SidError::InvalidState(why) => AuthorizationError::LastAdministrator(why),
        other => administration(other),
    }
}

/// Why replacing an assignment set was refused: the set moved on, or the
/// last installation administrator assignment would go, otherwise as
/// [`administration`].
fn replacement(error: SidError) -> AuthorizationError {
    match error {
        SidError::AssignmentSetChanged { current } => {
            AuthorizationError::AssignmentSetChanged { current }
        }
        other => revocation(other),
    }
}

/// The set a request names.
fn assignment_set_of(set: Option<RoleAssignmentSet>) -> Result<AssignmentSet, AuthorizationError> {
    use role_assignment_set::Holder;
    let set = set.ok_or(AuthorizationError::MissingField("assignment_set"))?;
    let principal = match set.holder {
        Some(Holder::ProfileId(id)) => {
            RoleAssignmentPrincipal::Profile(wire_id(Some(&id), "assignment_set.profile_id")?)
        }
        Some(Holder::GroupId(id)) => {
            RoleAssignmentPrincipal::Group(wire_id(Some(&id), "assignment_set.group_id")?)
        }
        Some(Holder::MachineUserId(id)) => RoleAssignmentPrincipal::MachineUser(wire_id(
            Some(&id),
            "assignment_set.machine_user_id",
        )?),
        Some(Holder::OauthClientId(client_id)) => RoleAssignmentPrincipal::OAuthClient(client_id),
        Some(Holder::ProvisioningConnectorId(id)) => {
            RoleAssignmentPrincipal::ProvisioningConnector(connector_id(&id)?)
        }
        None => return Err(AuthorizationError::MissingField("assignment_set.holder")),
    };
    Ok(AssignmentSet {
        principal,
        scope: set.scope,
    })
}

/// A timestamp of a request field, which must be in the future.
fn future_timestamp(
    ts: prost_types::Timestamp,
    field: &'static str,
) -> Result<chrono::DateTime<chrono::Utc>, AuthorizationError> {
    u32::try_from(ts.nanos)
        .ok()
        .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
        .filter(|at| *at > chrono::Utc::now())
        .ok_or_else(|| invalid_field(field, "not a timestamp in the future"))
}

/// The answer to a command once its commit returned `committed`: `answer`
/// when this attempt committed, otherwise the failure as `refuse` maps it (a
/// key another attempt completed as a concurrent change, resolved by
/// [`KeyedCommand::settle`] to that attempt's result when it was this
/// command's).
fn settled<T>(
    committed: Result<(), SidError>,
    answer: T,
    refuse: impl FnOnce(SidError) -> AuthorizationError,
) -> Result<T, AuthorizationError> {
    match committed {
        Ok(()) => Ok(answer),
        Err(SidError::OperationCompleted(_)) => Err(AuthorizationError::ChangedConcurrently),
        Err(SidError::OperationPeriodRefused(refusal)) => {
            Err(OperationError::PeriodRefused(refusal).into())
        }
        Err(e) => Err(refuse(e)),
    }
}

/// The installation administrator role goes only to a Profile, across the
/// whole installation, and the installation scope only to that role: any
/// other combination would make an administrator that the claim, the
/// last-administrator guard and the token do not see.
fn check_installation_assignment(
    role: &Role,
    assignment: &RoleAssignment,
) -> Result<(), AuthorizationError> {
    let administrator = role.id == Role::installation_administrator().id;
    let installation_wide =
        assignment.scope.as_deref() == Some(sid_core::models::INSTALLATION_SCOPE);
    if administrator && !matches!(assignment.principal, RoleAssignmentPrincipal::Profile(_)) {
        return Err(AuthorizationError::Assignment(
            AssignmentRule::AdministratorToProfile,
        ));
    }
    if administrator != installation_wide {
        return Err(AuthorizationError::Assignment(
            AssignmentRule::InstallationScope,
        ));
    }
    Ok(())
}

/// The fields of one assignment a request names.
fn principal_of(
    principal: Option<assign_role_request::Principal>,
) -> Result<RoleAssignmentPrincipal, AuthorizationError> {
    use assign_role_request::Principal;
    Ok(match principal {
        Some(Principal::ProfileId(id)) => {
            RoleAssignmentPrincipal::Profile(wire_id(Some(&id), "profile_id")?)
        }
        Some(Principal::GroupId(id)) => {
            RoleAssignmentPrincipal::Group(wire_id(Some(&id), "group_id")?)
        }
        Some(Principal::MachineUserId(id)) => {
            RoleAssignmentPrincipal::MachineUser(wire_id(Some(&id), "machine_user_id")?)
        }
        Some(Principal::OauthClientId(client_id)) => {
            RoleAssignmentPrincipal::OAuthClient(client_id)
        }
        Some(Principal::ProvisioningConnectorId(id)) => {
            RoleAssignmentPrincipal::ProvisioningConnector(connector_id(&id)?)
        }
        None => return Err(AuthorizationError::MissingField("principal")),
    })
}

fn connector_id(
    id: &sid_proto::sid::v1::ids::ProvisioningConnectorId,
) -> Result<ProvisioningConnectorId, AuthorizationError> {
    ProvisioningConnectorId::try_from(id).map_err(|_| {
        invalid_field(
            "provisioning_connector_id",
            "not a provisioning connector identifier",
        )
    })
}

/// A recorded AssignRole answer, as a retry of its command gets it.
fn decode_assigned(result: &[u8]) -> Result<AssignRoleResponse, AuthorizationError> {
    AssignRoleResponse::decode(result).map_err(|e| internal("recorded AssignRole answer", e))
}

/// The authorization management of one installation.
pub struct Authorization {
    storage: Arc<dyn StorageBackend>,
    cedar: CedarService,
    sod_warnings: Arc<sid_authz::sod::SodService>,
}

impl Authorization {
    /// Management with no separation-of-duties warnings configured.
    pub fn new(storage: Arc<dyn StorageBackend>, cedar: CedarService) -> Self {
        Self {
            storage,
            cedar,
            sod_warnings: Arc::new(sid_authz::sod::SodService::ce_default()),
        }
    }

    /// Warn of the conflicts the installation configuration defines.
    pub fn with_sod_warnings(mut self, warnings: Arc<sid_authz::sod::SodService>) -> Self {
        self.sod_warnings = warnings;
        self
    }

    fn administration(&self) -> RoleAdministration {
        RoleAdministration::new(self.storage.clone())
    }

    /// `caller` as the installation's administrator: it holds the
    /// administrator role in its token and, currently, in the store.
    pub async fn installation_administrator(
        &self,
        caller: &Caller,
    ) -> Result<InstallationAdministrator, AuthorizationError> {
        caller.require_admin()?;
        self.administration()
            .require_installation_administrator(caller.profile_id)
            .await
            .map_err(administration)?;
        Ok(InstallationAdministrator {
            caller: caller.clone(),
        })
    }

    /// `answer`, a command's outcome after its first completion lookup, with
    /// a refusal resolved ([`KeyedCommand::settle`]).
    async fn resolved<T: Message + Default>(
        &self,
        command: &KeyedCommand,
        answer: Result<T, AuthorizationError>,
    ) -> Result<T, AuthorizationError> {
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(CommandError::refusal)
    }

    /// The role `id`, or the refusal the actor gets for a missing one: only
    /// the root learns a role is missing, anyone else is refused as for any
    /// change its authority does not cover.
    async fn role_for(
        &self,
        administrator: &Administrator,
        id: sid_core::models::RoleId,
    ) -> Result<Role, AuthorizationError> {
        match self.storage.get_role(id).await? {
            Some(role) => Ok(role),
            None => Err(match administrator {
                Administrator::Root(_) => AuthorizationError::RoleNotFound(id.to_string()),
                Administrator::Holder(_) => AuthorizationError::Denied,
            }),
        }
    }

    // ── Roles ───────────────────────────────────────────────────────

    pub async fn create_role(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: CreateRoleRequest,
    ) -> Result<CreateRoleResponse, AuthorizationError> {
        // A retry of a completed creation answers with the role it created,
        // not "name taken" by that very role.
        let command = KeyedCommand::of::<keyed::CreateRole>(admin.namespace(), operation, &req);
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
            if req.name.is_empty() {
                return Err(AuthorizationError::MissingField("name"));
            }

            let mut role = Role::new(project_id, &req.name, &req.name);
            role.description = req.description.clone();
            role.permissions = req.permissions.clone();

            let answer = CreateRoleResponse {
                role: Some(role_to_proto(&role)),
            };
            let ctx = MutationContext::from(admin.audit("role.create", role.id.to_string()))
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.create_role(&role, ctx).await;
            let answer = settled(committed, answer, |e| match e {
                SidError::Conflict(_) => AuthorizationError::RoleTaken(req.name.clone()),
                other => AuthorizationError::Store(other),
            })?;

            info!("Created role '{}' in project {project_id}", role.key);
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn get_role(
        &self,
        _admin: &InstallationAdministrator,
        req: GetRoleRequest,
    ) -> Result<GetRoleResponse, AuthorizationError> {
        let role = match req.identifier {
            Some(get_role_request::Identifier::Id(id)) => {
                let role_id = wire_id(Some(&id), "id")?;
                self.storage
                    .get_role(role_id)
                    .await?
                    .ok_or_else(|| AuthorizationError::RoleNotFound(role_id.to_string()))?
            }
            Some(get_role_request::Identifier::Name(name)) => {
                let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
                self.storage
                    .get_role_by_name(project_id, &name)
                    .await?
                    .ok_or(AuthorizationError::RoleNotFound(name))?
            }
            None => return Err(AuthorizationError::MissingField("identifier")),
        };
        Ok(GetRoleResponse {
            role: Some(role_to_proto(&role)),
        })
    }

    pub async fn update_role(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: UpdateRoleRequest,
    ) -> Result<UpdateRoleResponse, AuthorizationError> {
        let administrator = actor.administrator()?;
        // A retry of a completed edit answers with the role as that edit left
        // it, and never writes it over a later edit.
        let command = KeyedCommand::of::<keyed::UpdateRole>(
            format!("authz:{}", actor.subject()),
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let role_id = wire_id(req.id.as_ref(), "id")?;
            let mut role = self.role_for(&administrator, role_id).await?;

            if let Some(desc) = req.description.clone() {
                role.description = Some(desc);
            }
            if !req.permissions.is_empty() {
                role.permissions = req.permissions.clone();
            }
            role.updated_at = chrono::Utc::now();

            let answer = UpdateRoleResponse {
                role: Some(role_to_proto(&role)),
            };
            let audit = MutationContext::from(actor.audit("role.update", role.id.to_string()))
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = match self
                .administration()
                .edit_role(&administrator, &role, audit)
                .await
            {
                // Deleted or changed since it was read: never recreated or
                // overwritten.
                Ok(false) => return Err(AuthorizationError::ChangedConcurrently),
                Ok(true) => Ok(()),
                Err(e) => Err(e),
            };
            settled(committed, answer, administration)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn delete_role(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: DeleteRoleRequest,
    ) -> Result<DeleteRoleResponse, AuthorizationError> {
        // A retry of a completed deletion answers as the first, not "not
        // found" for the role it deleted.
        let command = KeyedCommand::of::<keyed::DeleteRole>(admin.namespace(), operation, &req);
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let role_id = wire_id(req.id.as_ref(), "id")?;
            self.storage
                .get_role(role_id)
                .await?
                .ok_or_else(|| AuthorizationError::RoleNotFound(role_id.to_string()))?;

            let answer = DeleteRoleResponse {};
            let ctx = MutationContext::from(admin.audit("role.delete", role_id.to_string()))
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.delete_role(role_id, ctx).await;
            let answer = settled(committed, answer, |e| match e {
                // The administrator role, still assigned: deleting it would
                // remove the installation's administrators with it.
                SidError::InvalidState(_) => revocation(e),
                other => AuthorizationError::Store(other),
            })?;

            info!("Deleted role {role_id}");
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn list_roles(
        &self,
        _admin: &InstallationAdministrator,
        req: ListRolesRequest,
    ) -> Result<ListRolesResponse, AuthorizationError> {
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let roles = self.storage.list_roles(project_id).await?;
        Ok(ListRolesResponse {
            roles: roles.iter().map(role_to_proto).collect(),
            next_page_token: String::new(),
        })
    }

    // ── Role assignments ────────────────────────────────────────────

    pub async fn assign_role(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: AssignRoleRequest,
    ) -> Result<AssignRoleResponse, AuthorizationError> {
        let administrator = actor.administrator()?;
        // A retry gets the recorded answer: the assignment the first call
        // made, whether or not it is still in force, and never a second one.
        let command = KeyedCommand::of::<keyed::AssignRole>(
            format!("authz:{}", administrator.subject()),
            operation,
            &req,
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return decode_assigned(&result);
        }
        let answer = async {
            let role_id = wire_id(req.role_id.as_ref(), "role_id")?;
            let role = self.role_for(&administrator, role_id).await?;

            let principal = principal_of(req.principal.clone())?;
            if let RoleAssignmentPrincipal::OAuthClient(client_id) = &principal {
                self.confidential_client(client_id).await?;
            }

            // An expiry is a valid timestamp in the future, never replaced by
            // another value.
            let expires_at = req
                .expires_at
                .map(|ts| {
                    u32::try_from(ts.nanos)
                        .ok()
                        .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
                        .filter(|at| *at > chrono::Utc::now())
                        .ok_or_else(|| invalid_field("expires_at", "not a timestamp in the future"))
                })
                .transpose()?;

            let mut assignment = RoleAssignment::new(principal, role_id);
            assignment.scope = req.scope.clone();
            assignment.expires_at = expires_at;
            assignment.admin = req.admin.clone().map(envelope_from_proto).transpose()?;
            assignment.policy_admin = req
                .policy_admin
                .clone()
                .map(policy_authority_from_proto)
                .transpose()?;
            check_installation_assignment(&role, &assignment)?;
            if role.has_permission(TOKEN_INTROSPECT) || role.has_permission(AUTHZ_CHECK) {
                self.check_service_assignment(&assignment).await?;
            }
            if role
                .permissions
                .iter()
                .any(|p| sid_core::models::is_invite_action(p))
            {
                self.check_invite_assignment(&assignment).await?;
            }
            if let RoleAssignmentPrincipal::ProvisioningConnector(connector) = assignment.principal
            {
                self.check_connector_assignment(connector, &assignment)
                    .await?;
            }

            let audit = actor.audit("role.assign", assignment.id.to_string()).into();
            let assigned = self
                .administration()
                .assign_recording(&administrator, assignment, audit, |stored| {
                    Some(
                        command.completion(
                            AssignRoleResponse {
                                assignment: Some(assignment_to_proto(stored)),
                            }
                            .encode_to_vec(),
                        ),
                    )
                })
                .await;
            let assignment = match assigned {
                Ok(assignment) => assignment,
                // A concurrent call with the same key committed first.
                Err(SidError::OperationCompleted(_)) => {
                    return Err(AuthorizationError::ChangedConcurrently);
                }
                Err(e) => return Err(administration(e)),
            };

            info!("Assigned role {role_id} (assignment {})", assignment.id);
            Ok(AssignRoleResponse {
                assignment: Some(assignment_to_proto(&assignment)),
            })
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn revoke_role(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: RevokeRoleRequest,
    ) -> Result<RevokeRoleResponse, AuthorizationError> {
        let administrator = actor.administrator()?;
        // A retry of a completed revocation answers as the first, not "not
        // found" for the assignment it removed.
        let command = KeyedCommand::of::<keyed::RevokeRole>(
            format!("authz:{}", administrator.subject()),
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let assignment_id = wire_id(req.assignment_id.as_ref(), "assignment_id")?;
            let answer = RevokeRoleResponse {};
            let audit =
                MutationContext::from(actor.audit("role.revoke", assignment_id.to_string()))
                    .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self
                .administration()
                .revoke(&administrator, assignment_id, audit)
                .await
                // `false`: no such assignment to revoke, answered as revoked.
                .map(|_| ());
            let answer = settled(committed, answer, revocation)?;

            info!("Revoked role assignment {assignment_id}");
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    /// Make one holder's assignments of the managed roles in one exact scope
    /// exactly the requested ones, in one commit at the expected revision.
    /// Every request moves the revision; a retry answers what the first
    /// attempt recorded without moving it again.
    pub async fn set_role_assignments(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: SetRoleAssignmentsRequest,
    ) -> Result<SetRoleAssignmentsResponse, AuthorizationError> {
        let administrator = actor.administrator()?;
        let command = KeyedCommand::of::<keyed::SetRoleAssignments>(
            format!("authz:{}", administrator.subject()),
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let set = assignment_set_of(req.assignment_set.clone())?;
            if let RoleAssignmentPrincipal::OAuthClient(client_id) = &set.principal {
                self.confidential_client(client_id).await?;
            }
            let mut managed = std::collections::BTreeSet::new();
            for id in &req.managed_role_ids {
                managed.insert(wire_id(Some(id), "managed_role_ids")?);
            }
            let mut assignments = Vec::with_capacity(req.assignments.len());
            for requested in &req.assignments {
                let role_id = wire_id(requested.role_id.as_ref(), "assignments.role_id")?;
                let until = requested
                    .expires_at
                    .map(|ts| future_timestamp(ts, "assignments.expires_at"))
                    .transpose()?;
                assignments.push((role_id, until));
            }
            // The same shape rules as a single assignment, for each requested one.
            for (role_id, until) in &assignments {
                let role = self
                    .storage
                    .get_role(*role_id)
                    .await?
                    .ok_or_else(|| AuthorizationError::RoleNotFound(role_id.to_string()))?;
                let mut probe = RoleAssignment::new(set.principal.clone(), *role_id);
                probe.scope = set.scope.clone();
                probe.expires_at = *until;
                check_installation_assignment(&role, &probe)?;
                if role.has_permission(TOKEN_INTROSPECT) || role.has_permission(AUTHZ_CHECK) {
                    self.check_service_assignment(&probe).await?;
                }
                if role
                    .permissions
                    .iter()
                    .any(|p| sid_core::models::is_invite_action(p))
                {
                    self.check_invite_assignment(&probe).await?;
                }
                if let RoleAssignmentPrincipal::ProvisioningConnector(connector) = probe.principal {
                    self.check_connector_assignment(connector, &probe).await?;
                }
            }
            let audit = MutationContext::from(actor.audit("role.set", set.to_string()));
            let request = SetRequest {
                set,
                managed,
                assignments,
                expected_revision: req.expected_revision,
            };
            let replaced = self
                .administration()
                .replace(&administrator, request, audit, |revision, stored| {
                    Some(
                        command.completion(
                            SetRoleAssignmentsResponse {
                                revision,
                                assignments: stored.iter().map(assignment_to_proto).collect(),
                            }
                            .encode_to_vec(),
                        ),
                    )
                })
                .await;
            let (revision, stored) = match replaced {
                Ok(done) => done,
                Err(SidError::OperationCompleted(_)) => {
                    return Err(AuthorizationError::ChangedConcurrently);
                }
                Err(SidError::OperationPeriodRefused(refusal)) => {
                    return Err(OperationError::PeriodRefused(refusal).into());
                }
                Err(e) => return Err(replacement(e)),
            };
            info!("Set role assignments to revision {revision}");
            Ok(SetRoleAssignmentsResponse {
                revision,
                assignments: stored.iter().map(assignment_to_proto).collect(),
            })
        }
        .await;
        self.resolved(&command, answer).await
    }

    /// The assignments the filter names that `actor` administers: a
    /// delegated administrator reads what it administers, as the root reads
    /// everything; anyone else is refused.
    pub async fn list_role_assignments(
        &self,
        actor: &Actor,
        req: ListRoleAssignmentsRequest,
    ) -> Result<ListRoleAssignmentsResponse, AuthorizationError> {
        use list_role_assignments_request::Filter;
        let administrator = actor.administrator()?;
        let storage = &self.storage;
        let mut set_revision = None;
        let assignments = match req.filter {
            // One exact set, read with its revision in one snapshot. A
            // delegated administrator sees only what it administers; a
            // replacement still covers every managed role of the set, whose
            // assignments it therefore sees whole.
            Some(Filter::AssignmentSet(set)) => {
                let set = assignment_set_of(Some(set))?;
                let (revision, held) = storage.role_assignment_set(&set).await?;
                set_revision = Some(revision);
                Ok(held)
            }
            Some(Filter::ProfileId(id)) => {
                let pid = wire_id(Some(&id), "profile_id")?;
                storage.list_role_assignments_for_profile(pid).await
            }
            Some(Filter::GroupId(id)) => {
                let gid = wire_id(Some(&id), "group_id")?;
                storage.list_role_assignments_for_group(gid).await
            }
            Some(Filter::MachineUserId(id)) => {
                let mid = wire_id(Some(&id), "machine_user_id")?;
                storage.list_role_assignments_for_machine_user(mid).await
            }
            Some(Filter::OauthClientId(client_id)) => {
                storage
                    .list_role_assignments_for_oauth_client(&client_id)
                    .await
            }
            Some(Filter::ProvisioningConnectorId(id)) => {
                storage
                    .list_role_assignments_for_provisioning_connector(connector_id(&id)?)
                    .await
            }
            Some(Filter::RoleId(id)) => {
                let role_id = wire_id(Some(&id), "role_id")?;
                storage.list_role_assignments_for_role(role_id).await
            }
            None => return Err(AuthorizationError::MissingField("filter")),
        };
        let assignments = self
            .administration()
            .administered(&administrator, assignments?)
            .await
            .map_err(administration)?;
        Ok(ListRoleAssignmentsResponse {
            assignments: assignments.iter().map(assignment_to_proto).collect(),
            set_revision,
        })
    }

    /// The confidential OAuth client `client_id` names: only a client that
    /// authenticates can act as its own principal.
    async fn confidential_client(&self, client_id: &str) -> Result<(), AuthorizationError> {
        let client = self
            .storage
            .get_oauth2_client(client_id)
            .await?
            .ok_or_else(|| AuthorizationError::ClientNotFound(client_id.to_owned()))?;
        if client.is_public() {
            return Err(AuthorizationError::PublicClient);
        }
        Ok(())
    }

    /// A role granting token inspection or permission queries goes only to a
    /// service identity (a machine user or an OAuth client), on one existing,
    /// not retired protected resource: neither is ever project-wide, and a
    /// user's sign-in is no such authority (D054).
    async fn check_service_assignment(
        &self,
        assignment: &RoleAssignment,
    ) -> Result<(), AuthorizationError> {
        if !matches!(
            assignment.principal,
            RoleAssignmentPrincipal::MachineUser(_) | RoleAssignmentPrincipal::OAuthClient(_)
        ) {
            return Err(AuthorizationError::Assignment(
                AssignmentRule::ServicePrincipal,
            ));
        }
        let resource = assignment
            .resource_scope()
            .ok_or(AuthorizationError::Assignment(
                AssignmentRule::ServiceResource,
            ))?;
        self.check_live_resource(resource).await
    }

    /// A role granting invite actions goes only to a machine user, on one
    /// existing, not retired protected resource: the invite RPCs admit no
    /// other caller.
    async fn check_invite_assignment(
        &self,
        assignment: &RoleAssignment,
    ) -> Result<(), AuthorizationError> {
        if !matches!(
            assignment.principal,
            RoleAssignmentPrincipal::MachineUser(_)
        ) {
            return Err(AuthorizationError::Assignment(
                AssignmentRule::InvitePrincipal,
            ));
        }
        let resource = assignment
            .resource_scope()
            .ok_or(AuthorizationError::Assignment(
                AssignmentRule::InviteResource,
            ))?;
        self.check_live_resource(resource).await
    }

    /// A provisioning connector's role is assigned only while the connector
    /// is not retired, and only on one live protected resource: the engine
    /// lets a connector act nowhere else.
    async fn check_connector_assignment(
        &self,
        connector: ProvisioningConnectorId,
        assignment: &RoleAssignment,
    ) -> Result<(), AuthorizationError> {
        let stored = self
            .storage
            .get_provisioning_connector(connector)
            .await?
            .ok_or(AuthorizationError::ConnectorNotFound(connector))?;
        if stored.state == ConnectorState::Retired {
            return Err(AuthorizationError::ConnectorRetired(connector));
        }
        let resource = assignment
            .resource_scope()
            .ok_or(AuthorizationError::Assignment(
                AssignmentRule::ConnectorResource,
            ))?;
        self.check_live_resource(resource).await
    }

    /// `resource` exists and is not retired.
    async fn check_live_resource(&self, resource: ResourceId) -> Result<(), AuthorizationError> {
        let stored = self
            .storage
            .get_protected_resource(resource)
            .await?
            .ok_or(AuthorizationError::ResourceNotFound(resource))?;
        if stored.state == ResourceState::Retired {
            return Err(AuthorizationError::ResourceRetired(resource));
        }
        Ok(())
    }

    // ── Groups ──────────────────────────────────────────────────────

    pub async fn create_group(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: CreateGroupRequest,
    ) -> Result<CreateGroupResponse, AuthorizationError> {
        // A retry of a completed creation answers with the group it created,
        // not "name taken" by that very group.
        let command = KeyedCommand::of::<keyed::CreateGroup>(admin.namespace(), operation, &req);
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
            if req.name.is_empty() {
                return Err(AuthorizationError::MissingField("name"));
            }

            let mut group = Group::new(project_id, &req.name);
            group.description = req.description.clone();

            let answer = CreateGroupResponse {
                group: Some(group_to_proto(&group)),
            };
            let ctx = MutationContext::from(admin.audit("group.create", group.id.to_string()))
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.create_group(&group, ctx).await;
            let answer = settled(committed, answer, |e| match e {
                SidError::Conflict(_) => AuthorizationError::GroupTaken(req.name.clone()),
                other => AuthorizationError::Store(other),
            })?;

            info!("Created group '{}' in project {project_id}", group.name);
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn get_group(
        &self,
        _admin: &InstallationAdministrator,
        req: GetGroupRequest,
    ) -> Result<GetGroupResponse, AuthorizationError> {
        let group = match req.identifier {
            Some(get_group_request::Identifier::Id(id)) => {
                let gid: GroupId = wire_id(Some(&id), "id")?;
                self.storage
                    .get_group(gid)
                    .await?
                    .ok_or_else(|| AuthorizationError::GroupNotFound(gid.to_string()))?
            }
            Some(get_group_request::Identifier::Name(name)) => {
                let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
                let groups = self.storage.list_groups(project_id).await?;
                match groups.into_iter().find(|g| g.name == name) {
                    Some(group) => group,
                    None => return Err(AuthorizationError::GroupNotFound(name)),
                }
            }
            None => return Err(AuthorizationError::MissingField("identifier")),
        };
        Ok(GetGroupResponse {
            group: Some(group_to_proto(&group)),
        })
    }

    pub async fn update_group(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: UpdateGroupRequest,
    ) -> Result<UpdateGroupResponse, AuthorizationError> {
        // A retry of a completed edit answers with the group as that edit
        // left it: the state its commit recorded, never one read around it.
        let command = KeyedCommand::of::<keyed::UpdateGroup>(admin.namespace(), operation, &req);
        let group_id: GroupId = wire_id(req.id.as_ref(), "id")?;
        let audit = || admin.audit("group.update", group_id.to_string());
        let not_found = || AuthorizationError::GroupNotFound(group_id.to_string());
        let group: Group = match req.description {
            // Without a description nothing is written: the group as it is,
            // recorded as this command's outcome so its retry answers the same.
            None => {
                command
                    .unchanged_recorded(&*self.storage, audit(), || async {
                        self.storage
                            .get_group(group_id)
                            .await?
                            .ok_or_else(not_found)
                    })
                    .await?
            }
            // Only the description is written, so a concurrent directory sync
            // of the name is never reverted and a deleted group is never
            // recreated; the group as that write left it is the answer.
            Some(desc) => {
                command
                    .execute_recorded(&*self.storage, || async {
                        let ctx = MutationContext::from(audit())
                            .with_operation(command.effect_completion());
                        match self
                            .storage
                            .set_group_description(group_id, Some(&desc), ctx)
                            .await
                        {
                            Ok(true) => Ok(command.recorded_effect(&*self.storage).await?),
                            Ok(false) => Err(Effect::Refused(not_found())),
                            Err(e) => Err(Effect::Store(e)),
                        }
                    })
                    .await?
            }
        };
        Ok(UpdateGroupResponse {
            group: Some(group_to_proto(&group)),
        })
    }

    pub async fn delete_group(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: DeleteGroupRequest,
    ) -> Result<DeleteGroupResponse, AuthorizationError> {
        // A retry of a completed deletion answers as the first, not "not
        // found" for the group it deleted.
        let command = KeyedCommand::of::<keyed::DeleteGroup>(admin.namespace(), operation, &req);
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let group_id: GroupId = wire_id(req.id.as_ref(), "id")?;
            self.storage
                .get_group(group_id)
                .await?
                .ok_or_else(|| AuthorizationError::GroupNotFound(group_id.to_string()))?;

            let answer = DeleteGroupResponse {};
            let ctx = MutationContext::from(admin.audit("group.delete", group_id.to_string()))
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.delete_group(group_id, ctx).await;
            let answer = settled(committed, answer, AuthorizationError::Store)?;

            info!("Deleted group {group_id}");
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn list_groups(
        &self,
        _admin: &InstallationAdministrator,
        req: ListGroupsRequest,
    ) -> Result<ListGroupsResponse, AuthorizationError> {
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let groups = self.storage.list_groups(project_id).await?;
        Ok(ListGroupsResponse {
            groups: groups.iter().map(group_to_proto).collect(),
            next_page_token: String::new(),
        })
    }

    // ── Group membership ────────────────────────────────────────────

    pub async fn add_to_group(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: AddToGroupRequest,
    ) -> Result<AddToGroupResponse, AuthorizationError> {
        // A retry of a completed addition answers as the first and never
        // adds the member back after a later removal.
        let command = KeyedCommand::of::<keyed::AddToGroup>(admin.namespace(), operation, &req);
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let group_id: GroupId = wire_id(req.group_id.as_ref(), "group_id")?;
            let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
            self.storage
                .get_group(group_id)
                .await?
                .ok_or_else(|| AuthorizationError::GroupNotFound(group_id.to_string()))?;

            let member = GroupMember::new(group_id, profile_id);
            let answer = AddToGroupResponse {};
            let ctx = MutationContext::from(
                admin.audit("group.add_member", format!("{group_id}:{profile_id}")),
            )
            .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.add_to_group(&member, ctx).await;
            let answer = settled(committed, answer, |e| match e {
                SidError::PolicyViolation(why) => AuthorizationError::GrantorOutsideGroup(why),
                other => AuthorizationError::Store(other),
            })?;

            info!("Added profile {profile_id} to group {group_id}");
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn remove_from_group(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: RemoveFromGroupRequest,
    ) -> Result<RemoveFromGroupResponse, AuthorizationError> {
        // A retry of a completed removal answers as the first and never
        // removes the member again after a later addition.
        let command =
            KeyedCommand::of::<keyed::RemoveFromGroup>(admin.namespace(), operation, &req);
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let group_id: GroupId = wire_id(req.group_id.as_ref(), "group_id")?;
            let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;

            let answer = RemoveFromGroupResponse {};
            let ctx = MutationContext::from(
                admin.audit("group.remove_member", format!("{group_id}:{profile_id}")),
            )
            .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self
                .storage
                .remove_from_group(group_id, profile_id, ctx)
                .await;
            let answer = settled(committed, answer, AuthorizationError::Store)?;

            info!("Removed profile {profile_id} from group {group_id}");
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn list_group_members(
        &self,
        _admin: &InstallationAdministrator,
        req: ListGroupMembersRequest,
    ) -> Result<ListGroupMembersResponse, AuthorizationError> {
        let group_id: GroupId = wire_id(req.group_id.as_ref(), "group_id")?;
        let members = self.storage.list_group_members(group_id).await?;
        Ok(ListGroupMembersResponse {
            profile_ids: members.iter().map(|m| m.profile_id.into()).collect(),
        })
    }

    // ── Policies (Cedar ABAC) ───────────────────────────────────────

    /// `actor`'s authority for `operation` on policies of `scope`, and the
    /// fence a write under it commits with.
    async fn policy_authority(
        &self,
        actor: &Actor,
        operation: PolicyOperation,
        scope: PolicyScope,
    ) -> Result<ActorFence, AuthorizationError> {
        self.administration()
            .policy_authority(&actor.administrator()?, operation, scope)
            .await
            .map_err(administration)
    }

    /// The stored policy `id` and `actor`'s authority for `operation` on it,
    /// decided on the policy's real scope. Only the root learns it is missing.
    async fn policy_for(
        &self,
        actor: &Actor,
        id: CedarPolicyId,
        operation: PolicyOperation,
    ) -> Result<(CedarPolicy, ActorFence), AuthorizationError> {
        let administrator = actor.administrator()?;
        let Some(policy) = self.storage.get_cedar_policy(id).await? else {
            return Err(match administrator {
                Administrator::Root(_) => AuthorizationError::PolicyNotFound(id),
                Administrator::Holder(_) => AuthorizationError::Denied,
            });
        };
        let fence = self
            .policy_authority(actor, operation, policy.scope)
            .await?;
        Ok((policy, fence))
    }

    /// A policy is stored only when Cedar parses it: an unparseable one would
    /// make every evaluation of its project fail closed.
    fn check_policy_text(&self, text: &str) -> Result<(), AuthorizationError> {
        if self.cedar.validate_policy(text).valid {
            Ok(())
        } else {
            Err(invalid_field("policy_text", "not a valid Cedar policy"))
        }
    }

    /// Refuse a scope whose project or protected resource does not exist: a
    /// policy written for it would apply nowhere.
    async fn check_scope_target(&self, scope: PolicyScope) -> Result<(), AuthorizationError> {
        match scope {
            PolicyScope::Installation => Ok(()),
            PolicyScope::Project(id) => self
                .storage
                .get_project(id)
                .await?
                .map(|_| ())
                .ok_or(AuthorizationError::ProjectNotFound(id)),
            PolicyScope::Resource(id) => self
                .storage
                .get_protected_resource(id)
                .await?
                .map(|_| ())
                .ok_or(AuthorizationError::ScopeResourceNotFound(id)),
        }
    }

    /// What a policy mutation commits with: its audit naming the actor and
    /// the authority that must still hold.
    fn policy_mutation(
        actor: &Actor,
        action: &str,
        id: CedarPolicyId,
        fence: ActorFence,
    ) -> MutationContext {
        MutationContext::from(actor.audit(action, id.to_string())).fenced_by(fence)
    }

    pub async fn create_policy(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: CreatePolicyRequest,
    ) -> Result<CreatePolicyResponse, AuthorizationError> {
        // A retry of a completed creation answers with the policy it created,
        // not "name taken" by that very policy.
        let command = KeyedCommand::of::<keyed::CreatePolicy>(
            format!("authz:{}", actor.subject()),
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let scope = policy_scope_from_proto(req.scope.as_ref(), "scope")?;
            let fence = self
                .policy_authority(actor, PolicyOperation::Edit, scope)
                .await?;
            if req.name.is_empty() {
                return Err(AuthorizationError::MissingField("name"));
            }
            if req.policy_text.is_empty() {
                return Err(AuthorizationError::MissingField("policy_text"));
            }
            self.check_policy_text(&req.policy_text)?;
            self.check_scope_target(scope).await?;

            let mut policy = CedarPolicy::new(
                scope,
                &req.name,
                &req.policy_text,
                policy_effect(req.effect),
            );
            policy.description = req.description.clone();
            policy.enabled = req.enabled;

            let answer = CreatePolicyResponse {
                policy: Some(policy_to_proto(&policy)),
            };
            let ctx = Self::policy_mutation(actor, "policy.create", policy.id, fence)
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.create_cedar_policy(&policy, ctx).await;
            let answer = settled(committed, answer, |e| match e {
                SidError::Conflict(_) => AuthorizationError::PolicyTaken(policy.name.clone()),
                other => AuthorizationError::Store(other),
            })?;

            info!("Created policy '{}' in scope {:?}", policy.name, scope);
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn get_policy(
        &self,
        actor: &Actor,
        req: GetPolicyRequest,
    ) -> Result<GetPolicyResponse, AuthorizationError> {
        let policy_id = wire_id(req.id.as_ref(), "id")?;
        let (policy, _) = self
            .policy_for(actor, policy_id, PolicyOperation::Read)
            .await?;
        Ok(GetPolicyResponse {
            policy: Some(policy_to_proto(&policy)),
        })
    }

    pub async fn update_policy(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: UpdatePolicyRequest,
    ) -> Result<UpdatePolicyResponse, AuthorizationError> {
        // A retry of a completed edit answers with the policy as that edit
        // left it, and never writes it over a later edit.
        let command = KeyedCommand::of::<keyed::UpdatePolicy>(
            format!("authz:{}", actor.subject()),
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let policy_id = wire_id(req.id.as_ref(), "id")?;
            let (mut policy, fence) = self
                .policy_for(actor, policy_id, PolicyOperation::Edit)
                .await?;

            if let Some(desc) = req.description.clone() {
                policy.description = Some(desc);
            }
            if let Some(text) = req.policy_text.clone() {
                self.check_policy_text(&text)?;
                policy.policy_text = text;
            }
            if let Some(effect) = req.effect {
                policy.effect = policy_effect(effect);
            }
            if let Some(enabled) = req.enabled {
                policy.enabled = enabled;
            }
            policy.updated_at = chrono::Utc::now();

            // The store writes over the revision just read and moves it on; the
            // answer is the policy as that commit leaves it.
            let mut left = policy_to_proto(&policy);
            left.revision = policy.revision + 1;
            let answer = UpdatePolicyResponse { policy: Some(left) };
            let ctx = Self::policy_mutation(actor, "policy.update", policy.id, fence)
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = match self.storage.update_cedar_policy(&policy, ctx).await {
                // Deleted or changed since it was read: never recreated or
                // overwritten.
                Ok(false) => return Err(AuthorizationError::ChangedConcurrently),
                Ok(true) => Ok(()),
                Err(e) => Err(e),
            };
            settled(committed, answer, AuthorizationError::Store)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn delete_policy(
        &self,
        actor: &Actor,
        operation: OperationContext,
        req: DeletePolicyRequest,
    ) -> Result<DeletePolicyResponse, AuthorizationError> {
        // A retry of a completed deletion answers as the first, not "not
        // found" for the policy it deleted.
        let command = KeyedCommand::of::<keyed::DeletePolicy>(
            format!("authz:{}", actor.subject()),
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let answer = async {
            let policy_id: CedarPolicyId = wire_id(req.id.as_ref(), "id")?;
            let (_, fence) = self
                .policy_for(actor, policy_id, PolicyOperation::Edit)
                .await?;

            let answer = DeletePolicyResponse {};
            let ctx = Self::policy_mutation(actor, "policy.delete", policy_id, fence)
                .with_operation(command.completion(answer.encode_to_vec()));
            let committed = self.storage.delete_cedar_policy(policy_id, ctx).await;
            let answer = settled(committed, answer, AuthorizationError::Store)?;

            info!("Deleted policy {policy_id}");
            Ok(answer)
        }
        .await;
        self.resolved(&command, answer).await
    }

    pub async fn list_policies(
        &self,
        actor: &Actor,
        req: ListPoliciesRequest,
    ) -> Result<ListPoliciesResponse, AuthorizationError> {
        let scope = policy_scope_from_proto(req.scope.as_ref(), "scope")?;
        self.policy_authority(actor, PolicyOperation::Read, scope)
            .await?;
        let policies = self.storage.list_cedar_policies(scope).await?;
        Ok(ListPoliciesResponse {
            policies: policies.iter().map(policy_to_proto).collect(),
            next_page_token: String::new(),
        })
    }

    // ── Policy evaluation ───────────────────────────────────────────

    /// Evaluate the enabled policies the named scope owns for one request.
    pub async fn evaluate_policy(
        &self,
        _admin: &InstallationAdministrator,
        req: EvaluatePolicyRequest,
    ) -> Result<EvaluatePolicyResponse, AuthorizationError> {
        let scope = policy_scope_from_proto(req.scope.as_ref(), "scope")?;
        let policies = self.storage.list_cedar_policies(scope).await?;
        let policy_pairs: Vec<(String, String)> = policies
            .into_iter()
            .filter(|p| p.enabled)
            .map(|p| (p.id.to_string(), p.policy_text))
            .collect();
        if policy_pairs.is_empty() {
            return Ok(EvaluatePolicyResponse {
                allowed: false,
                matches: vec![],
            });
        }

        let subject = format!(r#"User::"{}""#, req.subject);
        let action = format!(r#"Action::"{}""#, req.action);
        let resource = format!(r#"Resource::"{}""#, req.resource);
        let result = self
            .cedar
            .evaluate(&policy_pairs, &subject, &action, &resource, &req.context)
            .map_err(|e| match e {
                CedarError::InvalidEntity { field, .. } => {
                    invalid_field(field, "not a valid Cedar entity identifier")
                }
                CedarError::InvalidContext(_) => {
                    invalid_field("context", "not a valid Cedar request context")
                }
                // Policy text is checked when it is stored.
                CedarError::InvalidPolicy(_) => internal("evaluate_policy", e),
            })?;

        // Cedar names a match by the id text it was given above.
        let matches = result
            .matches
            .iter()
            .map(|m| {
                let id = CedarPolicyId::parse(&m.policy_id)
                    .map_err(|e| internal("evaluate_policy", e))?;
                Ok(PolicyMatch {
                    policy_id: Some(id.into()),
                    policy_name: String::new(),
                    effect: match m.effect {
                        CedarEffect::Permit => sid_proto::sid::v1::PolicyEffect::Permit.into(),
                        CedarEffect::Forbid => sid_proto::sid::v1::PolicyEffect::Forbid.into(),
                    },
                })
            })
            .collect::<Result<_, AuthorizationError>>()?;
        Ok(EvaluatePolicyResponse {
            allowed: result.allowed,
            matches,
        })
    }

    pub fn validate_policy(
        &self,
        _admin: &InstallationAdministrator,
        req: ValidatePolicyRequest,
    ) -> Result<ValidatePolicyResponse, AuthorizationError> {
        if req.policy_text.is_empty() {
            return Err(AuthorizationError::MissingField("policy_text"));
        }
        let result = self.cedar.validate_policy(&req.policy_text);
        Ok(ValidatePolicyResponse {
            valid: result.valid,
            errors: result.errors,
        })
    }

    pub async fn check_sod_conflicts(
        &self,
        _admin: &InstallationAdministrator,
        req: CheckSodConflictsRequest,
    ) -> Result<CheckSodConflictsResponse, AuthorizationError> {
        if req.proposed_role.is_empty() {
            return Err(AuthorizationError::MissingField("proposed_role"));
        }
        // A warning only: the assignment itself is decided elsewhere.
        let conflicts = self
            .sod_warnings
            .check_conflicts(&req.existing_roles, &req.proposed_role);
        let conflicts: Vec<sid_proto::sid::v1::SodConflict> = conflicts
            .into_iter()
            .map(|c| sid_proto::sid::v1::SodConflict {
                rule_name: c.rule_name,
                description: c.description,
                severity: c.severity.as_str().to_string(),
                conflicting_roles: c.conflicting_roles,
            })
            .collect();
        Ok(CheckSodConflictsResponse {
            has_conflicts: !conflicts.is_empty(),
            conflicts,
        })
    }

    /// What the proposed policy changes would grant and take away in the
    /// project, for the named subject and action or a default set.
    pub async fn simulate_policy(
        &self,
        _admin: &InstallationAdministrator,
        req: SimulatePolicyRequest,
    ) -> Result<SimulatePolicyResponse, AuthorizationError> {
        use sid_authz::simulator::{ImpactType, PolicySimulator, ProposedChange};
        use sid_proto::sid::v1::policy_change::Change;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        if req.proposed_changes.is_empty() {
            return Err(AuthorizationError::MissingField("proposed_changes"));
        }

        let mut changes = Vec::with_capacity(req.proposed_changes.len());
        for pc in &req.proposed_changes {
            changes.push(match &pc.change {
                Some(Change::CreatePolicy(cp)) => ProposedChange::CreatePolicy {
                    name: cp.name.clone(),
                    policy_text: cp.policy_text.clone(),
                    effect: policy_effect(cp.effect),
                },
                Some(Change::UpdatePolicy(up)) => ProposedChange::UpdatePolicy {
                    id: wire_id(up.id.as_ref(), "proposed_changes.update_policy.id")?,
                    policy_text: up.policy_text.clone(),
                    effect: up.effect.map(policy_effect),
                    enabled: up.enabled,
                },
                Some(Change::DeletePolicyId(id)) => ProposedChange::DeletePolicy {
                    id: wire_id(Some(id), "proposed_changes.delete_policy_id")?,
                },
                Some(Change::AssignRole(_)) | Some(Change::RevokeAssignmentId(_)) => {
                    return Err(AuthorizationError::NotInThisBuild(
                        "simulate_role_assignment",
                    ));
                }
                None => {
                    return Err(invalid_field(
                        "proposed_changes",
                        "a change names no action",
                    ));
                }
            });
        }

        // Without a named subject, a synthetic one.
        let subjects = match &req.subject {
            Some(s) => vec![s.clone()],
            None => vec!["user:00000000-0000-0000-0000-000000000000".to_string()],
        };
        let actions = match &req.action {
            Some(a) => vec![a.clone()],
            None => ["read", "write", "delete", "admin"]
                .map(String::from)
                .to_vec(),
        };
        let resource = req
            .resource
            .clone()
            .unwrap_or_else(|| format!("project:{project_id}"));

        let result = PolicySimulator::new(self.storage.clone())
            .simulate(project_id, &changes, &subjects, &actions, &resource)
            .await
            .map_err(|e| internal("simulate", e))?;

        info!(
            project_id = %project_id,
            changes = changes.len(),
            checked = result.total_checked,
            gained = result.total_gained,
            lost = result.total_lost,
            "policy simulation completed"
        );

        let impacts = result
            .impacts
            .into_iter()
            .map(|i| sid_proto::sid::v1::SimulationImpact {
                subject: i.subject,
                action: i.action,
                resource: i.resource,
                current_allowed: i.current_allowed,
                proposed_allowed: i.proposed_allowed,
                impact_type: match i.impact_type {
                    ImpactType::Gained => sid_proto::sid::v1::SimulationImpactType::Gained,
                    ImpactType::Lost => sid_proto::sid::v1::SimulationImpactType::Lost,
                    ImpactType::Unchanged => sid_proto::sid::v1::SimulationImpactType::Unchanged,
                } as i32,
                current_reason: i.current_reason,
                proposed_reason: i.proposed_reason,
            })
            .collect();

        Ok(SimulatePolicyResponse {
            project_id: Some(project_id.into()),
            impacts,
            total_checked: result.total_checked as i32,
            total_gained: result.total_gained as i32,
            total_lost: result.total_lost as i32,
            total_unchanged: result.total_unchanged as i32,
            warnings: result.warnings,
            errors: result.errors,
            simulated_at: Some(to_timestamp(chrono::Utc::now())),
        })
    }
}

#[cfg(test)]
mod tests;
