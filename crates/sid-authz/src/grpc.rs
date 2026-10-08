// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AuthzService implementation.
//!
//! CE authorization: RBAC + Cedar ABAC via AuthzEngine trait.
//! CRUD operations (role/group/policy) go through StorageBackend.
//! check_permission/batch_check delegate to AuthzEngine.
//! evaluate_policy/validate_policy use CedarService.

use crate::cedar::{CedarError, CedarService};
use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::resource_token::ResourceTokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::service_auth::authenticate_service;
use sid_authn::token_state::{TokenState, current_state};
use sid_core::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, maintenance,
    missing_field, not_found, not_in_this_build, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::audit::{ActorType, AuditOutcome};
use sid_core::models::{
    AUTHZ_CHECK, AuditEntry, CedarPolicy, CedarPolicyId, ConnectorState, Group, GroupId,
    GroupMember, ProfileId, ProjectId, ProvisioningConnectorId, ResourceId, ResourceState, Role,
    RoleAssignment, RoleAssignmentId, RoleAssignmentPrincipal, RoleId, TOKEN_INTROSPECT,
};
use sid_plugin::StorageBackend;
use sid_plugin::audit::AuditLog;
use sid_plugin::authz::{AuthzCheckRequest, AuthzEngine};
use sid_proto::sid::v1::authz::*;
use sid_proto::sid::v1::authz_service_server::AuthzService;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

// ── Utility helpers ─────────────────────────────────────────────────

fn to_timestamp(dt: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

#[allow(clippy::result_large_err)]
fn parse_profile_id(id: &str) -> Result<ProfileId, Status> {
    ProfileId::parse(id).map_err(|_| invalid_field("profile_id", "not a profile identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_project_id(id: &str) -> Result<ProjectId, Status> {
    uuid::Uuid::parse_str(id)
        .map(ProjectId)
        .map_err(|_| invalid_field("project_id", "not a project identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_role_id(id: &str) -> Result<RoleId, Status> {
    uuid::Uuid::parse_str(id)
        .map(RoleId)
        .map_err(|_| invalid_field("role_id", "not a role identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_group_id(id: &str) -> Result<GroupId, Status> {
    uuid::Uuid::parse_str(id)
        .map(GroupId)
        .map_err(|_| invalid_field("group_id", "not a group identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_policy_id(id: &str) -> Result<CedarPolicyId, Status> {
    uuid::Uuid::parse_str(id)
        .map(CedarPolicyId)
        .map_err(|_| invalid_field("policy_id", "not a policy identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_assignment_id(id: &str) -> Result<RoleAssignmentId, Status> {
    uuid::Uuid::parse_str(id)
        .map(RoleAssignmentId)
        .map_err(|_| invalid_field("assignment_id", "not a role assignment identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_machine_user_id(id: &str) -> Result<sid_core::models::MachineUserId, Status> {
    sid_core::models::MachineUserId::parse(id)
        .map_err(|_| invalid_field("machine_user_id", "not a machine user identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_connector_id(
    id: &sid_proto::sid::v1::ids::ProvisioningConnectorId,
) -> Result<ProvisioningConnectorId, Status> {
    ProvisioningConnectorId::try_from(id).map_err(|_| {
        invalid_field(
            "provisioning_connector_id",
            "not a provisioning connector identifier",
        )
    })
}

/// ROLE_NOT_FOUND for `id`.
fn role_not_found(id: RoleId) -> Status {
    not_found(ErrorReason::RoleNotFound, "Role", id.0.to_string())
}

/// GROUP_NOT_FOUND for `name` (an identifier or a group name).
fn group_not_found(name: impl Into<String>) -> Status {
    not_found(ErrorReason::GroupNotFound, "Group", name)
}

/// POLICY_NOT_FOUND for `id`.
fn policy_not_found(id: CedarPolicyId) -> Status {
    not_found(ErrorReason::PolicyNotFound, "Policy", id.0.to_string())
}

/// The checker may not ask this question: told apart from the subject's
/// denial, which is an answer.
fn checker_denied() -> Status {
    ApiError::new(
        ErrorReason::InsufficientPermissions,
        "the caller may not ask about permissions on this resource",
    )
    .into()
}

/// A failure evaluating a permission question: a malformed subject or
/// resource is the caller's mistake, an unreachable store is an outage that
/// never becomes an answer, anything else as [`engine_refusal`].
fn query_refusal(operation: &'static str, e: sid_plugin::authz::AuthzError) -> Status {
    use sid_plugin::authz::AuthzError;
    match e {
        AuthzError::InvalidSubject(_) => invalid_field("evaluation", "not a subject reference"),
        AuthzError::InvalidResource(_) => invalid_field("target", "not a target reference"),
        AuthzError::Storage(why) => dependency_unavailable("permission decision", why),
        e => engine_refusal(operation, e),
    }
}

/// Records a question about another subject with the asker as the acting
/// party and the evaluated subject apart from it (D054); a question about
/// oneself needs no separate record.
fn record_query(asker: &Asker, check: &AuthzCheckRequest, outcome: PermissionOutcome) {
    let asking = asker.own_subject();
    if asking != check.subject {
        info!(
            target: "sid_authz::permission_query",
            asker = %asking,
            subject = %check.subject,
            action = %check.action,
            resource = %check.resource,
            outcome = outcome.as_str_name(),
            "permission query answered"
        );
    }
}

/// An authorization engine failure: an unsupported operation is not part of
/// this build's engine, anything else is internal.
fn engine_refusal(operation: &'static str, e: sid_plugin::authz::AuthzError) -> Status {
    match e {
        sid_plugin::authz::AuthzError::NotSupported(_) => not_in_this_build(operation),
        other => internal(operation, other),
    }
}

fn proto_to_policy_effect(proto: i32) -> sid_core::models::PolicyEffect {
    match sid_proto::sid::v1::PolicyEffect::try_from(proto) {
        Ok(sid_proto::sid::v1::PolicyEffect::Forbid) => sid_core::models::PolicyEffect::Forbid,
        _ => sid_core::models::PolicyEffect::Permit,
    }
}

/// Extract project_id from a resource string.
///
/// Supported formats:
/// - "project:<uuid>" → project UUID
/// - bare UUID → interpreted as project ID
/// - "<type>:<id>" → attempt to parse <id> as project UUID
#[allow(clippy::result_large_err, dead_code)]
pub fn extract_project_from_resource(resource: &str) -> Result<ProjectId, Status> {
    if let Some(id) = resource.strip_prefix("project:") {
        return parse_project_id(id);
    }

    if let Ok(uuid) = uuid::Uuid::parse_str(resource) {
        return Ok(ProjectId(uuid));
    }

    if let Some((_type_part, id_part)) = resource.split_once(':')
        && let Ok(uuid) = uuid::Uuid::parse_str(id_part)
    {
        return Ok(ProjectId(uuid));
    }

    Err(invalid_field(
        "resource",
        "names a project: 'project:<uuid>' or '<type>:<uuid>'",
    ))
}

// ── Conversion helpers ──────────────────────────────────────────────

fn role_to_proto(r: &Role) -> sid_proto::sid::v1::Role {
    sid_proto::sid::v1::Role {
        id: r.id.0.to_string(),
        project_id: r.project_id.0.to_string(),
        name: r.key.clone(),
        description: r.description.clone(),
        permissions: r.permissions.clone(),
        created_at: Some(to_timestamp(r.created_at)),
        updated_at: Some(to_timestamp(r.updated_at)),
    }
}

fn group_to_proto(g: &Group) -> sid_proto::sid::v1::Group {
    sid_proto::sid::v1::Group {
        id: g.id.0.to_string(),
        project_id: g.project_id.0.to_string(),
        name: g.name.clone(),
        description: g.description.clone(),
        created_at: Some(to_timestamp(g.created_at)),
        updated_at: Some(to_timestamp(g.updated_at)),
    }
}

fn assignment_to_proto(a: &RoleAssignment) -> sid_proto::sid::v1::RoleAssignment {
    let principal = match &a.principal {
        RoleAssignmentPrincipal::Profile(pid) => {
            Some(role_assignment::Principal::ProfileId(pid.to_string()))
        }
        RoleAssignmentPrincipal::Group(gid) => {
            Some(role_assignment::Principal::GroupId(gid.0.to_string()))
        }
        RoleAssignmentPrincipal::MachineUser(mid) => {
            Some(role_assignment::Principal::MachineUserId(mid.to_string()))
        }
        RoleAssignmentPrincipal::OAuthClient(client_id) => {
            Some(role_assignment::Principal::OauthClientId(client_id.clone()))
        }
        RoleAssignmentPrincipal::ProvisioningConnector(connector) => Some(
            role_assignment::Principal::ProvisioningConnectorId((*connector).into()),
        ),
    };

    sid_proto::sid::v1::RoleAssignment {
        id: a.id.0.to_string(),
        principal,
        role_id: a.role_id.0.to_string(),
        scope: a.scope.clone(),
        expires_at: a.expires_at.map(to_timestamp),
        created_at: Some(to_timestamp(a.created_at)),
        admin: a.admin.as_ref().map(envelope_to_proto),
        provenance: a.provenance.as_ref().map(|p| AssignmentProvenance {
            granted_by: p.granted_by.clone(),
            basis_assignment_id: p.basis.map(|id| id.0.to_string()),
            depends_on_assignment_id: p.depends_on.map(|id| id.0.to_string()),
            approved_ceiling: p
                .ceiling
                .as_ref()
                .map(|c| c.iter().cloned().collect())
                .unwrap_or_default(),
        }),
    }
}

fn envelope_to_proto(e: &sid_core::models::AdminEnvelope) -> AdminEnvelope {
    use sid_core::models::AdminOperation as Op;
    use sid_core::models::RecipientKind as Kind;
    AdminEnvelope {
        operations: e
            .operations
            .iter()
            .map(|op| match op {
                Op::Assign => AdminOperation::Assign,
                Op::Revoke => AdminOperation::Revoke,
                Op::EditRole => AdminOperation::EditRole,
                Op::Redelegate => AdminOperation::Redelegate,
            } as i32)
            .collect(),
        role_ids: e.roles.iter().map(|id| id.0.to_string()).collect(),
        permission_ceiling: e.permission_ceiling.iter().cloned().collect(),
        recipient_kinds: e
            .recipient_kinds
            .iter()
            .map(|kind| match kind {
                Kind::Profile => RecipientKind::Profile,
                Kind::Group => RecipientKind::Group,
                Kind::MachineUser => RecipientKind::MachineUser,
                Kind::OAuthClient => RecipientKind::OauthClient,
            } as i32)
            .collect(),
        recipient_group_id: e.recipient_group.map(|g| g.0.to_string()),
        max_validity: Some(prost_types::Duration {
            seconds: e.max_validity_secs,
            nanos: 0,
        }),
    }
}

/// The envelope a request asks for, refused naming the field it breaks.
#[allow(clippy::result_large_err)]
fn envelope_from_proto(e: AdminEnvelope) -> Result<sid_core::models::AdminEnvelope, Status> {
    use sid_core::models::AdminOperation as Op;
    use sid_core::models::EnvelopeError;
    use sid_core::models::RecipientKind as Kind;
    let operations = e
        .operations
        .iter()
        .map(|op| match AdminOperation::try_from(*op) {
            Ok(AdminOperation::Assign) => Ok(Op::Assign),
            Ok(AdminOperation::Revoke) => Ok(Op::Revoke),
            Ok(AdminOperation::EditRole) => Ok(Op::EditRole),
            Ok(AdminOperation::Redelegate) => Ok(Op::Redelegate),
            Ok(AdminOperation::Unspecified) | Err(_) => Err(invalid_field(
                "admin.operations",
                "not an administration operation",
            )),
        })
        .collect::<Result<_, _>>()?;
    let roles = e
        .role_ids
        .iter()
        .map(|id| {
            uuid::Uuid::parse_str(id)
                .map(RoleId)
                .map_err(|_| invalid_field("admin.role_ids", "not a role identifier"))
        })
        .collect::<Result<_, _>>()?;
    let recipient_kinds = e
        .recipient_kinds
        .iter()
        .map(|kind| match RecipientKind::try_from(*kind) {
            Ok(RecipientKind::Profile) => Ok(Kind::Profile),
            Ok(RecipientKind::Group) => Ok(Kind::Group),
            Ok(RecipientKind::MachineUser) => Ok(Kind::MachineUser),
            Ok(RecipientKind::OauthClient) => Ok(Kind::OAuthClient),
            Ok(RecipientKind::Unspecified) | Err(_) => Err(invalid_field(
                "admin.recipient_kinds",
                "not a recipient kind",
            )),
        })
        .collect::<Result<_, _>>()?;
    let recipient_group = e
        .recipient_group_id
        .map(|id| {
            uuid::Uuid::parse_str(&id)
                .map(GroupId)
                .map_err(|_| invalid_field("admin.recipient_group_id", "not a group identifier"))
        })
        .transpose()?;
    let max_validity_secs = match e.max_validity {
        Some(d) if d.nanos == 0 => d.seconds,
        Some(_) => {
            return Err(invalid_field(
                "admin.max_validity",
                "not a whole number of seconds",
            ));
        }
        None => return Err(missing_field("admin.max_validity")),
    };
    let envelope = sid_core::models::AdminEnvelope {
        operations,
        roles,
        permission_ceiling: e.permission_ceiling.into_iter().collect(),
        recipient_kinds,
        recipient_group,
        max_validity_secs,
    };
    envelope.validate().map_err(|err| {
        let field = match err {
            EnvelopeError::NoOperations => "admin.operations",
            EnvelopeError::NoRoles => "admin.role_ids",
            EnvelopeError::NoPermissionCeiling => "admin.permission_ceiling",
            EnvelopeError::NoRecipientKinds => "admin.recipient_kinds",
            EnvelopeError::Validity => "admin.max_validity",
        };
        invalid_field(field, err.to_string())
    })?;
    Ok(envelope)
}

fn policy_to_proto(p: &CedarPolicy) -> Policy {
    let effect = if p.effect == sid_core::models::PolicyEffect::Permit {
        sid_proto::sid::v1::PolicyEffect::Permit
    } else {
        sid_proto::sid::v1::PolicyEffect::Forbid
    };

    Policy {
        id: p.id.0.to_string(),
        project_id: p.project_id.0.to_string(),
        name: p.name.clone(),
        description: p.description.clone(),
        policy_text: p.policy_text.clone(),
        effect: effect.into(),
        enabled: p.enabled,
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
    }
}

// ── Service ─────────────────────────────────────────────────────────

pub struct AuthzServiceImpl {
    engine: Arc<dyn AuthzEngine>,
    storage: Arc<dyn StorageBackend>,
    cedar: CedarService,
    maintenance_mode: Arc<AtomicBool>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// Verifies the tokens a permission checker obtained for this
    /// installation's authorization API; without it no service may ask
    /// about others (D054).
    service_tokens: Option<Arc<ResourceTokenVerifier>>,
    /// Services the deployment trusts to confirm checks of an original
    /// request; nobody unless configured.
    request_verifiers: crate::request_verifier::RequestVerifiers,
    /// Where denied permission questions are recorded.
    audit: Arc<dyn AuditLog>,
}

/// Most checks one batch may carry: bounded before any is admitted or
/// evaluated.
const MAX_BATCH_CHECKS: usize = 100;

/// Who asks a permission question.
enum Asker {
    /// A Profile, by its own installation credential: about itself, or, as
    /// an administrator, about a named subject.
    Profile(Caller),
    /// A service, by its own token for the authorization API, as this engine
    /// subject: about itself, or with the checker role about others (D054).
    Service(String),
}

impl Asker {
    /// The asker's own engine subject.
    fn own_subject(&self) -> String {
        match self {
            Self::Profile(caller) => format!("user:{}", caller.profile_id),
            Self::Service(subject) => subject.clone(),
        }
    }

    /// The asker as an audit record's actor.
    fn audit_actor(&self) -> (String, ActorType) {
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
}

/// The audit action of a denied permission question.
const PERMISSION_CHECK_AUDIT: &str = "authz.permission_check";

/// What an original request's token establishes.
#[derive(Clone)]
struct RequestEvidence {
    subject: String,
    context: std::collections::HashMap<String, String>,
    /// The token is key-bound and no proof was confirmed.
    missing: bool,
    /// Who the token says acts for the subject (RFC 8693 §4.1 `act`).
    delegated: Option<String>,
    /// The client the token was issued to.
    client: Option<String>,
}

/// The engine subject of a service named for abstract evaluation; a user is
/// resolved through the target's issuer instead.
#[allow(clippy::result_large_err)]
fn named_subject(named: &SubjectReference) -> Result<String, Status> {
    use subject_reference::Kind;
    match named.kind.as_ref() {
        Some(Kind::MachineUserId(id)) => {
            let id = sid_core::models::MachineUserId::try_from(id)
                .map_err(|_| invalid_field("named_subject", "not a machine user identifier"))?;
            Ok(format!("machine:{id}"))
        }
        Some(Kind::OauthClientId(client_id)) if !client_id.is_empty() => {
            Ok(format!("oauth_client:{client_id}"))
        }
        _ => Err(missing_field("named_subject")),
    }
}

/// Longest time a confirmation may be used for its pending request: long
/// enough to retry the permission call, short enough that it is no permit.
const MAX_CONFIRMATION_WINDOW: chrono::Duration = chrono::Duration::seconds(60);
/// Clock difference tolerated between the verifier and this service.
const CONFIRMATION_CLOCK_SKEW: chrono::Duration = chrono::Duration::seconds(5);

/// INVALID_ARGUMENT for a confirmation that does not fit its token or
/// request; never read as an allow or as a bearer token.
fn confirmation_unfit(field: &'static str, why: &str) -> Status {
    invalid_field(field, why)
}

/// The time `ts` stands for, if any.
fn instant(ts: Option<&prost_types::Timestamp>) -> Option<chrono::DateTime<chrono::Utc>> {
    let ts = ts?;
    chrono::DateTime::from_timestamp(ts.seconds, u32::try_from(ts.nanos).ok()?)
}

/// Whether `confirmation` fits the original request's verified `claims`
/// at `now`: the proof was made with the token's own key (RFC 9449 §6.1),
/// for a well-formed method and external URI without query or fragment
/// (the DPoP `htu`, RFC 9449 §4.2), for one identified request, recently,
/// and is used only within its short window and the token's lifetime.
#[allow(clippy::result_large_err)]
fn check_confirmation(
    confirmation: &RequestConfirmation,
    claims: &sid_authn::jwt::AccessTokenClaims,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Status> {
    match &claims.cnf {
        Some(cnf) if cnf.jkt == confirmation.jkt => {}
        Some(_) => {
            return Err(confirmation_unfit(
                "request.confirmation.jkt",
                "not the token's key",
            ));
        }
        None => {
            return Err(confirmation_unfit(
                "request.confirmation.jkt",
                "the token is bound to no key",
            ));
        }
    }
    // RFC 9110 §9.1: a method is a token.
    let tchar = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if confirmation.method.is_empty() || !confirmation.method.chars().all(tchar) {
        return Err(confirmation_unfit(
            "request.confirmation.method",
            "not an HTTP method",
        ));
    }
    let uri = &confirmation.uri;
    let authority = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or("");
    if authority.is_empty()
        || authority.starts_with('/')
        || uri.contains(['?', '#'])
        || uri.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(confirmation_unfit(
            "request.confirmation.uri",
            "not an absolute URI without query and fragment",
        ));
    }
    if confirmation.request_id.len() != 16 {
        return Err(confirmation_unfit(
            "request.confirmation.request_id",
            "not 16 bytes",
        ));
    }
    let verified_at = instant(confirmation.verified_at.as_ref()).ok_or_else(|| {
        confirmation_unfit("request.confirmation.verified_at", "missing or not a time")
    })?;
    let valid_until = instant(confirmation.valid_until.as_ref()).ok_or_else(|| {
        confirmation_unfit("request.confirmation.valid_until", "missing or not a time")
    })?;
    if verified_at > now + CONFIRMATION_CLOCK_SKEW {
        return Err(confirmation_unfit(
            "request.confirmation.verified_at",
            "in the future",
        ));
    }
    if valid_until <= now {
        return Err(confirmation_unfit(
            "request.confirmation.valid_until",
            "expired",
        ));
    }
    if valid_until <= verified_at || valid_until - verified_at > MAX_CONFIRMATION_WINDOW {
        return Err(confirmation_unfit(
            "valid_until",
            "outside the allowed window",
        ));
    }
    if valid_until.timestamp() > claims.exp {
        return Err(confirmation_unfit(
            "valid_until",
            "beyond the token's expiry",
        ));
    }
    Ok(())
}

/// What one call has already established for its asker: the resources it
/// was admitted to ask about others on, and what each original request's
/// token establishes on a resource. A batch about one original request
/// carries the same evidence in every question (D054: questions about one
/// request share its verified context); each question is still admitted,
/// but the same admission and the same evidence are not established twice.
#[derive(Default)]
struct Established<'a> {
    asking: Vec<ResourceId>,
    evidence: Vec<(ResourceId, &'a RequestEvaluation, RequestEvidence)>,
}

/// One admitted question, ready for the engine.
struct Question {
    check: AuthzCheckRequest,
    /// The original request's token is bound to a key whose proof nobody
    /// confirmed: the subject cannot act with it, whatever policy says.
    evidence_missing: bool,
    /// How the subject was established: `self`, `named` or `request`.
    evaluation: &'static str,
    /// For a request-bound question, the token's delegated actor and client.
    delegated: Option<String>,
    client: Option<String>,
}

impl Asker {
    /// The asker as an administrator of role assignments: the
    /// installation's administrator is the root of its scope, anyone else
    /// administers only through its own administrative assignments.
    #[allow(clippy::result_large_err)]
    fn administrator(&self) -> Result<crate::admin::Administrator, Status> {
        use crate::admin::Administrator;
        use sid_core::models::AuthzPrincipal;
        Ok(match self {
            Self::Profile(caller) if caller.is_admin() => {
                Administrator::Root(AuthzPrincipal::Profile(caller.profile_id))
            }
            Self::Profile(caller) => {
                Administrator::Holder(AuthzPrincipal::Profile(caller.profile_id))
            }
            Self::Service(subject) => match subject.split_once(':') {
                Some(("machine", id)) => Administrator::Holder(AuthzPrincipal::MachineUser(
                    sid_core::models::MachineUserId::parse(id)
                        .map_err(|_| internal("administrator", "unparsable machine subject"))?,
                )),
                Some(("oauth_client", id)) => {
                    Administrator::Holder(AuthzPrincipal::OAuthClient(id.to_owned()))
                }
                _ => return Err(internal("administrator", "unknown service subject")),
            },
        })
    }

    /// An audit entry naming the asker as the actor of `action`.
    fn audit(&self, action: &str, resource: String) -> AuditEntry {
        let (actor, kind) = self.audit_actor();
        AuditEntry::by_actor(actor, kind, action, resource)
    }
}

/// The status of a refused administration change: no covering authority,
/// an authority that changed before the commit, or an invalid change.
fn administration_refusal(error: sid_core::Error) -> Status {
    use sid_core::grpc_error::refuse::authority_changed;
    match error {
        sid_core::Error::AuthorizationDenied(_) => ApiError::new(
            ErrorReason::InsufficientPermissions,
            "no administrative assignment of the caller covers this change",
        )
        .into(),
        sid_core::Error::Fenced(_) => authority_changed(),
        sid_core::Error::Validation(why) => invalid_field("assignment", &why),
        // Only the root receives this: an approved ceiling binds the role.
        sid_core::Error::InvalidState(why) => ApiError::new(
            ErrorReason::InvalidState,
            "the edit would widen an assignment past its approved ceiling",
        )
        .with_precondition("APPROVED_CEILING", "role", why)
        .into(),
        sid_core::Error::NotFound(what) => not_found(ErrorReason::RoleNotFound, "Role", what),
        other => storage_failure(other),
    }
}

impl AuthzServiceImpl {
    pub fn new(
        engine: Arc<dyn AuthzEngine>,
        storage: Arc<dyn StorageBackend>,
        cedar: CedarService,
        maintenance_mode: Arc<AtomicBool>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        audit: Arc<dyn AuditLog>,
    ) -> Self {
        Self {
            engine,
            storage,
            cedar,
            maintenance_mode,
            jwt,
            revocation,
            service_tokens: None,
            request_verifiers: Default::default(),
            audit,
        }
    }

    /// Trust the configured services to confirm checks of original requests
    /// to their resources (D054 receiver-side verifier trust).
    pub fn with_request_verifiers(
        mut self,
        verifiers: crate::request_verifier::RequestVerifiers,
    ) -> Self {
        self.request_verifiers = verifiers;
        self
    }

    /// Lets services holding the checker role ask about others, with their
    /// own tokens for the authorization API `tokens` verifies.
    pub fn with_service_tokens(mut self, tokens: Arc<ResourceTokenVerifier>) -> Self {
        self.service_tokens = Some(tokens);
        self
    }

    /// Who asks: a service with its own token for the authorization API, or
    /// else a Profile with its own installation credential.
    async fn asker<T>(&self, request: &Request<T>) -> Result<Asker, Status> {
        if let Some(tokens) = &self.service_tokens {
            // A service token is valid only for the authorization API and a
            // user's sign-in token never is, so each credential has one path.
            match authenticate_service(request, self.storage.as_ref(), tokens, &self.revocation)
                .await
            {
                Ok(service) => return Ok(Asker::Service(service.subject())),
                Err(status) if status.code() == tonic::Code::Unauthenticated => {}
                Err(status) => return Err(status),
            }
        }
        Ok(Asker::Profile(self.caller(request).await?))
    }

    /// Every one of `checks` admitted for `asker` before any subject is
    /// evaluated (D054): one refused question refuses them all.
    async fn admit_all(
        &self,
        asker: &Asker,
        checks: &[CheckPermissionRequest],
    ) -> Result<Vec<Question>, Status> {
        if checks.len() > MAX_BATCH_CHECKS {
            return Err(invalid_field("checks", "at most 100 checks in one batch"));
        }
        let mut questions = Vec::with_capacity(checks.len());
        let mut established = Established::default();
        for check in checks {
            match self.question(asker, check, &mut established).await {
                Ok(question) => questions.push(question),
                Err(refused) if refused.code() == tonic::Code::PermissionDenied => {
                    self.record_caller_refusal(asker, check).await?;
                    return Err(refused);
                }
                Err(refused) => return Err(refused),
            }
        }
        Ok(questions)
    }

    /// Record that `asker` was refused `check` (audit-log.md: denied
    /// permission checks), with the asker as the actor and the target as
    /// what was affected.
    async fn record_caller_refusal(
        &self,
        asker: &Asker,
        check: &CheckPermissionRequest,
    ) -> Result<(), Status> {
        use permission_target::Scope;
        let target = match check.target.as_ref().and_then(|t| t.scope.as_ref()) {
            Some(Scope::Resource(id)) => ResourceId::try_from(id)
                .map(|id| format!("oauth_resource:{id}"))
                .unwrap_or_else(|_| "oauth_resource:unknown".to_owned()),
            Some(Scope::ProjectId(id)) => format!("project:{id}"),
            None => "unknown".to_owned(),
        };
        let metadata = serde_json::json!({
            "refused": "caller",
            "action": check.action,
        });
        self.record_denial(asker, &target, metadata).await
    }

    /// Record a denied permission question about `target` asked by `asker`:
    /// the asker is the actor, the evaluated subject and any original
    /// delegated actor are in `metadata`, apart from it (D054 disclosure).
    /// An unwritten record leaves the question unanswered.
    async fn record_denial(
        &self,
        asker: &Asker,
        target: &str,
        metadata: serde_json::Value,
    ) -> Result<(), Status> {
        let (actor, actor_type) = asker.audit_actor();
        let entry = AuditEntry {
            actor_id: actor,
            actor_type,
            action: PERMISSION_CHECK_AUDIT.to_owned(),
            resource: target.to_owned(),
            outcome: AuditOutcome::Denied,
            metadata,
            ip_address: None,
            device_id: None,
        };
        self.audit
            .log(target, entry)
            .await
            .map(|_| ())
            .map_err(|e| dependency_unavailable("audit log", e))
    }

    /// `check` as `asker` may ask it, or why not: the target, whose
    /// permission is evaluated and on what evidence.
    async fn question<'a>(
        &self,
        asker: &Asker,
        check: &'a CheckPermissionRequest,
        established: &mut Established<'a>,
    ) -> Result<Question, Status> {
        use check_permission_request::Evaluation;
        use permission_target::Scope;

        let target = check
            .target
            .as_ref()
            .ok_or_else(|| missing_field("target"))?;
        let resource = match &target.scope {
            Some(Scope::Resource(id)) => Some(ResourceId::try_from(id).map_err(|_| {
                invalid_field("target.resource", "not a protected resource identifier")
            })?),
            Some(Scope::ProjectId(id)) => {
                parse_project_id(id)?;
                None
            }
            None => return Err(missing_field("target")),
        };
        let engine_resource = match (&target.scope, resource) {
            (_, Some(resource)) => format!("oauth_resource:{resource}"),
            (Some(Scope::ProjectId(id)), None) => format!("project:{id}"),
            _ => return Err(missing_field("target")),
        };
        // The object is part of the question, in the application's own
        // namespace; policies may name it.
        let mut context = std::collections::HashMap::new();
        if !target.object.is_empty() {
            context.insert("object".to_owned(), target.object.clone());
        }
        let evaluation = check
            .evaluation
            .as_ref()
            .ok_or_else(|| missing_field("evaluation"))?;
        let mut evidence_missing = false;
        let (mut delegated, mut client) = (None, None);
        let (subject, kind) = match evaluation {
            Evaluation::Self_(_) => (asker.own_subject(), "self"),
            Evaluation::NamedSubject(named) => {
                self.admit_asking(asker, resource, established).await?;
                let subject = match named.kind.as_ref() {
                    Some(subject_reference::Kind::IssuerSubject(issued)) => {
                        self.issuer_subject(resource, issued).await?
                    }
                    _ => named_subject(named)?,
                };
                (subject, "named")
            }
            Evaluation::Request(request) => {
                let (Asker::Service(_), Some(resource)) = (asker, resource) else {
                    return Err(checker_denied());
                };
                self.admit_asking(asker, Some(resource), established)
                    .await?;
                let known = established
                    .evidence
                    .iter()
                    .find(|(on, evaluated, _)| *on == resource && *evaluated == request)
                    .map(|(_, _, evidence)| evidence.clone());
                let evidence = match known {
                    Some(evidence) => evidence,
                    None => {
                        let evidence = self.request_evidence(asker, resource, request).await?;
                        established
                            .evidence
                            .push((resource, request, evidence.clone()));
                        evidence
                    }
                };
                context.extend(evidence.context);
                evidence_missing = evidence.missing;
                delegated = evidence.delegated;
                client = evidence.client;
                (evidence.subject, "request")
            }
        };
        Ok(Question {
            check: AuthzCheckRequest {
                subject,
                action: check.action.clone(),
                resource: engine_resource,
                context,
            },
            evidence_missing,
            evaluation: kind,
            delegated,
            client,
        })
    }

    /// The answers to admitted `questions`, in order. A question whose
    /// subject cannot act without unconfirmed evidence is answered as such
    /// without evaluating it.
    async fn answer(
        &self,
        asker: &Asker,
        questions: Vec<Question>,
        operation: &'static str,
    ) -> Result<Vec<CheckPermissionResponse>, Status> {
        let evaluated: Vec<AuthzCheckRequest> = questions
            .iter()
            .filter(|q| !q.evidence_missing)
            .map(|q| q.check.clone())
            .collect();
        let mut results = self
            .engine
            .batch_check(&evaluated)
            .await
            .map_err(|e| query_refusal(operation, e))?
            .into_iter();
        let mut answers = Vec::with_capacity(questions.len());
        for question in &questions {
            let (outcome, reason) = if question.evidence_missing {
                (PermissionOutcome::EvidenceRequired, None)
            } else {
                let result = results.next().ok_or_else(|| {
                    internal(operation, "the engine answered fewer questions than asked")
                })?;
                let outcome = if result.is_allowed() {
                    PermissionOutcome::Allowed
                } else {
                    PermissionOutcome::Denied
                };
                (outcome, Some(result.reason().to_string()))
            };
            record_query(asker, &question.check, outcome);
            if outcome == PermissionOutcome::Denied {
                let metadata = serde_json::json!({
                    "refused": "subject",
                    "action": question.check.action,
                    "subject": question.check.subject,
                    "evaluation": question.evaluation,
                    "delegated_actor": question.delegated,
                    "client_id": question.client,
                });
                self.record_denial(asker, &question.check.resource, metadata)
                    .await?;
            }
            answers.push(CheckPermissionResponse {
                // A service gets the decision, not the policy behind it.
                reason: match asker {
                    Asker::Profile(_) => reason,
                    Asker::Service(_) => None,
                },
                zookie: None,
                outcome: outcome.into(),
            });
        }
        Ok(answers)
    }

    /// [`Self::may_ask_about_others`], once per resource in one call.
    async fn admit_asking(
        &self,
        asker: &Asker,
        resource: Option<ResourceId>,
        established: &mut Established<'_>,
    ) -> Result<(), Status> {
        if let Some(resource) = resource
            && established.asking.contains(&resource)
        {
            return Ok(());
        }
        self.may_ask_about_others(asker, resource).await?;
        if let Some(resource) = resource {
            established.asking.push(resource);
        }
        Ok(())
    }

    /// Whether `asker` may ask about a subject other than itself on
    /// `resource`: a service holding the checker role on that registered
    /// resource (D054), or an administrator of this installation.
    async fn may_ask_about_others(
        &self,
        asker: &Asker,
        resource: Option<ResourceId>,
    ) -> Result<(), Status> {
        match (asker, resource) {
            (Asker::Profile(caller), _) if caller.is_admin() => Ok(()),
            (Asker::Service(checker), Some(resource)) => {
                let decision = self
                    .engine
                    .check(&AuthzCheckRequest {
                        subject: checker.clone(),
                        action: AUTHZ_CHECK.to_owned(),
                        resource: format!("oauth_resource:{resource}"),
                        context: Default::default(),
                    })
                    .await
                    // An unknown authority never becomes an allow.
                    .map_err(|e| dependency_unavailable("checker permission", e))?;
                if decision.is_allowed() {
                    Ok(())
                } else {
                    Err(checker_denied())
                }
            }
            _ => Err(checker_denied()),
        }
    }

    /// The engine subject of a user named by `named` on `resource`: the
    /// subject the target's issuer gives the target's organization, resolved
    /// under that hop's rule (subject-resolution contract). Only the target's
    /// own issuer names its subjects; anything else is refused, never cast.
    /// A well-formed subject that names nobody is evaluated like anyone
    /// without a grant, so the answer reveals no existence.
    async fn issuer_subject(
        &self,
        resource: Option<ResourceId>,
        named: &IssuerSubject,
    ) -> Result<String, Status> {
        use sid_authn::subject::SubjectRule;
        let not_ours = || invalid_field("named_subject", "not a subject of the target's issuer");
        let tokens = self.service_tokens.as_ref().ok_or_else(not_ours)?;
        let resource = resource
            .ok_or_else(|| invalid_field("target", "a user is named on a registered resource"))?;
        let registered = self
            .storage
            .get_protected_resource(resource)
            .await
            .map_err(|e| dependency_unavailable("protected resource registry", e))?
            .filter(|r| r.state == ResourceState::Active && r.issuer_id == tokens.issuer_id())
            .ok_or_else(not_ours)?;
        if named.issuer != tokens.issuer() {
            return Err(not_ours());
        }
        debug_assert_eq!(registered.issuer_id, tokens.issuer_id());
        match SubjectRule::for_resource(tokens.oidc_issuer()) {
            SubjectRule::ManagedProfile => ProfileId::parse(&named.subject)
                .map(|profile| format!("user:{profile}"))
                .map_err(|_| not_ours()),
            // The hop gives a binding: its subject is opaque here.
            SubjectRule::OrganizationBinding => Err(not_ours()),
        }
    }

    /// The subject of an original request to `resource`, established from
    /// the request's own access token (D054 request-bound evaluation): the
    /// token is this issuer's, for exactly that resource, unrevoked, and its
    /// actor can act now. Its issuer-owned facts become the evaluation
    /// context; nothing is taken from the caller.
    async fn request_evidence(
        &self,
        asker: &Asker,
        resource: ResourceId,
        request: &RequestEvaluation,
    ) -> Result<RequestEvidence, Status> {
        let invalid =
            || invalid_field("request.access_token", "not usable evidence for the target");
        let tokens = self.service_tokens.as_ref().ok_or_else(checker_denied)?;
        let registered = self
            .storage
            .get_protected_resource(resource)
            .await
            .map_err(|e| dependency_unavailable("protected resource registry", e))?
            .filter(|r| r.state == ResourceState::Active && r.issuer_id == tokens.issuer_id())
            .ok_or_else(invalid)?;
        // A token for the authorization API is a caller's credential, never
        // evidence about a subject.
        if registered.indicator.as_str() == tokens.indicator().as_str() {
            return Err(invalid());
        }
        let claims = match tokens
            .verify_for(&request.access_token, &registered.indicator)
            .await
        {
            Ok(claims) => claims,
            Err(sid_core::Error::AuthenticationFailed(_)) => return Err(invalid()),
            Err(e) => return Err(dependency_unavailable("issuer keys", e)),
        };
        if self
            .revocation
            .is_revoked(&claims.jti, &claims.sid)
            .await
            .map_err(|e| dependency_unavailable("token revocation state", e))?
        {
            return Err(invalid());
        }
        let actor = match current_state(self.storage.as_ref(), &claims)
            .await
            .map_err(|e| dependency_unavailable("token state", e))?
        {
            TokenState::Active(actor) => actor,
            TokenState::Inactive => return Err(invalid()),
        };
        // A key-bound token acts only with a confirmed proof of its key on
        // the original request (RFC 9449 §7.1). Only the deployment's
        // configured verifier for this resource may testify to it; the
        // checker role alone never does.
        let missing = match &request.confirmation {
            None => claims.cnf.is_some(),
            Some(confirmation) => {
                let profile = match SenderProofProfile::try_from(confirmation.profile) {
                    Ok(SenderProofProfile::Dpop) => crate::request_verifier::ProofProfile::Dpop,
                    _ => {
                        return Err(confirmation_unfit(
                            "request.confirmation.profile",
                            "not a supported proof kind",
                        ));
                    }
                };
                let Asker::Service(verifier) = asker else {
                    return Err(checker_denied());
                };
                if !self
                    .request_verifiers
                    .permits(verifier, registered.indicator.as_str(), profile)
                {
                    return Err(checker_denied());
                }
                check_confirmation(confirmation, &claims, chrono::Utc::now())?;
                false
            }
        };
        let mut context = std::collections::HashMap::new();
        context.insert("acr".to_owned(), claims.acr.clone());
        context.insert("amr".to_owned(), claims.amr.join(" "));
        context.insert("auth_time".to_owned(), claims.auth_time.to_string());
        Ok(RequestEvidence {
            subject: actor.subject(),
            context,
            missing,
            delegated: claims.act.as_ref().map(|act| act.sub.clone()),
            client: claims.client_id.clone(),
        })
    }

    /// Authenticate the caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// Authenticate the caller of `request` and require the administrator role:
    /// roles, assignments, groups and policies decide every other permission.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = self.caller(request).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// Authenticate the caller of `request` and allow it to ask only about its
    /// own subject; an administrator may ask about any.
    #[allow(clippy::result_large_err)]
    async fn subject_caller<'a, T>(
        &self,
        request: &Request<T>,
        subjects: impl IntoIterator<Item = &'a str>,
    ) -> Result<Caller, Status> {
        let caller = self.caller(request).await?;
        caller.require_own_subjects(subjects)?;
        Ok(caller)
    }

    /// The confidential OAuth client `client_id` names: only a client that
    /// authenticates can act as its own principal.
    async fn confidential_client(&self, client_id: &str) -> Result<(), Status> {
        let client = self
            .storage
            .get_oauth2_client(client_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| not_found(ErrorReason::ApplicationNotFound, "OAuthClient", client_id))?;
        if client.is_public() {
            return Err(ApiError::new(
                ErrorReason::InvalidFieldValue,
                "a public client cannot hold roles: it has no credential",
            )
            .with_field_violation("oauth_client_id", "public client")
            .into());
        }
        Ok(())
    }

    /// A role granting token inspection or permission queries goes only to a
    /// service identity (a machine user or an OAuth client), on one existing,
    /// not retired protected resource: neither is ever project-wide, and a
    /// user's sign-in is no such authority (D054).
    async fn check_service_assignment(&self, assignment: &RoleAssignment) -> Result<(), Status> {
        if !matches!(
            assignment.principal,
            RoleAssignmentPrincipal::MachineUser(_) | RoleAssignmentPrincipal::OAuthClient(_)
        ) {
            return Err(ApiError::new(
                ErrorReason::InvalidFieldValue,
                "token inspection and permission queries are assigned to a machine user or an OAuth client",
            )
            .with_field_violation("principal", "not a service identity")
            .into());
        }
        let Some(resource) = assignment.resource_scope() else {
            return Err(ApiError::new(
                ErrorReason::InvalidFieldValue,
                "token inspection and permission queries are assigned on one protected resource",
            )
            .with_field_violation("scope", "expected oauth_resource:<resource_id>")
            .into());
        };
        self.check_live_resource(resource).await
    }

    /// A provisioning connector's role is assigned only while the connector
    /// is not retired, and only on one live protected resource: the engine
    /// lets a connector act nowhere else.
    async fn check_connector_assignment(
        &self,
        connector: ProvisioningConnectorId,
        assignment: &RoleAssignment,
    ) -> Result<(), Status> {
        let stored = self
            .storage
            .get_provisioning_connector(connector)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ProvisioningConnectorNotFound,
                    "ProvisioningConnector",
                    connector.to_string(),
                )
            })?;
        if stored.state == ConnectorState::Retired {
            return Err(ApiError::new(
                ErrorReason::ResourceRetired,
                "the provisioning connector is retired",
            )
            .with_precondition(
                "CONNECTOR_RETIRED",
                connector.to_string(),
                "assign to a connector that is not retired",
            )
            .into());
        }
        let Some(resource) = assignment.resource_scope() else {
            return Err(ApiError::new(
                ErrorReason::InvalidFieldValue,
                "a provisioning connector's role is assigned on one protected resource",
            )
            .with_field_violation("scope", "expected oauth_resource:<resource_id>")
            .into());
        };
        self.check_live_resource(resource).await
    }

    /// `resource` exists and is not retired.
    async fn check_live_resource(&self, resource: ResourceId) -> Result<(), Status> {
        let stored = self
            .storage
            .get_protected_resource(resource)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ResourceNotFound,
                    "ProtectedResource",
                    resource.to_string(),
                )
            })?;
        if stored.state == ResourceState::Retired {
            return Err(ApiError::new(
                ErrorReason::ResourceRetired,
                "the protected resource is retired",
            )
            .with_precondition(
                "RESOURCE_RETIRED",
                resource.to_string(),
                "assign on a live resource",
            )
            .into());
        }
        Ok(())
    }

    /// A policy is stored only when Cedar parses it: an unparseable one would
    /// make every evaluation of its project fail closed.
    #[allow(clippy::result_large_err)]
    fn check_policy_text(&self, text: &str) -> Result<(), Status> {
        if self.cedar.validate_policy(text).valid {
            Ok(())
        } else {
            Err(invalid_field("policy_text", "not a valid Cedar policy"))
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_maintenance(&self) -> Result<(), Status> {
        if self.maintenance_mode.load(Ordering::Relaxed) {
            Err(maintenance())
        } else {
            Ok(())
        }
    }
}

#[tonic::async_trait]
impl AuthzService for AuthzServiceImpl {
    // ── Permission checks (delegated to AuthzEngine) ────────────────

    #[instrument(skip_all, fields(method = "check_permission"))]
    async fn check_permission(
        &self,
        request: Request<CheckPermissionRequest>,
    ) -> Result<Response<CheckPermissionResponse>, Status> {
        let asker = self.asker(&request).await?;
        let questions = self
            .admit_all(&asker, std::slice::from_ref(request.get_ref()))
            .await?;
        let mut answers = self.answer(&asker, questions, "check_permission").await?;
        Ok(Response::new(answers.remove(0)))
    }

    #[instrument(skip_all, fields(method = "batch_check_permission"))]
    async fn batch_check_permission(
        &self,
        request: Request<BatchCheckPermissionRequest>,
    ) -> Result<Response<BatchCheckPermissionResponse>, Status> {
        let asker = self.asker(&request).await?;
        let questions = self.admit_all(&asker, &request.get_ref().checks).await?;
        let results = self
            .answer(&asker, questions, "batch_check_permission")
            .await?;
        Ok(Response::new(BatchCheckPermissionResponse { results }))
    }

    #[instrument(skip_all, fields(method = "list_objects"))]
    async fn list_objects(
        &self,
        request: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        self.subject_caller(&request, [request.get_ref().subject.as_str()])
            .await?;
        let req = request.into_inner();
        let objects = self
            .engine
            .list_accessible_objects(&req.subject, &req.action, &req.resource_type)
            .await
            .map_err(|e| engine_refusal("list_objects", e))?;

        Ok(Response::new(ListObjectsResponse { objects }))
    }

    #[instrument(skip_all, fields(method = "list_subjects"))]
    async fn list_subjects(
        &self,
        request: Request<ListSubjectsRequest>,
    ) -> Result<Response<ListSubjectsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let subjects = self
            .engine
            .list_subjects_with_access(&req.action, &req.resource)
            .await
            .map_err(|e| engine_refusal("list_subjects", e))?;

        Ok(Response::new(ListSubjectsResponse { subjects }))
    }

    // ── Role management ─────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "create_role"))]
    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        if req.name.is_empty() {
            return Err(missing_field("name"));
        }

        let mut role = Role::new(project_id, &req.name, &req.name);
        role.description = req.description;
        role.permissions = req.permissions;

        self.storage
            .create_role(
                &role,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "role.create",
                    role.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                sid_core::Error::Conflict(_) => ApiError::new(
                    ErrorReason::RoleAlreadyExists,
                    "the project already has a role of this name",
                )
                .with_resource("Role", req.name.clone())
                .into(),
                other => storage_failure(other),
            })?;

        info!("Created role '{}' in project {}", role.key, project_id.0);

        Ok(Response::new(CreateRoleResponse {
            role: Some(role_to_proto(&role)),
        }))
    }

    #[instrument(skip_all, fields(method = "get_role"))]
    async fn get_role(
        &self,
        request: Request<GetRoleRequest>,
    ) -> Result<Response<GetRoleResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

        let role = match req.identifier {
            Some(get_role_request::Identifier::Id(id)) => {
                let role_id = parse_role_id(&id)?;
                self.storage
                    .get_role(role_id)
                    .await
                    .map_err(storage_failure)?
                    .ok_or_else(|| role_not_found(role_id))?
            }
            Some(get_role_request::Identifier::Name(name)) => {
                let project_id_str = req
                    .project_id
                    .as_deref()
                    .ok_or_else(|| missing_field("project_id"))?;
                let project_id = parse_project_id(project_id_str)?;
                self.storage
                    .get_role_by_name(project_id, &name)
                    .await
                    .map_err(storage_failure)?
                    .ok_or_else(|| not_found(ErrorReason::RoleNotFound, "Role", name))?
            }
            None => return Err(missing_field("identifier")),
        };

        Ok(Response::new(GetRoleResponse {
            role: Some(role_to_proto(&role)),
        }))
    }

    #[instrument(skip_all, fields(method = "update_role"))]
    async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<UpdateRoleResponse>, Status> {
        let asker = self.asker(&request).await?;
        let administrator = asker.administrator()?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let role_id = parse_role_id(&req.id)?;

        // Only the root learns a role is missing.
        let mut role = match self
            .storage
            .get_role(role_id)
            .await
            .map_err(storage_failure)?
        {
            Some(role) => role,
            None => {
                return Err(match administrator {
                    crate::admin::Administrator::Root(_) => role_not_found(role_id),
                    crate::admin::Administrator::Holder(_) => {
                        administration_refusal(sid_core::Error::AuthorizationDenied(String::new()))
                    }
                });
            }
        };

        if let Some(desc) = req.description {
            role.description = Some(desc);
        }
        if !req.permissions.is_empty() {
            role.permissions = req.permissions;
        }
        role.updated_at = chrono::Utc::now();

        let audit = asker.audit("role.update", role.id.0.to_string()).into();
        let updated = crate::admin::RoleAdministration::new(self.storage.clone())
            .edit_role(&administrator, &role, audit)
            .await
            .map_err(administration_refusal)?;
        if !updated {
            // Deleted or changed since it was read: never recreated or overwritten.
            return Err(changed_concurrently());
        }
        role.revision += 1;

        Ok(Response::new(UpdateRoleResponse {
            role: Some(role_to_proto(&role)),
        }))
    }

    #[instrument(skip_all, fields(method = "delete_role"))]
    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let role_id = parse_role_id(&req.id)?;

        self.storage
            .get_role(role_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| role_not_found(role_id))?;

        self.storage
            .delete_role(
                role_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "role.delete",
                    role_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Deleted role {}", role_id.0);

        Ok(Response::new(DeleteRoleResponse {}))
    }

    #[instrument(skip_all, fields(method = "list_roles"))]
    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        let roles = self
            .storage
            .list_roles(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListRolesResponse {
            roles: roles.iter().map(role_to_proto).collect(),
            next_page_token: String::new(),
        }))
    }

    // ── Role assignment ─────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "assign_role"))]
    async fn assign_role(
        &self,
        request: Request<AssignRoleRequest>,
    ) -> Result<Response<AssignRoleResponse>, Status> {
        let asker = self.asker(&request).await?;
        let administrator = asker.administrator()?;
        self.check_maintenance()?;
        let req = request.into_inner();

        let role_id = parse_role_id(&req.role_id)?;

        // Only the root learns a role is missing; anyone else is refused as
        // for any change its authority does not cover.
        let role = match self
            .storage
            .get_role(role_id)
            .await
            .map_err(storage_failure)?
        {
            Some(role) => role,
            None => {
                return Err(match administrator {
                    crate::admin::Administrator::Root(_) => role_not_found(role_id),
                    crate::admin::Administrator::Holder(_) => {
                        administration_refusal(sid_core::Error::AuthorizationDenied(String::new()))
                    }
                });
            }
        };

        let principal = match req.principal {
            Some(assign_role_request::Principal::ProfileId(id)) => {
                let pid = parse_profile_id(&id)?;
                RoleAssignmentPrincipal::Profile(pid)
            }
            Some(assign_role_request::Principal::GroupId(id)) => {
                let gid = parse_group_id(&id)?;
                RoleAssignmentPrincipal::Group(gid)
            }
            Some(assign_role_request::Principal::MachineUserId(id)) => {
                let mid = parse_machine_user_id(&id)?;
                RoleAssignmentPrincipal::MachineUser(mid)
            }
            Some(assign_role_request::Principal::OauthClientId(client_id)) => {
                self.confidential_client(&client_id).await?;
                RoleAssignmentPrincipal::OAuthClient(client_id)
            }
            Some(assign_role_request::Principal::ProvisioningConnectorId(id)) => {
                RoleAssignmentPrincipal::ProvisioningConnector(parse_connector_id(&id)?)
            }
            None => return Err(missing_field("principal")),
        };

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
        assignment.scope = req.scope;
        assignment.expires_at = expires_at;
        assignment.admin = req.admin.map(envelope_from_proto).transpose()?;
        if role.has_permission(TOKEN_INTROSPECT) || role.has_permission(AUTHZ_CHECK) {
            self.check_service_assignment(&assignment).await?;
        }
        if let RoleAssignmentPrincipal::ProvisioningConnector(connector) = assignment.principal {
            self.check_connector_assignment(connector, &assignment)
                .await?;
        }

        let audit = asker
            .audit("role.assign", assignment.id.0.to_string())
            .into();
        let assignment = crate::admin::RoleAdministration::new(self.storage.clone())
            .assign(&administrator, assignment, audit)
            .await
            .map_err(administration_refusal)?;

        info!(
            "Assigned role {} (assignment {})",
            role_id.0, assignment.id.0
        );

        Ok(Response::new(AssignRoleResponse {
            assignment: Some(assignment_to_proto(&assignment)),
        }))
    }

    #[instrument(skip_all, fields(method = "revoke_role"))]
    async fn revoke_role(
        &self,
        request: Request<RevokeRoleRequest>,
    ) -> Result<Response<RevokeRoleResponse>, Status> {
        let asker = self.asker(&request).await?;
        let administrator = asker.administrator()?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let assignment_id = parse_assignment_id(&req.assignment_id)?;

        let audit = asker
            .audit("role.revoke", assignment_id.0.to_string())
            .into();
        crate::admin::RoleAdministration::new(self.storage.clone())
            .revoke(&administrator, assignment_id, audit)
            .await
            .map_err(administration_refusal)?;

        info!("Revoked role assignment {}", assignment_id.0);

        Ok(Response::new(RevokeRoleResponse {}))
    }

    #[instrument(skip_all, fields(method = "list_role_assignments"))]
    async fn list_role_assignments(
        &self,
        request: Request<ListRoleAssignmentsRequest>,
    ) -> Result<Response<ListRoleAssignmentsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

        let assignments = match req.filter {
            Some(list_role_assignments_request::Filter::ProfileId(id)) => {
                let pid = parse_profile_id(&id)?;
                self.storage.list_role_assignments_for_profile(pid).await
            }
            Some(list_role_assignments_request::Filter::GroupId(id)) => {
                let gid = parse_group_id(&id)?;
                self.storage.list_role_assignments_for_group(gid).await
            }
            Some(list_role_assignments_request::Filter::MachineUserId(id)) => {
                let mid = parse_machine_user_id(&id)?;
                self.storage
                    .list_role_assignments_for_machine_user(mid)
                    .await
            }
            Some(list_role_assignments_request::Filter::OauthClientId(client_id)) => {
                self.storage
                    .list_role_assignments_for_oauth_client(&client_id)
                    .await
            }
            Some(list_role_assignments_request::Filter::ProvisioningConnectorId(id)) => {
                self.storage
                    .list_role_assignments_for_provisioning_connector(parse_connector_id(&id)?)
                    .await
            }
            Some(list_role_assignments_request::Filter::RoleId(id)) => {
                let role_id = parse_role_id(&id)?;
                self.storage.list_role_assignments_for_role(role_id).await
            }
            None => return Err(missing_field("filter")),
        };

        let assignments = assignments.map_err(storage_failure)?;

        Ok(Response::new(ListRoleAssignmentsResponse {
            assignments: assignments.iter().map(assignment_to_proto).collect(),
        }))
    }

    // ── Group management ────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "create_group"))]
    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        if req.name.is_empty() {
            return Err(missing_field("name"));
        }

        let mut group = Group::new(project_id, &req.name);
        group.description = req.description;

        self.storage
            .create_group(
                &group,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "group.create",
                    group.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                sid_core::Error::Conflict(_) => ApiError::new(
                    ErrorReason::GroupAlreadyExists,
                    "the project already has a group of this name",
                )
                .with_resource("Group", req.name.clone())
                .into(),
                other => storage_failure(other),
            })?;

        info!("Created group '{}' in project {}", group.name, project_id.0);

        Ok(Response::new(CreateGroupResponse {
            group: Some(group_to_proto(&group)),
        }))
    }

    #[instrument(skip_all, fields(method = "get_group"))]
    async fn get_group(
        &self,
        request: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

        let group = match req.identifier {
            Some(get_group_request::Identifier::Id(id)) => {
                let gid = parse_group_id(&id)?;
                self.storage
                    .get_group(gid)
                    .await
                    .map_err(storage_failure)?
                    .ok_or_else(|| group_not_found(gid.0.to_string()))?
            }
            Some(get_group_request::Identifier::Name(name)) => {
                let project_id_str = req
                    .project_id
                    .as_deref()
                    .ok_or_else(|| missing_field("project_id"))?;
                let project_id = parse_project_id(project_id_str)?;
                let groups = self
                    .storage
                    .list_groups(project_id)
                    .await
                    .map_err(storage_failure)?;
                match groups.into_iter().find(|g| g.name == name) {
                    Some(group) => group,
                    None => return Err(group_not_found(name)),
                }
            }
            None => return Err(missing_field("identifier")),
        };

        Ok(Response::new(GetGroupResponse {
            group: Some(group_to_proto(&group)),
        }))
    }

    #[instrument(skip_all, fields(method = "update_group"))]
    async fn update_group(
        &self,
        request: Request<UpdateGroupRequest>,
    ) -> Result<Response<UpdateGroupResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.id)?;

        // Only the description is written, so a concurrent directory sync of
        // the name is never reverted and a deleted group is never recreated.
        if let Some(desc) = req.description.as_deref() {
            let updated = self
                .storage
                .set_group_description(
                    group_id,
                    Some(desc),
                    AuditEntry::admin(
                        caller.profile_id.to_string(),
                        "group.update",
                        group_id.0.to_string(),
                    )
                    .into(),
                )
                .await
                .map_err(storage_failure)?;
            if !updated {
                return Err(group_not_found(group_id.0.to_string()));
            }
        }

        let group = self
            .storage
            .get_group(group_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| group_not_found(group_id.0.to_string()))?;

        Ok(Response::new(UpdateGroupResponse {
            group: Some(group_to_proto(&group)),
        }))
    }

    #[instrument(skip_all, fields(method = "delete_group"))]
    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.id)?;

        self.storage
            .get_group(group_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| group_not_found(group_id.0.to_string()))?;

        self.storage
            .delete_group(
                group_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "group.delete",
                    group_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Deleted group {}", group_id.0);

        Ok(Response::new(DeleteGroupResponse {}))
    }

    #[instrument(skip_all, fields(method = "list_groups"))]
    async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<ListGroupsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        let groups = self
            .storage
            .list_groups(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListGroupsResponse {
            groups: groups.iter().map(group_to_proto).collect(),
            next_page_token: String::new(),
        }))
    }

    // ── Group membership ────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "add_to_group"))]
    async fn add_to_group(
        &self,
        request: Request<AddToGroupRequest>,
    ) -> Result<Response<AddToGroupResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.group_id)?;
        let profile_id = parse_profile_id(&req.profile_id)?;

        self.storage
            .get_group(group_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| group_not_found(group_id.0.to_string()))?;

        let member = GroupMember::new(group_id, profile_id);
        self.storage
            .add_to_group(
                &member,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "group.add_member",
                    format!("{}:{}", group_id.0, profile_id),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                sid_core::Error::PolicyViolation(why) => Status::from(
                    ApiError::new(
                        ErrorReason::InvalidState,
                        "the profile granted this group a role and cannot join it",
                    )
                    .with_precondition("GRANTOR_OUTSIDE_GROUP", "group", why),
                ),
                other => storage_failure(other),
            })?;

        info!("Added profile {} to group {}", profile_id, group_id.0);

        Ok(Response::new(AddToGroupResponse {}))
    }

    #[instrument(skip_all, fields(method = "remove_from_group"))]
    async fn remove_from_group(
        &self,
        request: Request<RemoveFromGroupRequest>,
    ) -> Result<Response<RemoveFromGroupResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.group_id)?;
        let profile_id = parse_profile_id(&req.profile_id)?;

        self.storage
            .remove_from_group(
                group_id,
                profile_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "group.remove_member",
                    format!("{}:{}", group_id.0, profile_id),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Removed profile {} from group {}", profile_id, group_id.0);

        Ok(Response::new(RemoveFromGroupResponse {}))
    }

    #[instrument(skip_all, fields(method = "list_group_members"))]
    async fn list_group_members(
        &self,
        request: Request<ListGroupMembersRequest>,
    ) -> Result<Response<ListGroupMembersResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.group_id)?;

        let members = self
            .storage
            .list_group_members(group_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListGroupMembersResponse {
            profile_ids: members.iter().map(|m| m.profile_id.to_string()).collect(),
        }))
    }

    // ── Policy management (Cedar ABAC) ──────────────────────────────

    #[instrument(skip_all, fields(method = "create_policy"))]
    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        if req.name.is_empty() {
            return Err(missing_field("name"));
        }
        if req.policy_text.is_empty() {
            return Err(missing_field("policy_text"));
        }
        self.check_policy_text(&req.policy_text)?;

        let effect = proto_to_policy_effect(req.effect);
        let mut policy = CedarPolicy::new(project_id, &req.name, &req.policy_text, effect);
        policy.description = req.description;
        policy.enabled = req.enabled;

        self.storage
            .create_cedar_policy(
                &policy,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "policy.create",
                    policy.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                sid_core::Error::Conflict(_) => ApiError::new(
                    ErrorReason::PolicyAlreadyExists,
                    "the project already has a policy of this name",
                )
                .with_resource("Policy", policy.name.clone())
                .into(),
                other => storage_failure(other),
            })?;

        info!(
            "Created policy '{}' in project {}",
            policy.name, project_id.0
        );

        Ok(Response::new(CreatePolicyResponse {
            policy: Some(policy_to_proto(&policy)),
        }))
    }

    #[instrument(skip_all, fields(method = "get_policy"))]
    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let policy_id = parse_policy_id(&req.id)?;

        let policy = self
            .storage
            .get_cedar_policy(policy_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| policy_not_found(policy_id))?;

        Ok(Response::new(GetPolicyResponse {
            policy: Some(policy_to_proto(&policy)),
        }))
    }

    #[instrument(skip_all, fields(method = "update_policy"))]
    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let policy_id = parse_policy_id(&req.id)?;

        let mut policy = self
            .storage
            .get_cedar_policy(policy_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| policy_not_found(policy_id))?;

        if let Some(desc) = req.description {
            policy.description = Some(desc);
        }
        if let Some(text) = req.policy_text {
            self.check_policy_text(&text)?;
            policy.policy_text = text;
        }
        if let Some(effect) = req.effect {
            policy.effect = proto_to_policy_effect(effect);
        }
        if let Some(enabled) = req.enabled {
            policy.enabled = enabled;
        }
        policy.updated_at = chrono::Utc::now();

        let updated = self
            .storage
            .update_cedar_policy(
                &policy,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "policy.update",
                    policy.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            // Deleted or changed since it was read: never recreated or overwritten.
            return Err(changed_concurrently());
        }
        policy.revision += 1;

        Ok(Response::new(UpdatePolicyResponse {
            policy: Some(policy_to_proto(&policy)),
        }))
    }

    #[instrument(skip_all, fields(method = "delete_policy"))]
    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();
        let policy_id = parse_policy_id(&req.id)?;

        self.storage
            .get_cedar_policy(policy_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| policy_not_found(policy_id))?;

        self.storage
            .delete_cedar_policy(
                policy_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "policy.delete",
                    policy_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Deleted policy {}", policy_id.0);

        Ok(Response::new(DeletePolicyResponse {}))
    }

    #[instrument(skip_all, fields(method = "list_policies"))]
    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        let policies = self
            .storage
            .list_cedar_policies(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListPoliciesResponse {
            policies: policies.iter().map(policy_to_proto).collect(),
            next_page_token: String::new(),
        }))
    }

    // ── Policy evaluation ───────────────────────────────────────────

    #[instrument(skip_all, fields(method = "evaluate_policy"))]
    async fn evaluate_policy(
        &self,
        request: Request<EvaluatePolicyRequest>,
    ) -> Result<Response<EvaluatePolicyResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

        // Load policies: project-scoped if project_id provided, otherwise all.
        let project_id = req
            .project_id
            .as_deref()
            .ok_or_else(|| missing_field("project_id"))?;
        let policies = self
            .storage
            .list_cedar_policies(parse_project_id(project_id)?)
            .await
            .map_err(storage_failure)?;

        // Filter enabled policies, convert to (id, text) pairs.
        let policy_pairs: Vec<(String, String)> = policies
            .into_iter()
            .filter(|p| p.enabled)
            .map(|p| (p.id.0.to_string(), p.policy_text))
            .collect();

        if policy_pairs.is_empty() {
            return Ok(Response::new(EvaluatePolicyResponse {
                allowed: false,
                matches: vec![],
            }));
        }

        // Build Cedar entity UIDs from request fields.
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

        let matches = result
            .matches
            .iter()
            .map(|m| PolicyMatch {
                policy_id: m.policy_id.clone(),
                policy_name: String::new(),
                effect: match m.effect {
                    crate::cedar::CedarEffect::Permit => {
                        sid_proto::sid::v1::PolicyEffect::Permit.into()
                    }
                    crate::cedar::CedarEffect::Forbid => {
                        sid_proto::sid::v1::PolicyEffect::Forbid.into()
                    }
                },
            })
            .collect();

        Ok(Response::new(EvaluatePolicyResponse {
            allowed: result.allowed,
            matches,
        }))
    }

    #[instrument(skip_all, fields(method = "validate_policy"))]
    async fn validate_policy(
        &self,
        request: Request<ValidatePolicyRequest>,
    ) -> Result<Response<ValidatePolicyResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

        if req.policy_text.is_empty() {
            return Err(missing_field("policy_text"));
        }

        let result = self.cedar.validate_policy(&req.policy_text);

        Ok(Response::new(ValidatePolicyResponse {
            valid: result.valid,
            errors: result.errors,
        }))
    }

    #[instrument(skip_all, fields(method = "check_sod_conflicts"))]
    async fn check_sod_conflicts(
        &self,
        request: Request<CheckSodConflictsRequest>,
    ) -> Result<Response<CheckSodConflictsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

        if req.proposed_role.is_empty() {
            return Err(missing_field("proposed_role"));
        }

        let sod_rules = self
            .storage
            .list_sod_rules()
            .await
            .map_err(storage_failure)?;

        let sod_service = crate::sod::SodService::new(sod_rules);
        let conflicts = sod_service.check_conflicts(&req.existing_roles, &req.proposed_role);

        let proto_conflicts: Vec<sid_proto::sid::v1::SodConflict> = conflicts
            .into_iter()
            .map(|c| sid_proto::sid::v1::SodConflict {
                rule_name: c.rule_name,
                description: c.description,
                severity: c.severity.as_str().to_string(),
                conflicting_roles: c.conflicting_roles,
            })
            .collect();

        Ok(Response::new(CheckSodConflictsResponse {
            has_conflicts: !proto_conflicts.is_empty(),
            conflicts: proto_conflicts,
        }))
    }

    #[instrument(skip_all, fields(method = "simulate_policy"))]
    async fn simulate_policy(
        &self,
        request: Request<SimulatePolicyRequest>,
    ) -> Result<Response<SimulatePolicyResponse>, Status> {
        self.admin(&request).await?;
        self.check_maintenance()?;
        let req = request.into_inner();

        let project_id = parse_project_id(&req.project_id)?;

        if req.proposed_changes.is_empty() {
            return Err(missing_field("proposed_changes"));
        }

        // Convert proto changes to domain model.
        let mut changes = Vec::new();
        for pc in &req.proposed_changes {
            let change = match &pc.change {
                Some(sid_proto::sid::v1::policy_change::Change::CreatePolicy(cp)) => {
                    crate::simulator::ProposedChange::CreatePolicy {
                        name: cp.name.clone(),
                        policy_text: cp.policy_text.clone(),
                        effect: match cp.effect {
                            x if x == sid_proto::sid::v1::PolicyEffect::Forbid as i32 => {
                                sid_core::models::PolicyEffect::Forbid
                            }
                            _ => sid_core::models::PolicyEffect::Permit,
                        },
                    }
                }
                Some(sid_proto::sid::v1::policy_change::Change::UpdatePolicy(up)) => {
                    let id = parse_policy_id(&up.id)?;
                    crate::simulator::ProposedChange::UpdatePolicy {
                        id,
                        policy_text: up.policy_text.clone(),
                        effect: up.effect.map(|e| {
                            if e == sid_proto::sid::v1::PolicyEffect::Forbid as i32 {
                                sid_core::models::PolicyEffect::Forbid
                            } else {
                                sid_core::models::PolicyEffect::Permit
                            }
                        }),
                        enabled: up.enabled,
                    }
                }
                Some(sid_proto::sid::v1::policy_change::Change::DeletePolicyId(id)) => {
                    let policy_id = parse_policy_id(id)?;
                    crate::simulator::ProposedChange::DeletePolicy { id: policy_id }
                }
                Some(sid_proto::sid::v1::policy_change::Change::AssignRole(_))
                | Some(sid_proto::sid::v1::policy_change::Change::RevokeAssignmentId(_)) => {
                    return Err(not_in_this_build("simulate_role_assignment"));
                }
                None => {
                    return Err(invalid_field(
                        "proposed_changes",
                        "a change names no action",
                    ));
                }
            };
            changes.push(change);
        }

        // Determine subjects to check.
        let subjects = if let Some(ref s) = req.subject {
            vec![s.clone()]
        } else {
            // Default: check with a synthetic subject.
            vec!["user:00000000-0000-0000-0000-000000000000".to_string()]
        };

        // Determine actions to check.
        let actions = if let Some(ref a) = req.action {
            vec![a.clone()]
        } else {
            vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
                "admin".to_string(),
            ]
        };

        // Resource scope.
        let resource = req
            .resource
            .unwrap_or_else(|| format!("project:{}", project_id.0));

        let simulator = crate::simulator::PolicySimulator::new(self.storage.clone());
        let result = simulator
            .simulate(project_id, &changes, &subjects, &actions, &resource)
            .await
            .map_err(storage_failure)?;

        info!(
            project_id = %project_id.0,
            changes = changes.len(),
            checked = result.total_checked,
            gained = result.total_gained,
            lost = result.total_lost,
            "policy simulation completed"
        );

        let impacts: Vec<sid_proto::sid::v1::SimulationImpact> = result
            .impacts
            .into_iter()
            .map(|i| sid_proto::sid::v1::SimulationImpact {
                subject: i.subject,
                action: i.action,
                resource: i.resource,
                current_allowed: i.current_allowed,
                proposed_allowed: i.proposed_allowed,
                impact_type: match i.impact_type {
                    crate::simulator::ImpactType::Gained => {
                        sid_proto::sid::v1::SimulationImpactType::Gained as i32
                    }
                    crate::simulator::ImpactType::Lost => {
                        sid_proto::sid::v1::SimulationImpactType::Lost as i32
                    }
                    crate::simulator::ImpactType::Unchanged => {
                        sid_proto::sid::v1::SimulationImpactType::Unchanged as i32
                    }
                },
                current_reason: i.current_reason,
                proposed_reason: i.proposed_reason,
            })
            .collect();

        Ok(Response::new(SimulatePolicyResponse {
            project_id: project_id.0.to_string(),
            impacts,
            total_checked: result.total_checked as i32,
            total_gained: result.total_gained as i32,
            total_lost: result.total_lost as i32,
            total_unchanged: result.total_unchanged as i32,
            warnings: result.warnings,
            errors: result.errors,
            simulated_at: Some(to_timestamp(chrono::Utc::now())),
        }))
    }
}

#[cfg(test)]
mod tests;
