// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AuthzService: the permission questions of the fixed CE engine, asked
//! by a Profile or by a service with its own token for the authorization API,
//! and the authorization management the `sid` library owns
//! ([`sid::authorization`]), behind authentication, the maintenance switch
//! and the operation context.

use sid::authorization::{
    Actor, AssignmentRule, Authorization, AuthorizationError, InstallationAdministrator,
};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::resource_token::ResourceTokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::token_state::{TokenState, current_state};
use sid_authz::cedar::CedarService;
use sid_authz::decision::AuthzCheckRequest;
use sid_authz::engine::CeAuthzEngine;
use sid_core::models::audit::AuditOutcome;
use sid_core::models::{AUTHZ_CHECK, AuditEntry, ProfileId, ProjectId, ResourceId, ResourceState};
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::metadata_context;
use sid_infra::authn::own_token::authenticate_service;
use sid_infra::grpc_error::refuse::{
    authority_changed, changed_concurrently, dependency_unavailable, internal, invalid_field,
    maintenance, missing_field, not_found, not_in_this_build, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::StorageBackend;
use sid_plugin::audit::AuditLog;
use sid_proto::sid::v1::authn::{RequestConfirmation, SenderProofProfile};
use sid_proto::sid::v1::authz::*;
use sid_proto::sid::v1::authz_service_server::AuthzService;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

// ── Utility helpers ─────────────────────────────────────────────────

/// The identifier a request names in `field`, checked before any lookup: an
/// absent or malformed one is refused on that field.
#[allow(clippy::result_large_err)]
pub(crate) fn wire_id<W: sid_ids_proto::WireId>(
    value: Option<&W>,
    field: &'static str,
) -> Result<W::Domain, Status> {
    sid_ids_proto::required(value).map_err(|e| invalid_field(field, e.to_string()))
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
/// never becomes an answer, anything else is internal.
fn query_refusal(operation: &'static str, e: sid_authz::decision::AuthzError) -> Status {
    use sid_authz::decision::AuthzError;
    match e {
        AuthzError::InvalidSubject(_) => invalid_field("evaluation", "not a subject reference"),
        AuthzError::InvalidResource(_) => invalid_field("target", "not a target reference"),
        AuthzError::Storage(why) => dependency_unavailable("permission decision", why),
        other => internal(operation, other),
    }
}

/// Records a question about another subject with the asker as the acting
/// party and the evaluated subject apart from it (D054); a question about
/// oneself needs no separate record.
fn record_query(asker: &Actor, check: &AuthzCheckRequest, outcome: PermissionOutcome) {
    let asking = asker.subject();
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

/// The status an authorization management refusal answers with.
pub(crate) fn refusal(e: AuthorizationError) -> Status {
    use AuthorizationError as E;
    match e {
        E::Caller(e) => e.into_status(),
        E::Operation(e) => e.into_status(),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
        E::MissingField(field) => missing_field(field),
        E::InvalidField { field, reason } => invalid_field(field, reason),
        E::RoleNotFound(name) => not_found(ErrorReason::RoleNotFound, "Role", name),
        E::GroupNotFound(name) => not_found(ErrorReason::GroupNotFound, "Group", name),
        E::PolicyNotFound(id) => not_found(ErrorReason::PolicyNotFound, "Policy", id.to_string()),
        E::ProjectNotFound(id) => {
            not_found(ErrorReason::ProjectNotFound, "Project", id.to_string())
        }
        E::ScopeResourceNotFound(id) => {
            not_found(ErrorReason::ResourceNotFound, "Resource", id.to_string())
        }
        E::ResourceNotFound(id) => not_found(
            ErrorReason::ResourceNotFound,
            "ProtectedResource",
            id.to_string(),
        ),
        E::ResourceRetired(id) => ApiError::new(
            ErrorReason::ResourceRetired,
            "the protected resource is retired",
        )
        .with_precondition(
            "RESOURCE_RETIRED",
            id.to_string(),
            "assign on a live resource",
        )
        .into(),
        E::ConnectorNotFound(id) => not_found(
            ErrorReason::ProvisioningConnectorNotFound,
            "ProvisioningConnector",
            id.to_string(),
        ),
        E::ConnectorRetired(id) => ApiError::new(
            ErrorReason::ResourceRetired,
            "the provisioning connector is retired",
        )
        .with_precondition(
            "CONNECTOR_RETIRED",
            id.to_string(),
            "assign to a connector that is not retired",
        )
        .into(),
        E::ClientNotFound(id) => not_found(ErrorReason::ApplicationNotFound, "OAuthClient", id),
        E::PublicClient => ApiError::new(
            ErrorReason::InvalidFieldValue,
            "a public client cannot hold roles: it has no credential",
        )
        .with_field_violation("oauth_client_id", "public client")
        .into(),
        E::RoleTaken(name) => ApiError::new(
            ErrorReason::RoleAlreadyExists,
            "the project already has a role of this name",
        )
        .with_resource("Role", name)
        .into(),
        E::GroupTaken(name) => ApiError::new(
            ErrorReason::GroupAlreadyExists,
            "the project already has a group of this name",
        )
        .with_resource("Group", name)
        .into(),
        E::PolicyTaken(name) => ApiError::new(
            ErrorReason::PolicyAlreadyExists,
            "the scope already has a policy of this name",
        )
        .with_resource("Policy", name)
        .into(),
        E::ChangedConcurrently => changed_concurrently(),
        E::AssignmentSetChanged { current } => ApiError::new(
            ErrorReason::RoleAssignmentSetChanged,
            "the role assignment set changed since it was read",
        )
        .with_metadata("currentRevision", current.to_string())
        .with_precondition(
            "ROLE_ASSIGNMENT_SET_REVISION",
            "assignment_set",
            "read the set again and decide on its current revision",
        )
        .into(),
        E::Denied => ApiError::new(
            ErrorReason::InsufficientPermissions,
            "no administrative assignment of the caller covers this change",
        )
        .into(),
        E::AuthorityChanged => authority_changed(),
        E::InvalidAssignment(why) => invalid_field("assignment", why),
        E::CeilingExceeded(why) => ApiError::new(
            ErrorReason::InvalidState,
            "the edit would widen an assignment past its approved ceiling",
        )
        .with_precondition("APPROVED_CEILING", "role", why)
        .into(),
        E::LastAdministrator(why) => ApiError::new(
            ErrorReason::InvalidState,
            "the installation's last administrator assignment is kept",
        )
        .with_precondition("LAST_ADMINISTRATOR", "installation", why)
        .into(),
        E::Assignment(rule) => assignment_refusal(rule),
        E::GrantorOutsideGroup(why) => ApiError::new(
            ErrorReason::InvalidState,
            "the profile granted this group a role and cannot join it",
        )
        .with_precondition("GRANTOR_OUTSIDE_GROUP", "group", why)
        .into(),
        E::NotInThisBuild(what) => not_in_this_build(what),
        E::ProfileNotFound(id) => {
            not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
        }
        E::AccessRequestNotFound(id) => not_found(
            ErrorReason::AccessRequestNotFound,
            "AccessRequest",
            id.to_string(),
        ),
        E::AlreadyDecided(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the access request was already decided",
        )
        .with_precondition("ACCESS_REQUEST_STATE", id.to_string(), "not pending")
        .into(),
        E::RequestedRoleDeleted(key) => ApiError::new(
            ErrorReason::InvalidState,
            "the requested role no longer exists",
        )
        .with_precondition("REQUESTED_ROLE", key, "deleted")
        .into(),
    }
}

/// A role assignment of a shape the engine refuses, on the field it names.
fn assignment_refusal(rule: AssignmentRule) -> Status {
    let (field, violation) = rule.violation();
    ApiError::new(ErrorReason::InvalidFieldValue, rule.message())
        .with_field_violation(field, violation)
        .into()
}

/// Why role administration refused or failed, as a status (see
/// [`sid::authorization::administration`]).
pub(crate) fn administration_refusal(error: sid_core::Error) -> Status {
    refusal(sid::authorization::administration(error))
}

// ── Service ─────────────────────────────────────────────────────────

pub struct AuthzServiceImpl {
    engine: Arc<CeAuthzEngine<dyn StorageBackend>>,
    storage: Arc<dyn StorageBackend>,
    /// Roles, assignments, groups and policies.
    authorization: Authorization,
    maintenance_mode: Arc<AtomicBool>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// Verifies the tokens a permission checker obtained for this
    /// installation's authorization API; without it no service may ask
    /// about others (D054).
    service_tokens: Option<Arc<ResourceTokenVerifier>>,
    /// Services the deployment trusts to confirm checks of an original
    /// request; nobody unless configured.
    request_verifiers: sid_authz::request_verifier::RequestVerifiers,
    /// Where denied permission questions are recorded.
    audit: Arc<dyn AuditLog>,
}

/// Most checks one batch may carry: bounded before any is admitted or
/// evaluated.
const MAX_BATCH_CHECKS: usize = 100;

/// The audit action of a denied permission question.
const PERMISSION_CHECK_AUDIT: &str = "authz.permission_check";

/// What an original request's token establishes.
#[derive(Clone)]
struct RequestEvidence {
    subject: String,
    context: std::collections::BTreeMap<String, String>,
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

/// Whether `status` refuses a request's token or proof as evidence: the
/// INVALID_ARGUMENT naming `request.access_token`.
fn refuses_evidence(status: &Status) -> bool {
    use tonic_types::StatusExt;
    status.code() == tonic::Code::InvalidArgument
        && status.get_details_bad_request().is_some_and(|bad| {
            bad.field_violations
                .iter()
                .any(|violation| violation.field == "request.access_token")
        })
}

/// The proof `confirmation` reports, as the issuer admits it: its `jti` and
/// `iat` as the verifier read them from the proof.
#[allow(clippy::result_large_err)]
fn confirmed_proof(
    confirmation: &RequestConfirmation,
) -> Result<sid_authn::dpop::VerifiedProof, Status> {
    if confirmation.proof_jti.is_empty() {
        return Err(confirmation_unfit(
            "request.confirmation.proof_jti",
            "missing",
        ));
    }
    let iat = confirmation
        .proof_iat
        .as_ref()
        .ok_or_else(|| confirmation_unfit("request.confirmation.proof_iat", "missing"))?;
    Ok(sid_authn::dpop::VerifiedProof {
        jti: confirmation.proof_jti.clone(),
        iat: iat.seconds,
    })
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

impl AuthzServiceImpl {
    pub fn new(
        engine: Arc<CeAuthzEngine<dyn StorageBackend>>,
        storage: Arc<dyn StorageBackend>,
        cedar: CedarService,
        maintenance_mode: Arc<AtomicBool>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        audit: Arc<dyn AuditLog>,
    ) -> Self {
        Self {
            engine,
            authorization: Authorization::new(storage.clone(), cedar),
            storage,
            maintenance_mode,
            jwt,
            revocation,
            service_tokens: None,
            request_verifiers: Default::default(),
            audit,
        }
    }

    /// Warn of the separation-of-duties conflicts the installation
    /// configuration defines.
    pub fn with_sod_warnings(mut self, warnings: Arc<sid_authz::sod::SodService>) -> Self {
        self.authorization = self.authorization.with_sod_warnings(warnings);
        self
    }

    /// Trust the configured services to confirm checks of original requests
    /// to their resources (D054 receiver-side verifier trust).
    pub fn with_request_verifiers(
        mut self,
        verifiers: sid_authz::request_verifier::RequestVerifiers,
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

    /// Admit one original request's sender proof for the configured verifier
    /// asking (OidcIssuerService.AdmitSenderProof): the request's token is
    /// established as for a request-bound question, then its proof admitted
    /// once for that request. A token or proof refused as evidence is
    /// UNAUTHENTICATED (TOKEN_INVALID, `invalid_dpop_proof`); an untrusted caller
    /// PERMISSION_DENIED; an undecidable admission UNAVAILABLE.
    pub async fn admit_sender_proof(
        &self,
        request: Request<sid_proto::sid::v1::authn::AdmitSenderProofRequest>,
    ) -> Result<(), Status> {
        let asker = self.asker(&request).await?;
        if !matches!(asker, Actor::Service(_)) {
            return Err(checker_denied());
        }
        let request = request.into_inner();
        let resource =
            ResourceId::try_from(request.resource.ok_or_else(|| missing_field("resource"))?)
                .map_err(|_| invalid_field("resource", "not a protected resource identifier"))?;
        let confirmation = request
            .confirmation
            .ok_or_else(|| missing_field("confirmation"))?;
        let evaluation = RequestEvaluation {
            access_token: request.access_token,
            confirmation: Some(confirmation),
        };
        match self.request_evidence(&asker, resource, &evaluation).await {
            Ok(_) => Ok(()),
            Err(status) if refuses_evidence(&status) => Err(sid_infra::grpc_error::ApiError::new(
                ErrorReason::TokenInvalid,
                "the request's token or proof is not usable for this request",
            )
            .with_metadata("oauthError", "invalid_dpop_proof")
            .into()),
            Err(status) => Err(status),
        }
    }

    /// Who asks: a service with its own token for the authorization API, or
    /// else a Profile with its own installation credential.
    async fn asker<T>(&self, request: &Request<T>) -> Result<Actor, Status> {
        if let Some(tokens) = &self.service_tokens {
            // A service token is valid only for the authorization API and a
            // user's sign-in token never is, so each credential has one path.
            match authenticate_service(request, self.storage.as_ref(), tokens, &self.revocation)
                .await
            {
                Ok(service) => return Ok(Actor::Service(service.caller.subject())),
                Err(status) if status.code() == tonic::Code::Unauthenticated => {}
                Err(status) => return Err(status),
            }
        }
        Ok(Actor::Profile(self.caller(request).await?))
    }

    /// Every one of `checks` admitted for `asker` before any subject is
    /// evaluated (D054): one refused question refuses them all.
    async fn admit_all(
        &self,
        asker: &Actor,
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
        asker: &Actor,
        check: &CheckPermissionRequest,
    ) -> Result<(), Status> {
        use permission_target::Scope;
        let target = match check.target.as_ref().and_then(|t| t.scope.as_ref()) {
            Some(Scope::Resource(id)) => ResourceId::try_from(id)
                .map(|id| format!("oauth_resource:{id}"))
                .unwrap_or_else(|_| "oauth_resource:unknown".to_owned()),
            Some(Scope::ProjectId(id)) => ProjectId::try_from(id)
                .map(|id| format!("project:{id}"))
                .unwrap_or_else(|_| "project:unknown".to_owned()),
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
        asker: &Actor,
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
        asker: &Actor,
        check: &'a CheckPermissionRequest,
        established: &mut Established<'a>,
    ) -> Result<Question, Status> {
        use check_permission_request::Evaluation;
        use permission_target::Scope;

        let target = check
            .target
            .as_ref()
            .ok_or_else(|| missing_field("target"))?;
        let (resource, engine_resource) = match &target.scope {
            Some(Scope::Resource(id)) => {
                let resource = ResourceId::try_from(id).map_err(|_| {
                    invalid_field("target.resource", "not a protected resource identifier")
                })?;
                (Some(resource), format!("oauth_resource:{resource}"))
            }
            Some(Scope::ProjectId(id)) => {
                let project: ProjectId = wire_id(Some(id), "target.project_id")?;
                (None, format!("project:{project}"))
            }
            None => return Err(missing_field("target")),
        };
        // The object is part of the question, in the application's own
        // namespace; policies may name it.
        let mut context = std::collections::BTreeMap::new();
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
            Evaluation::Self_(_) => (asker.subject(), "self"),
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
                let (Actor::Service(_), Some(resource)) = (asker, resource) else {
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
        asker: &Actor,
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
                    Actor::Profile(_) => reason,
                    Actor::Service(_) => None,
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
        asker: &Actor,
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
        asker: &Actor,
        resource: Option<ResourceId>,
    ) -> Result<(), Status> {
        match (asker, resource) {
            (Actor::Profile(caller), _) if caller.is_admin() => {
                sid_authz::admin::RoleAdministration::new(self.storage.clone())
                    .require_installation_administrator(caller.profile_id)
                    .await
                    .map_err(administration_refusal)
            }
            (Actor::Service(checker), Some(resource)) => {
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
        asker: &Actor,
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
                    Ok(SenderProofProfile::Dpop) => sid_authz::request_verifier::ProofProfile::Dpop,
                    _ => {
                        return Err(confirmation_unfit(
                            "request.confirmation.profile",
                            "not a supported proof kind",
                        ));
                    }
                };
                let Actor::Service(verifier) = asker else {
                    return Err(checker_denied());
                };
                if !self
                    .request_verifiers
                    .permits(verifier, registered.indicator.as_str(), profile)
                {
                    return Err(checker_denied());
                }
                check_confirmation(confirmation, &claims, chrono::Utc::now())?;
                self.admit_confirmed_proof(
                    confirmation,
                    &request.access_token,
                    &claims.iss,
                    &registered.id,
                    verifier,
                )
                .await?;
                false
            }
        };
        let mut context = std::collections::BTreeMap::new();
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

    /// Admit the original request's proof that `confirmation` reports at this
    /// issuer, once for that request (RFC 9449 §11.1): the question about a
    /// request whose proof another request used is refused, and one this
    /// issuer cannot decide is UNAVAILABLE, never an allow.
    #[allow(clippy::result_large_err)]
    async fn admit_confirmed_proof(
        &self,
        confirmation: &RequestConfirmation,
        access_token: &str,
        issuer: &str,
        resource: &sid_core::models::ResourceId,
        verifier: &str,
    ) -> Result<(), Status> {
        let proof = confirmed_proof(confirmation)?;
        let holder = sid_authn::dpop::request_holder(
            &confirmation.request_id,
            access_token,
            &confirmation.method,
            &confirmation.uri,
            verifier,
        );
        sid_authn::dpop::DPopValidator::new(self.storage.clone())
            .admit_for_request(
                &format!("{issuer} {resource}"),
                &confirmation.jkt,
                &proof,
                &holder,
            )
            .await
            .map_err(|e| match e {
                sid_authn::dpop::DPopError::ReplayStoreUnavailable => {
                    dependency_unavailable("DPoP replay record", "replay store unreachable")
                }
                // The request's token with its proof is no longer usable: the
                // evidence itself is refused, as for a revoked token.
                other => invalid_field("request.access_token", other.to_string()),
            })
    }

    /// Authenticate the caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// Authenticate the caller of `request` as the installation's
    /// administrator: roles, assignments, groups and policies decide every
    /// other permission.
    async fn admin<T>(&self, request: &Request<T>) -> Result<InstallationAdministrator, Status> {
        let caller = self.caller(request).await?;
        self.authorization
            .installation_administrator(&caller)
            .await
            .map_err(refusal)
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

/// The answer of a management operation.
fn answered<T>(result: Result<T, AuthorizationError>) -> Result<Response<T>, Status> {
    result.map(Response::new).map_err(refusal)
}

#[tonic::async_trait]
impl AuthzService for AuthzServiceImpl {
    // ── Permission checks (delegated to CeAuthzEngine) ──────────────

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

    // ── Roles ───────────────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "create_role"))]
    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(self.authorization.create_role(&admin, operation, req).await)
    }

    #[instrument(skip_all, fields(method = "get_role"))]
    async fn get_role(
        &self,
        request: Request<GetRoleRequest>,
    ) -> Result<Response<GetRoleResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .get_role(&admin, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "update_role"))]
    async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<UpdateRoleResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(self.authorization.update_role(&actor, operation, req).await)
    }

    #[instrument(skip_all, fields(method = "delete_role"))]
    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(self.authorization.delete_role(&admin, operation, req).await)
    }

    #[instrument(skip_all, fields(method = "list_roles"))]
    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .list_roles(&admin, request.into_inner())
                .await,
        )
    }

    // ── Role assignments ────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "assign_role"))]
    async fn assign_role(
        &self,
        request: Request<AssignRoleRequest>,
    ) -> Result<Response<AssignRoleResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(self.authorization.assign_role(&actor, operation, req).await)
    }

    #[instrument(skip_all, fields(method = "revoke_role"))]
    async fn revoke_role(
        &self,
        request: Request<RevokeRoleRequest>,
    ) -> Result<Response<RevokeRoleResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(self.authorization.revoke_role(&actor, operation, req).await)
    }

    #[instrument(skip_all, fields(method = "set_role_assignments"))]
    async fn set_role_assignments(
        &self,
        request: Request<SetRoleAssignmentsRequest>,
    ) -> Result<Response<SetRoleAssignmentsResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .set_role_assignments(&actor, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "list_role_assignments"))]
    async fn list_role_assignments(
        &self,
        request: Request<ListRoleAssignmentsRequest>,
    ) -> Result<Response<ListRoleAssignmentsResponse>, Status> {
        let actor = self.asker(&request).await?;
        answered(
            self.authorization
                .list_role_assignments(&actor, request.into_inner())
                .await,
        )
    }

    // ── Groups ──────────────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "create_group"))]
    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .create_group(&admin, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "get_group"))]
    async fn get_group(
        &self,
        request: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .get_group(&admin, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "update_group"))]
    async fn update_group(
        &self,
        request: Request<UpdateGroupRequest>,
    ) -> Result<Response<UpdateGroupResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .update_group(&admin, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "delete_group"))]
    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .delete_group(&admin, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "list_groups"))]
    async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<ListGroupsResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .list_groups(&admin, request.into_inner())
                .await,
        )
    }

    // ── Group membership ────────────────────────────────────────────

    #[instrument(skip_all, fields(method = "add_to_group"))]
    async fn add_to_group(
        &self,
        request: Request<AddToGroupRequest>,
    ) -> Result<Response<AddToGroupResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .add_to_group(&admin, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "remove_from_group"))]
    async fn remove_from_group(
        &self,
        request: Request<RemoveFromGroupRequest>,
    ) -> Result<Response<RemoveFromGroupResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .remove_from_group(&admin, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "list_group_members"))]
    async fn list_group_members(
        &self,
        request: Request<ListGroupMembersRequest>,
    ) -> Result<Response<ListGroupMembersResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .list_group_members(&admin, request.into_inner())
                .await,
        )
    }

    // ── Policies (Cedar ABAC) ───────────────────────────────────────

    #[instrument(skip_all, fields(method = "create_policy"))]
    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .create_policy(&actor, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "get_policy"))]
    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let actor = self.asker(&request).await?;
        answered(
            self.authorization
                .get_policy(&actor, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "update_policy"))]
    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .update_policy(&actor, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "delete_policy"))]
    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let actor = self.asker(&request).await?;
        self.check_maintenance()?;
        let (metadata, _, req) = request.into_parts();
        let operation = metadata_context(&metadata)?;
        answered(
            self.authorization
                .delete_policy(&actor, operation, req)
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "list_policies"))]
    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let actor = self.asker(&request).await?;
        answered(
            self.authorization
                .list_policies(&actor, request.into_inner())
                .await,
        )
    }

    // ── Policy evaluation ───────────────────────────────────────────

    #[instrument(skip_all, fields(method = "evaluate_policy"))]
    async fn evaluate_policy(
        &self,
        request: Request<EvaluatePolicyRequest>,
    ) -> Result<Response<EvaluatePolicyResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .evaluate_policy(&admin, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "validate_policy"))]
    async fn validate_policy(
        &self,
        request: Request<ValidatePolicyRequest>,
    ) -> Result<Response<ValidatePolicyResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .validate_policy(&admin, request.into_inner()),
        )
    }

    #[instrument(skip_all, fields(method = "check_sod_conflicts"))]
    async fn check_sod_conflicts(
        &self,
        request: Request<CheckSodConflictsRequest>,
    ) -> Result<Response<CheckSodConflictsResponse>, Status> {
        let admin = self.admin(&request).await?;
        answered(
            self.authorization
                .check_sod_conflicts(&admin, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "simulate_policy"))]
    async fn simulate_policy(
        &self,
        request: Request<SimulatePolicyRequest>,
    ) -> Result<Response<SimulatePolicyResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.check_maintenance()?;
        answered(
            self.authorization
                .simulate_policy(&admin, request.into_inner())
                .await,
        )
    }
}

#[cfg(test)]
mod tests;
