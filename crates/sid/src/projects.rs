// SPDX-License-Identifier: AGPL-3.0-only
//! Project management: projects, their applications with client and resource
//! roles, access of clients to resources, project roles and the initial
//! access tokens of dynamic client registration, plus that registration
//! itself (RFC 7591, RFC 7592). The same operations for the service and an
//! embedding application. An administrative operation takes a verified
//! [`Caller`] and checks its authority itself; a registration operation
//! takes the initial or registration access token its client presents. A
//! keyed operation takes the caller's operation context, commits its state,
//! audit and completion together and answers a retry with what the first
//! attempt recorded.

use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, phc::PasswordHash},
};
use prost::Message;
use secrecy::{ExposeSecret, SecretBox};
use sid_authn::caller::{Caller, CallerError};
use sid_authn::dcr;
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::{
    self as model, ApplicationId, ApplicationType, AuditEntry, InitialAccessToken,
    InitialAccessTokenId, LoginStrategy, MutationContext, OAuth2Client, OperationContext, Project,
    ProjectChange, ProjectId, ResourceId, ResourceIndicator, ResourceState, Role, RoleId,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::projects::project_service as keyed;
use sid_proto::sid::v1::{
    self as v1, AddClientRoleRequest, AddResourceRoleRequest, AddRoleRequest, Application,
    ClientRoleSettings, CreateApplicationRequest, CreateApplicationResponse,
    CreateInitialAccessTokenRequest, CreateInitialAccessTokenResponse, CreateProjectRequest,
    DeleteApplicationRequest, DeleteProjectRequest, DeleteRegisteredClientRequest,
    GetApplicationRequest, GetProjectRequest, GetRegisteredClientRequest, ListApplicationsRequest,
    ListApplicationsResponse, ListInitialAccessTokensRequest, ListInitialAccessTokensResponse,
    ListProjectsRequest, ListProjectsResponse, ListResourceAccessRequest,
    ListResourceAccessResponse, OAuthClient, RegisterClientRequest, RegisterClientResponse,
    RemoveResourceAccessRequest, RemoveRoleRequest, ResourceRoleSettings,
    RevokeInitialAccessTokenRequest, SetResourceAccessRequest, UpdateApplicationRequest,
    UpdateClientRoleRequest, UpdateProjectRequest, UpdateRegisteredClientRequest,
    UpdateResourceRoleRequest,
};
use tracing::{info, warn};

use crate::wire::{FieldError, wire_id};

mod view;

use view::{
    access_to_proto, application_to_proto, client_to_proto, iat_to_proto, project_to_proto,
    resource_to_proto, role_to_proto,
};

/// Which check a refused registration or self-service update failed: the
/// request's own metadata, or what its initial access token allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCheck {
    /// The metadata is malformed or unsupported (`invalid_client_metadata`).
    Metadata,
    /// The initial access token does not allow it.
    TokenPolicy,
}

/// Why a project operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
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
    /// Client metadata the issuer refuses (RFC 7591 §3.2.2
    /// `invalid_client_metadata`), naming the field.
    #[error("{field}: {message}")]
    Metadata {
        field: &'static str,
        message: String,
    },
    /// A registration or self-service update the dynamic registration rules
    /// refused.
    #[error("{error}")]
    Registration {
        error: dcr::DcrError,
        check: RegistrationCheck,
    },
    #[error("project {0} not found")]
    ProjectNotFound(ProjectId),
    #[error("application {0} not found")]
    ApplicationNotFound(ApplicationId),
    /// No client has this identifier (the client an edit names).
    #[error("no client {0}")]
    ClientNotFound(String),
    /// No client was found to answer an update with: it was deleted.
    #[error("client {0} not found")]
    ClientGone(String),
    /// Neither a client nor a live machine user has this identifier.
    #[error("no client or machine user {0}")]
    RequesterNotFound(String),
    #[error("protected resource {0} not found")]
    ResourceNotFound(ResourceId),
    #[error("role {0} not found")]
    RoleNotFound(RoleId),
    #[error("initial access token {0} not found")]
    IatNotFound(InitialAccessTokenId),
    /// No OIDC issuer has this handle here.
    #[error("no OIDC issuer {0}")]
    IssuerNotFound(String),
    /// The project still has applications or SCIM targets.
    #[error("project {0} is in use")]
    ProjectInUse(ProjectId),
    /// SID provisions and keeps the system project.
    #[error("the system project cannot be changed: {0}")]
    SystemProject(&'static str),
    /// SID provisions and keeps the installation's own integrations.
    #[error("the application is managed by SID: {what}")]
    SystemManaged {
        application: ApplicationId,
        what: &'static str,
    },
    /// The application already has a role of this kind.
    #[error("the application already has a {role} role")]
    RoleExists {
        application: ApplicationId,
        role: &'static str,
    },
    /// The issuer has, or had, a protected resource with this indicator.
    #[error("indicator {0} is taken")]
    IndicatorTaken(ResourceIndicator),
    /// The protected resource is retired with its application.
    #[error("protected resource {0} is retired")]
    ResourceRetired(ResourceId),
    /// A resource is retired only by removing its application.
    #[error("protected resource {0} is retired only with its application")]
    RetireByRemoval(ResourceId),
    /// The client and the resource belong to different issuers.
    #[error("the client and resource {0} belong to different issuers")]
    IssuerMismatch(ResourceId),
    /// The project already has a role with this key or display name.
    #[error("the project already has role {0}")]
    RoleTaken(String),
    /// An application needs a client role, a resource role, or both.
    #[error("an application needs a client role, a resource role, or both")]
    RoleRequired,
    /// Resource access is listed for a client or a resource.
    #[error("name a client or a resource")]
    SubjectRequired,
    /// Changing a client's subject type needs the identity migration.
    #[error("client {0} needs the identity migration")]
    SubjectMigrationRequired(String),
    /// The initial access token is unknown, revoked, expired or used up.
    #[error("the initial access token is not valid")]
    IatUnusable,
    /// The initial access token is expired or revoked.
    #[error("the initial access token is expired or revoked")]
    IatEnded,
    /// The registration access token does not manage this client.
    #[error("the registration access token is not valid")]
    RatInvalid,
    /// The client was not registered dynamically.
    #[error("client {0} was not dynamically registered")]
    NotRegisteredDynamically(String),
    /// The initial access token the client was registered with is gone.
    #[error("initial access token {0} no longer exists")]
    IatDeleted(InitialAccessTokenId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<ProjectError> for Effect<ProjectError> {
    fn from(e: ProjectError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<ProjectError>> for ProjectError {
    fn from(e: CommandError<ProjectError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for ProjectError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

impl From<FieldError> for Effect<ProjectError> {
    fn from(e: FieldError) -> Self {
        Self::Refused(e.into())
    }
}

fn invalid_field(field: &'static str, reason: impl Into<String>) -> ProjectError {
    ProjectError::InvalidField {
        field,
        reason: reason.into(),
    }
}

fn metadata_refusal(field: &'static str, message: impl Into<String>) -> ProjectError {
    ProjectError::Metadata {
        field,
        message: message.into(),
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> ProjectError {
    tracing::error!(operation, error = %cause, "internal failure");
    ProjectError::Internal
}

/// What a created client role or application answers with, and the secret
/// issued with it, handed to the caller once and never recorded.
pub struct Issued<T> {
    pub response: T,
    pub client_secret: Option<SecretBox<String>>,
}

/// The project management of one installation's organization and issuer.
pub struct Projects {
    storage: Arc<dyn StorageBackend>,
    /// The installation's organization: every application registered here
    /// belongs to it.
    org: model::OrgId,
    /// That organization's OIDC issuer, the one its applications configure.
    issuer: model::OidcIssuer,
}

/// The request fields a new resource role's indicator and scopes come from.
#[derive(Clone, Copy)]
struct ResourceFields {
    indicator: &'static str,
    scopes: &'static str,
}

/// The fields of `CreateApplicationRequest.resource`.
const CREATE_RESOURCE_FIELDS: ResourceFields = ResourceFields {
    indicator: "resource.indicator",
    scopes: "resource.scopes",
};

/// The fields of `AddResourceRoleRequest.settings`.
const ADD_RESOURCE_FIELDS: ResourceFields = ResourceFields {
    indicator: "settings.indicator",
    scopes: "settings.scopes",
};

impl Projects {
    pub fn new(storage: Arc<dyn StorageBackend>, issuer: model::OidcIssuer) -> Self {
        Self {
            storage,
            org: issuer.recipient_org,
            issuer,
        }
    }

    /// Projects, applications (OAuth clients and their secrets), project
    /// roles and registration tokens are instance administration.
    fn admin(caller: &Caller) -> Result<(), ProjectError> {
        Ok(caller.require_admin()?)
    }

    /// The exact issuer `client` is registered under. Every application here
    /// belongs to the installation's organization; one that does not has no
    /// issuer to report, which is an internal inconsistency, never an empty
    /// value a relying party would configure.
    fn issuer_of(&self, client: &OAuth2Client) -> Result<&str, ProjectError> {
        if self.issuer.serves(client.org_id) {
            Ok(&self.issuer.canonical_url)
        } else {
            warn!(client_id = %client.client_id, "application outside the installation's organization");
            Err(ProjectError::Internal)
        }
    }

    /// `client` as the API shows it, with its issuer.
    fn client_view(&self, client: &OAuth2Client) -> Result<OAuthClient, ProjectError> {
        Ok(client_to_proto(client, self.issuer_of(client)?))
    }

    /// The exact issuer whose tokens `resource` accepts. Resources here are
    /// registered under the installation organization's issuer; any other is
    /// an internal inconsistency.
    fn resource_issuer(&self, resource: &model::ProtectedResource) -> Result<&str, ProjectError> {
        if resource.issuer_id == self.issuer.id {
            Ok(&self.issuer.canonical_url)
        } else {
            warn!(resource = %resource.id, "resource of another issuer");
            Err(ProjectError::Internal)
        }
    }

    /// `resource` as the API shows it, with its issuer.
    fn resource_view(
        &self,
        resource: &model::ProtectedResource,
    ) -> Result<v1::ProtectedResource, ProjectError> {
        Ok(resource_to_proto(resource, self.resource_issuer(resource)?))
    }

    /// `app` with the roles given.
    fn application_with(
        &self,
        app: &model::Application,
        client: Option<&OAuth2Client>,
        resource: Option<&model::ProtectedResource>,
    ) -> Result<Application, ProjectError> {
        Ok(application_to_proto(
            app,
            client.map(|c| self.client_view(c)).transpose()?,
            resource.map(|r| self.resource_view(r)).transpose()?,
        ))
    }

    /// `app` with its stored roles.
    async fn application_view(
        &self,
        app: &model::Application,
    ) -> Result<Application, ProjectError> {
        let client = self.storage.oauth2_client_of_application(app.id).await?;
        let resource = self
            .storage
            .protected_resource_of_application(app.id)
            .await?;
        self.application_with(app, client.as_ref(), resource.as_ref())
    }

    /// The stored application `id` names (field `field`).
    async fn load_application(
        &self,
        field: &'static str,
        id: Option<&sid_ids_proto::ApplicationId>,
    ) -> Result<model::Application, ProjectError> {
        let id: ApplicationId = wire_id(id, field)?;
        self.storage
            .get_application(id)
            .await?
            .ok_or(ProjectError::ApplicationNotFound(id))
    }

    /// The stored client `client_id` names.
    async fn load_client(&self, client_id: &str) -> Result<OAuth2Client, ProjectError> {
        if client_id.is_empty() {
            return Err(ProjectError::MissingField("client_id"));
        }
        self.storage
            .get_oauth2_client(client_id)
            .await?
            .ok_or_else(|| ProjectError::ClientNotFound(client_id.to_owned()))
    }

    /// Whether this issuer serves the client `client_id` names: an OAuth
    /// client of its organization, or a live machine user, which belongs to
    /// the installation. Neither is NOT_FOUND. An OAuth client is looked up
    /// first, as the token endpoint does.
    async fn requester_served(&self, client_id: &str) -> Result<bool, ProjectError> {
        if client_id.is_empty() {
            return Err(ProjectError::MissingField("client_id"));
        }
        if let Some(client) = self.storage.get_oauth2_client(client_id).await? {
            return Ok(self.issuer.serves(client.org_id));
        }
        match self
            .storage
            .get_machine_user_by_client_id(client_id)
            .await?
        {
            Some(machine) if machine.status != model::machine_user::MachineUserStatus::Deleted => {
                Ok(self.issuer.serves(Some(self.org)))
            }
            _ => Err(ProjectError::RequesterNotFound(client_id.to_owned())),
        }
    }

    /// Whether application `id` is one of the installation's own integrations.
    async fn is_system(&self, id: ApplicationId) -> Result<bool, ProjectError> {
        Ok(self
            .storage
            .get_application(id)
            .await?
            .is_some_and(|app| app.system.is_some()))
    }

    /// The integration application whose client `client_id` is, if it is one.
    async fn system_client(&self, client_id: &str) -> Result<Option<ApplicationId>, ProjectError> {
        let Some(client) = self.storage.get_oauth2_client(client_id).await? else {
            return Ok(None);
        };
        Ok(self
            .is_system(client.application_id)
            .await?
            .then_some(client.application_id))
    }

    /// The stored resource `id` names (field `field`), retired ones included.
    async fn load_resource(
        &self,
        field: &'static str,
        id: Option<&sid_ids_proto::ResourceId>,
    ) -> Result<model::ProtectedResource, ProjectError> {
        let id: ResourceId = wire_id(id, field)?;
        self.storage
            .get_protected_resource(id)
            .await?
            .ok_or(ProjectError::ResourceNotFound(id))
    }

    /// A new client role of `app` from `settings`, with the secret a
    /// confidential client is issued.
    fn new_client(
        &self,
        app: &model::Application,
        settings: ClientRoleSettings,
    ) -> Result<(OAuth2Client, Option<SecretBox<String>>), ProjectError> {
        let app_type = proto_to_app_type(settings.r#type);
        // Generate client_id and secret. The whole id: a UUIDv7 prefix is a
        // timestamp, so a prefix repeats across clients created close together.
        let client_id = format!("sid_{}", uuid::Uuid::now_v7().simple());
        // Browser and native applications are public clients: a secret
        // shipped in them is readable by anyone, so they get none and
        // authenticate with PKCE alone (RFC 8252 §8.4, OAuth 2.1 §2.1).
        let public = matches!(app_type, ApplicationType::Spa | ApplicationType::Native);
        // A client that brings its keys proves itself with them (RFC 7523
        // §2.2): it gets no secret. A public client holds no credential.
        let jwks = requested_jwks(settings.jwks.as_deref())?;
        if public && jwks.is_some() {
            return Err(metadata_refusal(
                "client.jwks",
                "a native or single-page client is public and registers no keys",
            ));
        }
        dcr::validate_post_logout_redirect_uris(&settings.post_logout_redirect_uris, app_type)
            .map_err(|e| invalid_field("client.post_logout_redirect_uris", e.to_string()))?;
        let client_secret = (!public && jwks.is_none()).then(generate_client_secret);
        let secret_hash = client_secret
            .as_ref()
            .map(|secret| hash_secret(secret.expose_secret()))
            .transpose()?;
        let now = chrono::Utc::now();
        let client = OAuth2Client {
            client_id,
            project_id: app.project_id,
            application_id: app.id,
            default_resource: None,
            application_type: app_type,
            client_secret_hash: secret_hash.map(String::into_bytes),
            redirect_uris: settings.redirect_uris,
            allowed_scopes: if settings.allowed_scopes.is_empty() {
                vec!["openid".into(), "profile".into(), "email".into()]
            } else {
                settings.allowed_scopes
            },
            grant_types: if settings.grant_types.is_empty() {
                vec!["authorization_code".into(), "refresh_token".into()]
            } else {
                settings.grant_types
            },
            client_name: app.name.clone(),
            logo_uri: None,
            active: true,
            // A confidential client without keys gets the registration default
            // (RFC 7591 §2).
            token_endpoint_auth_method: match (public, &jwks) {
                (true, _) => model::TokenEndpointAuthMethod::None,
                (false, Some(_)) => model::TokenEndpointAuthMethod::PrivateKeyJwt,
                (false, None) => model::TokenEndpointAuthMethod::ClientSecretBasic,
            },
            jwks,
            response_types: vec!["code".into()],
            // The documented registration value (registration metadata A):
            // issuer-relative public, which does not decide a user's subject.
            subject_type: model::SubjectType::Public,
            sector_identifier_uri: None,
            contacts: vec![],
            client_id_issued_at: now,
            client_secret_expires_at: None,
            registration_iat: None,
            registration_access_token_hash: None,
            required_acr: None,
            required_amr: vec![],
            enforcement_mode: model::EnforcementMode::Audit,
            min_device_assurance: None,
            require_verified_email: None,
            require_verified_phone: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            post_logout_redirect_uris: settings.post_logout_redirect_uris,
            claim_mappings: vec![],
            login_strategy: LoginStrategy::LocalFirst,
            show_federation_button: true,
            federation_timeout_ms: 500,
            unified_input: false,
            org_id: Some(self.org),
            revision: 0,
            created_at: now,
        };
        Ok((client, client_secret))
    }

    /// A new resource role of `app` from `settings`, under the installation
    /// organization's issuer. `fields` name the request's indicator and
    /// scopes fields in a refusal.
    fn new_resource(
        &self,
        app: &model::Application,
        fields: ResourceFields,
        settings: ResourceRoleSettings,
    ) -> Result<model::ProtectedResource, ProjectError> {
        let indicator = ResourceIndicator::parse(&settings.indicator)
            .map_err(|e| invalid_field(fields.indicator, e))?;
        let scopes =
            model::scope_list(&settings.scopes).map_err(|e| invalid_field(fields.scopes, e))?;
        let now = chrono::Utc::now();
        Ok(model::ProtectedResource {
            id: ResourceId::generate(),
            application_id: Some(app.id),
            issuer_id: self.issuer.id,
            indicator,
            scopes,
            state: ResourceState::Active,
            revision: 0,
            created_at: now,
            updated_at: now,
        })
    }

    /// Why a new resource role of `app` was refused as a conflict: `app`
    /// already has one, or its indicator is taken under the issuer.
    async fn resource_conflict(
        &self,
        app: ApplicationId,
        indicator: &ResourceIndicator,
    ) -> ProjectError {
        match self.storage.protected_resource_of_application(app).await {
            Ok(Some(_)) => ProjectError::RoleExists {
                application: app,
                role: "resource",
            },
            Ok(None) => ProjectError::IndicatorTaken(indicator.clone()),
            Err(e) => ProjectError::Store(e),
        }
    }

    /// The issuer a registration request names by `handle`. Clients register
    /// only under the installation organization's issuer; any other handle
    /// names no issuer here and never falls back to it.
    fn registering_issuer(&self, handle: &str) -> Result<&model::OidcIssuer, ProjectError> {
        if handle == self.issuer.handle.as_str() {
            Ok(&self.issuer)
        } else {
            Err(ProjectError::IssuerNotFound(handle.to_owned()))
        }
    }

    // ── Project CRUD ────────────────────────────────────────────────

    pub async fn create_project(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateProjectRequest,
    ) -> Result<v1::Project, ProjectError> {
        Self::admin(caller)?;
        if req.name.is_empty() {
            return Err(ProjectError::MissingField("name"));
        }

        // A retry of a completed create returns the project it created.
        let command = KeyedCommand::of::<keyed::CreateProject>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return decode_result(&result);
        }
        // A failure a concurrent attempt of this command caused (a value its
        // project took) is that attempt's answer.
        let answer: Result<v1::Project, ProjectError> = async {
            let owner_id = req
                .owner_profile_id
                .as_ref()
                .map(|id| wire_id(Some(id), "owner_profile_id"))
                .transpose()?;

            let mut project = Project::new(&req.name, owner_id);
            project.description = req.description;
            let response = project_to_proto(&project);

            let ctx: MutationContext = AuditEntry::admin(
                caller.profile_id.to_string(),
                "project.create",
                project.id.to_string(),
            )
            .into();
            match self
                .storage
                .create_project(
                    &project,
                    ctx.with_operation(command.completion(response.encode_to_vec())),
                )
                .await
            {
                Ok(()) => {}
                // A concurrent attempt of this command committed first.
                Err(SidError::OperationCompleted(_)) => {
                    let result = command.committed_elsewhere(&*self.storage).await?;
                    return decode_result(&result);
                }
                Err(e) => return Err(ProjectError::Store(e)),
            }

            info!("Created project '{}' ({})", project.name, project.id);

            Ok(response)
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn get_project(
        &self,
        caller: &Caller,
        req: GetProjectRequest,
    ) -> Result<v1::Project, ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.id.as_ref(), "id")?;
        match self.storage.get_project(project_id).await? {
            Some(p) => Ok(project_to_proto(&p)),
            None => Err(ProjectError::ProjectNotFound(project_id)),
        }
    }

    pub async fn list_projects(
        &self,
        caller: &Caller,
        req: ListProjectsRequest,
    ) -> Result<ListProjectsResponse, ProjectError> {
        Self::admin(caller)?;
        let limit = if req.page_size > 0 {
            req.page_size as u64
        } else {
            50
        };

        let projects = self.storage.list_projects(0, limit).await?;

        Ok(ListProjectsResponse {
            projects: projects.iter().map(project_to_proto).collect(),
            next_page_token: String::new(),
        })
    }

    pub async fn update_project(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateProjectRequest,
    ) -> Result<v1::Project, ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.id.as_ref(), "id")?;

        if project_id.is_system() {
            return Err(ProjectError::SystemProject("update"));
        }

        // A retry of a completed edit returns the project as that edit left
        // it, and never writes its fields again over a later edit.
        let command = KeyedCommand::of::<keyed::UpdateProject>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        let change = ProjectChange {
            name: req.name,
            description: req.description,
            updated_at: chrono::Utc::now(),
        };
        let project: Project = command
            .execute_recorded(&*self.storage, || async {
                let ctx = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "project.update",
                    project_id.to_string(),
                ))
                .with_operation(command.effect_completion());
                // Only the fields given are written: an edit racing a deletion
                // never recreates the project, and two edits of different
                // fields keep both.
                self.storage
                    .update_project(project_id, &change, ctx)
                    .await?
                    .ok_or_else(|| ProjectError::ProjectNotFound(project_id).into())
            })
            .await?;

        Ok(project_to_proto(&project))
    }

    pub async fn delete_project(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: DeleteProjectRequest,
    ) -> Result<(), ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.id.as_ref(), "id")?;

        if project_id.is_system() {
            return Err(ProjectError::SystemProject("delete"));
        }

        // A retry of a completed deletion answers as the deletion did, not
        // with the absence it left.
        let command = KeyedCommand::of::<keyed::DeleteProject>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                self.storage
                    .get_project(project_id)
                    .await?
                    .ok_or(ProjectError::ProjectNotFound(project_id))?;
                let ctx = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "project.delete",
                    project_id.to_string(),
                ))
                .with_operation(command.completion(().encode_to_vec()));
                self.storage
                    .delete_project(project_id, ctx)
                    .await
                    .map_err(|e| match e {
                        SidError::InvalidState(_) => {
                            Effect::from(ProjectError::ProjectInUse(project_id))
                        }
                        e => Effect::from(e),
                    })?;
                info!("Deleted project {project_id}");
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Application CRUD ────────────────────────────────────────────

    /// Create an application; its client secret, if one is issued, is
    /// handed back beside the response and never recorded. A retry answers
    /// with the application it created, without the secret: SID keeps only
    /// its hash, and a retry creates no second application.
    pub async fn create_application(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateApplicationRequest,
    ) -> Result<Issued<CreateApplicationResponse>, ProjectError> {
        Self::admin(caller)?;
        let command = KeyedCommand::by_profile::<keyed::CreateApplication>(
            caller.profile_id,
            operation,
            &req,
        );
        let mut issued = None;
        let response = command
            .execute(&*self.storage, || async {
                let (recorded, secret) =
                    self.new_application(caller, &command, req.clone()).await?;
                issued = secret;
                Ok(recorded)
            })
            .await?;
        Ok(Issued {
            response,
            client_secret: issued,
        })
    }

    pub async fn get_application(
        &self,
        caller: &Caller,
        req: GetApplicationRequest,
    ) -> Result<Application, ProjectError> {
        Self::admin(caller)?;
        let app = self.load_application("id", req.id.as_ref()).await?;
        self.application_view(&app).await
    }

    pub async fn list_applications(
        &self,
        caller: &Caller,
        req: ListApplicationsRequest,
    ) -> Result<ListApplicationsResponse, ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let limit = if req.page_size > 0 {
            req.page_size as u64
        } else {
            50
        };

        let apps = self
            .storage
            .list_applications_by_project(project_id, 0, limit)
            .await?;

        let mut applications = Vec::with_capacity(apps.len());
        for app in &apps {
            applications.push(self.application_view(app).await?);
        }
        Ok(ListApplicationsResponse {
            applications,
            next_page_token: String::new(),
        })
    }

    pub async fn update_application(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateApplicationRequest,
    ) -> Result<Application, ProjectError> {
        Self::admin(caller)?;
        // A retry of a completed edit returns the application as that edit
        // left it, and never renames it again over a later edit.
        let command = KeyedCommand::of::<keyed::UpdateApplication>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                let mut app = self.load_application("id", req.id.as_ref()).await?;
                if let Some(name) = req.name.clone() {
                    if name.is_empty() {
                        return Err(ProjectError::MissingField("name").into());
                    }
                    app.name = name;
                }
                app.updated_at = chrono::Utc::now();
                // The application as this edit leaves it: the store applies
                // the edit only to the revision it was read at.
                let mut left = app.clone();
                left.revision += 1;
                let view = self.application_view(&left).await?;
                let ctx = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "application.update",
                    app.id.to_string(),
                ))
                .with_operation(command.completion(view.encode_to_vec()));
                if !self.storage.update_application(&app, ctx).await? {
                    // Deleted meanwhile, or changed since it was read.
                    return Err(match self.storage.get_application(app.id).await {
                        Ok(None) => ProjectError::ApplicationNotFound(app.id),
                        Ok(Some(_)) => ProjectError::ChangedConcurrently,
                        Err(e) => ProjectError::Store(e),
                    }
                    .into());
                }
                Ok(view)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn update_client_role(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateClientRoleRequest,
    ) -> Result<Application, ProjectError> {
        Self::admin(caller)?;
        // A retry of a completed edit answers with the application as that
        // edit left it, and never applies the edit again over a later one.
        let command =
            KeyedCommand::by_profile::<keyed::UpdateClientRole>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || {
                self.edit_client(caller, &command, req.clone())
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn delete_application(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: DeleteApplicationRequest,
    ) -> Result<(), ProjectError> {
        Self::admin(caller)?;
        let id: ApplicationId = wire_id(req.id.as_ref(), "id")?;
        // Deleting it would only bring it back, with new identifiers, at the
        // next start; an integration is disabled instead.
        if self
            .storage
            .get_application(id)
            .await?
            .is_some_and(|app| app.system.is_some())
        {
            return Err(ProjectError::SystemManaged {
                application: id,
                what: "it cannot be deleted",
            });
        }
        // A retry of a completed deletion answers as the deletion did.
        let command = KeyedCommand::by_profile::<keyed::DeleteApplication>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                let ctx = admin_ctx(caller, "application.delete", id.to_string())
                    .with_operation(command.completion(().encode_to_vec()));
                if !self.storage.delete_application(id, ctx).await? {
                    return Err(ProjectError::ApplicationNotFound(id).into());
                }
                info!("Deleted application {}", id);
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Add a client role to an application; its secret, if one is issued, is
    /// handed back beside the response. A retry answers with the application
    /// and its client, without the secret: SID keeps only its hash, and a
    /// retry issues nothing new.
    pub async fn add_client_role(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AddClientRoleRequest,
    ) -> Result<Issued<CreateApplicationResponse>, ProjectError> {
        Self::admin(caller)?;
        let command =
            KeyedCommand::by_profile::<keyed::AddClientRole>(caller.profile_id, operation, &req);
        let mut issued = None;
        let response = command
            .execute(&*self.storage, || async {
                let app = self
                    .load_application("application_id", req.application_id.as_ref())
                    .await?;
                let settings = req
                    .settings
                    .clone()
                    .ok_or(ProjectError::MissingField("settings"))?;
                let (client, client_secret) = self.new_client(&app, settings)?;
                // The application as this addition leaves it: its stored
                // roles and the new client.
                let mut view = self.application_view(&app).await?;
                view.client = Some(self.client_view(&client)?);
                let recorded = CreateApplicationResponse {
                    application: Some(view),
                    client_secret: String::new(),
                };
                let ctx = admin_ctx(caller, "client.create", client.client_id.clone())
                    .with_operation(command.completion(recorded.encode_to_vec()));
                self.storage
                    .create_oauth2_client(&client, ctx)
                    .await
                    .map_err(|e| match e {
                        // The client id is freshly generated: the role is taken.
                        SidError::Conflict(_) => Effect::from(ProjectError::RoleExists {
                            application: app.id,
                            role: "client",
                        }),
                        e => Effect::from(e),
                    })?;
                info!(
                    "Added client role {} to application {}",
                    client.client_id, app.id
                );
                issued = client_secret;
                Ok(recorded)
            })
            .await?;
        Ok(Issued {
            response,
            client_secret: issued,
        })
    }

    pub async fn add_resource_role(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AddResourceRoleRequest,
    ) -> Result<Application, ProjectError> {
        Self::admin(caller)?;
        // A retry of a completed addition answers with the application as it
        // left it, and never adds a second resource.
        let command =
            KeyedCommand::by_profile::<keyed::AddResourceRole>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let app = self
                    .load_application("application_id", req.application_id.as_ref())
                    .await?;
                let settings = req
                    .settings
                    .clone()
                    .ok_or(ProjectError::MissingField("settings"))?;
                let resource = self.new_resource(&app, ADD_RESOURCE_FIELDS, settings)?;
                let mut view = self.application_view(&app).await?;
                view.resource = Some(self.resource_view(&resource)?);
                let ctx = admin_ctx(caller, "resource.create", resource.id.to_string())
                    .with_operation(command.completion(view.encode_to_vec()));
                if let Err(e) = self.storage.create_protected_resource(&resource, ctx).await {
                    return Err(match e {
                        SidError::Conflict(_) => self
                            .resource_conflict(app.id, &resource.indicator)
                            .await
                            .into(),
                        e => e.into(),
                    });
                }
                info!(
                    "Added resource role {} ({}) to application {}",
                    resource.id, resource.indicator, app.id
                );
                Ok(view)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn update_resource_role(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateResourceRoleRequest,
    ) -> Result<v1::ProtectedResource, ProjectError> {
        Self::admin(caller)?;
        // A retry of a completed edit answers with the resource as that edit
        // left it, and never applies it again over a later edit.
        let command = KeyedCommand::by_profile::<keyed::UpdateResourceRole>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || {
                self.edit_resource(caller, &command, req.clone())
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn set_resource_access(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: SetResourceAccessRequest,
    ) -> Result<v1::ResourceAccess, ProjectError> {
        Self::admin(caller)?;
        // A retry of a completed grant answers with the access it set, and
        // never sets those scopes again over a later change.
        let command = KeyedCommand::by_profile::<keyed::SetResourceAccess>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || {
                self.grant_access(caller, &command, req.clone())
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn remove_resource_access(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RemoveResourceAccessRequest,
    ) -> Result<(), ProjectError> {
        Self::admin(caller)?;
        if req.client_id.is_empty() {
            return Err(ProjectError::MissingField("client_id"));
        }
        let resource: ResourceId = wire_id(req.resource_id.as_ref(), "resource_id")?;
        if let Some(app) = self.system_client(&req.client_id).await? {
            return Err(ProjectError::SystemManaged {
                application: app,
                what: "its client's access follows the integration",
            });
        }
        // A retry of a completed removal never removes a grant made after it.
        let command = KeyedCommand::by_profile::<keyed::RemoveResourceAccess>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                let ctx = admin_ctx(
                    caller,
                    "resource_access.remove",
                    format!("{}:{}", req.client_id, resource),
                )
                .with_operation(command.completion(().encode_to_vec()));
                // Removing access the client does not have leaves the state
                // asked for.
                self.storage
                    .remove_resource_access(&req.client_id, resource, ctx)
                    .await?;
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn list_resource_access(
        &self,
        caller: &Caller,
        req: ListResourceAccessRequest,
    ) -> Result<ListResourceAccessResponse, ProjectError> {
        use sid_proto::sid::v1::list_resource_access_request::Subject;
        Self::admin(caller)?;
        let access = match req.subject {
            Some(Subject::ClientId(client_id)) if !client_id.is_empty() => {
                self.storage
                    .list_resource_access_by_client(&client_id)
                    .await?
            }
            Some(Subject::ResourceId(id)) => {
                let resource: ResourceId = wire_id(Some(&id), "resource_id")?;
                self.storage
                    .list_resource_access_by_resource(resource)
                    .await?
            }
            _ => return Err(ProjectError::SubjectRequired),
        };
        Ok(ListResourceAccessResponse {
            access: access.iter().map(access_to_proto).collect(),
        })
    }

    // ── Role management ─────────────────────────────────────────────

    pub async fn add_role(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AddRoleRequest,
    ) -> Result<v1::Role, ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;

        if req.key.is_empty() {
            return Err(ProjectError::MissingField("key"));
        }
        if req.display_name.is_empty() {
            return Err(ProjectError::MissingField("display_name"));
        }

        // A retry of a completed addition answers with the role it added,
        // never as a conflict with that role.
        let command =
            KeyedCommand::by_profile::<keyed::AddRole>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                self.storage
                    .get_project(project_id)
                    .await?
                    .ok_or(ProjectError::ProjectNotFound(project_id))?;

                let mut role = Role::new(project_id, &req.key, &req.display_name);
                role.description = req.description.clone();
                role.group = req.group.clone();
                role.permissions = req.permissions.clone();
                let view = role_to_proto(&role);
                let ctx = admin_ctx(caller, "role.create", role.id.to_string())
                    .with_operation(command.completion(view.encode_to_vec()));

                // The store rejects a second role with this key or display name.
                self.storage
                    .create_role(&role, ctx)
                    .await
                    .map_err(|e| match e {
                        SidError::Conflict(_) => {
                            Effect::from(ProjectError::RoleTaken(req.key.clone()))
                        }
                        other => Effect::from(other),
                    })?;
                info!("Added role '{}' to project {project_id}", role.key);
                Ok(view)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn remove_role(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RemoveRoleRequest,
    ) -> Result<(), ProjectError> {
        Self::admin(caller)?;
        let role_id: RoleId = wire_id(req.role_id.as_ref(), "role_id")?;
        // An absent project leaves the role's own project; a named one must be it.
        let project_id: Option<ProjectId> = req
            .project_id
            .as_ref()
            .map(|id| wire_id(Some(id), "project_id"))
            .transpose()?;

        // A retry of a completed removal answers as the removal did.
        let command =
            KeyedCommand::by_profile::<keyed::RemoveRole>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                // Verify role exists and belongs to the specified project
                let role = self
                    .storage
                    .get_role(role_id)
                    .await?
                    .ok_or(ProjectError::RoleNotFound(role_id))?;
                if project_id.is_some_and(|project| project != role.project_id) {
                    return Err(ProjectError::RoleNotFound(role_id).into());
                }
                let ctx = admin_ctx(caller, "role.delete", role_id.to_string())
                    .with_operation(command.completion(().encode_to_vec()));
                self.storage.delete_role(role_id, ctx).await?;
                info!("Removed role {} from project {}", role_id, role.project_id);
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Dynamic Client Registration (RFC 7591) ──────────────────────

    /// Whether clients register here under the issuer `handle` names: a
    /// transport checks this before it reads the registrant's token, so an
    /// unknown issuer is refused as such.
    pub fn check_registration_issuer(&self, handle: &str) -> Result<(), ProjectError> {
        self.registering_issuer(handle).map(|_| ())
    }

    /// Register a client with the initial access token `iat_token` its
    /// registrant presents.
    pub async fn register_client(
        &self,
        iat_token: &str,
        mut req: RegisterClientRequest,
    ) -> Result<RegisterClientResponse, ProjectError> {
        let issuer = self.registering_issuer(&req.issuer_handle)?.clone();
        let iat_hash = sha256_hash(iat_token.as_bytes());

        let iat = self
            .storage
            .get_initial_access_token_by_hash(&iat_hash)
            .await?
            .ok_or(ProjectError::IatUnusable)?;

        dcr::apply_metadata_defaults(&mut req.grant_types, &mut req.response_types);

        let app_type = proto_to_app_type(req.application_type);
        let dcr_req = dcr::ClientRegistrationRequest {
            client_name: req.client_name.clone(),
            redirect_uris: req.redirect_uris.clone(),
            grant_types: req.grant_types.clone(),
            response_types: req.response_types.clone(),
            token_endpoint_auth_method: requested_auth_method(req.token_endpoint_auth_method)?,
            application_type: app_type,
            subject_type: requested_subject_type(req.subject_type)?,
            sector_identifier_uri: req.sector_identifier_uri.clone(),
            contacts: req.contacts.clone(),
            scope: req.scope.clone(),
            post_logout_redirect_uris: req.post_logout_redirect_uris.clone(),
        };

        // Validate request structure; incompatible subject metadata is refused
        // before any credential is generated or anything is written.
        dcr::validate_registration_request(&dcr_req)
            .map_err(|e| dcr_refusal(e, RegistrationCheck::Metadata))?;

        // Validate IAT constraints
        dcr::validate_iat_constraints(&iat, &dcr_req)
            .map_err(|e| dcr_refusal(e, RegistrationCheck::TokenPolicy))?;

        // The whole UUIDv7: its random part is what makes the identifier unique.
        let client_id = format!("dyn_{}", uuid::Uuid::now_v7().simple());
        let needs_secret = matches!(
            dcr_req.token_endpoint_auth_method,
            model::TokenEndpointAuthMethod::ClientSecretPost
                | model::TokenEndpointAuthMethod::ClientSecretBasic
        );
        let (client_secret, secret_hash) = if needs_secret {
            let secret = generate_client_secret();
            let hash = hash_secret(secret.expose_secret())?;
            (Some(secret), Some(hash.into_bytes()))
        } else {
            (None, None)
        };

        // Generate Registration Access Token (RFC 7592)
        let rat = generate_client_secret();
        let rat_hash = sha256_hash(rat.expose_secret().as_bytes());

        let now = chrono::Utc::now();
        // Enforce registration policy: AdminApproval = client created inactive.
        let policy = model::RegistrationPolicy::default(); // CE default.
        let client_active = match policy {
            model::RegistrationPolicy::AdminApproval => false,
            model::RegistrationPolicy::Authenticated => true,
        };

        // A registration creates a client role of a new application, never a
        // resource or access to one.
        let app = model::Application {
            id: ApplicationId::generate(),
            project_id: iat.project_id,
            name: req.client_name.clone(),
            system: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        };
        let client = OAuth2Client {
            client_id: client_id.clone(),
            project_id: iat.project_id,
            application_id: app.id,
            default_resource: None,
            application_type: app_type,
            client_secret_hash: secret_hash,
            jwks: requested_jwks(req.jwks.as_deref())?,
            redirect_uris: req.redirect_uris,
            allowed_scopes: req.scope,
            grant_types: req.grant_types,
            client_name: req.client_name,
            logo_uri: None,
            active: client_active,
            token_endpoint_auth_method: dcr_req.token_endpoint_auth_method,
            response_types: req.response_types,
            subject_type: dcr_req.subject_type,
            sector_identifier_uri: req.sector_identifier_uri,
            contacts: req.contacts,
            client_id_issued_at: now,
            client_secret_expires_at: None,
            registration_iat: Some(iat.id),
            registration_access_token_hash: Some(rat_hash),
            required_acr: None,
            required_amr: vec![],
            enforcement_mode: model::EnforcementMode::Audit,
            min_device_assurance: None,
            require_verified_email: None,
            require_verified_phone: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            post_logout_redirect_uris: req.post_logout_redirect_uris,
            claim_mappings: vec![],
            login_strategy: LoginStrategy::LocalFirst,
            show_federation_button: true,
            federation_timeout_ms: 500,
            unified_input: false,
            // The organization the issuer serves: its registration access
            // token manages it only under this issuer.
            org_id: Some(issuer.recipient_org),
            revision: 0,
            created_at: now,
        };
        // A client that could never authenticate by the method it names is
        // not registered (RFC 7591 §2: `private_key_jwt` needs `jwks`).
        if let Some(problem) = client.credential_problem() {
            return Err(metadata_refusal("token_endpoint_auth_method", problem));
        }

        // One transaction: the token's use is counted under a lock and the
        // client inserted, so concurrent registrations cannot exceed the limit
        // and a failure leaves neither.
        self.storage
            .register_dynamic_client(
                &app,
                &client,
                iat.id,
                // The actor is the holder of the initial access token, not
                // the administrator who created it.
                AuditEntry::machine(
                    format!("iat:{}", iat.id),
                    "dcr.register",
                    client.client_id.clone(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                // Used up, or revoked or expired between the check above and
                // the lock: the token no longer registers clients.
                SidError::InvalidState(_)
                | SidError::Revoked(_)
                | SidError::Expired(_)
                | SidError::NotFound(_) => ProjectError::IatUnusable,
                e => ProjectError::Store(e),
            })?;

        info!("DCR: registered client '{}' via IAT {}", client_id, iat.id);

        Ok(RegisterClientResponse {
            client: Some(self.client_view(&client)?),
            client_secret: client_secret.map(|s| s.expose_secret().clone()),
            registration_access_token: rat.expose_secret().clone(),
        })
    }

    /// The client its registration access token `rat` manages.
    pub async fn get_registered_client(
        &self,
        rat: &str,
        req: GetRegisteredClientRequest,
    ) -> Result<OAuthClient, ProjectError> {
        let client = self
            .verify_rat(rat, &req.client_id, &req.issuer_handle)
            .await?;
        self.client_view(&client)
    }

    /// Replace the metadata of the client its registration access token
    /// `rat` manages (RFC 7592 §2.2).
    pub async fn update_registered_client(
        &self,
        rat: &str,
        req: UpdateRegisteredClientRequest,
    ) -> Result<OAuthClient, ProjectError> {
        let current = self
            .verify_rat(rat, &req.client_id, &req.issuer_handle)
            .await?;
        // RFC 7592 §2.2: a secret sent back must be the issued one.
        if let Some(secret) = &req.client_secret
            && !secret_matches(&current, secret)
        {
            return Err(metadata_refusal(
                "client_secret",
                "client_secret does not match the issued secret",
            ));
        }

        // Subject metadata the request sets is checked first: an incompatible
        // value refuses the whole update (RFC 7592 §2.2), valid edits included.
        let requested_subject = req.subject_type.map(requested_subject_type).transpose()?;
        dcr::check_subject_metadata(
            requested_subject.unwrap_or(model::SubjectType::Public),
            req.sector_identifier_uri.as_deref(),
        )
        .map_err(|e| dcr_refusal(e, RegistrationCheck::Metadata))?;
        if requested_subject.is_some_and(|requested| requested != current.subject_type) {
            return Err(ProjectError::SubjectMigrationRequired(
                current.client_id.clone(),
            ));
        }

        // RFC 7592 §2.2: the request carries the client's whole metadata and
        // a field left out is removed, so every field is replaced; an absent
        // authentication method is the RFC 7591 §2 default.
        let mut client = current.clone();
        client.client_name = req.client_name.unwrap_or_default();
        client.redirect_uris = req.redirect_uris;
        client.grant_types = req.grant_types;
        client.response_types = req.response_types;
        dcr::apply_metadata_defaults(&mut client.grant_types, &mut client.response_types);
        client.token_endpoint_auth_method =
            requested_auth_method(req.token_endpoint_auth_method.unwrap_or_default())?;
        // A client that becomes public keeps no secret it could be asked for.
        if client.is_public() {
            client.client_secret_hash = None;
        }
        client.jwks = requested_jwks(req.jwks.as_deref())?;
        client.contacts = req.contacts;
        client.allowed_scopes = req.scope;
        client.post_logout_redirect_uris = req.post_logout_redirect_uris;

        self.check_client_update(&current, &client).await?;

        let updated = self
            .storage
            .update_oauth2_client(
                &client,
                // The client manages itself with its registration access token.
                AuditEntry::machine(
                    client.client_id.clone(),
                    "dcr.update",
                    client.client_id.clone(),
                )
                .into(),
            )
            .await?;
        if !updated {
            return Err(self.client_update_refused(&client.client_id).await);
        }
        client.revision += 1;

        self.client_view(&client)
    }

    /// Delete the client its registration access token `rat` manages.
    pub async fn delete_registered_client(
        &self,
        rat: &str,
        req: DeleteRegisteredClientRequest,
    ) -> Result<(), ProjectError> {
        let client = self
            .verify_rat(rat, &req.client_id, &req.issuer_handle)
            .await?;

        self.storage
            .delete_oauth2_client(
                &client.client_id,
                // The client manages itself with its registration access token.
                AuditEntry::machine(
                    client.client_id.clone(),
                    "dcr.delete",
                    client.client_id.clone(),
                )
                .into(),
            )
            .await?;

        info!("DCR: deleted client '{}'", client.client_id);
        Ok(())
    }

    // ── Initial Access Token management ──────────────────────────────

    /// Create an initial access token; its value is handed back beside the
    /// recorded response. A retry answers with the token it created, without
    /// its value: SID keeps only its hash, and a retry creates no second
    /// token.
    pub async fn create_initial_access_token(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateInitialAccessTokenRequest,
    ) -> Result<CreateInitialAccessTokenResponse, ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;

        let command = KeyedCommand::by_profile::<keyed::CreateInitialAccessToken>(
            caller.profile_id,
            operation,
            &req,
        );
        let mut issued = None;
        let mut response = command
            .execute(&*self.storage, || async {
                self.storage
                    .get_project(project_id)
                    .await?
                    .ok_or(ProjectError::ProjectNotFound(project_id))?;

                let expires_in = if req.expires_in_seconds > 0 {
                    chrono::Duration::seconds(req.expires_in_seconds)
                } else {
                    chrono::Duration::hours(24) // default 24h
                };
                let token_value = generate_client_secret();
                let token_hash = sha256_hash(token_value.expose_secret().as_bytes());
                let now = chrono::Utc::now();
                let token = InitialAccessToken {
                    id: InitialAccessTokenId::generate(),
                    token_hash,
                    project_id,
                    max_clients: req.max_clients,
                    clients_registered: 0,
                    allowed_scopes: req.allowed_scopes.clone(),
                    allowed_grant_types: req.allowed_grant_types.clone(),
                    allowed_redirect_patterns: req.allowed_redirect_patterns.clone(),
                    expires_at: now + expires_in,
                    created_at: now,
                    created_by: caller.profile_id,
                    revoked: false,
                };
                let recorded = CreateInitialAccessTokenResponse {
                    token: Some(iat_to_proto(&token)),
                    token_value: String::new(),
                };
                let ctx = admin_ctx(caller, "iat.create", token.id.to_string())
                    .with_operation(command.completion(recorded.encode_to_vec()));
                self.storage
                    .create_initial_access_token(&token, ctx)
                    .await?;
                info!(
                    "Created IAT {} for project {} (max_clients: {}, expires: {})",
                    token.id, project_id, token.max_clients, token.expires_at
                );
                issued = Some(token_value);
                Ok(recorded)
            })
            .await?;
        if let Some(value) = issued {
            response.token_value = value.expose_secret().clone();
        }
        Ok(response)
    }

    pub async fn list_initial_access_tokens(
        &self,
        caller: &Caller,
        req: ListInitialAccessTokensRequest,
    ) -> Result<ListInitialAccessTokensResponse, ProjectError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;

        let tokens = self
            .storage
            .list_initial_access_tokens_by_project(project_id)
            .await?;

        Ok(ListInitialAccessTokensResponse {
            tokens: tokens.iter().map(iat_to_proto).collect(),
        })
    }

    pub async fn revoke_initial_access_token(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RevokeInitialAccessTokenRequest,
    ) -> Result<(), ProjectError> {
        Self::admin(caller)?;
        let token_id: InitialAccessTokenId = wire_id(req.id.as_ref(), "id")?;

        // A retry of a completed revocation answers as the revocation did.
        let command = KeyedCommand::by_profile::<keyed::RevokeInitialAccessToken>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                self.storage
                    .get_initial_access_token(token_id)
                    .await?
                    .ok_or(ProjectError::IatNotFound(token_id))?;
                let ctx = admin_ctx(caller, "iat.revoke", token_id.to_string())
                    .with_operation(command.completion(().encode_to_vec()));
                self.storage
                    .revoke_initial_access_token(token_id, ctx)
                    .await?;
                info!("Revoked IAT {}", token_id);
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── The bodies of keyed commands, run once under their keys ─────

    /// Create the application CreateApplication describes, recording it
    /// without its client secret; the secret is returned beside the record.
    async fn new_application(
        &self,
        caller: &Caller,
        command: &KeyedCommand,
        req: CreateApplicationRequest,
    ) -> Result<(CreateApplicationResponse, Option<SecretBox<String>>), Effect<ProjectError>> {
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        self.storage
            .get_project(project_id)
            .await?
            .ok_or(ProjectError::ProjectNotFound(project_id))?;

        // Every application belongs to the installation's organization; a
        // request naming another one names an organization that is not here.
        if let Some(requested) = req.org_id.as_ref() {
            let requested: model::OrgId = wire_id(Some(requested), "org_id")?;
            if requested != self.org {
                return Err(invalid_field(
                    "org_id",
                    format!("organization {requested} is not this installation's"),
                )
                .into());
            }
        }
        if req.name.is_empty() {
            return Err(ProjectError::MissingField("name").into());
        }
        // An application is a client, a protected resource, or both.
        if req.client.is_none() && req.resource.is_none() {
            return Err(ProjectError::RoleRequired.into());
        }

        let now = chrono::Utc::now();
        let app = model::Application {
            id: ApplicationId::generate(),
            project_id,
            name: req.name,
            system: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        };
        let resource = req
            .resource
            .map(|settings| self.new_resource(&app, CREATE_RESOURCE_FIELDS, settings))
            .transpose()?;
        let (client, client_secret) = match req.client {
            Some(settings) => {
                let (client, secret) = self.new_client(&app, settings)?;
                (Some(client), secret)
            }
            None => (None, None),
        };

        let recorded = CreateApplicationResponse {
            application: Some(self.application_with(&app, client.as_ref(), resource.as_ref())?),
            client_secret: String::new(),
        };
        let ctx = admin_ctx(caller, "application.create", app.id.to_string())
            .with_operation(command.completion(recorded.encode_to_vec()));
        self.storage
            .create_application(&app, client.as_ref(), resource.as_ref(), ctx)
            .await
            .map_err(|e| match (e, &resource) {
                // Every other key is freshly generated: the indicator is taken.
                (SidError::Conflict(_), Some(resource)) => {
                    Effect::from(ProjectError::IndicatorTaken(resource.indicator.clone()))
                }
                (e, _) => Effect::from(e),
            })?;

        info!("Created application {} in project {project_id}", app.id);
        Ok((recorded, client_secret))
    }

    /// Apply an UpdateClientRole edit to the revision it read, recording the
    /// application as the edit leaves it.
    async fn edit_client(
        &self,
        caller: &Caller,
        command: &KeyedCommand,
        req: UpdateClientRoleRequest,
    ) -> Result<Application, Effect<ProjectError>> {
        let mut client = self.load_client(&req.client_id).await?;
        // Only the activity of an integration's client is the administrator's.
        let edits_settings = req.default_resource.is_some()
            || req.name.is_some()
            || !req.redirect_uris.is_empty()
            || !req.allowed_scopes.is_empty()
            || !req.grant_types.is_empty()
            || req.subject_type.is_some()
            || req.post_logout_redirect_uris.is_some();
        if edits_settings && self.is_system(client.application_id).await? {
            return Err(ProjectError::SystemManaged {
                application: client.application_id,
                what: "only its client's activity may change",
            }
            .into());
        }

        // A default target is one this client already has access to: a
        // default never grants access by itself.
        if let Some(requested) = &req.default_resource {
            client.default_resource = match &requested.resource_id {
                None => None,
                Some(id) => {
                    let resource = self
                        .load_resource("default_resource.resource_id", Some(id))
                        .await?;
                    let access = self
                        .storage
                        .resource_access(&client.client_id, resource.id)
                        .await?;
                    if access.is_none() {
                        return Err(invalid_field(
                            "default_resource",
                            "the client has no access to this resource",
                        )
                        .into());
                    }
                    Some(resource.id)
                }
            };
        }

        if let Some(name) = req.name {
            client.client_name = name;
        }
        if !req.redirect_uris.is_empty() {
            client.redirect_uris = req.redirect_uris;
        }
        if !req.allowed_scopes.is_empty() {
            client.allowed_scopes = req.allowed_scopes;
        }
        if !req.grant_types.is_empty() {
            client.grant_types = req.grant_types;
        }
        if let Some(active) = req.active {
            client.active = active;
        }
        if let Some(list) = req.post_logout_redirect_uris {
            dcr::validate_post_logout_redirect_uris(&list.uris, client.application_type)
                .map_err(|e| invalid_field("post_logout_redirect_uris", e.to_string()))?;
            client.post_logout_redirect_uris = list.uris;
        }
        // Registration metadata A: only `public` is a supported value, and a
        // settings edit never changes an application's subjects; that is an
        // explicit identity migration (pairwise-binding.md, migration path).
        if let Some(ref requested) = req.subject_type {
            use sid_core::models::oauth2_client::SubjectType;
            if requested != "public" {
                return Err(metadata_refusal(
                    "subject_type",
                    "subject_type is not supported by this issuer. Supported value: 'public'.",
                )
                .into());
            }
            if client.subject_type != SubjectType::Public {
                return Err(
                    ProjectError::SubjectMigrationRequired(client.client_id.clone()).into(),
                );
            }
        }

        // The application as this edit leaves it: the store applies the edit
        // only to the revision it was read at.
        let app = self
            .storage
            .get_application(client.application_id)
            .await?
            .ok_or(ProjectError::ApplicationNotFound(client.application_id))?;
        let mut left = client.clone();
        left.revision += 1;
        let mut view = self.application_view(&app).await?;
        view.client = Some(self.client_view(&left)?);
        let ctx = admin_ctx(caller, "client.update", client.client_id.clone())
            .with_operation(command.completion(view.encode_to_vec()));
        if !self.storage.update_oauth2_client(&client, ctx).await? {
            return Err(self.client_update_refused(&client.client_id).await.into());
        }
        Ok(view)
    }

    /// Apply an UpdateResourceRole edit to the revision it read, recording
    /// the resource as the edit leaves it.
    async fn edit_resource(
        &self,
        caller: &Caller,
        command: &KeyedCommand,
        req: UpdateResourceRoleRequest,
    ) -> Result<v1::ProtectedResource, Effect<ProjectError>> {
        let mut resource = self
            .load_resource("resource_id", req.resource_id.as_ref())
            .await?;
        if resource.state == ResourceState::Retired {
            return Err(ProjectError::ResourceRetired(resource.id).into());
        }
        // An integration's API is deactivated, never reshaped by hand.
        if req.scopes.is_some()
            && let Some(app) = resource.application_id
            && self.is_system(app).await?
        {
            return Err(ProjectError::SystemManaged {
                application: app,
                what: "only its resource's state may change",
            }
            .into());
        }
        if let Some(list) = req.scopes {
            resource.scopes =
                model::scope_list(&list.scopes).map_err(|e| invalid_field("scopes", e))?;
        }
        if let Some(state) = req.state {
            resource.state = match v1::ResourceState::try_from(state) {
                Ok(v1::ResourceState::Active) => ResourceState::Active,
                Ok(v1::ResourceState::Inactive) => ResourceState::Inactive,
                // A resource is retired only by removing its application.
                Ok(v1::ResourceState::Retired) => {
                    return Err(ProjectError::RetireByRemoval(resource.id).into());
                }
                _ => {
                    return Err(invalid_field("state", "state must be ACTIVE or INACTIVE").into());
                }
            };
        }
        resource.updated_at = chrono::Utc::now();
        // The resource as this edit leaves it: the store applies the edit
        // only to the revision it was read at.
        let mut left = resource.clone();
        left.revision += 1;
        let view = self.resource_view(&left)?;
        let ctx = admin_ctx(caller, "resource.update", resource.id.to_string())
            .with_operation(command.completion(view.encode_to_vec()));
        if !self
            .storage
            .update_protected_resource(&resource, ctx)
            .await?
        {
            // Retired or changed since it was read.
            return Err(
                match self.storage.get_protected_resource(resource.id).await {
                    Ok(Some(stored)) if stored.state == ResourceState::Retired => {
                        ProjectError::ResourceRetired(stored.id)
                    }
                    Ok(_) => ProjectError::ChangedConcurrently,
                    Err(e) => ProjectError::Store(e),
                }
                .into(),
            );
        }
        Ok(view)
    }

    /// Set a SetResourceAccess grant, recording the access as it is stored.
    async fn grant_access(
        &self,
        caller: &Caller,
        command: &KeyedCommand,
        req: SetResourceAccessRequest,
    ) -> Result<v1::ResourceAccess, Effect<ProjectError>> {
        if let Some(app) = self.system_client(&req.client_id).await? {
            return Err(ProjectError::SystemManaged {
                application: app,
                what: "its client's access follows the integration",
            }
            .into());
        }
        let served = self.requester_served(&req.client_id).await?;
        let resource = self
            .load_resource("resource_id", req.resource_id.as_ref())
            .await?;
        if resource.state == ResourceState::Retired {
            return Err(ProjectError::ResourceRetired(resource.id).into());
        }
        // Access never bridges issuers: the client's tokens come from the
        // issuer whose tokens the resource accepts.
        if !(served && resource.issuer_id == self.issuer.id) {
            return Err(ProjectError::IssuerMismatch(resource.id).into());
        }
        let scopes = model::scope_list(&req.scopes).map_err(|e| invalid_field("scopes", e))?;
        if let Some(unknown) = scopes.iter().find(|s| !resource.scopes.contains(s)) {
            return Err(invalid_field(
                "scopes",
                format!("{unknown:?} is not a scope of the resource"),
            )
            .into());
        }
        // The stored access keeps its first creation time.
        let first = self
            .storage
            .resource_access(&req.client_id, resource.id)
            .await?
            .map(|existing| existing.created_at);
        let access = model::ResourceAccess {
            client_id: req.client_id.clone(),
            resource_id: resource.id,
            scopes,
            created_at: first.unwrap_or_else(chrono::Utc::now),
        };
        let view = access_to_proto(&access);
        let ctx = admin_ctx(
            caller,
            "resource_access.set",
            format!("{}:{}", access.client_id, access.resource_id),
        )
        .with_operation(command.completion(view.encode_to_vec()));
        self.storage
            .set_resource_access(&access, ctx)
            .await
            .map_err(|e| match e {
                // Retired or gone between the check above and the write.
                SidError::InvalidState(_) => ProjectError::ResourceRetired(resource.id).into(),
                SidError::NotFound(_) => ProjectError::ResourceNotFound(resource.id).into(),
                e => Effect::from(e),
            })?;
        Ok(view)
    }

    /// Validate a client's self-service update (RFC 7592 §2.2) as a new
    /// registration would be: request rules and the constraints of the initial
    /// access token it was registered with. Subject metadata is checked by
    /// the caller on the fields the request sets; the stored subject type and
    /// organization never change here, since either would change every
    /// user's `sub` at the client.
    async fn check_client_update(
        &self,
        current: &OAuth2Client,
        updated: &OAuth2Client,
    ) -> Result<(), ProjectError> {
        if updated.subject_type != current.subject_type
            || updated.sector_identifier_uri != current.sector_identifier_uri
            || updated.org_id != current.org_id
        {
            return Err(ProjectError::SubjectMigrationRequired(
                current.client_id.clone(),
            ));
        }
        if let Some(problem) = updated.credential_problem() {
            return Err(metadata_refusal("token_endpoint_auth_method", problem));
        }

        let request = dcr::ClientRegistrationRequest {
            client_name: updated.client_name.clone(),
            redirect_uris: updated.redirect_uris.clone(),
            grant_types: updated.grant_types.clone(),
            response_types: updated.response_types.clone(),
            token_endpoint_auth_method: updated.token_endpoint_auth_method,
            application_type: updated.application_type,
            subject_type: updated.subject_type,
            sector_identifier_uri: updated.sector_identifier_uri.clone(),
            contacts: updated.contacts.clone(),
            scope: updated.allowed_scopes.clone(),
            post_logout_redirect_uris: updated.post_logout_redirect_uris.clone(),
        };
        dcr::validate_client_metadata(&request)
            .map_err(|e| dcr_refusal(e, RegistrationCheck::Metadata))?;

        let iat_id = updated
            .registration_iat
            .ok_or_else(|| ProjectError::NotRegisteredDynamically(updated.client_id.clone()))?;
        let iat = self
            .storage
            .get_initial_access_token(iat_id)
            .await?
            .ok_or(ProjectError::IatDeleted(iat_id))?;
        dcr::validate_iat_policy(&iat, &request)
            .map_err(|e| dcr_refusal(e, RegistrationCheck::TokenPolicy))
    }

    /// Why an update of `client_id` did not apply: the client was deleted
    /// meanwhile, or it was changed (the caller retries).
    async fn client_update_refused(&self, client_id: &str) -> ProjectError {
        match self.storage.get_oauth2_client(client_id).await {
            Ok(Some(_)) => ProjectError::ChangedConcurrently,
            Ok(None) => ProjectError::ClientGone(client_id.to_owned()),
            Err(e) => ProjectError::Store(e),
        }
    }

    /// The client `rat` manages under the issuer `issuer_handle`. An unknown
    /// client, one without a registration access token (created by an
    /// administrator), one of an organization this issuer does not serve and
    /// a wrong token are refused alike, so the answer does not reveal which
    /// clients exist (RFC 7592 §2.1).
    async fn verify_rat(
        &self,
        rat: &str,
        client_id: &str,
        issuer_handle: &str,
    ) -> Result<OAuth2Client, ProjectError> {
        let issuer = self.registering_issuer(issuer_handle)?;
        if client_id.is_empty() {
            return Err(ProjectError::MissingField("client_id"));
        }

        let client = self
            .storage
            .get_oauth2_client(client_id)
            .await?
            .filter(|client| client.registration_iat.is_some() && issuer.serves(client.org_id));

        let rat_hash = sha256_hash(rat.as_bytes());
        match client {
            Some(client)
                if client
                    .registration_access_token_hash
                    .as_ref()
                    .is_some_and(|stored| {
                        subtle::ConstantTimeEq::ct_eq(stored.as_slice(), rat_hash.as_slice()).into()
                    }) =>
            {
                Ok(client)
            }
            _ => Err(ProjectError::RatInvalid),
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// The audit of `caller`'s administrative `action` on `target`.
fn admin_ctx(caller: &Caller, action: &str, target: String) -> MutationContext {
    AuditEntry::admin(caller.profile_id.to_string(), action, target).into()
}

/// The project a completed CreateProject recorded as its result.
fn decode_result(result: &[u8]) -> Result<v1::Project, ProjectError> {
    v1::Project::decode(result).map_err(|e| {
        warn!("recorded CreateProject result unreadable: {}", e);
        ProjectError::Internal
    })
}

/// The refusal of a registration or self-service update that the dynamic
/// registration rules refused, by the check that refused it.
fn dcr_refusal(error: dcr::DcrError, check: RegistrationCheck) -> ProjectError {
    match error {
        _ if error.metadata_error().is_some() => ProjectError::Registration { error, check },
        dcr::DcrError::IatExpired | dcr::DcrError::IatRevoked => ProjectError::IatEnded,
        other => {
            warn!(error = %other, "registration refused");
            ProjectError::Internal
        }
    }
}

/// The client authentication method a registration asks for. Unset is
/// `client_secret_basic` (RFC 7591 §2: "If unspecified or omitted, the default
/// is client_secret_basic"); a value the issuer does not know is refused, not
/// coerced.
fn requested_auth_method(proto: i32) -> Result<model::TokenEndpointAuthMethod, ProjectError> {
    use model::TokenEndpointAuthMethod as Method;
    use v1::TokenEndpointAuthMethod as Proto;
    match Proto::try_from(proto) {
        Ok(Proto::Unspecified | Proto::ClientSecretBasic) => Ok(Method::ClientSecretBasic),
        Ok(Proto::ClientSecretPost) => Ok(Method::ClientSecretPost),
        Ok(Proto::None) => Ok(Method::None),
        Ok(Proto::PrivateKeyJwt) => Ok(Method::PrivateKeyJwt),
        Err(_) => Err(metadata_refusal(
            "token_endpoint_auth_method",
            "token_endpoint_auth_method is not a known value",
        )),
    }
}

/// The subject type a registration asks for. Unset (proto3 `UNSPECIFIED`) is
/// the documented `public`; a value outside the enum is malformed and refused,
/// never read as the default (authentication-flow.md, registration metadata A).
fn requested_subject_type(proto: i32) -> Result<model::SubjectType, ProjectError> {
    use v1::SubjectType as Proto;
    match Proto::try_from(proto) {
        Ok(Proto::Unspecified | Proto::Public) => Ok(model::SubjectType::Public),
        Ok(Proto::Pairwise) => Ok(model::SubjectType::Pairwise),
        Err(_) => Err(metadata_refusal(
            "subject_type",
            "subject_type is not a known value. Supported value: 'public'.",
        )),
    }
}

/// The key set a registration sends in `jwks` (RFC 7591 §2); left out, none.
fn requested_jwks(jwks: Option<&str>) -> Result<Option<model::ClientKeySet>, ProjectError> {
    jwks.map(|text| model::ClientKeySet::from_json(text).map_err(|e| metadata_refusal("jwks", e)))
        .transpose()
}

fn proto_to_app_type(proto: i32) -> ApplicationType {
    match v1::ApplicationType::try_from(proto) {
        Ok(v1::ApplicationType::Web) => ApplicationType::Web,
        Ok(v1::ApplicationType::Native) => ApplicationType::Native,
        Ok(v1::ApplicationType::Api) => ApplicationType::Api,
        Ok(v1::ApplicationType::Spa) => ApplicationType::Spa,
        _ => ApplicationType::Web, // default
    }
}

fn generate_client_secret() -> SecretBox<String> {
    let mut bytes = [0u8; 32];
    rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut bytes)
        .expect("the operating system random source is available");
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    SecretBox::new(Box::new(hex))
}

/// Whether `secret` is the secret issued to `client`.
fn secret_matches(client: &OAuth2Client, secret: &str) -> bool {
    use argon2::password_hash::PasswordVerifier;
    let Some(hash) = client
        .client_secret_hash
        .as_deref()
        .and_then(|hash| std::str::from_utf8(hash).ok())
    else {
        return false;
    };
    PasswordHash::new(hash).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(secret.as_bytes(), &hash)
            .is_ok()
    })
}

fn hash_secret(secret: &str) -> Result<String, ProjectError> {
    PasswordHasher::<PasswordHash>::hash_password(&Argon2::default(), secret.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| internal("hash client secret", e))
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

#[cfg(test)]
mod tests;
