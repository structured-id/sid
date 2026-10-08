// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC ProjectService implementation.
//!
//! Manages projects, applications (OIDC clients), and project-scoped roles.
//! Mirrors the REST admin handlers using the same storage backend.

use crate::feature_flags::FeatureFlagService;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, phc::PasswordHash},
};
use prost::Message;
use secrecy::{ExposeSecret, SecretBox};
use sid_authn::caller::{Caller, authenticate};
use sid_authn::dcr;
use sid_authn::jwt::JwtService;
use sid_authn::operation::{KeyedCommand, required_key};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::Error as SidError;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{
    self as model, ApplicationId, ApplicationType, AuditEntry, InitialAccessToken,
    InitialAccessTokenId, LoginStrategy, MutationContext, OAuth2Client, Project, ProjectChange,
    ProjectId, ResourceId, ResourceIndicator, ResourceState, Role, RoleId,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

use super::application_view::{
    access_to_proto, application_to_proto, client_to_proto, resource_to_proto,
};
use super::convert;
use sid_core::grpc_error::refuse::{
    changed_concurrently, internal, invalid_field, maintenance, missing_field, not_found,
    storage_failure,
};

pub struct ProjectServiceImpl {
    storage: Arc<dyn StorageBackend>,
    feature_flags: FeatureFlagService,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// The installation's organization: every application registered here
    /// belongs to it.
    org: sid_core::models::OrgId,
    /// That organization's OIDC issuer, the one its applications configure.
    issuer: sid_core::models::OidcIssuer,
}

impl ProjectServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        feature_flags: FeatureFlagService,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        issuer: sid_core::models::OidcIssuer,
    ) -> Self {
        Self {
            storage,
            feature_flags,
            jwt,
            revocation,
            org: issuer.recipient_org,
            issuer,
        }
    }

    /// The exact issuer `client` is registered under. Every application here
    /// belongs to the installation's organization; one that does not has no
    /// issuer to report, which is an internal inconsistency, never an empty
    /// value a relying party would configure.
    #[allow(clippy::result_large_err)]
    fn issuer_of(&self, client: &OAuth2Client) -> Result<&str, Status> {
        if self.issuer.serves(client.org_id) {
            Ok(&self.issuer.canonical_url)
        } else {
            warn!(client_id = %client.client_id, "application outside the installation's organization");
            Err(Status::from(sid_core::grpc_error::ApiError::internal()))
        }
    }

    /// `client` as the API shows it, with its issuer.
    #[allow(clippy::result_large_err)]
    fn client_view(&self, client: &OAuth2Client) -> Result<OAuthClient, Status> {
        Ok(client_to_proto(client, self.issuer_of(client)?))
    }

    /// The exact issuer whose tokens `resource` accepts. Resources here are
    /// registered under the installation organization's issuer; any other is
    /// an internal inconsistency.
    #[allow(clippy::result_large_err)]
    fn resource_issuer(&self, resource: &model::ProtectedResource) -> Result<&str, Status> {
        if resource.issuer_id == self.issuer.id {
            Ok(&self.issuer.canonical_url)
        } else {
            warn!(resource = %resource.id, "resource of another issuer");
            Err(Status::from(ApiError::internal()))
        }
    }

    /// `resource` as the API shows it, with its issuer.
    #[allow(clippy::result_large_err)]
    fn resource_view(
        &self,
        resource: &model::ProtectedResource,
    ) -> Result<sid_proto::sid::v1::ProtectedResource, Status> {
        Ok(resource_to_proto(resource, self.resource_issuer(resource)?))
    }

    /// `app` with the roles given.
    #[allow(clippy::result_large_err)]
    fn application_with(
        &self,
        app: &model::Application,
        client: Option<&OAuth2Client>,
        resource: Option<&model::ProtectedResource>,
    ) -> Result<Application, Status> {
        Ok(application_to_proto(
            app,
            client.map(|c| self.client_view(c)).transpose()?,
            resource.map(|r| self.resource_view(r)).transpose()?,
        ))
    }

    /// `app` with its stored roles.
    async fn application_view(&self, app: &model::Application) -> Result<Application, Status> {
        let client = self
            .storage
            .oauth2_client_of_application(app.id)
            .await
            .map_err(storage_failure)?;
        let resource = self
            .storage
            .protected_resource_of_application(app.id)
            .await
            .map_err(storage_failure)?;
        self.application_with(app, client.as_ref(), resource.as_ref())
    }

    /// The stored application `id` names (field `field`).
    async fn load_application(
        &self,
        field: &'static str,
        id: &str,
    ) -> Result<model::Application, Status> {
        let parsed =
            ApplicationId::parse(id).map_err(|e| invalid_field(field, format!("{field}: {e}")))?;
        self.storage
            .get_application(parsed)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| application_not_found(id))
    }

    /// The stored client `client_id` names.
    async fn load_client(&self, client_id: &str) -> Result<OAuth2Client, Status> {
        if client_id.is_empty() {
            return Err(missing_field("client_id"));
        }
        self.storage
            .get_oauth2_client(client_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorReason::ApplicationNotFound,
                    "no client has this identifier",
                )
                .with_resource("OAuthClient", client_id)
                .into()
            })
    }

    /// Whether this issuer serves the client `client_id` names: an OAuth
    /// client of its organization, or a live machine user, which belongs to
    /// the installation. Neither is NOT_FOUND. An OAuth client is looked up
    /// first, as the token endpoint does.
    async fn requester_served(&self, client_id: &str) -> Result<bool, Status> {
        if client_id.is_empty() {
            return Err(missing_field("client_id"));
        }
        if let Some(client) = self
            .storage
            .get_oauth2_client(client_id)
            .await
            .map_err(storage_failure)?
        {
            return Ok(self.issuer.serves(client.org_id));
        }
        match self
            .storage
            .get_machine_user_by_client_id(client_id)
            .await
            .map_err(storage_failure)?
        {
            Some(machine) if machine.status != model::machine_user::MachineUserStatus::Deleted => {
                Ok(self.issuer.serves(Some(self.org)))
            }
            _ => Err(ApiError::new(
                ErrorReason::ApplicationNotFound,
                "no client or machine user has this identifier",
            )
            .with_resource("OAuthClient", client_id)
            .into()),
        }
    }

    /// Whether application `id` is one of the installation's own integrations.
    async fn is_system(&self, id: ApplicationId) -> Result<bool, Status> {
        Ok(self
            .storage
            .get_application(id)
            .await
            .map_err(storage_failure)?
            .is_some_and(|app| app.system.is_some()))
    }

    /// The integration application whose client `client_id` is, if it is one.
    async fn system_client(&self, client_id: &str) -> Result<Option<ApplicationId>, Status> {
        let Some(client) = self
            .storage
            .get_oauth2_client(client_id)
            .await
            .map_err(storage_failure)?
        else {
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
        id: &str,
    ) -> Result<model::ProtectedResource, Status> {
        let parsed =
            ResourceId::parse(id).map_err(|e| invalid_field(field, format!("{field}: {e}")))?;
        self.storage
            .get_protected_resource(parsed)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorReason::ResourceNotFound,
                    "no protected resource has this identifier",
                )
                .with_resource("ProtectedResource", id)
                .into()
            })
    }

    /// A new client role of `app` from `settings`, with the secret a
    /// confidential client is issued.
    #[allow(clippy::result_large_err)]
    fn new_client(
        &self,
        app: &model::Application,
        settings: ClientRoleSettings,
    ) -> Result<(OAuth2Client, Option<SecretBox<String>>), Status> {
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
    #[allow(clippy::result_large_err)]
    fn new_resource(
        &self,
        app: &model::Application,
        fields: ResourceFields,
        settings: ResourceRoleSettings,
    ) -> Result<model::ProtectedResource, Status> {
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
    async fn resource_conflict(&self, app: ApplicationId, indicator: &ResourceIndicator) -> Status {
        match self.storage.protected_resource_of_application(app).await {
            Ok(Some(_)) => ApiError::new(
                ErrorReason::ApplicationRoleExists,
                "the application already has a resource role",
            )
            .with_resource("Application", app.to_string())
            .into(),
            Ok(None) => indicator_taken(indicator),
            Err(e) => storage_failure(e),
        }
    }

    /// The issuer a registration request names by `handle`. Clients register
    /// only under the installation organization's issuer; any other handle
    /// names no issuer here and never falls back to it.
    #[allow(clippy::result_large_err)]
    fn registering_issuer(&self, handle: &str) -> Result<&sid_core::models::OidcIssuer, Status> {
        if handle == self.issuer.handle.as_str() {
            Ok(&self.issuer)
        } else {
            Err(ApiError::new(
                ErrorReason::OidcIssuerNotFound,
                "no OIDC issuer has this handle",
            )
            .with_resource("OidcIssuer", handle)
            .into())
        }
    }

    /// Authenticate the caller and require the administrator role: projects,
    /// applications (OAuth clients and their secrets), project roles and
    /// registration tokens are instance administration.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }
}

impl ProjectServiceImpl {
    async fn check_maintenance(&self) -> Result<(), Status> {
        if self.feature_flags.is_maintenance_mode().await {
            Err(maintenance())
        } else {
            Ok(())
        }
    }
}

// ── Conversion helpers ──────────────────────────────────────────────

fn project_to_proto(p: &Project) -> sid_proto::sid::v1::Project {
    sid_proto::sid::v1::Project {
        id: p.id.0.to_string(),
        name: p.name.clone(),
        description: p.description.clone(),
        owner_profile_id: p.owner_id.map(|id| id.to_string()).unwrap_or_default(),
        is_system: p.is_system,
        created_at: Some(convert::to_timestamp(p.created_at)),
        updated_at: Some(convert::to_timestamp(p.updated_at)),
    }
}

fn application_not_found(id: &str) -> Status {
    ApiError::new(
        ErrorReason::ApplicationNotFound,
        "no application has this identifier",
    )
    .with_resource("Application", id)
    .into()
}

fn indicator_taken(indicator: &ResourceIndicator) -> Status {
    ApiError::new(
        ErrorReason::ResourceIndicatorTaken,
        "the issuer already has, or had, a protected resource with this indicator",
    )
    .with_resource("ProtectedResource", indicator.as_str())
    .into()
}

fn resource_retired(resource: &model::ProtectedResource) -> Status {
    ApiError::new(
        ErrorReason::ResourceRetired,
        "the protected resource is retired with its application",
    )
    .with_precondition("RESOURCE_STATE", resource.id.to_string(), "retired")
    .into()
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

/// The client authentication method a registration asks for. Unset is
/// `client_secret_basic` (RFC 7591 §2: "If unspecified or omitted, the default
/// is client_secret_basic"); a value the issuer does not know is refused, not
/// coerced.
fn requested_auth_method(proto: i32) -> Result<sid_core::models::TokenEndpointAuthMethod, Status> {
    use sid_core::models::TokenEndpointAuthMethod as Method;
    use sid_proto::sid::v1::TokenEndpointAuthMethod as Proto;
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
#[allow(clippy::result_large_err)]
fn requested_subject_type(proto: i32) -> Result<sid_core::models::SubjectType, Status> {
    use sid_proto::sid::v1::SubjectType as Proto;
    match Proto::try_from(proto) {
        Ok(Proto::Unspecified | Proto::Public) => Ok(sid_core::models::SubjectType::Public),
        Ok(Proto::Pairwise) => Ok(sid_core::models::SubjectType::Pairwise),
        Err(_) => Err(metadata_refusal(
            "subject_type",
            "subject_type is not a known value. Supported value: 'public'.",
        )),
    }
}

/// A refusal of client metadata the issuer does not support: OAuth
/// `invalid_client_metadata` (RFC 7591 §3.2.2) naming the field.
fn metadata_refusal(field: &'static str, message: impl Into<String>) -> Status {
    let message: String = message.into();
    ApiError::new(ErrorReason::InvalidFieldValue, message.clone())
        .with_metadata("field", field)
        .with_metadata("oauthError", "invalid_client_metadata")
        .with_field_violation(field, message)
        .into()
}

/// Refusal of a hand change to one of the installation's own integrations:
/// SID provisions and keeps them, so they are disabled rather than deleted
/// and their settings follow the deployment's configuration.
fn system_managed(app: ApplicationId, what: &'static str) -> Status {
    ApiError::new(
        ErrorReason::SystemManaged,
        format!("the application is managed by SID: {what}"),
    )
    .with_precondition(
        "SYSTEM_MANAGED",
        app.to_string(),
        "disable the integration instead; its settings follow the deployment",
    )
    .into()
}

/// The key set a registration sends in `jwks` (RFC 7591 §2); left out, none.
#[allow(clippy::result_large_err)]
fn requested_jwks(jwks: Option<&str>) -> Result<Option<model::ClientKeySet>, Status> {
    jwks.map(|text| model::ClientKeySet::from_json(text).map_err(|e| metadata_refusal("jwks", e)))
        .transpose()
}

/// The status for a refused registration or client update. A refusal of the
/// requested metadata carries its RFC 7591 §3.2.2 code and field in ErrorInfo
/// (`oauthError`, `field`) under `reason`: malformed or unsupported metadata
/// (`InvalidFieldValue`) or metadata the initial access token does not allow
/// (`InsufficientPermissions`). An expired or revoked initial access token is
/// UNAUTHENTICATED.
fn dcr_refusal(error: dcr::DcrError, reason: ErrorReason) -> Status {
    let Some((oauth_error, field)) = error.metadata_error() else {
        return match error {
            dcr::DcrError::IatExpired | dcr::DcrError::IatRevoked => ApiError::new(
                ErrorReason::TokenInvalid,
                "the initial access token is expired or revoked",
            )
            .into(),
            other => {
                warn!(error = %other, "registration refused");
                ApiError::internal().into()
            }
        };
    };
    let message = error.to_string();
    ApiError::new(reason, message.clone())
        .with_metadata("field", field)
        .with_metadata("oauthError", oauth_error)
        .with_field_violation(field, message)
        .into()
}

fn role_to_proto(r: &Role) -> sid_proto::sid::v1::Role {
    sid_proto::sid::v1::Role {
        id: r.id.0.to_string(),
        project_id: r.project_id.0.to_string(),
        name: r.key.clone(),
        description: r.description.clone(),
        permissions: r.permissions.clone(),
        created_at: Some(convert::to_timestamp(r.created_at)),
        updated_at: Some(convert::to_timestamp(r.updated_at)),
    }
}

/// The canonical method name keyed CreateProject commands are recorded under.
const CREATE_PROJECT: &str = "sid.v1.ProjectService/CreateProject";

/// The project a completed CreateProject recorded as its result.
#[allow(clippy::result_large_err)]
fn decode_result(result: &[u8]) -> Result<sid_proto::sid::v1::Project, Status> {
    sid_proto::sid::v1::Project::decode(result).map_err(|e| {
        warn!("recorded CreateProject result unreadable: {}", e);
        Status::from(sid_core::grpc_error::ApiError::internal())
    })
}

#[allow(clippy::result_large_err)]
fn parse_project_id(id: &str) -> Result<ProjectId, Status> {
    uuid::Uuid::parse_str(id)
        .map(ProjectId)
        .map_err(|_| invalid_field("project_id", "not a project identifier"))
}

/// PROJECT_NOT_FOUND for `id`.
fn project_not_found(id: ProjectId) -> Status {
    not_found(ErrorReason::ProjectNotFound, "Project", id.0.to_string())
}

/// The initial access token is unknown, revoked, expired or used up: it
/// registers no client (RFC 6750 §3.1 `invalid_token` on the HTTP form).
fn iat_unusable() -> Status {
    ApiError::new(
        ErrorReason::TokenInvalid,
        "the initial access token is not valid",
    )
    .into()
}

/// INVALID_STATE: changing a client's subject type changes its users'
/// subjects, which only the explicit identity migration does.
fn subject_migration_required(client_id: &str) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "changing the client's subject type changes its users' subjects \
         and needs the explicit identity migration",
    )
    .with_precondition("SUBJECT_TYPE", client_id, "identity migration required")
    .into()
}

/// INITIAL_ACCESS_TOKEN_NOT_FOUND for `id`.
fn iat_not_found(id: &str) -> Status {
    not_found(
        ErrorReason::InitialAccessTokenNotFound,
        "InitialAccessToken",
        id,
    )
}

/// SYSTEM_MANAGED: SID provisions and keeps the system project.
fn system_project(change: &'static str) -> Status {
    ApiError::new(
        ErrorReason::SystemManaged,
        "the system project is kept by SID and is not changed by hand",
    )
    .with_precondition("SYSTEM_MANAGED", "Project", change)
    .into()
}

fn proto_to_app_type(proto: i32) -> ApplicationType {
    match sid_proto::sid::v1::ApplicationType::try_from(proto) {
        Ok(sid_proto::sid::v1::ApplicationType::Web) => ApplicationType::Web,
        Ok(sid_proto::sid::v1::ApplicationType::Native) => ApplicationType::Native,
        Ok(sid_proto::sid::v1::ApplicationType::Api) => ApplicationType::Api,
        Ok(sid_proto::sid::v1::ApplicationType::Spa) => ApplicationType::Spa,
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

#[allow(clippy::result_large_err)]
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

fn hash_secret(secret: &str) -> Result<String, Status> {
    PasswordHasher::<PasswordHash>::hash_password(&Argon2::default(), secret.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| internal("hash client secret", e))
}

// ── Service implementation ──────────────────────────────────────────

#[tonic::async_trait]
impl ProjectService for ProjectServiceImpl {
    // ── Project CRUD ────────────────────────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "create_project"))]
    #[instrument(skip_all, fields(method = "create_project"))]
    async fn create_project(
        &self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Project>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let key = required_key(request.metadata())?;
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(missing_field("name"));
        }

        // A retry of a completed create returns the project it created.
        let command = KeyedCommand::new(
            format!("profile:{}", caller.profile_id),
            key,
            CREATE_PROJECT,
            req.encode_to_vec(),
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return Ok(Response::new(decode_result(&result)?));
        }

        let owner_id = if req.owner_profile_id.is_empty() {
            None
        } else {
            Some(convert::parse_profile_id(&req.owner_profile_id)?)
        };

        let mut project = Project::new(&req.name, owner_id);
        project.description = req.description;
        let response = project_to_proto(&project);

        let ctx: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "project.create",
            project.id.0.to_string(),
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
                return Ok(Response::new(decode_result(&result)?));
            }
            Err(e) => return Err(storage_failure(e)),
        }

        info!("Created project '{}' ({})", project.name, project.id.0);

        Ok(Response::new(response))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_project"))]
    #[instrument(skip_all, fields(method = "get_project"))]
    async fn get_project(
        &self,
        request: Request<GetProjectRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Project>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.id)?;

        match self.storage.get_project(project_id).await {
            Ok(Some(p)) => Ok(Response::new(project_to_proto(&p))),
            Ok(None) => Err(project_not_found(project_id)),
            Err(e) => Err(storage_failure(e)),
        }
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_projects"))]
    #[instrument(skip_all, fields(method = "list_projects"))]
    async fn list_projects(
        &self,
        request: Request<ListProjectsRequest>,
    ) -> Result<Response<ListProjectsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let limit = if req.page_size > 0 {
            req.page_size as u64
        } else {
            50
        };

        let projects = self
            .storage
            .list_projects(0, limit)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListProjectsResponse {
            projects: projects.iter().map(project_to_proto).collect(),
            next_page_token: String::new(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_project"))]
    #[instrument(skip_all, fields(method = "update_project"))]
    async fn update_project(
        &self,
        request: Request<UpdateProjectRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Project>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.id)?;

        if project_id.is_system() {
            return Err(system_project("update"));
        }

        let change = ProjectChange {
            name: req.name,
            description: req.description,
            updated_at: chrono::Utc::now(),
        };
        // Only the fields given are written: an edit racing a deletion never
        // recreates the project, and two edits of different fields keep both.
        let project = self
            .storage
            .update_project(
                project_id,
                &change,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "project.update",
                    project_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| project_not_found(project_id))?;

        Ok(Response::new(project_to_proto(&project)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_project"))]
    #[instrument(skip_all, fields(method = "delete_project"))]
    async fn delete_project(
        &self,
        request: Request<DeleteProjectRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.id)?;

        if project_id.is_system() {
            return Err(system_project("delete"));
        }

        // Verify project exists
        self.storage
            .get_project(project_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| project_not_found(project_id))?;

        self.storage
            .delete_project(
                project_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "project.delete",
                    project_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Deleted project {}", project_id.0);

        Ok(Response::new(()))
    }

    // ── Application CRUD ────────────────────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "create_application"))]
    #[instrument(skip_all, fields(method = "create_application"))]
    async fn create_application(
        &self,
        request: Request<CreateApplicationRequest>,
    ) -> Result<Response<CreateApplicationResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let project_id = parse_project_id(&req.project_id)?;

        // Verify project exists
        self.storage
            .get_project(project_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| project_not_found(project_id))?;

        // Every application belongs to the installation's organization; a
        // request naming another one names an organization that is not here.
        if let Some(requested) = req.org_id.as_deref().filter(|o| !o.is_empty())
            && model::OrgId::parse(requested).ok() != Some(self.org)
        {
            return Err(invalid_field(
                "org_id",
                format!("organization {requested} is not this installation's"),
            ));
        }
        if req.name.is_empty() {
            return Err(missing_field("name"));
        }
        // An application is a client, a protected resource, or both.
        if req.client.is_none() && req.resource.is_none() {
            return Err(ApiError::new(
                ErrorReason::RequiredFieldMissing,
                "an application needs a client role, a resource role, or both",
            )
            .with_field_violation("client", "required without resource")
            .with_field_violation("resource", "required without client")
            .into());
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

        self.storage
            .create_application(
                &app,
                client.as_ref(),
                resource.as_ref(),
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "application.create",
                    app.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(|e| match (e, &resource) {
                // Every other key is freshly generated: the indicator is taken.
                (SidError::Conflict(_), Some(resource)) => indicator_taken(&resource.indicator),
                (e, _) => storage_failure(e),
            })?;

        info!("Created application {} in project {}", app.id, project_id.0);

        Ok(Response::new(CreateApplicationResponse {
            application: Some(self.application_with(&app, client.as_ref(), resource.as_ref())?),
            client_secret: client_secret
                .map(|secret| secret.expose_secret().clone())
                .unwrap_or_default(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_application"))]
    #[instrument(skip_all, fields(method = "get_application"))]
    async fn get_application(
        &self,
        request: Request<GetApplicationRequest>,
    ) -> Result<Response<Application>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let app = self.load_application("id", &req.id).await?;
        Ok(Response::new(self.application_view(&app).await?))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_applications"))]
    #[instrument(skip_all, fields(method = "list_applications"))]
    async fn list_applications(
        &self,
        request: Request<ListApplicationsRequest>,
    ) -> Result<Response<ListApplicationsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;
        let limit = if req.page_size > 0 {
            req.page_size as u64
        } else {
            50
        };

        let apps = self
            .storage
            .list_applications_by_project(project_id, 0, limit)
            .await
            .map_err(storage_failure)?;

        let mut applications = Vec::with_capacity(apps.len());
        for app in &apps {
            applications.push(self.application_view(app).await?);
        }
        Ok(Response::new(ListApplicationsResponse {
            applications,
            next_page_token: String::new(),
        }))
    }

    #[instrument(skip_all, fields(method = "update_application"))]
    async fn update_application(
        &self,
        request: Request<UpdateApplicationRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let mut app = self.load_application("id", &req.id).await?;
        if let Some(name) = req.name {
            if name.is_empty() {
                return Err(missing_field("name"));
            }
            app.name = name;
        }
        app.updated_at = chrono::Utc::now();
        let updated = self
            .storage
            .update_application(
                &app,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "application.update",
                    app.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            // Deleted meanwhile, or changed since it was read.
            return Err(match self.storage.get_application(app.id).await {
                Ok(None) => application_not_found(&req.id),
                Ok(Some(_)) => changed_concurrently(),
                Err(e) => storage_failure(e),
            });
        }
        app.revision += 1;
        Ok(Response::new(self.application_view(&app).await?))
    }

    #[instrument(skip_all, fields(method = "update_client_role"))]
    async fn update_client_role(
        &self,
        request: Request<UpdateClientRoleRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let mut client = self.load_client(&req.client_id).await?;
        // Only the activity of an integration's client is the administrator's.
        let edits_settings = req.default_resource_id.is_some()
            || req.name.is_some()
            || !req.redirect_uris.is_empty()
            || !req.allowed_scopes.is_empty()
            || !req.grant_types.is_empty()
            || req.subject_type.is_some()
            || req.post_logout_redirect_uris.is_some();
        if edits_settings && self.is_system(client.application_id).await? {
            return Err(system_managed(
                client.application_id,
                "only its client's activity may change",
            ));
        }

        // A default target is one this client already has access to: a
        // default never grants access by itself.
        if let Some(requested) = req.default_resource_id.as_deref() {
            client.default_resource = if requested.is_empty() {
                None
            } else {
                let resource = self.load_resource("default_resource_id", requested).await?;
                let access = self
                    .storage
                    .resource_access(&client.client_id, resource.id)
                    .await
                    .map_err(storage_failure)?;
                if access.is_none() {
                    return Err(invalid_field(
                        "default_resource_id",
                        "the client has no access to this resource",
                    ));
                }
                Some(resource.id)
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
                ));
            }
            if client.subject_type != SubjectType::Public {
                return Err(subject_migration_required(&client.client_id));
            }
        }

        let updated = self
            .storage
            .update_oauth2_client(
                &client,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "client.update",
                    client.client_id.clone(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            return Err(self.client_update_refused(&client.client_id).await);
        }
        let app = self
            .storage
            .get_application(client.application_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| application_not_found(&client.application_id.to_string()))?;
        Ok(Response::new(self.application_view(&app).await?))
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_application"))]
    #[instrument(skip_all, fields(method = "delete_application"))]
    async fn delete_application(
        &self,
        request: Request<DeleteApplicationRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let id =
            ApplicationId::parse(&req.id).map_err(|e| invalid_field("id", format!("id: {e}")))?;
        // Deleting it would only bring it back, with new identifiers, at the
        // next start; an integration is disabled instead.
        if self
            .storage
            .get_application(id)
            .await
            .map_err(storage_failure)?
            .is_some_and(|app| app.system.is_some())
        {
            return Err(system_managed(id, "it cannot be deleted"));
        }
        let deleted = self
            .storage
            .delete_application(
                id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "application.delete",
                    id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !deleted {
            return Err(application_not_found(&req.id));
        }

        info!("Deleted application {}", id);

        Ok(Response::new(()))
    }

    #[instrument(skip_all, fields(method = "add_client_role"))]
    async fn add_client_role(
        &self,
        request: Request<AddClientRoleRequest>,
    ) -> Result<Response<CreateApplicationResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let app = self
            .load_application("application_id", &req.application_id)
            .await?;
        let settings = req.settings.ok_or_else(|| missing_field("settings"))?;
        let (client, client_secret) = self.new_client(&app, settings)?;
        self.storage
            .create_oauth2_client(
                &client,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "client.create",
                    client.client_id.clone(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                // The client id is freshly generated: the role is taken.
                SidError::Conflict(_) => Status::from(
                    ApiError::new(
                        ErrorReason::ApplicationRoleExists,
                        "the application already has a client role",
                    )
                    .with_resource("Application", app.id.to_string()),
                ),
                e => storage_failure(e),
            })?;

        info!(
            "Added client role {} to application {}",
            client.client_id, app.id
        );
        Ok(Response::new(CreateApplicationResponse {
            application: Some(self.application_view(&app).await?),
            client_secret: client_secret
                .map(|secret| secret.expose_secret().clone())
                .unwrap_or_default(),
        }))
    }

    #[instrument(skip_all, fields(method = "add_resource_role"))]
    async fn add_resource_role(
        &self,
        request: Request<AddResourceRoleRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let app = self
            .load_application("application_id", &req.application_id)
            .await?;
        let settings = req.settings.ok_or_else(|| missing_field("settings"))?;
        let resource = self.new_resource(&app, ADD_RESOURCE_FIELDS, settings)?;
        if let Err(e) = self
            .storage
            .create_protected_resource(
                &resource,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "resource.create",
                    resource.id.to_string(),
                )
                .into(),
            )
            .await
        {
            return Err(match e {
                SidError::Conflict(_) => self.resource_conflict(app.id, &resource.indicator).await,
                e => storage_failure(e),
            });
        }

        info!(
            "Added resource role {} ({}) to application {}",
            resource.id, resource.indicator, app.id
        );
        Ok(Response::new(self.application_view(&app).await?))
    }

    #[instrument(skip_all, fields(method = "update_resource_role"))]
    async fn update_resource_role(
        &self,
        request: Request<UpdateResourceRoleRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProtectedResource>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let mut resource = self.load_resource("resource_id", &req.resource_id).await?;
        if resource.state == ResourceState::Retired {
            return Err(resource_retired(&resource));
        }
        // An integration's API is deactivated, never reshaped by hand.
        if req.scopes.is_some()
            && let Some(app) = resource.application_id
            && self.is_system(app).await?
        {
            return Err(system_managed(app, "only its resource's state may change"));
        }
        if let Some(list) = req.scopes {
            resource.scopes =
                model::scope_list(&list.scopes).map_err(|e| invalid_field("scopes", e))?;
        }
        if let Some(state) = req.state {
            resource.state = match sid_proto::sid::v1::ResourceState::try_from(state) {
                Ok(sid_proto::sid::v1::ResourceState::Active) => ResourceState::Active,
                Ok(sid_proto::sid::v1::ResourceState::Inactive) => ResourceState::Inactive,
                // A resource is retired only by removing its application.
                Ok(sid_proto::sid::v1::ResourceState::Retired) => {
                    return Err(ApiError::new(
                        ErrorReason::ResourceRetired,
                        "a resource is retired only by removing its application",
                    )
                    .with_precondition(
                        "APPLICATION_REMOVED",
                        resource.id.to_string(),
                        "remove the application to retire its resource",
                    )
                    .into());
                }
                _ => return Err(invalid_field("state", "state must be ACTIVE or INACTIVE")),
            };
        }
        resource.updated_at = chrono::Utc::now();
        let updated = self
            .storage
            .update_protected_resource(
                &resource,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "resource.update",
                    resource.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            // Retired or changed since it was read.
            return Err(
                match self.storage.get_protected_resource(resource.id).await {
                    Ok(Some(stored)) if stored.state == ResourceState::Retired => {
                        resource_retired(&stored)
                    }
                    Ok(_) => changed_concurrently(),
                    Err(e) => storage_failure(e),
                },
            );
        }
        resource.revision += 1;
        Ok(Response::new(self.resource_view(&resource)?))
    }

    #[instrument(skip_all, fields(method = "set_resource_access"))]
    async fn set_resource_access(
        &self,
        request: Request<SetResourceAccessRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ResourceAccess>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        if let Some(app) = self.system_client(&req.client_id).await? {
            return Err(system_managed(
                app,
                "its client's access follows the integration",
            ));
        }
        let served = self.requester_served(&req.client_id).await?;
        let resource = self.load_resource("resource_id", &req.resource_id).await?;
        if resource.state == ResourceState::Retired {
            return Err(resource_retired(&resource));
        }
        // Access never bridges issuers: the client's tokens come from the
        // issuer whose tokens the resource accepts.
        if !(served && resource.issuer_id == self.issuer.id) {
            return Err(ApiError::new(
                ErrorReason::IssuerMismatch,
                "the client and the resource belong to different issuers",
            )
            .with_precondition(
                "SAME_ISSUER",
                resource.id.to_string(),
                "grant access only within one issuer",
            )
            .into());
        }
        let scopes = model::scope_list(&req.scopes).map_err(|e| invalid_field("scopes", e))?;
        if let Some(unknown) = scopes.iter().find(|s| !resource.scopes.contains(s)) {
            return Err(invalid_field(
                "scopes",
                format!("{unknown:?} is not a scope of the resource"),
            ));
        }
        let access = model::ResourceAccess {
            client_id: req.client_id.clone(),
            resource_id: resource.id,
            scopes,
            created_at: chrono::Utc::now(),
        };
        self.storage
            .set_resource_access(
                &access,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "resource_access.set",
                    format!("{}:{}", access.client_id, access.resource_id),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                // Retired or gone between the check above and the write.
                SidError::InvalidState(_) => resource_retired(&resource),
                SidError::NotFound(_) => ApiError::new(
                    ErrorReason::ResourceNotFound,
                    "no protected resource has this identifier",
                )
                .with_resource("ProtectedResource", req.resource_id.clone())
                .into(),
                e => storage_failure(e),
            })?;
        // The stored access keeps its first creation time.
        let stored = self
            .storage
            .resource_access(&access.client_id, access.resource_id)
            .await
            .map_err(storage_failure)?
            .unwrap_or(access);
        Ok(Response::new(access_to_proto(&stored)))
    }

    #[instrument(skip_all, fields(method = "remove_resource_access"))]
    async fn remove_resource_access(
        &self,
        request: Request<RemoveResourceAccessRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        if req.client_id.is_empty() {
            return Err(missing_field("client_id"));
        }
        let resource = ResourceId::parse(&req.resource_id)
            .map_err(|e| invalid_field("resource_id", format!("resource_id: {e}")))?;
        if let Some(app) = self.system_client(&req.client_id).await? {
            return Err(system_managed(
                app,
                "its client's access follows the integration",
            ));
        }
        // Removing access the client does not have leaves the state asked for.
        self.storage
            .remove_resource_access(
                &req.client_id,
                resource,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "resource_access.remove",
                    format!("{}:{}", req.client_id, resource),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        Ok(Response::new(()))
    }

    #[instrument(skip_all, fields(method = "list_resource_access"))]
    async fn list_resource_access(
        &self,
        request: Request<ListResourceAccessRequest>,
    ) -> Result<Response<ListResourceAccessResponse>, Status> {
        use sid_proto::sid::v1::list_resource_access_request::Subject;
        self.admin(&request).await?;
        let req = request.into_inner();
        let access = match req.subject {
            Some(Subject::ClientId(client_id)) if !client_id.is_empty() => self
                .storage
                .list_resource_access_by_client(&client_id)
                .await
                .map_err(storage_failure)?,
            Some(Subject::ResourceId(id)) => {
                let resource = ResourceId::parse(&id)
                    .map_err(|e| invalid_field("resource_id", format!("resource_id: {e}")))?;
                self.storage
                    .list_resource_access_by_resource(resource)
                    .await
                    .map_err(storage_failure)?
            }
            _ => {
                return Err(ApiError::new(
                    ErrorReason::RequiredFieldMissing,
                    "name a client or a resource",
                )
                .with_field_violation("client_id", "required without resource_id")
                .with_field_violation("resource_id", "required without client_id")
                .into());
            }
        };
        Ok(Response::new(ListResourceAccessResponse {
            access: access.iter().map(access_to_proto).collect(),
        }))
    }

    // ── Role management ─────────────────────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "add_role"))]
    #[instrument(skip_all, fields(method = "add_role"))]
    async fn add_role(
        &self,
        request: Request<AddRoleRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Role>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let project_id = parse_project_id(&req.project_id)?;

        if req.key.is_empty() {
            return Err(missing_field("key"));
        }
        if req.display_name.is_empty() {
            return Err(missing_field("display_name"));
        }

        // Verify project exists
        self.storage
            .get_project(project_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| project_not_found(project_id))?;

        let mut role = Role::new(project_id, &req.key, &req.display_name);
        role.description = req.description;
        role.group = req.group;
        role.permissions = req.permissions;

        // The store rejects a second role with this key or display name.
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
                sid_core::Error::Conflict(_) => Status::from(
                    ApiError::new(
                        ErrorReason::RoleAlreadyExists,
                        "the project already has a role with this key or display name",
                    )
                    .with_resource("Role", req.key.clone()),
                ),
                other => storage_failure(other),
            })?;

        info!("Added role '{}' to project {}", role.key, project_id.0);

        Ok(Response::new(role_to_proto(&role)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "remove_role"))]
    #[instrument(skip_all, fields(method = "remove_role"))]
    async fn remove_role(
        &self,
        request: Request<RemoveRoleRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let role_id = uuid::Uuid::parse_str(&req.role_id)
            .map(RoleId)
            .map_err(|_| invalid_field("role_id", "not a role identifier"))?;
        let role_not_found = || not_found(ErrorReason::RoleNotFound, "Role", req.role_id.clone());

        // Verify role exists and belongs to the specified project
        let role = self
            .storage
            .get_role(role_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(role_not_found)?;

        if !req.project_id.is_empty() {
            let project_id = parse_project_id(&req.project_id)?;
            if role.project_id != project_id {
                return Err(role_not_found());
            }
        }

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

        info!(
            "Removed role {} from project {}",
            role_id.0, role.project_id.0
        );

        Ok(Response::new(()))
    }

    // ── Dynamic Client Registration (RFC 7591) ──────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "register_client"))]
    #[instrument(skip_all, fields(method = "register_client"))]
    async fn register_client(
        &self,
        request: Request<RegisterClientRequest>,
    ) -> Result<Response<RegisterClientResponse>, Status> {
        self.check_maintenance().await?;
        let issuer = self
            .registering_issuer(&request.get_ref().issuer_handle)?
            .clone();

        // Extract IAT from authorization header
        let iat_token = extract_bearer(&request)?;
        let iat_hash = sha256_hash(iat_token.as_bytes());

        let iat = self
            .storage
            .get_initial_access_token_by_hash(&iat_hash)
            .await
            .map_err(storage_failure)?
            .ok_or_else(iat_unusable)?;

        let mut req = request.into_inner();
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
            .map_err(|e| dcr_refusal(e, ErrorReason::InvalidFieldValue))?;

        // Validate IAT constraints
        dcr::validate_iat_constraints(&iat, &dcr_req)
            .map_err(|e| dcr_refusal(e, ErrorReason::InsufficientPermissions))?;

        // The whole UUIDv7: its random part is what makes the identifier unique.
        let client_id = format!("dyn_{}", uuid::Uuid::now_v7().simple());
        let needs_secret = matches!(
            dcr_req.token_endpoint_auth_method,
            sid_core::models::TokenEndpointAuthMethod::ClientSecretPost
                | sid_core::models::TokenEndpointAuthMethod::ClientSecretBasic
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
        let policy = sid_core::models::RegistrationPolicy::default(); // CE default.
        let client_active = match policy {
            sid_core::models::RegistrationPolicy::AdminApproval => false,
            sid_core::models::RegistrationPolicy::Authenticated => true,
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
            enforcement_mode: sid_core::models::EnforcementMode::Audit,
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
                    format!("iat:{}", iat.id.0),
                    "dcr.register",
                    client.client_id.clone(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                // Used up, or revoked or expired between the check above and
                // the lock: the token no longer registers clients.
                sid_core::Error::InvalidState(_)
                | sid_core::Error::Revoked(_)
                | sid_core::Error::Expired(_)
                | sid_core::Error::NotFound(_) => iat_unusable(),
                e => storage_failure(e),
            })?;

        info!(
            "DCR: registered client '{}' via IAT {}",
            client_id, iat.id.0
        );

        Ok(Response::new(RegisterClientResponse {
            client: Some(self.client_view(&client)?),
            client_secret: client_secret.map(|s| s.expose_secret().clone()),
            registration_access_token: rat.expose_secret().clone(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_registered_client"))]
    #[instrument(skip_all, fields(method = "get_registered_client"))]
    async fn get_registered_client(
        &self,
        request: Request<GetRegisteredClientRequest>,
    ) -> Result<Response<OAuthClient>, Status> {
        let rat = extract_bearer(&request)?;
        let req = request.into_inner();

        let client = self
            .verify_rat(&rat, &req.client_id, &req.issuer_handle)
            .await?;

        Ok(Response::new(self.client_view(&client)?))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_registered_client"))]
    #[instrument(skip_all, fields(method = "update_registered_client"))]
    async fn update_registered_client(
        &self,
        request: Request<UpdateRegisteredClientRequest>,
    ) -> Result<Response<OAuthClient>, Status> {
        self.check_maintenance().await?;
        let rat = extract_bearer(&request)?;
        let req = request.into_inner();

        let current = self
            .verify_rat(&rat, &req.client_id, &req.issuer_handle)
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
            requested_subject.unwrap_or(sid_core::models::SubjectType::Public),
            req.sector_identifier_uri.as_deref(),
        )
        .map_err(|e| dcr_refusal(e, ErrorReason::InvalidFieldValue))?;
        if requested_subject.is_some_and(|requested| requested != current.subject_type) {
            return Err(subject_migration_required(&current.client_id));
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
            .await
            .map_err(storage_failure)?;
        if !updated {
            return Err(self.client_update_refused(&client.client_id).await);
        }
        client.revision += 1;

        Ok(Response::new(self.client_view(&client)?))
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_registered_client"))]
    #[instrument(skip_all, fields(method = "delete_registered_client"))]
    async fn delete_registered_client(
        &self,
        request: Request<DeleteRegisteredClientRequest>,
    ) -> Result<Response<()>, Status> {
        self.check_maintenance().await?;
        let rat = extract_bearer(&request)?;
        let req = request.into_inner();

        let client = self
            .verify_rat(&rat, &req.client_id, &req.issuer_handle)
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
            .await
            .map_err(storage_failure)?;

        info!("DCR: deleted client '{}'", client.client_id);

        Ok(Response::new(()))
    }

    // ── Initial Access Token management ──────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "create_initial_access_token"))]
    #[instrument(skip_all, fields(method = "create_initial_access_token"))]
    async fn create_initial_access_token(
        &self,
        request: Request<CreateInitialAccessTokenRequest>,
    ) -> Result<Response<CreateInitialAccessTokenResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let project_id = parse_project_id(&req.project_id)?;

        // Verify project exists
        self.storage
            .get_project(project_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| project_not_found(project_id))?;

        let expires_in = if req.expires_in_seconds > 0 {
            chrono::Duration::seconds(req.expires_in_seconds)
        } else {
            chrono::Duration::hours(24) // default 24h
        };

        // Generate token value
        let token_value = generate_client_secret();
        let token_hash = sha256_hash(token_value.expose_secret().as_bytes());
        let now = chrono::Utc::now();

        let token = InitialAccessToken {
            id: InitialAccessTokenId::new(),
            token_hash,
            project_id,
            max_clients: req.max_clients,
            clients_registered: 0,
            allowed_scopes: req.allowed_scopes,
            allowed_grant_types: req.allowed_grant_types,
            allowed_redirect_patterns: req.allowed_redirect_patterns,
            expires_at: now + expires_in,
            created_at: now,
            created_by: caller.profile_id.to_string(),
            revoked: false,
        };

        self.storage
            .create_initial_access_token(
                &token,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "iat.create",
                    token.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(
            "Created IAT {} for project {} (max_clients: {}, expires: {})",
            token.id.0, project_id.0, token.max_clients, token.expires_at
        );

        Ok(Response::new(CreateInitialAccessTokenResponse {
            token: Some(iat_to_proto(&token)),
            token_value: token_value.expose_secret().clone(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_initial_access_tokens"))]
    #[instrument(skip_all, fields(method = "list_initial_access_tokens"))]
    async fn list_initial_access_tokens(
        &self,
        request: Request<ListInitialAccessTokensRequest>,
    ) -> Result<Response<ListInitialAccessTokensResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        let tokens = self
            .storage
            .list_initial_access_tokens_by_project(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListInitialAccessTokensResponse {
            tokens: tokens.iter().map(iat_to_proto).collect(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_initial_access_token"))]
    #[instrument(skip_all, fields(method = "revoke_initial_access_token"))]
    async fn revoke_initial_access_token(
        &self,
        request: Request<RevokeInitialAccessTokenRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        self.check_maintenance().await?;
        let req = request.into_inner();

        let token_id = uuid::Uuid::parse_str(&req.id)
            .map(InitialAccessTokenId)
            .map_err(|_| invalid_field("id", "not an initial access token identifier"))?;

        // Verify token exists
        self.storage
            .get_initial_access_token(token_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| iat_not_found(&req.id))?;

        self.storage
            .revoke_initial_access_token(
                token_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "iat.revoke",
                    token_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Revoked IAT {}", token_id.0);

        Ok(Response::new(()))
    }
}

// ── Helper functions ──────────────────────────────────────────────────

/// The Registration Access Token (RFC 7592 §3) sent as a bearer credential.
#[allow(clippy::result_large_err)]
fn extract_bearer<T>(request: &Request<T>) -> Result<String, Status> {
    sid_authn::caller::bearer_token(request).map(str::to_string)
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

fn iat_to_proto(t: &InitialAccessToken) -> sid_proto::sid::v1::InitialAccessToken {
    sid_proto::sid::v1::InitialAccessToken {
        id: t.id.0.to_string(),
        project_id: t.project_id.0.to_string(),
        max_clients: t.max_clients,
        clients_registered: t.clients_registered,
        allowed_scopes: t.allowed_scopes.clone(),
        allowed_grant_types: t.allowed_grant_types.clone(),
        allowed_redirect_patterns: t.allowed_redirect_patterns.clone(),
        expires_at: Some(convert::to_timestamp(t.expires_at)),
        created_at: Some(convert::to_timestamp(t.created_at)),
        created_by: t.created_by.clone(),
        revoked: t.revoked,
    }
}

impl ProjectServiceImpl {
    /// Validate a client's self-service update (RFC 7592 §2.2) as a new
    /// registration would be: request rules and the constraints of the initial
    /// access token it was registered with. Subject metadata is checked by
    /// the caller on the fields the request sets; the stored subject type and
    /// organization never change here, since either would change every
    /// user's `sub` at the client.
    #[allow(clippy::result_large_err)]
    async fn check_client_update(
        &self,
        current: &OAuth2Client,
        updated: &OAuth2Client,
    ) -> Result<(), Status> {
        if updated.subject_type != current.subject_type
            || updated.sector_identifier_uri != current.sector_identifier_uri
            || updated.org_id != current.org_id
        {
            return Err(subject_migration_required(&current.client_id));
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
            .map_err(|e| dcr_refusal(e, ErrorReason::InvalidFieldValue))?;

        let iat_id = updated.registration_iat.ok_or_else(|| {
            Status::from(
                ApiError::new(
                    ErrorReason::InvalidState,
                    "the client was not dynamically registered",
                )
                .with_precondition(
                    "REGISTRATION",
                    updated.client_id.clone(),
                    "not registered dynamically",
                ),
            )
        })?;
        let iat = self
            .storage
            .get_initial_access_token(iat_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                Status::from(
                    ApiError::new(
                        ErrorReason::InvalidState,
                        "the client's initial access token no longer exists",
                    )
                    .with_precondition(
                        "INITIAL_ACCESS_TOKEN",
                        iat_id.0.to_string(),
                        "deleted",
                    ),
                )
            })?;
        dcr::validate_iat_policy(&iat, &request)
            .map_err(|e| dcr_refusal(e, ErrorReason::InsufficientPermissions))
    }

    /// Why an update of `client_id` did not apply: NotFound when the client
    /// was deleted meanwhile, Aborted when it was changed (the caller retries).
    async fn client_update_refused(&self, client_id: &str) -> Status {
        match self.storage.get_oauth2_client(client_id).await {
            Ok(Some(_)) => changed_concurrently(),
            Ok(None) => not_found(ErrorReason::ApplicationNotFound, "OAuthClient", client_id),
            Err(e) => storage_failure(e),
        }
    }

    /// Verify Registration Access Token and return the associated client.
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
    ) -> Result<OAuth2Client, Status> {
        let issuer = self.registering_issuer(issuer_handle)?;
        if client_id.is_empty() {
            return Err(missing_field("client_id"));
        }

        let client = self
            .storage
            .get_oauth2_client(client_id)
            .await
            .map_err(storage_failure)?
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
            _ => Err(ApiError::new(
                ErrorReason::TokenInvalid,
                "the registration access token is not valid",
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod tests;
