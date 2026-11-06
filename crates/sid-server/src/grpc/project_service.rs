// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC ProjectService: the transport of [`sid::projects`], which owns
//! projects, applications (OIDC clients and protected resources), resource
//! access, project roles, initial access tokens and dynamic client
//! registration. Each call is authenticated here, refused while the
//! installation is in maintenance where it changes state, and answered with
//! the status the operation's refusal names.

use crate::feature_flags::FeatureFlagService;
use secrecy::ExposeSecret;
use sid::projects::{Issued, ProjectError, Projects, RegistrationCheck};
use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::operation::grpc::context;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{
    changed_concurrently, invalid_field, maintenance, missing_field, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct ProjectServiceImpl {
    projects: Projects,
    feature_flags: FeatureFlagService,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
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
            projects: Projects::new(storage, issuer),
            feature_flags,
            jwt,
            revocation,
        }
    }

    /// The authenticated administrator making the call. Checked here, before
    /// the maintenance switch and the operation context, so a caller without
    /// the right learns that first; each operation checks it again for every
    /// other entry point.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    async fn check_maintenance(&self) -> Result<(), Status> {
        if self.feature_flags.is_maintenance_mode().await {
            Err(maintenance())
        } else {
            Ok(())
        }
    }
}

/// The Registration Access Token (RFC 7592 §3) or initial access token sent
/// as a bearer credential.
#[allow(clippy::result_large_err)]
fn bearer<T>(request: &Request<T>) -> Result<String, Status> {
    sid_authn::caller::bearer_token(request).map(str::to_string)
}

/// A refusal of client metadata the issuer does not support: OAuth
/// `invalid_client_metadata` (RFC 7591 §3.2.2) naming the field.
fn metadata_refusal(field: &'static str, message: String) -> Status {
    ApiError::new(ErrorReason::InvalidFieldValue, message.clone())
        .with_metadata("field", field)
        .with_metadata("oauthError", "invalid_client_metadata")
        .with_field_violation(field, message)
        .into()
}

/// The status of a project operation's refusal. A refusal of requested
/// client metadata carries its RFC 7591 §3.2.2 code and field in ErrorInfo
/// (`oauthError`, `field`) under its reason: malformed or unsupported
/// metadata (`InvalidFieldValue`) or metadata the initial access token does
/// not allow (`InsufficientPermissions`). An expired or revoked initial
/// access token is UNAUTHENTICATED.
fn refusal(e: ProjectError) -> Status {
    match e {
        ProjectError::Caller(e) => e.into(),
        ProjectError::Operation(e) => e.into(),
        ProjectError::Store(e) => storage_failure(e),
        ProjectError::Internal => ApiError::internal().into(),
        ProjectError::MissingField(field) => missing_field(field),
        ProjectError::InvalidField { field, reason } => invalid_field(field, reason),
        ProjectError::Metadata { field, message } => metadata_refusal(field, message),
        ProjectError::Registration { error, check } => {
            let reason = match check {
                RegistrationCheck::Metadata => ErrorReason::InvalidFieldValue,
                RegistrationCheck::TokenPolicy => ErrorReason::InsufficientPermissions,
            };
            // A registration refusal is built only from an error that names
            // its metadata.
            let Some((oauth_error, field)) = error.metadata_error() else {
                return ApiError::internal().into();
            };
            let message = error.to_string();
            ApiError::new(reason, message.clone())
                .with_metadata("field", field)
                .with_metadata("oauthError", oauth_error)
                .with_field_violation(field, message)
                .into()
        }
        ProjectError::ProjectNotFound(id) => {
            not_found(ErrorReason::ProjectNotFound, "Project", id.to_string())
        }
        ProjectError::ApplicationNotFound(id) => ApiError::new(
            ErrorReason::ApplicationNotFound,
            "no application has this identifier",
        )
        .with_resource("Application", id.to_string())
        .into(),
        ProjectError::ClientNotFound(client_id) => ApiError::new(
            ErrorReason::ApplicationNotFound,
            "no client has this identifier",
        )
        .with_resource("OAuthClient", client_id)
        .into(),
        ProjectError::ClientGone(client_id) => {
            not_found(ErrorReason::ApplicationNotFound, "OAuthClient", client_id)
        }
        ProjectError::RequesterNotFound(client_id) => ApiError::new(
            ErrorReason::ApplicationNotFound,
            "no client or machine user has this identifier",
        )
        .with_resource("OAuthClient", client_id)
        .into(),
        ProjectError::ResourceNotFound(id) => ApiError::new(
            ErrorReason::ResourceNotFound,
            "no protected resource has this identifier",
        )
        .with_resource("ProtectedResource", id.to_string())
        .into(),
        ProjectError::RoleNotFound(id) => {
            not_found(ErrorReason::RoleNotFound, "Role", id.to_string())
        }
        ProjectError::IatNotFound(id) => not_found(
            ErrorReason::InitialAccessTokenNotFound,
            "InitialAccessToken",
            id.to_string(),
        ),
        ProjectError::IssuerNotFound(handle) => ApiError::new(
            ErrorReason::OidcIssuerNotFound,
            "no OIDC issuer has this handle",
        )
        .with_resource("OidcIssuer", handle)
        .into(),
        ProjectError::ProjectInUse(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the project still has applications or SCIM targets",
        )
        .with_precondition(
            "PROJECT_IN_USE",
            id.to_string(),
            "remove its applications and SCIM targets first",
        )
        .into(),
        ProjectError::SystemProject(change) => ApiError::new(
            ErrorReason::SystemManaged,
            "the system project is kept by SID and is not changed by hand",
        )
        .with_precondition("SYSTEM_MANAGED", "Project", change)
        .into(),
        // SID provisions and keeps the installation's own integrations, so
        // they are disabled rather than deleted and their settings follow the
        // deployment's configuration.
        ProjectError::SystemManaged { application, what } => ApiError::new(
            ErrorReason::SystemManaged,
            format!("the application is managed by SID: {what}"),
        )
        .with_precondition(
            "SYSTEM_MANAGED",
            application.to_string(),
            "disable the integration instead; its settings follow the deployment",
        )
        .into(),
        ProjectError::RoleExists { application, role } => ApiError::new(
            ErrorReason::ApplicationRoleExists,
            format!("the application already has a {role} role"),
        )
        .with_resource("Application", application.to_string())
        .into(),
        ProjectError::IndicatorTaken(indicator) => ApiError::new(
            ErrorReason::ResourceIndicatorTaken,
            "the issuer already has, or had, a protected resource with this indicator",
        )
        .with_resource("ProtectedResource", indicator.as_str())
        .into(),
        ProjectError::ResourceRetired(id) => ApiError::new(
            ErrorReason::ResourceRetired,
            "the protected resource is retired with its application",
        )
        .with_precondition("RESOURCE_STATE", id.to_string(), "retired")
        .into(),
        ProjectError::RetireByRemoval(id) => ApiError::new(
            ErrorReason::ResourceRetired,
            "a resource is retired only by removing its application",
        )
        .with_precondition(
            "APPLICATION_REMOVED",
            id.to_string(),
            "remove the application to retire its resource",
        )
        .into(),
        ProjectError::IssuerMismatch(id) => ApiError::new(
            ErrorReason::IssuerMismatch,
            "the client and the resource belong to different issuers",
        )
        .with_precondition(
            "SAME_ISSUER",
            id.to_string(),
            "grant access only within one issuer",
        )
        .into(),
        ProjectError::RoleTaken(key) => ApiError::new(
            ErrorReason::RoleAlreadyExists,
            "the project already has a role with this key or display name",
        )
        .with_resource("Role", key)
        .into(),
        ProjectError::RoleRequired => ApiError::new(
            ErrorReason::RequiredFieldMissing,
            "an application needs a client role, a resource role, or both",
        )
        .with_field_violation("client", "required without resource")
        .with_field_violation("resource", "required without client")
        .into(),
        ProjectError::SubjectRequired => ApiError::new(
            ErrorReason::RequiredFieldMissing,
            "name a client or a resource",
        )
        .with_field_violation("client_id", "required without resource_id")
        .with_field_violation("resource_id", "required without client_id")
        .into(),
        // Changing a client's subject type changes its users' subjects,
        // which only the explicit identity migration does.
        ProjectError::SubjectMigrationRequired(client_id) => ApiError::new(
            ErrorReason::InvalidState,
            "changing the client's subject type changes its users' subjects \
             and needs the explicit identity migration",
        )
        .with_precondition("SUBJECT_TYPE", client_id, "identity migration required")
        .into(),
        // It registers no client (RFC 6750 §3.1 `invalid_token` on the HTTP
        // form).
        ProjectError::IatUnusable => ApiError::new(
            ErrorReason::TokenInvalid,
            "the initial access token is not valid",
        )
        .into(),
        ProjectError::IatEnded => ApiError::new(
            ErrorReason::TokenInvalid,
            "the initial access token is expired or revoked",
        )
        .into(),
        ProjectError::RatInvalid => ApiError::new(
            ErrorReason::TokenInvalid,
            "the registration access token is not valid",
        )
        .into(),
        ProjectError::NotRegisteredDynamically(client_id) => ApiError::new(
            ErrorReason::InvalidState,
            "the client was not dynamically registered",
        )
        .with_precondition("REGISTRATION", client_id, "not registered dynamically")
        .into(),
        ProjectError::IatDeleted(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the client's initial access token no longer exists",
        )
        .with_precondition("INITIAL_ACCESS_TOKEN", id.to_string(), "deleted")
        .into(),
        ProjectError::ChangedConcurrently => changed_concurrently(),
    }
}

/// The answer of an operation, or the status of its refusal.
#[allow(clippy::result_large_err)]
fn answer<T>(result: Result<T, ProjectError>) -> Result<Response<T>, Status> {
    result.map(Response::new).map_err(refusal)
}

/// A created application or client role with the secret issued beside it,
/// which is handed out once and never recorded.
#[allow(clippy::result_large_err)]
fn issued(
    result: Result<Issued<CreateApplicationResponse>, ProjectError>,
) -> Result<Response<CreateApplicationResponse>, Status> {
    let Issued {
        mut response,
        client_secret,
    } = result.map_err(refusal)?;
    if let Some(secret) = client_secret {
        response.client_secret = secret.expose_secret().clone();
    }
    Ok(Response::new(response))
}

#[tonic::async_trait]
impl ProjectService for ProjectServiceImpl {
    // ── Project CRUD ────────────────────────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "create_project"))]
    async fn create_project(
        &self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Project>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .create_project(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_project"))]
    async fn get_project(
        &self,
        request: Request<GetProjectRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Project>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.projects
                .get_project(&caller, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_projects"))]
    async fn list_projects(
        &self,
        request: Request<ListProjectsRequest>,
    ) -> Result<Response<ListProjectsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.projects
                .list_projects(&caller, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_project"))]
    async fn update_project(
        &self,
        request: Request<UpdateProjectRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Project>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .update_project(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_project"))]
    async fn delete_project(
        &self,
        request: Request<DeleteProjectRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .delete_project(&caller, operation, request.into_inner())
                .await,
        )
    }

    // ── Application CRUD ────────────────────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "create_application"))]
    async fn create_application(
        &self,
        request: Request<CreateApplicationRequest>,
    ) -> Result<Response<CreateApplicationResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        issued(
            self.projects
                .create_application(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_application"))]
    async fn get_application(
        &self,
        request: Request<GetApplicationRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.projects
                .get_application(&caller, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_applications"))]
    async fn list_applications(
        &self,
        request: Request<ListApplicationsRequest>,
    ) -> Result<Response<ListApplicationsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.projects
                .list_applications(&caller, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_application"))]
    async fn update_application(
        &self,
        request: Request<UpdateApplicationRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .update_application(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_client_role"))]
    async fn update_client_role(
        &self,
        request: Request<UpdateClientRoleRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .update_client_role(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_application"))]
    async fn delete_application(
        &self,
        request: Request<DeleteApplicationRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .delete_application(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "add_client_role"))]
    async fn add_client_role(
        &self,
        request: Request<AddClientRoleRequest>,
    ) -> Result<Response<CreateApplicationResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        issued(
            self.projects
                .add_client_role(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "add_resource_role"))]
    async fn add_resource_role(
        &self,
        request: Request<AddResourceRoleRequest>,
    ) -> Result<Response<Application>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .add_resource_role(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_resource_role"))]
    async fn update_resource_role(
        &self,
        request: Request<UpdateResourceRoleRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProtectedResource>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .update_resource_role(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "set_resource_access"))]
    async fn set_resource_access(
        &self,
        request: Request<SetResourceAccessRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ResourceAccess>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .set_resource_access(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "remove_resource_access"))]
    async fn remove_resource_access(
        &self,
        request: Request<RemoveResourceAccessRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .remove_resource_access(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_resource_access"))]
    async fn list_resource_access(
        &self,
        request: Request<ListResourceAccessRequest>,
    ) -> Result<Response<ListResourceAccessResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.projects
                .list_resource_access(&caller, request.into_inner())
                .await,
        )
    }

    // ── Role management ─────────────────────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "add_role"))]
    async fn add_role(
        &self,
        request: Request<AddRoleRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Role>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .add_role(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "remove_role"))]
    async fn remove_role(
        &self,
        request: Request<RemoveRoleRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .remove_role(&caller, operation, request.into_inner())
                .await,
        )
    }

    // ── Dynamic Client Registration (RFC 7591) ──────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "register_client"))]
    async fn register_client(
        &self,
        request: Request<RegisterClientRequest>,
    ) -> Result<Response<RegisterClientResponse>, Status> {
        self.check_maintenance().await?;
        self.projects
            .check_registration_issuer(&request.get_ref().issuer_handle)
            .map_err(refusal)?;
        let iat = bearer(&request)?;
        answer(
            self.projects
                .register_client(&iat, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_registered_client"))]
    async fn get_registered_client(
        &self,
        request: Request<GetRegisteredClientRequest>,
    ) -> Result<Response<OAuthClient>, Status> {
        let rat = bearer(&request)?;
        answer(
            self.projects
                .get_registered_client(&rat, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_registered_client"))]
    async fn update_registered_client(
        &self,
        request: Request<UpdateRegisteredClientRequest>,
    ) -> Result<Response<OAuthClient>, Status> {
        self.check_maintenance().await?;
        let rat = bearer(&request)?;
        answer(
            self.projects
                .update_registered_client(&rat, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_registered_client"))]
    async fn delete_registered_client(
        &self,
        request: Request<DeleteRegisteredClientRequest>,
    ) -> Result<Response<()>, Status> {
        self.check_maintenance().await?;
        let rat = bearer(&request)?;
        answer(
            self.projects
                .delete_registered_client(&rat, request.into_inner())
                .await,
        )
    }

    // ── Initial Access Token management ──────────────────────────────

    #[tracing::instrument(skip_all, fields(rpc = "create_initial_access_token"))]
    async fn create_initial_access_token(
        &self,
        request: Request<CreateInitialAccessTokenRequest>,
    ) -> Result<Response<CreateInitialAccessTokenResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .create_initial_access_token(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_initial_access_tokens"))]
    async fn list_initial_access_tokens(
        &self,
        request: Request<ListInitialAccessTokensRequest>,
    ) -> Result<Response<ListInitialAccessTokensResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.projects
                .list_initial_access_tokens(&caller, request.into_inner())
                .await,
        )
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_initial_access_token"))]
    async fn revoke_initial_access_token(
        &self,
        request: Request<RevokeInitialAccessTokenRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answer(
            self.projects
                .revoke_initial_access_token(&caller, operation, request.into_inner())
                .await,
        )
    }
}

#[cfg(test)]
mod tests;
