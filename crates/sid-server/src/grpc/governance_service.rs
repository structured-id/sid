// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC GovernanceService: the access requests and temporary roles the
//! `sid` library owns ([`sid::authorization`]), behind authentication. In
//! CE the approver of access requests and the grantor of temporary roles is
//! the installation's administrator.

use sid::authorization::{Authorization, InstallationAdministrator};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_infra::authn::caller::authenticate;
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::governance_service_server::GovernanceService;
use sid_proto::sid::v1::authz::{
    AccessRequestMessage, AccessRequestResponse, DecideRequestRequest, DecideRequestResponse,
    GrantTemporaryRoleRequest, GrantTemporaryRoleResponse, ListPendingRequestsRequest,
    ListPendingRequestsResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

use super::authz_service::refusal;

pub struct GovernanceServiceImpl {
    authorization: Authorization,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl GovernanceServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            authorization: Authorization::new(storage, CedarService::new()),
            jwt,
            revocation,
        }
    }

    /// Authenticate the caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// Authenticate the caller as the installation's administrator.
    async fn admin<T>(&self, request: &Request<T>) -> Result<InstallationAdministrator, Status> {
        let caller = self.caller(request).await?;
        self.authorization
            .installation_administrator(&caller)
            .await
            .map_err(refusal)
    }
}

#[tonic::async_trait]
impl GovernanceService for GovernanceServiceImpl {
    #[instrument(skip_all, fields(method = "request_access"))]
    async fn request_access(
        &self,
        request: Request<AccessRequestMessage>,
    ) -> Result<Response<AccessRequestResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.authorization
            .request_access(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, fields(method = "list_pending_requests"))]
    async fn list_pending_requests(
        &self,
        request: Request<ListPendingRequestsRequest>,
    ) -> Result<Response<ListPendingRequestsResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.authorization
            .list_pending_requests(&admin)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, fields(method = "decide_request"))]
    async fn decide_request(
        &self,
        request: Request<DecideRequestRequest>,
    ) -> Result<Response<DecideRequestResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.authorization
            .decide_request(&admin, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, fields(method = "grant_temporary_role"))]
    async fn grant_temporary_role(
        &self,
        request: Request<GrantTemporaryRoleRequest>,
    ) -> Result<Response<GrantTemporaryRoleResponse>, Status> {
        let admin = self.admin(&request).await?;
        self.authorization
            .grant_temporary_role(&admin, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
