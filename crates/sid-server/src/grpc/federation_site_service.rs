// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC FederationSiteService: an administrator's management of the
//! installation's enrollment as a site of the federation
//! ([`sid::federation_site`]).

use std::sync::Arc;

use sid::federation_site::{FederationSite, FederationSiteError};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_fed::participant::{Mount, Participant};
use sid_infra::authn::caller::authenticate;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_proto::sid::v1 as wire;
use sid_proto::sid::v1::federation_site_service_server::FederationSiteService;
use tonic::{Request, Response, Status};

/// A certificate that cannot be this site's enrollment, as a precondition
/// the administrator can act on.
fn not_this_sites(description: impl Into<String>) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "the certificate is not this site's enrollment",
    )
    .with_precondition("SITE_CERTIFICATE", "FederationSite", description)
    .into()
}

/// The status a site refusal answers with.
fn refusal(e: FederationSiteError) -> Status {
    // What cannot be decided now (no current status, the store) is retried;
    // what is refused is the administrator's to correct.
    if e.undecided() {
        return match e {
            FederationSiteError::Store(e) => storage_failure(e),
            FederationSiteError::Contended => changed_concurrently(),
            other => dependency_unavailable("the platform's certificate status", other),
        };
    }
    match e {
        FederationSiteError::Caller(e) => e.into_status(),
        FederationSiteError::Store(e) => storage_failure(e),
        FederationSiteError::Contended => changed_concurrently(),
        FederationSiteError::Key(cause) => internal("site key", cause),
        FederationSiteError::Refused(refused) => not_this_sites(refused.to_string()),
        e @ (FederationSiteError::AnotherKey | FederationSiteError::AnotherOrganization) => {
            not_this_sites(e.to_string())
        }
        FederationSiteError::NotAnEntry(mount) => invalid_field(
            "mount",
            format!("{mount} is not an address this site is entered at"),
        ),
        FederationSiteError::NotEnrolled => ApiError::new(
            ErrorReason::InvalidState,
            "this installation is not enrolled as a site",
        )
        .with_precondition(
            "SITE_NOT_ENROLLED",
            "FederationSite",
            "hold the certificate the platform issued for this site first",
        )
        .into(),
    }
}

/// The site as an administrator reads it.
fn view(site: Participant) -> wire::FederationSite {
    wire::FederationSite {
        organization: Some(
            sid_core::models::OrgId::from_uuid(site.organization)
                .map(Into::into)
                .unwrap_or_default(),
        ),
        site: site.site.to_string(),
        mounts: site.mounts.iter().map(Mount::to_string).collect(),
    }
}

/// gRPC service for the installation's enrollment as a site.
pub struct FederationSiteServiceImpl {
    site: Arc<FederationSite>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl FederationSiteServiceImpl {
    pub fn new(
        site: Arc<FederationSite>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            site,
            jwt,
            revocation,
        }
    }

    /// The authenticated administrator.
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        Ok(caller)
    }
}

#[tonic::async_trait]
impl FederationSiteService for FederationSiteServiceImpl {
    async fn prepare_site_enrollment(
        &self,
        request: Request<wire::PrepareSiteEnrollmentRequest>,
    ) -> Result<Response<wire::SiteEnrollmentRequest>, Status> {
        let caller = self.admin(&request).await?;
        let prepared = self
            .site
            .enrollment_request(&caller)
            .await
            .map_err(refusal)?;
        Ok(Response::new(wire::SiteEnrollmentRequest {
            public_key: prepared.public_key,
            key_record: prepared.key_record,
            mounts: prepared.mounts.iter().map(Mount::to_string).collect(),
        }))
    }

    async fn hold_site_certificate(
        &self,
        request: Request<wire::HoldSiteCertificateRequest>,
    ) -> Result<Response<wire::FederationSite>, Status> {
        let caller = self.admin(&request).await?;
        let held = request.into_inner();
        self.site
            .hold(&caller, held.certificate, held.chain)
            .await
            .map(|site| Response::new(view(site)))
            .map_err(refusal)
    }

    async fn get_federation_site(
        &self,
        request: Request<wire::GetFederationSiteRequest>,
    ) -> Result<Response<wire::FederationSiteState>, Status> {
        let caller = self.admin(&request).await?;
        self.site
            .enrolled(&caller)
            .await
            .map(|site| {
                Response::new(wire::FederationSiteState {
                    site: site.map(view),
                })
            })
            .map_err(refusal)
    }

    async fn sign_site_admission(
        &self,
        request: Request<wire::SignSiteAdmissionRequest>,
    ) -> Result<Response<wire::SiteAdmission>, Status> {
        let caller = self.admin(&request).await?;
        let mount = Mount::parse(&request.get_ref().mount)
            .ok_or_else(|| invalid_field("mount", "an https address without query or fragment"))?;
        self.site
            .admission(&caller, &mount)
            .await
            .map(|statement| Response::new(wire::SiteAdmission { statement }))
            .map_err(refusal)
    }
}
