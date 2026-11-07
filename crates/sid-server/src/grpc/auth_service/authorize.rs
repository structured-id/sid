// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization endpoint's answers: the engine's authorization
//! ([`sid::oauth::authorization`]) for the typed RPC and the browser
//! endpoint, its refusals as statuses.

use sid::oauth::authorization::AuthorizationError;
use sid_core::models::OAuth2Client;
use tonic::metadata::MetadataMap;

pub(crate) use sid::oauth::authorization::{
    BrowserAuthorization, PendingAuthorization, REQUEST_URI_PREFIX,
};

use super::*;

/// ABORTED: the login policy changed while the grant was being committed; the
/// authorization is asked again and judged under the current one.
pub(super) fn policy_changed() -> Status {
    Status::from(ApiError::new(
        ErrorReason::ConcurrentModification,
        "the login policy changed; authorize again",
    ))
}

/// The answer to a refused or failed authorization request. An unknown
/// client and an unregistered redirect URI are marked with their field, so
/// the front channel shows them instead of redirecting (RFC 6749 §4.1.2.1).
pub(super) fn authorization_refusal(e: AuthorizationError) -> Status {
    use AuthorizationError as E;
    match e {
        E::UnknownClient => Status::from(
            ApiError::new(ErrorReason::ApplicationNotFound, "unknown client")
                .with_metadata("field", "client_id"),
        ),
        E::Request(e) => authorize_refusal(e),
        E::StepUp(unmet) => super::step_up_required(&unmet).into(),
        E::PolicyChanged => policy_changed(),
        E::SessionEnded => session_ended(),
        E::NotWaiting => sid_infra::grpc_error::refuse::invalid_field(
            "authorization_request",
            "not an authorization request this issuer is waiting to complete",
        ),
        E::Caller(e) => e.into_status(),
        E::OAuth(e) => oauth_refusal(e),
        E::Ceremony(e) => e.into_status(),
        E::RandomUnavailable => Status::internal("operating system random source unavailable"),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

impl AuthServiceImpl {
    /// The active client `request` names and the issuer serving it (see
    /// [`sid::oauth::OAuth::authorize_client`]).
    pub(crate) async fn authorize_client(
        &self,
        request: &OAuth2AuthorizeRequest,
        addressed: Option<&sid_authn::issuer::AddressedIssuer>,
    ) -> Result<(OAuth2Client, OidcIssuer), Status> {
        self.oauth
            .authorize_client(request, addressed)
            .await
            .map_err(authorization_refusal)
    }

    /// The browser endpoint's answer to `pending`, the browser's IdP session
    /// read from the `cookie` headers of `metadata` (see
    /// [`sid::oauth::authorization::Authorizations::browser`]).
    pub(crate) async fn browser_authorize(
        &self,
        metadata: &MetadataMap,
        pending: PendingAuthorization,
    ) -> Result<BrowserAuthorization, Status> {
        self.check_maintenance().await?;
        let session = self.browser_session(metadata).await?;
        self.authorizations
            .browser(&self.oauth, &self.sign_ins, session, pending)
            .await
            .map_err(authorization_refusal)
    }

    /// Keep `pending` under a fresh random reference.
    pub(crate) async fn keep_authorization(
        &self,
        pending: &PendingAuthorization,
    ) -> Result<String, Status> {
        self.authorizations
            .keep(pending)
            .await
            .map_err(authorization_refusal)
    }

    /// The context of the kept request `authorization_request` continues (see
    /// [`sid::oauth::authorization::Authorizations::sign_in_context`]).
    pub(crate) async fn sign_in_context(
        &self,
        authorization_request: &str,
        addressed: Option<&sid_authn::issuer::AddressedIssuer>,
    ) -> Result<SignInContext, Status> {
        self.authorizations
            .sign_in_context(&self.oauth, authorization_request, addressed)
            .await
            .map_err(authorization_refusal)
    }

    /// The authorization response telling the client of the kept request
    /// `authorization_request` continues that the user declined to sign in
    /// for it: `access_denied` at its registered redirect URI, with the
    /// request's `state` and the issuer (RFC 6749 §4.1.2.1, RFC 9207 §2). A
    /// repeat is refused.
    pub async fn declined_sign_in(&self, authorization_request: &str) -> Result<url::Url, Status> {
        let declined = self
            .authorizations
            .decline(&self.oauth, authorization_request)
            .await
            .map_err(authorization_refusal)?;
        sid_infra::oauth_http::authorization_response_url(
            &declined.redirect_uri,
            &declined.issuer,
            &[("error", "access_denied")],
            declined.state.as_deref(),
        )
        .ok_or_else(|| authorization_refusal(AuthorizationError::NotWaiting))
    }

    /// The request kept under `reference`, taken: a reference continues once.
    pub(crate) async fn continue_authorization(
        &self,
        reference: &str,
    ) -> Result<Option<PendingAuthorization>, Status> {
        self.authorizations
            .take(reference)
            .await
            .map_err(authorization_refusal)
    }
}
