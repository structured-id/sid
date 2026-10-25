// SPDX-License-Identifier: AGPL-3.0-only
//! Browser sign-in calls addressed to one issuer on a shared origin:
//! `/i/{handle}/grpc/{package.Service}/{Method}`. Several issuers share the
//! host there, and the sign-in RPCs carry no issuer of their own, so the path
//! names it. The handle must name an issuer of this installation, and only
//! the sign-in surface is published under it; the call then reaches the same
//! service as at its root path, carrying the issuer it addressed and the path
//! it was received on.

use std::sync::Arc;
use std::task::{Context, Poll};

use sid_authn::issuer::{AddressedIssuer, IssuerRegistry};
use sid_authn::resource::TranscodedRequest;
use sid_core::grpc_error::{ApiError, ErrorReason, refuse};
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service, http};

/// The gRPC paths of the sign-in surface: every step of a ceremony a sign-in
/// page runs before it holds an account session (entry points included),
/// their factors and the installation's registration state. The signed-in
/// user's own account goes through the account API, never through an issuer
/// path.
pub const BROWSER_METHODS: &[&str] = &[
    "/sid.v1.authn.AuthService/ResolvePrincipal",
    "/sid.v1.authn.AuthService/GetZkppPolicy",
    "/sid.v1.authn.AuthService/OpaqueLoginStart",
    "/sid.v1.authn.AuthService/OpaqueLoginFinish",
    "/sid.v1.authn.AuthService/OpaqueRegistrationStart",
    "/sid.v1.authn.AuthService/OpaqueRegistrationFinish",
    "/sid.v1.authn.AuthService/OpaqueZkppRegistrationStart",
    "/sid.v1.authn.AuthService/OpaqueZkppRegistrationFinish",
    "/sid.v1.authn.AuthService/LegacyMigrateStart",
    "/sid.v1.authn.AuthService/LegacyMigrateFinish",
    "/sid.v1.authn.AuthService/WebAuthnAuthenticationStart",
    "/sid.v1.authn.AuthService/WebAuthnAuthenticationFinish",
    "/sid.v1.authn.AuthService/VerifyTotp",
    "/sid.v1.authn.AuthService/VerifySmsMfa",
    "/sid.v1.authn.AuthService/ResendSmsMfa",
    "/sid.v1.authn.AuthService/VerifyRecoveryCode",
    "/sid.v1.authn.AuthService/RequestOtp",
    "/sid.v1.authn.AuthService/VerifyOtp",
    "/sid.v1.authn.AuthService/ResendOtp",
    "/sid.v1.authn.AuthService/ResendEmailVerification",
    "/sid.v1.authn.AuthService/VerifyPhone",
    "/sid.v1.authn.AuthService/ResendPhoneVerification",
    "/sid.v1.authn.AuthService/SubmitDeviceUserCode",
    "/sid.v1.authn.AuthService/OAuth2Authorize",
    "/sid.v1.authn.AuthService/GetSignInContext",
    "/sid.v1.authn.AuthService/RequestMagicLink",
    "/sid.v1.authn.AuthService/VerifyMagicLink",
    "/sid.v1.authn.AuthService/ConfirmIdpLink",
    "/sid.v1.authn.AuthService/ListUserOrganizations",
    "/sid.v1.authn.AuthService/SelectOrganization",
    "/sid.v1.authn.AuthService/GetTerms",
    "/sid.v1.authn.AuthService/AcceptTerms",
    "/sid.v1.authn.AuthService/ApproveCiba",
    "/sid.v1.authn.AuthService/DenyCiba",
    "/sid.v1.authn.AuthService/VerifyCaptcha",
    "/sid.v1.authn.AuthService/GetDynamicPrompt",
    "/sid.v1.authn.AuthService/SubmitDynamicPrompt",
    "/sid.v1.authn.AuthService/RequestStepUp",
    "/sid.v1.authn.AuthService/CompleteStepUp",
    "/sid.v1.authn.AuthService/ConfirmAccountDeletion",
    "/sid.v1.authn.AuthService/RequestPasswordReset",
    "/sid.v1.authn.AuthService/VerifyPasswordReset",
    "/sid.v1.authn.AuthService/ExecutePasswordReset",
    "/sid.v1.authn.AuthService/CompletePasswordReset",
    "/sid.v1.authn.PasswordHistoryEvaluatorService/EvaluatePasswordHistory",
    "/sid.v1.admin.EnrollmentService/GetInstanceStatus",
    "/sid.v1.admin.EnrollmentService/GetEnrollmentPolicy",
];

/// The handle and the gRPC path of a call to `/i/{handle}/grpc/...`; `None`
/// for any other path.
pub(crate) fn addressed(path: &str) -> Option<(&str, &str)> {
    let (handle, rest) = path.strip_prefix("/i/")?.split_once('/')?;
    let method = rest.strip_prefix("grpc")?;
    method.starts_with('/').then_some((handle, method))
}

/// Serves issuer-addressed browser calls through `inner`; every call outside
/// `/i/` goes to it unchanged.
#[derive(Clone)]
pub struct IssuerRoute<S> {
    inner: S,
    issuers: Arc<IssuerRegistry>,
}

impl<S> IssuerRoute<S> {
    pub fn new(inner: S, issuers: Arc<IssuerRegistry>) -> Self {
        Self { inner, issuers }
    }
}

impl<S> Service<http::Request<Body>> for IssuerRoute<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        // The service polled ready serves this call; its clone the next one.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        if !request.uri().path().starts_with("/i/") {
            return Box::pin(inner.call(request));
        }
        let issuers = self.issuers.clone();
        Box::pin(async move {
            let received = request.uri().path().to_owned();
            // The method is checked first: a path outside the sign-in surface
            // costs no registry read.
            let Some((handle, method)) = addressed(&received).and_then(|(handle, method)| {
                let published = BROWSER_METHODS.iter().find(|m| **m == method)?;
                Some((handle, *published))
            }) else {
                return Ok(Status::unimplemented("no such method under an issuer path").into_http());
            };
            let issuer = match issuers.by_handle(handle).await {
                Ok(Some(issuer)) => issuer,
                Ok(None) => {
                    let refused: Status = ApiError::new(
                        ErrorReason::OidcIssuerNotFound,
                        "no OIDC issuer has this handle",
                    )
                    .with_resource("OidcIssuer", handle)
                    .into();
                    return Ok(refused.into_http());
                }
                Err(e) => {
                    return Ok(refuse::internal("resolve the addressed issuer", e).into_http());
                }
            };
            let mut uri = request.uri().clone().into_parts();
            uri.path_and_query = Some(http::uri::PathAndQuery::from_static(method));
            match http::Uri::from_parts(uri) {
                Ok(uri) => *request.uri_mut() = uri,
                Err(e) => return Ok(refuse::internal("route the addressed call", e).into_http()),
            }
            let transcoded = TranscodedRequest::new(request.method().as_str(), received.as_str());
            let extensions = request.extensions_mut();
            extensions.insert(transcoded);
            extensions.insert(AddressedIssuer(issuer));
            inner.call(request).await
        })
    }
}

#[cfg(test)]
mod tests;
