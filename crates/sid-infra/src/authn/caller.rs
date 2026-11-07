// SPDX-License-Identifier: AGPL-3.0-only
//! The gRPC entry to caller authentication: the request's bearer token, and
//! the canonical status of each refusal.

use sid_authn::caller::{
    Caller, CallerError, CurrentToken, FactorToken, Verified, authenticate_factor_token,
    authenticate_token,
};
use sid_authn::jwt::TokenVerifier;
use tonic::{Request, Status};

use crate::grpc_error::refuse::dependency_unavailable;
use crate::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};

impl IntoStatus for CallerError {
    fn into_status(self) -> Status {
        match self {
            CallerError::Unauthenticated => {
                ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
            }
            CallerError::Denied => ApiError::new(
                ErrorReason::InsufficientPermissions,
                "the caller may not perform this operation",
            )
            .into(),
            CallerError::Unavailable { what, detail } => dependency_unavailable(what, detail),
        }
    }
}

/// The bearer access token of `request`.
///
/// A `DPoP` authorization scheme is refused: these services do not verify
/// DPoP proofs, and accepting the token without its proof would drop the
/// sender constraint (RFC 9449 §7.1).
#[allow(clippy::result_large_err)]
pub fn bearer_token<T>(request: &Request<T>) -> Result<&str, Status> {
    let unauthenticated = || CallerError::Unauthenticated.into_status();
    let header = request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(unauthenticated)?;
    let (scheme, token) = header.split_once(' ').ok_or_else(unauthenticated)?;
    // RFC 7235 §2.1: the auth-scheme is case-insensitive.
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(unauthenticated());
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(unauthenticated());
    }
    Ok(token)
}

/// Verify the bearer access token of `request` (see [`authenticate_token`]).
#[allow(clippy::result_large_err)]
pub async fn verify_request<T>(
    request: &Request<T>,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<Verified, Status> {
    authenticate_token(bearer_token(request)?, verifier, current)
        .await
        .or_status()
}

/// Verify the bearer token of a second-factor verification (see
/// [`authenticate_factor_token`]).
#[allow(clippy::result_large_err)]
pub async fn verify_factor_request<T>(
    request: &Request<T>,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<FactorToken, Status> {
    authenticate_factor_token(bearer_token(request)?, verifier, current)
        .await
        .or_status()
}

/// Authenticate the caller of `request` from its bearer access token (see
/// [`verify_request`]).
#[allow(clippy::result_large_err)]
pub async fn authenticate<T>(
    request: &Request<T>,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<Caller, Status> {
    Ok(verify_request(request, verifier, current).await?.caller)
}

#[cfg(test)]
mod tests;
