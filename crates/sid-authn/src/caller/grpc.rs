// SPDX-License-Identifier: AGPL-3.0-only
//! The gRPC entry to caller authentication: the request's bearer token, and
//! the canonical status of each refusal.

use sid_core::grpc_error::{ApiError, ErrorReason};
use tonic::{Request, Status};

use super::{
    Caller, CallerError, CurrentToken, FactorToken, Verified, authenticate_factor_token,
    authenticate_token,
};
use crate::jwt::TokenVerifier;

impl From<CallerError> for Status {
    fn from(e: CallerError) -> Self {
        match e {
            CallerError::Unauthenticated => {
                ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
            }
            CallerError::Denied => ApiError::new(
                ErrorReason::InsufficientPermissions,
                "the caller may not perform this operation",
            )
            .into(),
            CallerError::Unavailable { what, detail } => {
                sid_core::grpc_error::refuse::dependency_unavailable(what, detail)
            }
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
    let header = request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(CallerError::Unauthenticated)?;
    let (scheme, token) = header.split_once(' ').ok_or(CallerError::Unauthenticated)?;
    // RFC 7235 §2.1: the auth-scheme is case-insensitive.
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(CallerError::Unauthenticated.into());
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(CallerError::Unauthenticated.into());
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
    Ok(authenticate_token(bearer_token(request)?, verifier, current).await?)
}

/// Verify the bearer token of a second-factor verification (see
/// [`authenticate_factor_token`]).
#[allow(clippy::result_large_err)]
pub async fn verify_factor_request<T>(
    request: &Request<T>,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<FactorToken, Status> {
    Ok(authenticate_factor_token(bearer_token(request)?, verifier, current).await?)
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
