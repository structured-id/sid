// SPDX-License-Identifier: AGPL-3.0-only
//! Shared gRPC caller authentication and authorization.
//!
//! [`authenticate`] turns the bearer token of a request into a [`Caller`]; the
//! caller's checks decide whether it may act on a target. Every management RPC
//! goes through them, so the rules are the same in every service.

use crate::account_api::AccountApiToken;
use crate::jwt::{AccessTokenClaims, TokenVerifier, VerifiedAccess};
use crate::revocation_cache::RevocationCache;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::ProfileId;
use tonic::{Request, Status};

/// `acr` of a token exchanged from a personal access token. Such a token
/// carries no resource-bound grant, so it is never an installation caller.
const ACR_PAT: &str = "urn:sid:acr:pat";
/// `acr` of an impersonation token (RFC 8693 token exchange).
const ACR_IMPERSONATION: &str = "urn:sid:acr:impersonation";

/// What kind of session the caller's token stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A user's own sign-in session.
    Interactive,
    /// A token a machine obtained to act as a user.
    Impersonation,
}

/// The authenticated party of a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub profile_id: ProfileId,
    /// The session the token was issued for (`sid`).
    pub session_id: String,
    admin: bool,
    kind: TokenKind,
}

impl Caller {
    /// Whether the caller holds the instance administrator role.
    pub fn is_admin(&self) -> bool {
        self.admin
    }

    /// The kind of session behind the caller's token.
    pub fn kind(&self) -> TokenKind {
        self.kind
    }

    /// Allow only an administrator.
    #[allow(clippy::result_large_err)]
    pub fn require_admin(&self) -> Result<(), Status> {
        if self.admin { Ok(()) } else { Err(denied()) }
    }

    /// Allow the owner of `target` or an administrator.
    #[allow(clippy::result_large_err)]
    pub fn require_self_or_admin(&self, target: ProfileId) -> Result<(), Status> {
        if self.admin || self.profile_id == target {
            Ok(())
        } else {
            Err(denied())
        }
    }

    /// Allow authorization queries only about the caller's own subject
    /// (`user:<profile_id>`), or about any subject for an administrator.
    #[allow(clippy::result_large_err)]
    pub fn require_own_subjects<'a>(
        &self,
        subjects: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Status> {
        if self.admin {
            return Ok(());
        }
        let own = format!("user:{}", self.profile_id);
        if subjects.into_iter().all(|s| s == own) {
            Ok(())
        } else {
            Err(denied())
        }
    }

    /// Allow only a user's own sign-in session: credentials, login handles and
    /// sessions are never managed through an impersonation token.
    #[allow(clippy::result_large_err)]
    pub fn require_interactive(&self) -> Result<(), Status> {
        if self.kind == TokenKind::Interactive {
            Ok(())
        } else {
            Err(denied())
        }
    }
}

fn denied() -> Status {
    ApiError::new(
        ErrorReason::InsufficientPermissions,
        "the caller may not perform this operation",
    )
    .into()
}

fn unauthenticated() -> Status {
    ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
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

/// A request's verified access token and the caller it stands for.
#[derive(Debug)]
pub struct Verified {
    pub claims: AccessTokenClaims,
    pub caller: Caller,
    pub source: TokenSource,
}

/// Which kind of access token a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// The installation's own token (its `sid` names an IdP session).
    Installation,
    /// An account API token (its `sid` names an application session).
    AccountApi,
}

impl Verified {
    /// Allow only the installation's own token: an application's token, the
    /// account API's included, never stands for the IdP session.
    #[allow(clippy::result_large_err)]
    pub fn require_installation(&self) -> Result<(), Status> {
        if self.source == TokenSource::Installation {
            Ok(())
        } else {
            Err(denied())
        }
    }
}

/// Verify the bearer access token of `request`, the installation's own or an
/// account API token: signature, issuer, audience, expiry, revocation, and
/// that it is not a DPoP-bound token presented as a bearer token
/// (RFC 9449 §7.1). The caller is resolved from the verified kind.
#[allow(clippy::result_large_err)]
pub async fn verify_request<T>(
    request: &Request<T>,
    verifier: &TokenVerifier,
    revocation: &RevocationCache,
) -> Result<Verified, Status> {
    let token = bearer_token(request)?;
    let (claims, caller, source) = match verifier
        .verify(token)
        .await
        .map_err(|_| unauthenticated())?
    {
        VerifiedAccess::Session(claims) => {
            let caller = Caller::from_claims(&claims)?;
            (claims, caller, TokenSource::Installation)
        }
        VerifiedAccess::AccountApi(token) => {
            let caller = Caller::for_account_api(&token);
            (token.claims, caller, TokenSource::AccountApi)
        }
    };
    if claims.cnf.is_some() {
        return Err(unauthenticated());
    }
    if check_revocation(revocation, &claims).await? {
        return Err(unauthenticated());
    }
    Ok(Verified {
        claims,
        caller,
        source,
    })
}

/// Verify an access token presented anywhere else than the authorization
/// header (a token-exchange `subject_token`), with the same checks as
/// [`verified_claims`].
#[allow(clippy::result_large_err)]
pub async fn verify_token(
    token: &str,
    verifier: &TokenVerifier,
    revocation: &RevocationCache,
) -> Result<AccessTokenClaims, Status> {
    let claims = verifier
        .validate_access_token(token)
        .map_err(|_| unauthenticated())?;
    if claims.cnf.is_some() {
        return Err(unauthenticated());
    }
    if check_revocation(revocation, &claims).await? {
        return Err(unauthenticated());
    }
    Ok(claims)
}

/// Whether `claims` were revoked. A revocation check the shared cache cannot
/// answer refuses the token as unavailable rather than accepting it.
#[allow(clippy::result_large_err)]
pub async fn check_revocation(
    revocation: &RevocationCache,
    claims: &AccessTokenClaims,
) -> Result<bool, Status> {
    revocation
        .is_revoked(&claims.jti, &claims.sid)
        .await
        .map_err(|e| {
            sid_core::grpc_error::refuse::dependency_unavailable("token revocation state", e)
        })
}

/// Authenticate the caller of `request` from its bearer access token (see
/// [`verify_request`]).
#[allow(clippy::result_large_err)]
pub async fn authenticate<T>(
    request: &Request<T>,
    verifier: &TokenVerifier,
    revocation: &RevocationCache,
) -> Result<Caller, Status> {
    Ok(verify_request(request, verifier, revocation).await?.caller)
}

impl Caller {
    /// The caller of a verified account API token: the Profile it acts for,
    /// in the application session it belongs to. It carries no
    /// administrator authority: the account integration's client serves a
    /// user's own account, and administration is not an account operation.
    pub fn for_account_api(token: &AccountApiToken) -> Self {
        Self {
            profile_id: token.profile_id,
            session_id: token.claims.sid.clone(),
            admin: false,
            kind: TokenKind::Interactive,
        }
    }

    /// The caller described by already verified claims (see [`verified_claims`]).
    #[allow(clippy::result_large_err)]
    pub fn from_claims(claims: &AccessTokenClaims) -> Result<Self, Status> {
        let profile_id = claims
            .pid
            .as_deref()
            .and_then(|pid| ProfileId::parse(pid).ok())
            .ok_or_else(unauthenticated)?;
        let kind = match claims.acr.as_str() {
            ACR_PAT => return Err(unauthenticated()),
            ACR_IMPERSONATION => TokenKind::Impersonation,
            _ if claims.act.is_some() => TokenKind::Impersonation,
            _ => TokenKind::Interactive,
        };
        let admin = claims.roles.split_whitespace().any(|r| r == "admin");
        Ok(Self {
            profile_id,
            session_id: claims.sid.clone(),
            admin,
            kind,
        })
    }
}
