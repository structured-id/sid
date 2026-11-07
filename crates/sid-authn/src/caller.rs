// SPDX-License-Identifier: AGPL-3.0-only
//! Caller authentication and authorization, the same for every entry point.
//!
//! [`authenticate_token`] turns a verified access token into a [`Caller`],
//! the only way to obtain one; the caller's checks decide whether it may act
//! on a target. A service reaches them through its transport adapter, which
//! reads the request's bearer token; an embedding application by presenting
//! the token itself, so the rules are the same in every service and in
//! process.

use crate::account_api::AccountApiToken;
use crate::jwt::{AccessTokenClaims, TokenVerifier, VerifiedAccess};
use crate::revocation_cache::RevocationCache;
use sid_core::models::ProfileId;

use crate::account_roles::ADMIN_ROLE_CLAIM;

/// `acr` of a token exchanged from a personal access token. Such a token
/// carries no resource-bound grant, so it is never an installation caller.
const ACR_PAT: &str = "urn:sid:acr:pat";
/// `acr` of an impersonation token (RFC 8693 token exchange).
pub const ACR_IMPERSONATION: &str = "urn:sid:acr:impersonation";

/// Why a caller was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallerError {
    /// No valid, current access token.
    #[error("authentication required")]
    Unauthenticated,
    /// The caller may not perform the operation.
    #[error("the caller may not perform this operation")]
    Denied,
    /// A source the decision needs (`what`) could not answer.
    #[error("{what} unavailable: {detail}")]
    Unavailable { what: &'static str, detail: String },
}

impl CallerError {
    fn unavailable(what: &'static str, cause: impl std::fmt::Display) -> Self {
        Self::Unavailable {
            what,
            detail: cause.to_string(),
        }
    }
}

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
    pub fn require_admin(&self) -> Result<(), CallerError> {
        if self.admin {
            Ok(())
        } else {
            Err(CallerError::Denied)
        }
    }

    /// Allow the owner of `target` or an administrator.
    pub fn require_self_or_admin(&self, target: ProfileId) -> Result<(), CallerError> {
        if self.admin || self.profile_id == target {
            Ok(())
        } else {
            Err(CallerError::Denied)
        }
    }

    /// Allow authorization queries only about the caller's own subject
    /// (`user:<profile_id>`), or about any subject for an administrator.
    pub fn require_own_subjects<'a>(
        &self,
        subjects: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), CallerError> {
        if self.admin {
            return Ok(());
        }
        let own = format!("user:{}", self.profile_id);
        if subjects.into_iter().all(|s| s == own) {
            Ok(())
        } else {
            Err(CallerError::Denied)
        }
    }

    /// Allow only a user's own sign-in session: credentials, login handles and
    /// sessions are never managed through an impersonation token.
    pub fn require_interactive(&self) -> Result<(), CallerError> {
        if self.kind == TokenKind::Interactive {
            Ok(())
        } else {
            Err(CallerError::Denied)
        }
    }
}

/// Where a verifier learns whether a validly signed token can still act.
#[async_trait::async_trait]
pub trait CurrentToken: Send + Sync {
    /// Whether `token`, verified as `claims`, can no longer act. A source
    /// that cannot answer refuses the request as unavailable.
    async fn ended(&self, token: &str, claims: &AccessTokenClaims) -> Result<bool, CallerError>;
}

/// In the issuer's own process: its revocation record.
#[async_trait::async_trait]
impl CurrentToken for RevocationCache {
    async fn ended(&self, _token: &str, claims: &AccessTokenClaims) -> Result<bool, CallerError> {
        check_revocation(self, claims).await
    }
}

#[async_trait::async_trait]
impl<T: CurrentToken + ?Sized> CurrentToken for std::sync::Arc<T> {
    async fn ended(&self, token: &str, claims: &AccessTokenClaims) -> Result<bool, CallerError> {
        (**self).ended(token, claims).await
    }
}

/// A resource apart from its issuer: a revocation its local view already
/// knows refuses at once; every other token is asked of the exact issuer,
/// whose answer alone admits it (resource-sdk.md token-state freshness). The
/// view's silence or failure proves nothing either way.
pub struct AtIssuer {
    pub known: std::sync::Arc<RevocationCache>,
    pub issuer: std::sync::Arc<dyn crate::issuer_state::IssuerState>,
}

#[async_trait::async_trait]
impl CurrentToken for AtIssuer {
    async fn ended(&self, token: &str, claims: &AccessTokenClaims) -> Result<bool, CallerError> {
        if claims.iss != self.issuer.issuer() {
            return Ok(true);
        }
        if let Ok(true) = self.known.is_revoked(&claims.jti, &claims.sid).await {
            return Ok(true);
        }
        let active = self
            .issuer
            .active(token)
            .await
            .map_err(|e| CallerError::unavailable("token state", e))?;
        Ok(!active)
    }
}

/// A verified access token and the caller it stands for.
#[derive(Debug)]
pub struct Verified {
    pub claims: AccessTokenClaims,
    pub caller: Caller,
    pub source: TokenSource,
}

/// Which kind of access token was presented.
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
    pub fn require_installation(&self) -> Result<(), CallerError> {
        if self.source == TokenSource::Installation {
            Ok(())
        } else {
            Err(CallerError::Denied)
        }
    }
}

/// Verify `token`, the installation's own access token or an account API
/// token: signature, issuer, audience, expiry, revocation, and that it is not
/// a DPoP-bound token presented as a bearer token (RFC 9449 §7.1). The caller
/// is resolved from the verified kind.
pub async fn authenticate_token(
    token: &str,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<Verified, CallerError> {
    let (claims, caller, source) = match verifier
        .verify(token)
        .await
        .map_err(|_| CallerError::Unauthenticated)?
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
        return Err(CallerError::Unauthenticated);
    }
    if current.ended(token, &claims).await? {
        return Err(CallerError::Unauthenticated);
    }
    Ok(Verified {
        claims,
        caller,
        source,
    })
}

/// The token a second-factor verification is presented with.
#[derive(Debug)]
pub enum FactorToken {
    /// The token of a sign-in owing this factor: its claims, verified.
    Pending(AccessTokenClaims),
    /// A caller's ordinary token, as [`authenticate_token`] verifies it.
    Session(Verified),
}

/// Verify `token`, presented with a second-factor verification: the token of
/// a sign-in owing its second factor, which nothing else accepts, or any
/// token [`authenticate_token`] accepts.
pub async fn authenticate_factor_token(
    token: &str,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<FactorToken, CallerError> {
    if let Ok(claims) = verifier.validate_pending_access_token(token) {
        if claims.cnf.is_some() || current.ended(token, &claims).await? {
            return Err(CallerError::Unauthenticated);
        }
        return Ok(FactorToken::Pending(claims));
    }
    authenticate_token(token, verifier, current)
        .await
        .map(FactorToken::Session)
}

/// Verify an access token presented anywhere else than the authorization
/// header (a token-exchange `subject_token`), with the same checks as
/// [`authenticate_token`].
pub async fn verify_token(
    token: &str,
    verifier: &TokenVerifier,
    current: &(impl CurrentToken + ?Sized),
) -> Result<AccessTokenClaims, CallerError> {
    let claims = verifier
        .validate_access_token(token)
        .map_err(|_| CallerError::Unauthenticated)?;
    if claims.cnf.is_some() {
        return Err(CallerError::Unauthenticated);
    }
    if current.ended(token, &claims).await? {
        return Err(CallerError::Unauthenticated);
    }
    Ok(claims)
}

/// Whether `claims` were revoked. A revocation check the shared cache cannot
/// answer refuses the token as unavailable rather than accepting it.
pub async fn check_revocation(
    revocation: &RevocationCache,
    claims: &AccessTokenClaims,
) -> Result<bool, CallerError> {
    revocation
        .is_revoked(&claims.jti, &claims.sid)
        .await
        .map_err(|e| CallerError::unavailable("token revocation state", e))
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

    /// The caller described by already verified claims (see
    /// [`authenticate_token`]).
    pub fn from_claims(claims: &AccessTokenClaims) -> Result<Self, CallerError> {
        let profile_id = claims
            .pid
            .as_deref()
            .and_then(|pid| ProfileId::parse(pid).ok())
            .ok_or(CallerError::Unauthenticated)?;
        let kind = match claims.acr.as_str() {
            ACR_PAT => return Err(CallerError::Unauthenticated),
            ACR_IMPERSONATION => TokenKind::Impersonation,
            _ if claims.act.is_some() => TokenKind::Impersonation,
            _ => TokenKind::Interactive,
        };
        let admin = claims
            .roles
            .split_whitespace()
            .any(|r| r == ADMIN_ROLE_CLAIM);
        Ok(Self {
            profile_id,
            session_id: claims.sid.clone(),
            admin,
            kind,
        })
    }
}

#[cfg(test)]
mod tests;
