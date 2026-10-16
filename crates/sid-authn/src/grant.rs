// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization code and refresh token grants of a token endpoint
//! (RFC 6749 §4.1.3, §6) for any authenticated account type. The host resolves
//! the client, the target, the proof of possession and the account; this
//! module keeps the grant checks and the atomic transitions of the code and
//! the refresh token family.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use sid_core::models::dpop::DPopBinding;
use sid_core::models::{
    AuditEntry, AuthCodeRedemption, OAuth2Client, OidcIssuer, Profile, ProfileEmail, ProfilePhone,
    ResourceId, Session, SessionId,
};
use sid_plugin::GrantStore;
use tracing::warn;

use crate::issuer::IssuerSigner;
use crate::oauth2::{IdTokenSource, OAuth2Server, RefreshRefusal, TokenError, TokenResponse};
use crate::target::Target;

/// How long the session a redeemed code starts lasts.
const GRANT_SESSION_TTL_HOURS: i64 = 24;

/// Why a grant gave no tokens.
#[derive(Debug)]
pub enum GrantFailure<E> {
    /// A required request parameter is missing (RFC 6749 §5.2
    /// `invalid_request`).
    MissingParameter(&'static str),
    /// The grant is refused with an RFC 6749 §5.2 error.
    Refused(TokenError, Cow<'static, str>),
    /// The refresh token is bound to another DPoP key (RFC 9449 §5).
    ProofMismatch,
    /// Grant state could not be read or written.
    Storage(sid_core::Error),
    /// The tokens could not be built.
    Issuance(sid_core::Error),
    /// The host refused the request or failed to resolve part of it.
    Host(E),
}

impl<E> GrantFailure<E> {
    fn invalid_grant(description: impl Into<Cow<'static, str>>) -> Self {
        Self::Refused(TokenError::InvalidGrant, description.into())
    }
}

/// What an ID token is built from, owned by the grant that issues it.
#[derive(Debug, Clone)]
pub struct IdTokenAccount {
    pub profile: Profile,
    pub email: Option<ProfileEmail>,
    pub phone: Option<ProfilePhone>,
}

impl IdTokenAccount {
    fn source(&self) -> IdTokenSource<'_> {
        IdTokenSource {
            profile: &self.profile,
            email: self.email.as_ref(),
            phone: self.phone.as_ref(),
        }
    }
}

/// The claims a grant's tokens carry for its account, as the host resolves
/// them for one client and scope set.
#[derive(Debug, Clone)]
pub struct AccountClaims {
    /// The `sub` the token issuer gives this client for the account.
    pub sub: String,
    pub roles: Vec<String>,
    /// Present when the account can be described in an ID token.
    pub id_token: Option<IdTokenAccount>,
    pub custom_claims: Option<HashMap<String, serde_json::Value>>,
}

/// What a token endpoint host supplies to a grant. One value serves one
/// request: it knows the request's client credentials, resource values and
/// proof.
#[async_trait]
pub trait GrantHost: Send + Sync {
    /// The authenticated account sessions, codes and refresh tokens belong to.
    type Owner: Clone + Display + Send + Sync + 'static;
    /// The account the host resolves an owner to.
    type Account: Send + Sync;
    /// A refusal or failure of the host, returned as is.
    type Error: Send;

    fn store(&self) -> &dyn GrantStore<Owner = Self::Owner>;
    fn oauth2(&self) -> &OAuth2Server;

    /// The client the request authenticates as and the issuer serving it.
    async fn client(&self) -> Result<(OAuth2Client, OidcIssuer), Self::Error>;

    /// The resource a grant bound to `bound` is redeemed for, if the request
    /// may have it (RFC 8707 §2.2).
    async fn resume_target(
        &self,
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        bound: ResourceId,
    ) -> Result<Target, Self::Error>;

    /// The request's DPoP proof, validated; `None` without one.
    async fn proof(&self) -> Result<Option<DPopBinding>, Self::Error>;

    /// The account `owner` names; `None` when it no longer exists.
    async fn account(&self, owner: &Self::Owner) -> Result<Option<Self::Account>, Self::Error>;

    /// The claims the tokens issued to `client` by `issuer` carry for
    /// `account` under `scopes`.
    async fn claims(
        &self,
        account: &Self::Account,
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        scopes: &[String],
    ) -> Result<AccountClaims, Self::Error>;

    /// The signer of `issuer`.
    async fn signer(&self, issuer: &OidcIssuer) -> Result<Arc<IssuerSigner>, Self::Error>;

    /// End session `session` and what depends on it: one of its credentials
    /// was replayed, as `action` names.
    async fn end_compromised_session(
        &self,
        session: SessionId,
        action: &'static str,
    ) -> Result<(), Self::Error>;

    /// The client address a session started by a grant records.
    fn session_address(&self) -> String;
}

/// The parameters of an authorization code grant request.
#[derive(Clone, Copy)]
pub struct CodeGrant<'a> {
    pub code: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
}

fn required<'a, E>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, GrantFailure<E>> {
    value
        .filter(|v| !v.is_empty())
        .ok_or(GrantFailure::MissingParameter(field))
}

async fn end_compromised<H: GrantHost>(
    host: &H,
    session: Option<SessionId>,
    action: &'static str,
) -> Result<(), GrantFailure<H::Error>> {
    let Some(session) = session else {
        return Ok(());
    };
    warn!(%session, action, "credential replayed; revoking its session");
    host.end_compromised_session(session, action)
        .await
        .map_err(GrantFailure::Host)
}

/// Redeem an authorization code (RFC 6749 §4.1.3) for tokens of a new
/// session. A code used before is refused and the session of its first use
/// ends (RFC 6749 §4.1.2); of concurrent redemptions exactly one gets tokens.
pub async fn redeem_code<H: GrantHost>(
    host: &H,
    request: CodeGrant<'_>,
) -> Result<TokenResponse, GrantFailure<H::Error>> {
    let raw_code = required(request.code, "code")?;
    let redirect_uri = required(request.redirect_uri, "redirect_uri")?;
    let (client, issuer) = host.client().await.map_err(GrantFailure::Host)?;

    let code_hash = OAuth2Server::hash_token(raw_code);
    let auth_code = host
        .store()
        .get_auth_code_by_hash(&code_hash)
        .await
        .map_err(GrantFailure::Storage)?
        .ok_or_else(|| GrantFailure::invalid_grant("authorization code not found"))?;
    if auth_code.used {
        end_compromised(host, auth_code.session_id, "auth_code.reuse").await?;
        return Err(GrantFailure::invalid_grant(
            "authorization code already used",
        ));
    }

    // Every refusal here (expired, other client or redirect URI, PKCE) is
    // `invalid_grant` (RFC 6749 §5.2, RFC 7636 §4.6).
    let exchanged = host
        .oauth2()
        .validate_code_exchange(&client, auth_code, request.code_verifier, redirect_uri)
        .map_err(|e| GrantFailure::invalid_grant(e.to_string()))?;
    // The tokens are for the resource the code was issued for, and only
    // while the client still has access to it.
    let target = host
        .resume_target(&issuer, &client, exchanged.resource())
        .await
        .map_err(GrantFailure::Host)?;

    let owner = exchanged.owner();
    let account = host
        .account(owner)
        .await
        .map_err(GrantFailure::Host)?
        .ok_or_else(|| GrantFailure::invalid_grant("the code's account no longer exists"))?;

    // The application's session reports the authentication of the session
    // that authorized the code (`auth_time`, `amr`, `acr`) and ends with it.
    let mut session = Session::new(
        owner.clone(),
        host.session_address(),
        Utc::now() + Duration::hours(GRANT_SESSION_TTL_HOURS),
    )
    .with_grant_authentication(exchanged.authentication());
    session.client_id = Some(client.client_id.clone());
    session.scopes = exchanged.scopes().to_vec();

    let proof = host.proof().await.map_err(GrantFailure::Host)?;
    let claims = host
        .claims(&account, &issuer, &client, exchanged.scopes())
        .await
        .map_err(GrantFailure::Host)?;
    let signer = host.signer(&issuer).await.map_err(GrantFailure::Host)?;
    let (response, refresh) = host
        .oauth2()
        .issue_tokens(
            &signer,
            &claims.sub,
            &claims.roles,
            &session,
            &client,
            &target,
            exchanged.scopes(),
            exchanged.nonce(),
            proof.as_ref(),
            claims.custom_claims.as_ref(),
            claims.id_token.as_ref().map(IdTokenAccount::source),
        )
        .map_err(GrantFailure::Issuance)?;

    // The code, the session and the refresh token commit together.
    let redemption = host
        .store()
        .redeem_auth_code(
            &code_hash,
            &session,
            &refresh,
            AuditEntry::user(
                owner.to_string(),
                "auth_code.exchange",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .map_err(GrantFailure::Storage)?;
    if let AuthCodeRedemption::AlreadyRedeemed { session_id } = redemption {
        end_compromised(host, session_id, "auth_code.reuse").await?;
        return Err(GrantFailure::invalid_grant(
            "authorization code already used",
        ));
    }
    tracing::info!(%owner, "issued tokens via authorization_code");
    Ok(response)
}

/// Rotate a refresh token (RFC 6749 §6): new tokens for the same session,
/// resource and scopes, the presented token replaced in one write. A rotated
/// token presented after its grace window ends its family and session.
pub async fn refresh<H: GrantHost>(
    host: &H,
    refresh_token: Option<&str>,
) -> Result<TokenResponse, GrantFailure<H::Error>> {
    let raw_token = required(refresh_token, "refresh_token")?;
    let (client, issuer) = host.client().await.map_err(GrantFailure::Host)?;

    let token_hash = OAuth2Server::hash_token(raw_token);
    let presented = host
        .store()
        .get_refresh_token_by_hash(&token_hash)
        .await
        .map_err(GrantFailure::Storage)?
        .ok_or_else(|| GrantFailure::invalid_grant("refresh token not found"))?;

    let validated = match host.oauth2().validate_refresh(presented, &client) {
        Ok(validated) => validated,
        Err(RefreshRefusal::Reused {
            session_id,
            family_id,
        }) => {
            // Whoever holds the family is not the client alone: the family and
            // its session end; a failure to revoke fails the request.
            warn!(%family_id, "refresh token reused; revoking family and session");
            host.store()
                .revoke_refresh_tokens_by_family(
                    family_id,
                    AuditEntry::system("token.reuse", family_id.to_string()).into(),
                )
                .await
                .map_err(GrantFailure::Storage)?;
            end_compromised(host, Some(session_id), "token.reuse").await?;
            return Err(GrantFailure::invalid_grant(
                "refresh token reused, all tokens revoked",
            ));
        }
        // Every refresh refusal is `invalid_grant` (RFC 6749 §5.2).
        Err(refusal) => return Err(GrantFailure::invalid_grant(refusal.to_string())),
    };
    // Refresh keeps the resource of its grant and never acquires another;
    // access revoked since ends further issuance.
    let target = host
        .resume_target(&issuer, &client, validated.resource())
        .await
        .map_err(GrantFailure::Host)?;

    let owner = validated.owner();
    let account = host
        .account(owner)
        .await
        .map_err(GrantFailure::Host)?
        .ok_or_else(|| GrantFailure::invalid_grant("the token's account no longer exists"))?;
    let session = host
        .store()
        .get_session(validated.session_id())
        .await
        .map_err(GrantFailure::Storage)?
        .ok_or_else(|| GrantFailure::invalid_grant("session ended"))?;

    let proof = host.proof().await.map_err(GrantFailure::Host)?;
    // A key-bound refresh token is used only with a proof for its key
    // (RFC 9449 §5).
    if let Some(bound) = validated.dpop_jkt()
        && proof.as_ref().map(|b| b.jkt.as_str()) != Some(bound)
    {
        return Err(GrantFailure::ProofMismatch);
    }

    let claims = host
        .claims(&account, &issuer, &client, validated.scopes())
        .await
        .map_err(GrantFailure::Host)?;
    let signer = host.signer(&issuer).await.map_err(GrantFailure::Host)?;
    let (response, mut rotated_to) = host
        .oauth2()
        .issue_tokens(
            &signer,
            &claims.sub,
            &claims.roles,
            &session,
            &client,
            &target,
            validated.scopes(),
            None,
            proof.as_ref(),
            claims.custom_claims.as_ref(),
            claims.id_token.as_ref().map(IdTokenAccount::source),
        )
        .map_err(GrantFailure::Issuance)?;
    // The new token continues the presented token's family.
    rotated_to.family_id = validated.family_id();

    // The presented token was revoked meanwhile (sign-out, reuse): nothing is
    // issued.
    let rotated = host
        .store()
        .rotate_refresh_token(
            validated.id(),
            &rotated_to,
            Utc::now()
                + Duration::seconds(sid_core::models::refresh_token::DEFAULT_GRACE_WINDOW_SECS),
            AuditEntry::user(owner.to_string(), "token.rotate", rotated_to.id.to_string()).into(),
        )
        .await
        .map_err(GrantFailure::Storage)?;
    if !rotated {
        return Err(GrantFailure::invalid_grant("refresh token revoked"));
    }
    tracing::info!(%owner, "rotated refresh token");
    Ok(response)
}

#[cfg(test)]
mod tests;
