// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization endpoint's core (RFC 6749 §4.1, OpenID Connect Core
//! §3.1.2), shared by the typed RPC, where a bearer token names the session,
//! and the browser endpoint, where the IdP session cookie does. A browser
//! request the user must first sign in for is kept server-side and
//! continued by an opaque reference, never rebuilt from the URL the sign-in
//! page returns to.

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Utc};
use sid_authn::caller::{CallerError, Verified};
use sid_authn::challenge_store::{ChallengeStore, ChallengeStoreError};
use sid_authn::issuer::AddressedIssuer;
use sid_authn::login_policy::{LoginDecision, Unmet};
use sid_authn::oauth2::AuthorizeError;
use sid_authn::oauth2::prompt::Prompt;
use sid_core::Error as SidError;
use sid_core::models::session::AuthLevel;
use sid_core::models::{AuditEntry, MutationContext, OAuth2Client, OidcIssuer, Session, SessionId};
use sid_proto::sid::v1::{
    OAuth2AuthorizeRequest, OAuth2AuthorizeResponse, SignInContext, o_auth2_authorize_response,
};
use tracing::info;

use super::{OAuth, OAuthError};
use crate::sign_in::SignIn;

/// Why an authorization request is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    /// The request names no active client of the issuer whose endpoint it
    /// reached; RFC 6749 §4.1.2.1 forbids redirecting this one.
    #[error("unknown client")]
    UnknownClient,
    /// The request itself is refused, with its RFC 6749 §4.1.2.1 error (an
    /// unregistered redirect URI is never redirected to).
    #[error(transparent)]
    Request(#[from] AuthorizeError),
    /// The application's login requirements ask for more first.
    #[error("a step-up is required")]
    StepUp(Unmet),
    /// The login policy changed while the code was committed; the
    /// authorization is asked again.
    #[error("the login policy changed")]
    PolicyChanged,
    /// The authorizing session ended, may not authorize, or was
    /// authenticated too long ago for the request: sign in again.
    #[error("the session has ended")]
    SessionEnded,
    /// The continued request is not one this issuer is waiting to complete,
    /// the same for every cause.
    #[error("not an authorization request this issuer is waiting to complete")]
    NotWaiting,
    /// The caller's token may not authorize (an application's).
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The requirements, issuer or target could not be decided.
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    /// The kept request could not be read or written.
    #[error(transparent)]
    Ceremony(#[from] ChallengeStoreError),
    /// No random reference could be drawn for a kept request.
    #[error("operating system random source unavailable")]
    RandomUnavailable,
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

/// Prefix of the `request_uri` that continues a kept request, the form of
/// RFC 9126 §2.2.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// How long a kept authorization request waits for the user to sign in.
const CONTINUATION_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Parse space-separated `acr_values` into the highest level asked for
/// (OpenID Connect Core 1.0 §3.1.2.1), canonical URNs or plain names; `None`
/// when none is recognized.
pub fn requested_acr(acr_values: &str) -> Option<AuthLevel> {
    acr_values
        .split_whitespace()
        .filter_map(AuthLevel::from_acr_value)
        .max()
}

/// An authorization request the browser endpoint keeps while the user signs
/// in, or while a cross-site POST continues on the issuer host.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingAuthorization {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    acr_values: Option<String>,
    issuer_handle: String,
    resource: Vec<String>,
    prompt: Option<String>,
    max_age: Option<u32>,
    /// When the request arrived: `prompt=login` and `max_age` count from it.
    arrived_at: DateTime<Utc>,
    /// The interaction `prompt` asked for (account selection, consent) has
    /// been offered on the sign-in page.
    interacted: bool,
}

impl PendingAuthorization {
    /// `request` as it arrives now.
    pub fn arrived(request: OAuth2AuthorizeRequest) -> Self {
        Self {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            response_type: request.response_type,
            scope: request.scope,
            state: request.state,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            nonce: request.nonce,
            acr_values: request.acr_values,
            issuer_handle: request.issuer_handle,
            resource: request.resource,
            prompt: request.prompt,
            max_age: request.max_age,
            arrived_at: Utc::now(),
            interacted: false,
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn issuer_handle(&self) -> &str {
        &self.issuer_handle
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// The request as the typed RPC carries it.
    pub fn request(&self) -> OAuth2AuthorizeRequest {
        OAuth2AuthorizeRequest {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            response_type: self.response_type.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            nonce: self.nonce.clone(),
            acr_values: self.acr_values.clone(),
            issuer_handle: self.issuer_handle.clone(),
            resource: self.resource.clone(),
            prompt: self.prompt.clone(),
            max_age: self.max_age,
            request_uri: None,
        }
    }
}

/// What the browser endpoint answers an authorization request with.
pub enum BrowserAuthorization {
    /// The authorization response for the client.
    Answer(OAuth2AuthorizeResponse),
    /// The user signs in (or interacts) first; the request is kept under
    /// `reference` for the sign-in page to return to.
    SignIn { reference: String },
    /// `prompt=none` asked for no interaction and one is needed: the OIDC
    /// error for the client (OpenID Connect Core §3.1.2.6).
    NoInteraction(&'static str),
}

/// The authorization response telling a client the user declined to sign in
/// for its request: `access_denied` (RFC 6749 §4.1.2.1) at `redirect_uri`,
/// with the request's `state` and the issuer (RFC 9207 §2).
pub struct Declined {
    pub redirect_uri: String,
    pub issuer: String,
    pub state: Option<String>,
}

impl OAuth {
    /// The active client `request` names and the issuer serving it, with its
    /// exact redirect URI registered. Established before anything else, the
    /// caller included: every later error is reported by redirecting there,
    /// which RFC 6749 §4.1.2.1 forbids for an unknown client or an
    /// unregistered URI. A client of another issuer than the one whose
    /// endpoint this is counts as unknown, as does a request naming another
    /// issuer than the one a call `addressed` by its path.
    pub async fn authorize_client(
        &self,
        request: &OAuth2AuthorizeRequest,
        addressed: Option<&AddressedIssuer>,
    ) -> Result<(OAuth2Client, OidcIssuer), AuthorizationError> {
        if addressed
            .is_some_and(|addressed| addressed.0.handle.to_string() != request.issuer_handle)
        {
            return Err(AuthorizationError::UnknownClient);
        }
        let client = self
            .storage
            .get_oauth2_client(&request.client_id)
            .await?
            .filter(|client| client.active)
            .ok_or(AuthorizationError::UnknownClient)?;
        let issuer = self
            .issuer_serving(&request.issuer_handle, client.org_id)
            .await?
            .ok_or(AuthorizationError::UnknownClient)?;
        if !client.is_redirect_uri_allowed(&request.redirect_uri) {
            return Err(AuthorizeError::UnregisteredRedirectUri.into());
        }
        Ok((client, issuer))
    }

    /// The authorization code `session` grants for `request` to `client` at
    /// `issuer`: the client's and the request's assurance judged against the
    /// session, the request validated, the code bound to its resource and
    /// carrying the session's authentication. The code commits only while
    /// the policy it was judged under holds.
    pub async fn authorize_with(
        &self,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        session: &Session,
        request: OAuth2AuthorizeRequest,
    ) -> Result<OAuth2AuthorizeResponse, AuthorizationError> {
        let profile_id = session.profile_id;
        // Every authorization is judged, over an existing session too: the
        // requirements the policy states for this client now, with the
        // client's own and the level the relying party asks for, each only
        // strengthening.
        let acr = request.acr_values.as_deref().and_then(requested_acr);
        // With the account's own enabled protection: a session admitted
        // before its second factor was enabled authorizes no code without it.
        let requirements = self
            .login_requirements(Some(&request.client_id))
            .await?
            .with_client(client, acr)
            .for_account(self.storage.as_ref(), profile_id)
            .await?;
        match requirements.decide(session, Utc::now()) {
            LoginDecision::Allow { audited } => {
                if !audited.is_empty() {
                    info!(
                        client = %request.client_id,
                        unmet = ?audited,
                        "Login requirements unmet, allowed by audit enforcement"
                    );
                }
            }
            LoginDecision::StepUp(unmet) => {
                info!(
                    client = %request.client_id,
                    session_acr = ?session.assurance_at(Utc::now()),
                    session_amr = ?session.amr,
                    ?unmet,
                    "Authorize: step-up required"
                );
                return Err(AuthorizationError::StepUp(unmet));
            }
        }

        let asked = sid_authn::oauth2::AuthorizeRequest {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            response_type: request.response_type,
            scope: request.scope,
            state: request.state,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            nonce: request.nonce,
        };
        let validated = self.oauth2.validate_authorize_request(client, &asked)?;
        // The code is bound to the resource its tokens will be for.
        let target = self
            .select_target(issuer, client, &request.resource)
            .await?;
        let (raw_code, auth_code) = self
            .oauth2
            .generate_auth_code(
                profile_id,
                &validated,
                target.resource_id(),
                session.grant_authentication(),
            )
            .map_err(|e| {
                tracing::error!(error = %e, "generate authorization code");
                AuthorizationError::Internal
            })?;
        let mut ctx: MutationContext = AuditEntry::user(
            profile_id.to_string(),
            "auth_code.create",
            auth_code.client_id.clone(),
        )
        .into();
        if let Some(fence) = requirements.fence {
            ctx = ctx.fenced_by(fence);
        }
        match self.storage.create_auth_code(&auth_code, ctx).await {
            Ok(()) => {}
            Err(SidError::Fenced(_)) => return Err(AuthorizationError::PolicyChanged),
            // The authorizing session ended (a logout) before the code was
            // stored: the user is signed out, not facing a server failure.
            Err(SidError::NotFound(_)) => return Err(AuthorizationError::SessionEnded),
            Err(e) => return Err(e.into()),
        }
        info!(
            "Issued auth code for profile {} → client {}",
            profile_id, auth_code.client_id
        );
        Ok(OAuth2AuthorizeResponse {
            state: validated.state,
            result: Some(o_auth2_authorize_response::Result::AuthorizationCode(
                raw_code,
            )),
        })
    }

    /// The typed RPC's authorization: the installation session `verified`
    /// stands for authorizes `request`, while it may authorize and is fresh
    /// enough for the request's `max_age` or `prompt`. The caller of this
    /// RPC is its own interface, so the interaction `prompt` asks for is its
    /// to have shown.
    pub async fn authorize_session(
        &self,
        sign_in: &SignIn,
        verified: &Verified,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        request: OAuth2AuthorizeRequest,
    ) -> Result<OAuth2AuthorizeResponse, AuthorizationError> {
        // Only the IdP session's own token: an application's session never
        // authorizes codes for other clients.
        verified.require_installation()?;
        let prompt = Prompt::parse(request.prompt.as_deref())?;
        let now = Utc::now();
        let session_id = SessionId::parse(&verified.claims.sid).map_err(|e| {
            tracing::error!(error = %e, "read session id of a verified token");
            AuthorizationError::Internal
        })?;
        // An ended session, and one authenticated too long ago, answer
        // alike: sign in again.
        let session = self
            .storage
            .get_session(session_id)
            .await?
            .filter(|session| session.profile_id == verified.caller.profile_id)
            .filter(|session| sign_in.authorizes(session, now))
            .filter(|session| {
                prompt
                    .authenticated_after(request.max_age, now)
                    .is_none_or(|after| session.authenticated_at >= after)
            })
            .ok_or(AuthorizationError::SessionEnded)?;
        self.authorize_with(client, issuer, &session, request).await
    }
}

/// The browser endpoint's authorization requests kept while the user signs
/// in.
pub struct Authorizations {
    continuations: ChallengeStore<PendingAuthorization>,
}

impl Authorizations {
    pub fn new(
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            continuations: ChallengeStore::new(
                ceremonies,
                keys,
                "authorize-continuation",
                CONTINUATION_TTL,
            ),
        }
    }

    /// The browser endpoint's answer to `pending` with `session`, the
    /// browser's IdP session. The client is established first; then the
    /// session must authorize, be fresh enough for `prompt=login` /
    /// `max_age`, and have had any interaction `prompt` asks for. Otherwise
    /// the user signs in and the request is kept, unless `prompt=none`
    /// forbids it.
    pub async fn browser(
        &self,
        oauth: &OAuth,
        sign_in: &SignIn,
        session: Option<Session>,
        pending: PendingAuthorization,
    ) -> Result<BrowserAuthorization, AuthorizationError> {
        let request = pending.request();
        // The endpoint's own path named the issuer the request was kept for.
        let (client, issuer) = oauth.authorize_client(&request, None).await?;
        let prompt = Prompt::parse(pending.prompt.as_deref())?;
        let now = Utc::now();
        let after = prompt.authenticated_after(pending.max_age, pending.arrived_at);
        let session = session.filter(|session| {
            sign_in.authorizes(session, now)
                && after.is_none_or(|after| session.authenticated_at >= after)
        });
        let interaction_owed = prompt.asks_interaction() && !pending.interacted;
        match session {
            Some(session) if !interaction_owed => {
                match oauth
                    .authorize_with(&client, &issuer, &session, request)
                    .await
                {
                    Ok(answer) => {
                        // Only an accepted use counts as activity.
                        oauth.storage.touch_session(session.id, now).await?;
                        Ok(BrowserAuthorization::Answer(answer))
                    }
                    // Below the level or methods the client requires: the
                    // user authenticates further (OIDC Core 1.0 §3.1.2.3).
                    Err(AuthorizationError::StepUp(_)) => self.sign_in_first(prompt, pending).await,
                    Err(e) => Err(e),
                }
            }
            _ => self.sign_in_first(prompt, pending).await,
        }
    }

    /// Keep `pending` for the sign-in page to return to, or, under
    /// `prompt=none`, the error that says an interaction is needed.
    async fn sign_in_first(
        &self,
        prompt: Prompt,
        mut pending: PendingAuthorization,
    ) -> Result<BrowserAuthorization, AuthorizationError> {
        if prompt.none() {
            return Ok(BrowserAuthorization::NoInteraction("login_required"));
        }
        // The sign-in page offers account selection and consent; the
        // continued request does not ask for them again.
        pending.interacted |= prompt.asks_interaction();
        Ok(BrowserAuthorization::SignIn {
            reference: self.keep(&pending).await?,
        })
    }

    /// Keep `pending` under a fresh random reference.
    pub async fn keep(&self, pending: &PendingAuthorization) -> Result<String, AuthorizationError> {
        let mut bytes = [0u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut bytes)
            .map_err(|_| AuthorizationError::RandomUnavailable)?;
        let reference = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.continuations.insert(&reference, pending).await?;
        Ok(reference)
    }

    /// The request kept under `reference`, taken: a reference continues once.
    pub async fn take(
        &self,
        reference: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationError> {
        Ok(self.continuations.take(reference).await?)
    }

    /// The context of the kept request `authorization_request` continues
    /// (`<issuer>/oauth2/authorize?client_id=..&request_uri=..`): its issuer
    /// and its client's name. The kept request is read, not taken, and must
    /// belong to that issuer, at its canonical URL, and to that client, which
    /// must be active with the request's redirect URI registered; a call
    /// `addressed` to an issuer by its path must name the same one. Anything
    /// else is [`AuthorizationError::NotWaiting`], the same for every cause.
    pub async fn sign_in_context(
        &self,
        oauth: &OAuth,
        authorization_request: &str,
        addressed: Option<&AddressedIssuer>,
    ) -> Result<SignInContext, AuthorizationError> {
        let (_, _, client, issuer) = self.kept(oauth, authorization_request, addressed).await?;
        Ok(SignInContext {
            issuer: issuer.canonical_url,
            client_name: client.client_name,
        })
    }

    /// The user declined to sign in for the kept request
    /// `authorization_request` continues: the request is checked as
    /// [`Self::sign_in_context`] checks it and taken, so it continues no
    /// further and a repeat is refused; the answer tells its client.
    pub async fn decline(
        &self,
        oauth: &OAuth,
        authorization_request: &str,
    ) -> Result<Declined, AuthorizationError> {
        let (reference, kept, _, issuer) = self.kept(oauth, authorization_request, None).await?;
        if self.take(&reference).await?.is_none() {
            return Err(AuthorizationError::NotWaiting);
        }
        Ok(Declined {
            redirect_uri: kept.redirect_uri,
            issuer: issuer.canonical_url,
            state: kept.state,
        })
    }

    /// The kept request `authorization_request` continues, read, with its
    /// reference, established client and issuer; see [`Self::sign_in_context`].
    async fn kept(
        &self,
        oauth: &OAuth,
        authorization_request: &str,
        addressed: Option<&AddressedIssuer>,
    ) -> Result<(String, PendingAuthorization, OAuth2Client, OidcIssuer), AuthorizationError> {
        let refused = || AuthorizationError::NotWaiting;
        let url = url::Url::parse(authorization_request).map_err(|_| refused())?;
        let handle = url
            .path()
            .strip_prefix("/i/")
            .and_then(|rest| rest.strip_suffix("/oauth2/authorize"))
            .ok_or_else(refused)?;
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        let (Some(client_id), Some(request_uri)) =
            (query.get("client_id"), query.get("request_uri"))
        else {
            return Err(refused());
        };
        let reference = request_uri
            .strip_prefix(REQUEST_URI_PREFIX)
            .ok_or_else(refused)?;
        let kept = self
            .continuations
            .read(reference)
            .await?
            .filter(|kept| kept.client_id() == client_id && kept.issuer_handle() == handle)
            .ok_or_else(refused)?;
        let (client, issuer) = oauth
            .authorize_client(&kept.request(), addressed)
            .await
            .map_err(|_| refused())?;
        // The request must be at the issuer's own canonical URL, not the same
        // path on another host.
        let at = format!("{}/oauth2/authorize", issuer.canonical_url);
        if authorization_request.split('?').next() != Some(at.as_str()) {
            return Err(refused());
        }
        Ok((reference.to_owned(), kept, client, issuer))
    }
}

#[cfg(test)]
mod tests;
