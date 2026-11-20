// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization endpoint's core (RFC 6749 §4.1, OpenID Connect Core
//! §3.1.2), shared by the typed RPC, where a bearer token names the session,
//! and the browser endpoint, where the IdP session cookie does. A browser
//! request the user must first sign in for is kept server-side and
//! continued by an opaque reference, never rebuilt from the URL the sign-in
//! page returns to.

use std::sync::Arc;

use base64::Engine;
use jiff::Timestamp;
use sid_authn::caller::{CallerError, Verified};
use sid_authn::challenge_store::{ChallengeStore, ChallengeStoreError};
use sid_authn::issuer::AddressedIssuer;
use sid_authn::login_policy::{LoginDecision, Unmet};
use sid_authn::oauth2::AuthorizeError;
use sid_authn::oauth2::prompt::Prompt;
use sid_core::Error as SidError;
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    AuditEntry, AuthorizationOperation, AuthorizationOperationId, AuthorizationStatus, ClaimLevel,
    ClaimRequest, CompletionOutcome, MutationContext, OAuth2Client, OidcIssuer, ProfileId,
    ResourceId, Session, SessionId,
};
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
    /// No current consent covers the request and this entry point cannot
    /// hold the user's decision; a caller saying it showed a screen is not
    /// consent (authz/consent-flow.md, return the protocol outcome).
    #[error("the user's consent is required")]
    ConsentRequired,
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

/// Prefix of the `request_uri` that continues a decided authorization
/// operation at its issuer.
pub const OPERATION_URI_PREFIX: &str = "urn:sid:authorization-operation:";

/// The GET of the authorization endpoint at `issuer_url` that continues
/// operation `id` of `client_id`: the only continuation a consent decision
/// returns (authz/consent-flow.md, resume at the issuer). It carries no code,
/// token or destination; the issuer completes only for the session that
/// reviewed the operation.
pub fn operation_continuation(
    issuer_url: &str,
    client_id: &str,
    id: AuthorizationOperationId,
) -> Option<url::Url> {
    let mut url = url::Url::parse(&format!("{issuer_url}/oauth2/authorize")).ok()?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("request_uri", &format!("{OPERATION_URI_PREFIX}{id}"));
    Some(url)
}

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
    arrived_at: Timestamp,
    /// The account selection `prompt=select_account` asked for has been
    /// offered on the sign-in page.
    account_offered: bool,
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
            arrived_at: Timestamp::now(),
            account_offered: false,
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

    /// What this request asks of the sign-in at `now` (OpenID Connect Core
    /// 1.0 §3.1.2.1): the highest level `acr_values` names, and how recent
    /// an authentication must be. `prompt=login` asks for one after the
    /// request arrived and `max_age` for one within its seconds, both
    /// counted from arrival as the authorization counts them.
    pub fn sign_in_requirements(&self, now: Timestamp) -> SignInRequirements {
        let elapsed =
            std::time::Duration::try_from(now.duration_since(self.arrived_at)).unwrap_or_default();
        let login = self
            .prompt
            .as_deref()
            .is_some_and(|p| p.split_whitespace().any(|v| v == "login"))
            .then_some(elapsed);
        let max_age = self.max_age.map(|seconds| {
            std::time::Duration::from_secs(u64::from(seconds)).saturating_sub(elapsed)
        });
        SignInRequirements {
            acr: self.acr_values.as_deref().and_then(requested_acr),
            max_age: match (login, max_age) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
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

/// What a kept authorization request asks of the sign-in it waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignInRequirements {
    /// The level asked for, if any the installation knows.
    pub acr: Option<AuthLevel>,
    /// How recent the authentication must be now, if a limit is asked.
    pub max_age: Option<std::time::Duration>,
}

/// A request admitted for a session: the policy fence its code commits
/// under, the validated request and its target.
struct Admitted {
    fence: Option<sid_core::models::ActorFence>,
    validated: sid_authn::oauth2::ValidatedAuthorizeRequest,
    resource: ResourceId,
}

/// A continued operation's outcome, with where its client is answered.
pub struct Continuation {
    pub redirect_uri: String,
    pub state: Option<String>,
    pub outcome: BrowserAuthorization,
}

/// What an admitted authorization request leads to.
pub enum Authorized {
    /// Current consent covers it: the authorization response.
    Code(OAuth2AuthorizeResponse),
    /// The user decides first: the operation to hold that decision, not yet
    /// stored.
    ConsentOwed(Box<AuthorizationOperation>),
}

/// What the browser endpoint answers an authorization request with.
pub enum BrowserAuthorization {
    /// The authorization response for the client.
    Answer(OAuth2AuthorizeResponse),
    /// The user reviews the request on the consent page; the stored
    /// operation holds it and the decision.
    Consent { operation: AuthorizationOperationId },
    /// The user declined the request on the consent page: `access_denied`
    /// for the client (RFC 6749 §4.1.2.1).
    Denied,
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
            .ok_or(AuthorizationError::UnknownClient)?;
        // The same check as at the token endpoint: an inactive client, one of
        // another issuer, or a federation site whose admission no longer
        // stands starts no interaction and is redirected nowhere.
        let issuer = self
            .client_issuer(&request.issuer_handle, &client)
            .await
            .map_err(|e| match e {
                OAuthError::ClientRefused => AuthorizationError::UnknownClient,
                other => other.into(),
            })?;
        if !client.is_redirect_uri_allowed(&request.redirect_uri) {
            return Err(AuthorizeError::UnregisteredRedirectUri.into());
        }
        Ok((client, issuer))
    }

    /// What `session` may do with `request` to `client` at `issuer`: the
    /// request admitted (assurance, validation, target), then the code when
    /// current consent covers it, else the operation the user's decision is
    /// recorded on (authz/consent-flow.md, browser consent transaction).
    /// `consent_asked` is `prompt=consent`: it needs an actual decision for
    /// this request whatever consent is held.
    pub async fn authorize_with(
        &self,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        session: &Session,
        request: OAuth2AuthorizeRequest,
        consent_asked: bool,
    ) -> Result<Authorized, AuthorizationError> {
        let acr_values = request.acr_values.clone();
        let admitted = self.admit(client, issuer, session, request).await?;
        if consent_asked
            || self
                .consent_owed(client, session.profile_id, &admitted)
                .await?
        {
            let now = Timestamp::now();
            let held = self
                .storage
                .get_consent_by_client(session.profile_id, &client.client_id)
                .await?;
            let claim_requests = super::consent::review_requests(
                &client.claim_requests,
                &admitted.validated.scopes,
                held.as_ref(),
            );
            return Ok(Authorized::ConsentOwed(Box::new(AuthorizationOperation {
                id: AuthorizationOperationId::generate(),
                issuer_id: issuer.id,
                client_id: admitted.validated.client_id.clone(),
                redirect_uri: admitted.validated.redirect_uri.clone(),
                response_type: "code".into(),
                state: admitted.validated.state.clone(),
                code_challenge: admitted.validated.code_challenge.clone(),
                // Validation admits S256 only (RFC 7636 §4.2).
                code_challenge_method: Some("S256".into()),
                nonce: admitted.validated.nonce.clone(),
                resource_id: admitted.resource,
                scopes: admitted.validated.scopes.clone(),
                acr_values,
                claim_requests,
                session_id: session.id,
                profile_id: session.profile_id,
                status: AuthorizationStatus::AwaitingConsent,
                revision: 0,
                decision: None,
                created_at: now,
                expires_at: AuthorizationOperation::expiry_from(now),
                decided_at: None,
            })));
        }
        self.issue(client, issuer, session, admitted, None)
            .await
            .map(Authorized::Code)
    }

    /// Whether the holder's recorded consent of `profile` to `client` leaves
    /// the admitted request uncovered: its scopes for its resource, every
    /// required claim the client asks for, and a decision on every claim it
    /// asks for, shared or refused (a claim asked for the first time needs
    /// one; one refused before is not asked again). Only the holder's own
    /// grant covers it; the client's registration, an integration or an
    /// empty claim list never does (authz/consent-flow.md, holder consent
    /// authority).
    async fn consent_owed(
        &self,
        client: &OAuth2Client,
        profile: ProfileId,
        admitted: &Admitted,
    ) -> Result<bool, AuthorizationError> {
        // The whole request, not only its name: a grant of another claim type
        // or a sharing mode the request no longer admits does not cover it.
        let required: Vec<&ClaimRequest> = client
            .claim_requests
            .iter()
            .filter(|r| r.level == ClaimLevel::Required)
            .collect();
        let held = self
            .storage
            .get_consent_by_client(profile, &client.client_id)
            .await?;
        Ok(!held.is_some_and(|consent| {
            let decided = super::consent::review_requests(
                &client.claim_requests,
                &admitted.validated.scopes,
                Some(&consent),
            )
            .iter()
            .all(|request| {
                // Refused, or shared with its approved value; a grant
                // re-enabled without one is not yet decided.
                consent.grants.iter().any(|g| {
                    g.claim_name == request.claim_name && (!g.is_active() || g.disclosed.is_some())
                })
            });
            decided && consent.covers(admitted.resource, &admitted.validated.scopes, &required)
        }))
    }

    /// `request` admitted for `session`: the client's and the request's
    /// assurance judged against the session, the request validated and its
    /// target resolved.
    async fn admit(
        &self,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        session: &Session,
        request: OAuth2AuthorizeRequest,
    ) -> Result<Admitted, AuthorizationError> {
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
        match requirements.decide(session, Timestamp::now()) {
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
                    session_acr = ?session.assurance_at(Timestamp::now()),
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
        Ok(Admitted {
            fence: requirements.fence,
            validated,
            resource: target.resource_id(),
        })
    }

    /// The code `session` grants for the `admitted` request, carrying the
    /// session's authentication. Stored on its own, or, for `operation`, by
    /// completing that operation, which issues at most one code. It commits
    /// only while the policy it was judged under holds.
    async fn issue(
        &self,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        session: &Session,
        admitted: Admitted,
        operation: Option<AuthorizationOperationId>,
    ) -> Result<OAuth2AuthorizeResponse, AuthorizationError> {
        let profile_id = session.profile_id;
        let Admitted {
            fence,
            validated,
            resource,
        } = admitted;
        let (raw_code, mut auth_code) = self
            .oauth2
            .generate_auth_code(
                profile_id,
                &validated,
                resource,
                session.grant_authentication(),
            )
            .map_err(|e| {
                tracing::error!(error = %e, "generate authorization code");
                AuthorizationError::Internal
            })?;
        // Made now, while the session that authorizes the code stands, and
        // kept with the code: its redemption carries it and nothing else
        // does.
        auth_code.presentation = self
            .presentation_for(
                issuer,
                client,
                profile_id,
                validated.nonce.as_deref(),
                &validated.redirect_uri,
            )
            .await?;
        let mut ctx: MutationContext = AuditEntry::user(
            profile_id.to_string(),
            "auth_code.create",
            auth_code.client_id.clone(),
        )
        .into();
        if let Some(fence) = fence {
            ctx = ctx.fenced_by(fence);
        }
        let stored = match operation {
            None => self.storage.create_auth_code(&auth_code, ctx).await,
            Some(id) => match self
                .storage
                .complete_authorization_operation(id, Some(&auth_code), Timestamp::now(), ctx)
                .await
            {
                Ok(CompletionOutcome::Completed) => Ok(()),
                // Completed meanwhile (a concurrent continuation issued its
                // one code) or expired: no second code.
                Ok(CompletionOutcome::NotDecided) => return Err(AuthorizationError::NotWaiting),
                Err(e) => Err(e),
            },
        };
        match stored {
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
    /// enough for the request's `max_age` or `prompt`. It passes the same
    /// consent gate as the browser endpoint and cannot hold a decision: a
    /// request no current consent covers, or one with `prompt=consent`, is
    /// [`AuthorizationError::ConsentRequired`].
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
        let now = Timestamp::now();
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
        match self
            .authorize_with(client, issuer, &session, request, prompt.consent())
            .await?
        {
            Authorized::Code(answer) => Ok(answer),
            Authorized::ConsentOwed(_) => Err(AuthorizationError::ConsentRequired),
        }
    }

    /// Continue the decided operation `id` at `issuer`, the issuer whose
    /// endpoint the browser returned to, with `session`, the browser's IdP
    /// session (authz/consent-flow.md, resume at the issuer). Only the
    /// session that reviewed it continues it. The issuer, client, redirect,
    /// assurance and current consent are judged again now: an approval saved
    /// before a revocation or a policy change revives nothing. An approval
    /// issues its one code by completing the operation; a denial completes
    /// it with none. Anything else is [`AuthorizationError::NotWaiting`],
    /// the same for every cause.
    pub async fn continue_operation(
        &self,
        sign_in: &SignIn,
        issuer: &OidcIssuer,
        session: Option<Session>,
        id: AuthorizationOperationId,
    ) -> Result<Continuation, AuthorizationError> {
        let now = Timestamp::now();
        let operation = self
            .storage
            .authorization_operation(id)
            .await?
            .filter(|op| op.issuer_id == issuer.id)
            .ok_or(AuthorizationError::NotWaiting)?;
        let session = session
            .filter(|s| s.id == operation.session_id && s.profile_id == operation.profile_id)
            .filter(|s| sign_in.authorizes(s, now))
            .ok_or(AuthorizationError::NotWaiting)?;
        let resource = self
            .storage
            .get_protected_resource(operation.resource_id)
            .await?
            .ok_or(AuthorizationError::NotWaiting)?;
        let request = OAuth2AuthorizeRequest {
            client_id: operation.client_id.clone(),
            redirect_uri: operation.redirect_uri.clone(),
            response_type: operation.response_type.clone(),
            scope: Some(operation.scopes.join(" ")),
            state: operation.state.clone(),
            code_challenge: operation.code_challenge.clone(),
            code_challenge_method: operation.code_challenge_method.clone(),
            nonce: operation.nonce.clone(),
            // The level the relying party asked for is judged again: an
            // elevation that lapsed during the review issues no code.
            acr_values: operation.acr_values.clone(),
            issuer_handle: issuer.handle.to_string(),
            resource: vec![resource.indicator.to_string()],
            prompt: None,
            max_age: None,
            request_uri: None,
        };
        // An inactive client or a redirect no longer registered is answered
        // by no redirect at all (RFC 6749 §4.1.2.1).
        let (client, issuer) = self.authorize_client(&request, None).await?;
        let continuation = |outcome| Continuation {
            redirect_uri: operation.redirect_uri.clone(),
            state: operation.state.clone(),
            outcome,
        };
        match operation.status {
            AuthorizationStatus::Denied => {
                let ctx: MutationContext = AuditEntry::user(
                    session.profile_id.to_string(),
                    "authorization_operation.deny",
                    operation.client_id.clone(),
                )
                .into();
                match self
                    .storage
                    .complete_authorization_operation(id, None, now, ctx)
                    .await?
                {
                    CompletionOutcome::Completed => Ok(continuation(BrowserAuthorization::Denied)),
                    CompletionOutcome::NotDecided => Err(AuthorizationError::NotWaiting),
                }
            }
            AuthorizationStatus::Approved if operation.completable_at(now) => {
                let admitted = self.admit(&client, &issuer, &session, request).await?;
                if self
                    .consent_owed(&client, session.profile_id, &admitted)
                    .await?
                {
                    return Err(AuthorizationError::NotWaiting);
                }
                let answer = self
                    .issue(&client, &issuer, &session, admitted, Some(id))
                    .await?;
                self.storage.touch_session(session.id, now).await?;
                Ok(continuation(BrowserAuthorization::Answer(answer)))
            }
            _ => Err(AuthorizationError::NotWaiting),
        }
    }

    /// The session `session_id` of `profile` while it still stands and its
    /// authentication satisfies the installation's current sign-in policy
    /// for that Profile, with the account's own enabled protection; `None`
    /// for another Profile's session, an ended or expired one, and one below
    /// the policy now. Judged at every read: nothing is renewed by it.
    pub async fn standing_session(
        &self,
        profile: ProfileId,
        session_id: SessionId,
    ) -> Result<Option<Session>, AuthorizationError> {
        // A session that ended is no longer stored; one past its time is
        // not live either.
        let Some(session) = self
            .storage
            .get_session(session_id)
            .await?
            .filter(|session| session.profile_id == profile && !session.is_expired())
        else {
            return Ok(None);
        };
        // Judged again at the read: a policy tightened or a second factor
        // enabled since the sign-in leaves the session insufficient.
        let requirements = self
            .login_requirements(None)
            .await?
            .for_account(self.storage.as_ref(), profile)
            .await?;
        Ok(match requirements.decide(&session, Timestamp::now()) {
            LoginDecision::Allow { .. } => Some(session),
            LoginDecision::StepUp(_) => None,
        })
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
        let now = Timestamp::now();
        let after = prompt.authenticated_after(pending.max_age, pending.arrived_at);
        let session = session.filter(|session| {
            sign_in.authorizes(session, now)
                && after.is_none_or(|after| session.authenticated_at >= after)
        });
        let selection_owed = prompt.select_account() && !pending.account_offered;
        match session {
            Some(session) if !selection_owed => {
                match oauth
                    .authorize_with(&client, &issuer, &session, request, prompt.consent())
                    .await
                {
                    Ok(Authorized::Code(answer)) => {
                        // Only an accepted use counts as activity.
                        oauth.storage.touch_session(session.id, now).await?;
                        Ok(BrowserAuthorization::Answer(answer))
                    }
                    // The user decides on the consent page, unless no page
                    // may be shown (OIDC Core 1.0 §3.1.2.6).
                    Ok(Authorized::ConsentOwed(_)) if prompt.none() => {
                        Ok(BrowserAuthorization::NoInteraction("consent_required"))
                    }
                    Ok(Authorized::ConsentOwed(operation)) => {
                        let ctx: MutationContext = AuditEntry::user(
                            session.profile_id.to_string(),
                            "authorization_operation.create",
                            operation.client_id.clone(),
                        )
                        .into();
                        oauth
                            .storage
                            .create_authorization_operation(&operation, ctx)
                            .await?;
                        Ok(BrowserAuthorization::Consent {
                            operation: operation.id,
                        })
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
        // The sign-in page offers account selection; the continued request
        // does not ask for it again. Consent is never decided there: it is
        // the consent page's recorded decision.
        pending.account_offered |= prompt.select_account();
        Ok(BrowserAuthorization::SignIn {
            reference: self.keep(&pending).await?,
        })
    }

    /// Keep `pending` under a fresh random reference.
    pub async fn keep(&self, kept: &PendingAuthorization) -> Result<String, AuthorizationError> {
        let mut bytes = [0u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut bytes)
            .map_err(|_| AuthorizationError::RandomUnavailable)?;
        let reference = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.continuations.insert(&reference, kept).await?;
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

    /// What the kept request `authorization_request` continues asks of the
    /// sign-in now, checked as [`Self::sign_in_context`] checks it and read,
    /// not taken.
    pub async fn sign_in_requirements(
        &self,
        oauth: &OAuth,
        authorization_request: &str,
    ) -> Result<SignInRequirements, AuthorizationError> {
        let (_, kept, _, _) = self.kept(oauth, authorization_request, None).await?;
        Ok(kept.sign_in_requirements(Timestamp::now()))
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
        // The authorization endpoint's route: the root for the root-addressed
        // base issuer, `/i/<handle>` for a scoped one; the request was kept
        // under the handle of the issuer that route reached.
        let route = match url.path() {
            "/oauth2/authorize" => "",
            path => path
                .strip_prefix("/i/")
                .and_then(|rest| rest.strip_suffix("/oauth2/authorize"))
                .ok_or_else(refused)?,
        };
        let handle = oauth
            .routed_issuer(route)
            .await?
            .ok_or_else(refused)?
            .handle
            .to_string();
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
            .filter(|kept| kept.client_id() == client_id && kept.issuer_handle() == handle.as_str())
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
