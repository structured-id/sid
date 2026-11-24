// SPDX-License-Identifier: AGPL-3.0-only
//! The browser session of one application, transport-free: it signs the
//! application's users in at its issuer as the confidential web client the
//! installation registered (code flow, S256 PKCE, the client's assertion),
//! keeps the issuer's tokens server-side and gives the browser only a session
//! id and a CSRF token.
//!
//! Every adapter (the UI host's RPCs, the application proxy's HTTP routes)
//! calls this one implementation of each step and check; it reads the cookie,
//! `Origin` and CSRF headers off its own transport into a [`BrowserRequest`]
//! and writes the answers back in its own form. The calls the client makes at
//! its issuer go through [`ApplicationClient`], which the transport layer
//! implements.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::bff_session::{
    BffSession, BffSessionStore, RefreshClaim, SessionClaims, TokenReplacement,
};
use crate::issuer_directory::{IssuedTokenRefusal, IssuerDirectory};
use crate::relying_party::{Connection, SignInChoice, sign_in_cookie};
use crate::revocation_cache::RevocationCache;

/// An access token this close to expiry is refreshed before use, so it does
/// not expire on its way to the API.
const REFRESH_MARGIN_SECS: i64 = 30;
/// How long one replica holds a session's refresh: longer than a token
/// endpoint call.
pub const REFRESH_HOLD: Duration = Duration::from_secs(15);
/// How long the holder of a refresh claim may take from claiming it to
/// storing the result: inside the hold, with room for the shared store's
/// clock and the last write.
const REFRESH_WORK: Duration = Duration::from_secs(12);
const _: () = assert!(REFRESH_WORK.as_secs() < REFRESH_HOLD.as_secs());
/// How often a replica that did not win the refresh looks for its result.
const REFRESH_POLL: Duration = Duration::from_millis(200);

/// The tokens a token endpoint call returned (RFC 6749 §5.1).
#[derive(Debug)]
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

/// Why a call the client made at its issuer did not succeed, as far as the
/// caller can tell what became of it.
#[derive(Debug, thiserror::Error)]
pub enum GrantFailure {
    /// Nothing reached the issuer: no connection, or an unusable key.
    #[error("nothing was sent to the issuer: {0}")]
    NotSent(String),
    /// The issuer answered with a refusal of the call: the grant or the code
    /// is no longer usable.
    #[error("the issuer refused the call: {0}")]
    Refused(String),
    /// The issuer answered that it cannot serve the call now; nothing was
    /// done and a later call may succeed.
    #[error("the issuer cannot serve the call now: {0}")]
    Declined(String),
    /// The answer was lost or broken: the call may have taken effect.
    #[error("the issuer's answer was lost: {0}")]
    Uncertain(String),
}

/// The application's client at its issuer: its connection and the token
/// endpoint calls it makes as that client.
#[async_trait::async_trait]
pub trait ApplicationClient: Send + Sync {
    /// The connection details, or why there are none yet.
    async fn connection(&self) -> Result<&Connection, GrantFailure>;
    /// Redeem an authorization code with the sign-in's PKCE verifier
    /// (RFC 6749 §4.1.3).
    async fn redeem(
        &self,
        connection: &Connection,
        code: String,
        code_verifier: String,
    ) -> Result<IssuedTokens, GrantFailure>;
    /// Refresh (RFC 6749 §6); the issuer rotates the refresh token.
    async fn refresh(
        &self,
        connection: &Connection,
        refresh_token: String,
    ) -> Result<IssuedTokens, GrantFailure>;
    /// Revoke a refresh token and its grant (RFC 7009 §2.1).
    async fn revoke(
        &self,
        connection: &Connection,
        refresh_token: String,
    ) -> Result<(), GrantFailure>;
}

/// What a browser request carries that a session check reads, taken off the
/// adapter's transport.
#[derive(Debug, Default)]
pub struct BrowserRequest<'a> {
    /// The value of the session cookie, when the request carries it exactly
    /// once (see [`cookie_value`]).
    pub session: Option<String>,
    /// Every `Origin` the request carries.
    pub origins: Vec<&'a [u8]>,
    /// Every CSRF token header the request carries.
    pub csrf: Vec<&'a [u8]>,
    /// The request cannot change anything (`GET`, `HEAD`, `OPTIONS`): another
    /// site can make the browser send it but cannot read the answer, so it
    /// needs neither the page's `Origin` nor the CSRF token.
    pub safe: bool,
}

/// Why a session request is refused.
#[derive(Debug, thiserror::Error)]
pub enum SessionFailure {
    /// No live session of this application: the user signs in again.
    #[error("no application session")]
    NotSignedIn,
    /// The request is not the application's own page's.
    #[error("the request does not come from the application's page")]
    NotThePage,
    /// The request does not echo the session's CSRF token.
    #[error("the request does not carry this session's CSRF token")]
    CsrfMismatch,
    /// A dependency could not answer; the session may be live.
    #[error("{dependency} unavailable: {detail}")]
    Unavailable {
        dependency: &'static str,
        detail: String,
    },
}

impl SessionFailure {
    fn unavailable(dependency: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::Unavailable {
            dependency,
            detail: detail.to_string(),
        }
    }
}

/// Why a sign-in did not start or complete.
#[derive(Debug, thiserror::Error)]
pub enum SignInFailure {
    /// The installation has not provisioned the application's client yet.
    #[error("no connection to the application's client: {0}")]
    NotProvisioned(String),
    /// The session store cannot record or claim the sign-in.
    #[error("the sign-in cannot be recorded: {0}")]
    Unavailable(String),
    /// The callback reached a browser that did not start this sign-in.
    #[error("the sign-in was started in another browser")]
    OtherBrowser,
    /// No such sign-in under this browser and connection: unknown, expired
    /// or already completed.
    #[error("the sign-in has expired or was already used")]
    ExpiredOrUsed,
    /// The authorization response names another issuer (RFC 9207 §2.4).
    #[error("the authorization response comes from another issuer")]
    WrongIssuer,
    /// The issuer answered with an authorization error.
    #[error("the issuer refused the sign-in: {error}")]
    Refused {
        error: String,
        /// Where the user would have returned, to start again from.
        return_to: String,
    },
    /// The authorization response carries no code.
    #[error("the authorization response carries no code")]
    NoCode,
    /// The issuer did not complete the sign-in, or what it returned is not
    /// this sign-in's.
    #[error("the issuer did not complete the sign-in: {0}")]
    IssuerFailed(String),
    /// The issuer ended its session before the callback (Back-Channel Logout
    /// 1.0 §2.7).
    #[error("the issuer session was already ended")]
    EndedAtIssuer,
    /// The session could not be stored.
    #[error("the session cannot be stored: {0}")]
    NotStored(String),
}

impl SignInFailure {
    /// Whether the sign-in was taken before it failed: its correlation cookie
    /// is then cleared, and only then.
    pub fn took_the_sign_in(&self) -> bool {
        matches!(
            self,
            Self::WrongIssuer
                | Self::Refused { .. }
                | Self::NoCode
                | Self::IssuerFailed(_)
                | Self::EndedAtIssuer
                | Self::NotStored(_)
        )
    }
}

/// A started sign-in: the browser goes to `authorize_url` holding
/// `browser_secret` in the correlation cookie of `state`.
#[derive(Debug)]
pub struct SignInStart {
    pub authorize_url: url::Url,
    pub state: String,
    pub browser_secret: String,
}

/// The issuer's authorization response, as the callback received it.
#[derive(Debug, Default)]
pub struct AuthorizationAnswer {
    pub state: String,
    pub code: Option<String>,
    pub error: Option<String>,
    /// The issuer that answered (RFC 9207 §2).
    pub iss: Option<String>,
}

/// A completed sign-in: the new session and where the user returns.
#[derive(Debug)]
pub struct SignedIn {
    pub session_id: String,
    pub return_to: String,
}

/// What became of the grant behind an ended session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOutcome {
    /// The issuer revoked it: its refresh token no longer works.
    Revoked,
    /// The session held a grant the issuer did not revoke; it lives until it
    /// expires, though nobody holds its token any more.
    NotRevoked,
    /// No grant stood behind the session.
    None,
    /// Not known: the session was already gone, or the revocation's answer
    /// was lost after it may have taken effect.
    Unknown,
}

/// The answer to an issuer's back-channel logout (Back-Channel Logout 1.0
/// §2.8).
#[derive(Debug, PartialEq, Eq)]
pub enum LogoutReceipt {
    /// The issuer session is recorded as ended: 200.
    Recorded,
    /// Not a valid logout request: 400 `invalid_request` with this text.
    Refused(&'static str),
    /// It cannot be told or recorded now: 503, and the issuer retries.
    Unavailable,
}

/// The access token a forwarded call carries and the session it was taken
/// from: the API's refusal of that call concerns this token of this session
/// only. Neither leaves the adapter.
#[derive(Debug)]
pub struct Bearer {
    session: String,
    token: SecretString,
}

impl Bearer {
    /// The access token session `id` holds now.
    fn held(id: &str, session: &BffSession) -> Self {
        Self {
            session: id.to_owned(),
            token: session.access_token.clone(),
        }
    }

    /// The token, for the call's `authorization` (RFC 6750 §2.1).
    pub fn token(&self) -> &SecretString {
        &self.token
    }
}

/// The browser sessions of one application: its client at the issuer, the
/// issuer directory that verifies what the issuer returns, the shared session
/// store and the revocations every SID process records.
pub struct BrowserSessions<C> {
    client: Arc<C>,
    issuers: Arc<IssuerDirectory>,
    sessions: Arc<BffSessionStore>,
    revocation: Arc<RevocationCache>,
    /// The session cookie's name; each sign-in's correlation cookie is named
    /// after it.
    cookie: String,
}

impl<C> std::fmt::Debug for BrowserSessions<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserSessions")
            .field("cookie", &self.cookie)
            .finish_non_exhaustive()
    }
}

impl<C: ApplicationClient> BrowserSessions<C> {
    pub fn new(
        client: Arc<C>,
        issuers: Arc<IssuerDirectory>,
        sessions: Arc<BffSessionStore>,
        revocation: Arc<RevocationCache>,
        cookie: String,
    ) -> Self {
        Self {
            client,
            issuers,
            sessions,
            revocation,
            cookie,
        }
    }

    /// The session cookie's name.
    pub fn cookie(&self) -> &str {
        &self.cookie
    }

    /// The name of the correlation cookie of the sign-in `state` names.
    pub fn sign_in_cookie(&self, state: &str) -> String {
        sign_in_cookie(&self.cookie, state)
    }

    /// How long a started sign-in waits for its callback: the lifetime of its
    /// correlation cookie.
    pub fn pending_ttl(&self) -> Duration {
        self.sessions.pending_ttl()
    }

    /// The application's connection.
    pub async fn connection(&self) -> Result<&Connection, GrantFailure> {
        self.client.connection().await
    }

    /// Start a sign-in that returns to `requested` when it is a path on this
    /// origin, else to the root, at the issuer's ordinary sign-in.
    pub async fn start_sign_in(&self, requested: &str) -> Result<SignInStart, SignInFailure> {
        self.start_sign_in_at(requested, SignInChoice::Ordinary)
            .await
    }

    /// [`Self::start_sign_in`], asking the issuer for the sign-in the user
    /// chose on the application's page.
    pub async fn start_sign_in_at(
        &self,
        requested: &str,
        sign_in: SignInChoice,
    ) -> Result<SignInStart, SignInFailure> {
        let connection = self
            .connection()
            .await
            .map_err(|e| SignInFailure::NotProvisioned(e.to_string()))?;
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        // Same shape and strength as the verifier: 256 random bits.
        let nonce = random_token();
        // The secret only the browser that started this sign-in holds, in a
        // correlation cookie of this sign-in alone: sign-ins started at once in
        // several tabs each keep their own and none replaces another's.
        let browser_secret = random_token();
        // Without a store there is no sign-in to start: sending the browser on
        // with a state nobody can verify would make the callback unverifiable.
        let state = self
            .sessions
            .store_pending(
                SecretString::from(verifier),
                nonce.clone(),
                local_path(requested),
                &connection.browser_sign_in_binding(&browser_secret),
            )
            .await
            .map_err(|e| SignInFailure::Unavailable(e.to_string()))?;
        Ok(SignInStart {
            authorize_url: connection.authorize_url(&challenge, &state, &nonce, sign_in),
            state,
            browser_secret,
        })
    }

    /// Complete the sign-in `answer.state` names, for the browser holding
    /// `browser_secret` in its correlation cookie.
    pub async fn complete_sign_in(
        &self,
        browser_secret: Option<&str>,
        answer: AuthorizationAnswer,
    ) -> Result<SignedIn, SignInFailure> {
        // A callback completes only the sign-in of the browser that started it
        // (RFC 6749 §10.12, RFC 9700 §4.7.1): otherwise an attacker's own
        // unused code, sent to a victim's browser, would sign the victim in to
        // the attacker's account.
        let secret = browser_secret.ok_or(SignInFailure::OtherBrowser)?;
        let connection = self
            .connection()
            .await
            .map_err(|e| SignInFailure::NotProvisioned(e.to_string()))?;
        // A sign-in started in another browser, or under another connection or
        // callback, is not found under this binding and stays where it is: for
        // its own browser, or a replica that still holds that connection.
        let pending = self
            .sessions
            .take_pending(&answer.state, &connection.browser_sign_in_binding(secret))
            .await
            // A store that cannot tell whether this state was already consumed
            // cannot rule out a replay.
            .map_err(|e| SignInFailure::Unavailable(e.to_string()))?
            .ok_or(SignInFailure::ExpiredOrUsed)?;

        // The answer must come from the application's issuer (RFC 9207 §2.4).
        if answer.iss.as_deref() != Some(connection.issuer.as_str()) {
            return Err(SignInFailure::WrongIssuer);
        }
        if let Some(error) = answer.error {
            return Err(SignInFailure::Refused {
                error,
                return_to: local_path(&pending.redirect_url),
            });
        }
        let code = answer.code.ok_or(SignInFailure::NoCode)?;
        let tokens = self
            .client
            .redeem(
                connection,
                code,
                pending.code_verifier.expose_secret().to_owned(),
            )
            .await
            .map_err(|e| SignInFailure::IssuerFailed(format!("code redemption: {e}")))?;
        let claims = SessionClaims::from(
            self.issuers
                .issued_access_token(
                    &connection.issuer,
                    &connection.resource,
                    &tokens.access_token,
                )
                .await
                .map_err(|e| {
                    SignInFailure::IssuerFailed(format!("not a token for the API: {e}"))
                })?,
        );
        // The ID token is this sign-in's (its nonce) and names its user, with
        // the Profile claims its issuer disclosed to this client there, if
        // any: they are taken from the verified token as received. A SID
        // issuer puts none there; a session then holds only its subject.
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or_else(|| SignInFailure::IssuerFailed("no ID token".into()))?;
        let identity = self
            .issuers
            .issued_id_token(
                &connection.issuer,
                &connection.client_id,
                &pending.nonce,
                id_token,
            )
            .await
            .map_err(|e| {
                SignInFailure::IssuerFailed(format!("not this sign-in's ID token: {e}"))
            })?;
        if identity.sub != claims.sub {
            return Err(SignInFailure::IssuerFailed(
                "the ID and access tokens name different users".into(),
            ));
        }
        let claims = SessionClaims {
            email: identity.email,
            name: identity.name,
            preferred_username: identity.preferred_username,
            ..claims
        };
        // A callback that arrives after the issuer ended this issuer session
        // opens nothing (Back-Channel Logout 1.0 §2.7).
        if self
            .sessions
            .ended_by_issuer(&claims)
            .await
            .map_err(|e| SignInFailure::NotStored(e.to_string()))?
        {
            return Err(SignInFailure::EndedAtIssuer);
        }
        let (session_id, _csrf) = self
            .sessions
            .create_session(
                SecretString::from(tokens.access_token),
                tokens.refresh_token.map(SecretString::from),
                claims,
                &connection.binding(),
            )
            .await
            .map_err(|e| SignInFailure::NotStored(e.to_string()))?;
        Ok(SignedIn {
            session_id,
            return_to: pending.redirect_url,
        })
    }

    /// The live session `request` names, for a read: the user's claims and
    /// the CSRF token the page echoes on its other calls.
    pub async fn read(&self, request: &BrowserRequest<'_>) -> Result<BffSession, SessionFailure> {
        self.require_the_page(request).await?;
        self.signed_in(request).await.map(|(_, session)| session)
    }

    /// The access token a call to the application's API carries for the
    /// signed-in user (RFC 6750 §2.1), refreshed first when it is about to
    /// expire or the API refused it.
    pub async fn bearer(&self, request: &BrowserRequest<'_>) -> Result<Bearer, SessionFailure> {
        self.require_the_page(request).await?;
        let (id, session) = self.signed_in(request).await?;
        if !request.safe && !csrf_matches(&request.csrf, &session.csrf_token) {
            return Err(SessionFailure::CsrfMismatch);
        }
        self.current_token(&id, session).await
    }

    /// Mark that the API refused the call `bearer` was presented with for
    /// want of a usable credential, so its session, while it still holds that
    /// token, refreshes before its next use.
    pub async fn refused(&self, bearer: &Bearer) -> Result<(), SessionFailure> {
        self.sessions
            .mark_token_refused(&bearer.session, &bearer.token)
            .await
            .map(|_| ())
            .map_err(|e| SessionFailure::unavailable("session store", e))
    }

    /// End the session `request` names and revoke its grant. A session
    /// already gone ends with nothing known of its grant.
    pub async fn end(&self, request: &BrowserRequest<'_>) -> Result<GrantOutcome, SessionFailure> {
        self.require_the_page(&BrowserRequest {
            safe: false,
            session: None,
            origins: request.origins.clone(),
            csrf: Vec::new(),
        })
        .await?;
        let id = request
            .session
            .as_deref()
            .ok_or(SessionFailure::NotSignedIn)?;
        match self.sessions.get_session(id).await {
            Ok(Some(session)) => {
                if !csrf_matches(&request.csrf, &session.csrf_token) {
                    return Err(SessionFailure::CsrfMismatch);
                }
                // The cookie must not be cleared while the session stays
                // usable by anyone holding its id.
                self.sessions
                    .destroy_session(id)
                    .await
                    .map_err(|e| SessionFailure::unavailable("session store", e))?;
                Ok(self.revoke_grant(session).await)
            }
            Ok(None) => Ok(GrantOutcome::Unknown),
            Err(e) => Err(SessionFailure::unavailable("session store", e)),
        }
    }

    /// The issuer's back-channel logout (Back-Channel Logout 1.0 §2.5–§2.8):
    /// the validated logout token's issuer session is recorded as ended.
    pub async fn receive_logout(&self, content_type: &str, body: &[u8]) -> LogoutReceipt {
        // §2.5: an `application/x-www-form-urlencoded` POST.
        let form = content_type.split(';').next().is_some_and(|t| {
            t.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
        if !form {
            return LogoutReceipt::Refused("the logout request is not a form");
        }
        let mut tokens = url::form_urlencoded::parse(body)
            .filter(|(name, _)| name == "logout_token")
            .map(|(_, value)| value.into_owned());
        let (Some(token), None) = (tokens.next(), tokens.next()) else {
            return LogoutReceipt::Refused("the form carries no single logout_token");
        };
        let connection = match self.connection().await {
            Ok(connection) => connection,
            Err(e) => {
                tracing::error!(error = %e, "no connection to the application's client");
                return LogoutReceipt::Unavailable;
            }
        };
        let claims = match self
            .issuers
            .issued_logout_token(&connection.issuer, &connection.client_id, &token)
            .await
        {
            Ok(claims) => claims,
            Err(IssuedTokenRefusal::Invalid(why)) => {
                tracing::warn!(%why, "back-channel logout token refused");
                return LogoutReceipt::Refused("the logout token is not valid");
            }
            Err(IssuedTokenRefusal::Unavailable(e)) => {
                tracing::warn!(error = %e, "issuer keys unavailable for a logout");
                return LogoutReceipt::Unavailable;
            }
        };
        // The client is registered with the session required (§2.2): a logout
        // naming no session is not one it accepts, never a subject-wide end.
        let Some(sid) = claims.sid.as_deref() else {
            return LogoutReceipt::Refused("the logout token names no session");
        };
        match self.sessions.record_issuer_logout(&claims.iss, sid).await {
            Ok(()) => LogoutReceipt::Recorded,
            Err(e) => {
                tracing::error!(error = %e, "cannot record the issuer's logout");
                LogoutReceipt::Unavailable
            }
        }
    }

    /// Refuse a request that can change something and is not the
    /// application's own page's: it must carry exactly one `Origin`, the
    /// origin of the application's registered callback. Another site's
    /// request carries the cookie but its own origin, or `null` (Fetch
    /// §3.2.5); CORS keeps a foreign page from reading the answer, not the
    /// request from arriving. A browser sends `Origin` with every request
    /// that is not `GET` or `HEAD` (Fetch §3.1).
    async fn require_the_page(&self, request: &BrowserRequest<'_>) -> Result<(), SessionFailure> {
        if request.safe {
            return Ok(());
        }
        let connection = self
            .connection()
            .await
            .map_err(|e| SessionFailure::unavailable("application connection", e))?;
        let expected = url::Url::parse(&connection.redirect_uri)
            .map(|callback| callback.origin().ascii_serialization())
            .map_err(|e| SessionFailure::unavailable("application connection", e))?;
        match request.origins.as_slice() {
            [origin] if *origin == expected.as_bytes() => Ok(()),
            _ => Err(SessionFailure::NotThePage),
        }
    }

    /// The session `request` names, when it is live, was made under this
    /// application's connection and its issuer session was not ended
    /// elsewhere.
    async fn signed_in(
        &self,
        request: &BrowserRequest<'_>,
    ) -> Result<(String, BffSession), SessionFailure> {
        // No cookie, or one naming no session, is a determinable refusal: the
        // connection is asked for only when there is a session to check.
        let id = request.session.clone().ok_or(SessionFailure::NotSignedIn)?;
        let session = self
            .sessions
            .get_session(&id)
            .await
            .map_err(|e| SessionFailure::unavailable("session store", e))?
            .ok_or(SessionFailure::NotSignedIn)?;
        let connection = self
            .connection()
            .await
            .map_err(|e| SessionFailure::unavailable("application connection", e))?;
        // A session of another connection (a bundle replaced since) is left in
        // place: during a rollout a replica of that connection shares the
        // store and still serves it.
        if session.connection != connection.binding() {
            return Err(SessionFailure::NotSignedIn);
        }
        // An issuer session ended elsewhere (sign-out on another device, an
        // administrator's kill) and known here ends this one with it. The
        // notices only arrive sooner than the issuer's own answer: without
        // them every call this session makes is still admitted by its issuer,
        // which refuses an ended session.
        let revoked = match self
            .revocation
            .is_revoked(&session.claims.jti, &session.claims.sid)
            .await
        {
            Ok(revoked) => revoked,
            Err(e) => {
                tracing::warn!(error = %e, "revocation notices unavailable");
                false
            }
        };
        // The issuer's back-channel logout is recorded in the session store
        // itself, the authority for this session: it reaches every replica
        // whatever cache the issuer publishes its notices to.
        let ended = revoked
            || self
                .sessions
                .ended_by_issuer(&session.claims)
                .await
                .map_err(|e| SessionFailure::unavailable("session store", e))?;
        if ended {
            if let Err(e) = self.sessions.destroy_session(&id).await {
                tracing::error!(error = %e, "cannot destroy an ended application session");
            }
            return Err(SessionFailure::NotSignedIn);
        }
        // The API refused the token this session holds: the issuer session may
        // have ended before its back-channel logout arrived here, or the token
        // alone is no longer usable. Its refresh tells which: a refused
        // refresh ends the session, a granted one replaces the token.
        if session.token_refused {
            self.current_token(&id, session).await?;
            let session = self
                .sessions
                .get_session(&id)
                .await
                .map_err(|e| SessionFailure::unavailable("session store", e))?
                .ok_or(SessionFailure::NotSignedIn)?;
            return Ok((id, session));
        }
        Ok((id, session))
    }

    /// Revoke the grant behind a destroyed session (RFC 7009 §2.1), so its
    /// refresh token dies with it. Only this needs the connection, so an
    /// unreachable issuer never keeps a user signed in.
    async fn revoke_grant(&self, session: BffSession) -> GrantOutcome {
        let Some(refresh_token) = session.refresh_token else {
            return GrantOutcome::None;
        };
        let connection = match self.connection().await {
            // A grant of another connection is not this client's to revoke.
            Ok(connection) if session.connection != connection.binding() => {
                return GrantOutcome::NotRevoked;
            }
            Ok(connection) => connection,
            Err(e) => {
                tracing::warn!(error = %e, "no connection; the grant was not revoked");
                return GrantOutcome::NotRevoked;
            }
        };
        match self
            .client
            .revoke(connection, refresh_token.expose_secret().to_owned())
            .await
        {
            Ok(()) => GrantOutcome::Revoked,
            Err(e) => {
                let outcome = match e {
                    GrantFailure::Uncertain(_) => GrantOutcome::Unknown,
                    GrantFailure::NotSent(_)
                    | GrantFailure::Refused(_)
                    | GrantFailure::Declined(_) => GrantOutcome::NotRevoked,
                };
                tracing::warn!(error = %e, ?outcome, "revocation failed");
                outcome
            }
        }
    }

    /// The session's access token, refreshed when it is due.
    ///
    /// One replica refreshes; the others wait for its result in the shared
    /// store. A refused refresh (the grant was revoked or expired) ends the
    /// session; a refresh that cannot be done now leaves it for the next call.
    ///
    /// A refresh whose answer was lost may still have rotated the token, so
    /// the next call presents the replaced one. The issuer accepts a replaced
    /// token for a grace window after its rotation and rotates again; after
    /// that window it reads the replay as theft, revokes the family and the
    /// refusal ends this session: the user signs in again, nothing is left
    /// holding a token the issuer no longer honours.
    async fn current_token(&self, id: &str, session: BffSession) -> Result<Bearer, SessionFailure> {
        let now = jiff::Timestamp::now().as_second();
        if !due(&session, now) {
            return Ok(Bearer::held(id, &session));
        }
        let Some(from) = session.refresh_token.clone() else {
            return Err(self.end_ended(id).await);
        };
        // The claim lapses after its hold whatever happens here, and another
        // replica may then present the same refresh token: everything up to
        // storing the result ends before, or is abandoned. Counted from before
        // the claim is made, so it never outlasts the claim.
        let deadline = tokio::time::Instant::now() + REFRESH_WORK;
        // The session read before the claim may predate a refresh another
        // replica completed under an earlier, now expired claim: the claim
        // hands back what the store holds now, so a refresh token already
        // rotated is never presented.
        let session = match self
            .sessions
            .claim_refresh(id, &from, REFRESH_HOLD, |current| due(current, now))
            .await
            .map_err(|e| SessionFailure::unavailable("session store", e))?
        {
            RefreshClaim::Claimed(current) => *current,
            RefreshClaim::Current(current) => return Ok(Bearer::held(id, &current)),
            RefreshClaim::HeldElsewhere => {
                return self
                    .refreshed_elsewhere(id, session.access_token.expose_secret())
                    .await;
            }
            RefreshClaim::Ended => return Err(SessionFailure::NotSignedIn),
        };
        tokio::time::timeout_at(deadline, self.refresh_claimed(id, session, now))
            .await
            .unwrap_or_else(|_| {
                Err(SessionFailure::unavailable(
                    "issuer",
                    "the refresh did not finish within its claim",
                ))
            })
    }

    /// The refresh of `session`, whose claim this caller holds.
    async fn refresh_claimed(
        &self,
        id: &str,
        session: BffSession,
        now: i64,
    ) -> Result<Bearer, SessionFailure> {
        if !due(&session, now) {
            return Ok(Bearer::held(id, &session));
        }
        let Some(refresh_token) = session.refresh_token.clone() else {
            return Err(self.end_ended(id).await);
        };
        let connection = self
            .connection()
            .await
            .map_err(|e| SessionFailure::unavailable("application connection", e))?;
        let tokens = match self
            .client
            .refresh(connection, refresh_token.expose_secret().to_owned())
            .await
        {
            Ok(tokens) => tokens,
            Err(GrantFailure::Refused(why)) => {
                tracing::info!(%why, "refresh refused, session ended");
                return Err(self.end_ended(id).await);
            }
            // The issuer could not serve it, nothing was sent, or the answer
            // was lost: the session stays, and a lost rotation is presented
            // again inside the issuer's grace window.
            Err(e) => return Err(SessionFailure::unavailable("issuer", e)),
        };
        let claims = self
            .issuers
            .issued_access_token(
                &connection.issuer,
                &connection.resource,
                &tokens.access_token,
            )
            .await
            .map_err(|e| SessionFailure::unavailable("issuer", e))?;
        let claims = SessionClaims::from(claims).refreshed(&session.claims);
        let access_token = SecretString::from(tokens.access_token);
        let replaced = Bearer {
            session: id.to_owned(),
            token: access_token.clone(),
        };
        match self
            .sessions
            .replace_tokens(
                id,
                &refresh_token,
                access_token,
                tokens.refresh_token.map(SecretString::from),
                claims,
            )
            .await
        {
            Ok(TokenReplacement::Replaced) => Ok(replaced),
            // A newer refresh landed first; its tokens stand.
            Ok(TokenReplacement::Superseded(current)) => Ok(Bearer::held(id, &current)),
            Ok(TokenReplacement::Ended) => Err(SessionFailure::NotSignedIn),
            Err(e) => Err(SessionFailure::unavailable("session store", e)),
        }
    }

    /// The token another replica's refresh stored, once it is there.
    async fn refreshed_elsewhere(&self, id: &str, stale: &str) -> Result<Bearer, SessionFailure> {
        let deadline = tokio::time::Instant::now() + REFRESH_HOLD;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(REFRESH_POLL).await;
            match self.sessions.get_session(id).await {
                Ok(Some(session)) if session.bearer() != stale => {
                    return Ok(Bearer::held(id, &session));
                }
                Ok(Some(_)) => {}
                Ok(None) => return Err(SessionFailure::NotSignedIn),
                Err(e) => return Err(SessionFailure::unavailable("session store", e)),
            }
        }
        Err(SessionFailure::unavailable(
            "session store",
            "another replica's refresh did not finish",
        ))
    }

    /// Destroy a session whose grant ended; the user signs in again.
    async fn end_ended(&self, id: &str) -> SessionFailure {
        match self.sessions.destroy_session(id).await {
            Ok(()) => SessionFailure::NotSignedIn,
            Err(e) => SessionFailure::unavailable("session store", e),
        }
    }
}

/// Whether `session`'s access token is refreshed before its use at `now`: it
/// is about to expire, or the API refused it.
fn due(session: &BffSession, now: i64) -> bool {
    session.token_refused || session.claims.exp - now <= REFRESH_MARGIN_SECS
}

/// The value of the cookie `name` in the request's `Cookie` headers, when it
/// is present exactly once: a `__Host-` cookie has one host and one path, so
/// a browser never sends two, and two would be ambiguous.
pub fn cookie_value<'a>(headers: impl IntoIterator<Item = &'a str>, name: &str) -> Option<String> {
    let mut found = None;
    for header in headers {
        // RFC 6265bis §4.2.1: cookie-pair *( ";" SP cookie-pair ).
        for pair in header.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

/// Whether the request echoes `expected` in exactly one CSRF header, compared
/// in constant time: a mismatch says nothing about how much of a guess was
/// right.
fn csrf_matches(sent: &[&[u8]], expected: &str) -> bool {
    match sent {
        [value] => bool::from(value.ct_eq(expected.as_bytes())),
        _ => false,
    }
}

/// A path on this origin to return to after sign-in; anything else, which
/// would make the adapter an open redirector (RFC 9700 §4.11), is the root.
/// `//host` and `/\host` are other origins to a browser.
fn local_path(requested: &str) -> String {
    if requested.starts_with('/')
        && !requested.starts_with("//")
        && !requested.starts_with("/\\")
        && !requested.chars().any(char::is_control)
    {
        requested.to_owned()
    } else {
        "/".to_owned()
    }
}

/// 256 random bits, base64url: a PKCE verifier (RFC 7636 §4.1), a nonce or
/// a browser's sign-in secret.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests;
