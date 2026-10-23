// SPDX-License-Identifier: AGPL-3.0-only
//! BFF (Backend-For-Frontend) sign-in for the account application.
//!
//! The BFF is the account integration's confidential client: it signs users
//! in with the code flow, S256 PKCE and its key (`private_key_jwt`), keeps
//! the tokens server-side and gives the browser only an HttpOnly session
//! cookie and a CSRF token.
//! - `/auth/login`: starts a sign-in at the integration's issuer
//! - `/auth/callback`: redeems the code, sets the session cookie
//! - `/auth/logout`: revokes the grant, clears the session and cookies
//! - `/auth/userinfo`: the signed-in user, from the session
//! - `/api/*`: the account API, see [`crate::api`]

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use subtle::ConstantTimeEq;

use crate::ProxyState;
use secrecy::{ExposeSecret, SecretString};
use sid_authn::bff_session::{BffSession, SessionClaims};

use sid_authn::rp_client::{Connection, RpClient, RpClientError};

/// BFF routes.
pub fn routes() -> Router<ProxyState> {
    Router::new()
        .route("/auth/login", get(login_handler))
        .route("/auth/callback", get(callback_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route("/api/{*path}", any(crate::api::api_handler))
}

/// The account link and its connection, or the answer when the BFF is off
/// (404) or SID has not provisioned the integration yet (503).
pub(crate) async fn connected(state: &ProxyState) -> Result<(&RpClient, &Connection), StatusCode> {
    let Some(link) = state.bff() else {
        return Err(StatusCode::NOT_FOUND);
    };
    match link.connection().await {
        Ok(connection) => Ok((link, connection)),
        Err(e) => {
            tracing::error!(error = %e, "BFF: no connection to the account integration");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// `GET /auth/login`: redirect to the issuer's authorization endpoint.
async fn login_handler(
    State(state): State<ProxyState>,
    Query(params): Query<LoginParams>,
) -> Response {
    let (_, connection) = match connected(&state).await {
        Ok(pair) => pair,
        Err(status) => return status.into_response(),
    };

    let code_verifier = generate_pkce_verifier();
    let code_challenge = generate_pkce_challenge(&code_verifier);
    // Same shape and strength as the verifier: 256 random bits.
    let nonce = generate_pkce_verifier();
    let return_to = local_path(params.rd.as_deref());

    // Without a store there is no login to start: sending the user on with a
    // state nobody can verify would make the callback unverifiable.
    let state_param = match state
        .bff_sessions
        .store_pending(
            SecretString::from(code_verifier),
            nonce.clone(),
            return_to,
            &connection.sign_in_binding(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "BFF login: cannot record the pending authorization");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    redirect(
        connection
            .authorize_url(&code_challenge, &state_param, &nonce)
            .as_str(),
    )
}

/// Query parameters for login.
#[derive(Debug, serde::Deserialize)]
struct LoginParams {
    /// Where on the account origin to return after sign-in.
    rd: Option<String>,
}

/// A path on this origin to return to after sign-in; anything else, which
/// would make the BFF an open redirector (RFC 9700 §4.11), is the root.
/// `//host` and `/\host` are other origins to a browser.
fn local_path(requested: Option<&str>) -> String {
    match requested {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && !path.starts_with("/\\")
                && !path.chars().any(char::is_control) =>
        {
            path.to_owned()
        }
        _ => "/".to_owned(),
    }
}

/// `GET /auth/callback`: redeem the authorization code.
async fn callback_handler(
    State(state): State<ProxyState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let (link, connection) = match connected(&state).await {
        Ok(pair) => pair,
        Err(status) => return status.into_response(),
    };

    // A sign-in started under another connection or callback (a bundle
    // replaced since) is not found under this one, and stays for a replica
    // that still holds that connection.
    let pending = match state
        .bff_sessions
        .take_pending(&params.state, &connection.sign_in_binding())
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(
                "BFF callback: unknown, expired, already used or another connection's state"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
        Err(e) => {
            // A store that cannot tell whether this state was already
            // consumed cannot rule out a replay.
            tracing::error!(error = %e, "BFF callback: cannot claim the pending authorization");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    // The answer must come from the integration's issuer (RFC 9207 §2.4).
    if params.iss.as_deref() != Some(connection.issuer.as_str()) {
        tracing::warn!("BFF callback: authorization response from another issuer");
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(error) = &params.error {
        tracing::warn!(error = %error, "BFF callback: authorization error");
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(code) = params.code else {
        tracing::warn!("BFF callback: missing authorization code");
        return StatusCode::BAD_REQUEST.into_response();
    };

    let tokens = match link
        .redeem(
            connection,
            code,
            pending.code_verifier.expose_secret().to_owned(),
        )
        .await
    {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::error!(error = %e, "BFF callback: code redemption failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let mut claims = match verified_claims(&state, connection, &tokens.access_token).await {
        Ok(claims) => claims,
        Err(status) => return status.into_response(),
    };
    // The ID token is this sign-in's (its nonce) and the user's profile
    // claims come from it; an access token carries none (RFC 9068 §2.2).
    let Some(id_token) = tokens.id_token.as_deref() else {
        tracing::error!("BFF callback: no ID token for an openid sign-in");
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let identity = match state
        .issuers
        .issued_id_token(
            &connection.issuer,
            &connection.client_id,
            &pending.nonce,
            id_token,
        )
        .await
    {
        Ok(identity) => identity,
        Err(e) => {
            tracing::error!(error = %e, "BFF callback: the ID token is not this sign-in's");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    if identity.sub != claims.sub {
        tracing::error!("BFF callback: ID and access tokens name different users");
        return StatusCode::BAD_GATEWAY.into_response();
    }
    claims.email = identity.email;
    claims.name = identity.name;
    claims.preferred_username = identity.preferred_username;

    // The session's CSRF token reaches the page with the session check
    // (`/auth/userinfo`), never in a cookie the page would have to find.
    let (session_id, _csrf_token) = match state
        .bff_sessions
        .create_session(
            SecretString::from(tokens.access_token),
            tokens.refresh_token.map(SecretString::from),
            claims,
            &connection.binding(),
        )
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "BFF callback: cannot store the session");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let secure_flag = if state.bff_dev_mode { "" } else { " Secure;" };
    let session_cookie = format!(
        "{}={session_id}; Path=/; HttpOnly;{secure_flag} SameSite=Lax",
        state.bff_cookie_name,
    );
    let mut response = redirect(&pending.redirect_url);
    if let Ok(val) = session_cookie.parse() {
        response.headers_mut().append("set-cookie", val);
    }
    response
}

/// The claims of an access token SID just issued to the BFF: the
/// integration's issuer, its keys, typed `at+jwt`, for the account API
/// (RFC 9068 §4). Anything else is SID misbehaving, not the user.
pub(crate) async fn verified_claims(
    state: &ProxyState,
    connection: &Connection,
    token: &str,
) -> Result<SessionClaims, StatusCode> {
    state
        .issuers
        .issued_access_token(&connection.issuer, &connection.resource, token)
        .await
        .map(SessionClaims::from)
        .map_err(|e| {
            tracing::error!(error = %e, "BFF: issued token is not for the account API");
            StatusCode::BAD_GATEWAY
        })
}

/// Query parameters for callback.
#[derive(Debug, serde::Deserialize)]
struct CallbackParams {
    state: String,
    code: Option<String>,
    error: Option<String>,
    /// The issuer that answered (RFC 9207 §2).
    iss: Option<String>,
}

/// `POST /auth/logout`: end the BFF session. Requires the CSRF token.
/// Answers `{"grant": "revoked" | "not_revoked" | "none" | "unknown"}`.
///
/// Ends the application session only: the IdP's own sign-in session is the
/// IdP's to end (RP-initiated logout), and the account UI does that itself.
async fn logout_handler(
    State(state): State<ProxyState>,
    headers: axum::http::HeaderMap,
) -> Response {
    if state.bff().is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Without a cookie there is nothing to end, whatever SID can answer.
    let Some(session_id) = extract_bff_cookie(&headers, &state.bff_cookie_name) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let grant = match state.bff_sessions.get_session(&session_id).await {
        Ok(Some(session)) => {
            if !csrf_matches(&headers, &session) {
                tracing::warn!("BFF logout: CSRF token mismatch");
                return StatusCode::FORBIDDEN.into_response();
            }
            if let Err(e) = state.bff_sessions.destroy_session(&session_id).await {
                // The cookies below would be cleared while the session stayed
                // usable by anyone holding its id. Say so instead.
                tracing::error!(error = %e, "BFF logout: cannot destroy the session");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            revoke_grant(&state, session).await
        }
        // Already gone, perhaps expired with its grant still alive: clear the
        // cookies anyway, and say nothing is known of the grant.
        Ok(None) => GrantOutcome::Unknown,
        Err(e) => {
            tracing::error!(error = %e, "BFF logout: cannot read the session");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let secure_flag = if state.bff_dev_mode { "" } else { " Secure;" };
    let clear_session = format!(
        "{}=; Path=/; HttpOnly;{secure_flag} SameSite=Lax; Max-Age=0",
        state.bff_cookie_name,
    );
    let mut response = Json(LogoutResult { grant }).into_response();
    if let Ok(val) = clear_session.parse() {
        response.headers_mut().append("set-cookie", val);
    }
    response
}

/// What `POST /auth/logout` answers once the session is ended.
#[derive(serde::Serialize)]
struct LogoutResult {
    grant: GrantOutcome,
}

/// What became of the grant behind an ended session.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum GrantOutcome {
    /// The issuer revoked it: its refresh token no longer works.
    Revoked,
    /// The session held a grant the issuer did not revoke; it lives until
    /// it expires, though nobody holds its token any more.
    NotRevoked,
    /// No grant stood behind the session.
    None,
    /// Not known: the session was already gone, or the revocation's answer
    /// was lost after it may have been committed.
    Unknown,
}

/// The outcome of a revocation call that failed. A refusal SID answered
/// leaves the grant alive; a call whose answer was lost or broken may have
/// been committed (gRPC status codes, `Unavailable` to `DataLoss`).
fn revocation_failure(failure: &RpClientError) -> GrantOutcome {
    use tonic::Code;
    match failure {
        RpClientError::Rpc(status) => match status.code() {
            Code::Unavailable
            | Code::Cancelled
            | Code::DeadlineExceeded
            | Code::Unknown
            | Code::Internal
            | Code::Aborted
            | Code::DataLoss => GrantOutcome::Unknown,
            _ => GrantOutcome::NotRevoked,
        },
        // Nothing was sent.
        RpClientError::Invalid(_) | RpClientError::Key(_) => GrantOutcome::NotRevoked,
    }
}

/// Revoke the grant behind a destroyed session (RFC 7009 §2.1), so its
/// refresh token dies with it. This is the only part of logout that needs
/// the connection, so SID being unreachable never keeps a user signed in;
/// the outcome tells the caller whether the grant went with the session.
async fn revoke_grant(state: &ProxyState, session: BffSession) -> GrantOutcome {
    let Some(refresh_token) = session.refresh_token else {
        return GrantOutcome::None;
    };
    let Some(link) = state.bff() else {
        return GrantOutcome::NotRevoked;
    };
    let connection = match link.connection().await {
        // A grant of another connection is not this client's to revoke.
        Ok(connection) if session.connection != connection.binding() => {
            return GrantOutcome::NotRevoked;
        }
        Ok(connection) => connection,
        // No revocation was sent.
        Err(e) => {
            tracing::warn!(error = %e, "BFF logout: no connection; the grant was not revoked");
            return GrantOutcome::NotRevoked;
        }
    };
    match link
        .revoke(connection, refresh_token.expose_secret().to_owned())
        .await
    {
        Ok(()) => GrantOutcome::Revoked,
        Err(e) => {
            let outcome = revocation_failure(&e);
            tracing::warn!(error = %e, ?outcome, "BFF logout: revocation failed");
            outcome
        }
    }
}

/// `GET /auth/userinfo`: the signed-in user, from the session, with the
/// session's CSRF token, which every state-changing call echoes in
/// `X-CSRF-Token`. Same-origin only: no other origin can read the answer.
async fn userinfo_handler(
    State(state): State<ProxyState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let (_, session) = match signed_in(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let claims = &session.claims;
    Json(serde_json::json!({
        "sub": claims.sub,
        "email": claims.email,
        "name": claims.name,
        "preferred_username": claims.preferred_username,
        "groups": claims.groups,
        "acr": claims.acr,
        "roles": claims.roles,
        "csrf_token": session.csrf_token,
    }))
    .into_response()
}

/// The session the request's cookie names, when it is live, was made under
/// this BFF's connection and its SID session was not ended elsewhere. 404
/// with the BFF off, 401 without a live session, 503 when that cannot be
/// told: an outage must not look like a signed-out user, or every browser
/// signs itself out at once.
pub(crate) async fn signed_in(
    state: &ProxyState,
    headers: &axum::http::HeaderMap,
) -> Result<(String, BffSession), StatusCode> {
    if state.bff().is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    // No cookie, or one naming no session, is a determinable 401: the
    // connection is asked for only when there is a session whose binding it
    // must check.
    let Some(session_id) = extract_bff_cookie(headers, &state.bff_cookie_name) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let session = match state.bff_sessions.get_session(&session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            tracing::error!(error = %e, "BFF: cannot read the session");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let (_, connection) = connected(state).await?;
    // Tokens issued to another client, by another issuer or for another API
    // (a connection replaced since) are not used under this one.
    // The session is left in place: during a rollout a replica holding its
    // connection shares the cache and still serves it. One whose connection
    // is gone everywhere expires with its idle window.
    if session.connection != connection.binding() {
        tracing::info!("BFF: session of another connection refused");
        return Err(StatusCode::UNAUTHORIZED);
    }
    // A SID session ended elsewhere (sign-out on another device, an
    // administrator's kill) ends this BFF session with it.
    match state
        .revocation
        .is_revoked(&session.claims.jti, &session.claims.sid)
        .await
    {
        Ok(false) => Ok((session_id, session)),
        Ok(true) => {
            if let Err(e) = state.bff_sessions.destroy_session(&session_id).await {
                tracing::error!(error = %e, "BFF: cannot destroy a revoked session");
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        Err(e) => {
            tracing::error!(error = %e, "BFF: revocation check unavailable");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Whether the request echoes the session's CSRF token in `X-CSRF-Token`,
/// compared in constant time: `!=` returns at the first differing byte and
/// tells a caller how much of its guess was right.
pub(crate) fn csrf_matches(headers: &axum::http::HeaderMap, session: &BffSession) -> bool {
    let sent = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    bool::from(sent.as_bytes().ct_eq(session.csrf_token.as_bytes()))
}

/// A `302 Found` to `location`.
fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(val) = location.parse() {
        response.headers_mut().insert("location", val);
    }
    response
}

/// Extract BFF session cookie value from request headers.
fn extract_bff_cookie(headers: &axum::http::HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    let prefix = format!("{}=", cookie_name);
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&prefix) {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Generate a random PKCE code verifier (43-128 chars, URL-safe base64).
fn generate_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("failed to generate random bytes");
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate PKCE code challenge (S256) from verifier.
fn generate_pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

impl ProxyState {
    /// The BFF's client, when the BFF answers: the configured switch and a
    /// client key together. Inferring the switch from the key alone would
    /// give two answers to one question.
    pub fn bff(&self) -> Option<&RpClient> {
        self.account.as_deref().filter(|_| self.bff_enabled)
    }
}

#[cfg(test)]
pub(crate) mod tests;
