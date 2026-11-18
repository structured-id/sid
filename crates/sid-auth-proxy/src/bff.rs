// SPDX-License-Identifier: AGPL-3.0-only
//! BFF (Backend-For-Frontend) sign-in for the account application, over HTTP:
//! the routes read the cookie, `Origin` and CSRF headers into a
//! [`BrowserRequest`] for the shared [`BrowserSessions`] and answer with its
//! outcomes.
//! - `/auth/login`: starts a sign-in at the integration's issuer
//! - `/auth/callback`: completes it, sets the session cookie
//! - `/auth/logout`: ends the session and revokes its grant
//! - `/auth/userinfo`: the signed-in user, from the session
//! - `/api/*`: the account API, see [`crate::api`]

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use sid_authn::application_session::{
    AuthorizationAnswer, BrowserRequest, BrowserSessions, GrantOutcome, SessionFailure,
    SignInFailure, cookie_value,
};
use sid_infra::issuer_client::RpClient;

use crate::ProxyState;

/// The header a page echoes its session's CSRF token in.
const CSRF_HEADER: &str = "x-csrf-token";

/// BFF routes.
pub fn routes() -> Router<ProxyState> {
    Router::new()
        .route("/auth/login", get(login_handler))
        .route("/auth/callback", get(callback_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route("/api/{*path}", any(crate::api::api_handler))
}

/// The BFF's sessions, or 404 when the BFF is off.
pub(crate) fn sessions(state: &ProxyState) -> Result<&BrowserSessions<RpClient>, StatusCode> {
    state.bff.as_deref().ok_or(StatusCode::NOT_FOUND)
}

/// What a request with `headers` carries for a session check. `GET`, `HEAD`
/// and `OPTIONS` change nothing, so they are safe.
pub(crate) fn browser_request<'a>(
    sessions: &BrowserSessions<RpClient>,
    headers: &'a HeaderMap,
    method: &Method,
) -> BrowserRequest<'a> {
    BrowserRequest {
        session: cookie_value(cookies(headers), sessions.cookie()),
        origins: headers
            .get_all("origin")
            .iter()
            .map(|value| value.as_bytes())
            .collect(),
        csrf: headers
            .get_all(CSRF_HEADER)
            .iter()
            .map(|value| value.as_bytes())
            .collect(),
        safe: matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS),
    }
}

/// The request's `Cookie` header values.
fn cookies(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
}

/// The HTTP refusal of a session request. An outage must not look like a
/// signed-out user, or every browser signs itself out at once.
pub(crate) fn refusal(failure: SessionFailure) -> StatusCode {
    match failure {
        SessionFailure::NotSignedIn => StatusCode::UNAUTHORIZED,
        SessionFailure::NotThePage | SessionFailure::CsrfMismatch => {
            tracing::warn!(error = %failure, "BFF: request refused");
            StatusCode::FORBIDDEN
        }
        SessionFailure::Unavailable { .. } => {
            tracing::error!(error = %failure, "BFF: cannot answer");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// The `Secure` attribute, left off only in development over plain HTTP.
fn secure(state: &ProxyState) -> &'static str {
    if state.bff_dev_mode { "" } else { " Secure;" }
}

/// `GET /auth/login`: redirect to the issuer's authorization endpoint.
async fn login_handler(
    State(state): State<ProxyState>,
    Query(params): Query<LoginParams>,
) -> Response {
    let sessions = match sessions(&state) {
        Ok(sessions) => sessions,
        Err(status) => return status.into_response(),
    };
    let start = match sessions
        .start_sign_in(params.rd.as_deref().unwrap_or_default())
        .await
    {
        Ok(start) => start,
        Err(e) => {
            tracing::error!(error = %e, "BFF login: the sign-in cannot start");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut response = redirect(start.authorize_url.as_str());
    let correlation = format!(
        "{}={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age={}",
        sessions.sign_in_cookie(&start.state),
        start.browser_secret,
        secure(&state),
        sessions.pending_ttl().as_secs()
    );
    if let Ok(val) = correlation.parse() {
        response.headers_mut().append("set-cookie", val);
    }
    response
}

/// Query parameters for login.
#[derive(Debug, serde::Deserialize)]
struct LoginParams {
    /// Where on the account origin to return after sign-in.
    rd: Option<String>,
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

/// `GET /auth/callback`: complete the sign-in.
async fn callback_handler(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let sessions = match sessions(&state) {
        Ok(sessions) => sessions,
        Err(status) => return status.into_response(),
    };
    let correlation = sessions.sign_in_cookie(&params.state);
    let secret = cookie_value(cookies(&headers), &correlation);
    let answer = AuthorizationAnswer {
        state: params.state,
        code: params.code,
        error: params.error,
        iss: params.iss,
    };
    let (mut response, taken) = match sessions.complete_sign_in(secret.as_deref(), answer).await {
        Ok(signed_in) => {
            let mut response = redirect(&signed_in.return_to);
            // The session's CSRF token reaches the page with the session check
            // (`/auth/userinfo`), never in a cookie the page would have to find.
            let cookie = format!(
                "{}={}; Path=/; HttpOnly;{} SameSite=Lax",
                sessions.cookie(),
                signed_in.session_id,
                secure(&state),
            );
            if let Ok(val) = cookie.parse() {
                response.headers_mut().append("set-cookie", val);
            }
            (response, true)
        }
        Err(failure) => {
            tracing::warn!(error = %failure, "BFF callback: the sign-in did not complete");
            (
                sign_in_status(&failure).into_response(),
                failure.took_the_sign_in(),
            )
        }
    };
    // A taken sign-in clears its correlation cookie, whatever came of it, and
    // only its own.
    if taken {
        let cleared = format!(
            "{correlation}=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
            secure(&state)
        );
        if let Ok(val) = cleared.parse() {
            response.headers_mut().append("set-cookie", val);
        }
    }
    response
}

/// The status of a sign-in that did not complete.
fn sign_in_status(failure: &SignInFailure) -> StatusCode {
    match failure {
        SignInFailure::OtherBrowser
        | SignInFailure::ExpiredOrUsed
        | SignInFailure::WrongIssuer
        | SignInFailure::NoCode => StatusCode::BAD_REQUEST,
        SignInFailure::Refused { .. } | SignInFailure::EndedAtIssuer => StatusCode::FORBIDDEN,
        SignInFailure::IssuerFailed(_) => StatusCode::BAD_GATEWAY,
        SignInFailure::NotProvisioned(_)
        | SignInFailure::Unavailable(_)
        | SignInFailure::NotStored(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// `POST /auth/logout`: end the BFF session. Requires the page's `Origin`
/// and the CSRF token. Answers `{"grant": "revoked" | "not_revoked" | "none"
/// | "unknown"}`.
///
/// Ends the application session only: the IdP's own sign-in session is the
/// IdP's to end (RP-initiated logout), and the account UI does that itself.
async fn logout_handler(
    State(state): State<ProxyState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let sessions = match sessions(&state) {
        Ok(sessions) => sessions,
        Err(status) => return status.into_response(),
    };
    let grant = match sessions
        .end(&browser_request(sessions, &headers, &method))
        .await
    {
        Ok(grant) => grant,
        Err(failure) => return refusal(failure).into_response(),
    };
    let clear_session = format!(
        "{}=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sessions.cookie(),
        secure(&state),
    );
    let mut response = Json(serde_json::json!({ "grant": grant_name(grant) })).into_response();
    if let Ok(val) = clear_session.parse() {
        response.headers_mut().append("set-cookie", val);
    }
    response
}

/// The wire name of a grant outcome.
fn grant_name(grant: GrantOutcome) -> &'static str {
    match grant {
        GrantOutcome::Revoked => "revoked",
        GrantOutcome::NotRevoked => "not_revoked",
        GrantOutcome::None => "none",
        GrantOutcome::Unknown => "unknown",
    }
}

/// `GET /auth/userinfo`: the signed-in user, from the session, with the
/// session's CSRF token, which every state-changing call echoes in
/// `X-CSRF-Token`. Same-origin only: no other origin can read the answer.
async fn userinfo_handler(
    State(state): State<ProxyState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let sessions = match sessions(&state) {
        Ok(sessions) => sessions,
        Err(status) => return status.into_response(),
    };
    let session = match sessions
        .read(&browser_request(sessions, &headers, &method))
        .await
    {
        Ok(session) => session,
        Err(failure) => return refusal(failure).into_response(),
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

/// A `302 Found` to `location`.
fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(val) = location.parse() {
        response.headers_mut().insert("location", val);
    }
    response
}

#[cfg(test)]
pub(crate) mod tests;
