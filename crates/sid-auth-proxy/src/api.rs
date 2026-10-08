// SPDX-License-Identifier: AGPL-3.0-only
//! `/api/*`: the account API through the BFF. The browser sends its session
//! cookie and CSRF token; the BFF forwards the request to the account API
//! with the session's access token as `Authorization: Bearer` (RFC 6750
//! §2.1), refreshing it first when it is about to expire. Neither the cookie
//! nor the CSRF token reaches the API, and nothing the API sets as a cookie
//! reaches the browser.

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::ProxyState;
use crate::bff::{connected, csrf_matches, signed_in, verified_claims};
use crate::session::BffSession;

/// An access token this close to expiry is refreshed before use, so it does
/// not expire between the BFF and the API.
const REFRESH_MARGIN_SECS: i64 = 30;
/// How long one replica holds a session's refresh: longer than a token
/// endpoint call.
const REFRESH_HOLD: Duration = Duration::from_secs(15);
/// How often a replica that did not win the refresh looks for its result.
const REFRESH_POLL: Duration = Duration::from_millis(200);

/// Hop-by-hop headers (RFC 9110 §7.6.1) and the ones the BFF owns: none
/// crosses it in either direction.
const NOT_FORWARDED: &[HeaderName] = &[
    header::CONNECTION,
    header::HOST,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::COOKIE,
    header::SET_COOKIE,
    header::AUTHORIZATION,
];

/// `ANY /api/{*path}`: the account API as the signed-in user.
pub async fn api_handler(
    State(state): State<ProxyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Body,
) -> Response {
    let (session_id, session) = match signed_in(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    // Every API call changes or reads account data on the user's behalf, so
    // a request another site can make the browser send is refused: the
    // session's CSRF token, handed to the page with its session check,
    // proves the page on this origin sent it.
    if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        && !csrf_matches(&headers, &session)
    {
        tracing::warn!("BFF API: CSRF token mismatch");
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(upstream) = state.api_upstream.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(target) = api_target(upstream, &path, uri.query()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let access_token = match current_token(&state, &session_id, session).await {
        Ok(token) => token,
        Err(status) => return status.into_response(),
    };

    let mut forwarded = reqwest::header::HeaderMap::new();
    for (name, value) in &headers {
        if !NOT_FORWARDED.contains(name) && name != "x-csrf-token" {
            forwarded.append(name.clone(), value.clone());
        }
    }
    if let Ok(bearer) = format!("Bearer {access_token}").parse() {
        forwarded.insert(header::AUTHORIZATION, bearer);
    }
    if let Ok(peer) = peer.ip().to_string().parse() {
        forwarded.append("x-forwarded-for", peer);
    }

    let answer = match state
        .http
        .request(method, target)
        .headers(forwarded)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
    {
        Ok(answer) => answer,
        Err(e) => {
            tracing::error!(error = %e, "BFF API: the account API did not answer");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let mut response = Response::builder().status(answer.status());
    if let Some(out) = response.headers_mut() {
        for (name, value) in answer.headers() {
            if !NOT_FORWARDED.contains(name) {
                out.append(name.clone(), value.clone());
            }
        }
    }
    response
        .body(Body::from_stream(answer.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// The account API URL for `path` under `upstream`, or `None` for a path
/// that would leave it (a `..` segment, or one the URL parser resolves
/// elsewhere).
fn api_target(upstream: &url::Url, path: &str, query: Option<&str>) -> Option<url::Url> {
    if path.split('/').any(|segment| segment == "..") {
        return None;
    }
    let base = upstream.as_str().trim_end_matches('/');
    let mut target = url::Url::parse(&format!("{base}/{path}")).ok()?;
    target.set_query(query);
    let stays = target.origin() == upstream.origin()
        && target
            .path()
            .starts_with(upstream.path().trim_end_matches('/'));
    stays.then_some(target)
}

/// The session's access token, refreshed first when it is about to expire.
///
/// One replica refreshes; the others wait for its result in the shared
/// store. A refused refresh (the grant was revoked or expired) ends the
/// session: 401. A refresh that cannot be done now is 503, and the session
/// stays for the next request.
async fn current_token(
    state: &ProxyState,
    session_id: &str,
    session: BffSession,
) -> Result<String, StatusCode> {
    let now = chrono::Utc::now().timestamp();
    if session.claims.exp - now > REFRESH_MARGIN_SECS {
        return Ok(session.access_token);
    }
    let Some(refresh_token) = session.refresh_token else {
        return Err(end_session(state, session_id).await);
    };
    let claimed = state
        .bff_sessions
        .claim_refresh(session_id, REFRESH_HOLD)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "BFF API: cannot claim the refresh");
            StatusCode::SERVICE_UNAVAILABLE
        })?;
    if !claimed {
        return refreshed_elsewhere(state, session_id, &session.access_token).await;
    }

    let (link, connection) = connected(state).await?;
    let tokens = match link.refresh(connection, refresh_token).await {
        Ok(tokens) => tokens,
        Err(crate::account::LinkError::Rpc(status)) if !transient(&status) => {
            tracing::info!(error = %status, "BFF API: refresh refused, session ended");
            return Err(end_session(state, session_id).await);
        }
        Err(e) => {
            tracing::error!(error = %e, "BFF API: refresh failed");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let mut claims = verified_claims(state, connection, &tokens.access_token).await?;
    // The profile claims came from the sign-in's ID token; a refreshed
    // access token carries none, and the user is the same.
    claims.email = session.claims.email;
    claims.name = session.claims.name;
    claims.preferred_username = session.claims.preferred_username;
    claims.groups = session.claims.groups;
    match state
        .bff_sessions
        .replace_tokens(
            session_id,
            tokens.access_token.clone(),
            tokens.refresh_token,
            claims,
        )
        .await
    {
        Ok(true) => Ok(tokens.access_token),
        Ok(false) => Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            tracing::error!(error = %e, "BFF API: cannot store the refreshed tokens");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// The token another replica's refresh stored, once it is there.
async fn refreshed_elsewhere(
    state: &ProxyState,
    session_id: &str,
    stale: &str,
) -> Result<String, StatusCode> {
    let deadline = tokio::time::Instant::now() + REFRESH_HOLD;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(REFRESH_POLL).await;
        match state.bff_sessions.get_session(session_id).await {
            Ok(Some(session)) if session.access_token != stale => {
                return Ok(session.access_token);
            }
            Ok(Some(_)) => {}
            Ok(None) => return Err(StatusCode::UNAUTHORIZED),
            Err(e) => {
                tracing::error!(error = %e, "BFF API: cannot read the session");
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        }
    }
    tracing::warn!("BFF API: another replica's refresh did not finish");
    Err(StatusCode::SERVICE_UNAVAILABLE)
}

/// Whether a refused call may succeed if repeated: SID or the path to it
/// failed, not the grant.
fn transient(status: &tonic::Status) -> bool {
    use tonic::Code;
    matches!(
        status.code(),
        Code::Unavailable
            | Code::DeadlineExceeded
            | Code::Internal
            | Code::Unknown
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Cancelled
    )
}

/// Destroy the session and answer 401: the user signs in again.
async fn end_session(state: &ProxyState, session_id: &str) -> StatusCode {
    if let Err(e) = state.bff_sessions.destroy_session(session_id).await {
        tracing::error!(error = %e, "BFF API: cannot destroy an ended session");
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::UNAUTHORIZED
}

#[cfg(test)]
mod tests;
