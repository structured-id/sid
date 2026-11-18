// SPDX-License-Identifier: AGPL-3.0-only
//! `/api/*`: the account API through the BFF. The browser sends its session
//! cookie and CSRF token; the BFF forwards the request to the account API
//! with the session's access token as `Authorization: Bearer` (RFC 6750
//! §2.1), refreshed first when it is due. Neither the cookie nor the CSRF
//! token reaches the API, and nothing the API sets as a cookie reaches the
//! browser.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;

use crate::ProxyState;
use crate::bff::{browser_request, refusal, sessions};

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
    let sessions = match sessions(&state) {
        Ok(sessions) => sessions,
        Err(status) => return status.into_response(),
    };
    let Some(upstream) = state.api_upstream.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(target) = api_target(upstream, &path, uri.query()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // A request that can change account data must come from the page on this
    // origin and echo the session's CSRF token, handed to the page with its
    // session check: another site can make the browser send it, but not that.
    let bearer = match sessions
        .bearer(&browser_request(sessions, &headers, &method))
        .await
    {
        Ok(bearer) => bearer,
        Err(failure) => return refusal(failure).into_response(),
    };

    let mut forwarded = reqwest::header::HeaderMap::new();
    for (name, value) in &headers {
        if !NOT_FORWARDED.contains(name) && name != "x-csrf-token" {
            forwarded.append(name.clone(), value.clone());
        }
    }
    if let Ok(value) = format!("Bearer {}", bearer.token().expose_secret()).parse() {
        forwarded.insert(header::AUTHORIZATION, value);
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
    // The API refused the token for want of a usable credential: a gRPC-Web
    // answer carries `UNAUTHENTICATED` (16) in its headers when it has no
    // body. The session refreshes before its next use, which tells an ended
    // grant from a token that alone is no longer usable.
    if answer
        .headers()
        .get("grpc-status")
        .is_some_and(|status| status.as_bytes() == b"16")
        && let Err(failure) = sessions.refused(&bearer).await
    {
        return refusal(failure).into_response();
    }

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

#[cfg(test)]
mod tests;
