// SPDX-License-Identifier: AGPL-3.0-only
//! The installation session on a selected subdomain: a host the selected scope
//! admits establishes its own host-only cookie through these endpoints, which
//! it serves for the installation. A response from the base host cannot set a
//! host-only cookie for a sibling, and the selected scope never emits a
//! parent-domain cookie, so the session travels in three navigations:
//!
//! 1. `GET <host>/session/establish?return=<path>`: the host sets a short
//!    correlation cookie of its own and sends the browser to the base host.
//! 2. `GET <base>/session/grant?...`: the base host reads the browser's live
//!    session from its cookie and stores a single-use grant bound to that
//!    host and to the correlation cookie, then sends the browser back.
//! 3. `GET <host>/session/complete?grant=<key>`: the host takes the grant
//!    once, checks its correlation cookie and sets the session cookie there.
//!
//! The grant is useless to whoever sees its key: completing it needs the
//! correlation cookie of the browser that started step 1, so neither a
//! leaked key nor a key minted from another browser's session establishes
//! anything (login CSRF). The session keeps one secret on the hosts it was
//! shared with; narrowing the scope ends it.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sid::web_settings::{InForce, WebSettingsAdmin};
use sid_authn::browser_session::{BrowserCookie, BrowserSecret};
use sid_authn::challenge_store::ChallengeStore;
use sid_core::models::CookieScope;
use sid_keys::KeyManager;
use sid_plugin::storage::StorageBackend;
use structured_proxy::hooks::{ExtraRoute, ExtraRouteHandler, RouteRequest, RouteResponse};
use tonic::codegen::http::{self, HeaderValue, StatusCode, header};

/// The path a selected host starts from.
pub const ESTABLISH_PATH: &str = "/session/establish";
/// The base host's path that grants the session.
pub const GRANT_PATH: &str = "/session/grant";
/// The path a selected host completes on.
pub const COMPLETE_PATH: &str = "/session/complete";

/// The correlation cookie of a pending establishment on a selected host.
const CORRELATION_COOKIE: &str = "__Host-sid_establish";

/// How long an establishment may take from its first navigation to its last.
const PENDING_FOR: Duration = Duration::from_secs(300);
/// How long a grant waits for its host.
const GRANT_FOR: Duration = Duration::from_secs(60);

/// What a grant hands its host.
#[derive(Serialize, Deserialize)]
struct Grant {
    /// The session cookie's value: the session's secret, sealed at rest.
    secret: String,
    /// The host it was granted to, lowercase.
    host: String,
    /// The hash of the correlation cookie that started it.
    correlation: String,
    /// When the session ends.
    expires_at: jiff::Timestamp,
    /// Where the host's page continues, a path on that host.
    return_path: String,
}

/// The three routes, sharing their state.
pub fn routes(
    web: Arc<WebSettingsAdmin>,
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn KeyManager>,
    cookie: BrowserCookie,
) -> Vec<ExtraRoute> {
    let state = Arc::new(Establishment {
        grants: ChallengeStore::new(storage.clone(), keys, "session-grant", GRANT_FOR),
        web,
        storage,
        cookie,
    });
    [
        (ESTABLISH_PATH, Phase::Establish),
        (GRANT_PATH, Phase::Grant),
        (COMPLETE_PATH, Phase::Complete),
    ]
    .into_iter()
    .map(|(path, phase)| {
        ExtraRoute::new(
            http::Method::GET,
            path,
            Arc::new(Step {
                state: state.clone(),
                phase,
            }),
        )
    })
    .collect()
}

struct Establishment {
    grants: ChallengeStore<Grant>,
    web: Arc<WebSettingsAdmin>,
    storage: Arc<dyn StorageBackend>,
    cookie: BrowserCookie,
}

#[derive(Clone, Copy)]
enum Phase {
    Establish,
    Grant,
    Complete,
}

struct Step {
    state: Arc<Establishment>,
    phase: Phase,
}

#[async_trait::async_trait]
impl ExtraRouteHandler for Step {
    async fn handle(&self, request: RouteRequest) -> RouteResponse {
        let state = &self.state;
        let settings = match state.web.recent().await {
            Ok(settings) => settings,
            Err(e) => {
                tracing::warn!(error = %e, "web settings unavailable; session not established");
                return plain(StatusCode::SERVICE_UNAVAILABLE);
            }
        };
        // Only a selected scope shares the session with sibling hosts this
        // way; every other scope serves none of these steps.
        if !matches!(
            settings.cookie_scope,
            CookieScope::SelectedSubdomains { .. }
        ) {
            return plain(StatusCode::NOT_FOUND);
        }
        let host = request_host(&request);
        let answer = match self.phase {
            Phase::Establish => state.establish(&request, &settings, &host),
            Phase::Grant => state.grant(&request, &settings, &host).await,
            Phase::Complete => state.complete(&request, &settings, &host).await,
        };
        answer.unwrap_or_else(plain)
    }
}

impl Establishment {
    /// Step 1, on a selected host: a correlation cookie, then the base host.
    fn establish(
        &self,
        request: &RouteRequest,
        settings: &InForce,
        host: &str,
    ) -> Result<RouteResponse, StatusCode> {
        if !selected(settings, host) {
            return Err(StatusCode::NOT_FOUND);
        }
        let return_path = local_path(query(request, "return").as_deref())?;
        let nonce = BrowserSecret::generate();
        let correlation = digest(nonce.encode().as_str());
        let mut grant = settings.public_url.clone();
        grant.set_path(GRANT_PATH);
        grant
            .query_pairs_mut()
            .append_pair("host", host)
            .append_pair("correlation", &correlation)
            .append_pair("return", &return_path);
        let mut response = see_other(grant.as_str())?;
        set_cookie(
            &mut response,
            &format!(
                "{CORRELATION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
                nonce.encode().as_str(),
                PENDING_FOR.as_secs()
            ),
        )?;
        Ok(response)
    }

    /// Step 2, on the base host: the browser's live session granted once to
    /// the host that asked, or the sign-in page when it has none.
    async fn grant(
        &self,
        request: &RouteRequest,
        settings: &InForce,
        host: &str,
    ) -> Result<RouteResponse, StatusCode> {
        if !host.eq_ignore_ascii_case(settings.base_domain()) {
            return Err(StatusCode::NOT_FOUND);
        }
        let target = query(request, "host")
            .map(|h| h.to_ascii_lowercase())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if !selected(settings, &target) {
            return Err(StatusCode::FORBIDDEN);
        }
        let correlation = query(request, "correlation").ok_or(StatusCode::BAD_REQUEST)?;
        let return_path = local_path(query(request, "return").as_deref())?;
        let cookies = request
            .headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok());
        let Some(secret) = self.cookie.secret(cookies) else {
            return sign_in(settings);
        };
        // The same admission as a browser call of the installation's API:
        // a live session past every sign-in step.
        let session = match sid_authn::caller::authenticate_browser_session(
            self.storage.as_ref(),
            &secret,
            None::<std::iter::Empty<&str>>,
        )
        .await
        {
            Ok(admitted) => admitted.session,
            Err(sid_authn::caller::BrowserSessionRefusal::Unavailable(e)) => {
                tracing::warn!(error = %e, "session store unavailable; session not granted");
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            Err(_) => return sign_in(settings),
        };
        let key = BrowserSecret::generate().encode().to_string();
        let grant = Grant {
            secret: secret.encode().to_string(),
            host: target.clone(),
            correlation,
            expires_at: session.expires_at,
            return_path,
        };
        if let Err(e) = self.grants.insert(&key, &grant).await {
            tracing::warn!(error = %e, "session grant not stored");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut complete = settings.public_url.clone();
        complete
            .set_host(Some(&target))
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        complete.set_path(COMPLETE_PATH);
        complete.query_pairs_mut().append_pair("grant", &key);
        see_other(complete.as_str())
    }

    /// Step 3, on the selected host: the grant taken once, matched to this
    /// host and to the browser that started, and the session cookie set.
    async fn complete(
        &self,
        request: &RouteRequest,
        settings: &InForce,
        host: &str,
    ) -> Result<RouteResponse, StatusCode> {
        if !selected(settings, host) {
            return Err(StatusCode::NOT_FOUND);
        }
        let key = query(request, "grant").ok_or(StatusCode::BAD_REQUEST)?;
        let grant = match self.grants.take(&key).await {
            Ok(Some(grant)) => grant,
            Ok(None) => return Err(StatusCode::FORBIDDEN),
            Err(e) => {
                tracing::warn!(error = %e, "session grant unreadable");
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        };
        let correlation = cookie_value(request, CORRELATION_COOKIE).map(|v| digest(&v));
        // A grant for another host, or completed by a browser that did not
        // start it, establishes nothing.
        let matches = correlation.is_some_and(|c| {
            bool::from(subtle::ConstantTimeEq::ct_eq(
                c.as_bytes(),
                grant.correlation.as_bytes(),
            ))
        });
        if !grant.host.eq_ignore_ascii_case(host) || !matches {
            return Err(StatusCode::FORBIDDEN);
        }
        let secret = BrowserSecret::decode(&grant.secret).ok_or(StatusCode::FORBIDDEN)?;
        let left = grant
            .expires_at
            .duration_since(jiff::Timestamp::now())
            .as_secs();
        if left <= 0 {
            return Err(StatusCode::FORBIDDEN);
        }
        let mut response = see_other(&grant.return_path)?;
        set_cookie(&mut response, &self.cookie.set(&secret, left))?;
        set_cookie(
            &mut response,
            &format!("{CORRELATION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
        )?;
        Ok(response)
    }
}

/// Whether `host` is a sibling the selected scope admits (not the base).
fn selected(settings: &InForce, host: &str) -> bool {
    !host.eq_ignore_ascii_case(settings.base_domain()) && settings.admits(host)
}

/// The host the browser asked for, lowercase, without its port.
fn request_host(request: &RouteRequest) -> String {
    let value = request
        .uri
        .host()
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.rsplit_once(':').map_or(v, |(name, _)| name).to_owned())
        })
        .unwrap_or_default();
    value.to_ascii_lowercase()
}

fn query(request: &RouteRequest, name: &str) -> Option<String> {
    url::form_urlencoded::parse(request.uri.query()?.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// A path on the same host: absolute, never protocol-relative (`//`) or a
/// backslash a browser reads as one (WHATWG URL, special-scheme parsing).
fn local_path(value: Option<&str>) -> Result<String, StatusCode> {
    let path = value.unwrap_or("/");
    let local = path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.bytes().any(|b| b.is_ascii_control());
    if local {
        Ok(path.to_owned())
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

fn cookie_value(request: &RouteRequest, name: &str) -> Option<String> {
    let mut found = None;
    for header in request.headers.get_all(header::COOKIE) {
        for pair in header.to_str().ok()?.split(';') {
            if let Some((n, v)) = pair.trim().split_once('=')
                && n == name
            {
                if found.is_some() {
                    return None;
                }
                found = Some(v.to_owned());
            }
        }
    }
    found
}

fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn sign_in(settings: &InForce) -> Result<RouteResponse, StatusCode> {
    let account = settings
        .public_url
        .join("account/")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    see_other(account.as_str())
}

fn see_other(location: &str) -> Result<RouteResponse, StatusCode> {
    let mut response = RouteResponse::new(StatusCode::SEE_OTHER, "");
    response.headers.insert(
        header::LOCATION,
        HeaderValue::try_from(location).map_err(|_| StatusCode::BAD_REQUEST)?,
    );
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn set_cookie(response: &mut RouteResponse, value: &str) -> Result<(), StatusCode> {
    response.headers.append(
        header::SET_COOKIE,
        HeaderValue::try_from(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok(())
}

fn plain(status: StatusCode) -> RouteResponse {
    let mut response = RouteResponse::new(status, "");
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests;
