// SPDX-License-Identifier: AGPL-3.0-only
//! The installation session cookie's domain scope, applied where the HTTP
//! port hands calls to the services. The services set, read and
//! clear one host-only cookie; this edge widens it to the base domain when
//! the administrator chose every subdomain, and removes a widened copy the
//! narrower scope no longer admits. A selected-subdomain scope keeps the
//! host-only cookie on every host: a list or a pattern cannot be put in
//! `Set-Cookie` (RFC 6265 §4.1.2.3), so no parent-domain cookie is emitted.

use std::sync::Arc;
use std::task::{Context, Poll};

use sid::web_settings::WebSettingsAdmin;
use sid_authn::browser_session::BrowserCookie;
use sid_core::models::CookieScope;
use tonic::client::GrpcService;
use tonic::codegen::http::{self, HeaderValue, header};
use tower::Service;

/// `inner` with the installation cookie scoped as the settings say.
#[derive(Clone)]
pub struct CookieScopeEdge<S> {
    inner: S,
    web: Arc<WebSettingsAdmin>,
    cookie: BrowserCookie,
}

impl<S> CookieScopeEdge<S> {
    pub fn new(inner: S, web: Arc<WebSettingsAdmin>, cookie: BrowserCookie) -> Self {
        Self { inner, web, cookie }
    }
}

impl<S> Service<http::Request<tonic::body::Body>> for CookieScopeEdge<S>
where
    S: GrpcService<tonic::body::Body> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<structured_proxy::upstream::BoxError>,
    S::ResponseBody: Send + 'static,
{
    type Response = http::Response<S::ResponseBody>;
    type Error = structured_proxy::upstream::BoxError;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        GrpcService::poll_ready(&mut self.inner, cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: http::Request<tonic::body::Body>) -> Self::Future {
        // The service polled ready serves this call; its clone the next one.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let (web, cookie) = (self.web.clone(), self.cookie.clone());
        Box::pin(async move {
            let sent = request.headers().contains_key(header::COOKIE);
            // Settings that cannot be read leave the call as sent: the
            // services read only the host-only cookie, so a widened copy
            // counts for nothing until the settings are known again.
            let scope = match web.recent().await {
                Ok(placed) => Some((
                    placed.cookie_scope == CookieScope::AllSubdomains,
                    placed.base_domain().to_owned(),
                )),
                Err(e) => {
                    tracing::warn!(error = %e, "web settings unavailable; cookie scope not applied");
                    None
                }
            };
            let mut stale = false;
            if let (true, Some((widened, _))) = (sent, &scope) {
                stale = present_as_scoped(request.headers_mut(), &cookie, *widened) && !widened;
            }
            let mut response = GrpcService::call(&mut inner, request)
                .await
                .map_err(Into::into)?;
            let Some((_, base)) = scope else {
                return Ok(response);
            };
            if sets(response.headers(), &cookie) {
                // A cookie being issued follows the settings read now: a
                // scope narrowed a moment ago never receives a widened one.
                match web.in_force().await {
                    Ok(now) if now.cookie_scope == CookieScope::AllSubdomains => {
                        widen(response.headers_mut(), &cookie, now.base_domain());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "web settings unavailable; cookie kept on this host");
                    }
                }
            }
            if stale {
                append(response.headers_mut(), &cookie.clear_for_domain(&base));
            }
            Ok(response)
        })
    }
}

/// Rewrite the `Cookie` headers so the services read the cookie the scope
/// admits; whether a widened copy was present.
fn present_as_scoped(headers: &mut http::HeaderMap, cookie: &BrowserCookie, widened: bool) -> bool {
    let sent: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let (scoped, present) = cookie.with_domain_variant(sent.iter().map(String::as_str), widened);
    if !present {
        return false;
    }
    headers.remove(header::COOKIE);
    for value in scoped {
        if let Ok(value) = HeaderValue::try_from(value) {
            headers.append(header::COOKIE, value);
        }
    }
    true
}

/// Whether the response sets or clears the installation cookie.
fn sets(headers: &http::HeaderMap, cookie: &BrowserCookie) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| named(v, cookie.name()))
}

fn named(set: &str, name: &str) -> bool {
    set.split_once('=').is_some_and(|(n, _)| n.trim() == name)
}

/// Each `Set-Cookie` of the installation cookie widened to `base`, with the
/// host-only copy removed so a browser keeps one value for the session.
fn widen(headers: &mut http::HeaderMap, cookie: &BrowserCookie, base: &str) {
    let all: Vec<HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .cloned()
        .collect();
    headers.remove(header::SET_COOKIE);
    let mut widened = false;
    for value in all {
        let rescoped = value
            .to_str()
            .ok()
            .filter(|v| named(v, cookie.name()))
            .and_then(|v| cookie.for_domain(v, base))
            .and_then(|v| HeaderValue::try_from(v).ok());
        match rescoped {
            Some(rescoped) => {
                widened = true;
                headers.append(header::SET_COOKIE, rescoped);
            }
            None => {
                headers.append(header::SET_COOKIE, value);
            }
        }
    }
    if widened {
        append(headers, &cookie.clear());
    }
}

fn append(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = HeaderValue::try_from(value) {
        headers.append(header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests;
