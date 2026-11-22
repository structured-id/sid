// SPDX-License-Identifier: AGPL-3.0-only
//! The installation cookie's domain scope at the HTTP edge: what the
//! services receive and what the browser is sent under each scope setting.

mod common;

use std::sync::{Arc, Mutex};

use common::mock_storage::MockStorage;
use sid_authn::browser_session::{BrowserCookie, BrowserSecret};
use sid_core::models::{AuditEntry, CookieScope, WebSettings};
use sid_plugin::StorageBackend;
use sid_server::cookie_scope::CookieScopeEdge;
use tonic::codegen::http::{self, header};
use tower::{Service, ServiceExt};

/// The services behind the edge: they record the `Cookie` headers they get
/// and answer with `set` as their `Set-Cookie`.
fn services(
    seen: Arc<Mutex<Vec<String>>>,
    set: Option<String>,
) -> impl Service<
    http::Request<tonic::body::Body>,
    Response = http::Response<tonic::body::Body>,
    Error = std::convert::Infallible,
    Future = impl Send,
> + Clone
+ Send
+ Sync
+ 'static {
    tower::service_fn(move |request: http::Request<tonic::body::Body>| {
        let (seen, set) = (seen.clone(), set.clone());
        async move {
            let mut got = seen.lock().unwrap();
            got.clear();
            got.extend(
                request
                    .headers()
                    .get_all(header::COOKIE)
                    .iter()
                    .map(|v| v.to_str().unwrap().to_owned()),
            );
            let mut response = http::Response::new(tonic::body::Body::empty());
            if let Some(set) = set {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, set.parse().unwrap());
            }
            Ok(response)
        }
    })
}

async fn with_scope(storage: &MockStorage, scope: CookieScope) {
    let stored = storage.web_settings().await.unwrap();
    let held = stored.clone().unwrap_or_default();
    let changed = WebSettings {
        cookie_scope: scope,
        revision: held.revision + 1,
        ..held
    };
    assert!(
        storage
            .set_web_settings(
                &changed,
                stored.as_ref(),
                None,
                AuditEntry::system("test", "web_settings").into()
            )
            .await
            .unwrap()
    );
}

/// One call through the edge, with a fresh settings snapshot: the `Cookie`
/// headers the services got and the `Set-Cookie` headers the browser gets.
async fn call(
    storage: &Arc<MockStorage>,
    cookies: Option<&str>,
    set: Option<String>,
) -> (Vec<String>, Vec<String>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut edge = CookieScopeEdge::new(
        services(seen.clone(), set),
        common::test_web_settings(storage.clone()),
        BrowserCookie::default(),
    );
    let mut request = http::Request::new(tonic::body::Body::empty());
    if let Some(cookies) = cookies {
        request
            .headers_mut()
            .append(header::COOKIE, cookies.parse().unwrap());
    }
    let response = edge.ready().await.unwrap().call(request).await.unwrap();
    let sent = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let got = seen.lock().unwrap().clone();
    (got, sent)
}

// This host only (the default): the cookie the services set reaches the
// browser as they set it, host-only.
#[tokio::test]
async fn the_default_scope_keeps_the_cookie_on_its_host() {
    let storage = Arc::new(MockStorage::new());
    let set = BrowserCookie::default().set(&BrowserSecret::generate(), 600);
    let (_, sent) = call(&storage, None, Some(set.clone())).await;
    assert_eq!(sent, vec![set]);
}

// Every subdomain: the cookie a sign-in sets is widened to the base domain
// under the __Secure- name and its host-only copy removed; the widened
// cookie a browser then sends reaches the services as the session cookie.
// Bug prevented: a scope setting that changes nothing the browser receives.
#[tokio::test]
async fn every_subdomain_widens_the_cookie_both_ways() {
    let storage = Arc::new(MockStorage::new());
    with_scope(&storage, CookieScope::AllSubdomains).await;
    let secret = BrowserSecret::generate();
    let cookie = BrowserCookie::default();
    let (_, sent) = call(&storage, None, Some(cookie.set(&secret, 600))).await;
    assert_eq!(
        sent,
        vec![
            cookie
                .for_domain(&cookie.set(&secret, 600), "sid.example.com")
                .unwrap(),
            cookie.clear(),
        ]
    );
    assert!(sent[0].contains("Domain=sid.example.com"));

    let widened = format!("__Secure-sid_session={}", secret.encode().as_str());
    let (got, _) = call(&storage, Some(&widened), None).await;
    let read = cookie.secret(got.iter().map(String::as_str)).unwrap();
    assert_eq!(read.hash(), secret.hash());
}

// After narrowing, a widened cookie still in a browser is neither read nor
// kept: the services do not see it and the response removes it at the base
// domain. Bug prevented: a formerly wide cookie that lingers on every
// subdomain after the administrator narrowed the scope.
#[tokio::test]
async fn a_narrowed_scope_removes_the_widened_cookie() {
    let storage = Arc::new(MockStorage::new());
    with_scope(&storage, CookieScope::AllSubdomains).await;
    with_scope(&storage, CookieScope::ThisHost).await;
    let widened = format!(
        "theme=dark; __Secure-sid_session={}",
        BrowserSecret::generate().encode().as_str()
    );
    let (got, sent) = call(&storage, Some(&widened), None).await;
    assert_eq!(got, vec!["theme=dark".to_owned()]);
    assert_eq!(
        sent,
        vec![BrowserCookie::default().clear_for_domain("sid.example.com")]
    );
}

// Selected subdomains never put a parent-domain cookie in the browser: the
// list cannot be expressed in Set-Cookie, so each host keeps its own
// host-only cookie.
#[tokio::test]
async fn selected_subdomains_keep_the_cookie_host_only() {
    let storage = Arc::new(MockStorage::new());
    with_scope(
        &storage,
        CookieScope::SelectedSubdomains {
            hosts: vec!["app.sid.example.com".into()],
            pattern: None,
        },
    )
    .await;
    let set = BrowserCookie::default().set(&BrowserSecret::generate(), 600);
    let (_, sent) = call(&storage, None, Some(set.clone())).await;
    assert_eq!(sent, vec![set]);
}
