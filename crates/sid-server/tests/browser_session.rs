// SPDX-License-Identifier: AGPL-3.0-only
//! The IdP browser session: a sign-in ceremony the sign-in page runs sets the
//! `__Host-sid_session` cookie, whose secret only the browser holds and whose
//! hash the session stores; any other caller gets no cookie.

mod common;

use common::mock_storage::MockStorage;
use common::opaque_client::{login_with_origins, register};
use common::{SIGN_IN_ORIGIN, TestServices};
use sid_authn::browser_session::{BrowserSecret, COOKIE_NAME};
use sid_core::models::SessionId;

const PASSWORD: &[u8] = b"browser-session-password-2026";

/// The `Set-Cookie` values of `response`.
fn set_cookies<T>(response: &tonic::Response<T>) -> Vec<String> {
    response
        .metadata()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// A sign-in on the sign-in page sets one host-only, HttpOnly, Lax cookie
/// living as long as the session; the session stores only the hash of its
/// secret, and the secret appears nowhere in the answer's body.
#[tokio::test]
async fn sign_in_page_ceremony_sets_the_session_cookie() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "browser@sid.example.com", PASSWORD).await;

    let response =
        login_with_origins(&svc, "browser@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN]).await;

    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let cookie = &cookies[0];
    assert!(cookie.starts_with(&format!("{COOKIE_NAME}=")), "{cookie}");
    assert!(
        cookie.contains("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="),
        "{cookie}"
    );
    assert!(!cookie.contains("Domain"), "{cookie}");
    let max_age: i64 = cookie.rsplit("Max-Age=").next().unwrap().parse().unwrap();
    assert!(max_age > 23 * 3600 && max_age <= 24 * 3600, "{max_age}");

    let secret = BrowserSecret::from_cookie_headers([cookie.split(';').next().unwrap()]).unwrap();
    let body = response.into_inner();
    let session = svc
        .storage
        .get_session(SessionId::parse(&body.session_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.browser_secret_hash, Some(secret.hash()));
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    assert!(!body.access_token.contains(value));
    assert_ne!(body.session_id, value);
}

/// A ceremony from anywhere else gets no cookie and its session no hash:
/// no `Origin` (a native client), another origin, `null`, and two origins.
#[tokio::test]
async fn other_callers_get_no_session_cookie() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "native@sid.example.com", PASSWORD).await;

    for origins in [
        &[][..],
        &["https://evil.example.com"][..],
        &["https://login.sid.example.com:8443"][..],
        &["null"][..],
        &[SIGN_IN_ORIGIN, SIGN_IN_ORIGIN][..],
    ] {
        let response = login_with_origins(&svc, "native@sid.example.com", PASSWORD, origins).await;
        assert!(set_cookies(&response).is_empty(), "{origins:?}");
        let session = svc
            .storage
            .get_session(SessionId::parse(&response.into_inner().session_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.browser_secret_hash, None, "{origins:?}");
    }
}

/// Each sign-in gets a fresh secret: a second sign-in in the same browser
/// replaces the cookie with a new one, and both sessions keep their own hash.
#[tokio::test]
async fn every_sign_in_gets_a_new_secret() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "twice@sid.example.com", PASSWORD).await;

    let first =
        login_with_origins(&svc, "twice@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN]).await;
    let second =
        login_with_origins(&svc, "twice@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN]).await;
    assert_ne!(set_cookies(&first), set_cookies(&second));
}
