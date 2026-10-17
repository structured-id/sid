// SPDX-License-Identifier: AGPL-3.0-only
//! The IdP browser session: a sign-in ceremony the sign-in page runs sets the
//! `__Host-sid_session` cookie, whose secret only the browser holds and whose
//! hash the session stores, and nothing else; a native client gets the access
//! token in `authorization` metadata and no cookie; any other browser request
//! is refused.

mod common;

use common::mock_storage::MockStorage;
use common::opaque_client::{
    bearer, finish_with_origins, login_with_origins, register, start_login,
};
use common::{SIGN_IN_ORIGIN, TestServices};
use sid_authn::browser_session::{BrowserCookie, DEFAULT_COOKIE_NAME};
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
/// living as long as the session, and delivers no access token; the session
/// stores only the hash of its secret, and the answer reports the cookie's
/// lifetime.
#[tokio::test]
async fn sign_in_page_ceremony_sets_the_session_cookie() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "browser@sid.example.com", PASSWORD).await;

    let response = login_with_origins(&svc, "browser@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN])
        .await
        .expect("login");

    assert!(response.metadata().get("authorization").is_none());
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let cookie = &cookies[0];
    assert!(
        cookie.starts_with(&format!("{DEFAULT_COOKIE_NAME}=")),
        "{cookie}"
    );
    assert!(
        cookie.contains("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="),
        "{cookie}"
    );
    assert!(!cookie.contains("Domain"), "{cookie}");
    let max_age: i64 = cookie.rsplit("Max-Age=").next().unwrap().parse().unwrap();
    assert!(max_age > 23 * 3600 && max_age <= 24 * 3600, "{max_age}");

    let secret = BrowserCookie::default()
        .secret([cookie.split(';').next().unwrap()])
        .unwrap();
    let body = response.into_inner();
    let session = svc
        .storage
        .get_session(SessionId::parse(&body.session_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.browser_secret_hash, Some(secret.hash()));
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    assert_ne!(body.session_id, value);
    assert!(
        (max_age - 1..=max_age).contains(&body.expires_in),
        "{}",
        body.expires_in
    );
}

/// An authority that names its own cookie, as one sharing its host with
/// another authority does, sets that cookie and never the default one.
#[tokio::test]
async fn sign_in_sets_the_authoritys_configured_cookie() {
    let configured = BrowserCookie::new("__Host-sid_second").unwrap();
    let svc = TestServices::with_browser_cookie(MockStorage::new(), configured.clone());
    register(&svc, &svc, "second@sid.example.com", PASSWORD).await;

    let response = login_with_origins(&svc, "second@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN])
        .await
        .expect("login");

    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let pair = cookies[0].split(';').next().unwrap();
    assert!(pair.starts_with("__Host-sid_second="), "{pair}");
    assert!(BrowserCookie::default().secret([pair]).is_none());
    let secret = configured.secret([pair]).unwrap();
    let session = svc
        .storage
        .get_session(SessionId::parse(&response.into_inner().session_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.browser_secret_hash, Some(secret.hash()));
}

/// A native client (no `Origin`) gets its access token in `authorization`
/// metadata, and no cookie; the token is the session's and authenticates.
#[tokio::test]
async fn native_client_gets_the_token_in_metadata() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "native@sid.example.com", PASSWORD).await;

    let response = login_with_origins(&svc, "native@sid.example.com", PASSWORD, &[])
        .await
        .expect("login");

    assert!(set_cookies(&response).is_empty());
    let token = bearer(&response);
    let body = response.into_inner();
    let claims = svc
        .jwt
        .validate_access_token(&token)
        .expect("a valid token");
    assert_eq!(claims.sid, body.session_id);
    let session = svc
        .storage
        .get_session(SessionId::parse(&body.session_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.browser_secret_hash, None);
}

/// A browser request from anywhere but the sign-in page is refused, never
/// answered as a native client with the token: another origin, another
/// port, `null`, two origins, and a server with no sign-in page at all. The
/// refusal consumes nothing: the same attempt then completes natively.
#[tokio::test]
async fn other_browser_requests_are_refused() {
    let svc = TestServices::new(MockStorage::new());
    let no_sign_in_page = TestServices::without_sign_in_page(MockStorage::new());
    register(&svc, &svc, "foreign@sid.example.com", PASSWORD).await;
    register(
        &no_sign_in_page,
        &no_sign_in_page,
        "foreign@sid.example.com",
        PASSWORD,
    )
    .await;

    for (server, origins) in [
        (&svc, &["https://evil.example.com"][..]),
        (&svc, &["https://login.sid.example.com:8443"][..]),
        (&svc, &["null"][..]),
        (&svc, &[SIGN_IN_ORIGIN, SIGN_IN_ORIGIN][..]),
        (&no_sign_in_page, &[SIGN_IN_ORIGIN][..]),
    ] {
        let finish = start_login(server, "foreign@sid.example.com", PASSWORD).await;
        let refused = finish_with_origins(server, finish.clone(), origins)
            .await
            .expect_err("a foreign browser request signs nobody in");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{origins:?}");
        let (reason, _, _) = sid_core::grpc_error::extract_error_info(&refused).unwrap();
        assert_eq!(reason, "SIGN_IN_REFUSED", "{origins:?}");

        let native = finish_with_origins(server, finish, &[])
            .await
            .expect("the refused attempt is still open");
        bearer(&native);
    }
}

/// Each sign-in gets a fresh secret: a second sign-in in the same browser
/// replaces the cookie with a new one, and both sessions keep their own hash.
#[tokio::test]
async fn every_sign_in_gets_a_new_secret() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "twice@sid.example.com", PASSWORD).await;

    let first = login_with_origins(&svc, "twice@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN])
        .await
        .expect("login");
    let second = login_with_origins(&svc, "twice@sid.example.com", PASSWORD, &[SIGN_IN_ORIGIN])
        .await
        .expect("login");
    assert_ne!(set_cookies(&first), set_cookies(&second));
}
