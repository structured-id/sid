// SPDX-License-Identifier: AGPL-3.0-only

use chrono::{Duration, Utc};
use secrecy::SecretString;
use sid_core::models::{ProfileId, Session};
use tonic::metadata::MetadataMap;

use super::*;
use crate::browser_session::BrowserCookie;

fn page() -> url::Origin {
    url::Url::parse("https://sid.example.com/account/login")
        .unwrap()
        .origin()
}

fn with_origins(origins: &[&str]) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    for origin in origins {
        metadata.append("origin", origin.parse().unwrap());
    }
    metadata
}

/// A request without `Origin` is a native client, with or without a page.
#[test]
fn no_origin_is_a_native_client() {
    assert_eq!(
        ceremony_client(&with_origins(&[]), Some(&page())).unwrap(),
        CeremonyClient::Native
    );
    assert_eq!(
        ceremony_client(&with_origins(&[]), None).unwrap(),
        CeremonyClient::Native
    );
}

/// Exactly the sign-in page's `Origin` is the browser.
#[test]
fn sign_in_page_origin_is_the_browser() {
    assert_eq!(
        ceremony_client(&with_origins(&["https://sid.example.com"]), Some(&page())).unwrap(),
        CeremonyClient::Browser
    );
}

/// Any other browser request is refused, never answered as a native client:
/// another origin, `null`, a repeated `Origin`, or no configured page.
#[test]
fn other_browser_requests_are_refused() {
    for origins in [
        vec!["https://evil.example.com"],
        vec!["null"],
        vec!["https://sid.example.com", "https://sid.example.com"],
        vec!["https://sid.example.com:8443"],
    ] {
        assert!(
            ceremony_client(&with_origins(&origins), Some(&page())).is_err(),
            "{origins:?} was accepted"
        );
    }
    assert!(ceremony_client(&with_origins(&["https://sid.example.com"]), None).is_err());
}

/// The cookie goes into `set-cookie`, the token into `authorization`, both
/// marked sensitive, and nothing into the message.
#[test]
fn credentials_go_into_sensitive_metadata() {
    let response = SignedIn {
        session_id: "s".into(),
        expires_in: 60,
        delivery: Delivery::Cookie("__Host-sid_session=x".into()),
    }
    .respond(|id, expires_in| (id, expires_in))
    .unwrap();
    assert_eq!(response.get_ref(), &("s".to_string(), 60));
    let cookie = response.metadata().get("set-cookie").unwrap();
    assert_eq!(cookie, "__Host-sid_session=x");
    assert!(cookie.is_sensitive());
    assert!(response.metadata().get("authorization").is_none());

    let response = SignedIn {
        session_id: "s".into(),
        expires_in: 60,
        delivery: Delivery::Bearer(SecretString::from("token")),
    }
    .respond(|_, _| ())
    .unwrap();
    let token = response.metadata().get("authorization").unwrap();
    assert_eq!(token, "Bearer token");
    assert!(token.is_sensitive());
    assert!(response.metadata().get("set-cookie").is_none());
}

/// The cookie's lifetime is what remains of the session when the credential
/// is delivered, after the session is stored: time spent storing it never
/// lets the cookie outlive the session.
#[test]
fn cookie_lifetime_is_taken_at_delivery() {
    let cookie = BrowserCookie::new("__Host-sid_account").unwrap();
    let mut session = Session::new(
        ProfileId::generate(),
        "127.0.0.1".into(),
        Utc::now() + Duration::hours(1),
    );
    let credential = BrowserCredential::bind(&mut session);
    // The session being stored.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Sampled before delivery: what remains then bounds what delivery takes,
    // and lies a whole second below a lifetime taken at bind time.
    let remaining = (session.expires_at - Utc::now()).num_seconds();
    let signed = credential.signed_in(&cookie, &session);
    assert!(
        signed.expires_in <= remaining,
        "the cookie lives {}s, the session {remaining}s",
        signed.expires_in
    );
}

/// The browser's cookie carries a fresh secret whose hash the session now
/// stores, for the session's remaining lifetime.
#[test]
fn browser_sign_in_binds_the_cookie_to_the_session() {
    let cookie = BrowserCookie::new("__Host-sid_account").unwrap();
    let mut session = Session::new(
        ProfileId::generate(),
        "127.0.0.1".into(),
        Utc::now() + Duration::hours(1),
    );
    assert!(session.browser_secret_hash.is_none());

    let signed = BrowserCredential::bind(&mut session).signed_in(&cookie, &session);
    assert_eq!(signed.session_id, session.id.to_string());
    assert!(
        (3590..=3600).contains(&signed.expires_in),
        "{}",
        signed.expires_in
    );
    let Delivery::Cookie(set) = &signed.delivery else {
        panic!("a browser gets a cookie");
    };
    assert!(set.starts_with("__Host-sid_account="), "{set}");
    assert!(
        set.ends_with(&format!("Max-Age={}", signed.expires_in)),
        "{set}"
    );
    let pair = set.split(';').next().unwrap();
    let secret = cookie.secret([pair]).expect("the cookie holds a secret");
    assert_eq!(session.browser_secret_hash, Some(secret.hash()));

    let mut again = session.clone();
    BrowserCredential::bind(&mut again);
    assert_ne!(again.browser_secret_hash, session.browser_secret_hash);
}
