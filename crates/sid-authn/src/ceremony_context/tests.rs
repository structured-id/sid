// SPDX-License-Identifier: AGPL-3.0-only

use chrono::{Duration, Utc};
use sid_core::grpc_error::extract_error_info;
use tonic::metadata::MetadataMap;

use super::*;

const PAGE: &str = "https://sid.example.com";

fn page() -> url::Origin {
    url::Url::parse("https://sid.example.com/login")
        .unwrap()
        .origin()
}

fn cookie() -> BrowserCookie {
    BrowserCookie::new("__Host-sid_registration").unwrap()
}

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo is set").0
}

/// What a browser's start delivered: the cookie pair it sends back and the
/// CSRF token its page read.
struct Browser {
    pair: String,
    csrf: String,
}

fn open_browser() -> (Browser, CeremonyBinding, MetadataMap) {
    let (context, binding) = CeremonyContext::open(CeremonyClient::Browser);
    let mut response = MetadataMap::new();
    context
        .deliver(&cookie(), Utc::now() + Duration::minutes(10), &mut response)
        .unwrap();
    let set = response.get("set-cookie").unwrap().to_str().unwrap();
    let browser = Browser {
        pair: set.split(';').next().unwrap().to_owned(),
        csrf: response
            .get(CSRF_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    };
    (browser, binding, response)
}

fn open_native() -> (String, CeremonyBinding, MetadataMap) {
    let (context, binding) = CeremonyContext::open(CeremonyClient::Native);
    let mut response = MetadataMap::new();
    context
        .deliver(&cookie(), Utc::now() + Duration::minutes(10), &mut response)
        .unwrap();
    let authorization = response
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (authorization, binding, response)
}

fn request(entries: &[(&'static str, &str)]) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    for (name, value) in entries {
        metadata.append(*name, value.parse().unwrap());
    }
    metadata
}

/// The browser gets the transaction cookie and the CSRF token, both
/// sensitive, and no bearer; the cookie lives no longer than the operation.
#[test]
fn browser_start_delivers_cookie_and_csrf() {
    let (browser, _, response) = open_browser();
    let set = response.get("set-cookie").unwrap();
    assert!(set.is_sensitive());
    assert!(response.get(CSRF_HEADER).unwrap().is_sensitive());
    assert!(response.get("authorization").is_none());
    let set = set.to_str().unwrap();
    assert!(set.starts_with("__Host-sid_registration="), "{set}");
    assert!(set.contains("HttpOnly") && set.contains("Secure"), "{set}");
    let max_age: i64 = set.rsplit("Max-Age=").next().unwrap().parse().unwrap();
    assert!((595..=600).contains(&max_age), "{max_age}");
    assert!(!browser.csrf.is_empty());
}

/// A native client gets the secret in `authorization` only.
#[test]
fn native_start_delivers_bearer() {
    let (authorization, _, response) = open_native();
    assert!(authorization.starts_with("Bearer "), "{authorization}");
    assert!(response.get("authorization").unwrap().is_sensitive());
    assert!(response.get("set-cookie").is_none());
    assert!(response.get(CSRF_HEADER).is_none());
}

/// The browser that started continues with Origin, cookie and CSRF token,
/// other cookies alongside notwithstanding.
#[test]
fn browser_continues_its_operation() {
    let (browser, binding, _) = open_browser();
    let cookies = format!("__Host-sid_account=other; {}", browser.pair);
    let metadata = request(&[
        ("origin", PAGE),
        ("cookie", &cookies),
        (CSRF_HEADER, &browser.csrf),
    ]);
    binding.admit(&metadata, &cookie(), Some(&page())).unwrap();
}

/// The native client that started continues with its bearer secret.
#[test]
fn native_continues_its_operation() {
    let (authorization, binding, _) = open_native();
    let metadata = request(&[("authorization", &authorization)]);
    binding.admit(&metadata, &cookie(), Some(&page())).unwrap();
    // The scheme is case-insensitive.
    let lower = authorization.replacen("Bearer", "bearer", 1);
    binding
        .admit(
            &request(&[("authorization", &lower)]),
            &cookie(),
            Some(&page()),
        )
        .unwrap();
}

/// Another operation's secret, a missing one and two values are refused.
#[test]
fn foreign_or_missing_secret_is_refused() {
    let (browser, binding, _) = open_browser();
    let (other, _, _) = open_browser();
    for cookies in [
        vec![other.pair.as_str()],
        vec![],
        vec![browser.pair.as_str(), browser.pair.as_str()],
        vec!["__Host-sid_registration=not-a-secret"],
    ] {
        let mut entries = vec![("origin", PAGE), (CSRF_HEADER, browser.csrf.as_str())];
        entries.extend(cookies.iter().map(|c| ("cookie", *c)));
        let refused = binding
            .admit(&request(&entries), &cookie(), Some(&page()))
            .unwrap_err();
        assert_eq!(reason(&refused), "TOKEN_INVALID", "{cookies:?}");
    }

    let (authorization, binding, _) = open_native();
    let (other, _, _) = open_native();
    for values in [
        vec![other.as_str()],
        vec![],
        vec![authorization.as_str(), authorization.as_str()],
        vec!["Basic abc"],
        vec!["Bearer"],
    ] {
        let entries: Vec<_> = values.iter().map(|v| ("authorization", *v)).collect();
        let refused = binding
            .admit(&request(&entries), &cookie(), Some(&page()))
            .unwrap_err();
        assert_eq!(reason(&refused), "TOKEN_INVALID", "{values:?}");
    }
}

/// The cookie alone does not continue: the CSRF token must be there, once,
/// and be this operation's.
#[test]
fn browser_without_its_csrf_token_is_refused() {
    let (browser, binding, _) = open_browser();
    let (other, _, _) = open_browser();
    for csrf in [
        vec![],
        vec![other.csrf.as_str()],
        vec![browser.csrf.as_str(), browser.csrf.as_str()],
        vec!["%%%"],
    ] {
        let mut entries = vec![("origin", PAGE), ("cookie", browser.pair.as_str())];
        entries.extend(csrf.iter().map(|c| (CSRF_HEADER, *c)));
        let refused = binding
            .admit(&request(&entries), &cookie(), Some(&page()))
            .unwrap_err();
        assert_eq!(reason(&refused), "INSUFFICIENT_PERMISSIONS", "{csrf:?}");
    }
}

/// A page on another origin, `null` or a repeated Origin cannot use the
/// browser's cookie, and is not retried as a native client.
#[test]
fn foreign_origin_is_refused() {
    let (browser, binding, _) = open_browser();
    for origins in [
        vec!["https://evil.example.com"],
        vec!["null"],
        vec![PAGE, PAGE],
    ] {
        let mut entries = vec![
            ("cookie", browser.pair.as_str()),
            (CSRF_HEADER, browser.csrf.as_str()),
        ];
        entries.extend(origins.iter().map(|o| ("origin", *o)));
        let refused = binding
            .admit(&request(&entries), &cookie(), Some(&page()))
            .unwrap_err();
        assert_eq!(reason(&refused), "SIGN_IN_REFUSED", "{origins:?}");
    }
    // No configured sign-in page: no browser continues.
    let entries = [
        ("origin", PAGE),
        ("cookie", browser.pair.as_str()),
        (CSRF_HEADER, browser.csrf.as_str()),
    ];
    assert!(binding.admit(&request(&entries), &cookie(), None).is_err());
}

/// A context continues only over the transport it was opened for: a
/// browser's secret sent as a bearer without Origin, or a native secret
/// sent by the page, is refused.
#[test]
fn transport_must_match() {
    let (browser, binding, _) = open_browser();
    let secret = browser.pair.split_once('=').unwrap().1;
    let as_native = request(&[("authorization", &format!("Bearer {secret}"))]);
    let refused = binding
        .admit(&as_native, &cookie(), Some(&page()))
        .unwrap_err();
    assert_eq!(reason(&refused), "TOKEN_INVALID");

    let (authorization, binding, _) = open_native();
    let secret = authorization.strip_prefix("Bearer ").unwrap();
    let pair = format!("__Host-sid_registration={secret}");
    let as_browser = request(&[("origin", PAGE), ("cookie", &pair)]);
    let refused = binding
        .admit(&as_browser, &cookie(), Some(&page()))
        .unwrap_err();
    assert_eq!(reason(&refused), "TOKEN_INVALID");
}

/// The cookie of another name, such as the authority's session cookie with
/// the same secret, is not the context.
#[test]
fn only_the_transaction_cookie_carries_the_context() {
    let (browser, binding, _) = open_browser();
    let secret = browser.pair.split_once('=').unwrap().1;
    let pair = format!("__Host-sid_account={secret}");
    let metadata = request(&[
        ("origin", PAGE),
        ("cookie", &pair),
        (CSRF_HEADER, &browser.csrf),
    ]);
    assert!(binding.admit(&metadata, &cookie(), Some(&page())).is_err());
}

/// The binding survives storage with its operation and keeps checking; its
/// debug output shows neither hash nor token.
#[test]
fn binding_round_trips_and_redacts() {
    let (browser, binding, _) = open_browser();
    let stored: CeremonyBinding =
        serde_json::from_str(&serde_json::to_string(&binding).unwrap()).unwrap();
    let metadata = request(&[
        ("origin", PAGE),
        ("cookie", &browser.pair),
        (CSRF_HEADER, &browser.csrf),
    ]);
    stored.admit(&metadata, &cookie(), Some(&page())).unwrap();
    assert_eq!(
        format!("{stored:?}"),
        "CeremonyBinding { browser: true, .. }"
    );
}

/// Every context is fresh: two starts share neither secret nor token.
#[test]
fn contexts_are_fresh() {
    let (a, _, _) = open_browser();
    let (b, _, _) = open_browser();
    assert_ne!(a.pair, b.pair);
    assert_ne!(a.csrf, b.csrf);
}
