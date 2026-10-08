use super::*;

fn url(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}

/// The cookie carries the secret with the host-only attributes, and parsing
/// it back yields the same secret, so the hash a session stores finds it.
#[test]
fn test_cookie_round_trips_the_secret() {
    let secret = BrowserSecret::generate();
    let set = secret.set_cookie(3600);
    let value = set
        .strip_prefix("__Host-sid_session=")
        .and_then(|rest| rest.split(';').next())
        .unwrap();
    // 32 bytes, base64url without padding.
    assert_eq!(value.len(), 43);
    assert!(set.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"));
    assert!(!set.contains("Domain"));

    let header = format!("theme=dark; {COOKIE_NAME}={value}; lang=uk");
    let parsed = BrowserSecret::from_cookie_headers([header.as_str()]).unwrap();
    assert_eq!(parsed.hash(), secret.hash());
}

/// Every secret is fresh: two sessions never share a hash.
#[test]
fn test_generated_secrets_differ() {
    assert_ne!(
        BrowserSecret::generate().hash(),
        BrowserSecret::generate().hash()
    );
}

/// A past expiry never yields a negative lifetime.
#[test]
fn test_max_age_is_not_negative() {
    assert!(
        BrowserSecret::generate()
            .set_cookie(-5)
            .ends_with("Max-Age=0")
    );
}

/// No cookie, another cookie, a malformed or short value, and two values of
/// the cookie name no session.
#[test]
fn test_cookie_headers_without_one_secret_name_nothing() {
    let value = BrowserSecret::generate().set_cookie(60);
    let pair = value.split(';').next().unwrap();
    for headers in [
        vec![],
        vec!["theme=dark"],
        vec!["__Host-sid_session=not*base64"],
        vec!["__Host-sid_session=AAAA"],
        vec!["__Host-sid_session="],
        vec!["sid_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    ] {
        assert!(
            BrowserSecret::from_cookie_headers(headers.clone()).is_none(),
            "{headers:?}"
        );
    }
    let twice = format!("{pair}; {pair}");
    assert!(BrowserSecret::from_cookie_headers([twice.as_str()]).is_none());
    assert!(BrowserSecret::from_cookie_headers([pair, pair]).is_none());
    assert!(BrowserSecret::from_cookie_headers([pair]).is_some());
}

/// Clearing uses the attributes that set the cookie, with no lifetime.
#[test]
fn test_clear_cookie() {
    assert_eq!(
        clear_cookie(),
        "__Host-sid_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

/// Only the exact serialized origin matches; `null`, a path, another port or
/// scheme do not.
#[test]
fn test_origin_is_exact() {
    let login = url("https://login.sid.example.com/sign-in").origin();
    assert!(origin_is("https://login.sid.example.com", &login));
    for other in [
        "null",
        "",
        "https://login.sid.example.com/",
        "https://login.sid.example.com:8443",
        "http://login.sid.example.com",
        "https://evil.example.com",
    ] {
        assert!(!origin_is(other, &login), "{other}");
    }
    assert!(!origin_is("null", &url("data:text/plain,x").origin()));
}

/// Same site is scheme plus registrable domain; ports and sub-domains may
/// differ, public-suffix neighbours and other schemes may not.
#[test]
fn test_same_site() {
    let same = [
        (
            "https://sid.example.com",
            "https://login.sid.example.com:8443",
        ),
        ("https://a.example.co.uk", "https://b.example.co.uk"),
        ("https://sid.internal", "https://login.sid.internal"),
        ("http://localhost:8085", "http://localhost:9000"),
        ("http://127.0.0.1:1", "http://127.0.0.1:2"),
    ];
    for (a, b) in same {
        assert!(same_site(&url(a), &url(b)), "{a} {b}");
    }
    let different = [
        ("https://sid.example.com", "http://sid.example.com"),
        ("https://a.example.com", "https://a.example.net"),
        ("https://one.github.io", "https://two.github.io"),
        ("https://a.co.uk", "https://b.co.uk"),
        ("http://localhost", "http://127.0.0.1"),
        ("http://127.0.0.1", "http://127.0.0.2"),
    ];
    for (a, b) in different {
        assert!(!same_site(&url(a), &url(b)), "{a} {b}");
    }
}
