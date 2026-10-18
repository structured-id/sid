use super::*;

fn url(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}

fn cookie() -> BrowserCookie {
    BrowserCookie::default()
}

/// The cookie carries the secret with the host-only attributes, and parsing
/// it back yields the same secret, so the hash a session stores finds it.
#[test]
fn test_cookie_round_trips_the_secret() {
    let secret = BrowserSecret::generate();
    let set = cookie().set(&secret, 3600);
    let value = set
        .strip_prefix("__Host-sid_session=")
        .and_then(|rest| rest.split(';').next())
        .unwrap();
    // 32 bytes, base64url without padding.
    assert_eq!(value.len(), 43);
    assert!(set.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"));
    assert!(!set.contains("Domain"));

    let header = format!("theme=dark; __Host-sid_session={value}; lang=uk");
    let parsed = cookie().secret([header.as_str()]).unwrap();
    assert_eq!(parsed.hash(), secret.hash());
}

/// Authorities sharing a host each set, read and clear only their own
/// cookie: one authority's secret is never another's, whichever comes first.
#[test]
fn test_each_authority_reads_only_its_own_cookie() {
    let second = BrowserCookie::new("__Host-sid_second").unwrap();
    let (theirs, ours) = (BrowserSecret::generate(), BrowserSecret::generate());
    let theirs_pair = cookie().set(&theirs, 60);
    let ours_pair = second.set(&ours, 60);
    let header = format!(
        "{}; {}",
        theirs_pair.split(';').next().unwrap(),
        ours_pair.split(';').next().unwrap()
    );

    assert_eq!(
        second.secret([header.as_str()]).unwrap().hash(),
        ours.hash()
    );
    assert_eq!(
        cookie().secret([header.as_str()]).unwrap().hash(),
        theirs.hash()
    );
    assert!(ours_pair.starts_with("__Host-sid_second="));
    assert_eq!(
        second.clear(),
        "__Host-sid_second=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

/// A cookie name keeps the `__Host-` prefix and is a token: anything else
/// would drop the host-only guarantee or break the header.
#[test]
fn test_cookie_name_is_a_host_only_token() {
    for bad in [
        "",
        "sid_session",
        "__Secure-sid",
        "__Host-",
        "__Host-a b",
        "__Host-a;b",
        "__Host-a=b",
        "__Host-é",
    ] {
        assert!(BrowserCookie::new(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        BrowserCookie::new("__Host-sid_second").unwrap().name(),
        "__Host-sid_second"
    );
    assert_eq!(cookie().name(), "__Host-sid_session");
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
        cookie()
            .set(&BrowserSecret::generate(), -5)
            .ends_with("Max-Age=0")
    );
}

/// No cookie, another cookie, a malformed or short value, and two values of
/// the cookie name no session.
#[test]
fn test_cookie_headers_without_one_secret_name_nothing() {
    let value = cookie().set(&BrowserSecret::generate(), 60);
    let pair = value.split(';').next().unwrap();
    for headers in [
        vec![],
        vec!["theme=dark"],
        vec!["__Host-sid_session=not*base64"],
        vec!["__Host-sid_session=AAAA"],
        vec!["__Host-sid_session="],
        vec!["sid_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    ] {
        assert!(cookie().secret(headers.clone()).is_none(), "{headers:?}");
    }
    let twice = format!("{pair}; {pair}");
    assert!(cookie().secret([twice.as_str()]).is_none());
    assert!(cookie().secret([pair, pair]).is_none());
    assert!(cookie().secret([pair]).is_some());
}

/// Clearing uses the attributes that set the cookie, with no lifetime.
#[test]
fn test_clear_cookie() {
    assert_eq!(
        cookie().clear(),
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

/// The page echoes exactly the token it was given: the encoded token
/// matches, another token, a truncated or extended value, a repeated header,
/// a malformed value and no header do not.
#[test]
fn csrf_matches_only_the_session_token_once() {
    let token = BrowserCsrf::generate();
    let sent = BrowserCsrf::encode(&token);
    assert_eq!(sent.len(), 43);
    assert!(BrowserCsrf::matches([sent.as_str()], &token));

    let other = BrowserCsrf::encode(&BrowserCsrf::generate());
    let truncated = &sent[..42];
    let extended = format!("{sent}A");
    for refused in [
        vec![other.as_str()],
        vec![truncated],
        vec![extended.as_str()],
        vec![sent.as_str(), sent.as_str()],
        vec!["not base64!"],
        vec![""],
        vec![],
    ] {
        assert!(
            !BrowserCsrf::matches(refused.iter().copied(), &token),
            "{refused:?} matched"
        );
    }
}
