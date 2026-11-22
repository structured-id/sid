use super::*;

fn cookie() -> BrowserCookie {
    BrowserCookie::default()
}

fn set_cookies(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

// Widening rewrites only the installation cookie: its value goes to the
// base domain under the __Secure- name, its host-only copy is removed, and
// other cookies (the account pages' own) keep their attributes.
#[test]
fn widening_rescopes_only_the_installation_cookie() {
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    let mut headers = http::HeaderMap::new();
    append(&mut headers, &cookie().set(&secret, 600));
    append(
        &mut headers,
        "__Host-sid_account=x; Path=/; Secure; HttpOnly",
    );
    assert!(sets(&headers, &cookie()));
    widen(&mut headers, &cookie(), "sid.example.com");
    let set = set_cookies(&headers);
    let value = secret.encode();
    assert_eq!(
        set,
        vec![
            format!(
                "__Secure-sid_session={}; Domain=sid.example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
                value.as_str()
            ),
            "__Host-sid_account=x; Path=/; Secure; HttpOnly".to_owned(),
            cookie().clear(),
        ]
    );
}

// A response that does not set the installation cookie is not touched.
#[test]
fn other_cookies_alone_are_not_rescoped() {
    let mut headers = http::HeaderMap::new();
    append(&mut headers, "__Host-sid_account=x; Path=/");
    assert!(!sets(&headers, &cookie()));
    widen(&mut headers, &cookie(), "sid.example.com");
    assert_eq!(set_cookies(&headers), vec!["__Host-sid_account=x; Path=/"]);
}

// Under a widened scope the services receive the widened cookie under the
// host-only name; under a narrower one it is removed from the call and
// reported, the other cookies kept.
#[test]
fn a_request_carries_the_cookie_its_scope_admits() {
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    let pair = format!("__Secure-sid_session={}", secret.encode().as_str());
    let sent = || {
        let mut headers = http::HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::try_from(format!("theme=dark; {pair}")).unwrap(),
        );
        headers
    };

    let mut admitted = sent();
    assert!(present_as_scoped(&mut admitted, &cookie(), true));
    let read = cookie()
        .secret(
            admitted
                .get_all(header::COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap()),
        )
        .unwrap();
    assert_eq!(read.hash(), secret.hash());

    let mut refused = sent();
    assert!(present_as_scoped(&mut refused, &cookie(), false));
    let values: Vec<_> = refused
        .get_all(header::COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(values, vec!["theme=dark"]);

    let mut plain = http::HeaderMap::new();
    plain.append(header::COOKIE, HeaderValue::from_static("theme=dark"));
    assert!(!present_as_scoped(&mut plain, &cookie(), true));
    assert_eq!(plain[header::COOKIE], "theme=dark");
}
