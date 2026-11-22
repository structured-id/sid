use super::*;

fn request(uri: &str, host: &str, cookie: Option<&str>) -> RouteRequest {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::try_from(host).unwrap());
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, HeaderValue::try_from(cookie).unwrap());
    }
    RouteRequest::new(
        http::Method::GET,
        uri.parse().unwrap(),
        headers,
        Default::default(),
        structured_proxy::ClientAddress::from_peer(None),
    )
}

// A page continues only on its own host: an absolute path, never a
// protocol-relative one or a backslash form a browser resolves to another
// host. Bug prevented: an open redirect through the establishment steps.
#[test]
fn the_return_is_a_path_on_this_host() {
    assert_eq!(local_path(None).unwrap(), "/");
    assert_eq!(local_path(Some("/app/x?y=1")).unwrap(), "/app/x?y=1");
    for bad in [
        "https://evil.example.com/",
        "//evil.example.com/",
        "/\\evil.example.com",
        "app",
        "/a\nb",
    ] {
        assert_eq!(
            local_path(Some(bad)),
            Err(StatusCode::BAD_REQUEST),
            "{bad:?}"
        );
    }
}

// The host is the one the browser asked for, without its port; a query
// parameter and the correlation cookie are read exactly, and two
// correlation cookies name none.
#[test]
fn the_request_is_read_exactly() {
    let one = request(
        "/session/complete?grant=k1&x=2",
        "App.Sid.Example.com:8443",
        Some("theme=dark; __Host-sid_establish=n1"),
    );
    assert_eq!(request_host(&one), "app.sid.example.com");
    assert_eq!(query(&one, "grant").as_deref(), Some("k1"));
    assert_eq!(query(&one, "missing"), None);
    assert_eq!(
        cookie_value(&one, CORRELATION_COOKIE).as_deref(),
        Some("n1")
    );
    let twice = request(
        "/",
        "app.sid.example.com",
        Some("__Host-sid_establish=n1; __Host-sid_establish=n2"),
    );
    assert_eq!(cookie_value(&twice, CORRELATION_COOKIE), None);
}
