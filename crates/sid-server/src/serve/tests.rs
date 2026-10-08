// SPDX-License-Identifier: AGPL-3.0-only

/// Without a bind address or a configuration file there is no HTTP form.
#[cfg(feature = "http")]
#[tokio::test]
async fn test_no_http_setting_no_transcoder() {
    let transcoder = super::http_transcoder(None, None, None).unwrap();
    assert!(transcoder.is_none());
}

/// A configuration file that cannot be read or parsed stops startup instead
/// of leaving the HTTP form silently off; so does one naming an upstream,
/// which would send this server's own RPCs elsewhere.
#[cfg(feature = "http")]
#[tokio::test]
async fn test_unreadable_http_config_stops_startup() {
    assert!(super::http_transcoder(None, Some("/nonexistent/http.yaml"), None).is_err());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "listen: [not, a, mapping").unwrap();
    assert!(super::http_transcoder(None, file.path().to_str(), None).is_err());
    std::fs::write(
        file.path(),
        "upstream: { default: \"http://elsewhere:1\" }\n",
    )
    .unwrap();
    assert!(super::http_transcoder(None, file.path().to_str(), None).is_err());
}

/// The server's own annotated RPCs are mounted and reach this server's
/// services in process; the forward-auth decision is sid-auth's and is not
/// mounted here.
#[cfg(feature = "http")]
#[tokio::test]
async fn test_transcoder_mounts_own_rpcs_not_forward_auth() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let proxy = super::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    for header in super::HTTP_FORWARDED_HEADERS {
        assert!(proxy.config().forwarded_headers.iter().any(|h| h == header));
    }
    // No service is registered: a mounted route reaches the process and is
    // answered UNIMPLEMENTED (501), an unmounted one is not found.
    let service = proxy.service(tonic::service::Routes::default()).unwrap();

    let discovery = service
        .clone()
        .oneshot(
            Request::get("/i/0123456789abcdef0123456789abcdef/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.status(), StatusCode::NOT_IMPLEMENTED);

    let verify = service
        .oneshot(
            Request::get("/auth/verify/orders")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify.status(), StatusCode::NOT_FOUND);
}

/// With a sign-in page, the transcoder answers that page's credentialed
/// preflight with its exact origin and credentials allowed, and allows no
/// other origin; origins the configuration lists stay allowed.
#[cfg(feature = "http")]
#[tokio::test]
async fn test_sign_in_origin_gets_credentialed_cors() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        "listen: { http: \"127.0.0.1:0\" }\ncors: { origins: [\"https://admin.sid.example.com\"] }\n",
    )
    .unwrap();
    let sign_in = url::Url::parse("https://login.sid.example.com/sign-in").unwrap();
    let proxy = super::http_transcoder(None, file.path().to_str(), Some(&sign_in))
        .unwrap()
        .unwrap();
    let service = proxy.service(tonic::service::Routes::default()).unwrap();
    let preflight = |origin: &str| {
        Request::options("/i/0123456789abcdef0123456789abcdef/oauth2/end-session")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap()
    };

    for allowed in [
        "https://login.sid.example.com",
        "https://admin.sid.example.com",
    ] {
        let answer = service.clone().oneshot(preflight(allowed)).await.unwrap();
        let headers = answer.headers();
        assert_eq!(headers["access-control-allow-origin"], allowed);
        assert_eq!(headers["access-control-allow-credentials"], "true");
    }
    let other = service
        .oneshot(preflight("https://evil.example.com"))
        .await
        .unwrap();
    assert!(other.headers().get("access-control-allow-origin").is_none());
}

/// A wildcard or `null` CORS origin cannot serve credentialed calls of the
/// sign-in page: such a configuration stops startup.
#[cfg(feature = "http")]
#[test]
fn test_sign_in_origin_refuses_wildcard_origins() {
    let origin = url::Url::parse("https://login.sid.example.com/")
        .unwrap()
        .origin();
    for listed in ["*", "null"] {
        let mut config: serde_yaml::Value =
            serde_yaml::from_str(&format!("cors: {{ origins: [\"{listed}\"] }}")).unwrap();
        assert!(
            super::allow_sign_in_origin(&mut config, &origin).is_err(),
            "{listed}"
        );
    }
    let mut config: serde_yaml::Value = serde_yaml::from_str("listen: { http: \"x\" }").unwrap();
    super::allow_sign_in_origin(&mut config, &origin).unwrap();
    super::allow_sign_in_origin(&mut config, &origin).unwrap();
    assert_eq!(
        config["cors"]["origins"],
        serde_yaml::from_str::<serde_yaml::Value>("[\"https://login.sid.example.com\"]").unwrap()
    );
}
