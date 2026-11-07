use super::*;

/// Refusals carry their challenges as `www-authenticate`, in order.
#[test]
fn test_challenges() {
    let status = no_token();
    let values: Vec<_> = status
        .metadata()
        .get_all("www-authenticate")
        .iter()
        .collect();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], "Bearer");
    assert!(values[1].to_str().unwrap().starts_with("DPoP algs=\"ES256"));

    for (scheme, expected) in [
        (Scheme::Bearer, r#"Bearer error="invalid_token""#),
        (Scheme::DPoP, r#"DPoP error="invalid_token""#),
    ] {
        let status = invalid_token(scheme);
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(status.metadata().get("www-authenticate").unwrap(), expected);
    }
    assert_eq!(scheme_name(Scheme::DPoP), "DPoP");
}

fn protocol(
    content_type: &str,
    data: &str,
    authorization: Option<&str>,
) -> Request<ProtocolRequest> {
    let mut request = Request::new(ProtocolRequest {
        issuer_handle: "0123456789abcdef0123456789abcdef".into(),
        body: Some(HttpBody {
            content_type: content_type.into(),
            data: data.as_bytes().to_vec(),
            extensions: Vec::new(),
        }),
    });
    if let Some(value) = authorization {
        request
            .metadata_mut()
            .insert("authorization", value.parse().unwrap());
    }
    request
        .metadata_mut()
        .insert("dpop", "proof".parse().unwrap());
    request
}

/// The typed request gets the form's values and the handle, and keeps the
/// metadata (a DPoP proof, HTTP Basic) the typed logic reads.
#[test]
fn test_form_request_keeps_the_metadata() {
    let (typed, basic) = form_request(
        protocol(
            "application/x-www-form-urlencoded",
            "token=t1",
            Some("basic YTpi"),
        ),
        |form, issuer_handle| (form.take("token"), issuer_handle),
    )
    .unwrap_or_else(|_| panic!("a form"));
    assert!(basic);
    assert_eq!(typed.metadata().get("dpop").unwrap(), "proof");
    let (token, handle) = typed.into_inner();
    assert_eq!(token.as_deref(), Some("t1"));
    assert_eq!(handle, "0123456789abcdef0123456789abcdef");
}

/// A body that is not the form answers `invalid_request` without building a
/// typed request; a bearer credential is not HTTP Basic.
#[test]
fn test_form_request_refuses_another_body() {
    let refused = form_request(protocol("application/json", "{}", None), |_, _| ()).err();
    let answer = refused.expect("refused");
    assert_eq!(answer.metadata().get("x-http-code").unwrap(), "400");

    let (_, basic) = form_request(
        protocol("application/x-www-form-urlencoded", "", Some("Bearer t")),
        |_, _| (),
    )
    .unwrap_or_else(|_| panic!("a form"));
    assert!(!basic);
    assert!(!uses_basic(&MetadataMap::new()));
}

/// The URL that continues a kept request is this issuer's authorization
/// endpoint with the client and the reference only: none of the request's
/// own parameters travel through the browser again.
#[test]
fn test_continuation_carries_only_the_reference() {
    let url = continuation(
        "https://sid.example.com/i/0123456789abcdef0123456789abcdef",
        "app",
        "ref_1",
    )
    .unwrap();
    assert_eq!(
        url.as_str(),
        "https://sid.example.com/i/0123456789abcdef0123456789abcdef/oauth2/authorize?client_id=app&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aref_1"
    );
}

/// A POSTed form gives the same request, `prompt` and `max_age` included;
/// unknown parameters are ignored.
#[test]
fn test_form_authorize_request() {
    let (typed, _) = form_request(
        protocol(
            "application/x-www-form-urlencoded",
            "response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&prompt=login&max_age=60&nonce=n&extra=1",
            None,
        ),
        form_authorize_request,
    )
    .unwrap_or_else(|_| panic!("a form"));
    let request = typed.into_inner().unwrap();
    assert_eq!(request.client_id, "app");
    assert_eq!(request.redirect_uri, "https://app.example.com/cb");
    assert_eq!(request.nonce.as_deref(), Some("n"));
    assert_eq!(request.prompt.as_deref(), Some("login"));
    assert_eq!(request.max_age, Some(60));
    assert!(request.state.is_none());
    assert_eq!(request.issuer_handle, "0123456789abcdef0123456789abcdef");
}

/// A `max_age` that is not a count of seconds refuses the form; an empty one
/// is omitted (RFC 6749 §3.1).
#[test]
fn test_form_authorize_request_refuses_a_malformed_max_age() {
    let (typed, _) = form_request(
        protocol(
            "application/x-www-form-urlencoded",
            "client_id=app&max_age=",
            None,
        ),
        form_authorize_request,
    )
    .unwrap_or_else(|_| panic!("a form"));
    assert_eq!(typed.into_inner().unwrap().max_age, None);
    for max_age in ["-1", "ten", "4294967296"] {
        let (typed, _) = form_request(
            protocol(
                "application/x-www-form-urlencoded",
                &format!("client_id=app&max_age={max_age}"),
                None,
            ),
            form_authorize_request,
        )
        .unwrap_or_else(|_| panic!("a form"));
        assert!(typed.into_inner().is_err(), "{max_age:?}");
    }
}

/// Only set values become members.
#[test]
fn test_put_skips_absent_values() {
    let mut body = Map::new();
    put(&mut body, "exp", Some(5_i64));
    put(&mut body, "scope", None::<String>);
    assert_eq!(Value::Object(body), json!({ "exp": 5 }));
}
