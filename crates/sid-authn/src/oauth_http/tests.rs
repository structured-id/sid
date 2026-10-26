use super::*;
use sid_core::grpc_error::{ApiError, ErrorReason};

fn body(content_type: &str, data: &str) -> HttpBody {
    HttpBody {
        content_type: content_type.into(),
        data: data.as_bytes().to_vec(),
        extensions: Vec::new(),
    }
}

fn status_code(response: &Response<HttpBody>) -> &str {
    response
        .metadata()
        .get("x-http-code")
        .unwrap()
        .to_str()
        .unwrap()
}

fn json_body(response: &Response<HttpBody>) -> serde_json::Value {
    serde_json::from_slice(&response.get_ref().data).unwrap()
}

fn refused(error: &str) -> Status {
    ApiError::new(ErrorReason::InvalidFieldValue, "refused")
        .with_metadata("oauthError", error)
        .into()
}

/// The form is read whatever the media type's case and parameters; values
/// are decoded, and an empty value counts as omitted (RFC 6749 §3.2).
#[test]
fn test_form_parses_the_urlencoded_body() {
    let mut form = Form::parse(Some(&body(
        "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
        "grant_type=client_credentials&scope=a+b%21&client_id=",
    )))
    .unwrap();
    assert_eq!(
        form.take("grant_type").as_deref(),
        Some("client_credentials")
    );
    assert_eq!(form.take("scope").as_deref(), Some("a b!"));
    assert_eq!(form.take("client_id"), None);
    assert_eq!(form.take("absent"), None);
    assert!(Form::parse(Some(&body("application/x-www-form-urlencoded", ""))).is_ok());
}

/// Another content type, no body at all, or a repeated parameter is refused.
#[test]
fn test_form_refuses_what_is_not_the_form() {
    assert!(Form::parse(None).is_err());
    assert!(Form::parse(Some(&body("application/json", "{}"))).is_err());
    assert!(Form::parse(Some(&body("", "a=b"))).is_err());
    assert!(
        Form::parse(Some(&body(
            "application/x-www-form-urlencoded",
            "scope=a&scope=b"
        )))
        .is_err()
    );
}

/// The token exchange `audience` may repeat (RFC 8693 §2.1) like `resource`:
/// every value reaches the grant, which refuses distinct ones itself.
#[test]
fn test_form_keeps_every_audience() {
    let mut form = Form::parse(Some(&body(
        "application/x-www-form-urlencoded",
        "audience=https%3A%2F%2Fa.example%2F&audience=https%3A%2F%2Fb.example%2F",
    )))
    .unwrap();
    assert_eq!(
        form.take_all("audience"),
        vec!["https://a.example/", "https://b.example/"]
    );
}

/// `resource` may repeat (RFC 8707 §2); its values are kept in order,
/// empty ones dropped, and taking it again yields nothing.
#[test]
fn test_form_keeps_every_resource() {
    let mut form = Form::parse(Some(&body(
        "application/x-www-form-urlencoded",
        "resource=https%3A%2F%2Fa.example%2F&scope=x&resource=&resource=https%3A%2F%2Fb.example%2F",
    )))
    .unwrap();
    assert_eq!(
        form.take_all("resource"),
        vec!["https://a.example/", "https://b.example/"]
    );
    assert!(form.take_all("resource").is_empty());
    assert_eq!(form.take("scope").as_deref(), Some("x"));
    assert!(form.take_all("absent").is_empty());
}

/// An answer carries its status, its JSON and `no-store` (RFC 6749 §5.1).
#[test]
fn test_json_answer() {
    let response = json(200, &serde_json::json!({ "active": false }));
    assert_eq!(status_code(&response), "200");
    assert_eq!(response.get_ref().content_type, "application/json");
    assert_eq!(
        response.metadata().get("cache-control").unwrap(),
        "no-store"
    );
    assert_eq!(response.metadata().get("pragma").unwrap(), "no-cache");
    assert_eq!(json_body(&response), serde_json::json!({ "active": false }));
}

/// A refusal's `oauthError` is the answer's `error`, with status 400.
#[test]
fn test_refusal_uses_the_oauth_error() {
    let response = refusal(&refused("invalid_grant"), false, "realm");
    assert_eq!(status_code(&response), "400");
    let body = json_body(&response);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "refused");
    assert!(response.metadata().get("www-authenticate").is_none());
}

/// `invalid_client` after HTTP Basic is a 401 with a Basic challenge
/// (RFC 6749 §5.2); without Basic it stays a 400.
#[test]
fn test_invalid_client_after_basic_is_401() {
    let response = refusal(
        &refused("invalid_client"),
        true,
        r#"https://sid.example.com/i/"x""#,
    );
    assert_eq!(status_code(&response), "401");
    assert_eq!(
        response.metadata().get("www-authenticate").unwrap(),
        r#"Basic realm="https://sid.example.com/i/\"x\"""#
    );
    assert_eq!(json_body(&response)["error"], "invalid_client");

    let response = refusal(&refused("invalid_client"), false, "realm");
    assert_eq!(status_code(&response), "400");
}

/// A refusal without an OAuth code is a server-side condition: rate limit,
/// unavailability or an internal error, with Retry-After rounded up from
/// RetryInfo.
#[test]
fn test_refusal_without_a_code() {
    let limited: Status = ApiError::new(ErrorReason::RateLimitExceeded, "slow")
        .with_retry_after(std::time::Duration::from_millis(1500))
        .into();
    let response = refusal(&limited, false, "realm");
    assert_eq!(status_code(&response), "429");
    assert_eq!(json_body(&response)["error"], "temporarily_unavailable");
    assert_eq!(response.metadata().get("retry-after").unwrap(), "2");

    let response = refusal(&Status::unavailable("down"), false, "realm");
    assert_eq!(status_code(&response), "503");
    let response = refusal(&ApiError::internal().into(), false, "realm");
    assert_eq!(status_code(&response), "500");
    assert_eq!(json_body(&response)["error"], "server_error");
}

/// `slow_down` keeps its code and says when to poll again.
#[test]
fn test_slow_down_carries_retry_after() {
    let status: Status = ApiError::new(ErrorReason::RateLimitExceeded, "slow")
        .with_metadata("oauthError", "slow_down")
        .with_retry_after(std::time::Duration::from_secs(10))
        .into();
    let response = refusal(&status, false, "realm");
    assert_eq!(status_code(&response), "400");
    assert_eq!(json_body(&response)["error"], "slow_down");
    assert_eq!(response.metadata().get("retry-after").unwrap(), "10");
}

/// `error_description` keeps only the characters RFC 6749 §5.2 allows.
#[test]
fn test_error_description_characters() {
    assert_eq!(error_description("a \"b\" \\c é\n"), "a b c ");
    let response = invalid_request("bad \"thing\"");
    assert_eq!(json_body(&response)["error_description"], "bad thing");
    assert_eq!(
        json_body(&error_json(400, "invalid_request", "")),
        serde_json::json!({ "error": "invalid_request" })
    );
}

/// Only refusals the core gives after establishing the client and redirect
/// URI are redirected; a policy block is `access_denied`, a missing or too
/// weak sign-in sends the user to sign in (RFC 6749 §4.1.2.1).
#[test]
fn test_authorize_refusal_classification() {
    let unknown: Status = ApiError::new(ErrorReason::ApplicationNotFound, "unknown client")
        .with_metadata("field", "client_id")
        .into();
    assert_eq!(
        classify_authorize_refusal(&unknown),
        AuthorizeRefusal::Show(400, "invalid_client")
    );
    let unregistered: Status = ApiError::new(ErrorReason::InvalidFieldValue, "no")
        .with_metadata("field", "redirect_uri")
        .into();
    assert_eq!(
        classify_authorize_refusal(&unregistered),
        AuthorizeRefusal::Show(400, "invalid_request")
    );
    assert_eq!(
        classify_authorize_refusal(&refused("unsupported_response_type")),
        AuthorizeRefusal::Redirect("unsupported_response_type".into())
    );
    assert_eq!(
        classify_authorize_refusal(&Status::unauthenticated("sign in")),
        AuthorizeRefusal::SignIn
    );
    let step_up: Status = ApiError::new(ErrorReason::StepUpRequired, "stronger sign-in")
        .with_precondition("acr", "urn:sid:acr:standard", "authenticate at this level")
        .into();
    assert_eq!(
        classify_authorize_refusal(&step_up),
        AuthorizeRefusal::SignIn
    );
    assert_eq!(
        classify_authorize_refusal(&Status::permission_denied("blocked")),
        AuthorizeRefusal::Redirect("access_denied".into())
    );
    assert_eq!(
        classify_authorize_refusal(&Status::unavailable("maintenance")),
        AuthorizeRefusal::Show(503, "temporarily_unavailable")
    );
    assert_eq!(
        classify_authorize_refusal(&Status::internal("boom")),
        AuthorizeRefusal::Show(500, "server_error")
    );
}

fn location(response: &Response<HttpBody>) -> &str {
    response
        .metadata()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
}

/// The response keeps the client's own query, encodes what it adds, and
/// names the issuer (RFC 9207 §2); an empty state is left out.
#[test]
fn test_authorization_response() {
    let response = authorization_response(
        "https://app.example.com/cb?tenant=a",
        "https://sid.example.com/i/abc",
        &[("code", "x&y")],
        Some("s t"),
    );
    assert_eq!(status_code(&response), "303");
    assert_eq!(
        location(&response),
        "https://app.example.com/cb?tenant=a&code=x%26y&state=s+t&iss=https%3A%2F%2Fsid.example.com%2Fi%2Fabc"
    );
    assert_eq!(
        response.metadata().get("cache-control").unwrap(),
        "no-store"
    );

    let response = authorization_response("https://app.example.com/cb", "iss", &[], Some(""));
    assert_eq!(location(&response), "https://app.example.com/cb?iss=iss");

    let response = authorization_response("not a url", "iss", &[], None);
    assert_eq!(status_code(&response), "400");
    assert!(response.metadata().get("location").is_none());
}

/// The sign-in redirect keeps the page's own query and carries the request
/// to return to.
#[test]
fn test_sign_in_redirect() {
    let login = url::Url::parse("https://login.sid.example.com/in?tenant=a").unwrap();
    let back = url::Url::parse("https://sid.example.com/i/h/oauth2/authorize?client_id=c").unwrap();
    let response = sign_in(&login, &back);
    assert_eq!(status_code(&response), "303");
    assert_eq!(
        location(&response),
        "https://login.sid.example.com/in?tenant=a&rd=https%3A%2F%2Fsid.example.com%2Fi%2Fh%2Foauth2%2Fauthorize%3Fclient_id%3Dc"
    );
}

/// A page is plain text with its status.
#[test]
fn test_page() {
    let response = page(404, "Unknown issuer");
    assert_eq!(status_code(&response), "404");
    assert_eq!(response.get_ref().content_type, "text/plain; charset=utf-8");
    assert_eq!(response.get_ref().data, b"Unknown issuer");
}

/// A raw answer with no content keeps an empty content type.
#[test]
fn test_raw_answer() {
    let response = raw(200, "", Vec::new());
    assert_eq!(status_code(&response), "200");
    assert!(response.get_ref().data.is_empty());
    assert!(response.get_ref().content_type.is_empty());
    assert_eq!(quoted("a\"b\\c\u{7f}"), "a\\\"b\\\\c");
}
