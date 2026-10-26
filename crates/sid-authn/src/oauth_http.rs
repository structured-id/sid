// SPDX-License-Identifier: AGPL-3.0-only
//! The HTTP form of an issuer's OAuth endpoints: a form-encoded request body
//! in (RFC 6749 §3.2), the RFC's JSON, status and headers out. The body
//! travels as `google.api.HttpBody`, the status as `x-http-code` response
//! metadata and the headers as response metadata, which the transcoder turns
//! into the HTTP answer. The token endpoint's refusals are typed statuses
//! whose ErrorInfo names the RFC error code [`refusal`] answers with.

use std::borrow::Cow;
use std::collections::HashMap;

use sid_core::grpc_error::refuse::{internal, storage_failure};
use sid_core::grpc_error::{ApiError, ErrorReason, extract_error_info, extract_retry_delay};
use sid_proto::google::api::HttpBody;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Code, Response, Status};

use crate::client_auth::ClientAuthentication;
use crate::grant::GrantFailure;
use crate::oauth2::TokenError;

/// Parameters a request may repeat: `resource` (RFC 8707 §2, RFC 8693
/// §2.1) and the token exchange `audience` (RFC 8693 §2.1).
const REPEATABLE: &[&str] = &["resource", "audience"];

/// The parameters of a form request.
pub struct Form {
    single: HashMap<String, String>,
    repeated: HashMap<String, Vec<String>>,
}

impl Form {
    /// Read `body` as an `application/x-www-form-urlencoded` form, the only
    /// request format of the endpoints (RFC 6749 §3.2). A parameter given
    /// twice is refused (RFC 6749 §3.2: "MUST NOT be included more than
    /// once"), except those RFC 8707 §2 and RFC 8693 §2.1 let repeat. The error is the
    /// `invalid_request` description.
    pub fn parse(body: Option<&HttpBody>) -> Result<Self, &'static str> {
        let body = body.ok_or("the request has no body")?;
        let media_type = body.content_type.split(';').next().unwrap_or("").trim();
        if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            return Err("the request body must be application/x-www-form-urlencoded");
        }
        let mut single = HashMap::new();
        let mut repeated: HashMap<String, Vec<String>> = HashMap::new();
        for (name, value) in url::form_urlencoded::parse(&body.data) {
            if REPEATABLE.contains(&name.as_ref()) {
                repeated
                    .entry(name.into_owned())
                    .or_default()
                    .push(value.into_owned());
            } else if single
                .insert(name.into_owned(), value.into_owned())
                .is_some()
            {
                return Err("a parameter is repeated");
            }
        }
        Ok(Self { single, repeated })
    }

    /// The value of `name`; a parameter sent without a value counts as
    /// omitted (RFC 6749 §3.2).
    pub fn take(&mut self, name: &str) -> Option<String> {
        self.single.remove(name).filter(|value| !value.is_empty())
    }

    /// Every value of the repeatable parameter `name`, in request order,
    /// empty values omitted.
    pub fn take_all(&mut self, name: &str) -> Vec<String> {
        let mut values = self.repeated.remove(name).unwrap_or_default();
        values.retain(|value| !value.is_empty());
        values
    }
}

/// An answer with `status`, a JSON `body`, and the `cache-control: no-store`
/// every OAuth answer carrying or refusing a credential needs (RFC 6749 §5.1,
/// §5.2).
pub fn json(status: u16, body: &serde_json::Value) -> Response<HttpBody> {
    let mut response = raw(status, "application/json", body.to_string().into_bytes());
    let metadata = response.metadata_mut();
    metadata.insert("cache-control", MetadataValue::from_static("no-store"));
    metadata.insert("pragma", MetadataValue::from_static("no-cache"));
    response
}

/// An answer with `status` and a body of `content_type` (empty for none).
pub fn raw(status: u16, content_type: &str, data: Vec<u8>) -> Response<HttpBody> {
    let mut response = Response::new(HttpBody {
        content_type: content_type.to_string(),
        data,
        extensions: Vec::new(),
    });
    response.metadata_mut().insert(
        "x-http-code",
        status
            .to_string()
            .parse()
            .expect("a status code is a header value"),
    );
    response
}

/// An `invalid_request` answer with `description` (RFC 6749 §5.2).
pub fn invalid_request(description: &str) -> Response<HttpBody> {
    error_json(400, "invalid_request", description)
}

/// The RFC answer to a refusal of the typed endpoint. Its `error` is the
/// code in ErrorInfo `oauthError` (RFC 6749 §5.2, RFC 8628 §3.5), status
/// 400, except `invalid_client` for a client that used HTTP Basic: 401 with
/// a Basic challenge for `realm` (RFC 6749 §5.2). A refusal without a code is
/// a server-side condition: 429, 503 or 500 with the RFC 6749 §4.1.2.1 code
/// that names it, and `Retry-After` when the refusal says when to retry
/// (RFC 9110 §10.2.3).
pub fn refusal(status: &Status, basic_used: bool, realm: &str) -> Response<HttpBody> {
    let description = status.message();
    let Some(error) =
        extract_error_info(status).and_then(|(_, _, mut metadata)| metadata.remove("oauthError"))
    else {
        let (code, error) = match status.code() {
            Code::ResourceExhausted => (429, "temporarily_unavailable"),
            Code::Unavailable => (503, "temporarily_unavailable"),
            _ => (500, "server_error"),
        };
        let mut response = error_json(code, error, description);
        copy_retry_after(status, response.metadata_mut());
        return response;
    };
    if error == "invalid_client" && basic_used {
        let mut response = error_json(401, &error, description);
        let challenge = format!(r#"Basic realm="{}""#, quoted(realm));
        match challenge.parse() {
            Ok(value) => {
                response.metadata_mut().insert("www-authenticate", value);
            }
            Err(e) => tracing::error!(error = %e, "Basic challenge is not a header value"),
        }
        return response;
    }
    let mut response = error_json(400, &error, description);
    copy_retry_after(status, response.metadata_mut());
    response
}

/// The RFC answer to a refusal of dynamic registration or client management.
/// Metadata refused under an ErrorInfo `oauthError` is 400 with that code
/// (RFC 7591 §3.2.2), other refused metadata 400 `invalid_client_metadata`.
/// A missing, invalid or used-up initial or registration access token is
/// 401 with a `Bearer` challenge (RFC 6750 §3), naming `invalid_token` when a
/// token was presented (RFC 6750 §3.1) and nothing when none was. An
/// unknown issuer is 404; a server-side failure 503 or 500.
pub fn registration_refusal(status: &Status, token_presented: bool) -> Response<HttpBody> {
    let description = status.message();
    if let Some(error) =
        extract_error_info(status).and_then(|(_, _, mut metadata)| metadata.remove("oauthError"))
    {
        return error_json(400, &error, description);
    }
    match status.code() {
        Code::Unauthenticated | Code::ResourceExhausted => {
            let (mut response, challenge) = if token_presented {
                (
                    error_json(401, "invalid_token", description),
                    r#"Bearer error="invalid_token""#,
                )
            } else {
                (raw(401, "", Vec::new()), "Bearer")
            };
            response
                .metadata_mut()
                .insert("www-authenticate", MetadataValue::from_static(challenge));
            response
        }
        Code::NotFound => raw(404, "", Vec::new()),
        Code::InvalidArgument | Code::FailedPrecondition | Code::PermissionDenied => {
            error_json(400, "invalid_client_metadata", description)
        }
        Code::Unavailable => error_json(503, "temporarily_unavailable", description),
        _ => error_json(500, "server_error", description),
    }
}

/// `{error, error_description}` with `status` (RFC 6749 §5.2).
pub fn error_json(status: u16, error: &str, description: &str) -> Response<HttpBody> {
    let mut body = serde_json::json!({ "error": error });
    let description = error_description(description);
    if !description.is_empty() {
        body["error_description"] = serde_json::Value::String(description);
    }
    json(status, &body)
}

/// `description` restricted to the characters RFC 6749 §5.2 allows in
/// `error_description` (%x20-21 / %x23-5B / %x5D-7E: printable ASCII without
/// `"` and `\`).
fn error_description(description: &str) -> String {
    description
        .chars()
        .filter(|c| matches!(c, ' '..='~') && *c != '"' && *c != '\\')
        .collect()
}

/// `value` as the content of an RFC 9110 §5.6.4 quoted-string.
fn quoted(value: &str) -> String {
    value
        .chars()
        .filter(|c| matches!(c, ' '..='~'))
        .flat_map(|c| match c {
            '"' | '\\' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

/// A redirect of the browser to `location`: 303, so a POSTed form is not sent
/// on (RFC 9700 §4.11), and not stored by caches, since it may carry a code.
pub fn redirect(location: &url::Url) -> Response<HttpBody> {
    let mut response = raw(303, "", Vec::new());
    let metadata = response.metadata_mut();
    metadata.insert(
        "location",
        location
            .as_str()
            .parse()
            .expect("a serialized URL is a header value"),
    );
    metadata.insert("cache-control", MetadataValue::from_static("no-store"));
    response
}

/// A page with `status` and plain `text`, shown instead of a redirect.
pub fn page(status: u16, text: &str) -> Response<HttpBody> {
    let mut response = raw(
        status,
        "text/plain; charset=utf-8",
        text.as_bytes().to_vec(),
    );
    response
        .metadata_mut()
        .insert("cache-control", MetadataValue::from_static("no-store"));
    response
}

/// A page asking `question`, with a form that POSTs `confirmation` back to
/// the URL it was served at, and a link back to `return_to` for declining.
/// It may not be framed (CSP `frame-ancestors`, `X-Frame-Options`), so
/// another site cannot overlay it to trick a click, and its form may post
/// only to this origin.
pub fn confirmation_page(
    question: &str,
    confirmation: &str,
    return_to: Option<&url::Url>,
) -> Response<HttpBody> {
    // `confirmation` is base64url, `question` a fixed text: neither needs
    // escaping, and the form's action is the page itself. The return link is
    // a client's registered URI with the relying party's `state`, escaped.
    let back = return_to
        .map(|target| {
            format!(
                "<p><a href=\"{}\">Return to the application</a></p>",
                html_attribute(target.as_str())
            )
        })
        .unwrap_or_default();
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign out</title></head>\
         <body><p>{question}</p><form method=\"post\">\
         <input type=\"hidden\" name=\"confirmation\" value=\"{confirmation}\">\
         <button type=\"submit\">Sign out</button></form>{back}</body></html>"
    );
    let mut response = raw(200, "text/html; charset=utf-8", html.into_bytes());
    let metadata = response.metadata_mut();
    metadata.insert("cache-control", MetadataValue::from_static("no-store"));
    metadata.insert(
        "content-security-policy",
        MetadataValue::from_static(
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    metadata.insert("x-frame-options", MetadataValue::from_static("DENY"));
    response
}

/// `value` escaped for a double-quoted HTML attribute (HTML Living Standard
/// §13.1.2.3: `"` ends it, `&` starts a character reference).
fn html_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// How the authorization endpoint answers a refusal of the typed request.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizeRefusal {
    /// Shown, never redirected: the client or its exact redirect URI is not
    /// established (RFC 6749 §4.1.2.1), or the refusal is not one the core
    /// gives only after establishing them.
    Show(u16, &'static str),
    /// The user must sign in, or sign in again at a higher level.
    SignIn,
    /// Sent to the established redirect URI as this `error` code.
    Redirect(String),
}

/// Classify a refusal of `OAuth2Authorize`. The core establishes the client
/// and its exact redirect URI before anything else and marks those two
/// refusals (`ApplicationNotFound`, and `field = redirect_uri` without an
/// OAuth code), so only what it refuses after that point is redirected.
pub fn classify_authorize_refusal(status: &Status) -> AuthorizeRefusal {
    let oauth_error =
        extract_error_info(status).and_then(|(_, _, mut metadata)| metadata.remove("oauthError"));
    match status.code() {
        Code::Unauthenticated => AuthorizeRefusal::SignIn,
        // The session is below the level or methods the client requires: the
        // user signs in again (OIDC Core 1.0 §3.1.2.3).
        Code::FailedPrecondition => AuthorizeRefusal::SignIn,
        // A policy block, given only once the client is established
        // (RFC 6749 §4.1.2.1 `access_denied`).
        Code::PermissionDenied => AuthorizeRefusal::Redirect("access_denied".into()),
        Code::InvalidArgument => match oauth_error {
            Some(error) => AuthorizeRefusal::Redirect(error),
            None => AuthorizeRefusal::Show(400, "invalid_request"),
        },
        Code::NotFound => AuthorizeRefusal::Show(400, "invalid_client"),
        Code::Unavailable => AuthorizeRefusal::Show(503, "temporarily_unavailable"),
        _ => AuthorizeRefusal::Show(500, "server_error"),
    }
}

/// The authorization response (RFC 6749 §4.1.2, §4.1.2.1): `redirect_uri`
/// with `params`, `state` and the issuer as `iss` (RFC 9207 §2) added to its
/// query, keeping the query it already has.
pub fn authorization_response(
    redirect_uri: &str,
    issuer: &str,
    params: &[(&str, &str)],
    state: Option<&str>,
) -> Response<HttpBody> {
    match authorization_response_url(redirect_uri, issuer, params, state) {
        Some(url) => redirect(&url),
        None => page(400, "Authorization request refused: invalid_request"),
    }
}

/// The URL [`authorization_response`] redirects to, for a front end that
/// sends the browser there itself; `None` when `redirect_uri` is not a URL.
pub fn authorization_response_url(
    redirect_uri: &str,
    issuer: &str,
    params: &[(&str, &str)],
    state: Option<&str>,
) -> Option<url::Url> {
    let mut url = url::Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in params {
            query.append_pair(key, value);
        }
        if let Some(state) = state.filter(|s| !s.is_empty()) {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Some(url)
}

/// The sign-in page `login`, told to return to `authorize_url` (`rd`).
pub fn sign_in(login: &url::Url, authorize_url: &url::Url) -> Response<HttpBody> {
    let mut url = login.clone();
    url.query_pairs_mut()
        .append_pair("rd", authorize_url.as_str());
    redirect(&url)
}

/// A token endpoint refusal as an [`ApiError`]: `ErrorInfo.metadata["oauthError"]`
/// carries the RFC 6749 §5.2 `error` code [`refusal`] answers with.
pub fn token_error(error: TokenError, message: impl Into<Cow<'static, str>>) -> ApiError {
    let reason = match error {
        TokenError::InvalidClient => ErrorReason::AuthenticationFailed,
        TokenError::UnauthorizedClient | TokenError::AccessDenied => {
            ErrorReason::InsufficientPermissions
        }
        TokenError::InvalidScope => ErrorReason::ScopeNotGranted,
        // The user has not yet consented to the device request.
        TokenError::AuthorizationPending => ErrorReason::ConsentRequired,
        TokenError::SlowDown => ErrorReason::RateLimitExceeded,
        TokenError::ExpiredToken => ErrorReason::OperationExpired,
        TokenError::InvalidRequest
        | TokenError::InvalidGrant
        | TokenError::UnsupportedGrantType
        | TokenError::InvalidDpopProof
        | TokenError::InvalidTarget => ErrorReason::InvalidFieldValue,
    };
    ApiError::new(reason, message).with_metadata("oauthError", error.code())
}

/// A token endpoint refusal with `error` (RFC 6749 §5.2).
pub fn token_refusal(error: TokenError, message: impl Into<Cow<'static, str>>) -> Status {
    token_error(error, message).into()
}

/// The client failed to authenticate (RFC 6749 §5.2 `invalid_client`); what
/// failed goes to the log, never to the client.
pub fn client_refused() -> Status {
    token_refusal(TokenError::InvalidClient, "client authentication failed")
}

/// A request whose target resource is refused (RFC 8707 §2
/// `invalid_target`), naming the `resource` parameter.
pub fn target_refused(refusal: crate::target::TargetRefusal) -> Status {
    token_error(TokenError::InvalidTarget, refusal.to_string())
        .with_field_violation("resource", refusal.to_string())
        .with_metadata("field", "resource")
        .into()
}

/// A required token request parameter is missing (RFC 6749 §5.2
/// `invalid_request`).
pub fn missing_parameter(field: &'static str) -> Status {
    ApiError::new(
        ErrorReason::RequiredFieldMissing,
        format!("{field} is required"),
    )
    .with_field_violation(field, "required")
    .with_metadata("field", field)
    .with_metadata("oauthError", TokenError::InvalidRequest.code())
    .into()
}

/// A DPoP proof that is not valid for the request (RFC 9449 §7.1
/// `invalid_dpop_proof`).
pub fn dpop_refusal(detail: impl std::fmt::Display) -> Status {
    ApiError::new(
        ErrorReason::InvalidFieldValue,
        format!("invalid DPoP proof: {detail}"),
    )
    .with_metadata("field", "DPoP")
    .with_metadata("oauthError", TokenError::InvalidDpopProof.code())
    .into()
}

/// The client authentication a request presents: HTTP Basic in its
/// `authorization` metadata, or the given body parameters (RFC 6749 §2.3).
/// An `authorization` value that is not ASCII is no credential.
pub fn client_authentication(
    metadata: &MetadataMap,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
) -> Result<ClientAuthentication, Status> {
    let authorization = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    ClientAuthentication::from_request(
        authorization,
        client_id,
        client_secret,
        client_assertion,
        client_assertion_type,
    )
    .map_err(|error| match error {
        TokenError::InvalidRequest => token_refusal(
            error,
            "the client must name itself and use one authentication method",
        ),
        _ => client_refused(),
    })
}

/// The token endpoint's answer to a refused or failed grant.
pub fn grant_refusal(failure: GrantFailure<Status>) -> Status {
    match failure {
        GrantFailure::MissingParameter(field) => missing_parameter(field),
        GrantFailure::Refused(error, description) => token_refusal(error, description),
        GrantFailure::ProofMismatch => dpop_refusal("refresh token is bound to another key"),
        GrantFailure::Storage(e) => storage_failure(e),
        GrantFailure::Issuance(e) => internal("issue tokens", e),
        GrantFailure::Host(status) => status,
    }
}

/// Carry the retry delay of `status` (RetryInfo) into `to` as `Retry-After`
/// seconds.
fn copy_retry_after(status: &Status, to: &mut MetadataMap) {
    let Some(delay) = extract_retry_delay(status) else {
        return;
    };
    // Round up: waiting less than asked would poll too early.
    let seconds = delay.as_secs() + u64::from(delay.subsec_nanos() > 0);
    to.insert(
        "retry-after",
        seconds
            .to_string()
            .parse()
            .expect("a number is a header value"),
    );
}

#[cfg(test)]
mod tests;
