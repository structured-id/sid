// SPDX-License-Identifier: AGPL-3.0-only
//! An issuer's public endpoints for its relying parties: OIDC Discovery 1.0
//! and RFC 8414 metadata, the JWK Set (RFC 7517) of the keys that sign its
//! tokens, UserInfo (OIDC Core 1.0 §5.3), and the HTTP form of its OAuth
//! endpoints (token, introspection, revocation, device authorization) over
//! the same logic as AuthService. Every answer belongs to the issuer the
//! handle names; there is no issuer-less endpoint and no fallback to another
//! issuer.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use sid::oauth::provider::{Presented, ProviderError};
use sid_authn::resource::Scheme;
use sid_core::models::OidcIssuer;
use sid_infra::authn::resource as presented_request;
use sid_infra::grpc_error::{ApiError, ErrorReason};
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::o_auth2_authorize_response::Result as AuthorizeResult;
use sid_proto::sid::v1::oidc_provider_service_server::OidcProviderService;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::{
    DeviceAuthorizationRequest, EndSessionRequest, IssuerHandleRequest, JsonWebKeySet,
    OAuth2AuthorizeRequest, OAuth2IntrospectRequest, OAuth2RevokeRequest, OAuth2TokenRequest,
    ProtocolRequest, ProviderMetadata, UserInfo,
};
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

use super::auth_service::{
    AuthServiceImpl, BrowserAuthorization, EndSession, LogoutRequest, PendingAuthorization,
    REQUEST_URI_PREFIX,
};
use super::client_metadata;
use super::project_service::ProjectServiceImpl;
use sid_infra::oauth_http::{self, Form};

/// How long HTTP caches may keep a key set, and serve a stale one while
/// fetching the next: a new signing generation is published well before it
/// signs anything.
const JWKS_CACHE_CONTROL: &str = "public, max-age=3600, stale-while-revalidate=600";

/// The UserInfo RPCs, as a native gRPC client calls them.
const GET_USER_INFO_RPC: &str = "/sid.v1.authn.OidcProviderService/GetUserInfo";
const POST_USER_INFO_RPC: &str = "/sid.v1.authn.OidcProviderService/PostUserInfo";

pub struct OidcProviderServiceImpl {
    auth: Arc<AuthServiceImpl>,
    project: Arc<ProjectServiceImpl>,
    login_url: Option<url::Url>,
}

impl OidcProviderServiceImpl {
    /// The issuer endpoints over the engine's OAuth of `auth`: discovery,
    /// keys, UserInfo and the OAuth endpoints; the registration endpoints
    /// run the logic of `project`; a user who must sign in is sent to
    /// `login_url`, or, without one, the client gets `login_required`.
    pub fn new(
        auth: Arc<AuthServiceImpl>,
        project: Arc<ProjectServiceImpl>,
        login_url: Option<url::Url>,
    ) -> Self {
        Self {
            auth,
            project,
            login_url,
        }
    }

    /// The browser authorization endpoint's answer to `request`: a redirect
    /// to the client or to sign-in, or a page when the client or its redirect
    /// URI is not established, or the continued request is not live. A POST
    /// is kept and continued by a top-level GET on this host, where the
    /// browser sends its `SameSite=Lax` IdP session cookie
    /// (RFC 6265bis §5.6.7.1); nothing is decided from the POST itself.
    async fn authorize(
        &self,
        request: Request<OAuth2AuthorizeRequest>,
        method: Method,
    ) -> Result<Response<HttpBody>, Status> {
        use oauth_http::AuthorizeRefusal;

        let issuer = match self.page_issuer(&request.get_ref().issuer_handle).await? {
            Some(issuer) => issuer,
            None => return Ok(oauth_http::page(404, "Unknown issuer")),
        };
        let (metadata, _, asked) = request.into_parts();
        let pending = match asked.request_uri.as_deref() {
            None => PendingAuthorization::arrived(asked),
            Some(uri) => {
                let kept = match uri.strip_prefix(REQUEST_URI_PREFIX) {
                    Some(reference) => self.auth.continue_authorization(reference).await?,
                    None => None,
                };
                // A reference continues only the request of the client and
                // issuer it was kept for, and only once.
                match kept.filter(|kept| {
                    kept.client_id() == asked.client_id
                        && kept.issuer_handle() == asked.issuer_handle
                }) {
                    Some(kept) => kept,
                    None => {
                        return Ok(oauth_http::page(
                            400,
                            "Authorization request expired or unknown: start again from the application",
                        ));
                    }
                }
            }
        };
        let redirect_uri = pending.redirect_uri().to_string();
        let state = pending.state().map(str::to_string);
        let answer = |params: &[(&str, &str)]| {
            oauth_http::authorization_response(
                &redirect_uri,
                &issuer.canonical_url,
                params,
                state.as_deref(),
            )
        };
        let refused = |status: Status| match oauth_http::classify_authorize_refusal(&status) {
            AuthorizeRefusal::Show(code, error) => {
                tracing::info!(error = %status, "authorization request refused without redirect");
                oauth_http::page(code, &format!("Authorization request refused: {error}"))
            }
            AuthorizeRefusal::SignIn => answer(&[("error", "login_required")]),
            AuthorizeRefusal::Redirect(error) => answer(&[("error", &error)]),
        };

        if method == Method::Post {
            // Only an established client's request is kept. This endpoint's
            // own path named the issuer.
            if let Err(status) = self.auth.authorize_client(&pending.request(), None).await {
                return Ok(refused(status));
            }
            let reference = self.auth.keep_authorization(&pending).await?;
            return Ok(
                match continuation(&issuer.canonical_url, pending.client_id(), &reference) {
                    Some(url) => oauth_http::redirect(&url),
                    None => oauth_http::page(500, "Authorization request refused: server_error"),
                },
            );
        }

        let client_id = pending.client_id().to_string();
        match self.auth.browser_authorize(&metadata, pending).await {
            Ok(BrowserAuthorization::Answer(response)) => {
                // An answer means the core established the client and URI.
                let (key, value) = match response.result {
                    Some(AuthorizeResult::AuthorizationCode(code)) => ("code", code),
                    Some(AuthorizeResult::Error(error)) => ("error", error),
                    // Only the code flow is served; a token never goes into a URL.
                    Some(AuthorizeResult::AccessToken(_)) | None => {
                        ("error", "server_error".to_string())
                    }
                };
                Ok(answer(&[(key, &value)]))
            }
            Ok(BrowserAuthorization::NoInteraction(error)) => Ok(answer(&[("error", error)])),
            Ok(BrowserAuthorization::SignIn { reference }) => Ok(
                match (
                    &self.login_url,
                    continuation(&issuer.canonical_url, &client_id, &reference),
                ) {
                    (Some(login), Some(back)) => oauth_http::sign_in(login, &back),
                    _ => answer(&[("error", "login_required")]),
                },
            ),
            Err(status) => Ok(refused(status)),
        }
    }
}

impl OidcProviderServiceImpl {
    /// RP-Initiated Logout `request` at the issuer `handle` names: a 303 to
    /// the validated post-logout redirect, or a page (signed out, or a
    /// confirmation form for ending the browser's IdP session). The IdP
    /// session cookie is cleared when single sign-on ended.
    async fn end_session(
        &self,
        metadata: &MetadataMap,
        handle: &str,
        request: LogoutRequest<'_>,
    ) -> Result<Response<HttpBody>, Status> {
        let issuer = match self.page_issuer(handle).await? {
            Some(issuer) => issuer,
            None => return Ok(oauth_http::page(404, "Unknown issuer")),
        };
        const CONFIRM: &str = "Sign out of your account on this device?";
        let ended = self.auth.end_session(metadata, &issuer, request).await;
        let returned = |return_to: Option<url::Url>, text: &str| match return_to {
            Some(target) => oauth_http::redirect(&target),
            None => oauth_http::page(200, text),
        };
        Ok(match ended {
            Ok(EndSession::SignedOut { return_to }) => {
                let mut answer = returned(return_to, "Signed out");
                answer.metadata_mut().insert(
                    "set-cookie",
                    self.auth.browser_cookie().clear().parse().map_err(|e| {
                        sid_infra::grpc_error::refuse::internal("encode session cookie", e)
                    })?,
                );
                answer
            }
            Ok(EndSession::ApplicationSignedOut {
                confirmation: Some(confirmation),
                return_to,
            }) => oauth_http::confirmation_page(
                "You are signed out of the application. Sign out of your account on this device too?",
                &confirmation,
                return_to.as_ref(),
            ),
            Ok(EndSession::ApplicationSignedOut {
                confirmation: None,
                return_to,
            }) => returned(return_to, "Signed out of the application"),
            Ok(EndSession::Confirm { confirmation }) => {
                oauth_http::confirmation_page(CONFIRM, &confirmation, None)
            }
            Ok(EndSession::NothingToEnd { return_to }) => returned(return_to, "Signed out"),
            Err(status) => {
                tracing::warn!(error = %status, "end-session failed");
                let code = if status.code() == tonic::Code::Unavailable {
                    503
                } else {
                    500
                };
                oauth_http::page(code, "Logout failed, try again")
            }
        })
    }
}

/// How the browser endpoint was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
}

/// The GET of this issuer's authorization endpoint that continues the request
/// kept under `reference` for `client_id`: what a cross-site POST redirects
/// to, and what the sign-in page returns to. It carries no parameter of the
/// request itself.
fn continuation(issuer_url: &str, client_id: &str, reference: &str) -> Option<url::Url> {
    let mut url = url::Url::parse(&format!("{issuer_url}/oauth2/authorize")).ok()?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("request_uri", &format!("{REQUEST_URI_PREFIX}{reference}"));
    Some(url)
}

/// The authorization request a POSTed form makes (OIDC Core 1.0 §3.1.2.1);
/// parameters the endpoint does not know are ignored (RFC 6749 §3.1). A
/// `max_age` that is not a count of seconds refuses the form.
fn form_authorize_request(
    form: &mut Form,
    issuer_handle: String,
) -> Result<OAuth2AuthorizeRequest, ()> {
    let max_age = form
        .take("max_age")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| ())?;
    Ok(OAuth2AuthorizeRequest {
        client_id: form.take("client_id").unwrap_or_default(),
        redirect_uri: form.take("redirect_uri").unwrap_or_default(),
        response_type: form.take("response_type").unwrap_or_default(),
        scope: form.take("scope"),
        state: form.take("state"),
        code_challenge: form.take("code_challenge"),
        code_challenge_method: form.take("code_challenge_method"),
        nonce: form.take("nonce"),
        acr_values: form.take("acr_values"),
        issuer_handle,
        resource: form.take_all("resource"),
        prompt: form.take("prompt"),
        max_age,
        request_uri: form.take("request_uri"),
    })
}

impl OidcProviderServiceImpl {
    /// The issuer `handle` names for a page answer; `None` for no issuer.
    async fn page_issuer(&self, handle: &str) -> Result<Option<OidcIssuer>, Status> {
        match self.auth.oauth().issuer_by_handle(handle).await {
            Ok(issuer) => Ok(Some(issuer)),
            Err(ProviderError::IssuerNotFound(_)) => Ok(None),
            Err(e) => Err(provider_refusal(e)),
        }
    }

    /// UserInfo for a request to the RPC at `rpc` (OIDC Core 1.0 §5.3; see
    /// [`sid::oauth::OAuth::user_info`]), its proof naming the request as
    /// received, over REST or gRPC.
    async fn user_info(
        &self,
        request: Request<IssuerHandleRequest>,
        rpc: &str,
    ) -> Result<Response<UserInfo>, Status> {
        let target = presented_request::request_target(&request, self.auth.public_origin(), rpc);
        let proofs = presented_request::proofs(&request);
        let presented = presented_request::presented(&request).map(|(scheme, token)| Presented {
            scheme,
            token,
            proofs: &proofs,
            method: &target.method,
            uri: &target.uri,
        });
        self.auth
            .oauth()
            .user_info(&request.get_ref().issuer_handle, presented)
            .await
            .map(Response::new)
            .map_err(provider_refusal)
    }
}

/// The answer to a refused or failed issuer endpoint: the RFC 6750 / RFC 9449
/// challenges go out as `www-authenticate`.
fn provider_refusal(e: ProviderError) -> Status {
    match e {
        ProviderError::IssuerNotFound(handle) => ApiError::new(
            ErrorReason::OidcIssuerNotFound,
            "no OIDC issuer has this handle",
        )
        .with_resource("OidcIssuer", handle)
        .into(),
        ProviderError::NoToken => no_token(),
        ProviderError::InvalidToken(scheme) => invalid_token(scheme),
        ProviderError::Proof { challenge } => refused(
            ErrorReason::TokenInvalid,
            "the proof of possession is not valid",
            &[challenge],
        ),
        ProviderError::InsufficientScope(scheme) => refused(
            ErrorReason::ScopeNotGranted,
            "the access token lacks the openid scope",
            &[format!(
                r#"{} error="insufficient_scope", scope="openid""#,
                scheme_name(scheme)
            )],
        ),
        ProviderError::Unavailable { what, cause } => {
            sid_infra::grpc_error::refuse::dependency_unavailable(what, cause)
        }
        ProviderError::Store(e) => internal(e),
    }
}

/// The typed request `build` makes of `request`'s form, carrying its
/// metadata (HTTP Basic, DPoP, forwarded client address) and extensions, and
/// whether the client used HTTP Basic; or the `invalid_request` answer to a
/// body that is not the form.
fn form_request<T>(
    request: Request<ProtocolRequest>,
    build: impl FnOnce(&mut Form, String) -> T,
) -> Result<(Request<T>, bool), Response<HttpBody>> {
    let (metadata, extensions, protocol) = request.into_parts();
    let mut form = Form::parse(protocol.body.as_ref()).map_err(oauth_http::invalid_request)?;
    let basic = uses_basic(&metadata);
    let typed = build(&mut form, protocol.issuer_handle);
    Ok((Request::from_parts(metadata, extensions, typed), basic))
}

/// Whether the request authenticates its client with HTTP Basic (RFC 7617).
fn uses_basic(metadata: &MetadataMap) -> bool {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
}

/// `value` under `name` in `body` when it is set.
fn put(body: &mut Map<String, Value>, name: &str, value: Option<impl Into<Value>>) {
    if let Some(value) = value {
        body.insert(name.to_string(), value.into());
    }
}

fn internal(e: sid_core::Error) -> Status {
    tracing::error!(error = %e, "reading an OIDC issuer");
    Status::from(ApiError::internal())
}

/// A refusal carrying `challenges` as `www-authenticate` response metadata
/// (RFC 6750 §3, RFC 9449 §7.1).
fn refused(reason: ErrorReason, message: &'static str, challenges: &[String]) -> Status {
    let mut status: Status = ApiError::new(reason, message).into();
    for challenge in challenges {
        match challenge.parse() {
            Ok(value) => {
                status.metadata_mut().append("www-authenticate", value);
            }
            Err(e) => tracing::error!(error = %e, "challenge is not a header value"),
        }
    }
    status
}

/// The name of `scheme` in a challenge.
fn scheme_name(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Bearer => "Bearer",
        Scheme::DPoP => "DPoP",
    }
}

/// No token: both schemes are offered, without an error code (RFC 6750 §3,
/// RFC 9449 §7.1).
fn no_token() -> Status {
    let algs = sid_core::models::dpop::DPopProof::SIGNING_ALGORITHMS.join(" ");
    refused(
        ErrorReason::TokenInvalid,
        "an access token is required",
        &["Bearer".into(), format!(r#"DPoP algs="{algs}""#)],
    )
}

/// The token presented under `scheme` is not valid here (RFC 6750 §3.1).
fn invalid_token(scheme: Scheme) -> Status {
    refused(
        ErrorReason::TokenInvalid,
        "the access token is not valid",
        &[format!(r#"{} error="invalid_token""#, scheme_name(scheme))],
    )
}

#[tonic::async_trait]
impl OidcProviderService for OidcProviderServiceImpl {
    /// Public data every relying party fetches, so the caller is not
    /// authenticated.
    async fn get_provider_metadata(
        &self,
        request: Request<IssuerHandleRequest>,
    ) -> Result<Response<ProviderMetadata>, Status> {
        self.auth
            .oauth()
            .provider_metadata(&request.into_inner().issuer_handle)
            .await
            .map(Response::new)
            .map_err(provider_refusal)
    }

    /// Public keys only, so the caller is not authenticated.
    async fn get_jwks(
        &self,
        request: Request<IssuerHandleRequest>,
    ) -> Result<Response<JsonWebKeySet>, Status> {
        let mut response = Response::new(
            self.auth
                .oauth()
                .jwks(&request.into_inner().issuer_handle)
                .await
                .map_err(provider_refusal)?,
        );
        response.metadata_mut().insert(
            "cache-control",
            tonic::metadata::MetadataValue::from_static(JWKS_CACHE_CONTROL),
        );
        Ok(response)
    }

    async fn get_user_info(
        &self,
        request: Request<IssuerHandleRequest>,
    ) -> Result<Response<UserInfo>, Status> {
        self.user_info(request, GET_USER_INFO_RPC).await
    }

    async fn post_user_info(
        &self,
        request: Request<IssuerHandleRequest>,
    ) -> Result<Response<UserInfo>, Status> {
        self.user_info(request, POST_USER_INFO_RPC).await
    }

    async fn get_authorize(
        &self,
        request: Request<OAuth2AuthorizeRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        self.authorize(request, Method::Get).await
    }

    /// A form that is not one, repeats a parameter (RFC 6749 §3.1) or has a
    /// malformed `max_age` is shown: nothing about its client is established
    /// yet.
    async fn post_authorize(
        &self,
        request: Request<ProtocolRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let refused = || oauth_http::page(400, "Authorization request refused: invalid_request");
        match form_request(request, form_authorize_request) {
            Ok((typed, _)) => {
                let (metadata, extensions, parsed) = typed.into_parts();
                match parsed {
                    Ok(parsed) => {
                        self.authorize(
                            Request::from_parts(metadata, extensions, parsed),
                            Method::Post,
                        )
                        .await
                    }
                    Err(()) => Ok(refused()),
                }
            }
            Err(_) => Ok(refused()),
        }
    }

    async fn get_end_session(
        &self,
        request: Request<EndSessionRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let (metadata, _, asked) = request.into_parts();
        self.end_session(
            &metadata,
            &asked.issuer_handle,
            LogoutRequest {
                id_token_hint: asked.id_token_hint.as_deref(),
                client_id: asked.client_id.as_deref(),
                post_logout_redirect_uri: asked.post_logout_redirect_uri.as_deref(),
                state: asked.state.as_deref(),
                confirmation: None,
            },
        )
        .await
    }

    /// A form that is not one, or repeats a parameter (RFC 6749 §3.1), ends
    /// nothing.
    async fn post_end_session(
        &self,
        request: Request<ProtocolRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let parsed = form_request(request, |form, issuer_handle| {
            (
                issuer_handle,
                [
                    form.take("id_token_hint"),
                    form.take("client_id"),
                    form.take("post_logout_redirect_uri"),
                    form.take("state"),
                    form.take("confirmation"),
                ],
            )
        });
        match parsed {
            Ok((typed, _)) => {
                let (metadata, _, (handle, [hint, client_id, uri, state, confirmation])) =
                    typed.into_parts();
                self.end_session(
                    &metadata,
                    &handle,
                    LogoutRequest {
                        id_token_hint: hint.as_deref(),
                        client_id: client_id.as_deref(),
                        post_logout_redirect_uri: uri.as_deref(),
                        state: state.as_deref(),
                        confirmation: confirmation.as_deref(),
                    },
                )
                .await
            }
            Err(_) => Ok(oauth_http::page(
                400,
                "Logout request refused: invalid_request",
            )),
        }
    }

    /// Every grant of the token endpoint. The DPoP proof comes from the
    /// `dpop` metadata only (RFC 9449 §4.1), never from the form.
    async fn token(&self, request: Request<ProtocolRequest>) -> Result<Response<HttpBody>, Status> {
        let parsed = form_request(request, |form, issuer_handle| OAuth2TokenRequest {
            grant_type: form.take("grant_type").unwrap_or_default(),
            code: form.take("code"),
            redirect_uri: form.take("redirect_uri"),
            client_id: form.take("client_id"),
            client_secret: form.take("client_secret"),
            refresh_token: form.take("refresh_token"),
            code_verifier: form.take("code_verifier"),
            dpop_proof: None,
            scope: form.take("scope"),
            client_assertion: form.take("client_assertion"),
            client_assertion_type: form.take("client_assertion_type"),
            subject_token: form.take("subject_token"),
            subject_token_type: form.take("subject_token_type"),
            issuer_handle,
            device_code: form.take("device_code"),
            resource: form.take_all("resource"),
            audience: form.take_all("audience"),
            requested_token_type: form.take("requested_token_type"),
        });
        let (typed, basic) = match parsed {
            Ok(parsed) => parsed,
            Err(answer) => return Ok(answer),
        };
        // RFC 6749 §4.1.3, §4.4.2, §6: grant_type is REQUIRED.
        if typed.get_ref().grant_type.is_empty() {
            return Ok(oauth_http::invalid_request("grant_type is required"));
        }
        let realm = typed.get_ref().issuer_handle.clone();
        match self.auth.o_auth2_token(typed).await {
            Ok(response) => {
                let issued = response.into_inner();
                // RFC 6749 §5.1: `expires_in` is a JSON number.
                let mut body = Map::new();
                body.insert("access_token".into(), issued.access_token.into());
                body.insert("token_type".into(), issued.token_type.into());
                body.insert("expires_in".into(), issued.expires_in.into());
                put(&mut body, "refresh_token", issued.refresh_token);
                put(&mut body, "id_token", issued.id_token);
                put(&mut body, "scope", issued.scope);
                put(&mut body, "issued_token_type", issued.issued_token_type);
                Ok(oauth_http::json(200, &Value::Object(body)))
            }
            Err(status) => Ok(oauth_http::refusal(&status, basic, &realm)),
        }
    }

    /// Token introspection. A token this issuer does not vouch for is only
    /// `{"active": false}` (RFC 7662 §2.2).
    async fn introspect(
        &self,
        request: Request<ProtocolRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let parsed = form_request(request, |form, issuer_handle| OAuth2IntrospectRequest {
            token: form.take("token").unwrap_or_default(),
            issuer_handle,
            client_id: form.take("client_id"),
            client_secret: form.take("client_secret"),
            client_assertion: form.take("client_assertion"),
            client_assertion_type: form.take("client_assertion_type"),
        });
        let (typed, basic) = match parsed {
            Ok(parsed) => parsed,
            Err(answer) => return Ok(answer),
        };
        // RFC 7662 §2.1: token is REQUIRED.
        if typed.get_ref().token.is_empty() {
            return Ok(oauth_http::invalid_request("token is required"));
        }
        let realm = typed.get_ref().issuer_handle.clone();
        match self.auth.o_auth2_introspect(typed).await {
            Ok(response) => {
                let info = response.into_inner();
                if !info.active {
                    return Ok(oauth_http::json(200, &json!({ "active": false })));
                }
                let mut body = Map::new();
                body.insert("active".into(), true.into());
                put(&mut body, "scope", info.scope);
                put(&mut body, "client_id", info.client_id);
                put(&mut body, "username", info.username);
                // RFC 7662 §2.2: `exp` and `iat` are JSON numbers.
                put(&mut body, "exp", info.exp);
                put(&mut body, "iat", info.iat);
                put(&mut body, "sub", info.sub);
                Ok(oauth_http::json(200, &Value::Object(body)))
            }
            Err(status) => Ok(oauth_http::refusal(&status, basic, &realm)),
        }
    }

    /// Token revocation: 200 with no content, also for a token that is
    /// unknown or already revoked (RFC 7009 §2.2).
    async fn revoke(
        &self,
        request: Request<ProtocolRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let parsed = form_request(request, |form, issuer_handle| OAuth2RevokeRequest {
            token: form.take("token").unwrap_or_default(),
            token_type_hint: form.take("token_type_hint"),
            issuer_handle,
            client_id: form.take("client_id"),
            client_secret: form.take("client_secret"),
            client_assertion: form.take("client_assertion"),
            client_assertion_type: form.take("client_assertion_type"),
        });
        let (typed, basic) = match parsed {
            Ok(parsed) => parsed,
            Err(answer) => return Ok(answer),
        };
        // RFC 7009 §2.1: token is REQUIRED.
        if typed.get_ref().token.is_empty() {
            return Ok(oauth_http::invalid_request("token is required"));
        }
        let realm = typed.get_ref().issuer_handle.clone();
        match self.auth.o_auth2_revoke(typed).await {
            Ok(_) => Ok(oauth_http::raw(200, "", Vec::new())),
            Err(status) => Ok(oauth_http::refusal(&status, basic, &realm)),
        }
    }

    /// Device authorization (RFC 8628 §3.1, §3.2).
    async fn device_authorization(
        &self,
        request: Request<ProtocolRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let parsed = form_request(request, |form, issuer_handle| DeviceAuthorizationRequest {
            client_id: form.take("client_id"),
            scope: form.take("scope"),
            issuer_handle,
            client_secret: form.take("client_secret"),
            resource: form.take_all("resource"),
            client_assertion: form.take("client_assertion"),
            client_assertion_type: form.take("client_assertion_type"),
        });
        let (typed, basic) = match parsed {
            Ok(parsed) => parsed,
            Err(answer) => return Ok(answer),
        };
        let realm = typed.get_ref().issuer_handle.clone();
        match self.auth.start_device_authorization(typed).await {
            Ok(response) => {
                let started = response.into_inner();
                // RFC 8628 §3.2: `expires_in` and `interval` are JSON numbers.
                Ok(oauth_http::json(
                    200,
                    &json!({
                        "device_code": started.device_code,
                        "user_code": started.user_code,
                        "verification_uri": started.verification_uri,
                        "verification_uri_complete": started.verification_uri_complete,
                        "expires_in": started.expires_in,
                        "interval": started.interval,
                    }),
                ))
            }
            Err(status) => Ok(oauth_http::refusal(&status, basic, &realm)),
        }
    }

    /// Client registration (RFC 7591 §3): 201 with the client information
    /// and its credentials.
    async fn register(
        &self,
        request: Request<ProtocolRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let (metadata, extensions, protocol) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = match client_metadata::Metadata::parse(protocol.body.as_ref()) {
            Ok(parsed) => parsed.into_registration(protocol.issuer_handle),
            Err(invalid) => return Ok(invalid_metadata(&invalid)),
        };
        match self
            .project
            .register_client(Request::from_parts(metadata, extensions, typed))
            .await
        {
            Ok(response) => {
                let registered = response.into_inner();
                let client = registered
                    .client
                    .ok_or_else(|| Status::from(ApiError::internal()))?;
                let credentials = client_metadata::Credentials {
                    client_secret: registered.client_secret.as_deref(),
                    registration_access_token: &registered.registration_access_token,
                };
                Ok(oauth_http::json(
                    201,
                    &client_metadata::client_information(&client, Some(credentials)),
                ))
            }
            Err(status) => Ok(oauth_http::registration_refusal(&status, presented)),
        }
    }

    /// Read a registration (RFC 7592 §2.1).
    async fn read_registration(
        &self,
        request: Request<sid_proto::sid::v1::RegistrationRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let (metadata, extensions, managed) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = sid_proto::sid::v1::GetRegisteredClientRequest {
            client_id: managed.client_id,
            issuer_handle: managed.issuer_handle,
        };
        match self
            .project
            .get_registered_client(Request::from_parts(metadata, extensions, typed))
            .await
        {
            Ok(application) => Ok(oauth_http::json(
                200,
                &client_metadata::client_information(&application.into_inner(), None),
            )),
            Err(status) => Ok(oauth_http::registration_refusal(&status, presented)),
        }
    }

    /// Update a registration (RFC 7592 §2.2): the body replaces the metadata.
    async fn update_registration(
        &self,
        request: Request<sid_proto::sid::v1::RegistrationRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let (metadata, extensions, managed) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = match client_metadata::Metadata::parse(managed.body.as_ref())
            .and_then(|parsed| parsed.into_update(managed.client_id, managed.issuer_handle))
        {
            Ok(typed) => typed,
            Err(invalid) => return Ok(invalid_metadata(&invalid)),
        };
        match self
            .project
            .update_registered_client(Request::from_parts(metadata, extensions, typed))
            .await
        {
            Ok(application) => Ok(oauth_http::json(
                200,
                &client_metadata::client_information(&application.into_inner(), None),
            )),
            Err(status) => Ok(oauth_http::registration_refusal(&status, presented)),
        }
    }

    /// Delete a registration (RFC 7592 §2.3): 204 with no body.
    async fn delete_registration(
        &self,
        request: Request<sid_proto::sid::v1::RegistrationRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let (metadata, extensions, managed) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = sid_proto::sid::v1::DeleteRegisteredClientRequest {
            client_id: managed.client_id,
            issuer_handle: managed.issuer_handle,
        };
        match self
            .project
            .delete_registered_client(Request::from_parts(metadata, extensions, typed))
            .await
        {
            Ok(_) => Ok(oauth_http::raw(204, "", Vec::new())),
            Err(status) => Ok(oauth_http::registration_refusal(&status, presented)),
        }
    }
}

/// Whether the request presents a bearer token (RFC 6750 §2.1).
fn bearer_presented(metadata: &MetadataMap) -> bool {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
}

/// The 400 answer to a body that is not readable client metadata
/// (RFC 7591 §3.2.2 `invalid_client_metadata`).
fn invalid_metadata(invalid: &client_metadata::Invalid) -> Response<HttpBody> {
    oauth_http::error_json(400, "invalid_client_metadata", invalid.description)
}

#[cfg(test)]
mod tests;
