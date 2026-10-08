// SPDX-License-Identifier: AGPL-3.0-only
//! An issuer's public endpoints for its relying parties: OIDC Discovery 1.0
//! and RFC 8414 metadata, the JWK Set (RFC 7517) of the keys that sign its
//! tokens, UserInfo (OIDC Core 1.0 §5.3), and the HTTP form of its OAuth
//! endpoints (token, introspection, revocation, device authorization) over
//! the same logic as AuthService. Every answer belongs to the issuer the
//! handle names; there is no issuer-less endpoint and no fallback to another
//! issuer.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use sid_authn::dpop::DPopValidator;
use sid_authn::issuer::IssuerRegistry;
use sid_authn::resource::{self, Scheme};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{OidcIssuer, SessionId};
use sid_plugin::cache::CacheBackend;
use sid_plugin::storage::StorageBackend;
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::o_auth2_authorize_response::Result as AuthorizeResult;
use sid_proto::sid::v1::oidc_provider_service_server::OidcProviderService;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::{
    DeviceAuthorizationRequest, EndSessionRequest, IssuerHandleRequest, JsonWebKey, JsonWebKeySet,
    OAuth2AuthorizeRequest, OAuth2IntrospectRequest, OAuth2RevokeRequest, OAuth2TokenRequest,
    ProtocolRequest, ProviderMetadata, UserInfo,
};
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

use super::auth_service::{
    AuthServiceImpl, BrowserAuthorization, EndSession, LogoutRequest, PendingAuthorization,
};
use super::client_metadata;
use super::oauth_http::{self, Form};
use super::project_service::ProjectServiceImpl;

/// How long HTTP caches may keep a key set, and serve a stale one while
/// fetching the next: a new signing generation is published well before it
/// signs anything.
const JWKS_CACHE_CONTROL: &str = "public, max-age=3600, stale-while-revalidate=600";

/// The UserInfo RPCs, as a native gRPC client calls them.
const GET_USER_INFO_RPC: &str = "/sid.v1.authn.OidcProviderService/GetUserInfo";
const POST_USER_INFO_RPC: &str = "/sid.v1.authn.OidcProviderService/PostUserInfo";

pub struct OidcProviderServiceImpl {
    issuers: Arc<IssuerRegistry>,
    storage: Arc<dyn StorageBackend>,
    revocation: Arc<RevocationCache>,
    dpop: DPopValidator,
    auth: Arc<AuthServiceImpl>,
    project: Arc<ProjectServiceImpl>,
    login_url: Option<url::Url>,
}

impl OidcProviderServiceImpl {
    /// The endpoints of the issuers in `issuers`; UserInfo reads users from
    /// `storage`, checks revocation in `revocation` and records DPoP proofs
    /// in `cache`, which every replica shares. The OAuth endpoints run the
    /// logic of `auth`, the registration endpoints that of `project`; a user
    /// who must sign in is sent to `login_url`, or, without one, the client
    /// gets `login_required`.
    pub fn new(
        issuers: Arc<IssuerRegistry>,
        storage: Arc<dyn StorageBackend>,
        revocation: Arc<RevocationCache>,
        cache: Arc<dyn CacheBackend>,
        auth: Arc<AuthServiceImpl>,
        project: Arc<ProjectServiceImpl>,
        login_url: Option<url::Url>,
    ) -> Self {
        Self {
            issuers,
            storage,
            revocation,
            dpop: DPopValidator::new(cache),
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

        let issuer = match self
            .issuers
            .by_handle(&request.get_ref().issuer_handle)
            .await
        {
            Ok(Some(issuer)) => issuer,
            Ok(None) => return Ok(oauth_http::page(404, "Unknown issuer")),
            Err(e) => return Err(internal(e)),
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
            // Only an established client's request is kept.
            if let Err(status) = self.auth.authorize_client(&pending.request()).await {
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
        let issuer = match self.issuers.by_handle(handle).await {
            Ok(Some(issuer)) => issuer,
            Ok(None) => return Ok(oauth_http::page(404, "Unknown issuer")),
            Err(e) => return Err(internal(e)),
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
                    sid_authn::browser_session::clear_cookie()
                        .parse()
                        .map_err(|e| {
                            sid_core::grpc_error::refuse::internal("encode session cookie", e)
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

/// Prefix of the `request_uri` that continues a kept request, the form of
/// RFC 9126 §2.2.
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

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
    /// The issuer `handle` names, or NOT_FOUND.
    async fn issuer(&self, handle: &str) -> Result<OidcIssuer, Status> {
        match self.issuers.by_handle(handle).await {
            Ok(Some(issuer)) => Ok(issuer),
            Ok(None) => Err(ApiError::new(
                ErrorReason::OidcIssuerNotFound,
                "no OIDC issuer has this handle",
            )
            .with_resource("OidcIssuer", handle)
            .into()),
            Err(e) => Err(internal(e)),
        }
    }

    /// UserInfo for a request to the RPC at `rpc` (OIDC Core 1.0 §5.3): the
    /// token must be one this issuer signed for its UserInfo resource,
    /// unrevoked, for the `openid` scope, sent under its key binding (its
    /// proof naming the request as received, over REST or gRPC), and of a
    /// session that still exists.
    async fn user_info(
        &self,
        request: Request<IssuerHandleRequest>,
        rpc: &str,
    ) -> Result<Response<UserInfo>, Status> {
        let proof_target =
            sid_authn::resource::request_target(&request, self.auth.public_origin(), rpc);
        let issuer = self.issuer(&request.get_ref().issuer_handle).await?;
        let Some((scheme, token)) = resource::presented(&request) else {
            return Err(no_token());
        };
        let verifier = self.issuers.verifier(&issuer).await.map_err(internal)?;
        // Only this issuer's tokens for its UserInfo resource: a sibling
        // issuer's or a sign-in token names another `iss` or key, and a token
        // for another resource another `aud` (RFC 9068 §4).
        let endpoint = sid_authn::issuer::userinfo_endpoint(&issuer.canonical_url);
        let claims = verifier
            .validate_access_token_for(token, &endpoint)
            .map_err(|_| invalid_token(scheme))?;
        match self.revocation.is_revoked(&claims.jti, &claims.sid).await {
            Ok(false) => {}
            Ok(true) => return Err(invalid_token(scheme)),
            Err(e) => {
                return Err(sid_core::grpc_error::refuse::dependency_unavailable(
                    "token revocation state",
                    e,
                ));
            }
        }
        // A key-bound token needs its proof for this request (RFC 9449 §7.1),
        // naming it as it was received.
        resource::check_sender(
            &self.dpop,
            scheme,
            token,
            claims.cnf.as_ref().map(|cnf| cnf.jkt.as_str()),
            &resource::proofs(&request),
            &proof_target.method,
            Some(&proof_target.uri),
        )
        .await
        .map_err(|e| match e {
            // An unreachable replay record cannot rule out a replay; the
            // client retries the same request with a new proof.
            resource::SenderError::Proof(sid_authn::dpop::DPopError::ReplayCacheUnavailable) => {
                sid_core::grpc_error::refuse::dependency_unavailable(
                    "DPoP replay record",
                    "replay cache unreachable",
                )
            }
            other => {
                tracing::debug!(error = %other, "UserInfo: sender constraint not met");
                refused(
                    ErrorReason::TokenInvalid,
                    "the proof of possession is not valid",
                    &[other.challenge().to_string()],
                )
            }
        })?;
        // RFC 6750 §3.1: a token without `openid` was not issued for UserInfo.
        if !claims.scope.split_whitespace().any(|s| s == "openid") {
            return Err(refused(
                ErrorReason::ScopeNotGranted,
                "the access token lacks the openid scope",
                &[format!(
                    r#"{} error="insufficient_scope", scope="openid""#,
                    scheme_name(scheme)
                )],
            ));
        }
        let session_id = SessionId::parse(&claims.sid).map_err(|_| invalid_token(scheme))?;
        let session = match self.storage.get_session(session_id).await {
            Ok(Some(session)) if !session.is_expired() => session,
            Ok(_) => return Err(invalid_token(scheme)),
            Err(e) => return Err(internal(e)),
        };
        let profile = match self.storage.get_profile(session.profile_id).await {
            Ok(Some(profile)) => profile,
            Ok(None) => return Err(invalid_token(scheme)),
            Err(e) => return Err(internal(e)),
        };
        let email = self
            .storage
            .get_primary_profile_email(profile.id)
            .await
            .map_err(internal)?;
        let phone = self
            .storage
            .get_primary_profile_phone(profile.id)
            .await
            .map_err(internal)?;
        // `sub` as the token carries it: the ID token of this client under the
        // same hop carried the same value (OIDC Core 1.0 §5.3.2).
        Ok(Response::new(granted_claims(
            claims.sub.clone(),
            &claims.scope,
            &profile,
            email.as_ref(),
            phone.as_ref(),
        )))
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

/// The claims of `profile` the token's `scopes` grant (OIDC Core 1.0 §5.4),
/// about subject `sub`.
fn granted_claims(
    sub: String,
    scopes: &str,
    profile: &sid_core::models::Profile,
    email: Option<&sid_core::models::ProfileEmail>,
    phone: Option<&sid_core::models::ProfilePhone>,
) -> UserInfo {
    let granted = |scope: &str| scopes.split_whitespace().any(|s| s == scope);
    let mut info = UserInfo {
        sub,
        ..Default::default()
    };
    if granted("profile") {
        info.name = profile.formatted_name();
        info.given_name = profile.given_name.clone();
        info.family_name = profile.family_name.clone();
        info.middle_name = profile.middle_name.clone();
        info.preferred_username = profile.username.clone();
        // Seconds since the epoch fit 32 bits until 2106; a time outside
        // that range is left out rather than wrapped.
        info.updated_at = u32::try_from(profile.updated_at.timestamp()).ok();
    }
    if granted("email")
        && let Some(email) = email
    {
        info.email = Some(email.email.clone());
        info.email_verified = Some(email.verified);
    }
    if granted("phone")
        && let Some(phone) = phone
    {
        info.phone_number = Some(phone.formatted_e164());
        info.phone_number_verified = Some(phone.verified);
    }
    info
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

/// The asymmetric algorithms a registered client key verifies, wherever a
/// client authenticates with `private_key_jwt`.
const CLIENT_ASSERTION_ALGORITHMS: &[&str] = &[
    "EdDSA", "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];

/// The metadata of `issuer`: every endpoint under its URL.
fn metadata(issuer: &str) -> ProviderMetadata {
    ProviderMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        userinfo_endpoint: sid_authn::issuer::userinfo_endpoint(issuer),
        jwks_uri: format!("{issuer}/jwks"),
        end_session_endpoint: format!("{issuer}/oauth2/end-session"),
        introspection_endpoint: format!("{issuer}/oauth2/introspect"),
        revocation_endpoint: format!("{issuer}/oauth2/revoke"),
        device_authorization_endpoint: format!("{issuer}/oauth2/device"),
        response_types_supported: strings(&["code"]),
        grant_types_supported: strings(&[
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ]),
        // OIDC Core §8: `public` is issuer-relative. Within this issuer every
        // client of the organization gets the same permitted subject for a
        // user; other organizations and contours are other issuers.
        subject_types_supported: strings(&["public"]),
        // Signed with the issuer's own Ed25519 key.
        id_token_signing_alg_values_supported: strings(&["EdDSA"]),
        scopes_supported: strings(&["openid", "profile", "email", "offline_access"]),
        token_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ]),
        token_endpoint_auth_signing_alg_values_supported: strings(CLIENT_ASSERTION_ALGORITHMS),
        // Revocation authenticates a client as the token endpoint does
        // (RFC 7009 §2.1), a public one by naming itself.
        revocation_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ]),
        revocation_endpoint_auth_signing_alg_values_supported: strings(CLIENT_ASSERTION_ALGORITHMS),
        // Only an authenticated caller introspects (RFC 7662 §2.1, §4).
        introspection_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ]),
        introspection_endpoint_auth_signing_alg_values_supported: strings(
            CLIENT_ASSERTION_ALGORITHMS,
        ),
        code_challenge_methods_supported: strings(&["S256"]),
        dpop_signing_alg_values_supported: strings(
            sid_core::models::dpop::DPopProof::SIGNING_ALGORITHMS,
        ),
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        // RFC 9207 §3: every authorization response names its issuer.
        authorization_response_iss_parameter_supported: true,
        registration_endpoint: format!("{issuer}/oauth2/register"),
    }
}

#[tonic::async_trait]
impl OidcProviderService for OidcProviderServiceImpl {
    /// Public data every relying party fetches, so the caller is not
    /// authenticated.
    async fn get_provider_metadata(
        &self,
        request: Request<IssuerHandleRequest>,
    ) -> Result<Response<ProviderMetadata>, Status> {
        let issuer = self.issuer(&request.into_inner().issuer_handle).await?;
        Ok(Response::new(metadata(&issuer.canonical_url)))
    }

    /// Public keys only, so the caller is not authenticated.
    async fn get_jwks(
        &self,
        request: Request<IssuerHandleRequest>,
    ) -> Result<Response<JsonWebKeySet>, Status> {
        let issuer = self.issuer(&request.into_inner().issuer_handle).await?;
        let mut keys = self.issuers.public_keys(&issuer).await.map_err(internal)?;
        // Newest generation first, as the contract lists them.
        keys.reverse();
        let mut response = Response::new(JsonWebKeySet {
            keys: keys
                .into_iter()
                .map(|(kid, public_key)| JsonWebKey {
                    kty: "OKP".into(),
                    r#use: "sig".into(),
                    alg: "EdDSA".into(),
                    kid,
                    crv: "Ed25519".into(),
                    x: URL_SAFE_NO_PAD.encode(public_key),
                })
                .collect(),
        });
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
