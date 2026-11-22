// SPDX-License-Identifier: AGPL-3.0-only
//! The serving guard of every method's declared access rule
//! (`sid.v1.common.access`): before a call reaches its service, the rule its
//! method declares in the schema is read from the descriptors and enforced.
//! An open method passes. A protected one is called with a credential of an
//! admitted kind carrying every scope the method requires, else it is
//! refused before any effect. The rule is a ceiling on the credential: the
//! service still decides the caller's authority for the action and target.
//!
//! The credential is verified once, here, and handed to the service in the
//! request's extensions, where [`super::caller::verify_request`] and
//! [`super::own_token::authenticate_service`] take it instead of verifying
//! the token again. Native gRPC and the transcoded HTTP form reach a service
//! through the same guard.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use prost_reflect::{DescriptorPool, Value};
use sid_authn::caller::{
    BrowserCaller, BrowserSessionRefusal, CallerError, CurrentToken, TokenKind, TokenSource,
    Verified, authenticate_browser_session, authenticate_token,
};
use sid_authn::jwt::JwtService;
use sid_authn::resource_token::{OwnTokenError, ResourceTokenVerifier};
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::service_auth::{AuthenticatedService, authenticate_service};
use sid_plugin::StorageBackend;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::server::NamedService;

use crate::grpc_error::{ApiError, ErrorReason, IntoStatus};

pub mod installation;

/// The method option holding a method's access rule.
const ACCESS: &str = "sid.v1.common.access";

/// A kind of credential a method admits (`sid.v1.common.CredentialKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredentialKind {
    OwnSession = 1,
    Delegated = 2,
    Client = 3,
    PersonalAccessToken = 4,
    Impersonation = 5,
    AccountApi = 6,
}

impl CredentialKind {
    fn from_wire(number: i32) -> Option<Self> {
        Some(match number {
            1 => Self::OwnSession,
            2 => Self::Delegated,
            3 => Self::Client,
            4 => Self::PersonalAccessToken,
            5 => Self::Impersonation,
            6 => Self::AccountApi,
            _ => return None,
        })
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// The access rule one method declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessRule {
    /// Called before or without an access token.
    Open,
    /// Called with a credential of an admitted kind carrying every scope.
    Protected {
        /// The admitted kinds, one bit per [`CredentialKind`].
        kinds: u8,
        scopes: Box<[String]>,
        /// What a receiver asks its issuer before the call takes effect;
        /// `None` where the service's own handlers decide.
        permission: Option<Permission>,
    },
}

/// The permission a receiver asks its issuer for
/// (`sid.v1.common.ReceiverPermission`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub action: String,
    pub target: PermissionTarget,
}

/// What a receiver's permission is decided on
/// (`sid.v1.common.PermissionTarget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionTarget {
    /// The resource as a whole, before the call reaches the service.
    Resource,
    /// One object the request names, by its handler.
    Object,
    /// One object whose owner acts on it by the service's own rule.
    OwnedObject,
}

impl PermissionTarget {
    fn from_wire(number: i32) -> Option<Self> {
        Some(match number {
            1 => Self::Resource,
            2 => Self::Object,
            3 => Self::OwnedObject,
            _ => return None,
        })
    }
}

impl AccessRule {
    /// A protected rule admitting `kinds` carrying `scopes`, with the
    /// receiver `permission` when there is one.
    pub fn protected(
        kinds: &[CredentialKind],
        scopes: &[&str],
        permission: Option<Permission>,
    ) -> Self {
        Self::Protected {
            kinds: kinds.iter().fold(0, |bits, kind| bits | kind.bit()),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            permission,
        }
    }

    /// Whether a credential of `kind` may call the method.
    pub fn admits(&self, kind: CredentialKind) -> bool {
        match self {
            Self::Open => true,
            Self::Protected { kinds, .. } => kinds & kind.bit() != 0,
        }
    }

    /// Whether `granted` carries every scope the method requires; a caller's
    /// own session carries every scope of the installation's API.
    pub fn granted(&self, kind: CredentialKind, granted: &str) -> bool {
        match self {
            Self::Open => true,
            Self::Protected { .. } if kind == CredentialKind::OwnSession => true,
            Self::Protected { scopes, .. } => scopes
                .iter()
                .all(|s| granted.split_whitespace().any(|g| g == s)),
        }
    }

    /// The receiver permission the method declares.
    pub fn permission(&self) -> Option<&Permission> {
        match self {
            Self::Protected { permission, .. } => permission.as_ref(),
            Self::Open => None,
        }
    }
}

/// Every method's access rule, by its gRPC path `/package.Service/Method`.
#[derive(Debug, Default)]
pub struct AccessRules {
    methods: HashMap<String, AccessRule>,
    services: std::collections::HashSet<String>,
    /// Methods declaring `idempotency_level = NO_SIDE_EFFECTS`: a call
    /// changes nothing.
    reads: std::collections::HashSet<String>,
}

/// `google.protobuf.MethodOptions.IdempotencyLevel.NO_SIDE_EFFECTS`.
const NO_SIDE_EFFECTS: i32 = 1;

impl AccessRules {
    /// The rules every service of the encoded `descriptor_set` declares. A
    /// method without a valid rule is an error: the build refuses it, so a
    /// descriptor set without one is not the schema this build compiled.
    pub fn from_descriptors(descriptor_set: &[u8]) -> Result<Self, String> {
        let mut rules = Self::default();
        rules.add(descriptor_set)?;
        Ok(rules)
    }

    /// Add the rules of another encoded descriptor set (a private schema
    /// served beside SID's).
    pub fn add(&mut self, descriptor_set: &[u8]) -> Result<(), String> {
        let pool = DescriptorPool::decode(descriptor_set)
            .map_err(|e| format!("the descriptor set: {e}"))?;
        let access = pool
            .get_extension_by_name(ACCESS)
            .ok_or_else(|| format!("the descriptors define no {ACCESS}"))?;
        for service in pool.services() {
            for method in service.methods() {
                let path = format!("/{}/{}", service.full_name(), method.name());
                let options = method.options();
                let rule = rule_of(&options, &access).map_err(|why| format!("{path}: {why}"))?;
                if options
                    .get_field_by_name("idempotency_level")
                    .and_then(|level| level.as_enum_number())
                    == Some(NO_SIDE_EFFECTS)
                {
                    self.reads.insert(path.clone());
                }
                self.methods.insert(path, rule);
            }
            self.services.insert(service.full_name().to_owned());
        }
        Ok(())
    }

    /// Declare `rule` for the method at `path` (`/package.Service/Method`).
    pub fn insert(&mut self, path: &str, rule: AccessRule) {
        if let Some((service, _)) = path.strip_prefix('/').and_then(|p| p.split_once('/')) {
            self.services.insert(service.to_owned());
        }
        self.methods.insert(path.to_owned(), rule);
    }

    /// The rule of the method at `path`.
    pub fn rule(&self, path: &str) -> Option<&AccessRule> {
        self.methods.get(path)
    }

    /// Whether the method at `path` declares that a call changes nothing.
    pub fn changes_nothing(&self, path: &str) -> bool {
        self.reads.contains(path)
    }

    /// Whether the schema declares the service `name`.
    pub fn declares(&self, name: &str) -> bool {
        self.services.contains(name)
    }

    /// Every method of the service `name` with its rule, by gRPC path.
    pub fn methods_of<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a AccessRule)> + 'a {
        self.methods.iter().filter_map(move |(path, rule)| {
            let service = path.strip_prefix('/')?.split_once('/')?.0;
            (service == name).then_some((path.as_str(), rule))
        })
    }
}

fn rule_of(
    options: &prost_reflect::DynamicMessage,
    access: &prost_reflect::ExtensionDescriptor,
) -> Result<AccessRule, String> {
    if !options.has_extension(access) {
        return Err("declares no access rule".into());
    }
    let declared = options.get_extension(access);
    let rule = declared
        .as_message()
        .ok_or("the access rule is a message")?;
    match rule.fields().next() {
        Some((field, Value::String(_))) if field.name() == "open" => Ok(AccessRule::Open),
        Some((field, Value::Message(protected))) if field.name() == "protected" => {
            let mut kinds = 0u8;
            if let Some(list) = protected.get_field_by_name("credentials") {
                for number in list.as_list().unwrap_or_default() {
                    let kind = number
                        .as_enum_number()
                        .and_then(CredentialKind::from_wire)
                        .ok_or("an unknown credential kind")?;
                    kinds |= kind.bit();
                }
            }
            if kinds == 0 {
                return Err("a protected rule admits no credential kind".into());
            }
            let scopes = protected
                .get_field_by_name("scopes")
                .map(|list| {
                    list.as_list()
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect::<Box<[String]>>()
                })
                .unwrap_or_default();
            let permission = match protected.get_field_by_name("permission") {
                Some(value) if protected.has_field_by_name("permission") => {
                    let declared = value
                        .as_message()
                        .ok_or("the receiver permission is a message")?;
                    let action = declared
                        .get_field_by_name("action")
                        .and_then(|a| a.as_str().map(str::to_owned))
                        .filter(|a| !a.trim().is_empty())
                        .ok_or("a receiver permission names its action")?;
                    let target = declared
                        .get_field_by_name("target")
                        .and_then(|t| t.as_enum_number())
                        .and_then(PermissionTarget::from_wire)
                        .ok_or("a receiver permission names its target")?;
                    Some(Permission { action, target })
                }
                _ => None,
            };
            Ok(AccessRule::Protected {
                kinds,
                scopes,
                permission,
            })
        }
        _ => Err("the access rule is `open` or `protected`".into()),
    }
}

/// Which page origins may act with the installation's browser session.
#[async_trait::async_trait]
pub trait AdmittedOrigins: Send + Sync {
    /// Whether `origin`, a request's serialized `Origin`, is one of the
    /// installation's pages (its public origin, its console's origin).
    async fn admits(&self, origin: &str) -> bool;
}

/// The installation's own browser session as an OWN_SESSION credential: its
/// session cookie, from a page on an admitted origin, echoing the session's
/// CSRF token on every call that changes something.
#[derive(Clone)]
pub struct BrowserSessions {
    pub cookie: sid_authn::browser_session::BrowserCookie,
    pub origins: Arc<dyn AdmittedOrigins>,
}

/// What the guard verifies credentials with.
pub struct Access {
    rules: Arc<AccessRules>,
    tokens: Arc<JwtService>,
    current: Arc<dyn CurrentToken>,
    storage: Arc<dyn StorageBackend>,
    revocation: Arc<RevocationCache>,
    /// The verifier of a service's own tokens for an API, by the gRPC
    /// service that serves it.
    service_tokens: HashMap<String, Arc<ResourceTokenVerifier>>,
    /// The installation's browser session, when its pages call this API.
    browser: Option<BrowserSessions>,
}

impl Access {
    /// A guard of `rules` verifying the installation's tokens with the
    /// verifier of `tokens` and their currency with `current`.
    pub fn new(
        rules: Arc<AccessRules>,
        tokens: Arc<JwtService>,
        current: Arc<dyn CurrentToken>,
        storage: Arc<dyn StorageBackend>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            rules,
            tokens,
            current,
            storage,
            revocation,
            service_tokens: HashMap::new(),
            browser: None,
        }
    }

    /// The installation's pages call this API with its browser session.
    pub fn with_browser_sessions(mut self, browser: BrowserSessions) -> Self {
        self.browser = Some(browser);
        self
    }

    /// Admit a protected call presenting no bearer token by the browser
    /// session its cookie holds.
    async fn admit_browser(
        &self,
        path: &str,
        rule: &AccessRule,
        headers: &http::HeaderMap,
        extensions: &mut http::Extensions,
    ) -> Result<(), Status> {
        let unauthenticated = || CallerError::Unauthenticated.into_status();
        let browser = self.browser.as_ref().ok_or_else(unauthenticated)?;
        let values = |name: &str| {
            headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
        };
        let secret = browser
            .cookie
            .secret(values("cookie"))
            .ok_or_else(unauthenticated)?;
        // Only the installation's own pages act with its session: one exact
        // Origin (RFC 6454 §7), never `null` or another page of the site.
        let not_the_page = || {
            Status::from(ApiError::new(
                ErrorReason::CsrfTokenInvalid,
                "the request does not come from a page of the installation",
            ))
        };
        let origins = values("origin");
        let [origin] = origins.as_slice() else {
            return Err(not_the_page());
        };
        if !browser.origins.admits(origin).await {
            return Err(not_the_page());
        }
        if !rule.admits(CredentialKind::OwnSession) {
            return Err(CallerError::Denied.into_status());
        }
        // A call that changes nothing needs no CSRF token: the Origin check
        // already keeps other pages from reading its answer.
        let csrf = values(sid_authn::browser_session::CSRF_HEADER);
        let csrf = (!self.rules.changes_nothing(path)).then_some(csrf);
        match authenticate_browser_session(self.storage.as_ref(), &secret, csrf).await {
            Ok(caller) => {
                extensions.insert(Arc::new(caller));
                Ok(())
            }
            Err(BrowserSessionRefusal::NotSignedIn) => Err(unauthenticated()),
            Err(BrowserSessionRefusal::Csrf) => Err(ApiError::new(
                ErrorReason::CsrfTokenInvalid,
                "the request does not carry this session's CSRF token",
            )
            .into()),
            Err(BrowserSessionRefusal::Unavailable(detail)) => Err(
                crate::grpc_error::refuse::dependency_unavailable("installation session", detail),
            ),
        }
    }

    /// A service's own tokens for the API `service` serves are verified with
    /// `tokens`.
    pub fn with_service_tokens(
        mut self,
        service: &str,
        tokens: Arc<ResourceTokenVerifier>,
    ) -> Self {
        self.service_tokens.insert(service.to_owned(), tokens);
        self
    }

    /// `inner` behind this guard. A service the schema does not declare is
    /// refused here, at start-up: a method without a rule is never served.
    pub fn guard<S: NamedService>(self: &Arc<Self>, inner: S) -> Result<Guarded<S>, String> {
        if !self.rules.declares(S::NAME) {
            return Err(format!(
                "the schema declares no access rule for {}",
                S::NAME
            ));
        }
        Ok(Guarded {
            inner,
            access: self.clone(),
        })
    }

    /// Admit a call of `path` with the `authorization` header value
    /// `presented`, recording the verified credential in `extensions`.
    async fn admit(
        &self,
        path: &str,
        headers: &http::HeaderMap,
        extensions: &mut http::Extensions,
    ) -> Result<(), Status> {
        let Some(rule) = self.rules.rule(path) else {
            // A method of a declared service that the schema does not have.
            return Err(Status::unimplemented("unknown method"));
        };
        let AccessRule::Protected { scopes, .. } = rule else {
            return Ok(());
        };
        let presented = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let Some(token) = bearer(presented) else {
            // No bearer: the installation's own page with its session cookie.
            return self.admit_browser(path, rule, headers, extensions).await;
        };
        let (kind, granted) =
            match authenticate_token(token, self.tokens.verifier(), self.current.as_ref()).await {
                Ok(verified) => {
                    let kind = match (verified.source, verified.caller.kind()) {
                        (TokenSource::AccountApi, _) => CredentialKind::AccountApi,
                        (TokenSource::Installation, TokenKind::Interactive) => {
                            CredentialKind::OwnSession
                        }
                        (TokenSource::Installation, TokenKind::Impersonation) => {
                            CredentialKind::Impersonation
                        }
                    };
                    let granted = scope_set(&verified.claims.scope);
                    extensions.insert(Arc::new(verified));
                    (kind, granted)
                }
                Err(CallerError::Unauthenticated) => {
                    let service = path
                        .strip_prefix('/')
                        .and_then(|p| p.split_once('/'))
                        .map(|(service, _)| service)
                        .unwrap_or_default();
                    let verifier = match self.service_tokens.get(service) {
                        Some(verifier) if rule.admits(CredentialKind::Client) => verifier,
                        _ => return Err(CallerError::Unauthenticated.into_status()),
                    };
                    let caller = authenticate_service(
                        token,
                        self.storage.as_ref(),
                        verifier,
                        &self.revocation,
                    )
                    .await
                    .map_err(|e| match e {
                        OwnTokenError::Unauthenticated => {
                            CallerError::Unauthenticated.into_status()
                        }
                        storage => storage.into_status(),
                    })?;
                    let granted = scopes
                        .iter()
                        .filter(|s| caller.may(s))
                        .cloned()
                        .collect::<Vec<_>>();
                    extensions.insert(Arc::new(caller));
                    (CredentialKind::Client, granted)
                }
                Err(other) => return Err(other.into_status()),
            };
        if !rule.admits(kind) {
            return Err(CallerError::Denied.into_status());
        }
        // The installation's own session carries every scope of its API; the
        // caller's current authority limits it.
        if kind != CredentialKind::OwnSession
            && !scopes.iter().all(|s| granted.iter().any(|g| g == s))
        {
            return Err(ApiError::new(
                ErrorReason::ScopeNotGranted,
                "the access token does not grant this operation",
            )
            .into());
        }
        Ok(())
    }
}

/// The bearer token of an `authorization` header value; a `DPoP` scheme is
/// refused (these services verify no DPoP proof, RFC 9449 §7.1), and the
/// scheme is case-insensitive (RFC 7235 §2.1).
fn bearer(presented: Option<&str>) -> Option<&str> {
    let (scheme, token) = presented?.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty()).then_some(token)
}

fn scope_set(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(str::to_owned).collect()
}

/// A service behind its access guard.
pub struct Guarded<S> {
    inner: S,
    access: Arc<Access>,
}

impl<S: Clone> Clone for Guarded<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            access: self.access.clone(),
        }
    }
}

impl<S: NamedService> NamedService for Guarded<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> Service<http::Request<Body>> for Guarded<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        // The service polled ready is the one that serves the call.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let access = self.access.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            if let Err(status) = access
                .admit(parts.uri.path(), &parts.headers, &mut parts.extensions)
                .await
            {
                return Ok(status.into_http());
            }
            inner.call(http::Request::from_parts(parts, body)).await
        })
    }
}

/// The credential the guard verified for `extensions`' request, if any.
pub fn verified(extensions: &http::Extensions) -> Option<&Verified> {
    extensions.get::<Arc<Verified>>().map(Arc::as_ref)
}

/// The browser session the guard admitted for `extensions`' request, if any.
pub fn browser_caller(extensions: &http::Extensions) -> Option<&BrowserCaller> {
    extensions.get::<Arc<BrowserCaller>>().map(Arc::as_ref)
}

/// The service credential the guard verified for `extensions`' request, if
/// any.
pub fn verified_service(extensions: &http::Extensions) -> Option<&AuthenticatedService> {
    extensions
        .get::<Arc<AuthenticatedService>>()
        .map(Arc::as_ref)
}

#[cfg(test)]
mod tests;
