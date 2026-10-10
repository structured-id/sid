// SPDX-License-Identifier: AGPL-3.0-only
//! A gRPC service protected by an issuer it does not run: the internal
//! receivers of the platform (ops, central, tenant runtime) admitting calls
//! with a SID access token for their registered resource.
//!
//! The receiver holds public trust material only: the issuer registry
//! (exact issuer, its public keys, the registered resource) and its own
//! credential for the issuer's authorization API. It reaches no issuer
//! store and holds no signing key. Every call is admitted in this order:
//!
//! 1. the call's path names an action; a path without one is refused
//! 2. the token is the configured issuer's access token for exactly this
//!    resource (signature, `iss`, `aud`, type, time)
//! 3. a key-bound token carries one proof for this call: `POST` and the
//!    configured external origin plus the RPC path (RFC 9449 §4.3)
//! 4. the issuer's authorization API, asked as this receiver, decides the
//!    subject's permission for the action from the call's own token; it
//!    also establishes that the token, its session and its subject are
//!    current (revocation, suspended subject), which a signature cannot
//!
//! Only an admitted call reaches the service, carrying [`Admitted`] in its
//! extensions: the verified claims a handler takes its audit actor from.

use std::convert::Infallible;
use std::sync::Arc;

use http::HeaderMap;
use sid_core::grpc_error::{ApiError, ErrorReason};
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service, http};
use tonic::server::NamedService;

use crate::auth::jwt::{ForwardAuthClaims, TargetAccess, TokenRefusal, presented_token};
use crate::auth::policy::Target;
use crate::issuers::IssuerDirectory;
use sid_authn::client_credential::ClientCredential;

/// What a receiver admits calls against.
pub struct Receiver {
    /// For the log: the protected service.
    name: String,
    issuers: Arc<IssuerDirectory>,
    /// The exact issuer and resource every admitted token must be for.
    target: Target,
    /// Scheme and authority of this service as its callers address it, the
    /// prefix of every proof's `htu`; never taken from the request.
    origin: String,
    /// Proof checks; `jti`s are recorded where every replica of this
    /// resource records them, so a proof is accepted once.
    dpop: Arc<sid_authn::dpop::DPopValidator>,
    checker: Arc<ClientCredential>,
    /// Channel to the issuer's authorization API.
    authz: tonic::transport::Channel,
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("name", &self.name)
            .field("issuer", &self.target.issuer)
            .field("resource", &self.target.resource)
            .finish_non_exhaustive()
    }
}

/// An admitted call: the verified claims of its token and the registered
/// resource it was admitted to.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub claims: ForwardAuthClaims,
    pub resource: sid_core::models::ResourceId,
}

impl Receiver {
    /// The receiver `config` describes, for the service `name`. A credential
    /// that does not load stops start-up rather than leaving every call
    /// without a decision.
    pub async fn connect(
        name: impl Into<String>,
        config: &crate::config::ReceiverConfig,
    ) -> anyhow::Result<Self> {
        let upstream = tonic::transport::Channel::from_shared(config.upstream.clone())
            .map_err(|e| anyhow::anyhow!("upstream {}: {e}", config.upstream))?
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(5))
            .connect_lazy();
        let checker =
            ClientCredential::checker(&config.checker, &config.issuer_url, upstream.clone())?;
        let cache = crate::shared_cache(config.cache_url.as_deref()).await?;
        Ok(Self::new(
            name,
            Arc::new(IssuerDirectory::new(
                &config.issuer_url,
                Arc::new(crate::issuers::GrpcIssuerSource::new(upstream.clone())),
            )),
            Target {
                issuer: config.checker.issuer.clone(),
                resource: config.resource.clone(),
            },
            &config.origin,
            Arc::new(sid_authn::dpop::DPopValidator::new(cache)),
            Arc::new(checker),
            upstream,
        ))
    }

    /// A receiver `name` admitting tokens of `target`, addressed at `origin`.
    pub fn new(
        name: impl Into<String>,
        issuers: Arc<IssuerDirectory>,
        target: Target,
        origin: &str,
        dpop: Arc<sid_authn::dpop::DPopValidator>,
        checker: Arc<ClientCredential>,
        authz: tonic::transport::Channel,
    ) -> Self {
        Self {
            name: name.into(),
            issuers,
            target,
            origin: origin.trim_end_matches('/').to_owned(),
            dpop,
            checker,
            authz,
        }
    }

    /// Admit a call to `path` (`/package.Service/Method`), made with
    /// `method` and `headers`, performing `action`.
    pub async fn admit(
        &self,
        method: &http::Method,
        path: &str,
        headers: &HeaderMap,
        action: &str,
    ) -> Result<Admitted, Status> {
        // gRPC is POST (gRPC over HTTP/2); a proof names the method it was
        // made for, so another one is no call this service serves.
        if method != http::Method::POST {
            return Err(unauthenticated());
        }
        let presented = presented_token(headers).ok_or_else(unauthenticated)?;
        let TargetAccess { claims, resource } = match crate::auth::jwt::validate_for_target(
            &self.issuers,
            &self.target,
            presented.token(),
        )
        .await
        {
            Ok(access) => access,
            Err(TokenRefusal::Invalid(why)) => {
                tracing::debug!(receiver = self.name, why, "access token refused");
                return Err(unauthenticated());
            }
            Err(TokenRefusal::Unavailable(why)) => {
                return Err(sid_core::grpc_error::refuse::dependency_unavailable(
                    "issuer registry",
                    why,
                ));
            }
            // The configured resource is unknown or inactive at its
            // issuer: nothing opens this service until it is.
            Err(TokenRefusal::NoTarget(why)) => {
                tracing::error!(
                    receiver = self.name,
                    resource = self.target.resource,
                    why,
                    "receiver target refused"
                );
                return Err(sid_core::grpc_error::refuse::dependency_unavailable(
                    "protected resource registration",
                    why,
                ));
            }
        };
        let uri = format!("{}{path}", self.origin);
        if let Err(e) = crate::auth::sender::check_sender(
            &self.dpop,
            presented,
            &claims,
            headers,
            method.as_str(),
            Some(&uri),
        )
        .await
        {
            tracing::debug!(receiver = self.name, error = %e, "sender constraint not met");
            return Err(unauthenticated());
        }
        let question = crate::auth::permission::Question {
            asking: &self.name,
            issuer: &self.target.issuer,
            resource,
            action,
            object: "",
            token: presented.token(),
            claims: &claims,
            method: method.as_str(),
            uri: &uri,
        };
        use crate::auth::permission::Permission;
        match crate::auth::permission::ask(Some(&self.checker), &self.authz, question)
            .await
            .map_err(|e| {
                sid_core::grpc_error::refuse::dependency_unavailable("authorization check", e)
            })? {
            Permission::Allowed => Ok(Admitted { claims, resource }),
            Permission::Denied => Err(denied()),
            Permission::TokenRefused => Err(unauthenticated()),
        }
    }
}

/// The action each path of a service performs; `None` for a path the
/// service does not serve, which no call reaches.
pub type Actions = Arc<dyn Fn(&str) -> Option<&'static str> + Send + Sync>;

/// `inner` served behind `receiver`: only admitted calls reach it.
pub struct Guarded<S> {
    inner: S,
    receiver: Arc<Receiver>,
    actions: Actions,
}

impl<S> Guarded<S> {
    pub fn new(inner: S, receiver: Arc<Receiver>, actions: Actions) -> Self {
        Self {
            inner,
            receiver,
            actions,
        }
    }
}

impl<S: Clone> Clone for Guarded<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            receiver: self.receiver.clone(),
            actions: self.actions.clone(),
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
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        // The ready service answers this call; its clone waits for the next.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let receiver = self.receiver.clone();
        let actions = self.actions.clone();
        Box::pin(async move {
            let path = request.uri().path().to_owned();
            let Some(action) = actions(&path) else {
                return Ok(Status::unimplemented("no such method").into_http());
            };
            match receiver
                .admit(request.method(), &path, request.headers(), action)
                .await
            {
                Ok(admitted) => {
                    request.extensions_mut().insert(admitted);
                    inner.call(request).await
                }
                Err(status) => Ok(status.into_http()),
            }
        })
    }
}

/// The verified call of a handler reached through [`Guarded`].
pub fn admitted<T>(request: &tonic::Request<T>) -> Result<&Admitted, Status> {
    // A handler served without the guard has no admitted call: a wiring
    // fault, refused rather than served unauthenticated.
    request
        .extensions()
        .get::<Admitted>()
        .ok_or_else(unauthenticated)
}

fn unauthenticated() -> Status {
    ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
}

fn denied() -> Status {
    ApiError::new(
        ErrorReason::InsufficientPermissions,
        "the caller may not perform this operation",
    )
    .into()
}

#[cfg(test)]
mod tests;
