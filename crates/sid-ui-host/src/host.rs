// SPDX-License-Identifier: AGPL-3.0-only
//! An application hosted on one listener: its UI bundle, its browser adapter
//! ([`ApplicationSessions`]) and its API, called by the page over gRPC-Web as
//! the signed-in user.
//!
//! The embedded transcoder serves the listener. Navigations to the adapter's
//! sign-in routes are its annotated RPCs; every gRPC or gRPC-Web call goes to
//! [`HostUpstream`], which answers the adapter's own service and forwards any
//! other call to the application's API with the session's access token as
//! `authorization`; any other request is the bundle's.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt;
use secrecy::ExposeSecret;
use sid_core::grpc_error::refuse;
use sid_infra::deadline::IssuerChannel;
use sid_proto::sid::v1::authn::application_session_service_server::ApplicationSessionServiceServer;
use structured_proxy::hooks::{ExtraRoute, ExtraRouteHandler, RouteRequest, RouteResponse};
use tonic::metadata::MetadataMap;
use tower::ServiceExt;

use crate::application_session::{ApplicationSessions, CSRF_HEADER};

/// The gRPC path prefix of the adapter's own service, answered in process.
const ADAPTER_SERVICE: &str = "/sid.v1.authn.ApplicationSessionService/";

/// The proto file of the adapter's service: the only annotated RPCs the
/// transcoder serves here.
pub const ADAPTER_PROTO: &str = "sid/v1/authn/application_session.proto";

/// Request headers that belong to the browser and this host, never to the
/// application's API: the session cookie and CSRF token stay here, and the
/// API sees only the bearer this host puts in.
const NOT_FORWARDED: [&str; 3] = ["cookie", CSRF_HEADER, "authorization"];

/// How long a call to the issuer may take, its whole answer included:
/// shorter than a refresh claim's hold, so a refresh never outlives the
/// claim that lets it run.
pub use sid_infra::deadline::ISSUER_CALL_TIMEOUT;

/// The channel to the issuer at `address`, every call bounded by
/// [`ISSUER_CALL_TIMEOUT`]: an issuer that accepts a call and never finishes
/// its answer fails it instead of holding the user's request.
pub fn issuer_channel(address: &str) -> anyhow::Result<IssuerChannel> {
    bounded_channel(address, ISSUER_CALL_TIMEOUT)
}

fn bounded_channel(address: &str, timeout: Duration) -> anyhow::Result<IssuerChannel> {
    Ok(sid_infra::deadline::bounded_channel(address, timeout)?)
}

/// The shared cache a host with a browser adapter must name. Sessions,
/// started sign-ins and revocations are shared state: a host behind a load
/// balancer completes a sign-in another replica started, and a store of its
/// own process would answer every other replica "no such sign-in", so there
/// is no default to fall back to.
pub fn required_shared_cache(configured: Option<String>) -> anyhow::Result<String> {
    configured.ok_or_else(|| {
        anyhow::anyhow!("the browser adapter needs the shared cache: set SID_CACHE_URL")
    })
}

/// The gRPC services of one hosted application. `A` is its API: a remote
/// [`tonic::transport::Channel`] in a deployment.
#[derive(Clone)]
pub struct HostUpstream<A = tonic::transport::Channel> {
    adapter: tonic::service::Routes,
    sessions: Arc<ApplicationSessions>,
    /// The application's API; without one, only the adapter answers.
    api: Option<A>,
}

impl<A> HostUpstream<A> {
    pub fn new(sessions: Arc<ApplicationSessions>, api: Option<A>) -> Self {
        let adapter = tonic::service::Routes::new(ApplicationSessionServiceServer::from_arc(
            sessions.clone(),
        ));
        Self {
            adapter,
            sessions,
            api,
        }
    }
}

type Answer = http::Response<tonic::body::Body>;

impl<A> tower::Service<http::Request<tonic::body::Body>> for HostUpstream<A>
where
    A: tower::Service<http::Request<tonic::body::Body>, Response = Answer>
        + Clone
        + Send
        + Sync
        + 'static,
    A::Error: std::fmt::Display,
    A::Future: Send,
{
    type Response = Answer;
    type Error = Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Answer, Infallible>> + Send + 'static>,
    >;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Both services are cloned per call below and polled there.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: http::Request<tonic::body::Body>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            if request.uri().path().starts_with(ADAPTER_SERVICE) {
                return Ok(match this.adapter.oneshot(request).await {
                    Ok(answer) => answer,
                    Err(never) => match never {},
                });
            }
            let Some(api) = this.api else {
                return Ok(refuse::not_in_this_build("hosted API").into_http());
            };
            let metadata = MetadataMap::from_headers(request.headers().clone());
            let bearer = match this.sessions.bearer(&metadata).await {
                Ok(bearer) => bearer,
                Err(status) => return Ok(status.into_http()),
            };
            let headers = request.headers_mut();
            for name in NOT_FORWARDED {
                headers.remove(name);
            }
            match http::HeaderValue::try_from(format!("Bearer {}", bearer.expose_secret())) {
                Ok(mut value) => {
                    value.set_sensitive(true);
                    headers.insert(http::header::AUTHORIZATION, value);
                }
                Err(e) => {
                    return Ok(refuse::internal("session bearer", e).into_http());
                }
            }
            // The API's own answers, refusals included, go back as they are;
            // only a call that never reached it is this host's to answer.
            Ok(match api.oneshot(request).await {
                Ok(answer) => answer,
                Err(e) => refuse::dependency_unavailable("application API", e).into_http(),
            })
        })
    }
}

/// The bundle's routes as routes of the transcoder: every `GET` it does not
/// answer itself. `router` is the bundle's (and the health probe's) router.
pub fn asset_routes(router: axum::Router) -> Vec<ExtraRoute> {
    let handler: Arc<dyn ExtraRouteHandler> = Arc::new(Assets(router));
    ["/", "/{*path}"]
        .into_iter()
        .map(|path| ExtraRoute::new(http::Method::GET, path, handler.clone()))
        .collect()
}

/// The bundle's router behind the transcoder's route seam.
struct Assets(axum::Router);

#[async_trait::async_trait]
impl ExtraRouteHandler for Assets {
    async fn handle(&self, request: RouteRequest) -> RouteResponse {
        let mut forwarded = http::Request::new(axum::body::Body::from(request.body));
        *forwarded.method_mut() = request.method;
        *forwarded.uri_mut() = request.uri;
        *forwarded.headers_mut() = request.headers;
        let answer = match self.0.clone().oneshot(forwarded).await {
            Ok(answer) => answer,
            Err(never) => match never {},
        };
        let (parts, body) = answer.into_parts();
        // The bundle's files are read whole: SPA builds are a few megabytes.
        let body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::error!(error = %e, "cannot read a bundle answer");
                return RouteResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR, "");
            }
        };
        let mut response = RouteResponse::new(parts.status, body);
        response.headers = parts.headers;
        response
    }
}

#[cfg(test)]
mod tests;
