// SPDX-License-Identifier: Apache-2.0
//! How a StructuredID service binary serves gRPC and stops (multi-instance
//! rule 6 of the binary architecture): every served service is reported on the
//! gRPC health service; on shutdown they and the overall status turn
//! NOT_SERVING, so load balancers stop routing here, the listeners stop
//! accepting, calls in flight get a bounded drain interval and whatever is
//! still open then ends with its connection. A server that fails is the
//! process's error, never a clean exit.
//!
//! [`serve`] is the whole loop for a binary with one gRPC listener. A binary
//! with more listeners composes [`Services`], [`stop_signal`] and [`run`].

use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;

use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::server::NamedService;
use tonic::service::{Routes, RoutesBuilder};
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

#[cfg(feature = "error-contract")]
pub mod error_contract;
pub mod shutdown;

/// The gRPC services of one process, routed and reported on the gRPC health
/// service together, so none is served without a health status.
pub struct Services {
    routes: RoutesBuilder,
    health: Health,
}

impl Default for Services {
    fn default() -> Self {
        Self::new()
    }
}

impl Services {
    /// The gRPC health service alone.
    pub fn new() -> Self {
        let (reporter, health_service) = tonic_health::server::health_reporter();
        let mut routes = RoutesBuilder::default();
        routes.add_service(health_service);
        Self {
            routes,
            health: Health {
                reporter,
                names: Vec::new(),
            },
        }
    }

    /// Serves `svc` and reports it serving.
    pub async fn add<S>(&mut self, svc: S) -> &mut Self
    where
        S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.health.reporter.set_serving::<S>().await;
        self.health.names.push(S::NAME);
        self.routes.add_service(svc);
        self
    }

    /// Serves `svc` without a health status of its own: infrastructure such
    /// as server reflection, which is not an API a load balancer routes to.
    pub fn route<S>(&mut self, svc: S) -> &mut Self
    where
        S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.routes.add_service(svc);
        self
    }

    /// The routes to serve and the health of what they serve.
    pub fn into_parts(self) -> (Routes, Health) {
        (self.routes.routes(), self.health)
    }
}

/// The health status of the services one process serves.
pub struct Health {
    reporter: HealthReporter,
    /// Every service reported serving, reported NOT_SERVING at shutdown.
    names: Vec<&'static str>,
}

impl Health {
    /// The full names of the services reported serving.
    pub fn names(&self) -> &[&'static str] {
        &self.names
    }

    /// The reporter, for a status change other than shutdown.
    pub fn reporter(&self) -> &HealthReporter {
        &self.reporter
    }

    /// The overall status and every reported service turn NOT_SERVING.
    pub async fn not_serving(&self) {
        for name in std::iter::once("").chain(self.names.iter().copied()) {
            self.reporter
                .set_service_status(name, ServingStatus::NotServing)
                .await;
        }
    }
}

/// Ends the listeners of a process: [`Stopper::stop`] resolves every
/// [`Stopped::wait`] made from its pair.
pub fn stop_signal() -> (Stopper, Stopped) {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    (Stopper(stop), Stopped(stopped))
}

/// See [`stop_signal`].
pub struct Stopper(tokio::sync::watch::Sender<bool>);

impl Stopper {
    /// Tells every listener to stop accepting.
    pub fn stop(&self) {
        self.0.send_replace(true);
    }
}

/// See [`stop_signal`].
#[derive(Clone)]
pub struct Stopped(tokio::sync::watch::Receiver<bool>);

impl Stopped {
    /// Resolves once the process stops, or its [`Stopper`] is gone (the
    /// process is ending then too).
    pub async fn wait(mut self) {
        // An error means the sender is gone: stop as well.
        self.0.wait_for(|stop| *stop).await.ok();
    }
}

/// `serving` within the drain interval; `None` when the interval ended first.
pub async fn drain<F: Future>(serving: F, interval: Duration) -> Option<F::Output> {
    match tokio::time::timeout(interval, serving).await {
        Ok(served) => Some(served),
        Err(_) => {
            tracing::warn!(
                "drain interval of {interval:?} ended with calls in flight; closing them"
            );
            None
        }
    }
}

/// Runs `serving` until it ends or `shutdown` resolves. On shutdown `health`
/// turns NOT_SERVING, `stopper` stops the listeners and `serving` gets the
/// drain interval; calls still open after it end with their connections. The
/// result is `serving`'s own: a listener that fails, before or during the
/// drain, is an error.
pub async fn run<E>(
    serving: impl Future<Output = Result<(), E>>,
    shutdown: impl Future<Output = ()>,
    health: &Health,
    stopper: &Stopper,
    interval: Duration,
) -> Result<(), E> {
    tokio::pin!(serving);
    tokio::select! {
        served = &mut serving => served,
        () = shutdown => {
            health.not_serving().await;
            stopper.stop();
            drain(&mut serving, interval).await.unwrap_or(Ok(()))
        }
    }
}

/// Serves `services` on `listener` until `shutdown` resolves (typically
/// [`shutdown::signal`]), then stops as [`run`] does. HTTP/1.1 is accepted so
/// a gRPC-Web layer in front can reach the same listener.
pub async fn serve(
    listener: tokio::net::TcpListener,
    services: Services,
    shutdown: impl Future<Output = ()>,
    interval: Duration,
) -> Result<(), tonic::transport::Error> {
    let (routes, health) = services.into_parts();
    let (stopper, stopped) = stop_signal();
    let server = tonic::transport::Server::builder()
        .accept_http1(true)
        .add_routes(routes)
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            stopped.wait(),
        );
    run(server, shutdown, &health, &stopper, interval).await
}

#[cfg(test)]
mod tests;
