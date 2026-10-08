// SPDX-License-Identifier: Apache-2.0
use std::convert::Infallible;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::server::NamedService;
use tonic::transport::Channel;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;

use super::{Services, drain, run, serve, stop_signal};

/// A served gRPC service that answers nothing; only its name matters here.
#[derive(Clone)]
struct Echo;

impl NamedService for Echo {
    const NAME: &'static str = "test.Echo";
}

impl Service<http::Request<Body>> for Echo {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: http::Request<Body>) -> Self::Future {
        std::future::ready(Ok(tonic::Status::unimplemented("test service").into_http()))
    }
}

async fn echo_services() -> Services {
    let mut services = Services::new();
    services.add(Echo).await;
    services
}

/// A listener on a free local port and its address.
async fn listener() -> (tokio::net::TcpListener, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a local port");
    let addr = listener.local_addr().expect("local address");
    (listener, addr)
}

async fn client(addr: std::net::SocketAddr) -> HealthClient<Channel> {
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to the server");
    HealthClient::new(channel)
}

async fn status(
    client: &mut HealthClient<Channel>,
    name: &str,
) -> Result<ServingStatus, tonic::Code> {
    client
        .check(HealthCheckRequest {
            service: name.to_string(),
        })
        .await
        .map(|r| r.into_inner().status())
        .map_err(|s| s.code())
}

/// A service added to the set is served and reported SERVING; one never
/// added is unknown to the health service.
#[tokio::test]
async fn test_added_service_is_reported_serving() {
    let (listener, addr) = listener().await;
    let server = tokio::spawn(serve(
        listener,
        echo_services().await,
        std::future::pending(),
        Duration::from_secs(1),
    ));
    let mut client = client(addr).await;

    assert_eq!(status(&mut client, "").await, Ok(ServingStatus::Serving));
    assert_eq!(
        status(&mut client, Echo::NAME).await,
        Ok(ServingStatus::Serving)
    );
    assert_eq!(
        status(&mut client, "test.Other").await,
        Err(tonic::Code::NotFound)
    );
    server.abort();
}

/// On shutdown the reported service turns NOT_SERVING while its watchers are
/// still connected, and the server ends within the drain interval although a
/// stream that never ends on its own is still open (rolling update, scale-in).
#[tokio::test]
async fn test_shutdown_reports_not_serving_and_drains_within_interval() {
    const DRAIN: Duration = Duration::from_secs(1);
    let (listener, addr) = listener().await;
    let (shut, shutdown) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(
        listener,
        echo_services().await,
        async {
            shutdown.await.ok();
        },
        DRAIN,
    ));
    let mut client = client(addr).await;
    let mut watch = client
        .watch(HealthCheckRequest {
            service: Echo::NAME.to_string(),
        })
        .await
        .expect("watch the health status")
        .into_inner();
    let first = watch
        .message()
        .await
        .expect("first status")
        .expect("open stream");
    assert_eq!(first.status(), ServingStatus::Serving);

    shut.send(()).expect("signal shutdown");
    let stopped_at = Instant::now();

    let next = tokio::time::timeout(DRAIN, watch.message())
        .await
        .expect("a status change before the drain interval ends")
        .expect("status message")
        .expect("stream still open");
    assert_eq!(next.status(), ServingStatus::NotServing);

    let served = tokio::time::timeout(DRAIN + Duration::from_secs(5), server)
        .await
        .expect("the server ends after its drain interval")
        .expect("server task");
    assert!(served.is_ok(), "{served:?}");
    assert!(
        stopped_at.elapsed() >= DRAIN,
        "the open stream was cut before the drain interval"
    );
}

/// A listener that fails is the process's error, never a clean exit, both
/// before shutdown and while draining.
#[tokio::test]
async fn test_failed_listener_is_an_error() {
    let health = Services::new().into_parts().1;
    let (stopper, _stopped) = stop_signal();

    let before = run(
        async { Err::<(), _>("listener failed") },
        std::future::pending(),
        &health,
        &stopper,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(before, Err("listener failed"));

    let during = run(
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Err::<(), _>("failed while draining")
        },
        std::future::ready(()),
        &health,
        &stopper,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(during, Err("failed while draining"));
}

/// Calls still open after the drain interval end; the drain reports that it
/// ran out instead of waiting for them.
#[tokio::test(start_paused = true)]
async fn test_drain_ends_after_its_interval() {
    let ended = drain(std::future::pending::<()>(), Duration::from_secs(3)).await;
    assert!(ended.is_none());
    let done = drain(std::future::ready(7), Duration::from_secs(3)).await;
    assert_eq!(done, Some(7));
}

/// Every listener stops when told to, and also when the process drops the
/// stopper without telling (it is ending then too).
#[tokio::test]
async fn test_stopped_resolves_on_stop_or_dropped_stopper() {
    let (stopper, stopped) = stop_signal();
    let other = stopped.clone();
    stopper.stop();
    tokio::time::timeout(Duration::from_secs(1), stopped.wait())
        .await
        .expect("stopped after stop");
    tokio::time::timeout(Duration::from_secs(1), other.wait())
        .await
        .expect("every listener stops");

    let (stopper, stopped) = stop_signal();
    drop(stopper);
    tokio::time::timeout(Duration::from_secs(1), stopped.wait())
        .await
        .expect("stopped once the stopper is gone");
}
