// SPDX-License-Identifier: AGPL-3.0-only
//! The `sid-server` binary serves every CE service, each one answering SERVING
//! on the gRPC health service of a running server (which registers a service
//! and its health status together), and on SIGTERM reports NOT_SERVING and
//! stops within its drain interval.

use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use sid_proto::sid::v1 as pb;
use tonic::transport::Channel;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;

/// Every CE service a CE server must serve.
const CE_SERVICES: &[&str] = &[
    pb::identity_service_server::SERVICE_NAME,
    pb::auth_service_server::SERVICE_NAME,
    pb::project_service_server::SERVICE_NAME,
    pb::authz_service_server::SERVICE_NAME,
    pb::admin_service_server::SERVICE_NAME,
    pb::branding_service_server::SERVICE_NAME,
    pb::flow_config_service_server::SERVICE_NAME,
    pb::flow_action_service_server::SERVICE_NAME,
    pb::admin::enrollment_service_server::SERVICE_NAME,
    pb::admin::security_service_server::SERVICE_NAME,
    pb::admin::realm_service_server::SERVICE_NAME,
    pb::authz::governance_service_server::SERVICE_NAME,
    pb::events::event_stream_service_server::SERVICE_NAME,
    pb::account::account_service_server::SERVICE_NAME,
    pb::scim_service_server::SERVICE_NAME,
    pb::scim_protocol_service_server::SERVICE_NAME,
];

/// Startup includes migrating a fresh schema.
const STARTUP_LIMIT: Duration = Duration::from_secs(120);

/// A server process, stopped when the test ends.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        if let Err(e) = self.0.kill() {
            eprintln!("stopping the server: {e}");
        }
        if let Err(e) = self.0.wait() {
            eprintln!("waiting for the server: {e}");
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

/// A free UDP port for the WebTransport endpoint of a server built with it.
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind an ephemeral UDP port")
        .local_addr()
        .expect("local address")
        .port()
}

/// Starts `binary` against the test stack (PostgreSQL 54399 in its own schema,
/// Redis 63799, NATS 4399), ignoring any SID setting of the caller.
fn start(binary: &str, data_dir: &std::path::Path, port: u16, env: &[(&str, &str)]) -> Server {
    let mut cmd = Command::new(binary);
    for (key, _) in std::env::vars() {
        if key.starts_with("SID_") {
            cmd.env_remove(key);
        }
    }
    let schema = format!("served_{}", uuid::Uuid::now_v7().simple());
    cmd.env(
        "SID_DATABASE_URL",
        "postgres://sid:sid_dev@localhost:54399/sid",
    )
    .env("SID_STORAGE_POSTGRESQL_SCHEMA", schema)
    .env("SID_DATA_DIR", data_dir)
    .env("SID_NATS_URL", "nats://localhost:4399")
    .env("SID_REDIS_URL", "redis://localhost:63799")
    .env("SID_IPINTEL_PROVIDERS", "none")
    .env("SID_ISSUER", "https://sid.example.com")
    .env("SID_GRPC_BIND", format!("127.0.0.1:{port}"))
    .env("SID_WEBTRANSPORT_DEV_TLS", "true")
    .env(
        "SID_WEBTRANSPORT_BIND",
        format!("127.0.0.1:{}", free_udp_port()),
    )
    .envs(env.iter().copied());
    Server(cmd.spawn().expect("start the server"))
}

/// Waits until the server answers.
async fn connect(server: &mut Server, port: u16) -> HealthClient<Channel> {
    let deadline = Instant::now() + STARTUP_LIMIT;
    loop {
        if let Some(status) = server.0.try_wait().expect("server status") {
            panic!("the server exited during startup: {status}");
        }
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
            .expect("server endpoint");
        match endpoint.connect().await {
            Ok(channel) => return HealthClient::new(channel),
            // Not listening yet: retry until the deadline.
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => panic!("the server did not start within {STARTUP_LIMIT:?}: {e}"),
        }
    }
}

async fn status(client: &mut HealthClient<Channel>, name: &str) -> ServingStatus {
    match client
        .check(HealthCheckRequest {
            service: name.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner().status(),
        Err(s) if s.code() == tonic::Code::NotFound => ServingStatus::ServiceUnknown,
        Err(s) => panic!("health check of {name}: {s}"),
    }
}

/// A CE service missing from the server, or served without being reported,
/// is listed with its status.
#[tokio::test]
async fn test_ce_server_serves_every_ce_service() {
    let data_dir = tempfile::tempdir().expect("data directory");
    let port = free_port();
    let mut server = start(env!("CARGO_BIN_EXE_sid"), data_dir.path(), port, &[]);
    let mut client = connect(&mut server, port).await;

    let mut not_serving = Vec::new();
    for &name in CE_SERVICES {
        let s = status(&mut client, name).await;
        if s != ServingStatus::Serving {
            not_serving.push((name, s));
        }
    }
    assert!(not_serving.is_empty(), "not served: {not_serving:?}");
}

/// On SIGTERM the server reports NOT_SERVING, so the load balancer stops
/// routing to it, and ends within the drain interval even though a stream is
/// still open (deployment rules, scale-in and rolling update).
#[cfg(unix)]
#[tokio::test]
async fn test_sigterm_reports_not_serving_and_drains_within_interval() {
    const DRAIN: Duration = Duration::from_secs(2);
    let data_dir = tempfile::tempdir().expect("data directory");
    let port = free_port();
    let mut server = start(
        env!("CARGO_BIN_EXE_sid"),
        data_dir.path(),
        port,
        &[("SID_SHUTDOWN_DRAIN_SECONDS", "2")],
    );
    let mut client = connect(&mut server, port).await;

    // A stream that never ends on its own.
    let service = pb::identity_service_server::SERVICE_NAME;
    let mut watch = client
        .watch(HealthCheckRequest {
            service: service.to_string(),
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

    let signalled = Command::new("kill")
        .args(["-TERM", &server.0.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signalled.success());
    let stopped_at = Instant::now();

    let next = tokio::time::timeout(DRAIN, watch.message())
        .await
        .expect("a status change before the drain interval ends")
        .expect("status message")
        .expect("stream still open");
    assert_eq!(next.status(), ServingStatus::NotServing);

    let exit = loop {
        if let Some(exit) = server.0.try_wait().expect("server status") {
            break exit;
        }
        assert!(
            stopped_at.elapsed() < DRAIN + Duration::from_secs(5),
            "the server did not stop after its drain interval"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(exit.success(), "shutdown exit status: {exit}");
}
