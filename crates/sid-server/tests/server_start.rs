// SPDX-License-Identifier: AGPL-3.0-only
//! The server started from its settings, as its binary starts it. The test
//! sets process settings, so it is the only test of its binary.
#![cfg(all(feature = "http", feature = "storage-pg"))]

const ISSUER: &str = "https://sid.example.com";

/// An address nothing listens on: bound once, then released.
fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The body of `GET url` once the listener answers, which must be 200.
async fn get(client: &reqwest::Client, url: &str) -> serde_json::Value {
    let mut tries = 0;
    let answer = loop {
        match client.get(url).send().await {
            Ok(answer) => break answer,
            Err(e) if e.is_connect() && tries < 100 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => panic!("GET {url}: {e}"),
        }
    };
    assert_eq!(answer.status(), reqwest::StatusCode::OK, "GET {url}");
    answer.json().await.unwrap()
}

/// The server opens its installation from the process settings, serves the
/// HTTP form of its issuer on the address it was told and the gRPC services
/// on the listener it was given, and stops cleanly when asked: its listeners
/// close and its background work drains.
/// Bug prevented: a start or a shutdown path of the server that only its
/// image exercises, so a broken one is first seen in a deployment.
#[test]
fn the_server_starts_from_its_settings_serves_and_stops() {
    let data = tempfile::tempdir().unwrap();
    let http = free_address();
    let settings = [
        (
            "SID_DATABASE_URL",
            std::env::var("SID_TEST_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into()),
        ),
        // A schema of this run's own: the installation is opened from empty.
        (
            "SID_STORAGE_POSTGRESQL_SCHEMA",
            format!("server_start_{}", uuid::Uuid::new_v4().simple()),
        ),
        ("SID_DATA_DIR", data.path().to_str().unwrap().to_owned()),
        ("SID_ISSUER", ISSUER.to_owned()),
        ("SID_BIND", http.to_string()),
        ("SID_NATS_URL", "in-process".to_owned()),
    ];
    for (name, value) in settings {
        // SAFETY: the test's only thread so far; the runtime starts below.
        unsafe { std::env::set_var(name, value) };
    }
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .expect("no TLS provider is installed yet");
    sid_crypto::jwt::install_jwt_provider().unwrap();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc_address = grpc.local_addr().unwrap();
        let c = sid_server::init::init_ce_with(Default::default())
            .await
            .unwrap();
        let services = sid_server::serve::CeServices::new(&c, Default::default())
            .await
            .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(sid_server::serve::serve_on(grpc, c, services, async {
            stopped.await.ok();
        }));

        let client = reqwest::Client::new();
        let discovery = get(
            &client,
            &format!("http://{http}/.well-known/openid-configuration"),
        )
        .await;
        assert_eq!(discovery["issuer"], ISSUER);
        let keys = get(&client, &format!("http://{http}/jwks")).await;
        assert!(!keys["keys"].as_array().unwrap().is_empty());
        assert!(tokio::net::TcpStream::connect(grpc_address).await.is_ok());

        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
        for address in [http, grpc_address] {
            assert!(
                tokio::net::TcpStream::connect(address).await.is_err(),
                "the stopped server listens on {address}"
            );
        }
    });
    runtime.shutdown_background();
}
