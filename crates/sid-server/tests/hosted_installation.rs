// SPDX-License-Identifier: AGPL-3.0-only
//! An installation served by a host with a listener of its own: the host
//! calls the installation's HTTP surface in process, and the installation
//! binds nothing.
#![cfg(all(feature = "ui", feature = "storage-pg"))]

use http_body_util::BodyExt as _;
use tonic::codegen::http;
use tower::ServiceExt as _;

const ISSUER: &str = "https://sid.example.com";

/// The body of the answer to `GET path`, which must be 200.
async fn get<S>(surface: &S, path: &str) -> serde_json::Value
where
    S: tower::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<axum::body::Body>,
            Error = std::convert::Infallible,
        > + Clone,
{
    let request = http::Request::get(path)
        .header("host", "sid.example.com")
        .body(tonic::body::Body::empty())
        .unwrap();
    let Ok(answer) = surface.clone().oneshot(request).await;
    assert_eq!(answer.status(), http::StatusCode::OK, "GET {path}");
    let body = answer.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

/// An address nothing listens on: bound once, then released.
fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The test PostgreSQL (docker-compose.test.yml).
fn database_url() -> String {
    std::env::var("SID_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into())
}

/// The process settings `settings` name. Called first in a test, on its only
/// thread: the runtime starts afterwards.
fn configure(settings: &[(&str, String)]) {
    for (name, value) in settings {
        // SAFETY: no other thread exists yet.
        unsafe { std::env::set_var(name, value) };
    }
    // Ignored when another test of this process installed them already.
    let _ = sid_crypto::tls::aws_lc::provider().install_default();
    sid_crypto::jwt::install_jwt_provider().unwrap();
}

/// A host opens the database itself, prepares its schema and hands the open
/// store to the installation: with no storage setting in the process, the
/// installation is opened over that store, answers through the hosted
/// service, and its records are in the host's schema.
/// Bug prevented: an installation that can only connect to a database it is
/// told the address of, so a host cannot keep SID's records in the store it
/// already holds.
#[test]
fn a_host_opens_the_installation_over_its_own_store() {
    use std::sync::Arc;

    let data = tempfile::tempdir().unwrap();
    configure(&[
        ("SID_DATA_DIR", data.path().to_str().unwrap().to_owned()),
        ("SID_ISSUER", ISSUER.to_owned()),
        ("SID_GRPC_BIND", free_address().to_string()),
        ("SID_NATS_URL", "in-process".to_owned()),
    ]);
    assert!(std::env::var_os("SID_DATABASE_URL").is_none());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let schema = format!("hosted_{}", uuid::Uuid::new_v4().simple());
        let backend =
            sid_storage::PostgresBackend::connect(&database_url(), Some(schema.clone()), None)
                .await
                .expect("the test PostgreSQL is running");
        sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
            .await
            .unwrap();
        let history = sid_storage::PgHistoryKeyStore::new(backend.pool().clone());
        history.migrate().await.unwrap();
        let pool = backend.pool().clone();

        let c = sid_server::init::init_ce_with(sid_server::init::CeHost {
            store: Some(sid_server::init::HostStore {
                audit_log: Arc::new(sid_storage::audit_log::PostgresAuditLog::new(pool.clone())),
                history_keys: Arc::new(history),
                storage: Arc::new(backend),
            }),
            ..Default::default()
        })
        .await
        .unwrap();
        let services = sid_server::serve::CeServices::new(&c, Default::default())
            .await
            .unwrap();
        let hosted = sid_server::serve::hosted(c, services, serde_json::json!({})).unwrap();

        let discovery = get(&hosted.http, "/.well-known/openid-configuration").await;
        assert_eq!(discovery["issuer"], ISSUER);
        // The installation's issuer is recorded in the host's schema, which
        // the host's pool resolves unqualified names in.
        let (resolved, issuers): (String, i64) =
            sqlx::query_as("SELECT current_schema()::text, (SELECT count(*) FROM oidc_issuers)")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(resolved, schema);
        assert!(issuers > 0);
        hosted.background.drain().await.unwrap();
    });
    runtime.shutdown_background();
}

/// A host assembles the installation from its settings and gets its HTTP
/// surface as one service: discovery and the issuer's keys answer through it
/// in process, nothing listens on the addresses the server would have bound,
/// and the background work drains when the host stops.
/// Bug prevented: an installation whose HTTP surface exists only behind the
/// server's own gRPC and HTTP ports, so a host with one listener cannot
/// serve it.
#[test]
fn a_host_serves_the_installation_on_no_listener_of_the_installations() {
    let data = tempfile::tempdir().unwrap();
    let (grpc, http_port) = (free_address(), free_address());
    configure(&[
        ("SID_DATABASE_URL", database_url()),
        // A schema of this run's own: the installation is opened from empty.
        (
            "SID_STORAGE_POSTGRESQL_SCHEMA",
            format!("hosted_{}", uuid::Uuid::new_v4().simple()),
        ),
        ("SID_DATA_DIR", data.path().to_str().unwrap().to_owned()),
        ("SID_ISSUER", ISSUER.to_owned()),
        ("SID_GRPC_BIND", grpc.to_string()),
    ]);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let c = sid_server::init::init_ce_with(Default::default())
            .await
            .unwrap();
        let services = sid_server::serve::CeServices::new(&c, Default::default())
            .await
            .unwrap();
        let hosted = sid_server::serve::hosted(c, services, serde_json::json!({})).unwrap();

        let discovery = get(&hosted.http, "/.well-known/openid-configuration").await;
        assert_eq!(discovery["issuer"], ISSUER);
        let keys = get(&hosted.http, "/jwks").await;
        assert!(!keys["keys"].as_array().unwrap().is_empty());

        for address in [grpc, http_port] {
            assert!(
                tokio::net::TcpStream::connect(address).await.is_err(),
                "the installation listens on {address}"
            );
        }
        hosted.background.drain().await.unwrap();
    });
    runtime.shutdown_background();
}
