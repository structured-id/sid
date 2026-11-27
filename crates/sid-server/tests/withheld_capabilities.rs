// SPDX-License-Identifier: AGPL-3.0-only
//! A server whose host withholds the optional capabilities, started from its
//! settings as a binary starts it. The test sets process settings, so it is
//! the only test of its binary.
#![cfg(all(feature = "http", feature = "storage-pg", feature = "scim"))]

use sid_server::init::{CeHost, Withheld};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;

const ISSUER: &str = "https://sid.example.com";

/// The services of the withheld capabilities.
const WITHHELD: &[&str] = &[
    "sid.v1.scim.ScimService",
    "sid.v1.scim.ScimProtocolService",
    "sid.v1.admin.ProvisioningService",
    "sid.v1.events.EventStreamService",
];

/// Services no composition of this server mounts: nothing here creates or
/// exchanges a personal access token, grants an impersonation or imports a
/// blueprint.
const NEVER_SERVED: &[&str] = &[
    "sid.v1.machine.PatService",
    "sid.v1.machine.MachineUserService",
    "sid.v1.admin.MigrationService",
];

/// An address nothing listens on: bound once, then released.
fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The answer to `request` once the listener answers.
async fn sent(request: impl Fn() -> reqwest::RequestBuilder) -> reqwest::Response {
    let mut tries = 0;
    loop {
        match request().send().await {
            Ok(answer) => break answer,
            Err(e) if e.is_connect() && tries < 100 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the HTTP form: {e}"),
        }
    }
}

/// With every optional capability withheld, the server serves none of their
/// services on gRPC, none of the SCIM paths on HTTP, names no token exchange
/// in its discovery and takes none at its token endpoint; what it serves
/// otherwise is untouched.
/// Bug prevented: a withheld capability left out of one transport only, or
/// advertised by an endpoint that refuses it.
#[test]
fn a_withholding_host_serves_none_of_the_withheld_capabilities() {
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
            format!("withheld_{}", uuid::Uuid::new_v4().simple()),
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
        let c = sid_server::init::init_ce_with(CeHost {
            withheld: Withheld {
                scim_provisioning: true,
                external_event_stream: true,
                impersonation: true,
                imported_password_sign_in: true,
            },
            ..CeHost::default()
        })
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
        let discovery: serde_json::Value =
            sent(|| client.get(format!("http://{http}/.well-known/openid-configuration")))
                .await
                .json()
                .await
                .unwrap();
        let grants: Vec<&str> = discovery["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.as_str().unwrap())
            .collect();
        assert!(
            !grants.contains(&sid::oauth::TOKEN_EXCHANGE_GRANT),
            "{grants:?}"
        );
        assert!(grants.contains(&"client_credentials"), "{grants:?}");

        let token = sent(|| {
            client
                .post(format!("http://{http}/oauth2/token"))
                .form(&[("grant_type", sid::oauth::TOKEN_EXCHANGE_GRANT)])
        })
        .await;
        assert_eq!(token.status(), reqwest::StatusCode::BAD_REQUEST);
        let refusal: serde_json::Value = token.json().await.unwrap();
        assert_eq!(refusal["error"], "unsupported_grant_type", "{refusal}");

        for path in ["/scim/v2/ServiceProviderConfig", "/scim/v2/Users"] {
            let answer = sent(|| client.get(format!("http://{http}{path}"))).await;
            assert!(
                matches!(answer.status().as_u16(), 404 | 501),
                "GET {path} answered {}",
                answer.status()
            );
        }

        let channel = tonic::transport::Endpoint::from_shared(format!("http://{grpc_address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut health = HealthClient::new(channel);
        for name in WITHHELD.iter().chain(NEVER_SERVED) {
            let refused = health
                .check(HealthCheckRequest {
                    service: (*name).to_string(),
                })
                .await
                .expect_err("a service that is not served has no status");
            assert_eq!(refused.code(), tonic::Code::NotFound, "{name}: {refused:?}");
        }
        let served = health
            .check(HealthCheckRequest {
                service: "sid.v1.common.OperationService".to_string(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(served.status(), ServingStatus::Serving);

        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
    });
    runtime.shutdown_background();
}
