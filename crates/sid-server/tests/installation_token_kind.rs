// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's own management services take only its own session
//! token, on every transport they are served on: over native gRPC and over
//! HTTP through the transcoder the server embeds. A token signed with the
//! installation's key but of another kind (an application's `at+jwt`, a
//! logout token), for another audience as well, or naming a requesting
//! client is refused before the request is served, even when it carries an
//! administrator's every other claim.

#![cfg(feature = "http")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sid_authn::jwt::AccessTokenClaims;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::ProfileId;
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::admin::ListIpAllowlistEntriesRequest;
use sid_proto::sid::v1::admin::security_service_client::SecurityServiceClient;
use sid_proto::sid::v1::admin::security_service_server::SecurityServiceServer;
use sid_server::grpc::security_service::SecurityServiceImpl;
use tonic::transport::Channel;

/// The security service of an installation on SQLite, as a server serves it.
async fn service() -> (
    SecurityServiceServer<SecurityServiceImpl>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("data directory");
    let storage: Arc<dyn StorageBackend> = Arc::new(
        sid_storage::sqlite::SqliteBackend::new(
            dir.path().join("sid.db").to_str().expect("UTF-8 path"),
        )
        .await
        .expect("SQLite store"),
    );
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let revocation = Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        cache.clone(),
    ));
    let svc = SecurityServiceImpl::new(
        storage,
        common::test_jwt(),
        revocation,
        common::RecordingAuditLog::shared(),
        cache,
    );
    (SecurityServiceServer::new(svc), dir)
}

/// The claims of an administrator's session token the installation issued.
fn administrator() -> AccessTokenClaims {
    let token = common::issue_admin_token(&common::test_jwt_service(), ProfileId::generate());
    common::test_jwt_service()
        .validate_access_token(&token)
        .expect("the installation's own token")
}

/// `claims` signed with the installation's key under JWS `typ` `typ` (the
/// library's default `JWT` when `None`).
fn signed(typ: Option<&str>, claims: &AccessTokenClaims) -> String {
    let key = jsonwebtoken::EncodingKey::from_ed_pem(include_bytes!(
        "../../sid-authn/tests/fixtures/test_ed25519_private.pem"
    ))
    .expect("signing key");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    if let Some(typ) = typ {
        header.typ = Some(typ.to_string());
    }
    jsonwebtoken::encode(&header, claims, &key).expect("sign")
}

/// Tokens of the installation's key that are not its session token.
fn foreign_kinds() -> Vec<(&'static str, String)> {
    let claims = administrator();
    let mut wider = administrator();
    wider.aud.push("https://app.example.com".to_string());
    let mut requested = administrator();
    requested.client_id = Some("app".to_string());
    vec![
        (
            "an application's access token",
            signed(Some("at+jwt"), &claims),
        ),
        ("a logout token", signed(Some("logout+jwt"), &claims)),
        ("another audience too", signed(None, &wider)),
        ("a requesting client", signed(None, &requested)),
    ]
}

#[tokio::test]
async fn only_the_session_token_is_admitted_over_grpc() {
    let (service, _dir) = service().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = SecurityServiceClient::new(channel);
    let call = |token: String| {
        let mut request = tonic::Request::new(ListIpAllowlistEntriesRequest::default());
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    };

    client
        .list_ip_allowlist_entries(call(signed(None, &administrator())))
        .await
        .expect("the administrator's session token");
    for (kind, token) in foreign_kinds() {
        let refused = client
            .list_ip_allowlist_entries(call(token))
            .await
            .expect_err(kind);
        assert_eq!(refused.code(), tonic::Code::Unauthenticated, "{kind}");
    }
}

#[tokio::test]
async fn only_the_session_token_is_admitted_over_http() {
    let (service, _dir) = service().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let proxy = sid_server::serve::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            tonic::service::Routes::new(service),
            listener,
            std::future::pending(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    });
    let http = common::crypto::with_tls(sid_plugin::client_builder)
        .build()
        .unwrap();
    let get = |token: String| {
        http.get(format!("http://{addr}/v1/admin/security/ip-allowlist"))
            .bearer_auth(token)
            .send()
    };

    let admitted = get(signed(None, &administrator())).await.unwrap();
    assert_eq!(admitted.status(), 200, "the administrator's session token");
    for (kind, token) in foreign_kinds() {
        assert_eq!(get(token).await.unwrap().status(), 401, "{kind}");
    }
}
