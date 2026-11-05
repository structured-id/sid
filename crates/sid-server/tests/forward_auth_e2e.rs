// SPDX-License-Identifier: AGPL-3.0-only
//! Forward auth end to end: tokens this server issues are verified by
//! sid-auth, which resolves the protected application's target through this
//! server's issuer registry over gRPC. Nothing is hand-built: the token
//! format, the registry answer and the verifier meet as in a deployment.

mod common;

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, test_profile};
use sid_core::models::{
    Application, ApplicationId, AuditEntry, Profile, ProjectId, ProtectedResource, ResourceAccess,
    ResourceId, ResourceIndicator, ResourceState, Session,
};
use sid_proto::sid::v1::OAuth2TokenRequest;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerServiceServer;
use tower::ServiceExt;

const ORDERS: &str = "https://resources.example/orders";
const WIKI: &str = "https://wiki.example/";
const MACHINE: &str = "mu_forward_auth";
const MACHINE_SECRET: &str = "forward-auth-machine-secret";
/// sid-auth's own client at the issuer, which inspects the tokens it admits.
const INSPECTOR: &str = "mu_forward_auth_inspector";
const INSPECTOR_SECRET: &str = "forward-auth-inspector-secret";

/// A machine user of the installation with a client secret.
fn with_machine_user(storage: MockStorage, client_id: &str, secret: &str) -> MockStorage {
    use sid_core::models::machine_user::*;
    let mu = MachineUser::new(
        ProjectId::SYSTEM,
        client_id,
        "Forward auth bot",
        OwnerType::System,
        "system",
    );
    let cred = MachineUserCredential::new(
        mu.id,
        format!("kid_{client_id}"),
        MachineCredentialType::ClientSecret,
        sid_authn::bearer_secret::verifier_of(secret),
    );
    storage.with_machine_user(mu).with_machine_credential(cred)
}

/// The token's subject machine and sid-auth's inspector machine.
fn with_machine(storage: MockStorage) -> MockStorage {
    with_machine_user(
        with_machine_user(storage, MACHINE, MACHINE_SECRET),
        INSPECTOR,
        INSPECTOR_SECRET,
    )
}

/// sid-auth's inspector may inspect the tokens of `resource`.
async fn inspect_on(svc: &TestServices, resource: &ProtectedResource) {
    let inspector = svc
        .storage
        .get_machine_user_by_client_id(INSPECTOR)
        .await
        .unwrap()
        .expect("the inspector machine");
    common::grant_inspection(
        svc,
        sid_core::models::RoleAssignmentPrincipal::MachineUser(inspector.id),
        resource.id,
    )
    .await;
}

/// Register `indicator` under the installation's issuer and, when
/// `machine_scopes` is given, give the machine user access to it.
async fn register(
    svc: &TestServices,
    indicator: &str,
    machine_scopes: Option<&[&str]>,
) -> ProtectedResource {
    let now = Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::SYSTEM,
        name: indicator.into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: svc.issuer.id,
        indicator: ResourceIndicator::parse(indicator).unwrap(),
        scopes: vec!["api.read".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    svc.storage
        .create_application(
            &app,
            None,
            Some(&resource),
            AuditEntry::system("test", "api").into(),
        )
        .await
        .unwrap();
    if let Some(scopes) = machine_scopes {
        svc.storage
            .set_resource_access(
                &ResourceAccess {
                    client_id: MACHINE.into(),
                    resource_id: resource.id,
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                    created_at: now,
                },
                AuditEntry::system("test", "access").into(),
            )
            .await
            .unwrap();
    }
    resource
}

/// The machine user's access token for Orders, from the token endpoint.
async fn machine_token(svc: &TestServices) -> String {
    svc.auth
        .o_auth2_token(tonic::Request::new(OAuth2TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: Some(MACHINE.into()),
            client_secret: Some(MACHINE_SECRET.into()),
            issuer_handle: svc.issuer.handle.to_string(),
            resource: vec![ORDERS.into()],
            ..Default::default()
        }))
        .await
        .expect("client credentials for Orders")
        .into_inner()
        .access_token
}

/// A user's access token for `indicator` as the installation's issuer signs
/// it for client `orders-web`, in a sign-in session the issuer holds.
async fn user_token(svc: &TestServices, profile: &Profile, indicator: &str) -> String {
    let session = Session::new(profile.id, None, Utc::now() + Duration::hours(1));
    svc.storage
        .create_session(&session, AuditEntry::system("test", "sign-in").into())
        .await
        .unwrap();
    let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
    svc.jwt
        .access_token_signed_by(
            signer.as_ref(),
            sid_authn::jwt::TokenAudience::Resource {
                indicator,
                client_id: "orders-web",
            },
            &profile.id.to_string(),
            None,
            &profile.roles,
            &session,
            &["api.read".to_string()],
            None,
            None,
        )
        .unwrap()
}

/// Serve this server's issuer registry and token endpoints on a local port.
async fn serve_registry(svc: &TestServices) -> SocketAddr {
    let registry = sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
        svc.issuers.clone(),
        svc.storage.clone(),
        svc.authz.clone(),
    );
    let auth =
        sid_proto::sid::v1::auth_service_server::AuthServiceServer::from_arc(svc.auth.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(OidcIssuerServiceServer::new(registry))
            .add_service(auth)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    addr
}

/// sid-auth's HTTP form as it serves it: the embedded transcoder in front of
/// its own gRPC services, called in process.
type Http = structured_proxy::ProxyService<tonic::service::Routes>;

/// sid-auth as deployed, protecting Orders and Wiki under the installation's
/// issuer, answering forward auth through its embedded transcoder. It asks
/// this server's registry at `addr` and has the issuer inspect each token
/// with its own client. The route and secret files live as long as the
/// returned handle.
async fn forward_auth(svc: &TestServices, addr: SocketAddr) -> (Http, Files) {
    forward_auth_over(svc, addr, svc.cache.clone()).await
}

/// As [`forward_auth`], with `cache` as sid-auth's shared cache.
async fn forward_auth_over(
    svc: &TestServices,
    addr: SocketAddr,
    cache: std::sync::Arc<dyn sid_plugin::cache::CacheBackend>,
) -> (Http, Files) {
    let issuer = svc.issuer.canonical_url.clone();
    let base = issuer
        .split("/i/")
        .next()
        .expect("issuer URL under the installation's base")
        .to_owned();
    let routes = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        routes.path(),
        format!(
            r#"
applications:
  - name: orders
    origin: https://orders.example
    issuer: {issuer}
    resource: {ORDERS}
    routes:
      - match: {{ path: "/**" }}
        policy: {{ auth: required, headers: {{ inject: [user] }} }}
  - name: wiki
    origin: https://wiki.example
    issuer: {issuer}
    resource: {WIKI}
"#
        ),
    )
    .unwrap();
    let secret = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(secret.path(), INSPECTOR_SECRET).unwrap();
    let config: sid_auth::config::AuthConfig = serde_saphyr::from_str(&format!(
        "upstream: http://{addr}\nissuer_url: {base}\nroute_policy_path: {}\nhttp:\n  listen: {{ http: \"127.0.0.1:0\" }}\n\
         authz_checker:\n  issuer: {issuer}\n  client_id: {INSPECTOR}\n  authentication: {{ method: client_secret_basic, secret_file: {} }}\n",
        routes.path().display(),
        secret.path().display(),
    ))
    .unwrap();
    let server = sid_auth::server::AuthServer::new(config, cache).unwrap();
    let http = server
        .http_proxy()
        .unwrap()
        .expect("an http section gives a transcoder")
        .service(server.routes().await)
        .unwrap();
    (http, Files(vec![routes, secret]))
}

/// Files sid-auth reads while it runs.
struct Files(#[allow(dead_code)] Vec<tempfile::NamedTempFile>);

async fn verify(router: &Http, application: &str, token: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/verify/{application}"))
                .header("x-original-uri", "/api/items")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn setup() -> (TestServices, Profile, Http, Files) {
    let profile = test_profile();
    let svc = TestServices::new(with_machine(
        MockStorage::new().with_profile(profile.clone()),
    ));
    let orders = register(&svc, ORDERS, Some(&["api.read"])).await;
    let wiki = register(&svc, WIKI, None).await;
    inspect_on(&svc, &orders).await;
    inspect_on(&svc, &wiki).await;
    // The client the users' tokens are issued to.
    let mut web = common::test_client();
    web.client_id = "orders-web".into();
    common::store_client(svc.storage.as_ref(), &web)
        .await
        .unwrap();
    let addr = serve_registry(&svc).await;
    let (router, routes) = forward_auth(&svc, addr).await;
    (svc, profile, router, routes)
}

/// A machine client's token from the token endpoint opens the API it was
/// issued for, and the upstream learns the machine as the subject; the same
/// token does not open another application of the same issuer.
#[tokio::test]
async fn machine_token_opens_only_its_resource() {
    let (svc, _profile, router, _routes) = setup().await;
    let token = machine_token(&svc).await;

    let response = verify(&router, "orders", &token).await;
    assert_eq!(response.status(), StatusCode::OK);
    // The machine's own principal, as its token names it: its ID, not its
    // client_id (an opaque subject to the upstream either way).
    let machine = svc
        .storage
        .get_machine_user_by_client_id(MACHINE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        response.headers()["x-forwarded-user"],
        machine.id.to_string().as_str()
    );

    let response = verify(&router, "wiki", &token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A user's access token for Orders opens Orders only; the same user's
/// installation sign-in token, valid for SID's own services, opens neither.
#[tokio::test]
async fn user_tokens_are_bound_to_their_resource() {
    let (svc, profile, router, _routes) = setup().await;
    let orders = user_token(&svc, &profile, ORDERS).await;

    let response = verify(&router, "orders", &orders).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["x-forwarded-user"],
        profile.id.to_string()
    );
    assert_eq!(
        verify(&router, "wiki", &orders).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let session_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    for application in ["orders", "wiki"] {
        assert_eq!(
            verify(&router, application, &session_token).await.status(),
            StatusCode::UNAUTHORIZED,
            "{application}"
        );
    }
}

/// A session the server revokes stops opening the application at once:
/// the issuer reports its token inactive to sid-auth's inspection.
#[tokio::test]
async fn revocation_by_the_server_is_honoured() {
    let (svc, profile, router, _routes) = setup().await;
    let token = user_token(&svc, &profile, ORDERS).await;
    assert_eq!(
        verify(&router, "orders", &token).await.status(),
        StatusCode::OK
    );

    let claims = svc
        .issuers
        .verifier(&svc.issuer)
        .await
        .unwrap()
        .validate_access_token_for(&token, ORDERS)
        .unwrap();
    svc.revocation_cache
        .revoke_session(claims.sid.clone())
        .await
        .unwrap();
    assert_eq!(
        verify(&router, "orders", &token).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

/// sid-auth started without its shared cache still decides on the issuer's
/// current state: an active token opens the application, a revoked one does
/// not, and with the issuer unreachable there is no verdict, never an allow.
#[tokio::test]
async fn forward_auth_without_its_cache_asks_the_issuer() {
    let (svc, profile, _router, _files) = setup().await;
    let addr = serve_registry(&svc).await;
    let (router, _files) =
        forward_auth_over(&svc, addr, std::sync::Arc::new(common::DownCache)).await;
    let token = user_token(&svc, &profile, ORDERS).await;
    assert_eq!(
        verify(&router, "orders", &token).await.status(),
        StatusCode::OK
    );

    let claims = svc
        .issuers
        .verifier(&svc.issuer)
        .await
        .unwrap()
        .validate_access_token_for(&token, ORDERS)
        .unwrap();
    svc.revocation_cache
        .revoke_session(claims.sid.clone())
        .await
        .unwrap();
    assert_eq!(
        verify(&router, "orders", &token).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let unreachable: SocketAddr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let (router, _files) =
        forward_auth_over(&svc, unreachable, std::sync::Arc::new(common::DownCache)).await;
    let fresh = user_token(&svc, &profile, ORDERS).await;
    assert_ne!(
        verify(&router, "orders", &fresh).await.status(),
        StatusCode::OK
    );
}

/// A resource deactivated in the registry opens nothing to a newly started
/// verifier, whatever the token.
#[tokio::test]
async fn deactivated_resource_opens_nothing() {
    let (svc, profile, _router, _routes) = setup().await;
    let mut orders = svc
        .storage
        .protected_resource_by_indicator(svc.issuer.id, &ResourceIndicator::parse(ORDERS).unwrap())
        .await
        .unwrap()
        .unwrap();
    orders.state = ResourceState::Inactive;
    assert!(
        svc.storage
            .update_protected_resource(&orders, AuditEntry::system("test", "resource").into())
            .await
            .unwrap()
    );
    let (router, _routes) = forward_auth(&svc, serve_registry(&svc).await).await;
    let token = user_token(&svc, &profile, ORDERS).await;
    assert_eq!(
        verify(&router, "orders", &token).await.status(),
        StatusCode::FORBIDDEN
    );
}
