// SPDX-License-Identifier: AGPL-3.0-only
//! A keyed command whose response is lost after its commit, retried as a
//! caller retries it: on another replica of the installation, over another
//! of the transports a server serves on its HTTP port (native gRPC, gRPC-Web,
//! the HTTP form), after a replica restart, and concurrently with itself. It
//! commits once and every retry gets the original outcome, while the retry
//! still passes the caller's current authorization: another caller under the
//! same key runs its own command, one without the permission gets a refusal
//! and no receipt, and a caller whose session ended gets no receipt either.
//! On PostgreSQL and on SQLite.
//!
//! Requires sid-test-postgres on port 54399.

#![cfg(feature = "http")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use prost::Message as _;
use sid_authn::issuer::IssuerRegistry;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{
    AuditEntry, OidcIssuer, OperationContext, OperationKey, OperationPeriod, Profile, Session,
};
use sid_plugin::StorageBackend;
use sid_plugin::cache::CacheBackend;
use sid_proto::sid::v1::operation_service_server::OperationServiceServer;
use sid_proto::sid::v1::project_service_client::ProjectServiceClient;
use sid_proto::sid::v1::project_service_server::ProjectServiceServer;
use sid_proto::sid::v1::{CreateProjectRequest, ListProjectsRequest, Project};
use sid_server::feature_flags::FeatureFlagService;
use sid_server::grpc::project_service::ProjectServiceImpl;
use tonic::Code;
use tonic::transport::Channel;

/// The storage engine an installation runs on.
#[derive(Clone, Copy, Debug)]
enum Engine {
    Postgres,
    Sqlite,
}

/// One installation: the database and the shared cache its replicas use.
struct Installation {
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn CacheBackend>,
    issuer: OidcIssuer,
    /// Keeps a SQLite database file for the installation's lifetime.
    _dir: tempfile::TempDir,
}

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn installation(engine: Engine) -> Installation {
    let dir = tempfile::tempdir().expect("data directory");
    let storage: Arc<dyn StorageBackend> = match engine {
        Engine::Postgres => {
            let schema = format!("operation_retry_{}", uuid::Uuid::now_v7().simple());
            let backend = sid_storage::PostgresBackend::new(&database_url(), Some(schema.clone()))
                .await
                .expect("test database (docker-compose.test.yml)");
            sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
                .await
                .expect("migrations");
            Arc::new(backend)
        }
        Engine::Sqlite => Arc::new(
            sid_storage::sqlite::SqliteBackend::new(
                dir.path().join("sid.db").to_str().expect("UTF-8 path"),
            )
            .await
            .expect("SQLite store"),
        ),
    };
    storage
        .ensure_system_project(AuditEntry::system("project.ensure_system", "system").into())
        .await
        .unwrap();
    let organization = sid_authn::instance_org::ensure(storage.as_ref(), "sid.example.com")
        .await
        .unwrap();
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        common::test_key_manager().as_ref(),
        &url::Url::parse("https://sid.example.com").unwrap(),
        organization.id,
    )
    .await
    .unwrap();
    Installation {
        storage,
        cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        issuer,
        _dir: dir,
    }
}

/// One server replica: its HTTP port, where native gRPC, gRPC-Web and the
/// HTTP form reach the services as on a server's, and its revocations.
struct Replica {
    base: String,
    revocation: Arc<RevocationCache>,
    /// Receives the other replicas' revocations as long as it lives.
    _revocations: sid_authn::revocation_cache::RevocationListener,
}

impl Installation {
    /// A replica started now over the installation's database and cache.
    async fn replica(&self) -> Replica {
        let revocation = Arc::new(RevocationCache::new(
            Duration::from_secs(900),
            self.cache.clone(),
        ));
        let revocations = revocation.listen().await;
        let project = ProjectServiceImpl::new(
            self.storage.clone(),
            FeatureFlagService::disabled(),
            common::test_jwt(),
            revocation.clone(),
            self.issuer.clone(),
        );
        let periods: Arc<dyn sid_plugin::OperationResultStore> = self.storage.clone();
        let routes = tonic::service::Routes::new(ProjectServiceServer::new(project)).add_service(
            OperationServiceServer::new(sid_infra::authn::operation::OperationPeriods::new(
                periods,
            )),
        );
        let issuers = Arc::new(IssuerRegistry::new(
            self.storage.clone(),
            common::test_key_manager(),
        ));
        Replica {
            base: serve(routes, issuers).await,
            revocation,
            _revocations: revocations,
        }
    }

    /// A stored administrator signed in with a stored session: its bearer
    /// token and that session.
    async fn administrator(&self) -> (String, Session) {
        let mut profile = Profile::new(Some(format!("admin-{}", uuid::Uuid::now_v7().simple())));
        profile.roles = vec!["admin".to_string()];
        self.storage
            .create_profile(&profile, AuditEntry::system("test", "administrator").into())
            .await
            .unwrap();
        common::assign_administrator(self.storage.as_ref(), profile.id).await;
        let session = Session::new(
            profile.id,
            None,
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        self.storage
            .create_session(&session, AuditEntry::system("test", "session").into())
            .await
            .unwrap();
        common::issue_token_with_session(
            &common::test_jwt_service(),
            &profile,
            &["openid".to_string(), "profile".to_string()],
            session,
        )
    }

    /// A stored Profile holding no administration role: its bearer token.
    async fn member(&self) -> String {
        let profile = Profile::new(Some(format!("member-{}", uuid::Uuid::now_v7().simple())));
        self.storage
            .create_profile(&profile, AuditEntry::system("test", "member").into())
            .await
            .unwrap();
        common::issue_token(
            &common::test_jwt_service(),
            &profile,
            &["openid".to_string()],
        )
    }
}

/// `routes` served on a port of their own as a server's HTTP port serves
/// them: the transcoder in front of the same layers. Returns the base URL.
async fn serve(routes: tonic::service::Routes, issuers: Arc<IssuerRegistry>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let proxy = sid_server::serve::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    let upstream = sid_server::serve::transcoder_upstream(routes, issuers);
    // Serves until the test's runtime ends.
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            upstream,
            listener,
            std::future::pending(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    });
    format!("http://{addr}")
}

fn http_client() -> reqwest::Client {
    common::crypto::with_tls(sid_plugin::client_builder)
        .build()
        .unwrap()
}

/// The period `replica` issues, obtained as a client obtains it before its
/// first submission: over the HTTP form.
async fn period(replica: &Replica) -> OperationPeriod {
    let answer: serde_json::Value = http_client()
        .get(format!("{}/v1/operations/period", replica.base))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    OperationPeriod::new(
        answer["period"]
            .as_str()
            .expect("the period as a decimal string")
            .parse()
            .unwrap(),
    )
}

/// One logical command: the key a caller made once and the period it took.
#[derive(Clone)]
struct Command {
    context: OperationContext,
}

impl Command {
    fn new(period: OperationPeriod) -> Self {
        Self {
            context: OperationContext::new(
                OperationKey::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
                period,
            ),
        }
    }

    /// The command's two headers as the transports carry them.
    fn headers(&self) -> tonic::metadata::MetadataMap {
        let mut metadata = tonic::metadata::MetadataMap::new();
        sid_infra::authn::operation::insert_context(&mut metadata, &self.context);
        metadata
    }
}

/// How a call reaches a replica.
#[derive(Clone, Copy, Debug)]
enum Transport {
    Grpc,
    GrpcWeb,
    Http,
}

/// What a create answered: the project's id bytes, or the refusal's code.
type Answer = Result<Vec<u8>, Code>;

/// `name`'s creation by the bearer of `token` named by `command`, sent to
/// `replica` over `transport`.
async fn create(
    replica: &Replica,
    transport: Transport,
    token: &str,
    command: &Command,
    name: &str,
) -> Answer {
    let message = CreateProjectRequest {
        name: name.to_string(),
        ..Default::default()
    };
    match transport {
        Transport::Grpc => {
            let mut client = ProjectServiceClient::new(
                Channel::from_shared(replica.base.clone())
                    .unwrap()
                    .connect_lazy(),
            );
            let mut request = tonic::Request::new(message);
            *request.metadata_mut() = command.headers();
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            client
                .create_project(request)
                .await
                .map(|r| project_id(&r.into_inner()))
                .map_err(|s| s.code())
        }
        Transport::GrpcWeb => grpc_web_create(replica, token, command, &message).await,
        Transport::Http => {
            let mut request = http_client()
                .post(format!("{}/v1/projects", replica.base))
                .bearer_auth(token)
                .json(&serde_json::json!({ "name": name }));
            for (name, value) in http_headers(command) {
                request = request.header(name, value);
            }
            let response = request.send().await.unwrap();
            if !response.status().is_success() {
                return Err(code_of_http(response.status()));
            }
            let project: serde_json::Value = response.json().await.unwrap();
            Ok(base64::engine::general_purpose::STANDARD
                .decode(project["id"]["value"].as_str().expect("the project id"))
                .unwrap())
        }
    }
}

/// The command's headers under their HTTP names.
fn http_headers(command: &Command) -> Vec<(String, String)> {
    command
        .headers()
        .iter()
        .filter_map(|entry| match entry {
            tonic::metadata::KeyAndValueRef::Ascii(name, value) => Some((
                match name.as_str() {
                    "idempotency-key" => "Idempotency-Key".to_string(),
                    "sid-operation-period" => "SID-Operation-Period".to_string(),
                    other => other.to_string(),
                },
                value.to_str().unwrap().to_string(),
            )),
            tonic::metadata::KeyAndValueRef::Binary(..) => None,
        })
        .collect()
}

/// The gRPC code an HTTP form refusal maps back to.
fn code_of_http(status: reqwest::StatusCode) -> Code {
    match status {
        reqwest::StatusCode::UNAUTHORIZED => Code::Unauthenticated,
        reqwest::StatusCode::FORBIDDEN => Code::PermissionDenied,
        reqwest::StatusCode::CONFLICT => Code::AlreadyExists,
        reqwest::StatusCode::BAD_REQUEST => Code::InvalidArgument,
        other => panic!("unexpected HTTP status {other}"),
    }
}

/// The creation over gRPC-Web as a browser client sends it: one length
/// prefixed message, the answer and its trailers framed in the body.
async fn grpc_web_create(
    replica: &Replica,
    token: &str,
    command: &Command,
    message: &CreateProjectRequest,
) -> Answer {
    let encoded = message.encode_to_vec();
    let mut body = vec![0u8];
    body.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&encoded);
    // A browser reaches the services under the API mount.
    let mut request = http_client()
        .post(format!(
            "{}/api/{}/CreateProject",
            replica.base,
            sid_proto::sid::v1::project_service_server::SERVICE_NAME
        ))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .bearer_auth(token)
        .body(body);
    for (name, value) in command.headers().iter().filter_map(|entry| match entry {
        tonic::metadata::KeyAndValueRef::Ascii(name, value) => Some((
            name.as_str().to_string(),
            value.to_str().unwrap().to_string(),
        )),
        tonic::metadata::KeyAndValueRef::Binary(..) => None,
    }) {
        request = request.header(name, value);
    }
    let response = request.send().await.unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    // A refusal before any message is answered in the headers alone.
    if let Some(status) = response.headers().get("grpc-status") {
        let code = Code::from(status.to_str().unwrap().parse::<i32>().unwrap());
        if code != Code::Ok {
            return Err(code);
        }
    }
    let body = response.bytes().await.unwrap();
    let (mut message, mut status) = (None, None);
    let mut rest = &body[..];
    while rest.len() >= 5 {
        let length = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        let frame = &rest[5..5 + length];
        if rest[0] & 0x80 == 0 {
            message = Some(Project::decode(frame).unwrap());
        } else {
            status = std::str::from_utf8(frame)
                .unwrap()
                .split("\r\n")
                .find_map(|line| line.strip_prefix("grpc-status:"))
                .map(|code| Code::from(code.trim().parse::<i32>().unwrap()));
        }
        rest = &rest[5 + length..];
    }
    match status.expect("the call's trailers") {
        Code::Ok => Ok(project_id(&message.expect("the created project"))),
        code => Err(code),
    }
}

fn project_id(project: &Project) -> Vec<u8> {
    project.id.as_ref().expect("the project id").value.to_vec()
}

/// How many projects named `name` the installation holds, as an
/// administrator lists them.
async fn projects_named(replica: &Replica, token: &str, name: &str) -> usize {
    let mut client = ProjectServiceClient::new(
        Channel::from_shared(replica.base.clone())
            .unwrap()
            .connect_lazy(),
    );
    let mut request = tonic::Request::new(ListProjectsRequest::default());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    client
        .list_projects(request)
        .await
        .unwrap()
        .into_inner()
        .projects
        .iter()
        .filter(|p| p.name == name)
        .count()
}

/// The creation's response is lost after its commit. The caller retries it
/// on another replica over gRPC-Web, then over the HTTP form, then on a
/// replica started after the commit: every retry answers with the project
/// the first attempt created, and the installation holds one.
async fn a_lost_creation_is_answered_on_every_replica_and_transport(engine: Engine) {
    let installation = installation(engine).await;
    let (a, b) = (installation.replica().await, installation.replica().await);
    let (token, _) = installation.administrator().await;
    let command = Command::new(period(&a).await);

    let first = create(&a, Transport::Grpc, &token, &command, "billing")
        .await
        .expect("the first attempt commits");
    for transport in [Transport::GrpcWeb, Transport::Http] {
        assert_eq!(
            create(&b, transport, &token, &command, "billing").await,
            Ok(first.clone()),
            "the retry over {transport:?} on another replica"
        );
    }
    let restarted = installation.replica().await;
    assert_eq!(
        create(&restarted, Transport::Grpc, &token, &command, "billing").await,
        Ok(first),
        "the retry on a replica started after the commit"
    );
    assert_eq!(projects_named(&a, &token, "billing").await, 1);
}

/// One command sent many times at once to both replicas over both binary
/// transports: one project, and every attempt answers with it.
async fn concurrent_attempts_on_two_replicas_commit_once(engine: Engine) {
    let installation = installation(engine).await;
    let (a, b) = (
        Arc::new(installation.replica().await),
        Arc::new(installation.replica().await),
    );
    let (token, _) = installation.administrator().await;
    let command = Command::new(period(&a).await);

    let attempts: Vec<_> = (0..8)
        .map(|i| {
            let (replica, transport) = if i % 2 == 0 {
                (a.clone(), Transport::Grpc)
            } else {
                (b.clone(), Transport::GrpcWeb)
            };
            let (token, command) = (token.clone(), command.clone());
            tokio::spawn(
                async move { create(&replica, transport, &token, &command, "payroll").await },
            )
        })
        .collect();
    let mut answers = Vec::new();
    for attempt in attempts {
        answers.push(attempt.await.unwrap().expect("every attempt answers"));
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "the attempts answered with different projects"
    );
    assert_eq!(projects_named(&a, &token, "payroll").await, 1);
}

/// A completed command's receipt goes only to its caller, under the
/// caller's current authorization: another administrator under the same key
/// runs a command of its own, a caller without the permission is refused
/// with no project, and the original caller whose session ended on another
/// replica is refused instead of being answered.
async fn a_receipt_follows_current_authorization(engine: Engine) {
    let installation = installation(engine).await;
    let (a, b) = (installation.replica().await, installation.replica().await);
    let (alice, session) = installation.administrator().await;
    let (bob, _) = installation.administrator().await;
    let member = installation.member().await;
    let command = Command::new(period(&a).await);

    let first = create(&a, Transport::Grpc, &alice, &command, "ledger")
        .await
        .expect("the first attempt commits");
    let others = create(&b, Transport::GrpcWeb, &bob, &command, "ledger")
        .await
        .expect("another administrator's command under the same key");
    assert_ne!(
        others, first,
        "another caller was answered with the receipt"
    );
    assert_eq!(
        create(&b, Transport::Http, &member, &command, "ledger").await,
        Err(Code::PermissionDenied),
    );
    assert_eq!(projects_named(&a, &alice, "ledger").await, 2);

    a.revocation
        .revoke_session(session.id.to_string())
        .await
        .unwrap();
    // The revocation reaches the other replica through the shared cache.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match create(&b, Transport::GrpcWeb, &alice, &command, "ledger").await {
            Err(Code::Unauthenticated) => break,
            Ok(answered) => {
                assert_eq!(answered, first);
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the ended session was still answered with the receipt"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(code) => panic!("the ended session got {code:?}"),
        }
    }
}

/// Each scenario on PostgreSQL and on SQLite.
macro_rules! on_both_engines {
    ($($scenario:ident),* $(,)?) => {
        mod postgres {
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $scenario() {
                    super::$scenario(super::Engine::Postgres).await;
                }
            )*
        }
        mod sqlite {
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $scenario() {
                    super::$scenario(super::Engine::Sqlite).await;
                }
            )*
        }
    };
}

on_both_engines!(
    a_lost_creation_is_answered_on_every_replica_and_transport,
    concurrent_attempts_on_two_replicas_commit_once,
    a_receipt_follows_current_authorization,
);
