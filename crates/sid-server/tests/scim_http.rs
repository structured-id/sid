// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM provisioning end to end: an independent SCIM client talks HTTP to the
//! endpoint as a server serves it (the transcoder over the real services),
//! on PostgreSQL and on SQLite. It authenticates with a connector's SCIM
//! bearer or with an access token it obtained at the token endpoint, creates,
//! reads, updates, deactivates and deletes users and groups, and every wrong
//! credential, connector, organization, resource, issuer or direction fails
//! before any effect. Replicas over one database see each other's writes and
//! state at once; an authorization outage refuses instead of allowing.

#![cfg(all(feature = "scim", feature = "http"))]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use sid_authn::bearer_secret;
use sid_authn::issuer::IssuerRegistry;
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::provisioning_connector::SCIM_BEARER_PREFIX;
use sid_core::models::{
    AuditEntry, ConnectorCredentialKind, OidcIssuer, OrgId, ProjectId, ProtectedResource,
    ProvisioningConnector, ProvisioningCredential, ProvisioningDirection, SCIM_PROVISIONER_ROLE,
};
use sid_plugin::StorageBackend;
use sid_plugin::authz::{AuthzCheckRequest, AuthzCheckResponse, AuthzEngine, AuthzError};
use sid_plugin::cache::CacheBackend;
use sid_proto::sid::v1::admin as pb;
use sid_proto::sid::v1::admin::provisioning_service_server::ProvisioningService;
use sid_proto::sid::v1::authz::AssignRoleRequest;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz_service_server::AuthzService;
use sid_proto::sid::v1::oidc_provider_service_server::OidcProviderServiceServer;
use sid_proto::sid::v1::scim_protocol_service_server::ScimProtocolServiceServer;
use sid_scim::grpc::{ScimDirectory, ScimServiceImpl};
use sid_scim::protocol::ScimProtocolServiceImpl;
use sid_server::feature_flags::FeatureFlagService;
use sid_server::grpc::oidc_provider_service::OidcProviderServiceImpl;
use sid_server::grpc::project_service::ProjectServiceImpl;
use sid_server::grpc::provisioning_service::ProvisioningServiceImpl;
use tonic::Request;
use uuid::Uuid;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// The storage engine an installation runs on.
#[derive(Clone, Copy, Debug)]
enum Engine {
    Postgres,
    Sqlite,
}

/// One installation's database and shared cache, provisioned as a server
/// start provisions them.
struct Installation {
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn CacheBackend>,
    organization: sid_core::models::Organization,
    org: OrgId,
    issuer: OidcIssuer,
    directory: ProtectedResource,
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
            let schema = format!("scim_http_{}", Uuid::now_v7().simple());
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
    let org = organization.id;
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        common::test_key_manager().as_ref(),
        &url::Url::parse("https://sid.example.com").unwrap(),
        org,
    )
    .await
    .unwrap();
    let directory = sid_authn::issuer::ensure_scim_resource(storage.as_ref(), &issuer)
        .await
        .unwrap();
    sid_authz::builtin::ensure_scim_provisioner_role(storage.as_ref())
        .await
        .unwrap();
    Installation {
        storage,
        cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        organization,
        org,
        issuer,
        directory,
        _dir: dir,
    }
}

/// One server replica of an installation: its HTTP base URL and the
/// administration services a test drives in process.
struct Replica {
    base: String,
    provisioning: ProvisioningServiceImpl,
    authz: AuthzServiceImpl,
    issuers: Arc<IssuerRegistry>,
}

impl Installation {
    /// A replica deciding provisioning authorization with the installation's
    /// engine.
    async fn replica(&self) -> Replica {
        self.replica_with(Arc::new(sid_authz::CeAuthzEngine::new(
            self.storage.clone(),
        )))
        .await
    }

    /// A replica whose SCIM endpoint decides with `engine`.
    async fn replica_with(&self, engine: Arc<dyn AuthzEngine>) -> Replica {
        let storage = self.storage.clone();
        let jwt = common::test_jwt();
        let revocation = Arc::new(RevocationCache::new(
            Duration::from_secs(900),
            self.cache.clone(),
        ));
        revocation.listen().await.expect("revocation listener");
        let issuers = Arc::new(IssuerRegistry::new(
            storage.clone(),
            common::test_key_manager(),
        ));
        let flags = FeatureFlagService::disabled();
        let auth = common::auth_service(
            storage.clone(),
            self.cache.clone(),
            common::AuthOptions {
                opaque_router: common::stored_opaque_router(storage.as_ref()).await,
                jwt: jwt.clone(),
                oauth2: Arc::new(sid_authn::oauth2::OAuth2Server::new(jwt.clone())),
                webauthn: common::test_webauthn(self.cache.clone()),
                revocation_cache: revocation.clone(),
                feature_flags: flags.clone(),
                magic_link: None,
                zkpp: None,
                issuers: issuers.clone(),
                org: self.org,
                cascade: Arc::new(
                    sid_authn::revocation_cascade::RevocationCascadeService::new(
                        storage.clone(),
                        revocation.clone(),
                    ),
                ),
                security_policy: None,
            },
        );
        let project = Arc::new(ProjectServiceImpl::new(
            storage.clone(),
            flags,
            jwt.clone(),
            revocation.clone(),
            self.issuer.clone(),
        ));
        let provider = OidcProviderServiceImpl::new(
            issuers.clone(),
            storage.clone(),
            revocation.clone(),
            self.cache.clone(),
            auth,
            project,
            None,
        );
        let tokens = sid_authn::resource_token::ResourceTokenVerifier::new(
            issuers.clone(),
            self.issuer.clone(),
            self.directory.indicator.clone(),
        )
        .await
        .unwrap();
        let scim = ScimServiceImpl::new(
            storage.clone(),
            sid_scim::mapping::ScimOrgContext::installation(&self.organization),
            "https://sid.example.com".into(),
            ScimDirectory {
                org: self.org,
                resource: self.directory.id,
            },
            engine,
            revocation.clone(),
        )
        .with_access_tokens(Arc::new(tokens));
        let provisioning = ProvisioningServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation.clone(),
            self.issuer.clone(),
            self.directory.clone(),
            "https://sid.example.com/scim/v2".into(),
        );
        let authz = AuthzServiceImpl::new(
            Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
            storage,
            CedarService::new(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            jwt,
            revocation,
            common::RecordingAuditLog::shared(),
        );
        let routes = tonic::service::Routes::new(ScimProtocolServiceServer::new(
            ScimProtocolServiceImpl::new(Arc::new(scim)),
        ))
        .add_service(OidcProviderServiceServer::new(provider));
        Replica {
            base: over_http(routes).await,
            provisioning,
            authz,
            issuers,
        }
    }
}

/// `routes` behind the transcoder a server embeds; returns the base URL.
async fn over_http(routes: tonic::service::Routes) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let proxy = sid_server::serve::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    // Serves until the test's runtime ends.
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            routes,
            listener,
            std::future::pending(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    });
    format!("http://{addr}")
}

fn admin<T>(message: T) -> Request<T> {
    let token = common::issue_admin_token(
        &common::test_jwt_service(),
        sid_core::models::ProfileId::generate(),
    );
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn keyed<T>(message: T) -> Request<T> {
    let mut request = admin(message);
    request.metadata_mut().insert(
        "idempotency-key",
        Uuid::now_v7().simple().to_string().parse().unwrap(),
    );
    request
}

/// A connector the administrator registered, with its OAuth client_id.
struct Connector {
    proto: pb::ProvisioningConnector,
    client_id: String,
}

impl Replica {
    /// An inbound connector registered through the administration API.
    async fn connector(&self) -> Connector {
        let proto = self
            .provisioning
            .create_inbound_connector(keyed(pb::CreateInboundConnectorRequest {
                display_name: "HR sync".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let client_id = self
            .provisioning
            .get_scim_inbound_config(admin(pb::GetScimInboundConfigRequest {
                connector_id: proto.id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .client_id;
        Connector { proto, client_id }
    }

    /// Grants `connector` the built-in SCIM provisioner role on the
    /// directory, through the authorization API.
    async fn grant(&self, installation: &Installation, connector: &Connector) {
        let role = installation
            .storage
            .list_roles(ProjectId::system())
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.key == SCIM_PROVISIONER_ROLE)
            .unwrap();
        self.authz
            .assign_role(admin(AssignRoleRequest {
                principal: Some(Principal::ProvisioningConnectorId(
                    connector.proto.id.clone().unwrap(),
                )),
                role_id: role.id.0.to_string(),
                scope: Some(format!("oauth_resource:{}", installation.directory.id)),
                expires_at: None,
                admin: None,
            }))
            .await
            .unwrap();
    }

    /// A credential of `kind` issued to `connector`; returns its secret.
    async fn issue(&self, connector: &Connector, kind: pb::ConnectorCredentialKind) -> String {
        self.provisioning
            .create_connector_credential(keyed(pb::CreateConnectorCredentialRequest {
                connector_id: connector.proto.id.clone(),
                expires_at: None,
                kind: kind.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .secret
    }

    async fn set_state(&self, connector: &Connector, state: pb::ProvisioningConnectorState) {
        self.provisioning
            .change_provisioning_connector_state(admin(
                pb::ChangeProvisioningConnectorStateRequest {
                    connector_id: connector.proto.id.clone(),
                    state: state.into(),
                },
            ))
            .await
            .unwrap();
    }

    /// The token endpoint's answer to a client_credentials request of
    /// `client_id` with `secret` (client_secret_basic, RFC 6749 §2.3.1)
    /// carrying the extra form `fields`.
    async fn token_response(
        &self,
        issuer: &OidcIssuer,
        client_id: &str,
        secret: &str,
        fields: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut form = vec![("grant_type", "client_credentials")];
        form.extend_from_slice(fields);
        http()
            .post(format!("{}/i/{}/oauth2/token", self.base, issuer.handle))
            .basic_auth(client_id, Some(secret))
            .form(&form)
            .send()
            .await
            .unwrap()
    }

    /// An access token for the SCIM resource, as an HR system obtains it.
    async fn token(&self, issuer: &OidcIssuer, client_id: &str, secret: &str) -> String {
        let response = self.token_response(issuer, client_id, secret, &[]).await;
        assert_eq!(response.status(), 200, "token endpoint");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["token_type"], json!("Bearer"));
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = http()
            .request(method, format!("{}/scim/v2{path}", self.base))
            .header("accept", "application/scim+json");
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/scim+json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        let value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        (status, value)
    }

    /// How many users a filter on `user_name` finds, asked with `bearer`.
    async fn users_named(&self, bearer: &str, user_name: &str) -> u64 {
        let filter = format!("userName eq \"{user_name}\"");
        let url = url::Url::parse_with_params(
            &format!("{}/scim/v2/Users", self.base),
            [("filter", filter.as_str())],
        )
        .unwrap();
        let response = http().get(url).bearer_auth(bearer).send().await.unwrap();
        assert_eq!(response.status(), 200, "list users");
        let body: Value = response.json().await.unwrap();
        body["totalResults"].as_u64().unwrap_or(0)
    }
}

fn http() -> reqwest::Client {
    sid_plugin::client_builder().build().unwrap()
}

/// A user as an HR system sends it (RFC 7643 §4.1, RFC 7644 §3.3).
fn new_user(user_name: &str) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "userName": user_name,
        "externalId": format!("EMP-{user_name}"),
        "name": { "givenName": "Ada", "familyName": "Lovelace" },
        "emails": [{ "value": format!("{user_name}@corp.sid.example.com"), "type": "work", "primary": true }],
        "title": "Engineer",
        "active": true,
    })
}

fn patch(operations: Value) -> Value {
    json!({ "schemas": [PATCH_SCHEMA], "Operations": operations })
}

fn unique_name() -> String {
    format!("scim_http_{}", Uuid::now_v7().simple())
}

/// The full user and group lifecycle with `bearer`.
async fn lifecycle(replica: &Replica, storage: &dyn StorageBackend, bearer: &str) {
    use reqwest::Method;

    let user_name = unique_name();
    let (status, user) = replica
        .send(
            Method::POST,
            "/Users",
            Some(bearer),
            Some(new_user(&user_name)),
        )
        .await;
    assert_eq!(status, 201, "create user: {user}");
    assert_eq!(user["userName"], json!(user_name));
    let id = user["id"].as_str().expect("user id").to_owned();
    // The other end: the directory now holds the profile.
    let profile = storage
        .get_profile(sid_core::models::ProfileId::parse(&id).unwrap())
        .await
        .unwrap()
        .expect("provisioned profile");
    // A provisioned corporate profile waits for its holder to claim it.
    assert_eq!(profile.status, sid_core::models::ProfileStatus::Provisioned);
    // Its login is federated under the installation organization's domain.
    let principals = storage.get_principals_by_profile(profile.id).await.unwrap();
    assert!(
        principals
            .iter()
            .any(|p| p.value == format!("{user_name}#sid.example.com")),
        "{principals:?}"
    );

    let (status, read) = replica
        .send(Method::GET, &format!("/Users/{id}"), Some(bearer), None)
        .await;
    assert_eq!(status, 200, "read user: {read}");
    assert_eq!(read["userName"], json!(user_name));

    let (status, updated) = replica
        .send(
            Method::PATCH,
            &format!("/Users/{id}"),
            Some(bearer),
            Some(patch(
                json!([{ "op": "replace", "path": "title", "value": "Lead" }]),
            )),
        )
        .await;
    assert_eq!(status, 200, "update user: {updated}");
    assert_eq!(updated["title"], json!("Lead"));

    let (status, group) = replica
        .send(
            Method::POST,
            "/Groups",
            Some(bearer),
            Some(json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": unique_name(),
                "members": [{ "value": id }],
            })),
        )
        .await;
    assert_eq!(status, 201, "create group: {group}");
    let group_id = group["id"].as_str().expect("group id").to_owned();
    let (status, read) = replica
        .send(
            Method::GET,
            &format!("/Groups/{group_id}"),
            Some(bearer),
            None,
        )
        .await;
    assert_eq!(status, 200, "read group: {read}");
    assert_eq!(read["members"][0]["value"], json!(id));
    let (status, emptied) = replica
        .send(
            Method::PATCH,
            &format!("/Groups/{group_id}"),
            Some(bearer),
            Some(patch(
                json!([{ "op": "remove", "path": format!("members[value eq \"{id}\"]") }]),
            )),
        )
        .await;
    assert_eq!(status, 200, "update group: {emptied}");
    assert!(
        emptied["members"]
            .as_array()
            .is_none_or(|members| members.is_empty()),
        "{emptied}"
    );

    // Deactivation keeps the user, inactive.
    let (status, deactivated) = replica
        .send(
            Method::PATCH,
            &format!("/Users/{id}"),
            Some(bearer),
            Some(patch(
                json!([{ "op": "replace", "path": "active", "value": false }]),
            )),
        )
        .await;
    assert_eq!(status, 200, "deactivate user: {deactivated}");
    assert_eq!(deactivated["active"], json!(false));
    let stored = |id: &str| {
        let id = sid_core::models::ProfileId::parse(id).unwrap();
        async move { storage.get_profile(id).await.unwrap().unwrap().status }
    };
    assert_eq!(
        stored(&id).await,
        sid_core::models::ProfileStatus::Suspended
    );

    let (status, _) = replica
        .send(
            Method::DELETE,
            &format!("/Groups/{group_id}"),
            Some(bearer),
            None,
        )
        .await;
    assert_eq!(status, 204, "delete group");
    let (status, _) = replica
        .send(
            Method::GET,
            &format!("/Groups/{group_id}"),
            Some(bearer),
            None,
        )
        .await;
    assert_eq!(status, 404, "a deleted group is gone");

    // A deletion ends the account's access.
    let (status, _) = replica
        .send(Method::DELETE, &format!("/Users/{id}"), Some(bearer), None)
        .await;
    assert_eq!(status, 204, "delete user");
    assert!(!matches!(
        stored(&id).await,
        sid_core::models::ProfileStatus::Active | sid_core::models::ProfileStatus::Provisioned
    ));
}

/// An HR system provisions users and groups with its SCIM bearer and with an
/// access token it obtained with its client secret.
async fn provisions_over_http(engine: Engine) {
    let installation = installation(engine).await;
    let replica = installation.replica().await;
    let connector = replica.connector().await;
    replica.grant(&installation, &connector).await;
    let bearer = replica
        .issue(&connector, pb::ConnectorCredentialKind::ScimBearer)
        .await;
    let secret = replica
        .issue(&connector, pb::ConnectorCredentialKind::ClientSecret)
        .await;
    let token = replica
        .token(&installation.issuer, &connector.client_id, &secret)
        .await;

    lifecycle(&replica, installation.storage.as_ref(), &bearer).await;
    lifecycle(&replica, installation.storage.as_ref(), &token).await;
}

#[tokio::test]
async fn provisions_over_http_on_postgres() {
    provisions_over_http(Engine::Postgres).await;
}

#[tokio::test]
async fn provisions_over_http_on_sqlite() {
    provisions_over_http(Engine::Sqlite).await;
}

/// A connector stored directly, as no administration API creates it: of
/// another organization, or outbound. Returns its SCIM bearer.
async fn stored_connector(
    installation: &Installation,
    org: OrgId,
    direction: ProvisioningDirection,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    let audit = || AuditEntry::system("test", "connector").into();
    let connector = ProvisioningConnector::new(org, direction, "elsewhere");
    installation
        .storage
        .create_provisioning_connector(&connector, audit())
        .await
        .unwrap();
    let issued = bearer_secret::issue(SCIM_BEARER_PREFIX);
    let mut credential = ProvisioningCredential::new(
        connector.id,
        ConnectorCredentialKind::ScimBearer,
        issued.verifier.clone(),
    );
    credential.expires_at = expires_at;
    assert!(
        installation
            .storage
            .add_provisioning_credential(&credential, audit())
            .await
            .unwrap()
    );
    issued.secret.expose_secret().clone()
}

/// `token`'s claims, decoded without verification.
fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap()
}

/// Every wrong credential fails with 401 before any effect, a credential
/// without the authority with 403; the valid connector reaches no
/// administration, delegation or other resource.
async fn refuses_before_effects(engine: Engine) {
    use reqwest::Method;

    let installation = installation(engine).await;
    let replica = installation.replica().await;
    let connector = replica.connector().await;
    replica.grant(&installation, &connector).await;
    let bearer = replica
        .issue(&connector, pb::ConnectorCredentialKind::ScimBearer)
        .await;
    let secret = replica
        .issue(&connector, pb::ConnectorCredentialKind::ClientSecret)
        .await;
    let token = replica
        .token(&installation.issuer, &connector.client_id, &secret)
        .await;

    // Signed by this issuer, but for another resource, another connector,
    // with a proof key, or expired.
    let signer = replica.issuers.signer(&installation.issuer).await.unwrap();
    let forged = |edit: &dyn Fn(&mut Value)| {
        let mut claims = claims_of(&token);
        edit(&mut claims);
        signer.sign(Some("at+jwt"), &claims).unwrap()
    };
    let other_resource = forged(&|c| {
        c["aud"] = json!(sid_authn::issuer::userinfo_endpoint(
            &installation.issuer.canonical_url
        ))
    });
    let other_subject = forged(&|c| {
        c["sub"] = json!(sid_core::models::ProvisioningConnectorId::generate().to_string())
    });
    let proof_bound =
        forged(&|c| c["cnf"] = json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }));
    let expired = forged(&|c| {
        let past = chrono::Utc::now().timestamp() - 600;
        c["iat"] = json!(past - 60);
        c["exp"] = json!(past);
    });
    // Signed by another installation's issuer.
    let foreign = installation_of_another_org(&token).await;

    let other_org = stored_connector(
        &installation,
        OrgId::generate(),
        ProvisioningDirection::Inbound,
        None,
    )
    .await;
    let outbound = stored_connector(
        &installation,
        installation.org,
        ProvisioningDirection::Outbound,
        None,
    )
    .await;
    let lapsed = stored_connector(
        &installation,
        installation.org,
        ProvisioningDirection::Inbound,
        Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
    )
    .await;
    let administrator = common::issue_admin_token(
        &common::test_jwt_service(),
        sid_core::models::ProfileId::generate(),
    );

    for (case, credential) in [
        ("no credential", None),
        ("administrator browser bearer", Some(administrator.as_str())),
        (
            "connector of another organization",
            Some(other_org.as_str()),
        ),
        ("outbound connector", Some(outbound.as_str())),
        ("expired credential", Some(lapsed.as_str())),
        ("client secret as bearer", Some(secret.as_str())),
        ("token for another resource", Some(other_resource.as_str())),
        (
            "token naming another connector",
            Some(other_subject.as_str()),
        ),
        ("sender-constrained token", Some(proof_bound.as_str())),
        ("expired token", Some(expired.as_str())),
        ("token of another issuer", Some(foreign.as_str())),
    ] {
        let user_name = unique_name();
        let (status, body) = replica
            .send(
                Method::POST,
                "/Users",
                credential,
                Some(new_user(&user_name)),
            )
            .await;
        assert_eq!(status, 401, "{case}: {body}");
        assert_eq!(replica.users_named(&bearer, &user_name).await, 0, "{case}");
    }

    // A connector without a grant, and a token narrowed to reading.
    let ungranted = replica.connector().await;
    let ungranted_bearer = replica
        .issue(&ungranted, pb::ConnectorCredentialKind::ScimBearer)
        .await;
    let response = replica
        .token_response(
            &installation.issuer,
            &connector.client_id,
            &secret,
            &[("scope", "scim.user.read")],
        )
        .await;
    assert_eq!(response.status(), 200);
    let reader: Value = response.json().await.unwrap();
    let reader = reader["access_token"].as_str().unwrap().to_owned();
    for (case, credential) in [
        ("connector without a grant", ungranted_bearer.as_str()),
        ("token without the scope", reader.as_str()),
    ] {
        let user_name = unique_name();
        let (status, body) = replica
            .send(
                Method::POST,
                "/Users",
                Some(credential),
                Some(new_user(&user_name)),
            )
            .await;
        assert_eq!(status, 403, "{case}: {body}");
        assert_eq!(replica.users_named(&bearer, &user_name).await, 0, "{case}");
    }

    // The token endpoint: no other resource, no other issuer, no delegation.
    let response = replica
        .token_response(
            &installation.issuer,
            &connector.client_id,
            &secret,
            &[("resource", "https://resources.sid.example.com/orders")],
        )
        .await;
    assert_eq!(response.status(), 400, "another resource");
    let elsewhere = OidcIssuer {
        handle: sid_core::models::IssuerHandle::generate(),
        ..installation.issuer.clone()
    };
    let response = replica
        .token_response(&elsewhere, &connector.client_id, &secret, &[])
        .await;
    assert!(response.status().is_client_error(), "unknown issuer");
    let response = replica
        .token_response(
            &installation.issuer,
            &connector.client_id,
            &secret,
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", token.as_str()),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
            ],
        )
        .await;
    assert!(
        response.status().is_client_error(),
        "a connector exchanges no token: {}",
        response.text().await.unwrap()
    );

    // The connector's credentials are no administration credentials: it
    // grants itself nothing.
    for credential in [bearer.as_str(), token.as_str()] {
        let mut request = Request::new(AssignRoleRequest {
            principal: Some(Principal::ProvisioningConnectorId(
                connector.proto.id.clone().unwrap(),
            )),
            role_id: Uuid::now_v7().to_string(),
            scope: None,
            expires_at: None,
            admin: None,
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {credential}").parse().unwrap(),
        );
        let err = replica.authz.assign_role(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
    }

    // A SCIM group named like a role grants that role to nobody.
    let user_name = unique_name();
    let (status, user) = replica
        .send(
            Method::POST,
            "/Users",
            Some(&bearer),
            Some(new_user(&user_name)),
        )
        .await;
    assert_eq!(status, 201, "{user}");
    let id = user["id"].as_str().unwrap().to_owned();
    let (status, group) = replica
        .send(
            Method::POST,
            "/Groups",
            Some(&bearer),
            Some(json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "admin",
                "members": [{ "value": id }],
            })),
        )
        .await;
    assert_eq!(status, 201, "{group}");
    let profile = sid_core::models::ProfileId::parse(&id).unwrap();
    let assignments = installation
        .storage
        .list_role_assignments_for_profile(profile)
        .await
        .unwrap();
    assert!(assignments.is_empty(), "{assignments:?}");
    assert!(
        !installation
            .storage
            .get_profile(profile)
            .await
            .unwrap()
            .unwrap()
            .roles
            .iter()
            .any(|r| r == "admin")
    );

    // Disabling stops the bearer and the token already issued, at once.
    replica
        .set_state(&connector, pb::ProvisioningConnectorState::Disabled)
        .await;
    for (case, credential) in [("bearer", &bearer), ("issued token", &token)] {
        let user_name = unique_name();
        let (status, body) = replica
            .send(
                Method::POST,
                "/Users",
                Some(credential),
                Some(new_user(&user_name)),
            )
            .await;
        assert_eq!(status, 401, "disabled, {case}: {body}");
    }
    let response = replica
        .token_response(&installation.issuer, &connector.client_id, &secret, &[])
        .await;
    assert_eq!(response.status(), 401, "a disabled connector gets no token");
}

/// What the issuer's introspection endpoint (RFC 7662) answers about `token`
/// to an inspector holding the inspection permission on the directory.
async fn introspected(replica: &Replica, issuer: &OidcIssuer, token: &str) -> bool {
    let response = http()
        .post(format!(
            "{}/i/{}/oauth2/introspect",
            replica.base, issuer.handle
        ))
        .basic_auth(
            common::CONFIDENTIAL_CLIENT,
            Some(common::CONFIDENTIAL_SECRET),
        )
        .form(&[("token", token)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "introspection endpoint");
    let body: Value = response.json().await.unwrap();
    body["active"].as_bool().expect("active member")
}

/// A connector's access token is active only while the connector and the
/// client credential it was issued for can act: disabling the connector or
/// revoking the credential turns a still validly signed token inactive, and
/// enabling the connector again restores it.
async fn introspection_reflects_the_connectors_state(engine: Engine) {
    let installation = installation(engine).await;
    let replica = installation.replica().await;
    let connector = replica.connector().await;
    replica.grant(&installation, &connector).await;
    let secret = replica
        .issue(&connector, pb::ConnectorCredentialKind::ClientSecret)
        .await;
    let token = replica
        .token(&installation.issuer, &connector.client_id, &secret)
        .await;

    // An independent inspector, granted inspection on the directory.
    let audit = || AuditEntry::system("test", "inspector").into();
    let client = sid_core::models::OAuth2Client {
        org_id: Some(installation.org),
        ..common::confidential_client()
    };
    common::store_client(installation.storage.as_ref(), &client)
        .await
        .unwrap();
    let inspector = sid_authz::builtin::ensure_token_inspector_role(installation.storage.as_ref())
        .await
        .unwrap();
    installation
        .storage
        .create_role_assignment(
            &sid_core::models::RoleAssignment::new(
                sid_core::models::RoleAssignmentPrincipal::OAuthClient(
                    common::CONFIDENTIAL_CLIENT.into(),
                ),
                inspector.id,
            )
            .on_resource(installation.directory.id),
            audit(),
        )
        .await
        .unwrap();

    let issuer = &installation.issuer;
    assert!(introspected(&replica, issuer, &token).await, "fresh token");
    replica
        .set_state(&connector, pb::ProvisioningConnectorState::Disabled)
        .await;
    assert!(
        !introspected(&replica, issuer, &token).await,
        "disabled connector"
    );
    replica
        .set_state(&connector, pb::ProvisioningConnectorState::Active)
        .await;
    assert!(
        introspected(&replica, issuer, &token).await,
        "enabled again"
    );

    let credential = claims_of(&token)["sid"].as_str().unwrap().to_owned();
    replica
        .provisioning
        .revoke_connector_credential(admin(pb::RevokeConnectorCredentialRequest {
            connector_id: connector.proto.id.clone(),
            credential_id: Some(
                sid_core::models::ProvisioningCredentialId::parse(&credential)
                    .unwrap()
                    .into(),
            ),
        }))
        .await
        .unwrap();
    assert!(
        !introspected(&replica, issuer, &token).await,
        "revoked credential"
    );
}

#[tokio::test]
async fn introspection_reflects_the_connectors_state_on_postgres() {
    introspection_reflects_the_connectors_state(Engine::Postgres).await;
}

#[tokio::test]
async fn introspection_reflects_the_connectors_state_on_sqlite() {
    introspection_reflects_the_connectors_state(Engine::Sqlite).await;
}

/// A token of the same shape signed by another installation's issuer.
async fn installation_of_another_org(token: &str) -> String {
    let other = installation(Engine::Sqlite).await;
    let registry = IssuerRegistry::new(other.storage.clone(), common::test_key_manager());
    let signer = registry.signer(&other.issuer).await.unwrap();
    let mut claims = claims_of(token);
    claims["iss"] = json!(other.issuer.canonical_url);
    signer.sign(Some("at+jwt"), &claims).unwrap()
}

#[tokio::test]
async fn refuses_before_effects_on_postgres() {
    refuses_before_effects(Engine::Postgres).await;
}

#[tokio::test]
async fn refuses_before_effects_on_sqlite() {
    refuses_before_effects(Engine::Sqlite).await;
}

/// Two replicas over one database: a write on one is read on the other, a
/// disable on one stops the connector on the other at once, and the same
/// user created on both at the same moment exists once.
#[tokio::test]
async fn replicas_share_the_directory_and_the_connector_state() {
    use reqwest::Method;

    let installation = installation(Engine::Postgres).await;
    let a = installation.replica().await;
    let b = installation.replica().await;
    let connector = a.connector().await;
    a.grant(&installation, &connector).await;
    let bearer = a
        .issue(&connector, pb::ConnectorCredentialKind::ScimBearer)
        .await;
    let secret = a
        .issue(&connector, pb::ConnectorCredentialKind::ClientSecret)
        .await;
    // A token issued by one replica is accepted by the other.
    let token = a
        .token(&installation.issuer, &connector.client_id, &secret)
        .await;

    let user_name = unique_name();
    let (status, user) = a
        .send(
            Method::POST,
            "/Users",
            Some(&bearer),
            Some(new_user(&user_name)),
        )
        .await;
    assert_eq!(status, 201, "{user}");
    let id = user["id"].as_str().unwrap().to_owned();
    let (status, read) = b
        .send(Method::GET, &format!("/Users/{id}"), Some(&token), None)
        .await;
    assert_eq!(status, 200, "{read}");

    // The same user from both replicas at once: one is created, the other
    // conflicts, none is duplicated.
    let user_name = unique_name();
    let (first, second) = tokio::join!(
        a.send(
            Method::POST,
            "/Users",
            Some(&bearer),
            Some(new_user(&user_name))
        ),
        b.send(
            Method::POST,
            "/Users",
            Some(&token),
            Some(new_user(&user_name))
        ),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409], "{first:?} {second:?}");
    assert_eq!(a.users_named(&bearer, &user_name).await, 1);

    a.set_state(&connector, pb::ProvisioningConnectorState::Disabled)
        .await;
    for credential in [&bearer, &token] {
        let (status, body) = b
            .send(Method::GET, &format!("/Users/{id}"), Some(credential), None)
            .await;
        assert_eq!(status, 401, "disabled on the other replica: {body}");
    }
    b.set_state(&connector, pb::ProvisioningConnectorState::Active)
        .await;
    let (status, _) = a
        .send(Method::GET, &format!("/Users/{id}"), Some(&bearer), None)
        .await;
    assert_eq!(status, 200, "enabled on the other replica");
}

/// An authorization engine that cannot decide.
struct Unreachable;

#[async_trait::async_trait]
impl AuthzEngine for Unreachable {
    async fn check(&self, _: &AuthzCheckRequest) -> Result<AuthzCheckResponse, AuthzError> {
        Err(AuthzError::Storage(
            "authorization store unreachable".into(),
        ))
    }

    async fn list_accessible_objects(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Vec<String>, AuthzError> {
        Err(AuthzError::Storage(
            "authorization store unreachable".into(),
        ))
    }

    async fn list_subjects_with_access(&self, _: &str, _: &str) -> Result<Vec<String>, AuthzError> {
        Err(AuthzError::Storage(
            "authorization store unreachable".into(),
        ))
    }
}

/// While the authorization decision is unavailable, a granted connector is
/// refused as unavailable and writes nothing; it never falls back to allow.
#[tokio::test]
async fn an_authorization_outage_refuses_writes() {
    use reqwest::Method;

    let installation = installation(Engine::Postgres).await;
    let healthy = installation.replica().await;
    let outage = installation.replica_with(Arc::new(Unreachable)).await;
    let connector = healthy.connector().await;
    healthy.grant(&installation, &connector).await;
    let bearer = healthy
        .issue(&connector, pb::ConnectorCredentialKind::ScimBearer)
        .await;

    let user_name = unique_name();
    let (status, body) = outage
        .send(
            Method::POST,
            "/Users",
            Some(&bearer),
            Some(new_user(&user_name)),
        )
        .await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(healthy.users_named(&bearer, &user_name).await, 0);
}
