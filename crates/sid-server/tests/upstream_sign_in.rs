// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in through an upstream OIDC provider completes with a real session,
//! on PostgreSQL (54399, `DATABASE_URL`), against a provider served in this
//! process. The sign-in page gets the IdP session cookie and no token, a
//! native client a token of the signed-in Profile; a browser off the
//! sign-in page signs nobody in. The sign-in completes as every sign-in of
//! the authority does: only an active Profile, under its security policy.

mod common;
#[path = "../../../tests/support/oidc_provider.rs"]
mod oidc_provider;

use std::sync::Arc;

use oidc_provider::{CLIENT, Provider};
use serde_json::json;
use sid_core::models::{AuditEntry, SecurityPolicy, UpstreamProtocol, UpstreamProvider};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::upstream_service_server::UpstreamService;
use sid_proto::sid::v1::{
    HandleUpstreamCallbackRequest, InitiateUpstreamAuthRequest, handle_upstream_callback_response,
};
use sid_server::grpc::upstream_service::UpstreamServiceImpl;
use tonic::Request;

const REDIRECT: &str = "https://sid.example.com/account/login/upstream";

async fn storage() -> Arc<dyn StorageBackend> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    Arc::new(backend)
}

struct Setup {
    storage: Arc<dyn StorageBackend>,
    provider: Provider,
    provider_id: String,
    service: UpstreamServiceImpl,
}

/// A provider registered at the installation, and its upstream service
/// completing sign-ins under the CE security policy.
async fn setup() -> Setup {
    setup_under(None).await
}

/// The same, under `policy`.
async fn setup_under(policy: Option<SecurityPolicy>) -> Setup {
    common::crypto::install_tls();
    let storage = storage().await;
    let provider = Provider::start(None).await;
    let keys = common::test_key_manager();
    let id = sid_core::models::UpstreamProviderId::new();
    let secret = keys
        .encrypt(b"provider-secret", &format!("upstream:{}", id.0))
        .await
        .unwrap();
    let mut registered = UpstreamProvider::new(
        format!("Test IdP {}", id.0),
        UpstreamProtocol::Oidc,
        CLIENT,
        secret,
    );
    registered.id = id;
    registered.discovery_url = Some(provider.discovery_url());
    storage
        .create_upstream_provider(
            &registered,
            AuditEntry::system("upstream_provider.create", id.0.to_string()).into(),
        )
        .await
        .unwrap();
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let auth = common::auth_service_over(storage.clone(), cache.clone(), policy);
    let service = UpstreamServiceImpl::new(
        storage.clone(),
        keys,
        cache,
        common::test_jwt(),
        common::test_revocation(),
        auth,
    );
    Setup {
        storage,
        provider,
        provider_id: id.0.to_string(),
        service,
    }
}

impl Setup {
    /// Start a sign-in and have the provider answer it for `sub`; returns
    /// the callback's state.
    async fn started(&self, sub: &str) -> String {
        let started = self
            .service
            .initiate_upstream_auth(Request::new(InitiateUpstreamAuthRequest {
                provider_id: self.provider_id.clone(),
                redirect_uri: REDIRECT.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let nonce = reqwest::Url::parse(&started.authorization_url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "nonce")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        self.provider.answer(
            json!({ "access_token": "at", "id_token": self.provider.id_token(&nonce, sub) }),
            json!({ "sub": sub }),
        );
        started.state_token
    }

    fn callback(
        &self,
        state: String,
        origin: Option<&str>,
    ) -> Request<HandleUpstreamCallbackRequest> {
        let mut request = Request::new(HandleUpstreamCallbackRequest {
            provider_id: self.provider_id.clone(),
            code: "the-code".into(),
            state,
            redirect_uri: REDIRECT.into(),
        });
        if let Some(origin) = origin {
            request
                .metadata_mut()
                .insert("origin", origin.parse().unwrap());
        }
        request
    }

    /// Sign `sub` in from a native client; returns the Profile it names.
    async fn signed_in_profile(&self, sub: &str) -> sid_core::models::Profile {
        let state = self.started(sub).await;
        let native = self
            .service
            .handle_upstream_callback(self.callback(state, None))
            .await
            .unwrap();
        let bearer = native
            .metadata()
            .get("authorization")
            .expect("the native client gets its token")
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .to_owned();
        let sid_authn::jwt::VerifiedAccess::Session(claims) =
            common::test_jwt().verifier().verify(&bearer).await.unwrap()
        else {
            panic!("a sign-in session's token");
        };
        let id =
            sid_core::models::ProfileId::from_uuid(uuid::Uuid::parse_str(&claims.sub).unwrap())
                .unwrap();
        self.storage.get_profile(id).await.unwrap().unwrap()
    }
}

// A first sign-in provisions the Profile and gives the sign-in page the
// IdP session cookie, never a token; the next sign-in of the same upstream
// subject from a native client gets a token naming that same Profile. Both
// sessions are stored for it.
#[tokio::test]
async fn an_upstream_sign_in_creates_a_session() {
    let s = setup().await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());

    let state = s.started(&sub).await;
    let browser = s
        .service
        .handle_upstream_callback(s.callback(state, Some(common::SIGN_IN_ORIGIN)))
        .await
        .unwrap();
    let cookie = browser
        .metadata()
        .get("set-cookie")
        .expect("the sign-in page gets its cookie")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("__Host-sid_session="), "{cookie}");
    assert!(browser.metadata().get("authorization").is_none());
    let Some(handle_upstream_callback_response::Result::Success(first)) =
        browser.into_inner().result
    else {
        panic!("signed in");
    };
    assert!(first.new_profile_created);
    assert!(first.expires_in > 0);

    let state = s.started(&sub).await;
    let native = s
        .service
        .handle_upstream_callback(s.callback(state, None))
        .await
        .unwrap();
    assert!(native.metadata().get("set-cookie").is_none());
    let bearer = native
        .metadata()
        .get("authorization")
        .expect("the native client gets its token")
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let Some(handle_upstream_callback_response::Result::Success(second)) =
        native.into_inner().result
    else {
        panic!("signed in");
    };
    assert!(!second.new_profile_created, "the returning user");

    let sid_authn::jwt::VerifiedAccess::Session(claims) =
        common::test_jwt().verifier().verify(&bearer).await.unwrap()
    else {
        panic!("a sign-in session's token");
    };
    let profile =
        sid_core::models::ProfileId::from_uuid(uuid::Uuid::parse_str(&claims.sub).unwrap())
            .unwrap();
    let sessions = s.storage.list_sessions(&profile).await.unwrap();
    let ids: Vec<String> = sessions.iter().map(|x| x.id.to_string()).collect();
    assert!(ids.contains(&first.session_id), "{ids:?}");
    assert!(ids.contains(&second.session_id), "{ids:?}");
}

// A browser request from another origin than the sign-in page is refused
// before the code is exchanged: no session, and the pending sign-in stays
// for its own page.
#[tokio::test]
async fn a_foreign_origin_signs_nobody_in() {
    let s = setup().await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());
    let state = s.started(&sub).await;
    let refused = s
        .service
        .handle_upstream_callback(s.callback(state.clone(), Some("https://attacker.example.com")))
        .await
        .unwrap_err();
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("SIGN_IN_REFUSED")
    );
    assert!(s.provider.token_requests().is_empty(), "no code exchanged");
    s.service
        .handle_upstream_callback(s.callback(state, Some(common::SIGN_IN_ORIGIN)))
        .await
        .expect("the sign-in page still completes it");
}

// Regression: a suspended Profile does not regain access through its
// upstream link; the sign-in is refused and no session is created.
#[tokio::test]
async fn a_suspended_profile_is_not_signed_in() {
    let s = setup().await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());
    let mut profile = s.signed_in_profile(&sub).await;
    profile.status = sid_core::models::ProfileStatus::Suspended;
    assert!(
        s.storage
            .update_profile(
                &profile,
                AuditEntry::system("profile.suspend", profile.id.to_string()).into(),
            )
            .await
            .unwrap()
    );
    let before = s.storage.list_sessions(&profile.id).await.unwrap().len();

    let state = s.started(&sub).await;
    let refused = s
        .service
        .handle_upstream_callback(s.callback(state, None))
        .await
        .unwrap_err();
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert_eq!(
        s.storage.list_sessions(&profile.id).await.unwrap().len(),
        before,
        "no session"
    );
}

// Regression: the sign-in security rules apply to an upstream sign-in. A
// policy requiring more than basic assurance refuses it: SID verified no
// method of its own.
#[tokio::test]
async fn the_security_policy_applies_to_an_upstream_sign_in() {
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = sid_core::models::session::AuthLevel::Standard;
    let s = setup_under(Some(policy)).await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());
    let state = s.started(&sub).await;
    let refused = s
        .service
        .handle_upstream_callback(s.callback(state, None))
        .await
        .unwrap_err();
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("STEP_UP_REQUIRED")
    );
}
