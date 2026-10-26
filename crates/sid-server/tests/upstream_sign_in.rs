// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in through an upstream OIDC provider completes with a real session,
//! on PostgreSQL (54399, `DATABASE_URL`), against a provider served in this
//! process. The sign-in page gets the IdP session cookie and no token, a
//! native client a token of the signed-in Profile; a browser off the
//! sign-in page signs nobody in.

mod common;
#[path = "../../../tests/support/oidc_provider.rs"]
mod oidc_provider;

use std::sync::Arc;

use oidc_provider::{CLIENT, Provider};
use serde_json::json;
use sid_core::models::EnrollmentMode;
use sid_core::models::{AuditEntry, UpstreamProtocol, UpstreamProvider};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::upstream_service_server::UpstreamService;
use sid_proto::sid::v1::{
    HandleUpstreamCallbackRequest, InitiateUpstreamAuthRequest, handle_upstream_callback_response,
};
use sid_server::grpc::upstream_service::UpstreamServiceImpl;
use tonic::Request;

const SIGN_IN_PAGE: &str = "https://sid.example.com/account/login";
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

/// The upstream service over `storage` admitting new accounts under the
/// enrollment mode `pin`.
fn service(
    storage: Arc<dyn StorageBackend>,
    pin: sid_core::models::EnrollmentMode,
) -> UpstreamServiceImpl {
    UpstreamServiceImpl::new(
        storage,
        common::test_key_manager(),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        common::test_jwt(),
        common::test_revocation(),
        "https://sid.example.com".to_string(),
        sid_server::feature_flags::FeatureFlagService::disabled(),
    )
    .with_sign_in_page(&url::Url::parse(SIGN_IN_PAGE).unwrap())
    .with_enrollment_pin(Some(pin))
}

/// A provider registered on PostgreSQL, and its upstream service admitting
/// new accounts under `pin`.
async fn setup(pin: sid_core::models::EnrollmentMode) -> Setup {
    setup_on(storage().await, pin).await
}

async fn setup_on(
    storage: Arc<dyn StorageBackend>,
    pin: sid_core::models::EnrollmentMode,
) -> Setup {
    common::crypto::install_tls();
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
    Setup {
        service: service(storage.clone(), pin),
        storage,
        provider,
        provider_id: id.0.to_string(),
    }
}

impl Setup {
    /// The same installation, admitting new accounts under `pin` now.
    fn reopened(mut self, pin: sid_core::models::EnrollmentMode) -> Self {
        self.service = service(self.storage.clone(), pin);
        self
    }

    /// Start a sign-in and have the provider answer it for `sub`; returns
    /// the callback's state.
    async fn started(&self, sub: &str) -> String {
        self.started_as(sub, json!({ "sub": sub })).await
    }

    /// Start a sign-in and have the provider answer it for `sub`, its
    /// UserInfo answering `userinfo`; returns the callback's state.
    async fn started_as(&self, sub: &str, userinfo: serde_json::Value) -> String {
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
            userinfo,
        );
        started.state_token
    }

    async fn linked(&self, sub: &str) -> bool {
        let provider =
            sid_core::models::UpstreamProviderId(uuid::Uuid::parse_str(&self.provider_id).unwrap());
        self.storage
            .get_upstream_identity_by_provider_subject(provider, sub)
            .await
            .unwrap()
            .is_some()
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
}

// A first sign-in provisions the Profile and gives the sign-in page the
// IdP session cookie, never a token; the next sign-in of the same upstream
// subject from a native client gets a token naming that same Profile. Both
// sessions are stored for it.
#[tokio::test]
async fn an_upstream_sign_in_creates_a_session() {
    let s = setup(EnrollmentMode::Open).await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());

    let state = s.started(&sub).await;
    let browser = s
        .service
        .handle_upstream_callback(s.callback(state, Some("https://sid.example.com")))
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
    let s = setup(EnrollmentMode::Open).await;
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
        .handle_upstream_callback(s.callback(state, Some("https://sid.example.com")))
        .await
        .expect("the sign-in page still completes it");
}

// Regression (#242): an installation that admits no self-registration
// creates no account for an unknown upstream subject. Invite-only and
// admin-only refuse with REGISTRATION_RESTRICTED naming what is required,
// and no Profile or link is created.
#[tokio::test]
async fn a_closed_installation_provisions_nobody() {
    use tonic_types::StatusExt as _;
    for (mode, requirement) in [
        (EnrollmentMode::InviteOnly, "invite"),
        (EnrollmentMode::AdminOnly, "admin_only"),
    ] {
        let s = setup(mode).await;
        let sub = format!("user-{}", uuid::Uuid::now_v7());
        let state = s.started(&sub).await;
        let refused = s
            .service
            .handle_upstream_callback(s.callback(state, Some("https://sid.example.com")))
            .await
            .unwrap_err();
        let info = refused.get_details_error_info().expect("ErrorInfo");
        assert_eq!(info.reason, "REGISTRATION_RESTRICTED", "{mode:?}");
        assert_eq!(info.metadata["requirement"], requirement, "{mode:?}");
        assert!(!s.linked(&sub).await, "{mode:?}: nothing linked");
    }
}

// An upstream subject already linked to a Profile still signs in when the
// installation stops admitting new accounts.
#[tokio::test]
async fn a_linked_subject_signs_in_on_a_closed_installation() {
    let s = setup(EnrollmentMode::Open).await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());
    let state = s.started(&sub).await;
    s.service
        .handle_upstream_callback(s.callback(state, None))
        .await
        .unwrap();
    let s = s.reopened(EnrollmentMode::InviteOnly);
    let state = s.started(&sub).await;
    let signed_in = s
        .service
        .handle_upstream_callback(s.callback(state, None))
        .await
        .expect("the linked subject signs in");
    assert!(signed_in.metadata().get("authorization").is_some());
}

// Regression (#242): a failed lookup of the verified email fails the
// sign-in instead of provisioning a second account.
#[tokio::test]
async fn a_failed_email_lookup_provisions_nobody() {
    let mock = Arc::new(common::mock_storage::MockStorage::new());
    let s = setup_on(mock.clone(), EnrollmentMode::Open).await;
    let sub = format!("user-{}", uuid::Uuid::now_v7());
    let state = s
        .started_as(
            &sub,
            json!({ "sub": sub, "email": "alice@sid.example.com", "email_verified": true }),
        )
        .await;
    let before = mock.profile_count();
    mock.fail_profile_reads();
    let refused = s
        .service
        .handle_upstream_callback(s.callback(state, None))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Internal, "{refused:?}");
    assert_eq!(mock.profile_count(), before, "no account provisioned");
}
