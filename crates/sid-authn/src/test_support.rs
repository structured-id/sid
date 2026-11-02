// SPDX-License-Identifier: AGPL-3.0-only
//! Fixtures shared by this crate's unit tests.

use std::sync::Arc;

use secrecy::SecretBox;
use sid_crypto::RustCryptoPrimitives;
use sid_keys::{KeyManager, KeyVersionParams, SoftwareKeyManager};

/// A key manager over a fixed test master secret.
pub(crate) fn key_manager() -> Arc<dyn KeyManager> {
    key_manager_over([3u8; 32])
}

/// A key manager over another master secret: what an installation restored
/// without its master key has.
pub(crate) fn foreign_key_manager() -> Arc<dyn KeyManager> {
    key_manager_over([4u8; 32])
}

/// An installation over in-memory SQLite with its organization's issuer,
/// and the registry that signs as it.
pub(crate) async fn installation_issuer()
-> (crate::issuer::IssuerRegistry, sid_core::models::OidcIssuer) {
    let storage = sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite");
    let org = crate::instance_org::ensure(&storage, "sid.example.com")
        .await
        .expect("installation organization")
        .id;
    let keys = key_manager();
    let base = url::Url::parse("https://sid.example.com").expect("base URL");
    let issuer = crate::issuer::ensure_local_issuer(&storage, keys.as_ref(), &base, org)
        .await
        .expect("installation issuer");
    (
        crate::issuer::IssuerRegistry::new(Arc::new(storage), keys),
        issuer,
    )
}

/// A confidential web client as the client role of `app`, in organization
/// `org`.
pub(crate) fn client_of(
    app: &sid_core::models::Application,
    org: sid_core::models::OrgId,
) -> sid_core::models::OAuth2Client {
    use sid_core::models::*;
    OAuth2Client {
        client_id: format!("client-{}", app.id),
        project_id: app.project_id,
        application_id: app.id,
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/cb".into()],
        allowed_scopes: vec!["openid".into(), "read".into(), "write".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: app.name.clone(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: app.created_at,
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: Some(org),
        revision: 0,
        created_at: app.created_at,
    }
}

/// A ceremony state store that cannot answer anything: what an unreachable
/// database is to its callers.
pub(crate) struct DownCeremonies;

fn down<T>() -> sid_core::Result<T> {
    Err(sid_core::Error::Storage("down".into()))
}

#[async_trait::async_trait]
impl sid_plugin::SingleUseAdmissions for DownCeremonies {
    async fn admit_once(&self, _: &str, _: &str, _: std::time::Duration) -> sid_core::Result<bool> {
        down()
    }
    async fn admit_for(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: std::time::Duration,
    ) -> sid_core::Result<bool> {
        down()
    }
}

#[async_trait::async_trait]
impl sid_plugin::CeremonyStateStore for DownCeremonies {
    async fn put_ceremony_state(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: std::time::Duration,
    ) -> sid_core::Result<()> {
        down()
    }
    async fn take_ceremony_state(&self, _: &str, _: &str) -> sid_core::Result<Option<Vec<u8>>> {
        down()
    }
    async fn read_ceremony_state(&self, _: &str, _: &str) -> sid_core::Result<Option<Vec<u8>>> {
        down()
    }
    async fn replace_ceremony_state(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: &[u8],
        _: std::time::Duration,
    ) -> sid_core::Result<bool> {
        down()
    }
    async fn count_in_window(
        &self,
        _: &str,
        _: &str,
        _: std::time::Duration,
    ) -> sid_core::Result<u64> {
        down()
    }
    async fn read_count(&self, _: &str, _: &str) -> sid_core::Result<u64> {
        down()
    }
    async fn clear_count(&self, _: &str, _: &str) -> sid_core::Result<()> {
        down()
    }
    async fn purge_expired_ceremony_state(&self) -> sid_core::Result<u64> {
        down()
    }
}

fn key_manager_over(master: [u8; 32]) -> Arc<dyn KeyManager> {
    Arc::new(
        SoftwareKeyManager::new(
            SecretBox::new(Box::new(master)),
            vec![KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
            Arc::new(RustCryptoPrimitives::new()),
        )
        .expect("test key manager"),
    )
}
