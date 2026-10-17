// SPDX-License-Identifier: AGPL-3.0-only
//! Fixtures shared by this crate's unit tests.

use std::sync::Arc;

use secrecy::SecretBox;
use sid_keys::{KeyManager, KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};

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

/// A recipient that is not an organization: what a host serving its own
/// account authority names its issuer's recipient as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnAuthority;

type OwnIssuer = sid_core::models::OidcIssuer<OwnAuthority>;

/// The issuer store of such a host, in memory: one issuer per authority and
/// recipient, first insert kept.
#[derive(Default)]
pub(crate) struct OwnIssuers {
    rows: std::sync::Mutex<Vec<(OwnIssuer, Vec<sid_core::models::IssuerSigningKey>)>>,
}

#[async_trait::async_trait]
impl sid_plugin::IssuerStore<OwnAuthority> for OwnIssuers {
    async fn oidc_issuer_for(
        &self,
        authority: sid_core::models::IssuerAuthority,
        recipient: &OwnAuthority,
    ) -> sid_core::Result<Option<OwnIssuer>> {
        let rows = self.rows.lock().expect("issuer rows");
        Ok(rows
            .iter()
            .find(|(i, _)| i.authority == authority && &i.recipient == recipient)
            .map(|(i, _)| i.clone()))
    }

    async fn oidc_issuer_by_handle(
        &self,
        handle: &sid_core::models::IssuerHandle,
    ) -> sid_core::Result<Option<OwnIssuer>> {
        let rows = self.rows.lock().expect("issuer rows");
        Ok(rows
            .iter()
            .find(|(i, _)| &i.handle == handle)
            .map(|(i, _)| i.clone()))
    }

    async fn insert_oidc_issuer(
        &self,
        issuer: &OwnIssuer,
        first_key: &sid_core::models::IssuerSigningKey,
        _ctx: sid_core::models::MutationContext,
    ) -> sid_core::Result<bool> {
        issuer.check_first_key(first_key)?;
        let mut rows = self.rows.lock().expect("issuer rows");
        if rows
            .iter()
            .any(|(i, _)| i.authority == issuer.authority && i.recipient == issuer.recipient)
        {
            return Ok(false);
        }
        rows.push((issuer.clone(), vec![first_key.clone()]));
        Ok(true)
    }

    async fn oidc_issuer_signing_keys(
        &self,
        issuer: sid_core::models::IssuerId,
    ) -> sid_core::Result<Vec<sid_core::models::IssuerSigningKey>> {
        let rows = self.rows.lock().expect("issuer rows");
        Ok(rows
            .iter()
            .find(|(i, _)| i.id == issuer)
            .map(|(_, keys)| keys.clone())
            .unwrap_or_default())
    }
}

/// A host's own issuer, served to [`OwnAuthority`] with no organization, and
/// the registry that signs as it.
pub(crate) async fn own_issuer() -> (crate::issuer::IssuerRegistry<OwnAuthority>, OwnIssuer) {
    let store = Arc::new(OwnIssuers::default());
    let keys = key_manager();
    let base = url::Url::parse("https://sid.example.com").expect("base URL");
    let issuer =
        crate::issuer::ensure_local_issuer(store.as_ref(), keys.as_ref(), &base, OwnAuthority)
            .await
            .expect("own issuer");
    (crate::issuer::IssuerRegistry::new(store, keys), issuer)
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
