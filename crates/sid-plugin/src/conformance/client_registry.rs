// SPDX-License-Identifier: AGPL-3.0-only
//! [`ClientResourceRegistry`] scenarios: what issuance reads about clients,
//! protected resources and the access between them. Every scenario registers
//! records under fresh identifiers, so a harness may run them concurrently
//! against one shared store.

use async_trait::async_trait;
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    ApplicationId, ApplicationType, AuthLevel, ClientKeySet, EnforcementMode, IssuerId,
    LoginStrategy, OAuth2Client, OrgId, ProjectId, ProtectedResource, ResourceAccess, ResourceId,
    ResourceIndicator, ResourceState, SubjectType, TokenEndpointAuthMethod,
};
use uuid::Uuid;

use crate::ClientResourceRegistry;

/// What a backend's harness supplies to the scenarios. Registration is the
/// harness's own: the registry contract covers only what is read back.
#[async_trait]
pub trait RegistryHarness: Send + Sync {
    fn registry(&self) -> &dyn ClientResourceRegistry;

    /// An issuer resources may be registered under.
    async fn issuer(&self) -> IssuerId;

    /// Another issuer, distinct from [`Self::issuer`].
    async fn other_issuer(&self) -> IssuerId;

    /// An organization a client may belong to.
    async fn organization(&self) -> OrgId;

    /// Register `client`, without a default resource, with whatever the store
    /// keeps around it.
    async fn register_client(&self, client: &OAuth2Client);

    /// Register `resource`, active.
    async fn register_resource(&self, resource: &ProtectedResource);

    /// Give the access `access` names.
    async fn grant_access(&self, access: &ResourceAccess);

    /// Make `resource`, which `client` already has access to, its default.
    async fn set_default_resource(&self, client: &str, resource: ResourceId);

    /// Retire `resource`: it stays readable, retired, under its indicator.
    async fn retire_resource(&self, resource: ResourceId);
}

/// The public signing key of a `private_key_jwt` client: the Ed25519 key of
/// RFC 8037 Appendix A.2.
fn client_keys() -> ClientKeySet {
    ClientKeySet::from_json(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"conformance-1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#,
    )
    .expect("a valid key set")
}

/// A new confidential web client that can authenticate by its registered
/// method, its times at the millisecond precision every store keeps.
pub fn client() -> OAuth2Client {
    let now = Utc::now().trunc_subsecs(3);
    OAuth2Client {
        client_id: format!("conformance-{}", Uuid::now_v7().simple()),
        project_id: ProjectId::system(),
        application_id: ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: Some(client_keys()),
        redirect_uris: vec!["https://app.sid.example.com/callback".into()],
        allowed_scopes: vec!["orders.read".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: "Conformance client".into(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Pairwise,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: now,
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
        org_id: None,
        revision: 0,
        created_at: now,
    }
}

/// A new active resource of `issuer` under a fresh indicator.
pub fn resource(issuer: IssuerId) -> ProtectedResource {
    let now = Utc::now().trunc_subsecs(3);
    ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(ApplicationId::generate()),
        issuer_id: issuer,
        indicator: ResourceIndicator::parse(&format!(
            "https://resources.sid.example.com/{}",
            Uuid::now_v7().simple()
        ))
        .expect("a valid indicator"),
        scopes: vec!["orders.read".into(), "orders.write".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

/// A registered client is read back by its id exactly as registered: the
/// fields issuance reads (tenancy, default resource, keys, policy overrides,
/// logout targets) hold non-default values, so a store that drops or rewrites
/// one fails here. An id never registered is no client.
///
/// The client stays a web client: a `private_key_jwt` client with keys is
/// confidential, and native and single-page clients are public, so another
/// type would be a registration a harness using the real registration path
/// refuses. Its default resource is set only after access to it is granted:
/// a default never grants access by itself.
pub async fn client_found_by_id<H: RegistryHarness>(h: &H) {
    let api = resource(h.issuer().await);
    h.register_resource(&api).await;
    let registered = OAuth2Client {
        org_id: Some(h.organization().await),
        sector_identifier_uri: Some("https://app.sid.example.com/sector.json".into()),
        required_acr: Some(AuthLevel::Standard),
        required_amr: vec!["hwk".into()],
        enforcement_mode: EnforcementMode::Hard,
        require_verified_email: Some(true),
        backchannel_logout_uri: Some("https://app.sid.example.com/logout".into()),
        backchannel_logout_session_required: true,
        post_logout_redirect_uris: vec!["https://app.sid.example.com/signed-out".into()],
        ..client()
    };
    h.register_client(&registered).await;
    h.grant_access(&ResourceAccess {
        client_id: registered.client_id.clone(),
        resource_id: api.id,
        scopes: vec!["orders.read".into()],
        created_at: Utc::now().trunc_subsecs(3),
    })
    .await;
    h.set_default_resource(&registered.client_id, api.id).await;
    let read = h
        .registry()
        .get_oauth2_client(&registered.client_id)
        .await
        .unwrap()
        .expect("the registered client");
    // Setting the default is a change of the client, so its revision moved.
    assert_ne!(read.revision, registered.revision);
    let expected = OAuth2Client {
        default_resource: Some(api.id),
        revision: read.revision,
        ..registered
    };
    // The model has no equality of its own; its serialized form names every
    // field.
    assert_eq!(
        serde_json::to_value(&read).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let unknown = client().client_id;
    assert!(
        h.registry()
            .get_oauth2_client(&unknown)
            .await
            .unwrap()
            .is_none()
    );
}

/// A resource is read back whole by its id and by its issuer and indicator;
/// the same indicator under another issuer, or an unknown one, names none.
pub async fn resource_found_by_id_and_indicator<H: RegistryHarness>(h: &H) {
    let issuer = h.issuer().await;
    let registered = resource(issuer);
    h.register_resource(&registered).await;
    let registry = h.registry();
    assert_eq!(
        registry
            .get_protected_resource(registered.id)
            .await
            .unwrap(),
        Some(registered.clone())
    );
    assert_eq!(
        registry
            .protected_resource_by_indicator(issuer, &registered.indicator)
            .await
            .unwrap(),
        Some(registered.clone())
    );
    let other = h.other_issuer().await;
    assert!(
        registry
            .protected_resource_by_indicator(other, &registered.indicator)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        registry
            .protected_resource_by_indicator(issuer, &resource(issuer).indicator)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        registry
            .get_protected_resource(ResourceId::generate())
            .await
            .unwrap()
            .is_none()
    );
}

/// A retired resource is still found, retired, by its id and its indicator:
/// issuance refuses it rather than mistaking it for an unknown one.
pub async fn retired_resource_still_found<H: RegistryHarness>(h: &H) {
    let issuer = h.issuer().await;
    let registered = resource(issuer);
    h.register_resource(&registered).await;
    h.retire_resource(registered.id).await;
    let registry = h.registry();
    let by_id = registry
        .get_protected_resource(registered.id)
        .await
        .unwrap()
        .expect("a retired resource is still found");
    assert_eq!(by_id.state, ResourceState::Retired);
    assert_eq!(by_id.indicator, registered.indicator);
    let by_indicator = registry
        .protected_resource_by_indicator(issuer, &registered.indicator)
        .await
        .unwrap()
        .expect("a retired indicator is still found");
    assert_eq!(by_indicator.id, registered.id);
    assert_eq!(by_indicator.state, ResourceState::Retired);
}

/// Access is exact to its client and resource: read back with its scopes,
/// and absent for another client or another resource.
pub async fn resource_access_exact<H: RegistryHarness>(h: &H) {
    let issuer = h.issuer().await;
    let (api, other_api) = (resource(issuer), resource(issuer));
    h.register_resource(&api).await;
    h.register_resource(&other_api).await;
    let (granted_client, bystander) = (client(), client());
    h.register_client(&granted_client).await;
    h.register_client(&bystander).await;
    let granted = ResourceAccess {
        client_id: granted_client.client_id.clone(),
        resource_id: api.id,
        scopes: vec!["orders.read".into()],
        created_at: Utc::now().trunc_subsecs(3),
    };
    h.grant_access(&granted).await;
    let registry = h.registry();
    assert_eq!(
        registry
            .resource_access(&granted_client.client_id, api.id)
            .await
            .unwrap(),
        Some(granted)
    );
    assert!(
        registry
            .resource_access(&bystander.client_id, api.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        registry
            .resource_access(&granted_client.client_id, other_api.id)
            .await
            .unwrap()
            .is_none()
    );
}
