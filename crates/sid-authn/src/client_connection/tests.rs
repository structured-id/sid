use super::*;
use crate::system_integration::{AccountSettings, ensure_account_integration};
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    AuditEntry, ClientKeySet, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey,
    MutationContext, Organization, ResourceId, ResourceState,
};
use sid_plugin::storage::StorageBackend;
use sid_storage::sqlite::SqliteBackend;

const INSTALLATION: &str = "https://sid.example.com";

fn ctx() -> MutationContext {
    AuditEntry::system("test", "connection").into()
}

/// A registered web client with its issuer, resource and access, as the
/// account integration stores them.
struct Registration {
    issuer: OidcIssuer,
    client: OAuth2Client,
    resource: ProtectedResource,
    access: ResourceAccess,
}

impl Registration {
    fn connection(&self) -> SidResult<ClientConnection> {
        ClientConnection::of(&self.issuer, &self.client, &self.resource, &self.access)
    }
}

async fn registration() -> Registration {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let now = Utc::now().trunc_subsecs(3);
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("{INSTALLATION}/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org.id,
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: issuer.id,
        generation: 1,
        key_id: "kid".into(),
        public_key: [1; 32],
        sealed_private_key: vec![1],
        created_at: now,
    };
    storage
        .insert_oidc_issuer(&issuer, &key, ctx())
        .await
        .unwrap();
    let keys = ClientKeySet::try_from(serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "bff-1",
    }]}))
    .unwrap();
    let settings = AccountSettings::new("https://account.sid.example.com", keys).unwrap();
    let integration = ensure_account_integration(&storage, &issuer, INSTALLATION, &settings)
        .await
        .unwrap();
    Registration {
        issuer,
        client: integration.client,
        resource: integration.resource,
        access: integration.access.expect("the integration grants access"),
    }
}

fn refused(result: SidResult<ClientConnection>) -> bool {
    matches!(result, Err(SidError::InvalidState(_)))
}

/// The connection names exactly what the registration holds: the issuer's
/// canonical URL, the client, the resource indicator, the client's scopes,
/// its callback and `private_key_jwt`.
#[tokio::test]
async fn the_connection_is_the_stored_registration() {
    let r = registration().await;
    let connection = r.connection().unwrap();
    assert_eq!(connection.issuer, r.issuer.canonical_url);
    assert_eq!(connection.client_id, r.client.client_id);
    assert_eq!(connection.resource, format!("{INSTALLATION}/account"));
    assert_eq!(connection.scopes, r.client.allowed_scopes);
    assert_eq!(
        connection.redirect_uri,
        "https://account.sid.example.com/auth/callback"
    );
    assert_eq!(connection.token_endpoint_auth_method, "private_key_jwt");
    assert_eq!(connection.key_ids, ["bff-1"]);
}

/// A resource of another issuer would send the BFF's tokens to an API that
/// does not trust them: no connection is made of it.
#[tokio::test]
async fn a_resource_of_another_issuer_is_refused() {
    let mut r = registration().await;
    r.resource.issuer_id = IssuerId::generate();
    assert!(refused(r.connection()));
}

/// A client without a callback cannot complete a sign-in, and no callback is
/// invented for it.
#[tokio::test]
async fn a_client_without_a_callback_is_refused() {
    let mut r = registration().await;
    r.client.redirect_uris.clear();
    assert!(refused(r.connection()));
}

/// A client of another organization is not served by this issuer: its
/// sign-ins would all be refused, so no connection names the pair.
#[tokio::test]
async fn a_client_of_another_organization_is_refused() {
    let mut r = registration().await;
    r.client.org_id = Some(sid_core::models::OrgId::generate());
    assert!(refused(r.connection()));
    r.client.org_id = None;
    assert!(refused(r.connection()));
}

/// A client with several callbacks gives no way to tell which one is this
/// BFF's: picking one could send the authorization response to another
/// deployment, so the connection is refused.
#[tokio::test]
async fn a_client_with_several_callbacks_is_refused() {
    let mut r = registration().await;
    r.client
        .redirect_uris
        .push("https://other.sid.example.com/auth/callback".into());
    assert!(refused(r.connection()));
}

/// The BFF runs the authorization code flow and refreshes: a client
/// registered without either grant would have every sign-in or refresh
/// refused, so no connection is made of it.
#[tokio::test]
async fn a_client_without_the_code_or_refresh_grant_is_refused() {
    for grant in ["authorization_code", "refresh_token"] {
        let mut r = registration().await;
        r.client.grant_types.retain(|g| g != grant);
        assert!(refused(r.connection()), "without {grant}");
    }
}

/// A disabled client, or a resource that is not a token target (inactive or
/// retired), has every sign-in refused: no connection names it.
#[tokio::test]
async fn a_disabled_client_or_untargetable_resource_is_refused() {
    let mut r = registration().await;
    r.client.active = false;
    assert!(refused(r.connection()), "disabled client");
    for state in [ResourceState::Inactive, ResourceState::Retired] {
        let mut r = registration().await;
        r.resource.state = state;
        assert!(refused(r.connection()), "{state:?}");
    }
}

/// The BFF authenticates with its private key only. A client registered for
/// a secret or for no authentication, or a `private_key_jwt` client without
/// keys, would yield a bundle the BFF refuses at start or a sign-in whose
/// code it cannot redeem: no connection names it.
#[tokio::test]
async fn a_client_the_bffs_key_cannot_authenticate_is_refused() {
    use sid_core::models::TokenEndpointAuthMethod as M;
    for method in [M::ClientSecretBasic, M::ClientSecretPost, M::None] {
        let mut r = registration().await;
        r.client.token_endpoint_auth_method = method;
        r.client.client_secret_hash = Some(vec![1]);
        assert!(refused(r.connection()), "{method:?}");
    }
    let mut r = registration().await;
    r.client.jwks = None;
    assert!(refused(r.connection()), "private_key_jwt without keys");
}

/// The BFF's callback needs an ID token, issued only for `openid` (OIDC Core
/// 1.0 §3.1.2.1): a client that may not request it gets no connection.
#[tokio::test]
async fn a_client_without_openid_is_refused() {
    let mut r = registration().await;
    r.client.allowed_scopes.retain(|s| s != "openid");
    assert!(refused(r.connection()));
}

/// Access granted to another client, or to another resource, is not this
/// client's access to this resource: the issuer would refuse every request
/// for the target.
#[tokio::test]
async fn access_of_another_client_or_resource_is_refused() {
    let mut r = registration().await;
    r.access.client_id = "another-client".into();
    assert!(refused(r.connection()));

    let mut r = registration().await;
    r.access.resource_id = ResourceId::generate();
    assert!(refused(r.connection()));
}

/// The bundle a deployment delivers reads back as the same connection, and a
/// field this version does not know is refused rather than ignored.
#[tokio::test]
async fn the_bundle_round_trips_and_refuses_unknown_fields() {
    let r = registration().await;
    let connection = r.connection().unwrap();
    let bundle = serde_json::to_string(&connection).unwrap();
    assert_eq!(
        serde_json::from_str::<ClientConnection>(&bundle).unwrap(),
        connection
    );

    let mut extended = serde_json::to_value(&connection).unwrap();
    extended["client_secret"] = "s3cret".into();
    assert!(serde_json::from_value::<ClientConnection>(extended).is_err());
}
