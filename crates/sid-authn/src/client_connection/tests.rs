use super::*;
use crate::system_integration::{AccountSettings, ensure_account_integration};
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    AuditEntry, ClientKeySet, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey,
    MutationContext, Organization,
};
use sid_plugin::storage::StorageBackend;
use sid_storage::sqlite::SqliteBackend;

const INSTALLATION: &str = "https://sid.example.com";

fn ctx() -> MutationContext {
    AuditEntry::system("test", "connection").into()
}

/// The issuer and a registered web client with its resource, as the account
/// integration stores them.
async fn registration() -> (OidcIssuer, OAuth2Client, ProtectedResource) {
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
    (issuer, integration.client, integration.resource)
}

/// The connection names exactly what the registration holds: the issuer's
/// canonical URL, the client, the resource indicator, the client's scopes,
/// its callback and `private_key_jwt`.
#[tokio::test]
async fn the_connection_is_the_stored_registration() {
    let (issuer, client, resource) = registration().await;
    let connection = ClientConnection::of(&issuer, &client, &resource).unwrap();
    assert_eq!(connection.issuer, issuer.canonical_url);
    assert_eq!(connection.client_id, client.client_id);
    assert_eq!(connection.resource, format!("{INSTALLATION}/account"));
    assert_eq!(connection.scopes, client.allowed_scopes);
    assert_eq!(
        connection.redirect_uri,
        "https://account.sid.example.com/auth/callback"
    );
    assert_eq!(connection.token_endpoint_auth_method, "private_key_jwt");
}

/// A resource of another issuer would send the BFF's tokens to an API that
/// does not trust them: no connection is made of it.
#[tokio::test]
async fn a_resource_of_another_issuer_is_refused() {
    let (issuer, client, mut resource) = registration().await;
    resource.issuer_id = IssuerId::generate();
    assert!(matches!(
        ClientConnection::of(&issuer, &client, &resource),
        Err(SidError::InvalidState(_))
    ));
}

/// A client without a callback cannot complete a sign-in, and no callback is
/// invented for it.
#[tokio::test]
async fn a_client_without_a_callback_is_refused() {
    let (issuer, mut client, resource) = registration().await;
    client.redirect_uris.clear();
    assert!(matches!(
        ClientConnection::of(&issuer, &client, &resource),
        Err(SidError::InvalidState(_))
    ));
}

/// The bundle a deployment delivers reads back as the same connection, and a
/// field this version does not know is refused rather than ignored.
#[tokio::test]
async fn the_bundle_round_trips_and_refuses_unknown_fields() {
    let (issuer, client, resource) = registration().await;
    let connection = ClientConnection::of(&issuer, &client, &resource).unwrap();
    let bundle = serde_json::to_string(&connection).unwrap();
    assert_eq!(
        serde_json::from_str::<ClientConnection>(&bundle).unwrap(),
        connection
    );

    let mut extended = serde_json::to_value(&connection).unwrap();
    extended["client_secret"] = "s3cret".into();
    assert!(serde_json::from_value::<ClientConnection>(extended).is_err());
}
