use super::*;
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, MutationContext, Organization,
};
use sid_storage::sqlite::SqliteBackend;

const INSTALLATION: &str = "https://sid.example.com";

fn ctx() -> MutationContext {
    AuditEntry::system("test", "account").into()
}

fn keys(kid: &str) -> ClientKeySet {
    ClientKeySet::try_from(serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": kid,
    }]}))
    .unwrap()
}

fn settings(url: &str, kid: &str) -> AccountSettings {
    AccountSettings::new(url, keys(kid)).unwrap()
}

/// A store with the installation organization and its local issuer.
async fn store() -> (SqliteBackend, OidcIssuer) {
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
    (storage, issuer)
}

/// The integration is a system application holding a `private_key_jwt` web
/// client with the BFF's keys and exact callback, the account API under the
/// installation's issuer, and access to it with the account scope only.
#[tokio::test]
async fn the_integration_is_provisioned_in_the_registry() {
    let (storage, issuer) = store().await;
    let account = settings("https://account.sid.example.com", "bff-1");
    let integration = ensure_account_integration(&storage, &issuer, INSTALLATION, &account)
        .await
        .unwrap();

    assert_eq!(
        integration.application.system,
        Some(SystemIntegration::Account)
    );
    let client = &integration.client;
    assert_eq!(
        client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt
    );
    assert!(!client.is_public());
    assert!(client.client_secret_hash.is_none(), "no secret leaves SID");
    assert_eq!(client.jwks.as_ref(), Some(account.keys()));
    assert_eq!(
        client.redirect_uris,
        ["https://account.sid.example.com/auth/callback"]
    );
    assert_eq!(client.org_id, Some(issuer.recipient_org));
    assert_eq!(client.default_resource, Some(integration.resource.id));
    assert_eq!(integration.resource.issuer_id, issuer.id);
    assert_eq!(
        integration.resource.indicator.as_str(),
        "https://sid.example.com/account"
    );
    assert_eq!(integration.access.as_ref().unwrap().scopes, ["account"]);
    assert!(integration.is_ready());
}

/// Restarts and replicas starting together keep one integration and its
/// identifiers.
#[tokio::test]
async fn provisioning_is_idempotent_and_concurrent_safe() {
    let (storage, issuer) = store().await;
    let account = settings("https://account.sid.example.com", "bff-1");
    let (a, b) = tokio::join!(
        ensure_account_integration(&storage, &issuer, INSTALLATION, &account),
        ensure_account_integration(&storage, &issuer, INSTALLATION, &account),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.application.id, b.application.id);
    assert_eq!(a.client.client_id, b.client.client_id);
    let again = ensure_account_integration(&storage, &issuer, INSTALLATION, &account)
        .await
        .unwrap();
    assert_eq!(again.client.client_id, a.client.client_id);
    assert_eq!(again.resource.id, a.resource.id);
    let clients = storage.list_oauth2_clients(0, 100).await.unwrap();
    assert_eq!(clients.len(), 1, "one client, whatever the starts");
}

/// A moved account URL and a rotated key change the callback and keys, never
/// the client's identity.
#[tokio::test]
async fn settings_changes_keep_the_client_identity() {
    let (storage, issuer) = store().await;
    let first = ensure_account_integration(
        &storage,
        &issuer,
        INSTALLATION,
        &settings("https://account.sid.example.com", "bff-1"),
    )
    .await
    .unwrap();
    let moved = settings("https://me.sid.example.com", "bff-2");
    let second = ensure_account_integration(&storage, &issuer, INSTALLATION, &moved)
        .await
        .unwrap();
    assert_eq!(second.client.client_id, first.client.client_id);
    let stored = storage
        .get_oauth2_client(&first.client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.redirect_uris,
        ["https://me.sid.example.com/auth/callback"]
    );
    assert!(stored.jwks.unwrap().key("bff-2").is_some());
}

/// An administrator's disabling is not undone by the next start.
#[tokio::test]
async fn a_disabled_integration_stays_disabled() {
    let (storage, issuer) = store().await;
    let account = settings("https://account.sid.example.com", "bff-1");
    let integration = ensure_account_integration(&storage, &issuer, INSTALLATION, &account)
        .await
        .unwrap();
    let mut disabled = integration.client.clone();
    disabled.active = false;
    assert!(
        storage
            .update_oauth2_client(&disabled, ctx())
            .await
            .unwrap()
    );

    let restarted = ensure_account_integration(&storage, &issuer, INSTALLATION, &account)
        .await
        .unwrap();
    assert!(!restarted.client.active);
    assert!(!restarted.is_ready());
}

/// A start interrupted before the access was granted is completed by the
/// next one; until then the integration is not ready.
#[tokio::test]
async fn an_interrupted_provisioning_is_completed() {
    let (storage, issuer) = store().await;
    let account = settings("https://account.sid.example.com", "bff-1");
    let integration = ensure_account_integration(&storage, &issuer, INSTALLATION, &account)
        .await
        .unwrap();
    storage
        .remove_resource_access(
            &integration.client.client_id,
            integration.resource.id,
            ctx(),
        )
        .await
        .unwrap();
    let partial = account_integration(&storage).await.unwrap().unwrap();
    assert!(!partial.is_ready());

    let completed = ensure_account_integration(&storage, &issuer, INSTALLATION, &account)
        .await
        .unwrap();
    assert!(completed.is_ready());
}

/// The account URL supplies the exact callback: it is https (or http on a
/// loopback host) and carries nothing a request could vary.
#[test]
fn the_account_url_is_checked() {
    assert!(AccountSettings::new("https://account.sid.example.com", keys("k")).is_ok());
    assert!(AccountSettings::new("http://localhost:8084", keys("k")).is_ok());
    for bad in [
        "http://account.sid.example.com",
        "https://account.sid.example.com/?next=x",
        "https://account.sid.example.com/#f",
        "https://user@account.sid.example.com",
        "account.sid.example.com",
    ] {
        assert!(AccountSettings::new(bad, keys("k")).is_err(), "{bad}");
    }
}
