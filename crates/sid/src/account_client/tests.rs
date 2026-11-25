use super::*;
use jiff::Timestamp;
use sid_authn::system_integration::{AccountSettings, ensure_account_integration};
use sid_core::models::{
    AuditEntry, ClientKeySet, IssuerHandle, IssuerId, IssuerSigningKey, MutationContext,
    OidcIssuer, Organization,
};
use sid_plugin::IssuerStore;

const INSTALLATION: &str = "https://sid.example.com";
const ACCOUNT: &str = "https://account.sid.example.com";
const KID: &str = "bff-1";

fn ctx() -> MutationContext {
    AuditEntry::system("test", "account client").into()
}

/// An installation's store with its issuer and, with `provisioned`, the
/// account integration registered for the key [`KID`].
async fn installation(provisioned: bool) -> (Arc<dyn StorageBackend>, OidcIssuer) {
    let storage = crate::test_support::storage().await;
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let now = Timestamp::from_millisecond(Timestamp::now().as_millisecond()).unwrap();
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
    if provisioned {
        let keys = ClientKeySet::try_from(serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": KID,
        }]}))
        .unwrap();
        let settings = AccountSettings::new(ACCOUNT, keys).unwrap();
        ensure_account_integration(storage.as_ref(), &issuer, INSTALLATION, &settings)
            .await
            .unwrap();
    }
    (storage, issuer)
}

fn issuers(storage: &Arc<dyn StorageBackend>) -> InstallationIssuers {
    let registry = IssuerRegistry::new(storage.clone(), crate::test_support::keys());
    InstallationIssuers::new(Arc::new(registry), storage.clone())
}

/// The connection is the committed registration, read in process: the
/// issuer's exact URL and handle, the account API as the target, the scopes
/// the account pages sign in with and the registered callback.
/// Bug prevented: a host in the issuer's process needing a network round
/// trip to its own installation to learn what the store already holds.
#[tokio::test]
async fn the_connection_is_read_from_the_stored_registration() {
    let (storage, issuer) = installation(true).await;
    let connection = connection(storage.as_ref(), KID).await.unwrap();
    assert_eq!(connection.issuer, issuer.canonical_url);
    assert_eq!(connection.issuer_handle, issuer.handle.to_string());
    assert_eq!(connection.resource, format!("{INSTALLATION}/account"));
    assert_eq!(
        connection.scopes,
        [
            "openid",
            "profile",
            "email",
            "account.read",
            "account.write"
        ]
    );
    assert_eq!(connection.redirect_uri, format!("{ACCOUNT}/auth/callback"));
}

/// A key the account client did not register gets no connection: every
/// token call signed with it would be refused, so the host learns it at
/// once instead of at its first sign-in.
#[tokio::test]
async fn a_key_the_client_did_not_register_gets_no_connection() {
    let (storage, _) = installation(true).await;
    assert!(matches!(
        connection(storage.as_ref(), "another-key").await,
        Err(AccountClientError::UnregisteredKey(kid)) if kid == "another-key"
    ));
}

/// Before the account integration is provisioned there is no connection,
/// and none is invented.
#[tokio::test]
async fn an_installation_without_the_integration_has_no_connection() {
    let (storage, _) = installation(false).await;
    assert!(matches!(
        connection(storage.as_ref(), KID).await,
        Err(AccountClientError::NotReady(_))
    ));
}

/// An issuer is described as its registry holds it: the exact URL and its
/// public key; a handle that names none is absent.
#[tokio::test]
async fn an_issuer_is_described_as_the_registry_holds_it() {
    let (storage, issuer) = installation(false).await;
    let source = issuers(&storage);
    let record = source
        .issuer(&issuer.handle.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.issuer, issuer.canonical_url);
    assert_eq!(record.keys, [("kid".to_owned(), [1; 32])]);

    let other = IssuerHandle::generate().to_string();
    assert_eq!(source.issuer(&other).await.unwrap(), None);
    assert_eq!(source.issuer("not a handle").await.unwrap(), None);
}

/// A registered resource is found by its exact indicator under its own
/// issuer; another spelling, another issuer or an unregistered indicator
/// names none.
#[tokio::test]
async fn a_resource_is_found_by_its_exact_indicator_under_its_issuer() {
    let (storage, issuer) = installation(true).await;
    let source = issuers(&storage);
    let handle = issuer.handle.to_string();
    let account = format!("{INSTALLATION}/account");

    let record = source.resource(&handle, &account).await.unwrap().unwrap();
    assert_eq!(record.issuer, issuer.canonical_url);
    assert_eq!(record.resource, account);
    assert!(record.active);

    for absent in [
        format!("{INSTALLATION}/other"),
        "not an indicator".to_owned(),
    ] {
        assert_eq!(source.resource(&handle, &absent).await.unwrap(), None);
    }
    let other = IssuerHandle::generate().to_string();
    assert_eq!(source.resource(&other, &account).await.unwrap(), None);
}

/// A refusal of the grant is told apart from a limit and from a failure
/// that may have taken effect, as the browser sessions decide by it whether
/// a session ended.
#[test]
fn a_failed_call_is_classified_by_what_it_may_have_done() {
    use sid_authn::oauth2::TokenError;
    assert!(matches!(
        failure(OAuthError::token(TokenError::InvalidGrant, "used")),
        GrantFailure::Refused(_)
    ));
    assert!(matches!(
        failure(OAuthError::ClientRefused),
        GrantFailure::Refused(_)
    ));
    assert!(matches!(
        failure(OAuthError::RateLimited { rpm: 1 }),
        GrantFailure::Declined(_)
    ));
    for uncertain in [
        OAuthError::Internal,
        OAuthError::PolicyChanged,
        OAuthError::Store(sid_core::Error::Storage("lost".into())),
    ] {
        assert!(matches!(failure(uncertain), GrantFailure::Uncertain(_)));
    }
}
