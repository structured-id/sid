// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use super::*;
use crate::issuer::IssuerRegistry;
use crate::jwt::{ClientGrant, JwtService};
use sid_core::models::{
    Application, ApplicationId, AuditEntry, MachineCredentialType, MachineUser,
    MachineUserCredential, MachineUserStatus, MutationContext, OAuth2Client, OidcIssuer, OwnerType,
    ProjectId, ResourceIndicator, TokenEndpointAuthMethod,
};
use sid_storage::sqlite::SqliteBackend;
use tonic::Code;

fn audit() -> MutationContext {
    AuditEntry::system("test", "service").into()
}

/// An installation with its issuer, a verifier of its tokens for the
/// authorization API, a machine user with one credential and a confidential
/// OAuth client.
struct Fixture {
    storage: Arc<SqliteBackend>,
    registry: Arc<IssuerRegistry>,
    issuer: OidcIssuer,
    tokens: ResourceTokenVerifier,
    revocation: RevocationCache,
    jwt: JwtService,
    machine: MachineUser,
    machine_id: String,
    client: OAuth2Client,
    api: String,
    scopes: Vec<String>,
}

async fn fixture() -> Fixture {
    let storage = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    storage.ensure_system_project(audit()).await.unwrap();
    let org = crate::instance_org::ensure(storage.as_ref(), "sid.example.com")
        .await
        .unwrap()
        .id;
    let keys = crate::test_support::key_manager();
    let issuer = crate::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys.as_ref(),
        &url::Url::parse("https://sid.example.com").unwrap(),
        org,
    )
    .await
    .unwrap();
    let api = crate::issuer::ensure_authorization_api_resource(storage.as_ref(), &issuer)
        .await
        .unwrap();
    let registry = Arc::new(IssuerRegistry::new(storage.clone(), keys));
    let tokens =
        ResourceTokenVerifier::new(registry.clone(), issuer.clone(), api.indicator.clone())
            .await
            .unwrap();
    let machine = MachineUser::new(
        ProjectId::system(),
        "mu_checker",
        "Route checker",
        OwnerType::System,
        "system",
    );
    storage
        .create_machine_user(&machine, audit())
        .await
        .unwrap();
    storage
        .add_machine_credential(
            &MachineUserCredential::new(
                machine.id,
                "kid_a",
                MachineCredentialType::ClientSecret,
                "verifier",
            ),
            None,
            audit(),
        )
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: "Orders PDP".into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let client = crate::test_support::client_of(&app, org);
    storage
        .create_application(&app, Some(&client), None, audit())
        .await
        .unwrap();
    let jwt = JwtService::new(
        include_bytes!("../../tests/fixtures/test_ed25519_private.pem"),
        include_bytes!("../../tests/fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".into(),
    )
    .unwrap();
    Fixture {
        storage,
        registry,
        issuer,
        tokens,
        revocation: RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        ),
        jwt,
        machine_id: machine.id.to_string(),
        machine,
        client,
        api: api.indicator.to_string(),
        scopes: vec![sid_core::models::AUTHZ_CHECK.to_string()],
    }
}

impl Fixture {
    /// What the token endpoint grants the machine user for the API.
    fn machine_grant(&self) -> ClientGrant<'_> {
        ClientGrant {
            resource: &self.api,
            client_id: &self.machine.client_id,
            subject: &self.machine_id,
            credential: "kid_a",
            scopes: &self.scopes,
            dpop: None,
            max_lifetime: None,
        }
    }

    /// What the token endpoint grants the OAuth client acting for itself.
    fn client_grant(&self) -> ClientGrant<'_> {
        ClientGrant {
            resource: &self.api,
            client_id: &self.client.client_id,
            subject: &self.client.client_id,
            credential: &self.client.client_id,
            scopes: &self.scopes,
            dpop: None,
            max_lifetime: None,
        }
    }

    async fn token(&self, grant: ClientGrant<'_>) -> String {
        let signer = self.registry.signer(&self.issuer).await.unwrap();
        self.jwt
            .client_access_token_signed_by(signer.as_ref(), &grant)
            .unwrap()
    }

    async fn check(&self, token: &str) -> Result<ServiceCaller, Status> {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        authenticate_service(
            &request,
            self.storage.as_ref(),
            &self.tokens,
            &self.revocation,
        )
        .await
    }

    async fn refused(&self, token: &str, case: &str) {
        let err = self.check(token).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated, "{case}: {err:?}");
    }
}

/// A machine user and an OAuth client authenticate as themselves with their
/// own tokens for the API, as the engine subjects they are.
#[tokio::test]
async fn a_service_authenticates_as_itself() {
    let f = fixture().await;
    let machine = f.check(&f.token(f.machine_grant()).await).await.unwrap();
    assert_eq!(machine.subject(), format!("machine:{}", f.machine.id));
    let client = f.check(&f.token(f.client_grant()).await).await.unwrap();
    assert_eq!(
        client.subject(),
        format!("oauth_client:{}", f.client.client_id)
    );
}

/// A user's token (issued to the client but naming the Profile and its
/// sign-in), a token for another resource, one bound to a key the call does
/// not prove, and an unknown client are no service.
#[tokio::test]
async fn anything_but_a_service_token_for_the_api_is_refused() {
    let f = fixture().await;
    let profile = sid_core::models::ProfileId::generate().to_string();
    let session = sid_core::models::SessionId::generate().to_string();
    let binding =
        sid_core::models::dpop::DPopBinding::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    for (case, grant) in [
        (
            "a user's token",
            ClientGrant {
                subject: &profile,
                credential: &session,
                ..f.client_grant()
            },
        ),
        (
            "another resource",
            ClientGrant {
                resource: "https://resources.sid.example.com/orders",
                ..f.client_grant()
            },
        ),
        (
            "sender-constrained",
            ClientGrant {
                dpop: Some(&binding),
                ..f.machine_grant()
            },
        ),
        (
            "unknown client",
            ClientGrant {
                client_id: "nobody",
                subject: "nobody",
                credential: "nobody",
                ..f.client_grant()
            },
        ),
    ] {
        f.refused(&f.token(grant).await, case).await;
    }
}

/// A suspended machine, a deactivated or public client, and a revoked
/// credential stop tokens already issued.
#[tokio::test]
async fn current_state_is_checked_on_every_call() {
    let f = fixture().await;
    let machine_token = f.token(f.machine_grant()).await;
    let client_token = f.token(f.client_grant()).await;

    assert!(
        f.storage
            .transition_machine_user(
                f.machine.id,
                MachineUserStatus::Active,
                MachineUserStatus::Suspended,
                audit()
            )
            .await
            .unwrap()
    );
    f.refused(&machine_token, "suspended machine").await;

    let mut client = f.client.clone();
    client.active = false;
    assert!(
        f.storage
            .update_oauth2_client(&client, audit())
            .await
            .unwrap()
    );
    f.refused(&client_token, "deactivated client").await;
    let mut client = f
        .storage
        .get_oauth2_client(&f.client.client_id)
        .await
        .unwrap()
        .unwrap();
    client.active = true;
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::None;
    assert!(
        f.storage
            .update_oauth2_client(&client, audit())
            .await
            .unwrap()
    );
    f.refused(&client_token, "public client").await;

    let mut client = f
        .storage
        .get_oauth2_client(&f.client.client_id)
        .await
        .unwrap()
        .unwrap();
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
    assert!(
        f.storage
            .update_oauth2_client(&client, audit())
            .await
            .unwrap()
    );
    f.check(&client_token).await.unwrap();
    f.revocation
        .revoke_session(f.client.client_id.clone())
        .await
        .unwrap();
    f.refused(&client_token, "revoked in the cache").await;
}

/// The indicator the API's verifier checks is the authorization API of the
/// issuer.
#[test]
fn the_api_is_the_issuers_authorization_api() {
    assert_eq!(
        crate::issuer::authorization_api_endpoint("https://sid.example.com/i/abc"),
        "https://sid.example.com/i/abc/authz"
    );
    ResourceIndicator::parse(&crate::issuer::authorization_api_endpoint(
        "https://sid.example.com",
    ))
    .unwrap();
}
