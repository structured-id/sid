// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use super::*;
use crate::issuer::IssuerRegistry;
use crate::jwt::{ClientGrant, JwtService};
use sid_core::models::{
    AuditEntry, MachineCredentialType, MachineUserCredential, MachineUserStatus, MutationContext,
    OidcIssuer, OwnerType, ProjectId, ResourceIndicator,
};
use sid_storage::sqlite::SqliteBackend;
use tonic::Code;

const RESOURCE: &str = "https://resources.sid.example.com/tenants";

fn audit() -> MutationContext {
    AuditEntry::system("test", "machine").into()
}

/// An installation with its issuer, a verifier of that issuer's tokens for
/// [`RESOURCE`], and an active machine user with one credential.
struct Fixture {
    storage: Arc<SqliteBackend>,
    registry: Arc<IssuerRegistry>,
    issuer: OidcIssuer,
    tokens: ResourceTokenVerifier,
    revocation: RevocationCache,
    jwt: JwtService,
    machine: MachineUser,
    subject: String,
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
    let registry = Arc::new(IssuerRegistry::new(storage.clone(), keys));
    let tokens = ResourceTokenVerifier::new(
        registry.clone(),
        issuer.clone(),
        ResourceIndicator::parse(RESOURCE).unwrap(),
    )
    .await
    .unwrap();
    let machine = MachineUser::new(
        ProjectId::system(),
        "mu_orchestrator",
        "Tenant orchestrator",
        OwnerType::System,
        "system",
    );
    storage
        .create_machine_user(&machine, audit())
        .await
        .unwrap();
    credential(&storage, &machine, "kid_a").await;
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
        subject: machine.id.to_string(),
        scopes: vec!["tenant.read".to_string()],
        machine,
    }
}

async fn credential(storage: &SqliteBackend, machine: &MachineUser, kid: &str) {
    let cred = MachineUserCredential::new(
        machine.id,
        kid,
        MachineCredentialType::ClientSecret,
        "verifier",
    );
    storage
        .add_machine_credential(&cred, None, audit())
        .await
        .unwrap();
}

impl Fixture {
    /// What the token endpoint grants the machine with its first credential.
    fn grant(&self) -> ClientGrant<'_> {
        ClientGrant {
            resource: RESOURCE,
            client_id: &self.machine.client_id,
            subject: &self.subject,
            credential: "kid_a",
            scopes: &self.scopes,
            dpop: None,
            max_lifetime: None,
        }
    }

    /// `grant` as the issuer signs it.
    async fn token(&self, grant: ClientGrant<'_>) -> String {
        let signer = self.registry.signer(&self.issuer).await.unwrap();
        self.jwt
            .client_access_token_signed_by(signer.as_ref(), &grant)
            .unwrap()
    }

    async fn check(&self, token: &str) -> Result<MachineCaller, Status> {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        authenticate_machine(
            &request,
            self.storage.as_ref(),
            &self.tokens,
            &self.revocation,
        )
        .await
    }

    /// The stored state behind `grant` once the issuer signed it.
    async fn state(&self, grant: ClientGrant<'_>) -> MachineTokenState {
        let claims = self.tokens.verify(&self.token(grant).await).await.unwrap();
        machine_token_state(self.storage.as_ref(), &claims)
            .await
            .unwrap()
    }

    async fn refused(&self, token: &str, case: &str) {
        let err = self.check(token).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated, "{case}: {err:?}");
    }
}

/// A token the issuer signed for this resource authenticates its machine
/// user with the credential and scopes it names.
#[tokio::test]
async fn a_machine_token_authenticates_its_machine() {
    let f = fixture().await;
    let caller = f.check(&f.token(f.grant()).await).await.unwrap();
    assert_eq!(caller.machine.id, f.machine.id);
    assert_eq!(caller.credential, "kid_a");
    assert_eq!(caller.subject(), format!("machine:{}", f.machine.id));
    assert!(caller.may("tenant.read"));
    assert!(!caller.may("tenant.create"));
}

/// A token for another resource, naming another machine, an unknown or
/// foreign credential, or bound to a key the call does not prove, is refused.
#[tokio::test]
async fn a_token_for_something_else_is_refused() {
    let f = fixture().await;
    let other = MachineUser::new(
        ProjectId::system(),
        "mu_reader",
        "EDS reader",
        OwnerType::System,
        "system",
    );
    f.storage
        .create_machine_user(&other, audit())
        .await
        .unwrap();
    credential(&f.storage, &other, "kid_other").await;
    let other_id = other.id.to_string();

    let binding =
        sid_core::models::dpop::DPopBinding::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    for (case, grant) in [
        (
            "another resource",
            ClientGrant {
                resource: "https://resources.sid.example.com/orders",
                ..f.grant()
            },
        ),
        (
            "another machine's id",
            ClientGrant {
                subject: &other_id,
                ..f.grant()
            },
        ),
        (
            "unknown client",
            ClientGrant {
                client_id: "mu_unknown",
                ..f.grant()
            },
        ),
        (
            "unknown credential",
            ClientGrant {
                credential: "kid_missing",
                ..f.grant()
            },
        ),
        (
            "another machine's credential",
            ClientGrant {
                credential: "kid_other",
                ..f.grant()
            },
        ),
        (
            "sender-constrained",
            ClientGrant {
                dpop: Some(&binding),
                ..f.grant()
            },
        ),
    ] {
        f.refused(&f.token(grant).await, case).await;
    }
}

/// The state read for a verified token: a client that is no machine user,
/// a machine token that cannot act now, and one that can. Introspection
/// relies on telling the first two apart.
#[tokio::test]
async fn machine_token_state_tells_machine_tokens_apart() {
    let f = fixture().await;
    let state = |grant| f.state(grant);

    match state(f.grant()).await {
        MachineTokenState::Usable {
            machine,
            credential,
        } => {
            assert_eq!(machine.id, f.machine.id);
            assert_eq!(credential.kid, "kid_a");
        }
        other => panic!("usable machine token: {other:?}"),
    }
    assert!(matches!(
        state(ClientGrant {
            client_id: "orders-web",
            ..f.grant()
        })
        .await,
        MachineTokenState::NotMachine
    ));
    assert!(matches!(
        state(ClientGrant {
            credential: "kid_missing",
            ..f.grant()
        })
        .await,
        MachineTokenState::Unusable
    ));
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
    assert!(matches!(
        state(f.grant()).await,
        MachineTokenState::Unusable
    ));
}

/// Suspending the machine, revoking or expiring its credential, or revoking
/// the credential in the shared cache stops tokens already issued.
#[tokio::test]
async fn current_state_is_checked_on_every_request() {
    let f = fixture().await;
    let token = f.token(f.grant()).await;
    f.check(&token).await.unwrap();

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
    f.refused(&token, "suspended").await;
    assert!(
        f.storage
            .transition_machine_user(
                f.machine.id,
                MachineUserStatus::Suspended,
                MachineUserStatus::Active,
                audit()
            )
            .await
            .unwrap()
    );
    f.check(&token).await.unwrap();

    f.revocation.revoke_session("kid_a".into()).await.unwrap();
    f.refused(&token, "revoked in the cache").await;

    credential(&f.storage, &f.machine, "kid_b").await;
    let second = f
        .token(ClientGrant {
            credential: "kid_b",
            ..f.grant()
        })
        .await;
    f.check(&second).await.unwrap();
    assert!(
        f.storage
            .revoke_machine_credential(f.machine.id, "kid_b", audit())
            .await
            .unwrap()
    );
    f.refused(&second, "revoked credential").await;
}
