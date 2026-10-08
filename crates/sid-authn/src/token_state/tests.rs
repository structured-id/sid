// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use chrono::Utc;
use sid_core::models::{
    Application, ApplicationId, AuditEntry, ConnectorCredentialKind, ConnectorState,
    MachineCredentialType, MachineUser, MachineUserCredential, MachineUserStatus, MutationContext,
    OwnerType, ProjectId, ProvisioningConnector, ProvisioningCredential, ProvisioningDirection,
    Session,
};
use sid_storage::sqlite::SqliteBackend;

fn audit() -> MutationContext {
    AuditEntry::system("test", "token-state").into()
}

/// Verified claims of a token issued to `client_id`, naming `sub` and `sid`.
fn claims(client_id: Option<&str>, sub: &str, sid: &str) -> AccessTokenClaims {
    let now = Utc::now().timestamp();
    AccessTokenClaims {
        sub: sub.into(),
        pid: None,
        aud: vec!["https://resources.sid.example.com/orders".into()],
        client_id: client_id.map(str::to_owned),
        iss: "https://sid.example.com".into(),
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: String::new(),
        scope: "orders.read".into(),
        roles: String::new(),
        amr: Vec::new(),
        sid: sid.into(),
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
    }
}

/// A stored Profile a sign-in can belong to.
async fn stored_profile(storage: &SqliteBackend) -> ProfileId {
    let profile =
        sid_core::models::Profile::new(Some(&format!("user-{}", uuid::Uuid::now_v7().simple())));
    storage.create_profile(&profile, audit()).await.unwrap();
    profile.id
}

/// A store with a web client, a machine user with one credential and an
/// inbound connector with one client credential.
struct Fixture {
    storage: SqliteBackend,
    client: sid_core::models::OAuth2Client,
    machine: MachineUser,
    connector: ProvisioningConnector,
    connector_credential: String,
}

async fn fixture() -> Fixture {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    storage.ensure_system_project(audit()).await.unwrap();
    let org = crate::instance_org::ensure(&storage, "sid.example.com")
        .await
        .unwrap()
        .id;
    let now = Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: "Orders web".into(),
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
    let machine = MachineUser::new(
        ProjectId::system(),
        "mu_worker",
        "Worker",
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
    let connector = ProvisioningConnector::new(org, ProvisioningDirection::Inbound, "HR");
    storage
        .create_provisioning_connector(&connector, audit())
        .await
        .unwrap();
    let credential = ProvisioningCredential::new(
        connector.id,
        ConnectorCredentialKind::ClientSecret,
        crate::bearer_secret::issue(
            sid_core::models::provisioning_connector::CONNECTOR_CLIENT_SECRET_PREFIX,
        )
        .verifier,
    );
    assert!(
        storage
            .add_provisioning_credential(&credential, audit())
            .await
            .unwrap()
    );
    Fixture {
        storage,
        client,
        machine,
        connector,
        connector_credential: credential.id.to_string(),
    }
}

/// A machine user's, a connector's and a client's own token stand for that
/// service; a user's token stands for the Profile of its stored sign-in,
/// whatever its `sub` says.
#[tokio::test]
async fn an_active_token_names_its_actor() {
    let f = fixture().await;
    let state = |c| {
        let storage = &f.storage;
        async move { current_state(storage, &c).await.unwrap() }
    };
    assert_eq!(
        state(claims(
            Some(&f.machine.client_id),
            &f.machine.id.to_string(),
            "kid_a"
        ))
        .await,
        TokenState::Active(TokenActor::Machine(f.machine.id))
    );
    assert_eq!(
        state(claims(
            Some(&f.connector.client_id),
            &f.connector.id.to_string(),
            &f.connector_credential
        ))
        .await,
        TokenState::Active(TokenActor::Connector(f.connector.id))
    );
    assert_eq!(
        state(claims(
            Some(&f.client.client_id),
            &f.client.client_id,
            &f.client.client_id
        ))
        .await,
        TokenState::Active(TokenActor::Client(f.client.client_id.clone()))
    );

    let profile = stored_profile(&f.storage).await;
    let session = Session::new(
        profile,
        "127.0.0.1".into(),
        Utc::now() + chrono::Duration::hours(1),
    );
    f.storage.create_session(&session, audit()).await.unwrap();
    // The `sub` is a pairwise identifier that is not the ProfileId.
    let pairwise = uuid::Uuid::now_v7().to_string();
    let actor = state(claims(
        Some(&f.client.client_id),
        &pairwise,
        &session.id.to_string(),
    ))
    .await;
    assert_eq!(
        actor,
        TokenState::Active(TokenActor::Profile {
            profile,
            session: session.id
        })
    );
    assert_eq!(
        TokenActor::Profile {
            profile,
            session: session.id
        }
        .subject(),
        format!("user:{profile}")
    );
}

/// A suspended machine, a disabled connector, a deactivated client, an
/// ended or expired sign-in and a token naming no client are inactive.
#[tokio::test]
async fn a_token_whose_actor_cannot_act_now_is_inactive() {
    let f = fixture().await;
    let inactive = |c| {
        let storage = &f.storage;
        async move { current_state(storage, &c).await.unwrap() == TokenState::Inactive }
    };

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
    assert!(
        inactive(claims(
            Some(&f.machine.client_id),
            &f.machine.id.to_string(),
            "kid_a"
        ))
        .await,
        "suspended machine"
    );

    assert!(
        f.storage
            .transition_provisioning_connector(
                f.connector.id,
                ConnectorState::Active,
                ConnectorState::Disabled,
                audit()
            )
            .await
            .unwrap()
    );
    assert!(
        inactive(claims(
            Some(&f.connector.client_id),
            &f.connector.id.to_string(),
            &f.connector_credential
        ))
        .await,
        "disabled connector"
    );

    let profile = stored_profile(&f.storage).await;
    let ended = SessionId::generate();
    assert!(
        inactive(claims(
            Some(&f.client.client_id),
            &profile.to_string(),
            &ended.to_string()
        ))
        .await,
        "ended sign-in"
    );
    let mut expired = Session::new(
        profile,
        "127.0.0.1".into(),
        Utc::now() + chrono::Duration::hours(1),
    );
    expired.expires_at = Utc::now() - chrono::Duration::minutes(1);
    f.storage.create_session(&expired, audit()).await.unwrap();
    assert!(
        inactive(claims(
            Some(&f.client.client_id),
            &profile.to_string(),
            &expired.id.to_string()
        ))
        .await,
        "expired sign-in"
    );
    assert!(
        inactive(claims(None, &profile.to_string(), &expired.id.to_string())).await,
        "no requesting client"
    );

    let mut client = f.client.clone();
    client.active = false;
    assert!(
        f.storage
            .update_oauth2_client(&client, audit())
            .await
            .unwrap()
    );
    assert!(
        inactive(claims(
            Some(&f.client.client_id),
            &f.client.client_id,
            &f.client.client_id
        ))
        .await,
        "deactivated client"
    );
}
