// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use secrecy::ExposeSecret as _;
use sid_core::models::{
    AuditEntry, ConnectorCredentialKind, ConnectorState, MutationContext, ProvisioningCredential,
};
use sid_storage::sqlite::SqliteBackend;
use tonic::Code;

fn audit() -> MutationContext {
    AuditEntry::system("test", "connector").into()
}

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

/// A stored connector of `org` in `direction` with one credential; returns
/// the connector and the credential's secret.
async fn connector_with_secret(
    storage: &SqliteBackend,
    org: OrgId,
    direction: ProvisioningDirection,
) -> (ProvisioningConnector, ProvisioningCredential, String) {
    let connector = ProvisioningConnector::new(org, direction, "Directory sync");
    storage
        .create_provisioning_connector(&connector, audit())
        .await
        .unwrap();
    let issued = bearer_secret::issue(SCIM_BEARER_PREFIX);
    let credential = ProvisioningCredential::new(
        connector.id,
        ConnectorCredentialKind::ScimBearer,
        issued.verifier.clone(),
    );
    assert!(
        storage
            .add_provisioning_credential(&credential, audit())
            .await
            .unwrap()
    );
    (connector, credential, issued.secret.expose_secret().clone())
}

fn bearing(token: &str) -> Request<()> {
    let mut request = Request::new(());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn refused(storage: &SqliteBackend, org: OrgId, token: &str) {
    let err = authenticate_connector(&bearing(token), storage, org, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "{token}: {err:?}");
}

/// The secret of an active inbound connector of the endpoint's organization
/// authenticates that connector and names the credential used.
#[tokio::test]
async fn a_connector_secret_authenticates_its_connector() {
    let storage = storage().await;
    let org = OrgId::generate();
    let (connector, credential, secret) =
        connector_with_secret(&storage, org, ProvisioningDirection::Inbound).await;
    let caller = authenticate_connector(&bearing(&secret), &storage, org, None)
        .await
        .unwrap();
    assert_eq!(caller.connector.id, connector.id);
    assert_eq!(caller.credential_id, credential.id);
    // A SCIM bearer carries no token scopes: its grants alone decide.
    assert!(caller.scopes.is_none());
    assert!(caller.may("scim.user.create"));
}

/// A token's scopes limit its caller beside the grants.
#[test]
fn token_scopes_limit_the_caller() {
    let caller = ConnectorCaller {
        connector: ProvisioningConnector::new(
            OrgId::generate(),
            ProvisioningDirection::Inbound,
            "HR",
        ),
        credential_id: ProvisioningCredentialId::generate(),
        scopes: Some(vec!["scim.user.read".into()]),
    };
    assert!(caller.may("scim.user.read"));
    assert!(!caller.may("scim.user.create"));
}

/// A stored credential of `kind` of `connector` with a secret of `prefix`;
/// returns its secret.
async fn credential_of(
    storage: &SqliteBackend,
    connector: &ProvisioningConnector,
    kind: ConnectorCredentialKind,
    prefix: &str,
) -> String {
    let issued = bearer_secret::issue(prefix);
    assert!(
        storage
            .add_provisioning_credential(
                &ProvisioningCredential::new(connector.id, kind, issued.verifier.clone()),
                audit(),
            )
            .await
            .unwrap()
    );
    issued.secret.expose_secret().clone()
}

/// A client secret is no SCIM bearer, even one shaped like a bearer: the
/// kind is checked, not only the prefix.
#[tokio::test]
async fn a_client_secret_is_no_scim_bearer() {
    let storage = storage().await;
    let org = OrgId::generate();
    let connector = ProvisioningConnector::new(org, ProvisioningDirection::Inbound, "HR");
    storage
        .create_provisioning_connector(&connector, audit())
        .await
        .unwrap();
    let shaped = credential_of(
        &storage,
        &connector,
        ConnectorCredentialKind::ClientSecret,
        SCIM_BEARER_PREFIX,
    )
    .await;
    refused(&storage, org, &shaped).await;
    let client_secret = credential_of(
        &storage,
        &connector,
        ConnectorCredentialKind::ClientSecret,
        CONNECTOR_CLIENT_SECRET_PREFIX,
    )
    .await;
    refused(&storage, org, &client_secret).await;
}

/// At the token endpoint a connector authenticates with its client_id and a
/// client secret of its own; another client_id is not a connector's (the
/// endpoint tries its other clients); a bearer, another connector's secret,
/// a wrong secret, and a disabled connector are refused.
#[tokio::test]
async fn a_connector_client_authenticates_with_its_client_secret() {
    let storage = storage().await;
    let org = OrgId::generate();
    let (connector, _, bearer) =
        connector_with_secret(&storage, org, ProvisioningDirection::Inbound).await;
    let secret = credential_of(
        &storage,
        &connector,
        ConnectorCredentialKind::ClientSecret,
        CONNECTOR_CLIENT_SECRET_PREFIX,
    )
    .await;
    let caller = authenticate_connector_client(&storage, org, &connector.client_id, &secret)
        .await
        .unwrap()
        .expect("a connector client");
    assert_eq!(caller.connector.id, connector.id);

    assert!(
        authenticate_connector_client(&storage, org, "mu_not_a_connector", &secret)
            .await
            .unwrap()
            .is_none()
    );
    let (other, _, _) = connector_with_secret(&storage, org, ProvisioningDirection::Inbound).await;
    let others = credential_of(
        &storage,
        &other,
        ConnectorCredentialKind::ClientSecret,
        CONNECTOR_CLIENT_SECRET_PREFIX,
    )
    .await;
    let mut wrong = secret.clone();
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'A' { 'B' } else { 'A' });
    for presented in [bearer.as_str(), others.as_str(), wrong.as_str()] {
        let err = authenticate_connector_client(&storage, org, &connector.client_id, presented)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated, "{presented}");
    }
    let err =
        authenticate_connector_client(&storage, OrgId::generate(), &connector.client_id, &secret)
            .await
            .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "another organization");

    assert!(
        storage
            .transition_provisioning_connector(
                connector.id,
                ConnectorState::Active,
                ConnectorState::Disabled,
                audit()
            )
            .await
            .unwrap()
    );
    let err = authenticate_connector_client(&storage, org, &connector.client_id, &secret)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "disabled");
}

/// No bearer, a bearer of another kind, an unknown secret, and a secret with
/// one character changed are refused alike.
#[tokio::test]
async fn anything_but_a_stored_secret_is_refused() {
    let storage = storage().await;
    let org = OrgId::generate();
    let (_, _, secret) = connector_with_secret(&storage, org, ProvisioningDirection::Inbound).await;
    let err = authenticate_connector(&Request::new(()), &storage, org, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    let mut altered = secret.clone();
    let last = altered.pop().unwrap();
    altered.push(if last == 'A' { 'B' } else { 'A' });
    let unknown = bearer_secret::issue(SCIM_BEARER_PREFIX);
    for token in [
        "eyJhbGciOiJFZERTQSJ9.e30.c2ln".to_owned(),
        SCIM_BEARER_PREFIX.to_owned(),
        secret.trim_start_matches(SCIM_BEARER_PREFIX).to_owned(),
        unknown.secret.expose_secret().clone(),
        altered,
    ] {
        refused(&storage, org, &token).await;
    }
}

/// The endpoint serves one organization: another organization's connector
/// is refused, and so is an outbound connector, whose credentials SID never
/// accepts back.
#[tokio::test]
async fn only_an_inbound_connector_of_this_organization_is_accepted() {
    let storage = storage().await;
    let org = OrgId::generate();
    let (_, _, foreign) =
        connector_with_secret(&storage, OrgId::generate(), ProvisioningDirection::Inbound).await;
    let (_, _, outbound) =
        connector_with_secret(&storage, org, ProvisioningDirection::Outbound).await;
    refused(&storage, org, &foreign).await;
    refused(&storage, org, &outbound).await;
}

/// A disabled or retired connector, and a revoked or expired credential, no
/// longer authenticate; enabling the connector again restores its secret.
#[tokio::test]
async fn an_unusable_connector_or_credential_is_refused() {
    let storage = storage().await;
    let org = OrgId::generate();
    let (connector, credential, secret) =
        connector_with_secret(&storage, org, ProvisioningDirection::Inbound).await;

    assert!(
        storage
            .transition_provisioning_connector(
                connector.id,
                ConnectorState::Active,
                ConnectorState::Disabled,
                audit()
            )
            .await
            .unwrap()
    );
    refused(&storage, org, &secret).await;
    assert!(
        storage
            .transition_provisioning_connector(
                connector.id,
                ConnectorState::Disabled,
                ConnectorState::Active,
                audit()
            )
            .await
            .unwrap()
    );
    authenticate_connector(&bearing(&secret), &storage, org, None)
        .await
        .unwrap();

    assert!(
        storage
            .revoke_provisioning_credential(connector.id, credential.id, audit())
            .await
            .unwrap()
    );
    refused(&storage, org, &secret).await;

    let issued = bearer_secret::issue(SCIM_BEARER_PREFIX);
    let mut expired = ProvisioningCredential::new(
        connector.id,
        ConnectorCredentialKind::ScimBearer,
        issued.verifier.clone(),
    );
    expired.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
    assert!(
        storage
            .add_provisioning_credential(&expired, audit())
            .await
            .unwrap()
    );
    refused(&storage, org, issued.secret.expose_secret()).await;

    let (retiring, _, retiring_secret) =
        connector_with_secret(&storage, org, ProvisioningDirection::Inbound).await;
    assert!(
        storage
            .transition_provisioning_connector(
                retiring.id,
                ConnectorState::Active,
                ConnectorState::Retired,
                audit()
            )
            .await
            .unwrap()
    );
    refused(&storage, org, &retiring_secret).await;
}

/// Verified claims of an access token issued to `client_id` naming `sub`
/// and the credential `sid`.
fn claims(client_id: &str, sub: &str, sid: &str) -> AccessTokenClaims {
    let now = Utc::now().timestamp();
    AccessTokenClaims {
        sub: sub.into(),
        pid: None,
        aud: vec!["https://sid.example.com/scim/v2".into()],
        client_id: Some(client_id.into()),
        iss: "https://sid.example.com".into(),
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: String::new(),
        scope: "scim.user.read".into(),
        roles: String::new(),
        amr: Vec::new(),
        sid: sid.into(),
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
    }
}

/// The state read for a verified token: a client that is no connector, a
/// connector token that cannot act now, and one that can. Introspection
/// relies on telling the first two apart.
#[tokio::test]
async fn connector_token_state_tells_connector_tokens_apart() {
    let storage = storage().await;
    let org = OrgId::generate();
    let connector = ProvisioningConnector::new(org, ProvisioningDirection::Inbound, "HR");
    storage
        .create_provisioning_connector(&connector, audit())
        .await
        .unwrap();
    let issued = bearer_secret::issue(CONNECTOR_CLIENT_SECRET_PREFIX);
    let credential = ProvisioningCredential::new(
        connector.id,
        ConnectorCredentialKind::ClientSecret,
        issued.verifier.clone(),
    );
    assert!(
        storage
            .add_provisioning_credential(&credential, audit())
            .await
            .unwrap()
    );
    let subject = connector.id.to_string();
    let used = credential.id.to_string();
    let state = |claims: AccessTokenClaims| {
        let storage = &storage;
        async move { connector_token_state(storage, &claims).await.unwrap() }
    };

    match state(claims(&connector.client_id, &subject, &used)).await {
        ConnectorTokenState::Usable(caller) => {
            assert_eq!(caller.connector.id, connector.id);
            assert_eq!(caller.credential_id, credential.id);
            assert!(caller.may("scim.user.read"));
        }
        other => panic!("usable connector token: {other:?}"),
    }
    assert!(matches!(
        state(claims("orders-web", &subject, &used)).await,
        ConnectorTokenState::NotConnector
    ));
    for (case, sub, sid) in [
        (
            "another subject",
            "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e",
            used.as_str(),
        ),
        ("unknown credential", subject.as_str(), "kid_missing"),
    ] {
        assert!(
            matches!(
                state(claims(&connector.client_id, sub, sid)).await,
                ConnectorTokenState::Unusable
            ),
            "{case}"
        );
    }
    assert!(
        storage
            .transition_provisioning_connector(
                connector.id,
                ConnectorState::Active,
                ConnectorState::Disabled,
                audit()
            )
            .await
            .unwrap()
    );
    assert!(matches!(
        state(claims(&connector.client_id, &subject, &used)).await,
        ConnectorTokenState::Unusable
    ));
}
