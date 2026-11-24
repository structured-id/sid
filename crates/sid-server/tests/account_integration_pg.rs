// SPDX-License-Identifier: AGPL-3.0-only
//! The account integration provisioned on PostgreSQL by replicas starting
//! together: one integration, one client, its access, whatever the race.
//! Each run gets an installation of its own, since the integration is a
//! singleton of the database it lives in.

mod common;

use jiff::Timestamp;
use sid_authn::system_integration::{
    AccountSettings, account_integration, ensure_account_integration,
};
use sid_core::models::{
    AuditEntry, ClientKeySet, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey,
    OidcIssuer, SystemIntegration,
};
use sid_plugin::IssuerStore;
use sid_plugin::storage::StorageBackend;
use sid_storage::PostgresBackend;
use std::sync::Arc;

/// The installation organization's local issuer in `storage`.
async fn issuer(storage: &PostgresBackend) -> OidcIssuer {
    let org = sid_authn::instance_org::ensure(storage, "sid.example.com")
        .await
        .unwrap();
    let now = Timestamp::from_millisecond(Timestamp::now().as_millisecond()).unwrap();
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("https://sid.example.com/i/{handle}"),
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
        .insert_oidc_issuer(&issuer, &key, AuditEntry::system("test", "issuer").into())
        .await
        .unwrap();
    issuer
}

/// Four replicas start at once: every one of them ends with the same
/// application, client and resource, the database holds one integration
/// and one client, and the client has its access.
#[tokio::test]
async fn replicas_starting_together_provision_one_integration() {
    sid_storage::testing::in_isolated_postgres(|storage| {
        replicas_provision_one_integration(Arc::new(storage))
    })
    .await;
}

async fn replicas_provision_one_integration(storage: Arc<PostgresBackend>) {
    let issuer = issuer(&storage).await;
    let keys = ClientKeySet::from_json(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"bff"}]}"#,
    )
    .unwrap();
    let settings = AccountSettings::new("https://account.sid.example.com", keys).unwrap();

    let starts = (0..4).map(|_| {
        let storage = storage.clone();
        let issuer = issuer.clone();
        let settings = settings.clone();
        tokio::spawn(async move {
            ensure_account_integration(
                storage.as_ref(),
                &issuer,
                "https://sid.example.com",
                &settings,
            )
            .await
        })
    });
    let results: Vec<_> = futures::future::join_all(starts).await;
    let provisioned: Vec<_> = results
        .into_iter()
        .map(|joined| joined.unwrap().unwrap())
        .collect();
    let first = &provisioned[0];
    for other in &provisioned[1..] {
        assert_eq!(other.application.id, first.application.id);
        assert_eq!(other.client.client_id, first.client.client_id);
        assert_eq!(other.resource.id, first.resource.id);
    }

    let stored = account_integration(storage.as_ref())
        .await
        .unwrap()
        .expect("provisioned");
    assert!(stored.is_ready());
    assert_eq!(stored.application.system, Some(SystemIntegration::Account));
    assert_eq!(storage.list_oauth2_clients(0, 100).await.unwrap().len(), 1);
}
