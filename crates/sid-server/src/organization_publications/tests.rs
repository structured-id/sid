use chrono::{SubsecRound, Utc};
use sid_core::models::{
    AuditEntry, ClientCredential, ConnectionOwner, EntryConnection, EntryHandle, IssuerId, OrgId,
};
use sid_keys::EncryptedField;

use super::*;

/// A connection to `issuer` bringing identities of `source`.
fn connection(issuer: &str, source: Option<OrgId>) -> EntryConnection {
    let now = Utc::now().trunc_subsecs(6);
    EntryConnection {
        handle: EntryHandle::generate(),
        owner: ConnectionOwner::Administration,
        name: "Source".into(),
        issuer: issuer.into(),
        source,
        recipient_issuer: IssuerId::generate(),
        callback: "https://sid.example.com/auth/federation/callback".into(),
        client_id: "client".into(),
        credential: ClientCredential::SecretBasic(EncryptedField {
            ciphertext: vec![1; 48],
            nonce: [1; 12],
            key_version: 1,
            context: "entry-connection:test".into(),
        }),
        enabled: true,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

/// An organization is located only through a connection registered for
/// exactly it: none is no location, and the platform's connection, which
/// brings several organizations' identities, locates none of them. A
/// located organization's publication is read at its installation's
/// origin, and a failure to read it is an error, never "no list". Bug
/// prevented: an organization's list read from the platform or from another
/// organization's installation.
#[tokio::test]
async fn an_organization_is_read_only_where_it_is_connected() {
    let store = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let audit = || AuditEntry::system("test", "entry_connection").into();
    let source = OrgId::generate();
    store
        .create_entry_connection(
            &connection(
                "https://sid.example.com/i/0123456789abcdef0123456789abcdef",
                None,
            ),
            audit(),
        )
        .await
        .unwrap();
    let publications = ConnectedPublications::new(store.clone());
    assert_eq!(publications.fetch(source.into_uuid()).await, Ok(None));

    // Registered for the organization at an origin that does not answer.
    store
        .create_entry_connection(
            &connection("https://127.0.0.1:1/i/0123456789abcdef", Some(source)),
            audit(),
        )
        .await
        .unwrap();
    assert!(publications.fetch(source.into_uuid()).await.is_err());
    assert_eq!(publications.fetch(Uuid::now_v7()).await, Ok(None));
}
