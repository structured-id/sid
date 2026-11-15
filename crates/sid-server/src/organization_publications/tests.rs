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

/// A connection whose issuer names no publication (a loopback HTTP issuer
/// of development) is one failed candidate, not the end of the lookup: the
/// organization's other connections are still tried, enabled ones first.
/// Bug prevented: one such connection, even a disabled one, keeping every
/// healthy publication of the organization from being read.
#[tokio::test]
async fn a_connection_without_a_publication_does_not_hide_the_others() {
    // A publication's HTTPS client needs the process's TLS provider, as the
    // server installs it at start.
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        sid_crypto::tls::aws_lc::provider()
            .install_default()
            .expect("the test process's only TLS provider");
    });
    let store = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let audit = || AuditEntry::system("test", "entry_connection").into();
    let source = OrgId::generate();
    let mut development = connection("http://127.0.0.1:8080/i/0123456789abcdef", Some(source));
    development.enabled = false;
    store
        .create_entry_connection(&development, audit())
        .await
        .unwrap();
    store
        .create_entry_connection(
            &connection(
                "https://source.sid.example.com/i/0123456789abcdef",
                Some(source),
            ),
            audit(),
        )
        .await
        .unwrap();
    let candidates = ConnectedPublications::new(store)
        .publications(source.into_uuid())
        .await
        .expect("the organization's connections are read");
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates[0].is_ok(),
        "the enabled HTTPS one first: {:?}",
        candidates[0].as_ref().err()
    );
    assert!(candidates[1].is_err(), "the HTTP one names no publication");
}
