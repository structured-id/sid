// SPDX-License-Identifier: AGPL-3.0-only
use chrono::{SubsecRound, Utc};
use secrecy::ExposeSecret;
use sid_core::models::{IssuerAuthority, IssuerId, IssuerSigningKey, Organization};

use super::*;
use crate::test_support::{administrator, keys, operation, storage, stored_profile};

const OUTSIDE: &str = "https://source.sid.example.com/i/0123456789abcdef0123456789abcdef";

/// An installation with one issuer, its connections and an administrator.
struct Installed {
    storage: Arc<dyn StorageBackend>,
    connections: EntryConnections,
    issuer: OidcIssuer,
    admin: Caller,
}

async fn installed() -> Installed {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let org = Organization::implicit_community("sid.example.com");
    let ctx = || MutationContext::from(AuditEntry::system("test", "installation"));
    storage
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let org = storage.instance_organization().await.unwrap().unwrap().id;
    let (id, handle) = (IssuerId::generate(), IssuerHandle::generate());
    let now = Utc::now().trunc_subsecs(3);
    let issuer = OidcIssuer {
        id,
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org,
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: id,
        generation: 1,
        key_id: format!("kid-{id}"),
        public_key: [9; 32],
        sealed_private_key: vec![1, 2, 3, 4],
        created_at: now,
    };
    assert!(
        storage
            .insert_oidc_issuer(&issuer, &key, ctx())
            .await
            .unwrap()
    );
    let admin = administrator(stored_profile(storage.as_ref(), "admin").await);
    Installed {
        connections: EntryConnections::new(storage.clone(), keys()),
        storage,
        issuer,
        admin,
    }
}

impl Installed {
    fn request(&self, issuer: &str) -> CreateEntryConnectionRequest {
        CreateEntryConnectionRequest {
            name: "Source organization".into(),
            issuer: issuer.into(),
            source_organization: None,
            issuer_handle: self.issuer.handle.to_string(),
            client_id: "recipient-client".into(),
            client_secret: "client secret".into(),
            enabled: true,
        }
    }

    async fn create(&self, key: &str, issuer: &str) -> v1::EntryConnection {
        self.connections
            .create(
                &self.admin,
                operation(self.storage.as_ref(), key).await,
                self.request(issuer),
            )
            .await
            .unwrap()
    }

    async fn update(
        &self,
        key: &str,
        req: UpdateEntryConnectionRequest,
    ) -> Result<v1::EntryConnection, EntryConnectionError> {
        self.connections
            .update(
                &self.admin,
                operation(self.storage.as_ref(), key).await,
                req,
            )
            .await
    }

    fn authority(&self, issuer: &str) -> Provisioned {
        Provisioned {
            name: "Our organization".into(),
            issuer: issuer.into(),
            source: None,
            client_id: "installation-client".into(),
            client_secret: SecretString::from("provisioned secret".to_owned()),
        }
    }
}

/// A registration answers with the callback to register at the issuer, the
/// connection's own; the entry then authenticates with the secret given, and
/// no answer carries it. Bug prevented: a callback shared by connections, or
/// a credential returned to a reader.
#[tokio::test]
async fn a_registered_connection_serves_an_entry() {
    let i = installed().await;
    let created = i.create("create-1", OUTSIDE).await;
    let handle = EntryHandle::parse(&created.handle).unwrap();
    assert_eq!(
        created.callback,
        format!("{}/auth/federation/callback", i.issuer.canonical_url)
    );
    assert_eq!(created.issuer_handle, i.issuer.handle.to_string());
    assert_eq!(
        created.owner,
        v1::EntryConnectionOwner::Administration as i32
    );
    assert_eq!(created.revision, 0);

    let (connection, trusted) = i
        .connections
        .for_entry(&i.issuer, handle)
        .await
        .unwrap()
        .expect("an enabled connection");
    assert_eq!(connection.callback, created.callback);
    assert_eq!(trusted.issuer, OUTSIDE);
    assert_eq!(trusted.client_id, "recipient-client");
    assert_eq!(trusted.client_secret.expose_secret(), "client secret");
    // Stored sealed, never as given.
    let ClientCredential::SecretBasic(sealed) = &connection.credential;
    assert!(
        !sealed
            .to_bytes()
            .windows(b"client secret".len())
            .any(|w| w == b"client secret")
    );

    let listed = i.connections.list(&i.admin).await.unwrap().connections;
    assert_eq!(listed, vec![created.clone()]);
    let offered = i
        .connections
        .sign_in_connections(i.issuer.handle.as_str())
        .await
        .unwrap()
        .connections;
    assert_eq!(
        offered,
        vec![SignInConnection {
            handle: created.handle,
            name: created.name,
        }]
    );
}

/// A retried registration answers with the connection the first made; a
/// second registration of the same issuer under another key is refused.
/// Bug prevented: a lost reply registering the issuer twice, or two
/// connections holding identities of one issuer.
#[tokio::test]
async fn one_issuer_is_registered_once() {
    let i = installed().await;
    let first = i.create("create-1", OUTSIDE).await;
    assert_eq!(i.create("create-1", OUTSIDE).await, first);
    let again = i
        .connections
        .create(
            &i.admin,
            operation(i.storage.as_ref(), "create-2").await,
            i.request(OUTSIDE),
        )
        .await;
    assert!(matches!(again, Err(EntryConnectionError::IssuerTaken)));
    assert_eq!(
        i.connections
            .list(&i.admin)
            .await
            .unwrap()
            .connections
            .len(),
        1
    );
}

/// What a registration must name is checked before anything is written.
#[tokio::test]
async fn a_malformed_registration_writes_nothing() {
    let i = installed().await;
    let refused = |req: CreateEntryConnectionRequest| async {
        i.connections
            .create(&i.admin, operation(i.storage.as_ref(), "bad").await, req)
            .await
            .unwrap_err()
    };
    let mut req = i.request(OUTSIDE);
    req.issuer = "http://source.sid.example.com".into();
    assert!(matches!(
        refused(req).await,
        EntryConnectionError::InvalidField {
            field: "issuer",
            ..
        }
    ));
    let mut req = i.request(OUTSIDE);
    req.client_secret.clear();
    assert!(matches!(
        refused(req).await,
        EntryConnectionError::MissingField("client_secret")
    ));
    let mut req = i.request(OUTSIDE);
    req.name = "n".repeat(MAX_NAME + 1);
    assert!(matches!(
        refused(req).await,
        EntryConnectionError::InvalidField { field: "name", .. }
    ));
    let mut req = i.request(OUTSIDE);
    req.issuer_handle = IssuerHandle::generate().to_string();
    assert!(matches!(
        refused(req).await,
        EntryConnectionError::UnknownIssuer(_)
    ));
    assert!(
        i.connections
            .list(&i.admin)
            .await
            .unwrap()
            .connections
            .is_empty()
    );
}

/// A change applies over the revision it names and moves it on; a disabled
/// connection serves no entry and is not offered; a rotated secret is the
/// one the next entry uses. Bug prevented: a stale editor overwriting a
/// later change, or an entry completing through a disabled connection.
#[tokio::test]
async fn a_change_applies_over_its_revision() {
    let i = installed().await;
    let created = i.create("create-1", OUTSIDE).await;
    let handle = EntryHandle::parse(&created.handle).unwrap();
    let rotated = i
        .update(
            "update-1",
            UpdateEntryConnectionRequest {
                handle: created.handle.clone(),
                revision: 0,
                client_secret: Some("rotated secret".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(rotated.revision, 1);
    assert_eq!(rotated.callback, created.callback);
    let (_, trusted) = i
        .connections
        .for_entry(&i.issuer, handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trusted.client_secret.expose_secret(), "rotated secret");

    // Decided on the revision the first change moved on.
    let stale = i
        .update(
            "update-2",
            UpdateEntryConnectionRequest {
                handle: created.handle.clone(),
                revision: 0,
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        stale,
        Err(EntryConnectionError::ChangedConcurrently)
    ));

    let disabled = i
        .update(
            "update-3",
            UpdateEntryConnectionRequest {
                handle: created.handle.clone(),
                revision: 1,
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!((disabled.revision, disabled.enabled), (2, false));
    assert!(
        i.connections
            .for_entry(&i.issuer, handle)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        i.connections
            .sign_in_connections(i.issuer.handle.as_str())
            .await
            .unwrap()
            .connections
            .is_empty()
    );
    // The retry of the completed change answers as it did.
    let retried = i
        .update(
            "update-3",
            UpdateEntryConnectionRequest {
                handle: created.handle,
                revision: 1,
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(retried, disabled);
}

/// A removal names the revision it read; a repeat of a completed removal
/// answers as the first.
#[tokio::test]
async fn a_removal_applies_over_its_revision() {
    let i = installed().await;
    let created = i.create("create-1", OUTSIDE).await;
    let remove = |revision| {
        i.connections.remove(
            &i.admin,
            RemoveEntryConnectionRequest {
                handle: created.handle.clone(),
                revision,
            },
        )
    };
    assert!(matches!(
        remove(7).await,
        Err(EntryConnectionError::ChangedConcurrently)
    ));
    remove(0).await.unwrap();
    remove(0).await.unwrap();
    assert!(
        i.connections
            .list(&i.admin)
            .await
            .unwrap()
            .connections
            .is_empty()
    );
}

/// The provisioned authority is set once: the same issuer again answers
/// with it as it is, another issuer is refused, and an administrator's
/// command reads it but never changes or removes it. Bug prevented: an
/// administrator, or a repeated provisioning, replacing the authority the
/// installation's own Profiles sign in through.
#[tokio::test]
async fn the_provisioned_authority_is_set_once_and_not_an_administrators() {
    let i = installed().await;
    const AUTHORITY: &str = "https://platform.sid.example.com/i/fedcba9876543210fedcba9876543210";
    assert!(
        i.connections
            .provisioned(&i.issuer)
            .await
            .unwrap()
            .is_none()
    );
    let set = i
        .connections
        .provision("installation", &i.issuer, i.authority(AUTHORITY))
        .await
        .unwrap();
    assert_eq!(set.owner, ConnectionOwner::Provisioning);
    assert!(set.enabled);
    assert_eq!(
        i.connections.provisioned(&i.issuer).await.unwrap(),
        Some(set.clone())
    );
    // Again, with another secret: nothing is overwritten.
    let mut again = i.authority(AUTHORITY);
    again.client_secret = SecretString::from("another".to_owned());
    assert_eq!(
        i.connections
            .provision("installation", &i.issuer, again)
            .await
            .unwrap(),
        set
    );
    assert!(matches!(
        i.connections
            .provision("installation", &i.issuer, i.authority(OUTSIDE))
            .await,
        Err(EntryConnectionError::Established)
    ));

    let handle = set.handle.to_string();
    let listed = i.connections.list(&i.admin).await.unwrap().connections;
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].owner,
        v1::EntryConnectionOwner::Provisioning as i32
    );
    let changed = i
        .connections
        .update(
            &i.admin,
            operation(i.storage.as_ref(), "update-1").await,
            UpdateEntryConnectionRequest {
                handle: handle.clone(),
                revision: 0,
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(changed, Err(EntryConnectionError::Provisioned)));
    let removed = i
        .connections
        .remove(
            &i.admin,
            RemoveEntryConnectionRequest {
                handle,
                revision: 0,
            },
        )
        .await;
    assert!(matches!(removed, Err(EntryConnectionError::Provisioned)));
    // An administrator cannot register the authority's issuer either.
    let taken = i
        .connections
        .create(
            &i.admin,
            operation(i.storage.as_ref(), "create-1").await,
            i.request(AUTHORITY),
        )
        .await;
    assert!(matches!(taken, Err(EntryConnectionError::IssuerTaken)));
    assert_eq!(
        i.connections.provisioned(&i.issuer).await.unwrap(),
        Some(set)
    );
}

/// Provisioning never takes over a connection an administrator registered.
#[tokio::test]
async fn provisioning_does_not_take_an_administrators_connection() {
    let i = installed().await;
    let created = i.create("create-1", OUTSIDE).await;
    assert!(matches!(
        i.connections
            .provision("installation", &i.issuer, i.authority(OUTSIDE))
            .await,
        Err(EntryConnectionError::IssuerTaken)
    ));
    assert!(
        i.connections
            .provisioned(&i.issuer)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        i.connections.list(&i.admin).await.unwrap().connections,
        vec![created]
    );
}

/// Only an administrator reads or writes the connections.
#[tokio::test]
async fn a_caller_without_the_administrator_role_is_refused() {
    let i = installed().await;
    let profile = stored_profile(i.storage.as_ref(), "user").await;
    let now = Utc::now().timestamp();
    let user = Caller::from_claims(&sid_authn::jwt::AccessTokenClaims {
        sub: profile.to_string(),
        pid: Some(profile.to_string()),
        iss: "https://sid.example.com".into(),
        aud: vec!["https://sid.example.com".into()],
        client_id: None,
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: String::new(),
        sid: uuid::Uuid::now_v7().to_string(),
        amr: vec!["pwd".into()],
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
    })
    .unwrap();
    assert!(matches!(
        i.connections.list(&user).await,
        Err(EntryConnectionError::Caller(_))
    ));
    let created = i
        .connections
        .create(
            &user,
            operation(i.storage.as_ref(), "create-1").await,
            i.request(OUTSIDE),
        )
        .await;
    assert!(matches!(created, Err(EntryConnectionError::Caller(_))));
}
