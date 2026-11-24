// SPDX-License-Identifier: AGPL-3.0-only
use jiff::Timestamp;
use secrecy::ExposeSecret;
use sid_core::models::{IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, Organization};

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
    installed_with(false).await
}

/// [`installed`], its issuer the root-addressed base issuer when `root`.
async fn installed_with(root: bool) -> Installed {
    installed_on(root, PlatformScope::default()).await
}

/// The two platforms of these tests.
const PRODUCTION: &str = "https://platform.sid.example.com";
const DEVELOPMENT: &str = "https://dev.platform.sid.example.com";

/// The issuer of some organization at `platform`: the platform's origin and
/// that organization's own issuer handle, as the platform assigns one.
fn organization_at(platform: &str) -> String {
    format!("{platform}/i/{}", IssuerHandle::generate())
}

/// [`installed`], in a build made for the platform at `build`.
async fn installed_for(build: Option<&str>) -> Installed {
    let build = build.map(|origin| url::Url::parse(origin).unwrap());
    installed_on(
        false,
        PlatformScope::new(build.as_ref(), &[PRODUCTION, DEVELOPMENT]),
    )
    .await
}

async fn installed_on(root: bool, platform: PlatformScope) -> Installed {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let org = Organization::implicit_community("sid.example.com");
    let ctx = || MutationContext::from(AuditEntry::system("test", "installation"));
    storage
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let org = storage.instance_organization().await.unwrap().unwrap().id;
    let (id, handle) = (IssuerId::generate(), IssuerHandle::generate());
    let now = Timestamp::from_millisecond(Timestamp::now().as_millisecond()).unwrap();
    let issuer = OidcIssuer {
        id,
        canonical_url: if root {
            "https://sid.example.com".to_owned()
        } else {
            format!("https://sid.example.com/i/{handle}")
        },
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
        connections: EntryConnections::new(
            storage.clone(),
            keys(),
            Arc::new(IssuerRegistry::new(storage.clone(), keys()).with_base_issuer(&issuer)),
            platform,
        ),
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
            use_return: Some(USE_RETURN.into()),
        }
    }
}

impl Installed {
    /// Provision the authority at `issuer` for this installation's issuer.
    async fn provisioned_at(&self, issuer: &str) {
        self.connections
            .provision("provisioning", &self.issuer, self.authority(issuer))
            .await
            .unwrap();
    }

    /// The issuer of the connection an entry naming none goes through.
    async fn unnamed(&self) -> Option<String> {
        let handle = self
            .connections
            .unnamed_entry(&self.issuer)
            .await
            .unwrap()?;
        let (connection, _) = self
            .connections
            .for_entry(&self.issuer, handle)
            .await
            .unwrap()
            .expect("the entry's connection is enabled");
        Some(connection.issuer)
    }
}

/// An entry that names no connection goes through the installation's
/// provisioned authority and nothing else. An administrator's connection is
/// never taken for it by where its issuer is hosted or by being the only
/// one: several issuers share a platform's origin. A build made for a
/// platform refuses an authority provisioned at another platform and falls
/// back to nothing; an authority that is no platform's, and a build made for
/// no platform, are read as stored.
/// Bug prevented: an independent connection to another issuer on the
/// platform's host chosen silently as the installation's authority; a
/// provisioned authority no longer chosen because a connection sits beside
/// it; a closed test build sending its users to production.
#[tokio::test]
async fn the_unnamed_entry_is_the_provisioned_authority_only() {
    let prod_issuer = organization_at(PRODUCTION);
    let dev_issuer = organization_at(DEVELOPMENT);
    let other_dev_issuer = organization_at(DEVELOPMENT);

    // No authority provisioned: one administrator's connection at the
    // build's platform, or several, are no unnamed entry.
    let i = installed_for(Some(DEVELOPMENT)).await;
    i.create("only", &dev_issuer).await;
    assert_eq!(i.unnamed().await, None);
    i.create("other", &other_dev_issuer).await;
    i.create("prod", &prod_issuer).await;
    assert_eq!(i.unnamed().await, None);

    // The provisioned authority is the entry, whatever is registered beside
    // it at the same origin.
    let i = installed_for(Some(DEVELOPMENT)).await;
    i.provisioned_at(&dev_issuer).await;
    assert_eq!(i.unnamed().await.as_deref(), Some(dev_issuer.as_str()));
    i.create("other", &other_dev_issuer).await;
    assert_eq!(i.unnamed().await.as_deref(), Some(dev_issuer.as_str()));

    // An authority provisioned at production: a development build has no
    // unnamed entry, and a connection registered at development does not
    // stand in for it.
    let i = installed_for(Some(DEVELOPMENT)).await;
    i.provisioned_at(&prod_issuer).await;
    assert_eq!(i.unnamed().await, None);
    i.create("dev", &dev_issuer).await;
    assert_eq!(i.unnamed().await, None);

    // The production build enters through the same authority.
    let i = installed_for(Some(PRODUCTION)).await;
    i.provisioned_at(&prod_issuer).await;
    assert_eq!(i.unnamed().await.as_deref(), Some(prod_issuer.as_str()));

    // An authority that is no platform's (an organization's own installation)
    // is the entry in every build.
    let i = installed_for(Some(DEVELOPMENT)).await;
    i.provisioned_at(PROVISIONED_ISSUER).await;
    assert_eq!(i.unnamed().await.as_deref(), Some(PROVISIONED_ISSUER));

    // A build made for no platform reads its authority as stored.
    let i = installed_for(None).await;
    i.provisioned_at(&prod_issuer).await;
    assert_eq!(i.unnamed().await.as_deref(), Some(prod_issuer.as_str()));
}

/// A connection the browser names is entered by its own registration: the
/// build's platform restricts only the entry that names none. Several
/// issuers share an origin, so an issuer at another platform's origin, or
/// another issuer at the build's, registered on its own stays offered and
/// usable, and an administrator reads every connection.
/// Bug prevented: a separately configured connection disappearing from the
/// sign-in page because its issuer shares a host with a platform.
#[tokio::test]
async fn a_named_connection_is_entered_by_its_own_registration() {
    let at_prod_origin = organization_at(PRODUCTION);
    let at_dev_origin = organization_at(DEVELOPMENT);
    for build in [Some(DEVELOPMENT), Some(PRODUCTION), None] {
        let i = installed_for(build).await;
        let registered = [
            i.create("a", &at_prod_origin).await,
            i.create("b", &at_dev_origin).await,
            i.create("c", OUTSIDE).await,
        ];
        let offered = i
            .connections
            .sign_in_connections(&i.issuer.handle.to_string())
            .await
            .unwrap()
            .connections;
        assert_eq!(offered.len(), 3, "build {build:?}");
        for connection in &registered {
            let handle = EntryHandle::parse(&connection.handle).unwrap();
            let entered = i.connections.for_entry(&i.issuer, handle).await.unwrap();
            assert_eq!(
                entered.map(|(c, _)| c.issuer),
                Some(connection.issuer.clone()),
                "build {build:?}"
            );
        }
        assert_eq!(
            i.connections
                .list(&i.admin)
                .await
                .unwrap()
                .connections
                .len(),
            3
        );
    }
}

/// Where the provisioned authority resumes a holder's use.
const USE_RETURN: &str = "https://central.sid.example.com/corporate-use/return";

/// The provisioned authority's issuer.
const PROVISIONED_ISSUER: &str =
    "https://central.sid.example.com/i/fedcba9876543210fedcba9876543210";

/// The provisioned authority keeps the use return its provisioning supplied,
/// and a repeated provisioning, even with another value, keeps the first: a
/// holder is never sent back to an address the authority did not state
/// first. An administrator's connection has none, and a value that is not
/// an https URL without query or fragment is refused, so the continuation
/// appended to it is its only parameter.
#[tokio::test]
async fn the_provisioned_use_return_is_kept_as_first_stated() {
    let i = installed().await;
    let set = i
        .connections
        .provision("provisioning", &i.issuer, i.authority(PROVISIONED_ISSUER))
        .await
        .unwrap();
    assert_eq!(set.use_return.as_deref(), Some(USE_RETURN));
    let again = i
        .connections
        .provision(
            "provisioning",
            &i.issuer,
            Provisioned {
                use_return: Some("https://elsewhere.sid.example.com/return".into()),
                ..i.authority(PROVISIONED_ISSUER)
            },
        )
        .await
        .unwrap();
    assert_eq!(again.use_return.as_deref(), Some(USE_RETURN));
    let created = i.create("create-1", OUTSIDE).await;
    let handle = EntryHandle::parse(&created.handle).unwrap();
    assert_eq!(
        i.storage
            .entry_connection(handle)
            .await
            .unwrap()
            .unwrap()
            .use_return,
        None
    );

    let other = installed().await;
    for bad in [
        "http://central.sid.example.com/return",
        "https://central.sid.example.com/return?next=1",
        "https://central.sid.example.com/return#x",
        "not a url",
    ] {
        assert!(
            matches!(
                other
                    .connections
                    .provision(
                        "provisioning",
                        &other.issuer,
                        Provisioned {
                            use_return: Some(bad.into()),
                            ..other.authority(PROVISIONED_ISSUER)
                        },
                    )
                    .await,
                Err(EntryConnectionError::InvalidField {
                    field: "use_return",
                    ..
                })
            ),
            "{bad}"
        );
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

/// The root-addressed base issuer's sign-in page reaches its connections at
/// the root route, and its handle route offers none; a scoped issuer's
/// root route offers none of its connections. The connection registers the
/// root callback, built from the issuer URL.
#[tokio::test]
async fn sign_in_connections_follow_the_issuers_route() {
    let i = installed_with(true).await;
    let created = i.create("create-root", OUTSIDE).await;
    let stored = i
        .storage
        .entry_connection(EntryHandle::parse(&created.handle).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.callback,
        "https://sid.example.com/auth/federation/callback"
    );
    let offered = |handle: String| {
        let connections = &i.connections;
        async move {
            connections
                .sign_in_connections(&handle)
                .await
                .unwrap()
                .connections
        }
    };
    assert_eq!(offered(String::new()).await.len(), 1);
    assert!(offered(i.issuer.handle.to_string()).await.is_empty());

    let i = installed().await;
    i.create("create-scoped", OUTSIDE).await;
    assert!(
        i.connections
            .sign_in_connections("")
            .await
            .unwrap()
            .connections
            .is_empty()
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
    let now = Timestamp::now().as_second();
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
        credential_kind: None,
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
