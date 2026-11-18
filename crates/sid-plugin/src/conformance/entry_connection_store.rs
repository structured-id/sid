// SPDX-License-Identifier: AGPL-3.0-only
//! [`EntryConnectionStore`] scenarios: what every store of the registered
//! entry connections owes its caller. Each scenario needs a store that
//! holds no connection yet.

use crate::conformance::trunc;
use jiff::{SignedDuration, Timestamp, Unit};
use sid_core::Error;
use sid_core::models::{
    AuditEntry, ClientCredential, ConnectionOwner, EntryConnection, EntryHandle, IssuerId,
    MutationContext, OrgId,
};
use sid_keys::EncryptedField;

use crate::entry_connection::EntryConnectionStore;

fn audit() -> MutationContext {
    AuditEntry::system("conformance", "entry_connection").into()
}

fn sealed(seed: u8) -> ClientCredential {
    ClientCredential::SecretBasic(EncryptedField {
        ciphertext: vec![seed; 48],
        nonce: [seed; 12],
        key_version: 1,
        context: "entry-connection:conformance".into(),
    })
}

/// A new connection to the issuer named by `n`, owned by `owner`.
fn connection(n: u8, owner: ConnectionOwner) -> EntryConnection {
    // Stores keep times to the microsecond.
    let now = trunc(Timestamp::now(), Unit::Microsecond);
    EntryConnection {
        handle: EntryHandle::generate(),
        owner,
        name: format!("Source {n}"),
        issuer: format!("https://source{n}.sid.example.com/i/0123456789abcdef0123456789abcdef"),
        source: (n % 2 == 1).then(OrgId::generate),
        recipient_issuer: IssuerId::generate(),
        callback: format!("https://sid.example.com/i/handle/auth/federation/{n}/callback"),
        // Kept as given and absent as absent: provisioning sets one, an
        // administrator's connection has none.
        use_return: (owner == ConnectionOwner::Provisioning)
            .then(|| format!("https://source{n}.sid.example.com/corporate-use/return")),
        client_id: format!("client-{n}"),
        credential: sealed(n),
        enabled: true,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

/// A connection reads back exactly as stored, by its handle and by its
/// issuer; another handle or issuer names nothing. Both owners and both
/// shapes of the source are kept.
pub async fn a_connection_reads_back_as_stored(store: &dyn EntryConnectionStore) {
    assert!(store.list_entry_connections().await.unwrap().is_empty());
    let external = connection(1, ConnectionOwner::Administration);
    let own = connection(2, ConnectionOwner::Provisioning);
    for held in [&external, &own] {
        store.create_entry_connection(held, audit()).await.unwrap();
        assert_eq!(
            store.entry_connection(held.handle).await.unwrap().as_ref(),
            Some(held)
        );
        assert_eq!(
            store
                .entry_connection_of_issuer(&held.issuer)
                .await
                .unwrap()
                .as_ref(),
            Some(held)
        );
    }
    assert_eq!(
        store
            .entry_connection(EntryHandle::generate())
            .await
            .unwrap(),
        None
    );
    // An issuer is matched exactly, not by prefix or case.
    for near in [
        external.issuer.to_uppercase(),
        format!("{}/", external.issuer),
        external.issuer[..external.issuer.len() - 1].to_owned(),
    ] {
        assert_eq!(store.entry_connection_of_issuer(&near).await.unwrap(), None);
    }
}

/// Bug prevented: a second registration standing beside the first for the
/// same issuer, so an identity recorded under that issuer would be reached
/// through either. An existing handle or issuer is refused and the held
/// connection is untouched.
pub async fn one_issuer_has_one_connection(store: &dyn EntryConnectionStore) {
    let held = connection(1, ConnectionOwner::Provisioning);
    store.create_entry_connection(&held, audit()).await.unwrap();

    let mut same_issuer = connection(3, ConnectionOwner::Administration);
    same_issuer.issuer = held.issuer.clone();
    assert!(matches!(
        store.create_entry_connection(&same_issuer, audit()).await,
        Err(Error::Conflict(_))
    ));
    let mut same_handle = connection(4, ConnectionOwner::Administration);
    same_handle.handle = held.handle;
    assert!(matches!(
        store.create_entry_connection(&same_handle, audit()).await,
        Err(Error::Conflict(_))
    ));
    assert_eq!(store.list_entry_connections().await.unwrap(), vec![held]);
}

/// Connections are listed oldest first, then by handle, whatever their
/// state.
pub async fn connections_are_listed_in_one_order(store: &dyn EntryConnectionStore) {
    let mut expected = Vec::new();
    for n in 1..=4u8 {
        let mut held = connection(n, ConnectionOwner::Administration);
        held.created_at -= SignedDuration::from_secs(i64::from(10 - n / 2));
        held.updated_at = held.created_at;
        held.enabled = n % 2 == 0;
        store.create_entry_connection(&held, audit()).await.unwrap();
        expected.push(held);
    }
    expected.sort_by_key(|c| (c.created_at, c.handle));
    assert_eq!(store.list_entry_connections().await.unwrap(), expected);
}

/// A change is written over the revision it was read at and moves it on; a
/// change made over an older revision writes nothing. Bug prevented: two
/// administrators' changes of one connection, the later silently undoing
/// the earlier (a disabled connection enabled again by a rename).
pub async fn a_change_applies_over_the_revision_it_read(store: &dyn EntryConnectionStore) {
    let held = connection(1, ConnectionOwner::Administration);
    store.create_entry_connection(&held, audit()).await.unwrap();

    let mut disabled = held.clone();
    disabled.enabled = false;
    disabled.updated_at += SignedDuration::from_secs(1);
    assert!(
        store
            .update_entry_connection(&disabled, audit())
            .await
            .unwrap()
    );
    let stored = store.entry_connection(held.handle).await.unwrap().unwrap();
    assert_eq!(stored.revision, 1);
    assert!(!stored.enabled);

    // Read before the disabling: its rename is refused, nothing changes.
    let mut renamed = held.clone();
    renamed.name = "Renamed".into();
    assert!(
        !store
            .update_entry_connection(&renamed, audit())
            .await
            .unwrap()
    );
    assert_eq!(
        store.entry_connection(held.handle).await.unwrap(),
        Some(stored.clone())
    );

    // Over the revision it read, the rename and a rotated credential land.
    let mut rotated = stored.clone();
    rotated.name = "Renamed".into();
    rotated.client_id = "client-rotated".into();
    rotated.credential = sealed(9);
    assert!(
        store
            .update_entry_connection(&rotated, audit())
            .await
            .unwrap()
    );
    let stored = store.entry_connection(held.handle).await.unwrap().unwrap();
    assert_eq!(stored.revision, 2);
    assert_eq!(
        (&stored.name, &stored.client_id, &stored.credential),
        (&rotated.name, &rotated.client_id, &rotated.credential)
    );
    assert!(!stored.enabled, "the earlier disabling stands");
}

/// Bug prevented: a change that rebinds a registration (another issuer,
/// owner, source, callback, use return or recipient issuer under the same
/// handle), so identities recorded under the old issuer would be reached
/// through the new one, or a holder sent back somewhere else. Such a change
/// is refused and nothing is written.
pub async fn a_change_never_alters_the_registration(store: &dyn EntryConnectionStore) {
    let held = connection(1, ConnectionOwner::Administration);
    store.create_entry_connection(&held, audit()).await.unwrap();
    let rebound: [fn(&mut EntryConnection); 6] = [
        |c| c.issuer = "https://another.sid.example.com/i/handle".into(),
        |c| c.owner = ConnectionOwner::Provisioning,
        |c| c.source = None,
        |c| c.callback.push('x'),
        |c| c.use_return = Some("https://elsewhere.sid.example.com/return".into()),
        |c| c.recipient_issuer = IssuerId::generate(),
    ];
    for alter in rebound {
        let mut changed = held.clone();
        alter(&mut changed);
        assert!(matches!(
            store.update_entry_connection(&changed, audit()).await,
            Err(Error::Validation(_))
        ));
    }
    assert_eq!(
        store.entry_connection(held.handle).await.unwrap(),
        Some(held)
    );
}

/// A connection is removed at the revision it was read at; a removal over
/// an older revision, or of a connection already gone, removes nothing.
/// Its issuer may be registered again afterwards, as a new connection.
pub async fn a_removal_applies_over_the_revision_it_read(store: &dyn EntryConnectionStore) {
    let held = connection(1, ConnectionOwner::Administration);
    store.create_entry_connection(&held, audit()).await.unwrap();
    let mut changed = held.clone();
    changed.enabled = false;
    assert!(
        store
            .update_entry_connection(&changed, audit())
            .await
            .unwrap()
    );
    assert!(
        !store
            .remove_entry_connection(held.handle, 0, audit())
            .await
            .unwrap(),
        "removed over a revision that was changed since"
    );
    assert!(
        store
            .remove_entry_connection(held.handle, 1, audit())
            .await
            .unwrap()
    );
    assert_eq!(store.entry_connection(held.handle).await.unwrap(), None);
    assert_eq!(
        store
            .entry_connection_of_issuer(&held.issuer)
            .await
            .unwrap(),
        None
    );
    assert!(
        !store
            .remove_entry_connection(held.handle, 1, audit())
            .await
            .unwrap()
    );

    let mut again = connection(5, ConnectionOwner::Administration);
    again.issuer = held.issuer.clone();
    store
        .create_entry_connection(&again, audit())
        .await
        .unwrap();
    assert_eq!(
        store
            .entry_connection_of_issuer(&held.issuer)
            .await
            .unwrap(),
        Some(again)
    );
}

/// A written change and a removal each advance the login-policy epoch in the
/// same commit; a change or removal over a stale revision writes nothing and
/// leaves it. Bug prevented: a sign-in decided through a connection that an
/// administrator disabled or removed meanwhile still committing its session,
/// because nothing it was fenced on moved.
pub async fn connection_writes_move_the_login_policy_epoch(
    store: &dyn crate::storage::StorageBackend,
) {
    let held = connection(1, ConnectionOwner::Administration);
    store.create_entry_connection(&held, audit()).await.unwrap();
    let before = store.export_login_policy_epoch().await.unwrap();
    let mut disabled = held.clone();
    disabled.enabled = false;
    assert!(
        store
            .update_entry_connection(&disabled, audit())
            .await
            .unwrap()
    );
    let after_change = store.export_login_policy_epoch().await.unwrap();
    assert!(after_change > before, "{before:?} -> {after_change:?}");
    // Over the revision the change moved on: nothing is written.
    assert!(
        !store
            .update_entry_connection(&disabled, audit())
            .await
            .unwrap()
    );
    assert!(
        !store
            .remove_entry_connection(held.handle, 0, audit())
            .await
            .unwrap()
    );
    assert_eq!(
        store.export_login_policy_epoch().await.unwrap(),
        after_change
    );
    assert!(
        store
            .remove_entry_connection(held.handle, 1, audit())
            .await
            .unwrap()
    );
    let after_removal = store.export_login_policy_epoch().await.unwrap();
    assert!(
        after_removal > after_change,
        "{after_change:?} -> {after_removal:?}"
    );
}

/// Two registrations of one issuer at once end at one connection, and two
/// changes of one connection at once land one after the other or one of
/// them is refused: never both over the same revision. A store that
/// refuses a concurrent writer is asked again.
pub async fn concurrent_writers_end_at_one_state(store: &dyn EntryConnectionStore) {
    let a = connection(1, ConnectionOwner::Administration);
    let mut b = connection(2, ConnectionOwner::Administration);
    b.issuer = a.issuer.clone();
    let (first, second) = tokio::join!(
        store.create_entry_connection(&a, audit()),
        store.create_entry_connection(&b, audit())
    );
    let created = [first.is_ok(), second.is_ok()];
    // A writer refused for contention, not for the conflict, is asked again
    // and then meets the conflict.
    for (asked, result) in [(&a, first), (&b, second)] {
        if let Err(e) = result
            && !matches!(e, Error::Conflict(_))
        {
            assert!(matches!(
                store.create_entry_connection(asked, audit()).await,
                Err(Error::Conflict(_)) | Ok(())
            ));
        }
    }
    let held = store.list_entry_connections().await.unwrap();
    assert_eq!(held.len(), 1, "one issuer, one connection: {created:?}");

    let stored = held.into_iter().next().unwrap();
    let mut disabled = stored.clone();
    disabled.enabled = false;
    let mut renamed = stored.clone();
    renamed.name = "Renamed".into();
    let (first, second) = tokio::join!(
        store.update_entry_connection(&disabled, audit()),
        store.update_entry_connection(&renamed, audit())
    );
    let landed = [first, second]
        .into_iter()
        .filter(|written| matches!(written, Ok(true)))
        .count();
    let after = store
        .entry_connection(stored.handle)
        .await
        .unwrap()
        .unwrap();
    assert!(landed <= 1, "both changes landed over one revision");
    assert_eq!(after.revision, landed as u64);
}
