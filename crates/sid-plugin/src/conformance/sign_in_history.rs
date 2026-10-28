// SPDX-License-Identifier: AGPL-3.0-only
//! [`SignInHistoryStore`] scenarios: what an account's earlier sign-ins
//! tell the sign-in rules, for any account type. Every scenario works on
//! accounts it created, so a harness may run them concurrently against one
//! shared database.

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::SignInHistoryStore;

/// What a backend's harness supplies to the scenarios.
#[async_trait]
pub trait SignInHistoryHarness: Send + Sync {
    /// The account type the backend records sign-ins for.
    type Owner: Clone + PartialEq + Debug + Send + Sync + 'static;

    fn store(&self) -> &dyn SignInHistoryStore<Owner = Self::Owner>;

    /// A new account the store accepts as an owner.
    async fn owner(&self) -> Self::Owner;

    /// A session of `owner` established now from `ip` and `device`.
    async fn sign_in(&self, owner: &Self::Owner, ip: &str, device: Option<Uuid>);

    /// A sign-in of `owner` from `ip` and `device` that proved its first
    /// factor and still owes its second: its pending context stored now.
    async fn begin_sign_in(&self, owner: &Self::Owner, ip: &str, device: Option<Uuid>);
}

const DAY: Duration = Duration::from_secs(24 * 3600);

/// The most recent session's address is the baseline: none before the
/// first session, then the latest one's, never another account's.
pub async fn most_recent_session_is_the_latest<H: SignInHistoryHarness>(h: &H) {
    let store = h.store();
    let (owner, other) = (h.owner().await, h.owner().await);
    assert_eq!(
        store
            .get_most_recent_session_ip(owner.clone())
            .await
            .unwrap(),
        None
    );
    h.sign_in(&owner, "192.0.2.1", None).await;
    // Sessions are ordered by their creation time; keep them distinct.
    tokio::time::sleep(Duration::from_millis(5)).await;
    h.sign_in(&owner, "192.0.2.2", None).await;
    h.sign_in(&other, "198.51.100.9", None).await;
    let (ip, _) = store
        .get_most_recent_session_ip(owner)
        .await
        .unwrap()
        .expect("the latest session");
    assert_eq!(ip, "192.0.2.2");
}

/// An address or device counts as seen only for the account that signed in
/// from it, and only within the window.
pub async fn seen_address_and_device_are_per_account<H: SignInHistoryHarness>(h: &H) {
    let store = h.store();
    let (owner, other) = (h.owner().await, h.owner().await);
    let device = Uuid::now_v7();
    h.sign_in(&owner, "203.0.113.7", Some(device)).await;

    assert!(
        store
            .has_recent_session_from_ip(owner.clone(), "203.0.113.7", DAY)
            .await
            .unwrap()
    );
    assert!(
        !store
            .has_recent_session_from_ip(owner.clone(), "203.0.113.8", DAY)
            .await
            .unwrap()
    );
    assert!(
        !store
            .has_recent_session_from_ip(other.clone(), "203.0.113.7", DAY)
            .await
            .unwrap(),
        "another account's address counted"
    );
    assert!(
        store
            .has_recent_session_from_device(owner.clone(), device, DAY)
            .await
            .unwrap()
    );
    assert!(
        !store
            .has_recent_session_from_device(owner.clone(), Uuid::now_v7(), DAY)
            .await
            .unwrap()
    );
    assert!(
        !store
            .has_recent_session_from_device(other, device, DAY)
            .await
            .unwrap(),
        "another account's device counted"
    );

    // An empty window ends now: the session before it is outside.
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(
        !store
            .has_recent_session_from_ip(owner.clone(), "203.0.113.7", Duration::ZERO)
            .await
            .unwrap()
    );
    assert!(
        !store
            .has_recent_session_from_device(owner, device, Duration::ZERO)
            .await
            .unwrap()
    );
}

/// A sign-in that has not finished is no history: its address is not the
/// latest session's and neither its address nor its device counts as seen.
/// Counting it let an unfinished attempt from one place refuse a real
/// sign-in from another as impossible travel.
pub async fn an_unfinished_sign_in_is_no_history<H: SignInHistoryHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let device = Uuid::now_v7();
    h.sign_in(&owner, "192.0.2.10", None).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    h.begin_sign_in(&owner, "198.51.100.20", Some(device)).await;

    let (ip, _) = store
        .get_most_recent_session_ip(owner.clone())
        .await
        .unwrap()
        .expect("the completed session");
    assert_eq!(ip, "192.0.2.10");
    assert!(
        !store
            .has_recent_session_from_ip(owner.clone(), "198.51.100.20", DAY)
            .await
            .unwrap()
    );
    assert!(
        !store
            .has_recent_session_from_device(owner, device, DAY)
            .await
            .unwrap()
    );
}

/// A country becomes designated once the account signed in from it the
/// threshold number of times, and only for that account.
pub async fn location_is_designated_at_threshold<H: SignInHistoryHarness>(h: &H) {
    let store = h.store();
    let (owner, other) = (h.owner().await, h.owner().await);
    let record = |who: H::Owner, country: &'static str| async move {
        store
            .record_login_location(who, country, 50.45, 30.52, 3)
            .await
            .unwrap();
    };
    assert!(
        store
            .get_designated_countries(owner.clone())
            .await
            .unwrap()
            .is_empty()
    );
    record(owner.clone(), "UA").await;
    record(owner.clone(), "UA").await;
    record(owner.clone(), "PL").await;
    assert!(
        store
            .get_designated_countries(owner.clone())
            .await
            .unwrap()
            .is_empty(),
        "designated below the threshold"
    );
    record(owner.clone(), "UA").await;
    assert_eq!(
        store.get_designated_countries(owner).await.unwrap(),
        vec!["UA".to_string()]
    );
    assert!(
        store
            .get_designated_countries(other)
            .await
            .unwrap()
            .is_empty(),
        "another account's location counted"
    );
}
