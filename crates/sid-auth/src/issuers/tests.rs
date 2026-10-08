// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const BASE: &str = "https://sid.example.com";
const HANDLE: &str = "0123456789abcdef0123456789abcdef";

fn issuer_url(handle: &str) -> String {
    format!("{BASE}/i/{handle}")
}

/// A registry holding fixed records, counting how often it is asked.
struct Registry {
    records: Mutex<Vec<(String, IssuerRecord)>>,
    /// Resources as (issuer handle, record).
    resources: Mutex<Vec<(String, ResourceRecord)>>,
    asked: AtomicUsize,
}

impl Registry {
    fn with(records: Vec<(&str, IssuerRecord)>) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(
                records
                    .into_iter()
                    .map(|(h, r)| (h.to_owned(), r))
                    .collect(),
            ),
            resources: Mutex::new(Vec::new()),
            asked: AtomicUsize::new(0),
        })
    }

    fn put_resource(&self, handle: &str, record: ResourceRecord) {
        let mut resources = self.resources.lock().unwrap();
        resources.retain(|(h, r)| !(h == handle && r.resource == record.resource));
        resources.push((handle.to_owned(), record));
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    fn replace(&self, handle: &str, record: IssuerRecord) {
        let mut records = self.records.lock().unwrap();
        records.retain(|(h, _)| h != handle);
        records.push((handle.to_owned(), record));
    }
}

#[async_trait::async_trait]
impl IssuerSource for Registry {
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, tonic::Status> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|(h, _)| h == handle)
            .map(|(_, r)| r.clone()))
    }

    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, tonic::Status> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .resources
            .lock()
            .unwrap()
            .iter()
            .find(|(h, r)| h == handle && r.resource == resource)
            .map(|(_, r)| r.clone()))
    }
}

const ORDERS: &str = "https://api.example.com/orders";

fn orders(issuer: String, active: bool) -> ResourceRecord {
    ResourceRecord {
        issuer,
        resource: ORDERS.into(),
        active,
        id: sid_core::models::ResourceId::parse("0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e").unwrap(),
    }
}

/// A registered resource resolves with its state and the answer is reused;
/// once the answer ages out a deactivation is seen.
#[tokio::test]
async fn a_registered_resource_resolves_and_is_reused() {
    let registry = Registry::with(vec![]);
    registry.put_resource(HANDLE, orders(issuer_url(HANDLE), true));
    let directory = IssuerDirectory::new(BASE, registry.clone());

    let record = directory
        .resource(&issuer_url(HANDLE), ORDERS)
        .await
        .unwrap()
        .unwrap();
    assert!(record.active);
    directory
        .resource(&issuer_url(HANDLE), ORDERS)
        .await
        .unwrap();
    assert_eq!(registry.asked(), 1);

    registry.put_resource(HANDLE, orders(issuer_url(HANDLE), false));
    directory
        .resources
        .get_mut(&(HANDLE.to_owned(), ORDERS.to_owned()))
        .unwrap()
        .fetched = Instant::now() - RESOURCE_TTL - Duration::from_secs(1);
    let record = directory
        .resource(&issuer_url(HANDLE), ORDERS)
        .await
        .unwrap()
        .unwrap();
    assert!(!record.active, "a deactivation was not seen");
}

/// A resource under an issuer of another installation, or an answer naming
/// another issuer or indicator than asked, is no resource here; nothing is
/// kept for it.
#[tokio::test]
async fn a_resource_answer_must_match_the_question() {
    let registry = Registry::with(vec![]);
    registry.put_resource(
        HANDLE,
        orders(format!("https://other.example.com/i/{HANDLE}"), true),
    );
    let directory = IssuerDirectory::new(BASE, registry.clone());

    assert!(
        directory
            .resource(&issuer_url(HANDLE), ORDERS)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        directory
            .resource(&format!("https://evil.example.com/i/{HANDLE}"), ORDERS)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        directory
            .resource(&format!("{BASE}/i/../etc"), ORDERS)
            .await
            .unwrap()
            .is_none()
    );
    // Only the first question reached the registry: the other two named no
    // issuer of this installation.
    assert_eq!(registry.asked(), 1);
    assert!(directory.resources.is_empty());
}

fn record(handle: &str, kids: &[&str]) -> IssuerRecord {
    IssuerRecord {
        issuer: issuer_url(handle),
        keys: kids.iter().map(|kid| (kid.to_string(), [7; 32])).collect(),
    }
}

/// A stored handle resolves to its issuer with its keys; the answer is
/// reused for later requests.
#[tokio::test]
async fn a_known_handle_resolves_and_is_reused() {
    let registry = Registry::with(vec![(HANDLE, record(HANDLE, &["k1"]))]);
    let directory = IssuerDirectory::new(BASE, registry.clone());

    let issuer = directory.by_handle(HANDLE).await.unwrap().unwrap();
    assert_eq!(issuer.issuer, issuer_url(HANDLE));
    assert!(issuer.verifier.knows_key("k1"));
    assert!(!issuer.verifier.knows_key("k2"));
    directory.by_handle(HANDLE).await.unwrap().unwrap();
    assert_eq!(registry.asked(), 1);
}

/// Text that is not a handle is never asked about; an unknown handle is
/// asked about every time, so made-up handles leave nothing behind.
#[tokio::test]
async fn unknown_and_malformed_handles_resolve_to_nothing() {
    let registry = Registry::with(vec![]);
    let directory = IssuerDirectory::new(BASE, registry.clone());

    assert!(directory.by_handle("../etc").await.unwrap().is_none());
    assert_eq!(registry.asked(), 0);
    let unknown = "fedcba9876543210fedcba9876543210";
    assert!(directory.by_handle(unknown).await.unwrap().is_none());
    assert!(directory.by_handle(unknown).await.unwrap().is_none());
    assert_eq!(registry.asked(), 2);
    assert!(directory.cache.is_empty());
}

/// A registry answer naming an issuer under another base, or for another
/// handle, is not this handle's issuer.
#[tokio::test]
async fn an_answer_for_another_url_is_not_accepted() {
    let foreign = IssuerRecord {
        issuer: format!("https://other.example.com/i/{HANDLE}"),
        keys: vec![("k1".into(), [7; 32])],
    };
    let directory = IssuerDirectory::new(BASE, Registry::with(vec![(HANDLE, foreign)]));
    assert!(directory.by_handle(HANDLE).await.unwrap().is_none());
}

/// A token's `iss` is trusted only when it is exactly one of this
/// installation's issuers: another host, the root, or a longer path is not.
#[tokio::test]
async fn only_this_installations_issuers_verify_tokens() {
    let registry = Registry::with(vec![(HANDLE, record(HANDLE, &["k1"]))]);
    let directory = IssuerDirectory::new(BASE, registry.clone());

    assert!(
        directory
            .for_token(&issuer_url(HANDLE), "k1")
            .await
            .unwrap()
            .is_some()
    );
    for iss in [
        BASE.to_string(),
        format!("https://evil.example.com/i/{HANDLE}"),
        format!("{}/extra", issuer_url(HANDLE)),
    ] {
        assert!(
            directory.for_token(&iss, "k1").await.unwrap().is_none(),
            "{iss}"
        );
    }
}

/// A token naming a key the cached answer lacks triggers one fresh lookup,
/// and no more than one per refresh interval however many such tokens come.
#[tokio::test]
async fn an_unknown_key_refreshes_the_issuer_once() {
    let registry = Registry::with(vec![(HANDLE, record(HANDLE, &["k1"]))]);
    let directory = IssuerDirectory::new(BASE, registry.clone());
    directory.by_handle(HANDLE).await.unwrap();
    // Age the answer past the refresh interval, then rotate a key in.
    directory.cache.get_mut(HANDLE).unwrap().fetched =
        Instant::now() - UNKNOWN_KEY_REFRESH - Duration::from_secs(1);
    registry.replace(HANDLE, record(HANDLE, &["k2", "k1"]));

    let issuer = directory
        .for_token(&issuer_url(HANDLE), "k2")
        .await
        .unwrap()
        .unwrap();
    assert!(issuer.verifier.knows_key("k2"));
    assert_eq!(registry.asked(), 2);

    for _ in 0..5 {
        directory
            .for_token(&issuer_url(HANDLE), "never-issued")
            .await
            .unwrap();
    }
    assert_eq!(registry.asked(), 2, "unknown keys drove lookups");
}
