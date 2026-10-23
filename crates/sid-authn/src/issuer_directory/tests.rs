// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const BASE: &str = "https://sid.example.com";
const HANDLE: &str = "0123456789abcdef0123456789abcdef";
const OTHER_HANDLE: &str = "fedcba9876543210fedcba9876543210";

fn issuer_url(handle: &str) -> String {
    format!("{BASE}/i/{handle}")
}

/// A registry holding fixed records, counting how often it is asked.
struct Registry {
    records: Mutex<Vec<(String, IssuerRecord)>>,
    /// Resources as (issuer handle, record).
    resources: Mutex<Vec<(String, ResourceRecord)>>,
    asked: AtomicUsize,
    /// When set, every question fails as an unreachable registry would.
    down: std::sync::atomic::AtomicBool,
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
            down: std::sync::atomic::AtomicBool::new(false),
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

    fn fail(&self) -> Result<(), RegistryUnavailable> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(RegistryUnavailable("registry down".into()));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl IssuerSource for Registry {
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable> {
        self.fail()?;
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
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
        self.fail()?;
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
    assert!(directory.by_handle(OTHER_HANDLE).await.unwrap().is_none());
    assert!(directory.by_handle(OTHER_HANDLE).await.unwrap().is_none());
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

/// One issuer's Ed25519 signing key, its `kid` and public half.
struct Key {
    kid: &'static str,
    encoding: jsonwebtoken::EncodingKey,
    public: [u8; 32],
}

fn key(kid: &'static str, seed: u8) -> Key {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    Key {
        kid,
        encoding: jsonwebtoken::EncodingKey::from_ed_der(
            signing.to_pkcs8_der().unwrap().as_bytes(),
        ),
        public: signing.verifying_key().to_bytes(),
    }
}

fn signed(key: &Key, typ: &str, claims: &impl serde::Serialize) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(key.kid.into());
    header.typ = Some(typ.into());
    jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
}

fn access_claims(iss: &str, aud: &str) -> AccessTokenClaims {
    let now = chrono::Utc::now().timestamp();
    AccessTokenClaims {
        sub: "subject".into(),
        pid: None,
        iss: iss.into(),
        aud: vec![aud.into()],
        client_id: Some("ops-web".into()),
        exp: now + 60,
        iat: now,
        auth_time: now,
        acr: "urn:sid:acr:basic".into(),
        scope: "openid".into(),
        roles: String::new(),
        sid: "session".into(),
        amr: vec![],
        jti: "jti".into(),
        cnf: None,
        act: None,
    }
}

/// A directory knowing two issuers of this installation, each with its own
/// key.
fn two_issuers() -> (IssuerDirectory, Key, Key) {
    let own = key("k1", 1);
    let other = key("k2", 2);
    let registry = Registry::with(vec![
        (
            HANDLE,
            IssuerRecord {
                issuer: issuer_url(HANDLE),
                keys: vec![(own.kid.into(), own.public)],
            },
        ),
        (
            OTHER_HANDLE,
            IssuerRecord {
                issuer: issuer_url(OTHER_HANDLE),
                keys: vec![(other.kid.into(), other.public)],
            },
        ),
    ]);
    (IssuerDirectory::new(BASE, registry), own, other)
}

/// The access token a named issuer issued for a resource is accepted with
/// its claims; one for another resource, one another issuer of the same
/// installation signed (naming itself or claiming the expected issuer) and
/// one that is not an access token are refused as invalid.
#[tokio::test]
async fn an_issued_access_token_must_be_the_named_issuers_for_the_resource() {
    let (directory, own, other) = two_issuers();
    let iss = issuer_url(HANDLE);

    let token = signed(&own, "at+jwt", &access_claims(&iss, ORDERS));
    let claims = directory
        .issued_access_token(&iss, ORDERS, &token)
        .await
        .unwrap();
    assert_eq!(claims.client_id.as_deref(), Some("ops-web"));

    let elsewhere = signed(
        &own,
        "at+jwt",
        &access_claims(&iss, "https://api.example.com/billing"),
    );
    let by_other = signed(
        &other,
        "at+jwt",
        &access_claims(&issuer_url(OTHER_HANDLE), ORDERS),
    );
    let forged = signed(&other, "at+jwt", &access_claims(&iss, ORDERS));
    let untyped = signed(&own, "JWT", &access_claims(&iss, ORDERS));
    for (case, token) in [
        ("another resource", elsewhere),
        ("another issuer", by_other),
        ("another issuer's key", forged),
        ("not an access token", untyped),
        ("malformed", "not.a.token".to_owned()),
    ] {
        assert!(
            matches!(
                directory.issued_access_token(&iss, ORDERS, &token).await,
                Err(IssuedTokenRefusal::Invalid(_))
            ),
            "{case}"
        );
    }
}

/// The ID token of a code redemption is accepted only for its client and the
/// nonce its sign-in sent.
#[tokio::test]
async fn an_issued_id_token_must_match_client_and_nonce() {
    let (directory, own, _) = two_issuers();
    let iss = issuer_url(HANDLE);
    let now = chrono::Utc::now().timestamp();
    let id: IdTokenClaims = serde_json::from_value(serde_json::json!({
        "iss": iss, "sub": "subject", "aud": "ops-web",
        "exp": now + 60, "iat": now, "auth_time": now,
        "acr": "urn:sid:acr:basic", "nonce": "n-1",
    }))
    .unwrap();
    let token = signed(&own, "JWT", &id);

    let claims = directory
        .issued_id_token(&iss, "ops-web", "n-1", &token)
        .await
        .unwrap();
    assert_eq!(claims.sub, "subject");
    for (client, nonce) in [("other-web", "n-1"), ("ops-web", "n-2")] {
        assert!(
            matches!(
                directory.issued_id_token(&iss, client, nonce, &token).await,
                Err(IssuedTokenRefusal::Invalid(_))
            ),
            "{client} {nonce}"
        );
    }
}

/// A registry that cannot answer leaves the token undecided: unavailable,
/// not invalid, so a caller does not sign a user out over an outage.
#[tokio::test]
async fn an_unreachable_registry_is_unavailable_not_invalid() {
    let own = key("k1", 1);
    let registry = Registry::with(vec![]);
    registry.down.store(true, Ordering::SeqCst);
    let directory = IssuerDirectory::new(BASE, registry);
    let iss = issuer_url(HANDLE);
    let token = signed(&own, "at+jwt", &access_claims(&iss, ORDERS));

    assert!(matches!(
        directory.issued_access_token(&iss, ORDERS, &token).await,
        Err(IssuedTokenRefusal::Unavailable(_))
    ));
}

/// The path of an issuer-scoped endpoint is what follows the handle.
#[test]
fn the_endpoint_of_an_issuer_path() {
    assert_eq!(
        issuer_endpoint(&format!("/i/{HANDLE}/oauth2/token")),
        Some("/oauth2/token")
    );
    assert_eq!(issuer_endpoint("/oauth2/token"), None);
    assert_eq!(issuer_endpoint(&format!("/i/{HANDLE}")), None);
}
