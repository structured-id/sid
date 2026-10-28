use super::*;

use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;
use serde_json::json;
use sid_plugin::cache::InMemoryCacheBackend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CLIENT: &str = "platform-recipient";
const SECRET: &str = "the-client-secret-of-the-recipient-0123456789";
const REDIRECT: &str = "https://platform.sid.example.com/i/p/auth/federation/callback";
const CONTINUATION: &str = "https://platform.sid.example.com/i/p/oauth2/authorize?request_uri=x";

/// What the test issuer answers its token endpoint with, and what it checks.
#[derive(Default)]
struct Issued {
    /// The ID Token a valid exchange returns.
    id_token: Option<String>,
    /// The PKCE challenge of the request the code was issued for.
    challenge: Option<String>,
    /// Exchanges the token endpoint served.
    exchanges: usize,
    /// The failure the issuer answers with, if any.
    fault: Fault,
}

/// A failure of the test issuer.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Fault {
    #[default]
    None,
    /// The token endpoint takes the code and answers 500.
    TokenServerError,
    /// Discovery names a token endpoint nobody listens on.
    TokenUnreachable,
    /// The key set answers 500.
    KeysDown,
    /// The token endpoint answers correctly, but only after a while.
    TokenSlow,
}

/// A local trusted issuer: discovery, key set and token endpoint, signing
/// with one ES256 key.
struct TestIssuer {
    issuer: String,
    encoding: EncodingKey,
    issued: Arc<Mutex<Issued>>,
}

impl TestIssuer {
    async fn start() -> Self {
        let secret = p256::SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let point = secret.public_key().to_sec1_point(false);
        let encoding = EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes());
        let jwk = json!({
            "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let issuer = format!("{base}/i/central");
        let issued = Arc::new(Mutex::new(Issued::default()));
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
            "token_endpoint": format!("{issuer}/oauth2/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "id_token_signing_alg_values_supported": ["ES256"],
        });
        let keys = json!({ "keys": [jwk] });
        let state = issued.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let (head, body) = read_request(&mut socket).await;
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let fault = state.lock().unwrap().fault;
                let (status, answer) = match path.as_str() {
                    "/i/central/.well-known/openid-configuration" => {
                        let mut discovery = discovery.clone();
                        if fault == Fault::TokenUnreachable {
                            // The discard port: no listener, connection refused.
                            discovery["token_endpoint"] = json!("http://127.0.0.1:9/token");
                        }
                        (200, discovery)
                    }
                    "/i/central/jwks" if fault == Fault::KeysDown => (500, json!({})),
                    "/i/central/jwks" => (200, keys.clone()),
                    "/i/central/oauth2/token" if fault == Fault::TokenServerError => {
                        state.lock().unwrap().exchanges += 1;
                        (500, json!({}))
                    }
                    "/i/central/oauth2/token" => {
                        if fault == Fault::TokenSlow {
                            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        }
                        token(&state, &head, &body)
                    }
                    _ => (404, json!({})),
                };
                let text = answer.to_string();
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        Self {
            issuer,
            encoding,
            issued,
        }
    }

    fn trusted(&self) -> TrustedIssuer {
        TrustedIssuer {
            issuer: self.issuer.clone(),
            client_id: CLIENT.into(),
            client_secret: SecretString::from(SECRET.to_owned()),
        }
    }

    /// Issue the code for the authorization request `url`: its token
    /// endpoint answers with an ID Token carrying `claims` over the defaults
    /// (this issuer, this client, the request's nonce).
    fn issue_for(&self, url: &str, claims: serde_json::Value) {
        let url = reqwest::Url::parse(url).unwrap();
        let param = |name: &str| {
            url.query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };
        let now = jsonwebtoken::get_current_timestamp();
        let mut all = json!({
            "iss": self.issuer,
            "sub": "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e",
            "aud": CLIENT,
            "exp": now + 300,
            "iat": now,
            "auth_time": now - 60,
            "nonce": param("nonce").unwrap(),
        });
        // A null override leaves the claim out of the token.
        for (k, v) in claims.as_object().unwrap() {
            if v.is_null() {
                all.as_object_mut().unwrap().remove(k);
            } else {
                all[k] = v.clone();
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".into());
        let mut issued = self.issued.lock().unwrap();
        issued.id_token = Some(jsonwebtoken::encode(&header, &all, &self.encoding).unwrap());
        issued.challenge = param("code_challenge");
    }

    fn exchanges(&self) -> usize {
        self.issued.lock().unwrap().exchanges
    }

    fn fail(&self, fault: Fault) {
        self.issued.lock().unwrap().fault = fault;
    }
}

/// The request head and body `socket` sends.
async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, String) {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let read = socket.read(&mut buf).await.unwrap_or(0);
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buf[..read]);
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let head = text[..end].to_owned();
            let length = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                return (head, text[end + 4..end + 4 + length].to_owned());
            }
        }
    }
    (String::from_utf8_lossy(&data).into_owned(), String::new())
}

/// The token endpoint: the client authenticates with `client_secret_basic`
/// and proves the request's PKCE verifier (RFC 7636 §4.6).
fn token(issued: &Mutex<Issued>, head: &str, body: &str) -> (u16, serde_json::Value) {
    let mut issued = issued.lock().unwrap();
    issued.exchanges += 1;
    let basic = format!("basic {}", STANDARD.encode(format!("{CLIENT}:{SECRET}")));
    if !head
        .to_ascii_lowercase()
        .contains(&format!("authorization: {}", basic.to_ascii_lowercase()))
    {
        return (401, json!({ "error": "invalid_client" }));
    }
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    let proves = form
        .get("code_verifier")
        .map(|v| pkce_challenge(v))
        .zip(issued.challenge.clone())
        .is_some_and(|(proved, expected)| proved == expected);
    if !proves || form.get("redirect_uri").map(String::as_str) != Some(REDIRECT) {
        return (400, json!({ "error": "invalid_grant" }));
    }
    match &issued.id_token {
        Some(id_token) => (200, json!({ "access_token": "a", "id_token": id_token })),
        None => (400, json!({ "error": "invalid_grant" })),
    }
}

fn http() -> Client {
    let _ = sid_crypto::tls::aws_lc::provider().install_default();
    sid_plugin::client_builder().unwrap().build().unwrap()
}

fn entry(issuer: &TestIssuer) -> FederatedEntry {
    entry_on(issuer, Arc::new(InMemoryCacheBackend::new()))
}

/// The relying party of `issuer` over `cache`, which other relying parties
/// may share.
fn entry_on(issuer: &TestIssuer, cache: Arc<dyn CacheBackend>) -> FederatedEntry {
    FederatedEntry::new(
        issuer.trusted(),
        http(),
        cache,
        crate::test_support::key_manager(),
        BrowserCookie::new("__Host-sid_platform").unwrap(),
    )
}

/// An entry started in one browser: the authorization URL it goes to and
/// the `Cookie` header that browser then sends back.
struct Browser {
    url: String,
    cookie: String,
}

impl Browser {
    fn of(started: Started) -> Self {
        let cookie = started.set_cookie.split(';').next().unwrap().to_owned();
        Self {
            url: started.authorization_url,
            cookie,
        }
    }

    fn state(&self) -> String {
        state_of(&self.url)
    }

    /// Complete the entry this browser started with `code` at `redirect`.
    async fn complete(
        &self,
        entry: &FederatedEntry,
        code: &str,
        redirect: &str,
    ) -> Result<Returned, EntryError> {
        entry
            .complete(&self.state(), [self.cookie.as_str()], code, redirect)
            .await
    }
}

async fn begin(entry: &FederatedEntry, request: &EntryRequest) -> Browser {
    Browser::of(entry.start(REDIRECT, CONTINUATION, request).await.unwrap())
}

fn state_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

// A started entry asks the issuer for its subject with S256 PKCE, a nonce,
// and the requested assurance and authentication age; its return is
// exchanged with the client's Basic credentials and yields the subject, the
// issuer's evidence and the continuation.
#[tokio::test]
async fn an_entry_returns_the_subject_and_its_evidence() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let request = EntryRequest {
        acr: Some(AuthLevel::Elevated),
        max_age: Some(Duration::from_secs(300)),
    };
    let browser = begin(&entry, &request).await;
    let url = browser.url.clone();
    let parsed = reqwest::Url::parse(&url).unwrap();
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    assert!(url.starts_with(&format!("{}/oauth2/authorize?", issuer.issuer)));
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["client_id"], CLIENT);
    assert_eq!(params["redirect_uri"], REDIRECT);
    assert_eq!(params["scope"], "openid");
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["acr_values"], "urn:sid:acr:elevated");
    assert_eq!(params["max_age"], "300");

    let auth_time = jsonwebtoken::get_current_timestamp() - 30;
    issuer.issue_for(
        &url,
        json!({ "acr": "urn:sid:acr:elevated", "amr": ["hwk", "user"], "auth_time": auth_time }),
    );
    let returned = browser
        .complete(&entry, "the-code", REDIRECT)
        .await
        .unwrap();
    assert_eq!(returned.subject, "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e");
    assert_eq!(returned.continuation, CONTINUATION);
    assert_eq!(
        returned.evidence,
        AcceptedEvidence {
            acr: Some(AuthLevel::Elevated),
            amr: vec!["hwk".into(), "user".into()],
            auth_time: Utc.timestamp_opt(auth_time as i64, 0).single().unwrap(),
        }
    );
}

// A return names what its entry asked the issuer for, so the caller can tell
// a return to its own stronger request from the first one and never asks
// again in a loop.
#[tokio::test]
async fn a_return_names_what_its_entry_requested() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    for request in [
        EntryRequest::default(),
        EntryRequest {
            acr: Some(AuthLevel::Standard),
            max_age: None,
        },
        EntryRequest {
            acr: Some(AuthLevel::Elevated),
            max_age: Some(Duration::from_secs(0)),
        },
    ] {
        let browser = begin(&entry, &request).await;
        issuer.issue_for(&browser.url, json!({}));
        let returned = browser.complete(&entry, "c", REDIRECT).await.unwrap();
        assert_eq!(returned.requested, request);
    }
}

// Regression guard: a return exchanges its code once. Repeating it in the
// same browser (its response was lost) returns the same entry without a
// second exchange; an unknown state and a return to another redirect URI
// complete nothing, and the last never reaches the token endpoint.
#[tokio::test]
async fn a_return_completes_once_and_only_at_its_redirect() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let browser = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    let first = browser.complete(&entry, "c", REDIRECT).await.unwrap();
    let again = browser.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(again, first);
    assert_eq!(issuer.exchanges(), 1, "the code was redeemed twice");
    assert!(matches!(
        entry
            .complete("unknown", [browser.cookie.as_str()], "c", REDIRECT)
            .await,
        Err(EntryError::OtherBrowser)
    ));

    let other = begin(&entry, &EntryRequest::default()).await;
    let before = issuer.exchanges();
    assert!(matches!(
        other
            .complete(&entry, "c", "https://elsewhere.example/callback")
            .await,
        Err(EntryError::RedirectMismatch)
    ));
    assert_eq!(issuer.exchanges(), before);
    // The mismatched return consumed its state: the entry is over.
    assert!(matches!(
        other.complete(&entry, "c", REDIRECT).await,
        Err(EntryError::Unknown)
    ));
}

// Regression guard: relying parties of two issuers sharing one cache and one
// sealing key never complete each other's entries. An entry started for
// issuer A and returned to B's relying party is refused before B's token
// endpoint sees A's code verifier, and stays A's to complete.
#[tokio::test]
async fn an_entry_completes_only_at_the_issuer_it_was_started_for() {
    let a = TestIssuer::start().await;
    let b = TestIssuer::start().await;
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let at_a = entry_on(&a, cache.clone());
    let at_b = entry_on(&b, cache);
    let browser = begin(&at_a, &EntryRequest::default()).await;
    a.issue_for(&browser.url, json!({}));
    b.issue_for(&browser.url, json!({}));
    let refused = browser.complete(&at_b, "c", REDIRECT).await;
    assert!(matches!(refused, Err(EntryError::Unknown)), "{refused:?}");
    assert_eq!(b.exchanges(), 0, "B's token endpoint saw A's entry");
    let returned = browser.complete(&at_a, "c", REDIRECT).await.unwrap();
    assert_eq!(returned.continuation, CONTINUATION);
}

// Regression guard: an ID Token of another issuer, for another audience or
// another nonce is refused (OpenID Connect Core 1.0 §3.1.3.7).
#[tokio::test]
async fn a_token_not_for_this_entry_is_refused() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    for (case, claims) in [
        (
            "issuer",
            json!({ "iss": "https://other.example/i/central" }),
        ),
        ("audience", json!({ "aud": "another-client" })),
        ("nonce", json!({ "nonce": "another-nonce" })),
    ] {
        let browser = begin(&entry, &EntryRequest::default()).await;
        issuer.issue_for(&browser.url, claims);
        let refused = browser.complete(&entry, "c", REDIRECT).await;
        assert!(
            matches!(refused, Err(EntryError::Token(_))),
            "{case}: {refused:?}"
        );
    }
}

// Regression guard: every return needs the real authentication time: an ID
// Token without auth_time is refused, with or without a max_age request,
// since the session it admits would otherwise record an invented one.
#[tokio::test]
async fn auth_time_is_required() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    for request in [
        EntryRequest {
            acr: None,
            max_age: Some(Duration::from_secs(60)),
        },
        EntryRequest::default(),
    ] {
        let browser = begin(&entry, &request).await;
        issuer.issue_for(&browser.url, json!({ "auth_time": null }));
        let refused = browser.complete(&entry, "c", REDIRECT).await;
        assert!(
            matches!(refused, Err(EntryError::Token(_))),
            "{request:?}: {refused:?}"
        );
    }
}

// Regression guard: only a shared SID ACR URN is a level. A plain level name,
// another issuer's ACR and a missing ACR return evidence attesting none.
#[tokio::test]
async fn only_a_sid_acr_urn_is_a_level() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    for acr in [json!("standard"), json!("urn:other:acr:gold"), json!(null)] {
        let browser = begin(&entry, &EntryRequest::default()).await;
        issuer.issue_for(&browser.url, json!({ "acr": acr }));
        let returned = browser.complete(&entry, "c", REDIRECT).await.unwrap();
        assert_eq!(returned.evidence.acr, None, "{acr}");
        assert_eq!(returned.evidence.authentication(Utc::now()), None, "{acr}");
    }
}

// An exchange whose outcome is unknown (the issuer took the code and answered
// a server error) is never repeated: the return and every retry of it are
// ambiguous, and the issuer sees one exchange.
#[tokio::test]
async fn an_exchange_of_unknown_outcome_is_never_repeated() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let browser = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    issuer.fail(Fault::TokenServerError);
    for _ in 0..2 {
        match browser.complete(&entry, "c", REDIRECT).await {
            // Sign-in starts anew where the entry would have continued.
            Err(EntryError::Ambiguous { continuation }) => assert_eq!(continuation, CONTINUATION),
            other => panic!("{other:?}"),
        }
        issuer.fail(Fault::None);
    }
    assert_eq!(issuer.exchanges(), 1);
}

// A token request that never reached the issuer leaves the code unspent: the
// return is retried and completes with one exchange.
#[tokio::test]
async fn an_unsent_exchange_is_retried() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let browser = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    issuer.fail(Fault::TokenUnreachable);
    assert!(matches!(
        browser.complete(&entry, "c", REDIRECT).await,
        Err(EntryError::Issuer(_))
    ));
    issuer.fail(Fault::None);
    browser.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(issuer.exchanges(), 1);
}

// A token answer kept before its validation failed for want of keys is
// validated on retry without another exchange.
#[tokio::test]
async fn a_kept_answer_is_validated_on_retry_without_another_exchange() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let browser = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    issuer.fail(Fault::KeysDown);
    assert!(matches!(
        browser.complete(&entry, "c", REDIRECT).await,
        Err(EntryError::Issuer(_))
    ));
    issuer.fail(Fault::None);
    let returned = browser.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(returned.continuation, CONTINUATION);
    assert_eq!(issuer.exchanges(), 1);
}

// A return resumed after its exchange keeps the entry's redirect binding: a
// repeat to another redirect URI gets no subject or evidence, and the
// bound return still completes. Before, only an unexchanged entry checked it.
#[tokio::test]
async fn a_resumed_return_keeps_its_redirect_binding() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let browser = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    browser.complete(&entry, "c", REDIRECT).await.unwrap();

    assert!(matches!(
        browser
            .complete(&entry, "c", "https://other.sid.example.com/callback")
            .await,
        Err(EntryError::RedirectMismatch)
    ));
    browser.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(issuer.exchanges(), 1);
}

// Returns racing on several replicas exchange the code at most once and stay
// one entry: a return meeting a live exchange is told to retry, never that
// the outcome is lost, and its retry gets what the owning return got.
// Before, it was ambiguous, and the caller started a second sign-in while the
// first one completed.
#[tokio::test]
async fn racing_returns_exchange_at_most_once() {
    let issuer = TestIssuer::start().await;
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let replicas = [entry_on(&issuer, cache.clone()), entry_on(&issuer, cache)];
    let browser = begin(&replicas[0], &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    let (a, b) = tokio::join!(
        browser.complete(&replicas[0], "c", REDIRECT),
        browser.complete(&replicas[1], "c", REDIRECT)
    );
    assert_eq!(issuer.exchanges(), 1);
    let mut completed = Vec::new();
    for (replica, result) in replicas.iter().zip([a, b]) {
        match result {
            Ok(returned) => completed.push(returned),
            Err(EntryError::InProgress) => {
                completed.push(browser.complete(replica, "c", REDIRECT).await.unwrap())
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(completed[0], completed[1]);
    assert_eq!(issuer.exchanges(), 1);
}

// A return reaching another replica while the first return's exchange is
// still running is told the exchange is in progress, not that its outcome is
// lost; once the exchange answered, the retry completes the same entry.
#[tokio::test]
async fn a_return_during_a_live_exchange_is_told_to_retry() {
    let issuer = TestIssuer::start().await;
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let replicas = [entry_on(&issuer, cache.clone()), entry_on(&issuer, cache)];
    let browser = begin(&replicas[0], &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    issuer.fail(Fault::TokenSlow);
    let (owner, other) = tokio::join!(browser.complete(&replicas[0], "c", REDIRECT), async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        browser.complete(&replicas[1], "c", REDIRECT).await
    });
    assert!(matches!(other, Err(EntryError::InProgress)), "{other:?}");
    let owner = owner.unwrap();
    let retried = browser.complete(&replicas[1], "c", REDIRECT).await.unwrap();
    assert_eq!(owner, retried);
    assert_eq!(issuer.exchanges(), 1);
}

// An exchange whose owner stopped (its process died mid-request) is known
// lost once its lease has run out: the next return records it ambiguous and
// never redeems the code again.
#[tokio::test]
async fn an_exchange_whose_owner_stopped_is_ambiguous_after_its_lease() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let browser = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&browser.url, json!({}));
    let secret = entry
        .correlation(&browser.state())
        .secret([browser.cookie.as_str()])
        .unwrap();
    let key = entry.key(&browser.state(), &secret);
    let read = entry.pending.read_versioned(&key).await.unwrap().unwrap();
    let Progress::Pending(pending) = &read.value else {
        panic!("a started entry is pending");
    };
    let stopped = Progress::Exchanging {
        pending: pending.clone(),
        owned_until: Utc::now() - chrono::Duration::seconds(1),
    };
    assert!(
        entry
            .pending
            .replace(&key, &read, &stopped, pending.deadline)
            .await
            .unwrap()
    );

    for _ in 0..2 {
        match browser.complete(&entry, "c", REDIRECT).await {
            Err(EntryError::Ambiguous { continuation }) => assert_eq!(continuation, CONTINUATION),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(issuer.exchanges(), 0);
}

// A return's operation reference is stable for its entry and browser and
// differs between entries; its deadline is the one the entry started with.
#[tokio::test]
async fn a_return_names_its_operation_and_deadline() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let before = Utc::now();
    let first = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&first.url, json!({}));
    let returned = first.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(
        first
            .complete(&entry, "c", REDIRECT)
            .await
            .unwrap()
            .operation,
        returned.operation
    );
    let ttl = chrono::Duration::from_std(PENDING_TTL).unwrap();
    assert!(returned.deadline >= before + ttl && returned.deadline <= Utc::now() + ttl);

    let second = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&second.url, json!({}));
    assert_ne!(
        second
            .complete(&entry, "c", REDIRECT)
            .await
            .unwrap()
            .operation,
        returned.operation
    );
}

// A return completes only in the browser that started its entry (RFC 9700
// §4.7.1): the callback URL moved to a browser without the entry's cookie,
// or carrying another entry's, completes nothing, exchanges no code and
// leaves the entry to its own browser, which then completes it.
#[tokio::test]
async fn a_return_completes_only_in_the_browser_that_started_it() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let victim = begin(&entry, &EntryRequest::default()).await;
    let attacker = begin(&entry, &EntryRequest::default()).await;
    issuer.issue_for(&attacker.url, json!({}));

    let state = attacker.state();
    let foreign = format!(
        "{}={}",
        attacker.cookie.split('=').next().unwrap(),
        victim.cookie.split_once('=').unwrap().1
    );
    for cookies in [vec![], vec![victim.cookie.as_str()], vec![foreign.as_str()]] {
        let refused = entry.complete(&state, cookies.clone(), "c", REDIRECT).await;
        assert!(
            matches!(refused, Err(EntryError::OtherBrowser | EntryError::Unknown)),
            "{cookies:?}: {refused:?}"
        );
    }
    assert_eq!(
        issuer.exchanges(),
        0,
        "a code was exchanged in another browser"
    );

    let returned = attacker.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(returned.continuation, CONTINUATION);
}

// Entries started together in two tabs each keep their own correlation
// cookie, named after the authority's cookie and bound to the browser.
#[tokio::test]
async fn entries_started_together_keep_their_own_cookies() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let first = entry
        .start(REDIRECT, CONTINUATION, &EntryRequest::default())
        .await
        .unwrap();
    let second = entry
        .start(REDIRECT, CONTINUATION, &EntryRequest::default())
        .await
        .unwrap();
    let name = |started: &Started| started.set_cookie.split('=').next().unwrap().to_owned();
    assert_ne!(name(&first), name(&second));
    assert!(name(&first).starts_with("__Host-sid_platform-entry-"));
    assert!(
        first
            .set_cookie
            .contains("Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"),
        "{}",
        first.set_cookie
    );
    let (first, second) = (Browser::of(first), Browser::of(second));
    issuer.issue_for(&second.url, json!({}));
    second.complete(&entry, "c", REDIRECT).await.unwrap();
    issuer.issue_for(&first.url, json!({}));
    first.complete(&entry, "c", REDIRECT).await.unwrap();
    assert_eq!(
        entry.clear_cookie(&first.state()),
        format!(
            "{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
            name_of(&first)
        )
    );
}

fn name_of(browser: &Browser) -> &str {
    browser.cookie.split('=').next().unwrap()
}

// The client id and secret are form-urlencoded before Basic encoding
// (RFC 6749 §2.3.1).
#[test]
fn basic_credentials_are_form_encoded() {
    assert_eq!(form_encode("a b:c/d"), "a+b%3Ac%2Fd");
    assert_eq!(form_encode("plain-id_1.2~"), "plain-id_1.2%7E");
}
