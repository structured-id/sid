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
                let (status, answer) = match path.as_str() {
                    "/i/central/.well-known/openid-configuration" => (200, discovery.clone()),
                    "/i/central/jwks" => (200, keys.clone()),
                    "/i/central/oauth2/token" => token(&state, &head, &body),
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
            "nonce": param("nonce").unwrap(),
        });
        for (k, v) in claims.as_object().unwrap() {
            all[k] = v.clone();
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
    FederatedEntry::new(
        issuer.trusted(),
        http(),
        Arc::new(InMemoryCacheBackend::new()),
        crate::test_support::key_manager(),
    )
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
    let url = entry.start(REDIRECT, CONTINUATION, &request).await.unwrap();
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
    let returned = entry
        .complete(&state_of(&url), "the-code", REDIRECT)
        .await
        .unwrap();
    assert_eq!(returned.subject, "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e");
    assert_eq!(returned.continuation, CONTINUATION);
    assert_eq!(
        returned.evidence,
        Evidence {
            acr: Some(AuthLevel::Elevated),
            amr: vec!["hwk".into(), "user".into()],
            auth_time: Utc.timestamp_opt(auth_time as i64, 0).single(),
        }
    );
}

// Regression guard: a return completes once. A replayed state, an unknown
// one and one returning to another redirect URI complete nothing, and the
// last never reaches the token endpoint.
#[tokio::test]
async fn a_return_completes_once_and_only_at_its_redirect() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let url = entry
        .start(REDIRECT, CONTINUATION, &EntryRequest::default())
        .await
        .unwrap();
    issuer.issue_for(&url, json!({}));
    let state = state_of(&url);
    entry.complete(&state, "c", REDIRECT).await.unwrap();
    assert!(matches!(
        entry.complete(&state, "c", REDIRECT).await,
        Err(EntryError::Unknown)
    ));
    assert!(matches!(
        entry.complete("unknown", "c", REDIRECT).await,
        Err(EntryError::Unknown)
    ));

    let other = entry
        .start(REDIRECT, CONTINUATION, &EntryRequest::default())
        .await
        .unwrap();
    let before = issuer.exchanges();
    assert!(matches!(
        entry
            .complete(&state_of(&other), "c", "https://elsewhere.example/callback")
            .await,
        Err(EntryError::RedirectMismatch)
    ));
    assert_eq!(issuer.exchanges(), before);
    // The mismatched return consumed its state: the entry is over.
    assert!(matches!(
        entry.complete(&state_of(&other), "c", REDIRECT).await,
        Err(EntryError::Unknown)
    ));
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
        let url = entry
            .start(REDIRECT, CONTINUATION, &EntryRequest::default())
            .await
            .unwrap();
        issuer.issue_for(&url, claims);
        let refused = entry.complete(&state_of(&url), "c", REDIRECT).await;
        assert!(
            matches!(refused, Err(EntryError::Token(_))),
            "{case}: {refused:?}"
        );
    }
}

// Regression guard: an entry that asked for max_age needs auth_time in the
// ID Token (OpenID Connect Core 1.0 §2); one that did not may go without.
#[tokio::test]
async fn auth_time_is_required_after_a_max_age_request() {
    let issuer = TestIssuer::start().await;
    let entry = entry(&issuer);
    let aged = EntryRequest {
        acr: None,
        max_age: Some(Duration::from_secs(60)),
    };
    let url = entry.start(REDIRECT, CONTINUATION, &aged).await.unwrap();
    issuer.issue_for(&url, json!({}));
    assert!(matches!(
        entry.complete(&state_of(&url), "c", REDIRECT).await,
        Err(EntryError::Token(_))
    ));

    let url = entry
        .start(REDIRECT, CONTINUATION, &EntryRequest::default())
        .await
        .unwrap();
    issuer.issue_for(&url, json!({}));
    let returned = entry
        .complete(&state_of(&url), "c", REDIRECT)
        .await
        .unwrap();
    assert_eq!(returned.evidence.auth_time, None);
    assert_eq!(returned.evidence.acr, None);
}

// The client id and secret are form-urlencoded before Basic encoding
// (RFC 6749 §2.3.1).
#[test]
fn basic_credentials_are_form_encoded() {
    assert_eq!(form_encode("a b:c/d"), "a+b%3Ac%2Fd");
    assert_eq!(form_encode("plain-id_1.2~"), "plain-id_1.2%7E");
}
