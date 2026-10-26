//! Sign-in through an upstream OIDC provider over real HTTP: a provider
//! served in this process publishes its discovery document, keys, token and
//! UserInfo endpoints. The identity is the validated ID Token; a token for
//! another request, an absent token and UserInfo about another subject sign
//! nobody in.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use sid_authn::upstream::oidc::OidcProviderClient;
use sid_core::models::{UpstreamProtocol, UpstreamProvider};
use sid_plugin::UpstreamIdpProvider;
use sid_plugin::upstream::PendingAuthorization;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Only its TLS provider selection is used here.
#[allow(dead_code)]
#[path = "../../../tests/support/crypto.rs"]
mod test_crypto;

const CLIENT: &str = "sid-client";
const REDIRECT: &str = "https://sid.example.com/callback";

/// What the provider answers, and what it was sent.
#[derive(Default)]
struct Provider {
    issuer: String,
    /// The `issuer` its discovery document names; the real one when unset.
    announced_issuer: Option<String>,
    jwk: Value,
    /// The token endpoint's answer.
    token: Value,
    /// The UserInfo endpoint's answer.
    userinfo: Value,
    /// The token request bodies received.
    token_requests: Vec<String>,
}

type Shared = Arc<Mutex<Provider>>;

/// Serve the provider on a free local port; returns its issuer.
async fn serve(provider: Shared) -> String {
    test_crypto::install_tls();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    provider.lock().unwrap().issuer = issuer.clone();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let provider = provider.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut read = 0;
                let (head, body) = loop {
                    let n = socket.read(&mut buf[read..]).await.unwrap();
                    read += n;
                    let text = String::from_utf8_lossy(&buf[..read]).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let head = text[..end].to_string();
                        let length = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if read >= end + 4 + length {
                            break (head, text[end + 4..end + 4 + length].to_string());
                        }
                    }
                    if n == 0 {
                        return;
                    }
                };
                let path = head.split_whitespace().nth(1).unwrap().to_string();
                let answer = {
                    let mut p = provider.lock().unwrap();
                    match path.as_str() {
                        "/.well-known/openid-configuration" => json!({
                            "issuer": p.announced_issuer.clone().unwrap_or(p.issuer.clone()),
                            "authorization_endpoint": format!("{}/authorize", p.issuer),
                            "token_endpoint": format!("{}/token", p.issuer),
                            "userinfo_endpoint": format!("{}/userinfo", p.issuer),
                            "jwks_uri": format!("{}/jwks", p.issuer),
                            "id_token_signing_alg_values_supported": ["ES256"],
                        }),
                        "/jwks" => json!({ "keys": [p.jwk.clone()] }),
                        "/token" => {
                            p.token_requests.push(body);
                            p.token.clone()
                        }
                        "/userinfo" => p.userinfo.clone(),
                        _ => json!({}),
                    }
                };
                let body = answer.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    issuer
}

/// The provider's signing key and its JWK.
fn key() -> (EncodingKey, Value) {
    let secret = p256::SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
    let point = secret.public_key().to_sec1_point(false);
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    (
        EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes()),
        jwk,
    )
}

fn id_token(key: &EncodingKey, issuer: &str, nonce: &str, sub: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("k1".into());
    let now = jsonwebtoken::get_current_timestamp();
    jsonwebtoken::encode(
        &header,
        &json!({
            "iss": issuer, "sub": sub, "aud": CLIENT,
            "exp": now + 300, "iat": now, "nonce": nonce,
        }),
        key,
    )
    .unwrap()
}

fn configured(issuer: &str) -> UpstreamProvider {
    let secret = sid_keys::EncryptedField {
        ciphertext: Vec::new(),
        nonce: [0; 12],
        key_version: 1,
        context: "upstream:test".into(),
    };
    let mut provider = UpstreamProvider::new("Test IdP", UpstreamProtocol::Oidc, CLIENT, secret);
    provider.discovery_url = Some(format!("{issuer}/.well-known/openid-configuration"));
    provider
}

struct Setup {
    provider: Shared,
    issuer: String,
    key: EncodingKey,
    client: OidcProviderClient,
}

async fn setup() -> Setup {
    let (key, jwk) = key();
    let provider: Shared = Arc::new(Mutex::new(Provider {
        jwk,
        ..Default::default()
    }));
    let issuer = serve(provider.clone()).await;
    let client = OidcProviderClient::from_provider(&configured(&issuer), "secret".into())
        .await
        .unwrap();
    Setup {
        provider,
        issuer,
        key,
        client,
    }
}

fn query(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

// The request carries `openid`, its nonce and the S256 challenge; the code
// exchange sends the stored verifier, and the identity is the ID Token's
// issuer and subject, with UserInfo's claims for that subject.
#[tokio::test]
async fn a_valid_id_token_signs_the_user_in() {
    let s = setup().await;
    let request = s
        .client
        .authorization_request(REDIRECT, &["email".into()])
        .await
        .unwrap();
    let q = query(&request.url);
    assert!(q["scope"].split(' ').any(|v| v == "openid"));
    let nonce = request.nonce.clone().unwrap();
    assert_eq!(q["nonce"], nonce);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["state"], request.state);
    {
        let mut p = s.provider.lock().unwrap();
        p.token = json!({
            "access_token": "at",
            "id_token": id_token(&s.key, &s.issuer, &nonce, "user-1"),
        });
        p.userinfo = json!({ "sub": "user-1", "email": "alice@sid.example.com" });
    }
    let claims = s
        .client
        .exchange_code(
            "the-code",
            &PendingAuthorization {
                redirect_uri: REDIRECT,
                code_verifier: &request.code_verifier,
                nonce: request.nonce.as_deref(),
            },
        )
        .await
        .unwrap();
    assert_eq!(claims.upstream_subject, "user-1");
    assert_eq!(claims.upstream_issuer.as_deref(), Some(s.issuer.as_str()));
    assert_eq!(claims.email.as_deref(), Some("alice@sid.example.com"));
    let sent = s.provider.lock().unwrap().token_requests[0].clone();
    assert!(sent.contains(&format!("code_verifier={}", request.code_verifier)));
}

// A token minted for another request (its nonce), no token at all, and
// UserInfo about another subject each fail the sign-in.
#[tokio::test]
async fn only_this_requests_id_token_signs_in() {
    let s = setup().await;
    let request = s.client.authorization_request(REDIRECT, &[]).await.unwrap();
    let pending = PendingAuthorization {
        redirect_uri: REDIRECT,
        code_verifier: &request.code_verifier,
        nonce: request.nonce.as_deref(),
    };
    let nonce = request.nonce.clone().unwrap();
    let cases = [
        (
            json!({ "access_token": "at", "id_token": id_token(&s.key, &s.issuer, "another", "user-1") }),
            json!({ "sub": "user-1" }),
        ),
        (json!({ "access_token": "at" }), json!({ "sub": "user-1" })),
        (
            json!({ "access_token": "at", "id_token": id_token(&s.key, &s.issuer, &nonce, "user-1") }),
            json!({ "sub": "user-2" }),
        ),
    ];
    for (token, userinfo) in cases {
        {
            let mut p = s.provider.lock().unwrap();
            p.token = token.clone();
            p.userinfo = userinfo;
        }
        let result = s.client.exchange_code("the-code", &pending).await;
        assert!(
            matches!(result, Err(sid_core::Error::AuthenticationFailed(_))),
            "{token}: {result:?}"
        );
    }
}

// A discovery document naming another issuer than its URL is refused, and
// an OIDC provider configured without discovery is refused.
#[tokio::test]
async fn the_provider_is_its_discovered_issuer() {
    let (_, jwk) = key();
    let provider: Shared = Arc::new(Mutex::new(Provider {
        jwk,
        announced_issuer: Some("https://other.sid.example.com".into()),
        ..Default::default()
    }));
    let issuer = serve(provider).await;
    assert!(matches!(
        OidcProviderClient::from_provider(&configured(&issuer), "secret".into()).await,
        Err(sid_core::Error::Validation(_))
    ));
    let mut manual = configured(&issuer);
    manual.discovery_url = None;
    manual.authorization_endpoint = Some(format!("{issuer}/authorize"));
    manual.token_endpoint = Some(format!("{issuer}/token"));
    assert!(matches!(
        OidcProviderClient::from_provider(&manual, "secret".into()).await,
        Err(sid_core::Error::Validation(_))
    ));
}
