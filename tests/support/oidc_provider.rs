//! An upstream OIDC provider served in the test's process over plain HTTP:
//! its discovery document, ES256 keys, token and UserInfo endpoints. The
//! test sets what the token and UserInfo endpoints answer and reads what the
//! token endpoint was sent.

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The client id the provider registers SID under.
pub const CLIENT: &str = "sid-client";

/// What the provider answers, and what it was sent.
#[derive(Default)]
pub struct State {
    pub issuer: String,
    /// The `issuer` its discovery document names; the real one when unset.
    pub announced_issuer: Option<String>,
    jwk: Value,
    /// The token endpoint's answer.
    pub token: Value,
    /// The UserInfo endpoint's answer.
    pub userinfo: Value,
    /// The token request bodies received.
    pub token_requests: Vec<String>,
}

/// A running provider and its signing key.
pub struct Provider {
    pub state: Arc<Mutex<State>>,
    pub issuer: String,
    key: EncodingKey,
}

impl Provider {
    /// A provider on a free local port, announcing `announced_issuer` in its
    /// discovery document when given.
    pub async fn start(announced_issuer: Option<&str>) -> Self {
        let secret = p256::SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let point = secret.public_key().to_sec1_point(false);
        let jwk = json!({
            "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let state = Arc::new(Mutex::new(State {
            jwk,
            announced_issuer: announced_issuer.map(str::to_owned),
            ..Default::default()
        }));
        let issuer = serve(state.clone()).await;
        Self {
            state,
            issuer,
            key: EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes()),
        }
    }

    /// Its discovery URL.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }

    /// An ID Token for `sub` with `nonce`, signed by this provider for
    /// [`CLIENT`].
    pub fn id_token(&self, nonce: &str, sub: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".into());
        let now = jsonwebtoken::get_current_timestamp();
        jsonwebtoken::encode(
            &header,
            &json!({
                "iss": self.issuer, "sub": sub, "aud": CLIENT,
                "exp": now + 300, "iat": now, "nonce": nonce,
            }),
            &self.key,
        )
        .unwrap()
    }

    /// The token endpoint answers `token`, UserInfo `userinfo`.
    pub fn answer(&self, token: Value, userinfo: Value) {
        let mut s = self.state.lock().unwrap();
        s.token = token;
        s.userinfo = userinfo;
    }

    /// The token request bodies received so far.
    pub fn token_requests(&self) -> Vec<String> {
        self.state.lock().unwrap().token_requests.clone()
    }
}

/// Serve `state` on a free local port; returns the issuer.
async fn serve(state: Arc<Mutex<State>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    state.lock().unwrap().issuer = issuer.clone();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let state = state.clone();
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
                    let mut p = state.lock().unwrap();
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
