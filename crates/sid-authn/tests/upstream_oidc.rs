//! Sign-in through an upstream OIDC provider over real HTTP: a provider
//! served in this process publishes its discovery document, keys, token and
//! UserInfo endpoints. The identity is the validated ID Token; a token for
//! another request, an absent token and UserInfo about another subject sign
//! nobody in.

use std::collections::HashMap;

use serde_json::json;
use sid_authn::upstream::oidc::OidcProviderClient;
use sid_core::models::{UpstreamProtocol, UpstreamProvider};
use sid_plugin::UpstreamIdpProvider;
use sid_plugin::upstream::PendingAuthorization;

// Only its TLS provider selection is used here.
#[path = "../../../tests/support/oidc_provider.rs"]
mod oidc_provider;
#[allow(dead_code)]
#[path = "../../../tests/support/crypto.rs"]
mod test_crypto;

use oidc_provider::{CLIENT, Provider};

const REDIRECT: &str = "https://sid.example.com/callback";

fn configured(provider: &Provider) -> UpstreamProvider {
    let secret = sid_keys::EncryptedField {
        ciphertext: Vec::new(),
        nonce: [0; 12],
        key_version: 1,
        context: "upstream:test".into(),
    };
    let mut configured = UpstreamProvider::new("Test IdP", UpstreamProtocol::Oidc, CLIENT, secret);
    configured.discovery_url = Some(provider.discovery_url());
    configured
}

async fn setup() -> (Provider, OidcProviderClient) {
    test_crypto::install_tls();
    let provider = Provider::start(None).await;
    let client = OidcProviderClient::from_provider(&configured(&provider), "secret".into())
        .await
        .unwrap();
    (provider, client)
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
    let (provider, client) = setup().await;
    let request = client
        .authorization_request(REDIRECT, &["email".into()])
        .await
        .unwrap();
    let q = query(&request.url);
    assert!(q["scope"].split(' ').any(|v| v == "openid"));
    let nonce = request.nonce.clone().unwrap();
    assert_eq!(q["nonce"], nonce);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["state"], request.state);
    provider.answer(
        json!({ "access_token": "at", "id_token": provider.id_token(&nonce, "user-1") }),
        json!({ "sub": "user-1", "email": "alice@sid.example.com" }),
    );
    let claims = client
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
    assert_eq!(
        claims.upstream_issuer.as_deref(),
        Some(provider.issuer.as_str())
    );
    assert_eq!(claims.email.as_deref(), Some("alice@sid.example.com"));
    let sent = provider.token_requests()[0].clone();
    assert!(sent.contains(&format!("code_verifier={}", request.code_verifier)));
}

// A token minted for another request (its nonce), no token at all, and
// UserInfo about another subject each fail the sign-in.
#[tokio::test]
async fn only_this_requests_id_token_signs_in() {
    let (provider, client) = setup().await;
    let request = client.authorization_request(REDIRECT, &[]).await.unwrap();
    let pending = PendingAuthorization {
        redirect_uri: REDIRECT,
        code_verifier: &request.code_verifier,
        nonce: request.nonce.as_deref(),
    };
    let nonce = request.nonce.clone().unwrap();
    let cases = [
        (
            json!({ "access_token": "at", "id_token": provider.id_token("another", "user-1") }),
            json!({ "sub": "user-1" }),
        ),
        (json!({ "access_token": "at" }), json!({ "sub": "user-1" })),
        (
            json!({ "access_token": "at", "id_token": provider.id_token(&nonce, "user-1") }),
            json!({ "sub": "user-2" }),
        ),
    ];
    for (token, userinfo) in cases {
        provider.answer(token.clone(), userinfo);
        let result = client.exchange_code("the-code", &pending).await;
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
    test_crypto::install_tls();
    let provider = Provider::start(Some("https://other.sid.example.com")).await;
    assert!(matches!(
        OidcProviderClient::from_provider(&configured(&provider), "secret".into()).await,
        Err(sid_core::Error::Validation(_))
    ));
    let mut manual = configured(&provider);
    manual.discovery_url = None;
    manual.authorization_endpoint = Some(format!("{}/authorize", provider.issuer));
    manual.token_endpoint = Some(format!("{}/token", provider.issuer));
    assert!(matches!(
        OidcProviderClient::from_provider(&manual, "secret".into()).await,
        Err(sid_core::Error::Validation(_))
    ));
}
