use super::*;

use jsonwebtoken::{EncodingKey, Header};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;
use serde_json::json;

const ISSUER: &str = "https://idp.sid.example.com";
const CLIENT: &str = "sid-client";
const NONCE: &str = "the-nonce";

/// A provider's ES256 signing key and its published JWK.
struct Signer {
    kid: String,
    encoding: EncodingKey,
    jwk: serde_json::Value,
}

fn signer(kid: &str) -> Signer {
    let secret = p256::SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
    let point = secret.public_key().to_sec1_point(false);
    let der = secret.to_pkcs8_der().unwrap();
    Signer {
        kid: kid.to_owned(),
        encoding: EncodingKey::from_ec_der(der.as_bytes()),
        jwk: json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "use": "sig",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }),
    }
}

fn keys(signers: &[&Signer]) -> JwkSet {
    serde_json::from_value(
        json!({ "keys": signers.iter().map(|s| s.jwk.clone()).collect::<Vec<_>>() }),
    )
    .unwrap()
}

fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}

/// The claims a correct ID Token for this sign-in carries.
fn claims() -> serde_json::Value {
    json!({
        "iss": ISSUER,
        "sub": "user-1",
        "aud": CLIENT,
        "exp": now() + 300,
        "iat": now(),
        "nonce": NONCE,
        "email": "alice@sid.example.com",
    })
}

fn sign(signer: &Signer, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signer.kid.clone());
    jsonwebtoken::encode(&header, claims, &signer.encoding).unwrap()
}

fn expected(algorithms: &[String]) -> IdTokenExpectation<'_> {
    IdTokenExpectation {
        issuer: ISSUER,
        client_id: CLIENT,
        nonce: NONCE,
        algorithms,
        now: now(),
    }
}

fn refused(result: SidResult<HashMap<String, serde_json::Value>>) {
    assert!(
        matches!(result, Err(SidError::AuthenticationFailed(_))),
        "{result:?}"
    );
}

// A token the provider's published key signed for this client and request
// is accepted, and its claims are the identity.
#[test]
fn a_correct_id_token_is_accepted() {
    let s = signer("k1");
    let validated = validate_id_token(&sign(&s, &claims()), &keys(&[&s]), &expected(&[])).unwrap();
    assert_eq!(validated["sub"], "user-1");
    assert_eq!(validated["email"], "alice@sid.example.com");
}

// Signed by a key the provider does not publish, or under a key id it does
// not name: not the provider's token.
#[test]
fn another_key_is_refused() {
    let published = signer("k1");
    let other = signer("k1");
    refused(validate_id_token(
        &sign(&other, &claims()),
        &keys(&[&published]),
        &expected(&[]),
    ));
    let unknown = signer("k2");
    refused(validate_id_token(
        &sign(&unknown, &claims()),
        &keys(&[&published]),
        &expected(&[]),
    ));
}

// Without a key id the one published key decides; with several it is
// ambiguous and refused.
#[test]
fn a_token_without_key_id_needs_a_single_key() {
    let s = signer("k1");
    let header = Header::new(Algorithm::ES256);
    let token = jsonwebtoken::encode(&header, &claims(), &s.encoding).unwrap();
    validate_id_token(&token, &keys(&[&s]), &expected(&[])).unwrap();
    let second = signer("k2");
    refused(validate_id_token(
        &token,
        &keys(&[&s, &second]),
        &expected(&[]),
    ));
}

// HMAC (keyed with anything a client could know) and an algorithm the
// provider does not advertise are refused.
#[test]
fn symmetric_and_unadvertised_algorithms_are_refused() {
    let s = signer("k1");
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    let hmac = jsonwebtoken::encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(b"client secret"),
    )
    .unwrap();
    refused(validate_id_token(&hmac, &keys(&[&s]), &expected(&[])));
    refused(validate_id_token(
        &sign(&s, &claims()),
        &keys(&[&s]),
        &expected(&["RS256".to_owned()]),
    ));
    validate_id_token(
        &sign(&s, &claims()),
        &keys(&[&s]),
        &expected(&["RS256".to_owned(), "ES256".to_owned()]),
    )
    .unwrap();
}

// Another issuer, another audience, an expired token and a token without
// an expiry are refused.
#[test]
fn issuer_audience_and_expiry_are_checked() {
    let s = signer("k1");
    let set = keys(&[&s]);
    let with = |field: &str, value: serde_json::Value| {
        let mut c = claims();
        c[field] = value;
        sign(&s, &c)
    };
    refused(validate_id_token(
        &with("iss", json!("https://other.sid.example.com")),
        &set,
        &expected(&[]),
    ));
    refused(validate_id_token(
        &with("aud", json!("another-client")),
        &set,
        &expected(&[]),
    ));
    refused(validate_id_token(
        &with("exp", json!(now() - 3600)),
        &set,
        &expected(&[]),
    ));
    let mut no_exp = claims();
    no_exp.as_object_mut().unwrap().remove("exp");
    refused(validate_id_token(&sign(&s, &no_exp), &set, &expected(&[])));
}

// An issue time is required and may not lie in the future.
#[test]
fn the_issue_time_is_checked() {
    let s = signer("k1");
    let set = keys(&[&s]);
    let mut no_iat = claims();
    no_iat.as_object_mut().unwrap().remove("iat");
    refused(validate_id_token(&sign(&s, &no_iat), &set, &expected(&[])));
    let mut future = claims();
    future["iat"] = json!(now() + 3600);
    refused(validate_id_token(&sign(&s, &future), &set, &expected(&[])));
}

// The nonce binds the token to this request: another or none is refused.
#[test]
fn the_nonce_is_checked() {
    let s = signer("k1");
    let set = keys(&[&s]);
    let mut other = claims();
    other["nonce"] = json!("another");
    refused(validate_id_token(&sign(&s, &other), &set, &expected(&[])));
    let mut none = claims();
    none.as_object_mut().unwrap().remove("nonce");
    refused(validate_id_token(&sign(&s, &none), &set, &expected(&[])));
}

// Several audiences require this client as the authorized party; an
// authorized party that is another client is refused.
#[test]
fn several_audiences_need_this_client_as_authorized_party() {
    let s = signer("k1");
    let set = keys(&[&s]);
    let mut several = claims();
    several["aud"] = json!([CLIENT, "another-client"]);
    refused(validate_id_token(&sign(&s, &several), &set, &expected(&[])));
    several["azp"] = json!(CLIENT);
    validate_id_token(&sign(&s, &several), &set, &expected(&[])).unwrap();
    let mut foreign = claims();
    foreign["azp"] = json!("another-client");
    refused(validate_id_token(&sign(&s, &foreign), &set, &expected(&[])));
}

// A token without a subject identifies nobody.
#[test]
fn a_subject_is_required() {
    let s = signer("k1");
    let mut empty = claims();
    empty["sub"] = json!("");
    refused(validate_id_token(
        &sign(&s, &empty),
        &keys(&[&s]),
        &expected(&[]),
    ));
}

// UserInfo about another subject fails the sign-in; about the same one it
// adds claims without replacing the ID Token's.
#[test]
fn userinfo_must_be_about_the_same_subject() {
    let id_token: HashMap<String, serde_json::Value> =
        serde_json::from_value(json!({"sub": "user-1", "email": "a@sid.example.com"})).unwrap();
    let other: HashMap<String, serde_json::Value> =
        serde_json::from_value(json!({"sub": "user-2", "name": "Mallory"})).unwrap();
    assert!(matches!(
        merge_userinfo(id_token.clone(), other),
        Err(SidError::AuthenticationFailed(_))
    ));
    let same: HashMap<String, serde_json::Value> = serde_json::from_value(
        json!({"sub": "user-1", "name": "Alice", "email": "b@sid.example.com"}),
    )
    .unwrap();
    let merged = merge_userinfo(id_token, same).unwrap();
    assert_eq!(merged["name"], "Alice");
    assert_eq!(merged["email"], "a@sid.example.com");
}

// The email and its verification come from one source: a UserInfo
// verification never vouches for the ID Token's address, and an address
// only UserInfo names comes with UserInfo's own verification.
#[test]
fn an_email_keeps_its_own_verification() {
    let id_token: HashMap<String, serde_json::Value> =
        serde_json::from_value(json!({"sub": "user-1", "email": "old@sid.example.com"})).unwrap();
    let userinfo: HashMap<String, serde_json::Value> = serde_json::from_value(
        json!({"sub": "user-1", "email": "new@sid.example.com", "email_verified": true}),
    )
    .unwrap();
    let merged = merge_userinfo(id_token, userinfo.clone()).unwrap();
    assert_eq!(merged["email"], "old@sid.example.com");
    assert!(!merged.contains_key("email_verified"), "{merged:?}");

    let without: HashMap<String, serde_json::Value> =
        serde_json::from_value(json!({"sub": "user-1"})).unwrap();
    let merged = merge_userinfo(without, userinfo).unwrap();
    assert_eq!(merged["email"], "new@sid.example.com");
    assert_eq!(merged["email_verified"], true);
}

// The discovery URL is the issuer, without one terminating slash, with the
// well-known suffix (OpenID Connect Discovery 1.0 §4.1); the document must
// name that issuer (§4.3).
#[test]
fn the_discovered_issuer_is_the_named_one() {
    let url = |issuer: &str| format!("{issuer}{DISCOVERY_SUFFIX}");
    check_discovered_issuer(&url(ISSUER), ISSUER).unwrap();
    let tenant = "https://idp.sid.example.com/tenant/";
    check_discovered_issuer(&url("https://idp.sid.example.com/tenant"), tenant).unwrap();
    assert!(check_discovered_issuer(&url(ISSUER), "https://other.sid.example.com").is_err());
    assert!(check_discovered_issuer(&url(&format!("{ISSUER}/")), ISSUER).is_err());
    assert!(check_discovered_issuer(ISSUER, ISSUER).is_err());
}

// RFC 7636 Appendix B: the S256 challenge of the specification's verifier.
#[test]
fn the_pkce_challenge_is_s256() {
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn random_tokens_are_fresh() {
    let a = random_token();
    assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
    assert_ne!(a, random_token());
}

#[test]
fn test_oidc_discovery_deserialize() {
    let json = r#"{
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "id_token_signing_alg_values_supported": ["RS256"]
    }"#;

    let discovery: OidcDiscovery = serde_json::from_str(json).unwrap();
    assert_eq!(discovery.issuer, "https://accounts.google.com");
    assert_eq!(
        discovery.jwks_uri.as_deref(),
        Some("https://www.googleapis.com/oauth2/v3/certs")
    );
    assert_eq!(discovery.id_token_signing_alg_values_supported, ["RS256"]);
    assert!(discovery.userinfo_endpoint.is_some());
}

#[test]
fn test_token_response_deserialize() {
    let resp: TokenResponse =
        serde_json::from_str(r#"{"access_token": "token123", "id_token": "a.b.c"}"#).unwrap();
    assert_eq!(resp.access_token, "token123");
    assert_eq!(resp.id_token.as_deref(), Some("a.b.c"));
    let minimal: TokenResponse = serde_json::from_str(r#"{"access_token": "t"}"#).unwrap();
    assert!(minimal.id_token.is_none());
}

/// A local HTTP server answering each request whose path is a key of the
/// routes `routes` builds from the server's own base URL with that JSON
/// body, any other with 404. Returns that base URL.
async fn serve(routes: impl FnOnce(&str) -> Vec<(String, serde_json::Value)>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let routes = routes(&base);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let read = socket.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]);
            let path = request.split_whitespace().nth(1).unwrap_or("").to_owned();
            let answer = match routes.iter().find(|(p, _)| *p == path) {
                Some((_, body)) => {
                    let body = body.to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                }
                None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    .to_owned(),
            };
            let _ = socket.write_all(answer.as_bytes()).await;
        }
    });
    base
}

fn document(issuer: &str, jwks_uri: Option<&str>) -> serde_json::Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "jwks_uri": jwks_uri,
    })
}

/// A client under the host's TLS selection, as the server builds one; the
/// first test to run selects it for the process.
fn http() -> Client {
    let _ = sid_crypto::tls::aws_lc::provider().install_default();
    sid_plugin::client_builder().unwrap().build().unwrap()
}

// The discovery of an exact issuer identifier is the document at that
// issuer's well-known path, naming that issuer and its key set.
#[tokio::test]
async fn an_issuer_is_discovered_at_its_own_path() {
    let base = serve(|base| {
        vec![(
            "/i/central/.well-known/openid-configuration".into(),
            document(&format!("{base}/i/central"), Some("https://k.example/jwks")),
        )]
    })
    .await;
    let issuer = format!("{base}/i/central");
    let discovery = discover(&http(), &issuer).await.unwrap();
    assert_eq!(discovery.issuer, issuer);
    assert_eq!(
        discovery.jwks_uri.as_deref(),
        Some("https://k.example/jwks")
    );
}

// Regression guard: a document naming another issuer, or no key set, is
// refused (OpenID Connect Discovery 1.0 §4.3); a missing document fails.
#[tokio::test]
async fn a_document_of_another_issuer_or_without_keys_is_refused() {
    let base = serve(|base| {
        vec![
            (
                "/other/.well-known/openid-configuration".into(),
                document("https://elsewhere.example/other", Some("https://k.example")),
            ),
            (
                "/keyless/.well-known/openid-configuration".into(),
                document(&format!("{base}/keyless"), None),
            ),
        ]
    })
    .await;
    for path in ["other", "keyless", "missing"] {
        assert!(
            discover(&http(), &format!("{base}/{path}")).await.is_err(),
            "{path}"
        );
    }
}

// An issuer's key set is read from its JWK Set document; a failing one is
// an error, never an empty set.
#[tokio::test]
async fn a_key_set_is_fetched_or_fails() {
    let signer = signer("k1");
    let set = json!({ "keys": [signer.jwk] });
    let base = serve(|_| vec![("/jwks".into(), set)]).await;
    let keys = fetch_key_set(&http(), &format!("{base}/jwks"))
        .await
        .unwrap();
    assert!(keys.find("k1").is_some());
    assert!(
        fetch_key_set(&http(), &format!("{base}/missing"))
            .await
            .is_err()
    );
}
