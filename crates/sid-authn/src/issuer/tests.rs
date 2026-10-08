// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support::{foreign_key_manager, key_manager};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use sid_storage::sqlite::SqliteBackend;

/// An installation: storage with its organization.
async fn installation() -> (SqliteBackend, OrgId) {
    let storage = SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite");
    let org = crate::instance_org::ensure(&storage, "sid.example.com")
        .await
        .unwrap()
        .id;
    (storage, org)
}

fn base() -> Url {
    Url::parse("https://id.sid.example.com").unwrap()
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
}

fn claims_for(issuer: &OidcIssuer) -> Claims {
    Claims {
        iss: issuer.canonical_url.clone(),
        sub: "subject".into(),
        aud: "client".into(),
        exp: chrono::Utc::now().timestamp() + 60,
    }
}

/// Verify `token` against `jwks` for `issuer`, as a relying party does.
fn verify(token: &str, jwks: &JwkSet, issuer: &str) -> jsonwebtoken::errors::Result<Claims> {
    let kid = decode_header(token)?.kid.unwrap_or_default();
    let Some(jwk) = jwks.keys.iter().find(|k| k.kid == kid) else {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into());
    };
    let key = DecodingKey::from_ed_components(&jwk.x)?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&["client"]);
    decode::<Claims>(token, &key, &validation).map(|d| d.claims)
}

/// The installation's issuer is created once and read back unchanged by
/// every later start: its URL is `{base}/i/{handle}`.
#[tokio::test]
async fn provisioning_is_stable_across_starts() {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let first = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    let again = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(first.recipient_org, org);
    assert_eq!(first.authority, IssuerAuthority::Local);
    assert_eq!(
        first.canonical_url,
        format!("https://id.sid.example.com/i/{}", first.handle)
    );
    assert_eq!(
        storage
            .oidc_issuer_signing_keys(first.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A later start with a different public URL keeps the stored issuer: the
/// URL is identity and changes only by explicit migration.
#[tokio::test]
async fn a_changed_base_url_does_not_rewrite_the_issuer() {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let first = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    let moved = Url::parse("https://login.sid.example.com").unwrap();
    let later = ensure_local_issuer(&storage, keys.as_ref(), &moved, org)
        .await
        .unwrap();
    assert_eq!(later.canonical_url, first.canonical_url);
}

/// Replicas starting together agree on one issuer and one key.
#[tokio::test]
async fn concurrent_provisioning_yields_one_issuer() {
    let (storage, org) = installation().await;
    let (keys, base) = (key_manager(), base());
    let (a, b) = tokio::join!(
        ensure_local_issuer(&storage, keys.as_ref(), &base, org),
        ensure_local_issuer(&storage, keys.as_ref(), &base, org),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a, b);
    assert_eq!(
        storage.oidc_issuer_signing_keys(a.id).await.unwrap().len(),
        1
    );
}

/// Every issuer has one registered UserInfo resource: its indicator is the
/// issuer's UserInfo endpoint, it supports the OIDC scopes, and replicas
/// provisioning it together agree on one. No client gets access to it by
/// its existence (auth/oauth-resource-model.md: explicitly selected).
#[tokio::test]
async fn the_userinfo_resource_is_provisioned_once() {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let issuer = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        ensure_userinfo_resource(&storage, &issuer),
        ensure_userinfo_resource(&storage, &issuer),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.id, b.id);
    assert_eq!(
        a.indicator.as_str(),
        format!("{}/userinfo", issuer.canonical_url)
    );
    assert_eq!(
        a.indicator.as_str(),
        userinfo_endpoint(&issuer.canonical_url)
    );
    assert_eq!(a.issuer_id, issuer.id);
    assert!(a.is_target());
    for scope in ["openid", "profile", "email", "phone", "address"] {
        assert!(a.scopes.iter().any(|s| s == scope), "{scope}");
    }
    let again = ensure_userinfo_resource(&storage, &issuer).await.unwrap();
    assert_eq!(again.id, a.id);
    assert!(
        storage
            .list_resource_access_by_resource(a.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The issuer's SCIM directory resource is registered once, at the SCIM base
/// URL, with the SCIM actions as its scopes, beside (not instead of) the
/// UserInfo resource; no client gains access by it.
#[tokio::test]
async fn the_scim_resource_is_provisioned_once() {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let issuer = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    let userinfo = ensure_userinfo_resource(&storage, &issuer).await.unwrap();
    let (a, b) = tokio::join!(
        ensure_scim_resource(&storage, &issuer),
        ensure_scim_resource(&storage, &issuer),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.id, b.id);
    assert_ne!(a.id, userinfo.id);
    assert_eq!(
        a.indicator.as_str(),
        format!("{}/scim/v2", issuer.canonical_url)
    );
    assert_eq!(a.issuer_id, issuer.id);
    assert_eq!(
        a.scopes,
        sid_core::models::SCIM_ACTIONS.map(String::from).to_vec()
    );
    assert_eq!(
        ensure_scim_resource(&storage, &issuer).await.unwrap().id,
        a.id
    );
    assert!(
        storage
            .list_resource_access_by_resource(a.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// OIDC Discovery 1.0 §3: an issuer is https without query or fragment;
/// plain http only on a loopback host (local development).
#[test]
fn issuer_url_follows_the_discovery_rules() {
    let handle = IssuerHandle::generate();
    let url = |base: &str| issuer_url(&Url::parse(base).unwrap(), &handle);
    assert_eq!(
        url("https://sid.example.com/").unwrap(),
        format!("https://sid.example.com/i/{handle}")
    );
    assert_eq!(
        url("https://sid.example.com/auth").unwrap(),
        format!("https://sid.example.com/auth/i/{handle}")
    );
    assert!(url("http://localhost:8080").is_ok());
    assert!(url("http://127.0.0.1").is_ok());
    for bad in [
        "http://sid.example.com",
        "https://sid.example.com/?x=1",
        "https://sid.example.com/#f",
        "ftp://sid.example.com",
    ] {
        assert!(url(bad).is_err(), "accepted {bad}");
    }
}

/// A token signed for the issuer verifies with that issuer's published keys
/// and names its key.
#[tokio::test]
async fn signer_output_verifies_with_the_issuers_jwks() {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let issuer = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    let signer = IssuerSigner::load(&storage, keys.as_ref(), issuer.clone())
        .await
        .unwrap();
    let token = signer.sign(None, &claims_for(&issuer)).unwrap();

    let header = decode_header(&token).unwrap();
    assert_eq!(header.alg, Algorithm::EdDSA);
    assert_eq!(
        header.kid.as_deref(),
        Some(signer.jwks().keys[0].kid.as_str())
    );
    assert_eq!(
        verify(&token, signer.jwks(), &issuer.canonical_url).unwrap(),
        claims_for(&issuer)
    );
    // A logout token carries its explicit type (Back-Channel Logout 1.0 §2.4).
    let typed = signer
        .sign(Some("logout+jwt"), &claims_for(&issuer))
        .unwrap();
    assert_eq!(
        decode_header(&typed).unwrap().typ.as_deref(),
        Some("logout+jwt")
    );
}

/// Two installations' issuers have unrelated keys: a token of one does not
/// verify under the other's keys, even under the other's issuer name.
#[tokio::test]
async fn another_issuers_keys_do_not_verify() {
    let keys = key_manager();
    let (storage_a, org_a) = installation().await;
    let (storage_b, org_b) = installation().await;
    let a = ensure_local_issuer(&storage_a, keys.as_ref(), &base(), org_a)
        .await
        .unwrap();
    let b = ensure_local_issuer(&storage_b, keys.as_ref(), &base(), org_b)
        .await
        .unwrap();
    assert_ne!(a.canonical_url, b.canonical_url);
    let signer_a = IssuerSigner::load(&storage_a, keys.as_ref(), a.clone())
        .await
        .unwrap();
    let signer_b = IssuerSigner::load(&storage_b, keys.as_ref(), b.clone())
        .await
        .unwrap();

    let token = signer_a.sign(None, &claims_for(&a)).unwrap();
    assert!(verify(&token, signer_b.jwks(), &a.canonical_url).is_err());
    assert!(verify(&token, signer_a.jwks(), &b.canonical_url).is_err());
}

/// Without the master key its private key was sealed under, the issuer
/// cannot sign: loading fails and no replacement key is created.
#[tokio::test]
async fn a_key_that_cannot_be_opened_fails_closed() {
    let (storage, org) = installation().await;
    let issuer = ensure_local_issuer(&storage, key_manager().as_ref(), &base(), org)
        .await
        .unwrap();
    let foreign = foreign_key_manager();
    assert!(
        IssuerSigner::load(&storage, foreign.as_ref(), issuer.clone())
            .await
            .is_err()
    );
    // Provisioning under the foreign key keeps the stored issuer and key.
    let again = ensure_local_issuer(&storage, foreign.as_ref(), &base(), org)
        .await
        .unwrap();
    assert_eq!(again, issuer);
    assert_eq!(
        storage
            .oidc_issuer_signing_keys(issuer.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A registry over the installation's storage and key manager.
async fn registry() -> (IssuerRegistry, OidcIssuer) {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let issuer = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    (IssuerRegistry::new(Arc::new(storage), keys), issuer)
}

/// The resource the test access tokens are for.
const ORDERS: &str = "https://resources.example/orders";

/// Access-token claims as an issuer puts them in a token that `client-1`
/// requested for the Orders resource.
fn access_claims(iss: &str) -> crate::jwt::AccessTokenClaims {
    let now = chrono::Utc::now().timestamp();
    crate::jwt::AccessTokenClaims {
        sub: "subject".into(),
        pid: None,
        iss: iss.into(),
        aud: vec![ORDERS.into()],
        client_id: Some("client-1".into()),
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

/// A request names its issuer by the handle in its path: only a stored
/// handle resolves; any other text, well-formed or not, resolves to nothing
/// and never to another issuer.
#[tokio::test]
async fn only_stored_handles_resolve() {
    let (registry, issuer) = registry().await;
    assert_eq!(
        registry.by_handle(issuer.handle.as_str()).await.unwrap(),
        Some(issuer)
    );
    let unknown = IssuerHandle::generate();
    assert_eq!(registry.by_handle(unknown.as_str()).await.unwrap(), None);
    for malformed in ["", "../etc", "0123456789ABCDEF0123456789ABCDEF"] {
        assert_eq!(registry.by_handle(malformed).await.unwrap(), None);
    }
}

/// The key is opened once per generation, not on every token: two requests
/// get the same signer.
#[tokio::test]
async fn the_signer_is_opened_once_per_key_generation() {
    let (registry, issuer) = registry().await;
    let a = registry.signer(&issuer).await.unwrap();
    let b = registry.signer(&issuer).await.unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(a.issuer(), &issuer);
}

/// The verifier of an issuer accepts its own tokens and nothing signed with
/// another issuer's key or naming another issuer, even when the `kid`
/// matches.
#[tokio::test]
async fn the_verifier_accepts_only_its_issuers_tokens() {
    let (registry, issuer) = registry().await;
    let (other_registry, other) = self::registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let other_signer = other_registry.signer(&other).await.unwrap();
    let verifier = registry.verifier(&issuer).await.unwrap();
    assert_eq!(verifier.issuer(), issuer.canonical_url);

    let own = signer
        .sign(Some(AT_JWT), &access_claims(&issuer.canonical_url))
        .unwrap();
    assert_eq!(
        verifier.validate_access_token(&own).unwrap().iss,
        issuer.canonical_url
    );

    // Another issuer's key, claiming this issuer.
    let forged = other_signer
        .sign(Some(AT_JWT), &access_claims(&issuer.canonical_url))
        .unwrap();
    assert!(verifier.validate_access_token(&forged).is_err());

    // This issuer's key, naming another issuer.
    let misnamed = signer
        .sign(Some(AT_JWT), &access_claims(&other.canonical_url))
        .unwrap();
    assert!(verifier.validate_access_token(&misnamed).is_err());
}

const AT_JWT: &str = crate::jwt::ACCESS_TOKEN_TYP;

/// Only a token of the access-token purpose is one (RFC 9068 §2.1, §4): typed
/// `at+jwt` (also as `application/at+jwt`, in any case), with an audience
/// and the requesting `client_id`. The client need not be an audience
/// (auth/oauth-resource-model.md). The same claims untyped or under another
/// type, a token naming no client and one naming no audience are refused.
#[tokio::test]
async fn the_verifier_accepts_only_access_tokens_of_a_client() {
    let (registry, issuer) = registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let verifier = registry.verifier(&issuer).await.unwrap();
    let claims = || access_claims(&issuer.canonical_url);

    for typ in [AT_JWT, "application/at+jwt", "AT+JWT"] {
        let token = signer.sign(Some(typ), &claims()).unwrap();
        assert!(verifier.validate_access_token(&token).is_ok(), "{typ}");
    }
    for typ in [None, Some("JWT"), Some("logout+jwt")] {
        let token = signer.sign(typ, &claims()).unwrap();
        assert!(verifier.validate_access_token(&token).is_err(), "{typ:?}");
    }

    let mut no_client = claims();
    no_client.client_id = None;
    let token = signer.sign(Some(AT_JWT), &no_client).unwrap();
    assert!(verifier.validate_access_token(&token).is_err());

    let mut no_audience = claims();
    no_audience.aud = vec![];
    let token = signer.sign(Some(AT_JWT), &no_audience).unwrap();
    assert!(verifier.validate_access_token(&token).is_err());
}

/// A resource accepts a token only when it is the token's audience: a valid
/// token of the same issuer for another resource is refused there
/// (auth/oauth-resource-model.md, verification).
#[tokio::test]
async fn a_resource_accepts_only_tokens_for_itself() {
    let (registry, issuer) = registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let verifier = registry.verifier(&issuer).await.unwrap();
    let token = signer
        .sign(Some(AT_JWT), &access_claims(&issuer.canonical_url))
        .unwrap();
    assert_eq!(
        verifier
            .validate_access_token_for(&token, ORDERS)
            .unwrap()
            .client_id
            .as_deref(),
        Some("client-1")
    );
    assert!(
        verifier
            .validate_access_token_for(&token, "https://resources.example/wiki")
            .is_err()
    );
    // The requesting client is no audience of its own.
    assert!(
        verifier
            .validate_access_token_for(&token, "client-1")
            .is_err()
    );
}

/// A logout token is issued by the client's issuer and carries what the RP
/// matches: the subject it knows, its client id as audience, the ended
/// session, the logout event, a unique `jti` and an expiry
/// (Back-Channel Logout 1.0 §2.4).
#[tokio::test]
async fn logout_tokens_are_issued_by_the_issuer() {
    let (registry, issuer) = registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let verifier = registry.verifier(&issuer).await.unwrap();

    let token =
        crate::jwt::logout_token_signed_by(signer.as_ref(), "subject", "client-1", Some("sid-1"))
            .unwrap();
    let claims = verifier.validate_logout_token(&token).unwrap();
    assert_eq!(claims.iss, issuer.canonical_url);
    assert_eq!(claims.sub, "subject");
    assert_eq!(claims.aud, "client-1");
    assert_eq!(claims.sid.as_deref(), Some("sid-1"));
    assert!(claims.exp > claims.iat);
    assert_eq!(
        decode_header(&token).unwrap().typ.as_deref(),
        Some("logout+jwt")
    );

    let without_session =
        crate::jwt::logout_token_signed_by(signer.as_ref(), "subject", "client-1", None).unwrap();
    let other = verifier.validate_logout_token(&without_session).unwrap();
    assert!(other.sid.is_none());
    assert_ne!(other.jti, claims.jti);
}

/// A token without the logout event is not a logout token, even when this
/// issuer signed it.
#[tokio::test]
async fn a_token_without_the_logout_event_is_refused() {
    let (registry, issuer) = registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let now = chrono::Utc::now().timestamp();
    let token = signer
        .sign(
            Some("logout+jwt"),
            &serde_json::json!({
                "iss": issuer.canonical_url,
                "sub": "subject",
                "aud": "client-1",
                "iat": now,
                "exp": now + 60,
                "jti": "jti",
                "events": {},
            }),
        )
        .unwrap();
    assert!(
        registry
            .verifier(&issuer)
            .await
            .unwrap()
            .validate_logout_token(&token)
            .is_err()
    );
}

/// An ID token claims as the issuer gives `client-1` for session `sid-1`,
/// expiring at `exp`.
fn id_claims(iss: &str, exp: i64) -> crate::jwt::IdTokenClaims {
    serde_json::from_value(serde_json::json!({
        "sub": "subject",
        "iss": iss,
        "aud": "client-1",
        "exp": exp,
        "iat": exp - 60,
        "auth_time": exp - 60,
        "acr": "urn:sid:acr:basic",
        "sid": "sid-1",
    }))
    .unwrap()
}

/// `id_token_hint` accepts this issuer's ID tokens, expired ones too
/// (RP-Initiated Logout 1.0 §2); another issuer's, an access token, a logout
/// token and an ID token naming no session are refused.
#[tokio::test]
async fn id_token_hints_are_this_issuers_id_tokens() {
    let (registry, issuer) = registry().await;
    let (other_registry, other) = self::registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let verifier = registry.verifier(&issuer).await.unwrap();
    let now = chrono::Utc::now().timestamp();

    let live = signer
        .sign(None, &id_claims(&issuer.canonical_url, now + 60))
        .unwrap();
    let claims = verifier.validate_id_token_hint(&live).unwrap();
    assert_eq!(claims.aud, "client-1");
    assert_eq!(claims.sid.as_deref(), Some("sid-1"));
    let expired = signer
        .sign(None, &id_claims(&issuer.canonical_url, now - 3600))
        .unwrap();
    assert!(verifier.validate_id_token_hint(&expired).is_ok());

    let foreign = other_registry
        .signer(&other)
        .await
        .unwrap()
        .sign(None, &id_claims(&issuer.canonical_url, now + 60))
        .unwrap();
    let access = signer
        .sign(Some(AT_JWT), &access_claims(&issuer.canonical_url))
        .unwrap();
    let logout =
        crate::jwt::logout_token_signed_by(signer.as_ref(), "subject", "client-1", Some("sid-1"))
            .unwrap();
    let mut sessionless = id_claims(&issuer.canonical_url, now + 60);
    sessionless.sid = None;
    let sessionless = signer.sign(None, &sessionless).unwrap();
    for refused in [foreign, access, logout, sessionless] {
        assert!(verifier.validate_id_token_hint(&refused).is_err());
    }
}

/// A client accepts the ID token of its own code redemption (OIDC Core 1.0
/// §3.1.3.7): this issuer's, live, for this client, carrying the nonce the
/// client sent. Another client's, an expired one, one with another nonce or
/// none, and an access token are refused.
#[tokio::test]
async fn an_id_token_is_the_clients_own() {
    let (registry, issuer) = registry().await;
    let signer = registry.signer(&issuer).await.unwrap();
    let verifier = registry.verifier(&issuer).await.unwrap();
    let now = chrono::Utc::now().timestamp();
    let with_nonce = |mut claims: crate::jwt::IdTokenClaims, nonce: Option<&str>| {
        claims.nonce = nonce.map(str::to_owned);
        signer.sign(None, &claims).unwrap()
    };

    let own = with_nonce(id_claims(&issuer.canonical_url, now + 60), Some("n-1"));
    let claims = verifier.validate_id_token(&own, "client-1", "n-1").unwrap();
    assert_eq!(claims.sub, "subject");

    let mut other_client = id_claims(&issuer.canonical_url, now + 60);
    other_client.aud = "client-2".into();
    let refused = [
        with_nonce(other_client, Some("n-1")),
        with_nonce(id_claims(&issuer.canonical_url, now - 3600), Some("n-1")),
        with_nonce(id_claims(&issuer.canonical_url, now + 60), Some("n-2")),
        with_nonce(id_claims(&issuer.canonical_url, now + 60), None),
        signer
            .sign(Some(AT_JWT), &access_claims(&issuer.canonical_url))
            .unwrap(),
    ];
    for token in refused {
        assert!(
            verifier
                .validate_id_token(&token, "client-1", "n-1")
                .is_err()
        );
    }
}

/// The private key is never stored in the clear.
#[tokio::test]
async fn the_stored_private_key_is_sealed() {
    let (storage, org) = installation().await;
    let keys = key_manager();
    let issuer = ensure_local_issuer(&storage, keys.as_ref(), &base(), org)
        .await
        .unwrap();
    let stored = storage.oidc_issuer_signing_keys(issuer.id).await.unwrap();
    assert!(crate::sealed_secret::is_sealed(
        &stored[0].sealed_private_key
    ));
}
