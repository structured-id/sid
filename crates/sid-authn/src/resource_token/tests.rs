use std::sync::Arc;

use super::*;
use crate::jwt::{ACCESS_TOKEN_TYP, IssuedCredential, TokenSigner};

const SERVICE_API: &str = "https://sid.example.com/api/service";

/// A token the installation's issuer signed for the service API for a
/// machine whose subject is not its client id, carrying the credential kind
/// `kind`: everything but the kind is what a client's own token carries.
async fn token(
    issuers: &IssuerRegistry,
    issuer: &OidcIssuer,
    kind: Option<IssuedCredential>,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = AccessTokenClaims {
        sub: uuid::Uuid::now_v7().to_string(),
        pid: None,
        aud: vec![SERVICE_API.to_owned()],
        client_id: Some("billing-sync".into()),
        iss: issuer.canonical_url.clone(),
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "urn:sid:acr:basic".into(),
        scope: "service.read".into(),
        roles: String::new(),
        sid: "cred_billing".into(),
        amr: vec![],
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
        credential_kind: kind,
    };
    issuers
        .signer(issuer)
        .await
        .unwrap()
        .sign_claims(Some(ACCESS_TOKEN_TYP), &claims)
        .unwrap()
}

/// A token its holder obtained for itself is admitted only when its issuer
/// stated it to be a client credential: one signed by the right key for this
/// resource but stating no kind, a delegated or an account API kind is no
/// own token of a machine, service or connector. A machine whose subject is
/// not its client id is admitted.
#[tokio::test]
async fn only_a_client_credential_is_an_own_token() {
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let issuers = Arc::new(issuers);
    let verifier = ResourceTokenVerifier::new(
        issuers.clone(),
        issuer.clone(),
        ResourceIndicator::parse(SERVICE_API).unwrap(),
    )
    .await
    .unwrap();

    let own = token(&issuers, &issuer, Some(IssuedCredential::Client)).await;
    let claims = verifier
        .verify_own(&own)
        .await
        .expect("a client credential is an own token");
    assert_ne!(Some(claims.sub), claims.client_id);

    for kind in [
        None,
        Some(IssuedCredential::Delegated),
        Some(IssuedCredential::AccountApi),
    ] {
        let refused = verifier
            .verify_own(&token(&issuers, &issuer, kind).await)
            .await
            .expect_err("only a client credential is an own token");
        assert!(
            matches!(refused, OwnTokenError::Unauthenticated),
            "{kind:?}: {refused:?}"
        );
    }
}
