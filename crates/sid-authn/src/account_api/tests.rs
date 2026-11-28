use std::sync::Arc;

use sid_core::models::{ProfileId, ResourceIndicator};

use super::*;
use crate::jwt::{ACCESS_TOKEN_TYP, AccessTokenClaims, IssuedCredential, TokenSigner};

const ACCOUNT_API: &str = "https://sid.example.com/api/account";

/// A token the installation's issuer signed for the account API, for a
/// Profile, carrying the credential kind `kind`: everything but the kind is
/// what an account API token carries.
async fn token(
    issuers: &IssuerRegistry,
    issuer: &OidcIssuer,
    kind: Option<IssuedCredential>,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let claims = AccessTokenClaims {
        sub: ProfileId::generate().to_string(),
        pid: None,
        aud: vec![ACCOUNT_API.to_owned()],
        client_id: Some("account-console".into()),
        iss: issuer.canonical_url.clone(),
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "urn:sid:acr:basic".into(),
        scope: "account".into(),
        roles: String::new(),
        sid: uuid::Uuid::now_v7().to_string(),
        amr: vec!["pwd".into()],
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

/// An installation whose base issuer lives at its root origin signs both its
/// own session tokens and the account API's tokens under one `iss`: its
/// services still accept each as what it is.
/// Bug prevented: the verifier was picked by `iss` alone, so such an
/// installation handed its own session token to the account API verifier,
/// which refused it, and no service accepted a sign-in's token.
#[tokio::test]
async fn an_issuer_at_the_root_origin_keeps_its_session_tokens() {
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let issuers = Arc::new(issuers);
    let account = AccountApiVerifier::new(
        issuers.clone(),
        issuer.clone(),
        ResourceIndicator::parse(ACCOUNT_API).unwrap(),
    )
    .await
    .unwrap();
    let (private, public) = crate::jwt::generate_signing_key_pem().unwrap();
    let jwt = crate::jwt::JwtService::new(
        private.as_bytes(),
        public.as_bytes(),
        issuer.canonical_url.clone(),
    )
    .unwrap()
    .with_account_api(Arc::new(account));

    let profile = ProfileId::generate();
    let session = sid_core::models::Session::new(
        profile,
        None,
        jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    );
    let own = jwt
        .issue_access_token(
            &profile.to_string(),
            Some(&profile.to_string()),
            &[],
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();
    assert!(matches!(
        jwt.verifier().verify(&own).await,
        Ok(crate::jwt::VerifiedAccess::Session(_))
    ));

    let account_api = token(&issuers, &issuer, Some(IssuedCredential::AccountApi)).await;
    assert!(matches!(
        jwt.verifier().verify(&account_api).await,
        Ok(crate::jwt::VerifiedAccess::AccountApi(_))
    ));
}

/// The account API admits only what its issuer stated to be an account API
/// credential: a token signed by the right key for the right resource but
/// stating no kind, a delegated or a client kind is refused, so another
/// issuance path's token cannot act as the user's own account access.
#[tokio::test]
async fn only_an_account_api_credential_is_admitted() {
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let issuers = Arc::new(issuers);
    let verifier = AccountApiVerifier::new(
        issuers.clone(),
        issuer.clone(),
        ResourceIndicator::parse(ACCOUNT_API).unwrap(),
    )
    .await
    .unwrap();

    let admitted = token(&issuers, &issuer, Some(IssuedCredential::AccountApi)).await;
    verifier
        .verify(&admitted)
        .await
        .expect("an account API credential is admitted");

    for kind in [
        None,
        Some(IssuedCredential::Delegated),
        Some(IssuedCredential::Client),
    ] {
        let refused = verifier
            .verify(&token(&issuers, &issuer, kind).await)
            .await
            .expect_err("only an account API credential is admitted");
        assert!(
            matches!(refused, SidError::AuthenticationFailed(_)),
            "{kind:?}: {refused:?}"
        );
    }
}
