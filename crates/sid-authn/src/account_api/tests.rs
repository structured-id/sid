use std::sync::Arc;

use sid_core::models::{
    AuditEntry, Profile, ProfileId, ResourceIndicator, Role, RoleAssignment,
    RoleAssignmentPrincipal,
};
use sid_storage::sqlite::SqliteBackend;

use super::*;
use crate::jwt::{ACCESS_TOKEN_TYP, AccessTokenClaims, IssuedCredential, TokenSigner};

const ACCOUNT_API: &str = "https://sid.example.com/account";
const ADMIN_API: &str = "https://sid.example.com/admin";

/// A token the installation's issuer signed for `audience`, for `subject`,
/// carrying the credential kind `kind`: everything else is what an
/// installation API token carries.
async fn token(
    issuers: &IssuerRegistry,
    issuer: &OidcIssuer,
    audience: &str,
    subject: ProfileId,
    kind: Option<IssuedCredential>,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let claims = AccessTokenClaims {
        sub: subject.to_string(),
        pid: None,
        aud: vec![audience.to_owned()],
        client_id: Some("system-client".into()),
        iss: issuer.canonical_url.clone(),
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "urn:sid:acr:basic".into(),
        scope: "account.read admin.read".into(),
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

async fn storage() -> Arc<SqliteBackend> {
    Arc::new(
        SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    )
}

/// A stored Profile, holding the installation administrator assignment when
/// `administers`.
async fn profile(storage: &SqliteBackend, administers: bool) -> ProfileId {
    let profile = Profile::new(Some(format!("u{}", uuid::Uuid::now_v7().simple())));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    if administers {
        match storage
            .create_role(
                &Role::installation_administrator(),
                AuditEntry::system("test", "role").into(),
            )
            .await
        {
            Ok(()) | Err(sid_core::Error::Conflict(_)) => {}
            Err(e) => panic!("store the administrator role: {e}"),
        }
        let assignment = RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(profile.id),
            Role::installation_administrator().id,
        )
        .on_installation();
        storage
            .create_role_assignment(&assignment, AuditEntry::system("test", "assignment").into())
            .await
            .unwrap();
    }
    profile.id
}

/// The account API admits only what its issuer stated to be an account API
/// credential: a token signed by the right key for the right resource but
/// stating no kind, a delegated or a client kind is refused, so another
/// issuance path's token cannot act as the user's own account access. It
/// never carries administrator authority.
#[tokio::test]
async fn only_an_account_api_credential_is_admitted() {
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let issuers = Arc::new(issuers);
    let verifier = InstallationApiVerifier::account(
        issuers.clone(),
        issuer.clone(),
        ResourceIndicator::parse(ACCOUNT_API).unwrap(),
    )
    .await
    .unwrap();
    let user = ProfileId::generate();

    let admitted = verifier
        .verify(
            &token(
                &issuers,
                &issuer,
                ACCOUNT_API,
                user,
                Some(IssuedCredential::AccountApi),
            )
            .await,
        )
        .await
        .expect("an account API credential is admitted");
    assert!(!admitted.administers);

    for kind in [
        None,
        Some(IssuedCredential::Delegated),
        Some(IssuedCredential::Client),
    ] {
        let refused = verifier
            .verify(&token(&issuers, &issuer, ACCOUNT_API, user, kind).await)
            .await
            .expect_err("only an account API credential is admitted");
        assert!(
            matches!(refused, SidError::AuthenticationFailed(_)),
            "{kind:?}: {refused:?}"
        );
    }
}

/// The administrative API admits the console's delegated token, carrying
/// the administrator's authority as the current assignments state it, and
/// refuses the account pages' token of the same administrator: neither its
/// audience nor its kind is the console's.
#[tokio::test]
async fn the_console_token_carries_current_authority_and_the_account_token_none() {
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let issuers = Arc::new(issuers);
    let storage = storage().await;
    let verifier = InstallationApiVerifier::administration(
        issuers.clone(),
        issuer.clone(),
        ResourceIndicator::parse(ADMIN_API).unwrap(),
        storage.clone(),
    )
    .await
    .unwrap();
    let admin = profile(&storage, true).await;
    let user = profile(&storage, false).await;

    let delegated = Some(IssuedCredential::Delegated);
    let by_admin = verifier
        .verify(&token(&issuers, &issuer, ADMIN_API, admin, delegated).await)
        .await
        .expect("the console's token is admitted");
    assert!(by_admin.administers);
    assert_eq!(by_admin.profile_id, admin);

    let by_user = verifier
        .verify(&token(&issuers, &issuer, ADMIN_API, user, delegated).await)
        .await
        .expect("a console token of a non-administrator is a valid token");
    assert!(!by_user.administers, "authority comes from the assignment");

    for (audience, kind) in [
        (ACCOUNT_API, Some(IssuedCredential::AccountApi)),
        (ADMIN_API, Some(IssuedCredential::AccountApi)),
        (ADMIN_API, Some(IssuedCredential::Client)),
        (ADMIN_API, None),
    ] {
        let refused = verifier
            .verify(&token(&issuers, &issuer, audience, admin, kind).await)
            .await
            .expect_err("only the console's delegated token is admitted");
        assert!(
            matches!(refused, SidError::AuthenticationFailed(_)),
            "{audience} {kind:?}: {refused:?}"
        );
    }
}
