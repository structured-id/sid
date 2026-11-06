//! A caller exists only from a verified, current token, and its checks give
//! the same decisions whatever the entry point.

use std::sync::Arc;

use sid_core::models::{ProfileId, Session};

use super::*;
use crate::jwt::JwtService;

fn jwt() -> JwtService {
    JwtService::new(
        include_bytes!("../../tests/fixtures/test_ed25519_private.pem"),
        include_bytes!("../../tests/fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".into(),
    )
    .unwrap()
}

fn revocation() -> RevocationCache {
    RevocationCache::new(
        std::time::Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    )
}

/// A signed-in session of a new Profile and its access token, with `roles`.
fn token(jwt: &JwtService, roles: &[&str]) -> (ProfileId, Session, String) {
    let profile = ProfileId::generate();
    let session = Session::new(
        profile,
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let roles: Vec<String> = roles.iter().map(|r| (*r).to_owned()).collect();
    let pid = profile.to_string();
    let token = jwt
        .issue_access_token(&pid, Some(&pid), &roles, &session, &[], None, None)
        .unwrap();
    (profile, session, token)
}

// The administrator role in a verified token makes an administrator caller;
// every check admits it.
#[tokio::test]
async fn an_administrators_token_admits_administration() {
    let jwt = jwt();
    let (profile, _, token) = token(&jwt, &[ADMIN_ROLE_CLAIM]);
    let verified = authenticate_token(&token, jwt.verifier(), &revocation())
        .await
        .unwrap();
    assert_eq!(verified.source, TokenSource::Installation);
    let caller = verified.caller;
    assert_eq!(caller.profile_id, profile);
    assert!(caller.is_admin());
    assert_eq!(caller.require_admin(), Ok(()));
    assert_eq!(caller.require_self_or_admin(ProfileId::generate()), Ok(()));
    assert_eq!(caller.require_interactive(), Ok(()));
}

// Without the role the caller acts on its own Profile only.
#[tokio::test]
async fn a_users_token_admits_only_its_own_profile() {
    let jwt = jwt();
    let (profile, _, token) = token(&jwt, &[]);
    let caller = authenticate_token(&token, jwt.verifier(), &revocation())
        .await
        .unwrap()
        .caller;
    assert_eq!(caller.require_admin(), Err(CallerError::Denied));
    assert_eq!(caller.require_self_or_admin(profile), Ok(()));
    assert_eq!(
        caller.require_self_or_admin(ProfileId::generate()),
        Err(CallerError::Denied)
    );
    let own = format!("user:{profile}");
    assert_eq!(caller.require_own_subjects([own.as_str()]), Ok(()));
    assert_eq!(
        caller.require_own_subjects(["user:someone-else"]),
        Err(CallerError::Denied)
    );
}

// A token of an ended session, or one that does not verify, makes no
// caller.
#[tokio::test]
async fn no_caller_from_an_ended_or_invalid_token() {
    let jwt = jwt();
    let (_, session, token) = token(&jwt, &[ADMIN_ROLE_CLAIM]);
    let revocation = revocation();
    revocation
        .revoke_session(session.id.to_string())
        .await
        .unwrap();
    assert_eq!(
        authenticate_token(&token, jwt.verifier(), &revocation)
            .await
            .unwrap_err(),
        CallerError::Unauthenticated
    );
    assert_eq!(
        authenticate_token("not-a-token", jwt.verifier(), &revocation)
            .await
            .unwrap_err(),
        CallerError::Unauthenticated
    );
}
