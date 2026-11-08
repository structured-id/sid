// SPDX-License-Identifier: AGPL-3.0-only

use sid_authn::sign_in_delivery::{BrowserCredential, Delivery};
use sid_core::models::session::AuthLevel;
use sid_core::models::{AuditEntry, MutationContext, Profile, ProfileId};
use sid_plugin::StorageBackend;
use sid_storage::sqlite::SqliteBackend;
use tonic::metadata::MetadataValue;

use super::*;

fn ctx() -> MutationContext {
    AuditEntry::system("test", "second_factor").into()
}

/// `session` stored with a fresh browser binding, and the `Cookie` request
/// value that presents it.
async fn stored(
    store: &SqliteBackend,
    mut session: Session<ProfileId>,
) -> (Session<ProfileId>, String) {
    let credential = BrowserCredential::bind(&mut session);
    store
        .create_session_atomic(&session, 0, None, ctx())
        .await
        .unwrap();
    let Delivery::Cookie(set) = credential
        .signed_in(&BrowserCookie::default(), &session)
        .delivery
    else {
        panic!("a browser delivery");
    };
    let pair = set.split(';').next().unwrap().to_owned();
    (session, pair)
}

async fn account(store: &SqliteBackend) -> ProfileId {
    let profile = Profile::new(Some("alice"));
    store.create_profile(&profile, ctx()).await.unwrap();
    profile.id
}

fn metadata(cookie: Option<&str>, csrf: &[&str]) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    if let Some(cookie) = cookie {
        metadata.insert("cookie", MetadataValue::try_from(cookie).unwrap());
    }
    for token in csrf {
        metadata.append(CSRF_HEADER, MetadataValue::try_from(*token).unwrap());
    }
    metadata
}

fn csrf_of(session: &Session<ProfileId>) -> String {
    BrowserCsrf::encode(session.browser_csrf.as_ref().unwrap())
}

/// A live pending context with its CSRF token is the context to complete;
/// with a wrong one nothing is presented.
#[tokio::test]
async fn a_pending_context_needs_its_own_csrf_token() {
    let store = SqliteBackend::new_in_memory().await.unwrap();
    let alice = account(&store).await;
    let (pending, cookie) = stored(
        &store,
        Session::new_awaiting_second_factor(alice, None, AuthLevel::Basic, vec!["pwd".into()]),
    )
    .await;
    let found = browser_factor(
        &metadata(Some(&cookie), &[&csrf_of(&pending)]),
        &BrowserCookie::default(),
        &store,
    )
    .await
    .unwrap();
    assert!(matches!(found, BrowserFactor::Pending(s) if s.id == pending.id));
    let refused = browser_factor(
        &metadata(Some(&cookie), &["wrong"]),
        &BrowserCookie::default(),
        &store,
    )
    .await;
    assert!(refused.is_err());
}

/// The browser whose completion already installed its full session is told
/// so, not handed a context to complete.
#[tokio::test]
async fn an_installed_session_is_signed_in() {
    let store = SqliteBackend::new_in_memory().await.unwrap();
    let alice = account(&store).await;
    let (session, cookie) = stored(
        &store,
        Session::new(alice, None, chrono::Utc::now() + chrono::Duration::hours(1)),
    )
    .await;
    let found = browser_factor(
        &metadata(Some(&cookie), &[&csrf_of(&session)]),
        &BrowserCookie::default(),
        &store,
    )
    .await
    .unwrap();
    assert!(matches!(found, BrowserFactor::SignedIn(s) if s.id == session.id));
}

/// A cookie no session holds names the completed context, with the one CSRF
/// token presented; two tokens are ambiguous and no cookie names nothing.
#[tokio::test]
async fn a_cookie_no_session_holds_names_its_completed_context() {
    let store = SqliteBackend::new_in_memory().await.unwrap();
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    let set = BrowserCookie::default().set(&secret, 60);
    let cookie = set.split(';').next().unwrap();
    let found = browser_factor(
        &metadata(Some(cookie), &["token"]),
        &BrowserCookie::default(),
        &store,
    )
    .await
    .unwrap();
    match found {
        BrowserFactor::Completed(CompletedContext::Browser { secret: hash, csrf }) => {
            assert_eq!(hash, secret.hash());
            assert_eq!(csrf, "token");
        }
        _ => panic!("the completed context"),
    }
    assert!(
        browser_factor(
            &metadata(Some(cookie), &["a", "b"]),
            &BrowserCookie::default(),
            &store
        )
        .await
        .is_err()
    );
    assert!(
        browser_factor(&metadata(None, &["a"]), &BrowserCookie::default(), &store)
            .await
            .is_err()
    );
}

/// A refused factor answers with its reason, never the cause of an internal
/// failure.
#[test]
fn factor_refusals_carry_their_reason() {
    assert_eq!(
        FactorError::AuthenticationFailed.into_status().code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        FactorError::NotEnrolled("TOTP authenticator")
            .into_status()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let internal = FactorError::Corrupt("secret detail".into()).into_status();
    assert_eq!(internal.code(), tonic::Code::Internal);
    assert!(!internal.message().contains("secret detail"));
    assert_eq!(
        PendingError::SessionEnded.into_status().code(),
        tonic::Code::Unauthenticated
    );
}
