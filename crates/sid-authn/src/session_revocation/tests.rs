// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{RevocationReason, SessionEnd, SessionId};
use sid_plugin::cache::InMemoryCacheBackend;

fn claimed(work: NewWork) -> ClaimedWork {
    ClaimedWork {
        id: work.id,
        kind: work.kind,
        payload: work.payload,
        attempt: 1,
        max_attempts: work.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

/// The revocation an ended session owes, once performed, revokes every token
/// of that session; performing it again is harmless.
#[tokio::test]
async fn owed_revocation_revokes_the_session_tokens() {
    let cache = Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    ));
    let handler = SessionRevocationHandler::new(cache.clone());
    let session = SessionId::generate();
    let work = SessionEnd::new(RevocationReason::Admin, "system")
        .owed(session, sid_core::models::ProfileId::generate(), None)
        .into_iter()
        .find(|w| w.kind == *handler.kind())
        .expect("the revocation is owed");
    let work = claimed(work);

    assert!(!cache.is_revoked("any", &session.to_string()).await.unwrap());
    assert!(matches!(handler.handle(&work).await, WorkOutcome::Done(_)));
    assert!(cache.is_revoked("any", &session.to_string()).await.unwrap());
    assert!(matches!(handler.handle(&work).await, WorkOutcome::Done(_)));
}

/// An owed revocation is retried for as long as any access token of the
/// ended session can still be valid (the longest lifetime a deployment may
/// configure), so a revocation cache that recovers within that time still
/// publishes it; past it the revocation is moot and expires. Before, the
/// default five attempts gave up within half a minute.
#[test]
fn a_revocation_is_retried_while_a_token_can_live() {
    let ended_at = chrono::Utc::now();
    let work = sid_core::models::SessionRevocation {
        session_id: SessionId::generate().to_string(),
    }
    .work();
    let handler_schedule = SessionRevocationHandler::new(Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    )))
    .retry_schedule();
    let longest = crate::jwt::AccessTokenTtl::MAX.duration().to_std().unwrap();
    let retried: Duration = (1..work.max_attempts)
        .map(|attempt| handler_schedule.after(attempt))
        .sum();
    assert!(retried >= longest, "{retried:?} < {longest:?}");
    let expires = work.expires_at.expect("a moot revocation expires");
    assert!(expires >= ended_at + crate::jwt::AccessTokenTtl::MAX.duration());
}

/// A payload that is not a session revocation can never succeed.
#[tokio::test]
async fn malformed_revocation_fails_permanently() {
    let handler = SessionRevocationHandler::new(Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    )));
    let work = claimed(NewWork::new(handler.kind().clone(), b"{}".to_vec()));
    assert!(matches!(
        handler.handle(&work).await,
        WorkOutcome::Permanent(_)
    ));
}
