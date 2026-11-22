// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's stored browser-facing settings: public URL override,
//! console address and session cookie scope.
//!
//! Needs a backend whose web settings were never set (an isolated schema or
//! a fresh database): the scenarios start from the unset state.

use super::{create_test_profile, create_test_session, test_audit};
use sid_core::models::{
    BrowserSecretHash, CookieScope, RevocationReason, SessionEnd, SessionRevocation, WebSettings,
    WorkState,
};
use sid_plugin::storage::StorageBackend;

fn settings(console: Option<&str>, scope: CookieScope, revision: u64) -> WebSettings {
    WebSettings {
        public_url: None,
        console_url: console.map(str::to_owned),
        cookie_scope: scope,
        revision,
    }
}

fn selected() -> CookieScope {
    CookieScope::SelectedSubdomains {
        hosts: vec!["app.sid.example.com".into()],
        pattern: Some(r"[a-z]+\.apps\.sid\.example\.com".into()),
    }
}

/// Unset reads as none; every write reads back whole, including the scope's
/// hosts and pattern; a write expecting what is not stored writes nothing.
/// Bug prevented: a setting lost or carried over by the stored form, a
/// change decided on older settings overwriting newer ones.
pub async fn test_web_settings_stored_and_replaced(backend: &dyn StorageBackend) {
    assert_eq!(backend.web_settings().await.unwrap(), None);
    let first = settings(Some("https://admin.sid.example.com/"), selected(), 1);
    assert!(
        !backend
            .set_web_settings(&first, Some(&WebSettings::default()), None, test_audit())
            .await
            .unwrap(),
        "nothing is stored: a write expecting settings is a stale read"
    );
    assert!(
        backend
            .set_web_settings(&first, None, None, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.web_settings().await.unwrap(), Some(first.clone()));

    let second = WebSettings {
        public_url: Some("https://sid.example.com/".into()),
        ..settings(None, CookieScope::AllSubdomains, 2)
    };
    for stale in [None, Some(second.clone())] {
        assert!(
            !backend
                .set_web_settings(&second, stale.as_ref(), None, test_audit())
                .await
                .unwrap(),
            "{stale:?}"
        );
    }
    assert!(
        backend
            .set_web_settings(&second, Some(&first), None, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.web_settings().await.unwrap(), Some(second));
}

/// Of several administrators changing settings read the same way, one write
/// lands and each other is refused without an error, the very first write
/// included.
pub async fn test_web_settings_concurrent_writers(backend: &dyn StorageBackend) {
    let attempts = [
        settings(
            Some("https://sid.example.com/one/"),
            CookieScope::ThisHost,
            1,
        ),
        settings(
            Some("https://sid.example.com/two/"),
            CookieScope::ThisHost,
            1,
        ),
        settings(None, CookieScope::AllSubdomains, 1),
    ];
    let outcomes = futures::future::join_all(
        attempts
            .iter()
            .map(|written| backend.set_web_settings(written, None, None, test_audit())),
    )
    .await;
    let landed: Vec<bool> = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("a refused write is not a failure"))
        .collect();
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
    let winner = attempts[landed.iter().position(|l| *l).unwrap()].clone();
    assert_eq!(backend.web_settings().await.unwrap(), Some(winner.clone()));

    let next = settings(None, CookieScope::ThisHost, 2);
    let other = settings(None, selected(), 2);
    let (a, b) = tokio::join!(
        backend.set_web_settings(&next, Some(&winner), None, test_audit()),
        backend.set_web_settings(&other, Some(&winner), None, test_audit()),
    );
    let landed = [a.unwrap(), b.unwrap()];
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
}

/// A write that ends browser sessions ends every session holding a browser
/// secret, with each one's revocation stored in the same commit, and leaves
/// sessions without one; a write without it ends nothing. Bug prevented: a
/// narrowed cookie scope whose formerly shared secret still opens a session,
/// or a crash between the narrowing and the end.
pub async fn test_web_settings_end_browser_sessions(backend: &dyn StorageBackend) {
    let profile = create_test_profile("webscope");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut browser = create_test_session(profile.id);
    // A hash of its own: the column is unique across runs on one store.
    let mut hash = [0u8; 32];
    hash[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
    browser.browser_secret_hash = Some(BrowserSecretHash::from_bytes(hash));
    let native = create_test_session(profile.id);
    for s in [&browser, &native] {
        backend.create_session(s, test_audit()).await.unwrap();
    }

    let wide = settings(None, CookieScope::AllSubdomains, 1);
    assert!(
        backend
            .set_web_settings(&wide, None, None, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend.get_session(browser.id).await.unwrap().is_some(),
        "a write without the end ended a browser session"
    );

    let end = SessionEnd::new(RevocationReason::Admin, "admin");
    let narrow = settings(None, CookieScope::ThisHost, 2);
    assert!(
        backend
            .set_web_settings(&narrow, Some(&wide), Some(&end), test_audit())
            .await
            .unwrap()
    );
    assert!(backend.get_session(browser.id).await.unwrap().is_none());
    assert!(
        backend.get_session(native.id).await.unwrap().is_some(),
        "a session without a browser secret was ended"
    );
    let revocation = SessionRevocation {
        session_id: browser.id.to_string(),
    }
    .work();
    assert_eq!(
        backend
            .get_work(revocation.id)
            .await
            .unwrap()
            .map(|w| w.state),
        Some(WorkState::Pending),
        "the ended session's revocation was not stored with the narrowing"
    );
}
