// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's browser-facing settings through RealmService: where
//! browsers reach it, where the administration console is served and how
//! far its session cookie reaches. Only an administrator reads or changes
//! them; narrowing the cookie scope ends the browser sessions shared under
//! the former one.

mod common;

use common::mock_storage::MockStorage;
use common::{issue_admin_token, issue_token, test_jwt, test_key_manager, test_revocation};
use sid_core::models::{BrowserSecretHash, Profile, ProfileId, Session};
use sid_infra::grpc_error::extract_error_info;
use sid_plugin::{GrantStore, StorageBackend};
use sid_proto::sid::v1::admin::realm_service_server::RealmService;
use sid_proto::sid::v1::admin::{
    InstallationAddresses, SessionCookieDomain, SessionCookieScope,
    UpdateInstallationAddressesRequest, UpdateSessionCookieScopeRequest,
};
use sid_server::grpc::realm_service::RealmServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};

fn services() -> (RealmServiceImpl, Arc<MockStorage>) {
    let storage = Arc::new(MockStorage::new());
    let svc = RealmServiceImpl::new(
        storage.clone(),
        test_jwt(),
        test_revocation(),
        test_key_manager(),
        common::test_web_settings(storage.clone()),
    );
    (svc, storage)
}

/// `msg` from the bearer of `token`; with `key`, named as that command.
fn from<T>(msg: T, token: &str, key: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    match key {
        Some(key) => common::name_command(req.metadata_mut(), key),
        None => common::name_new_command(req.metadata_mut()),
    }
    req
}

fn admin_token() -> String {
    issue_admin_token(&test_jwt(), ProfileId::generate())
}

fn addresses(console: Option<&str>) -> UpdateInstallationAddressesRequest {
    UpdateInstallationAddressesRequest {
        public_url: None,
        console_url: console.map(str::to_owned),
    }
}

fn scope(domain: SessionCookieDomain, subdomains: &[&str]) -> UpdateSessionCookieScopeRequest {
    UpdateSessionCookieScopeRequest {
        domain: domain as i32,
        subdomains: subdomains.iter().map(|s| (*s).to_owned()).collect(),
        subdomain_pattern: String::new(),
    }
}

// A fresh installation answers its own URL and the console at /admin/; the
// console moves to another prefix and to a sibling admin host's root, an
// empty value restores the default, and each change that lands is the next
// revision. Bug prevented: a console address that cannot be changed, or one
// that silently keeps an earlier value.
#[tokio::test]
async fn console_moves_and_returns_to_its_default() {
    let (svc, _) = services();
    let token = admin_token();
    let read = svc
        .get_installation_addresses(from((), &token, None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        read,
        InstallationAddresses {
            public_url: "https://sid.example.com/".into(),
            public_url_overridden: false,
            console_url: "https://sid.example.com/admin/".into(),
        }
    );
    for (given, served) in [
        (
            "https://sid.example.com/console",
            "https://sid.example.com/console/",
        ),
        ("https://admin.example.com/", "https://admin.example.com/"),
        ("", "https://sid.example.com/admin/"),
    ] {
        let answered = svc
            .update_installation_addresses(from(addresses(Some(given)), &token, None))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answered.console_url, served, "{given}");
        let read = svc
            .get_installation_addresses(from((), &token, None))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(read, answered);
    }
}

// A console on another site, at the public root or over a path the
// installation serves is refused with the field named and nothing stored.
#[tokio::test]
async fn a_console_the_browser_cannot_use_is_refused() {
    let (svc, storage) = services();
    let token = admin_token();
    for bad in [
        "https://admin.example.net/",
        "https://sid.example.com/",
        "https://sid.example.com/account/",
        "http://admin.example.com/",
    ] {
        let refused = svc
            .update_installation_addresses(from(addresses(Some(bad)), &token, None))
            .await
            .expect_err(bad);
        assert_eq!(refused.code(), Code::InvalidArgument, "{bad}");
        let (reason, _, _) = extract_error_info(&refused).expect("ErrorInfo");
        assert_eq!(reason, "INVALID_FIELD_VALUE", "{bad}");
        let violations = tonic_types::StatusExt::get_details_bad_request(&refused)
            .expect("BadRequest")
            .field_violations;
        assert_eq!(violations.len(), 1, "{bad}");
        assert_eq!(violations[0].field, "console_url", "{bad}");
    }
    assert_eq!(storage.web_settings().await.unwrap(), None);
}

/// A stored session for `profile`, holding a browser secret when `browser`.
async fn session(storage: &MockStorage, profile: ProfileId, browser: bool) -> Session {
    let mut session = Session::new(
        profile,
        None,
        jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    );
    if browser {
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        session.browser_secret_hash = Some(BrowserSecretHash::from_bytes(hash));
    }
    storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    session
}

// Widening keeps every session; narrowing from all subdomains to this host
// ends the browser sessions, whose secret the wider cookie carried to every
// subdomain, and keeps the others. The answer names the base domain the
// scope derives from. Bug prevented: a formerly wide cookie that still opens
// a session after the administrator narrowed the scope.
#[tokio::test]
async fn narrowing_the_scope_ends_browser_sessions() {
    let (svc, storage) = services();
    let token = admin_token();
    let profile = ProfileId::generate();
    let browser = session(&storage, profile, true).await;
    let native = session(&storage, profile, false).await;

    let wide = svc
        .update_session_cookie_scope(from(
            scope(SessionCookieDomain::AllSubdomains, &[]),
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        wide,
        SessionCookieScope {
            domain: SessionCookieDomain::AllSubdomains as i32,
            base_domain: "sid.example.com".into(),
            revision: 1,
            ..Default::default()
        }
    );
    assert!(storage.get_session(browser.id).await.unwrap().is_some());

    let narrow = svc
        .update_session_cookie_scope(from(
            scope(SessionCookieDomain::ThisHost, &[]),
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(narrow.domain, SessionCookieDomain::ThisHost as i32);
    assert_eq!(narrow.revision, 2);
    assert!(storage.get_session(browser.id).await.unwrap().is_none());
    assert!(storage.get_session(native.id).await.unwrap().is_some());
}

// A selected scope answers its normalized subdomains; a subdomain outside
// the base and a selection with nothing selected are refused.
#[tokio::test]
async fn selected_subdomains_are_validated() {
    let (svc, _) = services();
    let token = admin_token();
    let answered = svc
        .update_session_cookie_scope(from(
            scope(
                SessionCookieDomain::SelectedSubdomains,
                &["App.Sid.Example.com."],
            ),
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(answered.subdomains, vec!["app.sid.example.com".to_owned()]);
    for bad in [
        scope(
            SessionCookieDomain::SelectedSubdomains,
            &["app.example.net"],
        ),
        scope(SessionCookieDomain::SelectedSubdomains, &[]),
        scope(SessionCookieDomain::Unspecified, &[]),
    ] {
        let refused = svc
            .update_session_cookie_scope(from(bad.clone(), &token, None))
            .await
            .expect_err("refused");
        assert_eq!(refused.code(), Code::InvalidArgument, "{bad:?}");
    }
}

// The settings decide what a browser is sent and where an administrator's
// console runs: only an administrator reads or changes them.
#[tokio::test]
async fn only_an_administrator_reads_or_changes_them() {
    let (svc, storage) = services();
    let user = issue_token(
        &test_jwt(),
        &Profile::new(Some("mallory")),
        &["openid".to_string()],
    );
    assert_eq!(
        svc.get_installation_addresses(from((), &user, None))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        svc.get_session_cookie_scope(from((), &user, None))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        svc.update_installation_addresses(from(
            addresses(Some("https://admin.example.com/")),
            &user,
            None
        ))
        .await
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        svc.update_session_cookie_scope(from(
            scope(SessionCookieDomain::AllSubdomains, &[]),
            &user,
            None
        ))
        .await
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        svc.update_installation_addresses(Request::new(addresses(None)))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(storage.web_settings().await.unwrap(), None);
}

// Every request reads the settings through a snapshot of at most a second:
// a change this process made applies to its next request at once, a change
// another replica committed within RECENT_FOR, and the synchronous view CORS
// uses holds whatever was read last. Bug prevented: a console moved by an
// administrator that one replica keeps serving at the old address, or a
// store read on every browser request.
#[tokio::test]
async fn the_settings_snapshot_follows_changes() {
    let storage = Arc::new(MockStorage::new());
    let web = common::test_web_settings(storage.clone());
    let svc = RealmServiceImpl::new(
        storage.clone(),
        test_jwt(),
        test_revocation(),
        test_key_manager(),
        web.clone(),
    );
    assert!(web.last().is_none());
    let default = web.recent().await.unwrap();
    assert_eq!(
        default.console_url.as_str(),
        "https://sid.example.com/admin/"
    );
    assert_eq!(web.last().unwrap().revision, 0);

    let token = admin_token();
    svc.update_installation_addresses(from(
        addresses(Some("https://admin.example.com/")),
        &token,
        None,
    ))
    .await
    .unwrap();
    // This process's own change: served at once, without waiting a second.
    assert_eq!(
        web.recent().await.unwrap().console_url.as_str(),
        "https://admin.example.com/"
    );
    assert_eq!(
        web.last().unwrap().console_url.as_str(),
        "https://admin.example.com/"
    );

    // Another replica's change, straight in the store: within a second.
    let stored = storage.web_settings().await.unwrap();
    let mut moved = stored.clone().unwrap();
    moved.console_url = Some("https://sid.example.com/console/".into());
    moved.revision += 1;
    assert!(
        storage
            .set_web_settings(
                &moved,
                stored.as_ref(),
                None,
                sid_core::models::AuditEntry::system("test", "web_settings").into(),
            )
            .await
            .unwrap()
    );
    tokio::time::sleep(sid::web_settings::RECENT_FOR + std::time::Duration::from_millis(50)).await;
    assert_eq!(
        web.recent().await.unwrap().console_url.as_str(),
        "https://sid.example.com/console/"
    );
}

// CORS admits the console's origin only when the console sits on a sibling
// host, from the settings the process holds: on the public origin itself
// it needs no CORS, and any other origin is refused. Bug prevented: a
// console moved to its own host whose every API call the browser blocks.
#[tokio::test]
async fn cors_admits_the_console_on_a_sibling_host() {
    use structured_proxy::hooks::CorsOrigins as _;
    let storage = Arc::new(MockStorage::new());
    let web = common::test_web_settings(storage.clone());
    let svc = RealmServiceImpl::new(
        storage.clone(),
        test_jwt(),
        test_revocation(),
        test_key_manager(),
        web.clone(),
    );
    let cors = sid_server::serve::ConsoleOrigin(web.clone());
    // Nothing read yet: nothing admitted.
    assert!(!cors.admits("https://admin.example.com"));
    web.recent().await.unwrap();
    assert!(!cors.admits("https://sid.example.com"));

    svc.update_installation_addresses(from(
        addresses(Some("https://admin.example.com/")),
        &admin_token(),
        None,
    ))
    .await
    .unwrap();
    assert!(cors.admits("https://admin.example.com"));
    assert!(!cors.admits("https://other.example.com"));
    assert!(!cors.admits("null"));
}

// A change whose answer was lost is repeated under its key: it answers what
// it answered first and does not undo a later change.
#[tokio::test]
async fn a_repeated_change_answers_its_first_result() {
    let (svc, _) = services();
    let token = admin_token();
    let first = svc
        .update_installation_addresses(from(
            addresses(Some("https://admin.example.com/")),
            &token,
            Some("move-1"),
        ))
        .await
        .unwrap()
        .into_inner();
    svc.update_installation_addresses(from(addresses(Some("")), &token, None))
        .await
        .unwrap();
    let repeated = svc
        .update_installation_addresses(from(
            addresses(Some("https://admin.example.com/")),
            &token,
            Some("move-1"),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(repeated, first);
    let read = svc
        .get_installation_addresses(from((), &token, None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.console_url, "https://sid.example.com/admin/");
}
