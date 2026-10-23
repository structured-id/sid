// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use sid_authn::client_connection::ClientConnection;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer_directory::{
    IssuerRecord, IssuerSource, RegistryUnavailable, ResourceRecord,
};
use sid_plugin::cache::{CacheBackend, CacheError, CacheResult, InMemoryCacheBackend};

use super::*;

const INSTALLATION: &str = "https://sid.example.com";
const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
pub(crate) const COOKIE: &str = "__Host-ops-bff";
const LONG: Duration = Duration::from_secs(3600);

/// A directory that knows no issuer: these tests never verify a token.
struct NoIssuers;

#[async_trait::async_trait]
impl IssuerSource for NoIssuers {
    async fn issuer(&self, _: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable> {
        Ok(None)
    }
    async fn resource(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
        Ok(None)
    }
}

/// A cache whose every call fails, as an unreachable store does.
struct Down;

#[async_trait::async_trait]
impl CacheBackend for Down {
    async fn get(&self, _: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn set(&self, _: &str, _: &[u8], _: Duration) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn delete(&self, _: &str) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn take(&self, _: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn set_nx(&self, _: &str, _: &[u8], _: Duration) -> CacheResult<bool> {
        Err(CacheError::Connection("down".into()))
    }
    async fn publish(&self, _: &str, _: &[u8]) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn subscribe(
        &self,
        _: &str,
    ) -> CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn health_check(&self) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
}

fn unreachable() -> sid_infra::deadline::IssuerChannel {
    sid_infra::deadline::bounded_channel("http://127.0.0.1:1", Duration::from_millis(100)).unwrap()
}

fn connection() -> Connection {
    Connection::accept(
        ClientConnection {
            issuer: ISSUER.into(),
            client_id: "ops-web".into(),
            resource: "https://ops.sid.example.com/api/".into(),
            scopes: vec!["openid".into()],
            redirect_uri: "https://ops.sid.example.com/auth/callback".into(),
            token_endpoint_auth_method: "private_key_jwt".into(),
            key_ids: vec![],
        },
        INSTALLATION,
    )
    .unwrap()
}

/// An adapter and the stores behind it; the host's tests build on it too.
pub(crate) struct Fixture {
    pub(crate) adapter: ApplicationSessions,
    pub(crate) sessions: Arc<BffSessionStore>,
    revocation: Arc<RevocationCache>,
}

/// An adapter over `cache`, with the connection delivered or, when
/// `delivered` is false, to be asked of an issuer that never answers.
pub(crate) fn fixture(cache: Arc<dyn CacheBackend>, delivered: bool) -> Fixture {
    let key = ClientKey::generate_ed25519().unwrap().0;
    let client = if delivered {
        RpClient::delivered(key, INSTALLATION.into(), unreachable(), connection())
    } else {
        RpClient::new(key, INSTALLATION.into(), unreachable())
    }
    .unwrap();
    let sessions = Arc::new(BffSessionStore::new(cache.clone(), LONG, LONG, LONG));
    let revocation = Arc::new(RevocationCache::new(LONG, cache));
    Fixture {
        adapter: ApplicationSessions::new(
            Arc::new(client),
            Arc::new(IssuerDirectory::new(INSTALLATION, Arc::new(NoIssuers))),
            sessions.clone(),
            revocation.clone(),
            COOKIE.into(),
        ),
        sessions,
        revocation,
    }
}

pub(crate) fn memory() -> Arc<dyn CacheBackend> {
    Arc::new(InMemoryCacheBackend::new())
}

fn claims() -> SessionClaims {
    SessionClaims {
        sub: "subject-1".into(),
        iss: ISSUER.into(),
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: 0,
        auth_time: 0,
        acr: "urn:sid:acr:basic".into(),
        scope: String::new(),
        roles: String::new(),
        sid: "issuer-session-1".into(),
        jti: "token-1".into(),
        email: Some("ops@sid.example.com".into()),
        name: None,
        preferred_username: None,
        groups: None,
    }
}

/// A session of the delivered connection, with or without a refresh token:
/// its id and CSRF token.
pub(crate) async fn signed_in(f: &Fixture, refresh: bool) -> (String, String) {
    f.sessions
        .create_session(
            "access".into(),
            refresh.then(|| "refresh".into()),
            claims(),
            &connection().binding(),
        )
        .await
        .unwrap()
}

/// The application's origin: its registered callback's.
pub(crate) const ORIGIN: &str = "https://ops.sid.example.com";

/// A call of the application's page: `cookie`, `csrf` and the page's own
/// `Origin`.
pub(crate) fn with_cookie<T>(message: T, cookie: &str, csrf: Option<&str>) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("origin", ORIGIN.parse().unwrap());
    request
        .metadata_mut()
        .insert("cookie", cookie.parse().unwrap());
    if let Some(csrf) = csrf {
        request
            .metadata_mut()
            .insert("x-csrf-token", csrf.parse().unwrap());
    }
    request
}

fn status(response: &Response<HttpBody>) -> String {
    response
        .metadata()
        .get("x-http-code")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn reason(status: &Status) -> String {
    sid_core::grpc_error::extract_error_info(status).unwrap().0
}

/// Sign-in starts with a redirect to the issuer's authorization endpoint,
/// carrying the code flow, S256 PKCE, the resource, a state and a nonce;
/// the sign-in is recorded under that state.
#[tokio::test]
async fn sign_in_redirects_to_the_issuer() {
    let f = fixture(memory(), true);
    let response = f
        .adapter
        .start_sign_in(Request::new(StartSignInRequest {
            rd: "/organizations".into(),
        }))
        .await
        .unwrap();
    assert_eq!(status(&response), "302");
    let location: url::Url = response
        .metadata()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        location.as_str().split('?').next().unwrap(),
        format!("{ISSUER}/oauth2/authorize")
    );
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["resource"], "https://ops.sid.example.com/api/");
    assert!(!query["nonce"].is_empty());
    let secret = response
        .metadata()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_owned();
    let pending = f
        .sessions
        .take_pending(&query["state"], &browser_binding(&connection(), &secret))
        .await
        .unwrap()
        .expect("the sign-in is recorded under its state");
    assert_eq!(pending.redirect_url, "/organizations");
    // The challenge is the S256 of the recorded verifier (RFC 7636 §4.6).
    assert_eq!(
        query["code_challenge"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(
            pending.code_verifier.expose_secret().as_bytes()
        ))
    );
}

/// Before the client is provisioned there is no sign-in: 503, nothing
/// recorded.
#[tokio::test]
async fn sign_in_without_a_connection_is_unavailable() {
    let f = fixture(memory(), false);
    let response = f
        .adapter
        .start_sign_in(Request::new(StartSignInRequest { rd: "/".into() }))
        .await
        .unwrap();
    assert_eq!(status(&response), "503");
}

/// A store that cannot record the sign-in sends no browser to the issuer.
#[tokio::test]
async fn sign_in_with_the_store_down_is_unavailable() {
    let f = fixture(Arc::new(Down), true);
    let response = f
        .adapter
        .start_sign_in(Request::new(StartSignInRequest { rd: "/".into() }))
        .await
        .unwrap();
    assert_eq!(status(&response), "503");
    assert!(response.metadata().get("location").is_none());
}

/// The prefix of the fixture application's sign-in correlation cookies.
const SIGN_IN_COOKIE: &str = "__Host-ops-bff-signin-";

/// A sign-in started by a browser that sent no cookie: its state and the
/// `name=value` of the correlation cookie the browser keeps for it.
async fn started(f: &Fixture) -> (String, String) {
    let response = f
        .adapter
        .start_sign_in(Request::new(StartSignInRequest { rd: "/".into() }))
        .await
        .unwrap();
    assert_eq!(status(&response), "302");
    let location: url::Url = response
        .metadata()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let state = location
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let set = response
        .metadata()
        .get("set-cookie")
        .expect("the sign-in binds its browser")
        .to_str()
        .unwrap()
        .to_owned();
    let pair = set.split(';').next().unwrap().to_owned();
    (state, pair)
}

fn callback(state: &str, iss: &str) -> CompleteSignInRequest {
    CompleteSignInRequest {
        state: state.into(),
        code: Some("code".into()),
        error: None,
        iss: Some(iss.into()),
    }
}

/// The cookie that clears `pair`'s cookie, as a response to `response` sets it.
fn clears(response: &Response<HttpBody>, pair: &str) -> bool {
    let name = pair.split_once('=').unwrap().0;
    response.metadata().get_all("set-cookie").iter().any(|set| {
        let set = set.to_str().unwrap();
        set.starts_with(&format!("{name}=;")) && set.contains("Max-Age=0")
    })
}

/// Each sign-in binds the browser that started it with a correlation cookie
/// of its own: HttpOnly, host-only, sent on the issuer's redirect back, and
/// living no longer than the sign-in.
#[tokio::test]
async fn a_sign_in_binds_its_browser() {
    let f = fixture(memory(), true);
    let response = f
        .adapter
        .start_sign_in(Request::new(StartSignInRequest { rd: "/".into() }))
        .await
        .unwrap();
    let set = response
        .metadata()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(set.starts_with(SIGN_IN_COOKIE), "{set}");
    assert!(
        set.contains(&format!(
            "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            LONG.as_secs()
        )),
        "{set}"
    );
}

/// A callback is completed only by the browser that started its sign-in
/// (RFC 6749 §10.12, RFC 9700 §4.7.1): one without its correlation cookie,
/// with another transaction's cookie or with this cookie's name carrying
/// another transaction's secret is refused before any code is redeemed, and
/// the sign-in stays for its own browser, which completes it once.
#[tokio::test]
async fn only_the_starting_browser_completes_a_sign_in() {
    let f = fixture(memory(), true);
    let (state, own) = started(&f).await;
    let (_, other) = started(&f).await;
    let swapped = format!(
        "{}={}",
        own.split_once('=').unwrap().0,
        other.split_once('=').unwrap().1
    );
    let without = f
        .adapter
        .complete_sign_in(Request::new(callback(&state, ISSUER)))
        .await
        .unwrap();
    assert_eq!(status(&without), "400");
    for wrong in [&other, &swapped] {
        let refused = f
            .adapter
            .complete_sign_in(with_cookie(callback(&state, ISSUER), wrong, None))
            .await
            .unwrap();
        assert_eq!(status(&refused), "400", "{wrong}");
    }

    // The starting browser reaches the code redemption: the issuer is
    // unreachable here, so 502, not the 400 of an unknown sign-in; the
    // sign-in is over, so its cookie is cleared.
    let completed = f
        .adapter
        .complete_sign_in(with_cookie(callback(&state, ISSUER), &own, None))
        .await
        .unwrap();
    assert_eq!(status(&completed), "502");
    assert!(clears(&completed, &own));
    let replay = f
        .adapter
        .complete_sign_in(with_cookie(callback(&state, ISSUER), &own, None))
        .await
        .unwrap();
    assert_eq!(status(&replay), "400", "the sign-in is taken once");
}

/// Two tabs start their first sign-ins at once, neither sending a cookie;
/// the browser keeps both correlation cookies, in whatever order they come.
/// Each callback finds its own sign-in and clears only its own cookie.
#[tokio::test]
async fn concurrent_first_sign_ins_both_complete() {
    for a_first in [true, false] {
        let f = fixture(memory(), true);
        let ((a, cookie_a), (b, cookie_b)) = tokio::join!(started(&f), started(&f));
        assert_ne!(
            cookie_a.split_once('=').unwrap().0,
            cookie_b.split_once('=').unwrap().0,
            "each sign-in has a cookie of its own"
        );
        let jar = if a_first {
            format!("{cookie_a}; {cookie_b}")
        } else {
            format!("{cookie_b}; {cookie_a}")
        };
        let first = f
            .adapter
            .complete_sign_in(with_cookie(callback(&a, ISSUER), &jar, None))
            .await
            .unwrap();
        assert_eq!(status(&first), "502", "reaches the code redemption");
        assert!(clears(&first, &cookie_a) && !clears(&first, &cookie_b));
        // A's cookie is gone from the jar; B still completes.
        let second = f
            .adapter
            .complete_sign_in(with_cookie(callback(&b, ISSUER), &cookie_b, None))
            .await
            .unwrap();
        assert_eq!(status(&second), "502", "reaches the code redemption");
    }
}

/// A callback whose state names no recorded sign-in is refused; one from
/// another issuer is refused before its code is used, and the sign-in it
/// took is not left for a replay.
#[tokio::test]
async fn a_callback_must_name_a_recorded_sign_in_of_the_issuer() {
    let f = fixture(memory(), true);
    let (state, browser) = started(&f).await;
    let unknown = f
        .adapter
        .complete_sign_in(with_cookie(
            callback(&"a".repeat(64), ISSUER),
            &browser,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(status(&unknown), "400");

    let foreign = f
        .adapter
        .complete_sign_in(with_cookie(
            callback(&state, "https://evil.example.com/i/x"),
            &browser,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(status(&foreign), "400");
    let replay = f
        .adapter
        .complete_sign_in(with_cookie(callback(&state, ISSUER), &browser, None))
        .await
        .unwrap();
    assert_eq!(status(&replay), "400", "the sign-in is taken once");
}

/// An authorization error from the issuer ends the sign-in without a
/// session.
#[tokio::test]
async fn an_authorization_error_is_refused() {
    let f = fixture(memory(), true);
    let (state, browser) = started(&f).await;
    let response = f
        .adapter
        .complete_sign_in(with_cookie(
            CompleteSignInRequest {
                state,
                code: None,
                error: Some("access_denied".into()),
                iss: Some(ISSUER.into()),
            },
            &browser,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(status(&response), "403");
    // No session is made; the ended sign-in's correlation cookie is cleared.
    let set: Vec<_> = response
        .metadata()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        set.iter().all(|c| !c.starts_with(&format!("{COOKIE}="))),
        "{set:?}"
    );
    assert!(clears(&response, &browser));
}

/// The session read answers the user and the CSRF token of a live session,
/// never stored by caches.
#[tokio::test]
async fn a_live_session_is_read_with_its_csrf_token() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, false).await;
    let response = f
        .adapter
        .get_application_session(with_cookie(
            GetApplicationSessionRequest {},
            &format!("other=1; {COOKIE}={id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.metadata().get("cache-control").unwrap(),
        "no-store"
    );
    let session = response.into_inner();
    assert_eq!(session.sub, "subject-1");
    assert_eq!(session.email.as_deref(), Some("ops@sid.example.com"));
    assert_eq!(session.csrf_token, csrf);
}

/// No cookie, a cookie naming no session, two cookies of the name and a
/// session of another connection are each no session.
#[tokio::test]
async fn no_live_session_is_unauthenticated() {
    let f = fixture(memory(), true);
    let (id, _) = signed_in(&f, false).await;
    let other = f
        .sessions
        .create_session("access".into(), None, claims(), "another connection")
        .await
        .unwrap()
        .0;
    let no_cookie = f
        .adapter
        .get_application_session(with_origin(
            Request::new(GetApplicationSessionRequest {}),
            &[ORIGIN],
        ))
        .await
        .unwrap_err();
    assert_eq!(no_cookie.code(), Code::Unauthenticated);
    for cookie in [
        format!("{COOKIE}={}", "b".repeat(64)),
        format!("{COOKIE}={id}; {COOKIE}={id}"),
        format!("{COOKIE}={other}"),
    ] {
        let refused = f
            .adapter
            .get_application_session(with_cookie(GetApplicationSessionRequest {}, &cookie, None))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::Unauthenticated, "{cookie}");
        assert_eq!(reason(&refused), "TOKEN_INVALID");
    }
}

/// `request` with its `Origin` replaced: none, another site's, the opaque
/// `null` origin, or two values.
fn with_origin<T>(mut request: Request<T>, origin: &[&str]) -> Request<T> {
    request.metadata_mut().remove("origin");
    for value in origin {
        request
            .metadata_mut()
            .append("origin", value.parse().unwrap());
    }
    request
}

/// Origins that are not the application's page.
const NOT_THE_PAGE: [&[&str]; 4] = [
    &[],
    &["https://evil.example.com"],
    &["null"],
    &[ORIGIN, ORIGIN],
];

/// The session read, the session's API calls and the sign-out answer only
/// the application's own page, by its exact `Origin`: a request another site
/// makes the browser send carries the cookie, but not this origin (Fetch
/// §3.2.5). The session stays as it was.
#[tokio::test]
async fn only_the_applications_origin_uses_the_session() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, false).await;
    let cookie = format!("{COOKIE}={id}");
    for origin in NOT_THE_PAGE {
        let read = f
            .adapter
            .get_application_session(with_origin(
                with_cookie(GetApplicationSessionRequest {}, &cookie, None),
                origin,
            ))
            .await
            .unwrap_err();
        assert_eq!(read.code(), Code::PermissionDenied, "{origin:?}");
        assert_eq!(reason(&read), "CSRF_TOKEN_INVALID");

        let api = f
            .adapter
            .bearer(with_origin(with_cookie((), &cookie, Some(&csrf)), origin).metadata())
            .await
            .unwrap_err();
        assert_eq!(api.code(), Code::PermissionDenied, "{origin:?}");

        let end = f
            .adapter
            .end_application_session(with_origin(
                with_cookie(EndApplicationSessionRequest {}, &cookie, Some(&csrf)),
                origin,
            ))
            .await
            .unwrap_err();
        assert_eq!(end.code(), Code::PermissionDenied, "{origin:?}");
    }
    assert!(f.sessions.get_session(&id).await.unwrap().is_some());
    // The page itself is answered.
    assert!(
        f.adapter
            .get_application_session(with_cookie(GetApplicationSessionRequest {}, &cookie, None))
            .await
            .is_ok()
    );
}

/// A session read before the refresh claim may predate a refresh another
/// replica completed under an earlier, expired claim: after winning the
/// claim the adapter uses what the store holds instead of presenting the
/// rotated refresh token. The issuer is unreachable here, so any refresh
/// attempt would be an outage.
#[tokio::test]
async fn a_stale_snapshot_is_not_refreshed_after_the_claim() {
    let f = fixture(memory(), true);
    let mut expired = claims();
    expired.exp = 0;
    let (id, _) = f
        .sessions
        .create_session(
            "access-0".into(),
            Some("refresh-0".into()),
            expired,
            &connection().binding(),
        )
        .await
        .unwrap();
    let stale = f.sessions.get_session(&id).await.unwrap().unwrap();
    assert!(matches!(
        f.sessions
            .replace_tokens(
                &id,
                &"refresh-0".into(),
                "access-1".into(),
                Some("refresh-1".into()),
                claims(),
            )
            .await
            .unwrap(),
        sid_authn::bff_session::TokenReplacement::Replaced
    ));
    let token = f.adapter.current_token(&id, stale).await.unwrap();
    assert_eq!(token.expose_secret(), "access-1");
}

/// An issuer session ended elsewhere ends the application session too: it
/// is refused and removed.
#[tokio::test]
async fn a_revoked_issuer_session_ends_the_application_session() {
    let f = fixture(memory(), true);
    let (id, _) = signed_in(&f, false).await;
    f.revocation
        .revoke_session("issuer-session-1".into())
        .await
        .unwrap();
    let refused = f
        .adapter
        .get_application_session(with_cookie(
            GetApplicationSessionRequest {},
            &format!("{COOKIE}={id}"),
            None,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated);
    assert!(f.sessions.get_session(&id).await.unwrap().is_none());
}

/// A store that cannot be read is an outage, never a signed-out user.
#[tokio::test]
async fn an_unreachable_store_is_unavailable_not_signed_out() {
    let f = fixture(Arc::new(Down), true);
    let refused = f
        .adapter
        .get_application_session(with_cookie(
            GetApplicationSessionRequest {},
            &format!("{COOKIE}={}", "a".repeat(64)),
            None,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unavailable);
    assert_eq!(reason(&refused), "DEPENDENCY_UNAVAILABLE");
}

/// Sign-out needs the session's CSRF token: without it, or with another,
/// the session is left as it was.
#[tokio::test]
async fn sign_out_requires_the_csrf_token() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, false).await;
    for sent in [None, Some("not-the-token")] {
        let refused = f
            .adapter
            .end_application_session(with_cookie(
                EndApplicationSessionRequest {},
                &format!("{COOKIE}={id}"),
                sent,
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::PermissionDenied);
        assert_eq!(reason(&refused), "CSRF_TOKEN_INVALID");
    }
    assert!(f.sessions.get_session(&id).await.unwrap().is_some());

    let ended = f
        .adapter
        .end_application_session(with_cookie(
            EndApplicationSessionRequest {},
            &format!("{COOKIE}={id}"),
            Some(&csrf),
        ))
        .await
        .unwrap();
    let cleared = ended
        .metadata()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cleared.starts_with(&format!("{COOKIE}=;")) && cleared.contains("Max-Age=0"));
    assert_eq!(ended.into_inner().grant, GrantOutcome::None as i32);
    assert!(f.sessions.get_session(&id).await.unwrap().is_none());
}

/// A session whose grant the issuer cannot be asked to revoke ends anyway;
/// the answer says the grant's fate is unknown, not that it was revoked.
#[tokio::test]
async fn sign_out_with_the_issuer_unreachable_reports_the_grant_unknown() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, true).await;
    let ended = f
        .adapter
        .end_application_session(with_cookie(
            EndApplicationSessionRequest {},
            &format!("{COOKIE}={id}"),
            Some(&csrf),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ended.grant, GrantOutcome::Unknown as i32);
    assert!(f.sessions.get_session(&id).await.unwrap().is_none());
}

/// A repeated sign-out finds no session: the cookie is cleared again and the
/// grant is unknown.
#[tokio::test]
async fn a_repeated_sign_out_is_harmless() {
    let f = fixture(memory(), true);
    let ended = f
        .adapter
        .end_application_session(with_cookie(
            EndApplicationSessionRequest {},
            &format!("{COOKIE}={}", "c".repeat(64)),
            Some("x"),
        ))
        .await
        .unwrap();
    assert!(ended.metadata().get("set-cookie").is_some());
    assert_eq!(ended.into_inner().grant, GrantOutcome::Unknown as i32);
}

/// The return path stays on this origin (RFC 9700 §4.11).
#[test]
fn only_local_paths_are_returned_to() {
    assert_eq!(local_path("/ca?x=1"), "/ca?x=1");
    for foreign in [
        "",
        "https://evil.example.com/",
        "//evil.example.com",
        "/\\evil",
        "/a\nb",
    ] {
        assert_eq!(local_path(foreign), "/", "{foreign:?}");
    }
}

/// The issued session cookie is host-only, TLS-only and HttpOnly.
#[tokio::test]
async fn the_session_cookie_is_host_only_and_http_only() {
    let f = fixture(memory(), true);
    assert_eq!(
        f.adapter.session_cookie("abc"),
        format!("{COOKIE}=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    );
}
