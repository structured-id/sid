// SPDX-License-Identifier: AGPL-3.0-only
//! The browser sessions against an issuer in this process: its keys come
//! from a registry the tests can take down or rotate, and its token endpoint
//! is a client whose answers each test scripts.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ed25519_dalek::pkcs8::EncodePrivateKey;
use sid_plugin::cache::InMemoryCacheBackend;
use sid_plugin::{CeremonyStateStore, InProcessCeremonyState};

use super::*;
use crate::client_connection::ClientConnection;
use crate::issuer_directory::{IssuerRecord, IssuerSource, RegistryUnavailable, ResourceRecord};
use crate::jwt::AccessTokenClaims;

const INSTALLATION: &str = "https://sid.example.com";
const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
const OTHER_ISSUER: &str = "https://sid.example.com/i/fedcba9876543210fedcba9876543210";
const CLIENT: &str = "web";
const RESOURCE: &str = "https://app.sid.example.com/api/";
const ORIGIN: &str = "https://app.sid.example.com";
const COOKIE: &str = "__Host-app";
const LONG: Duration = Duration::from_secs(3600);

// ── The issuer ──

/// A signing key of the issuer.
struct Key {
    kid: String,
    encoding: jsonwebtoken::EncodingKey,
    public: [u8; 32],
}

fn key(kid: &str, seed: u8) -> Key {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    Key {
        kid: kid.into(),
        encoding: jsonwebtoken::EncodingKey::from_ed_der(
            signing.to_pkcs8_der().unwrap().as_bytes(),
        ),
        public: signing.verifying_key().to_bytes(),
    }
}

/// The registry's view of the issuer: the keys it publishes, the one it signs
/// with, and whether the registry answers at all.
struct Registry {
    keys: Mutex<Vec<Key>>,
    signer: AtomicUsize,
    down: AtomicBool,
}

impl Registry {
    /// An issuer signing with `k1` and already publishing its next key `k2`,
    /// as a rotation announces a key before using it.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            keys: Mutex::new(vec![key("k1", 1), key("k2", 2)]),
            signer: AtomicUsize::new(0),
            down: AtomicBool::new(false),
        })
    }

    /// The issuer signs with its announced next key from now on.
    fn rotate(&self) {
        self.signer.store(1, Ordering::SeqCst);
    }

    fn sign(&self, typ: &str, claims: &impl serde::Serialize) -> String {
        let keys = self.keys.lock().unwrap();
        let key = &keys[self.signer.load(Ordering::SeqCst)];
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(key.kid.clone());
        header.typ = Some(typ.into());
        jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
    }
}

#[async_trait::async_trait]
impl IssuerSource for Registry {
    async fn issuer(&self, _: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable> {
        if self.down.load(Ordering::SeqCst) {
            return Err(RegistryUnavailable("registry down".into()));
        }
        Ok(Some(IssuerRecord {
            issuer: ISSUER.into(),
            keys: self
                .keys
                .lock()
                .unwrap()
                .iter()
                .map(|key| (key.kid.clone(), key.public))
                .collect(),
        }))
    }

    async fn resource(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
        Ok(None)
    }
}

/// What the token endpoint does with the next refresh.
enum Answer {
    /// Rotates the grant: a new access token living `lifetime` seconds.
    Rotate { lifetime: i64 },
    /// Fails the call this way.
    Fail(fn(String) -> GrantFailure),
}

/// The application's client at the in-process issuer.
struct Client {
    connection: Connection,
    registry: Arc<Registry>,
    /// Authorization codes the issuer granted: code → (nonce, audience).
    codes: Mutex<HashMap<String, (String, String)>>,
    /// Scripted answers to refreshes; a refresh with none scripted rotates.
    refreshes: Mutex<VecDeque<Answer>>,
    /// Every refresh token presented, in order.
    presented: Mutex<Vec<String>>,
    /// The next revocation's failure, if any.
    revoke_failure: Mutex<Option<GrantFailure>>,
    revoked: AtomicUsize,
    /// How many refresh tokens this issuer has issued.
    rotations: AtomicUsize,
}

impl Client {
    fn new(registry: Arc<Registry>) -> Arc<Self> {
        Arc::new(Self {
            connection: connection(),
            registry,
            codes: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(VecDeque::new()),
            presented: Mutex::new(Vec::new()),
            revoke_failure: Mutex::new(None),
            revoked: AtomicUsize::new(0),
            rotations: AtomicUsize::new(0),
        })
    }

    /// The issuer's authorization endpoint: the user signs in and the browser
    /// is sent back with a code for the request `authorize_url` describes.
    fn authorize(&self, authorize_url: &url::Url) -> String {
        let query: HashMap<_, _> = authorize_url.query_pairs().into_owned().collect();
        let code = random_token();
        self.codes.lock().unwrap().insert(
            code.clone(),
            (query["nonce"].clone(), query["resource"].clone()),
        );
        code
    }

    fn access_token(&self, audience: &str, lifetime: i64) -> String {
        let now = jiff::Timestamp::now().as_second();
        self.registry.sign(
            "at+jwt",
            &AccessTokenClaims {
                sub: "subject-1".into(),
                pid: None,
                iss: ISSUER.into(),
                aud: vec![audience.into()],
                client_id: Some(CLIENT.into()),
                exp: now + lifetime,
                iat: now,
                auth_time: now,
                acr: "urn:sid:acr:basic".into(),
                scope: "openid".into(),
                roles: String::new(),
                sid: "issuer-session-1".into(),
                amr: vec![],
                jti: random_token(),
                cnf: None,
                act: None,
                credential_kind: Some(crate::jwt::IssuedCredential::Delegated),
            },
        )
    }

    fn refresh_token(&self) -> String {
        format!(
            "refresh-{}",
            self.rotations.fetch_add(1, Ordering::SeqCst) + 1
        )
    }

    fn presented(&self) -> Vec<String> {
        self.presented.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ApplicationClient for Client {
    async fn connection(&self) -> Result<&Connection, GrantFailure> {
        Ok(&self.connection)
    }

    async fn redeem(
        &self,
        _: &Connection,
        code: String,
        _code_verifier: String,
    ) -> Result<IssuedTokens, GrantFailure> {
        // A code is redeemed once (RFC 6749 §4.1.2).
        let (nonce, audience) = self
            .codes
            .lock()
            .unwrap()
            .remove(&code)
            .ok_or_else(|| GrantFailure::Refused("invalid_grant".into()))?;
        let now = jiff::Timestamp::now().as_second();
        let id_token = self.registry.sign(
            "JWT",
            &serde_json::json!({
                "iss": ISSUER,
                "sub": "subject-1",
                "aud": CLIENT,
                "exp": now + 300,
                "iat": now,
                "auth_time": now,
                "acr": "urn:sid:acr:basic",
                "sid": "issuer-session-1",
                "nonce": nonce,
                "email": "user@sid.example.com",
            }),
        );
        Ok(IssuedTokens {
            access_token: self.access_token(&audience, 300),
            refresh_token: Some(self.refresh_token()),
            id_token: Some(id_token),
        })
    }

    async fn refresh(
        &self,
        _: &Connection,
        refresh_token: String,
    ) -> Result<IssuedTokens, GrantFailure> {
        self.presented.lock().unwrap().push(refresh_token);
        let answer = self
            .refreshes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Answer::Rotate { lifetime: 300 });
        match answer {
            Answer::Rotate { lifetime } => Ok(IssuedTokens {
                access_token: self.access_token(RESOURCE, lifetime),
                refresh_token: Some(self.refresh_token()),
                id_token: None,
            }),
            Answer::Fail(failure) => Err(failure("scripted".into())),
        }
    }

    async fn revoke(&self, _: &Connection, _: String) -> Result<(), GrantFailure> {
        if let Some(failure) = self.revoke_failure.lock().unwrap().take() {
            return Err(failure);
        }
        self.revoked.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn connection() -> Connection {
    Connection::accept(
        ClientConnection {
            issuer: ISSUER.into(),
            client_id: CLIENT.into(),
            resource: RESOURCE.into(),
            scopes: vec!["openid".into()],
            redirect_uri: format!("{ORIGIN}/auth/callback"),
            token_endpoint_auth_method: "private_key_jwt".into(),
            key_ids: vec![],
        },
        INSTALLATION,
    )
    .unwrap()
}

// ── The adapter's side ──

/// One replica's sessions over a store every replica shares.
struct World {
    registry: Arc<Registry>,
    client: Arc<Client>,
    store: Arc<dyn CeremonyStateStore>,
    revocation: Arc<RevocationCache>,
}

impl World {
    fn new() -> Self {
        let registry = Registry::new();
        Self {
            client: Client::new(registry.clone()),
            registry,
            store: Arc::new(InProcessCeremonyState::new()),
            revocation: Arc::new(RevocationCache::new(
                LONG,
                Arc::new(InMemoryCacheBackend::new()),
            )),
        }
    }

    /// A replica: its own issuer directory and cache, the shared store.
    fn replica(&self) -> BrowserSessions<Client> {
        BrowserSessions::new(
            self.client.clone(),
            Arc::new(IssuerDirectory::new(INSTALLATION, self.registry.clone())),
            Arc::new(BffSessionStore::new(self.store.clone(), LONG, LONG, LONG)),
            self.revocation.clone(),
            COOKIE.into(),
        )
    }

    fn store(&self) -> BffSessionStore {
        BffSessionStore::new(self.store.clone(), LONG, LONG, LONG)
    }
}

/// The issuer's answer to a started sign-in: the user signed in.
fn answered(world: &World, start: &SignInStart) -> AuthorizationAnswer {
    AuthorizationAnswer {
        state: start.state.clone(),
        code: Some(world.client.authorize(&start.authorize_url)),
        error: None,
        iss: Some(ISSUER.into()),
    }
}

/// A complete sign-in at `replica`: the new session's id.
async fn sign_in(world: &World, replica: &BrowserSessions<Client>) -> String {
    let start = replica.start_sign_in("/home").await.unwrap();
    replica
        .complete_sign_in(Some(&start.browser_secret), answered(world, &start))
        .await
        .unwrap()
        .session_id
}

/// A call from the application's page with session `id`.
fn page_call<'a>(id: &str, csrf: &'a str) -> BrowserRequest<'a> {
    BrowserRequest {
        session: Some(id.to_owned()),
        origins: vec![ORIGIN.as_bytes()],
        csrf: vec![csrf.as_bytes()],
        safe: false,
    }
}

/// The session `id`, with its access token about to expire.
async fn expiring(world: &World, id: &str) -> BffSession {
    let store = world.store();
    let mut session = store.get_session(id).await.unwrap().unwrap();
    let mut claims = session.claims.clone();
    claims.exp = jiff::Timestamp::now().as_second() + 5;
    let refresh = session.refresh_token.clone().unwrap();
    store
        .replace_tokens(
            id,
            &refresh,
            session.access_token.clone(),
            Some(refresh.clone()),
            claims.clone(),
        )
        .await
        .unwrap();
    session.claims = claims;
    session
}

// ── Sign-in ──

/// A sign-in started at one replica completes at another: the session holds
/// the verified user, its profile claims from the ID token, and returns the
/// user to the path asked for.
#[tokio::test]
async fn a_sign_in_completes_across_replicas() {
    let world = World::new();
    let (first, second) = (world.replica(), world.replica());
    let start = first.start_sign_in("/home").await.unwrap();
    let signed_in = second
        .complete_sign_in(Some(&start.browser_secret), answered(&world, &start))
        .await
        .unwrap();
    assert_eq!(signed_in.return_to, "/home");
    let session = world
        .store()
        .get_session(&signed_in.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.claims.sub, "subject-1");
    assert_eq!(
        session.claims.email.as_deref(),
        Some("user@sid.example.com")
    );
    let read = first
        .read(&page_call(&signed_in.session_id, ""))
        .await
        .unwrap();
    assert_eq!(read.csrf_token, session.csrf_token);
}

/// A callback is used once: replayed at either replica it finds no sign-in
/// and makes no session.
#[tokio::test]
async fn a_replayed_callback_makes_nothing() {
    let world = World::new();
    let (first, second) = (world.replica(), world.replica());
    let start = first.start_sign_in("/").await.unwrap();
    let answer = answered(&world, &start);
    let replay = AuthorizationAnswer {
        state: answer.state.clone(),
        code: answer.code.clone(),
        error: None,
        iss: answer.iss.clone(),
    };
    first
        .complete_sign_in(Some(&start.browser_secret), answer)
        .await
        .unwrap();
    let refused = second
        .complete_sign_in(Some(&start.browser_secret), replay)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SignInFailure::ExpiredOrUsed),
        "{refused:?}"
    );
}

/// A valid unused callback of one browser cannot sign another browser in,
/// even one with a sign-in of its own under way: the state is found only
/// under the browser that started it. That browser still completes it.
#[tokio::test]
async fn another_browsers_callback_cannot_sign_this_browser_in() {
    let world = World::new();
    let replica = world.replica();
    let victim = replica.start_sign_in("/").await.unwrap();
    let attacker = replica.start_sign_in("/").await.unwrap();
    // The attacker's own unused code and state, delivered to the victim's
    // browser, which presents its own correlation secret.
    let attackers_answer = answered(&world, &attacker);
    let refused = replica
        .complete_sign_in(Some(&victim.browser_secret), attackers_answer)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SignInFailure::ExpiredOrUsed),
        "{refused:?}"
    );
    // Without the correlation cookie nothing is even looked up.
    let refused = replica
        .complete_sign_in(None, answered(&world, &attacker))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SignInFailure::OtherBrowser),
        "{refused:?}"
    );
    // The victim's own sign-in is untouched.
    replica
        .complete_sign_in(Some(&victim.browser_secret), answered(&world, &victim))
        .await
        .unwrap();
}

/// Two first sign-ins of one browser, both started before either answer set
/// a cookie, complete in either order into two sessions: completing one does
/// not remove the other's binding.
#[tokio::test]
async fn two_first_sign_ins_complete_in_either_order() {
    for reversed in [false, true] {
        let world = World::new();
        let replica = world.replica();
        let one = replica.start_sign_in("/one").await.unwrap();
        let two = replica.start_sign_in("/two").await.unwrap();
        let (answer_one, answer_two) = (answered(&world, &one), answered(&world, &two));
        let order = if reversed {
            [(&two, answer_two), (&one, answer_one)]
        } else {
            [(&one, answer_one), (&two, answer_two)]
        };
        let mut sessions = Vec::new();
        for (start, answer) in order {
            sessions.push(
                replica
                    .complete_sign_in(Some(&start.browser_secret), answer)
                    .await
                    .unwrap()
                    .session_id,
            );
        }
        assert_ne!(sessions[0], sessions[1]);
    }
}

/// An authorization response naming another issuer (RFC 9207 §2.4) is
/// refused after its sign-in was taken: the code is never redeemed and the
/// sign-in cannot be retried with it.
#[tokio::test]
async fn an_answer_of_another_issuer_is_refused() {
    let world = World::new();
    let replica = world.replica();
    let start = replica.start_sign_in("/").await.unwrap();
    let mut answer = answered(&world, &start);
    answer.iss = Some(OTHER_ISSUER.into());
    let refused = replica
        .complete_sign_in(Some(&start.browser_secret), answer)
        .await
        .unwrap_err();
    assert!(matches!(refused, SignInFailure::WrongIssuer), "{refused:?}");
    assert!(refused.took_the_sign_in());
    let again = replica
        .complete_sign_in(Some(&start.browser_secret), answered(&world, &start))
        .await
        .unwrap_err();
    assert!(matches!(again, SignInFailure::ExpiredOrUsed), "{again:?}");
}

/// An access token issued for another resource is not this application's:
/// the sign-in makes no session.
#[tokio::test]
async fn a_token_for_another_resource_makes_no_session() {
    let world = World::new();
    let replica = world.replica();
    let start = replica.start_sign_in("/").await.unwrap();
    let answer = answered(&world, &start);
    world
        .client
        .codes
        .lock()
        .unwrap()
        .get_mut(answer.code.as_deref().unwrap())
        .unwrap()
        .1 = "https://other.sid.example.com/api/".into();
    let refused = replica
        .complete_sign_in(Some(&start.browser_secret), answer)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SignInFailure::IssuerFailed(_)),
        "{refused:?}"
    );
}

/// The issuer's authorization error comes back with where the user can start
/// again; `access_denied` is told apart by the adapter from its text.
#[tokio::test]
async fn an_authorization_error_is_returned_with_the_restart_path() {
    let world = World::new();
    let replica = world.replica();
    let start = replica.start_sign_in("/settings").await.unwrap();
    let refused = replica
        .complete_sign_in(
            Some(&start.browser_secret),
            AuthorizationAnswer {
                state: start.state.clone(),
                code: None,
                error: Some("access_denied".into()),
                iss: Some(ISSUER.into()),
            },
        )
        .await
        .unwrap_err();
    match refused {
        SignInFailure::Refused { error, return_to } => {
            assert_eq!(error, "access_denied");
            assert_eq!(return_to, "/settings");
        }
        other => panic!("{other:?}"),
    }
}

/// With the registry down the returned tokens cannot be verified: no session
/// is made from them.
#[tokio::test]
async fn an_unreachable_registry_makes_no_session() {
    let world = World::new();
    let replica = world.replica();
    let start = replica.start_sign_in("/").await.unwrap();
    world.registry.down.store(true, Ordering::SeqCst);
    let refused = replica
        .complete_sign_in(Some(&start.browser_secret), answered(&world, &start))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SignInFailure::IssuerFailed(_)),
        "{refused:?}"
    );
}

/// After the issuer rotates to the key it announced, a sign-in completes
/// with tokens of the new key, and a session made under the old key
/// refreshes into tokens of the new one.
#[tokio::test]
async fn sessions_continue_across_an_issuer_key_rotation() {
    let world = World::new();
    let replica = world.replica();
    let before = sign_in(&world, &replica).await;
    let csrf = expiring(&world, &before).await.csrf_token;
    world.registry.rotate();
    sign_in(&world, &replica).await;
    replica.bearer(&page_call(&before, &csrf)).await.unwrap();
    assert_eq!(world.client.presented(), ["refresh-1"]);
}

// ── Refresh ──

/// Two replicas using one expiring session at once present its refresh
/// token once: one refreshes, the other waits for that refresh and uses its
/// result.
#[tokio::test]
async fn concurrent_calls_refresh_once() {
    let world = World::new();
    let (first, second) = (world.replica(), world.replica());
    let id = sign_in(&world, &first).await;
    let session = expiring(&world, &id).await;
    let csrf = session.csrf_token.clone();
    let (call_a, call_b) = (page_call(&id, &csrf), page_call(&id, &csrf));
    let (a, b) = tokio::join!(first.bearer(&call_a), second.bearer(&call_b));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(world.client.presented(), ["refresh-1"]);
    assert_eq!(a.token().expose_secret(), b.token().expose_secret());
    assert_ne!(
        a.token().expose_secret(),
        session.access_token.expose_secret()
    );
}

/// A refresh whose answer was lost may have rotated the grant: the session
/// stays and the call is an outage. Nothing replays the refresh by itself,
/// and while the lost refresh's claim holds no replica presents the same
/// refresh token again; a call then reports the refresh unfinished.
#[tokio::test(start_paused = true)]
async fn a_lost_refresh_answer_keeps_the_session() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = expiring(&world, &id).await.csrf_token;
    world
        .client
        .refreshes
        .lock()
        .unwrap()
        .push_back(Answer::Fail(GrantFailure::Uncertain));
    let refused = replica.bearer(&page_call(&id, &csrf)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SessionFailure::Unavailable {
                dependency: "issuer",
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(world.client.presented(), ["refresh-1"]);
    assert!(world.store().get_session(&id).await.unwrap().is_some());

    let waited = replica.bearer(&page_call(&id, &csrf)).await.unwrap_err();
    assert!(
        matches!(
            waited,
            SessionFailure::Unavailable {
                dependency: "session store",
                ..
            }
        ),
        "{waited:?}"
    );
    assert_eq!(world.client.presented(), ["refresh-1"]);
}

/// An issuer that cannot serve the refresh now leaves the session as it was.
#[tokio::test]
async fn a_declined_refresh_keeps_the_session() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = expiring(&world, &id).await.csrf_token;
    world
        .client
        .refreshes
        .lock()
        .unwrap()
        .push_back(Answer::Fail(GrantFailure::Declined));
    let refused = replica.bearer(&page_call(&id, &csrf)).await.unwrap_err();
    assert!(
        matches!(refused, SessionFailure::Unavailable { .. }),
        "{refused:?}"
    );
    assert!(world.store().get_session(&id).await.unwrap().is_some());
}

/// A refused refresh means the grant is gone: the session ends.
#[tokio::test]
async fn a_refused_refresh_ends_the_session() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = expiring(&world, &id).await.csrf_token;
    world
        .client
        .refreshes
        .lock()
        .unwrap()
        .push_back(Answer::Fail(GrantFailure::Refused));
    let refused = replica.bearer(&page_call(&id, &csrf)).await.unwrap_err();
    assert!(
        matches!(refused, SessionFailure::NotSignedIn),
        "{refused:?}"
    );
    assert!(world.store().get_session(&id).await.unwrap().is_none());
}

/// A refreshed token the registry cannot verify now is not stored; the
/// session keeps its tokens for the next call.
#[tokio::test]
async fn a_refresh_with_the_registry_down_keeps_the_session() {
    let world = World::new();
    let id = sign_in(&world, &world.replica()).await;
    let before = expiring(&world, &id).await;
    world.registry.down.store(true, Ordering::SeqCst);
    // Another replica, whose directory has not met the issuer yet, must ask
    // the registry to verify the refreshed token.
    let refused = world
        .replica()
        .bearer(&page_call(&id, &before.csrf_token))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SessionFailure::Unavailable { .. }),
        "{refused:?}"
    );
    let after = world.store().get_session(&id).await.unwrap().unwrap();
    assert_eq!(
        after.access_token.expose_secret(),
        before.access_token.expose_secret()
    );
}

/// A refresh that completed with a token still inside the refresh margin (its
/// lifetime capped by an approaching step-up or issuer-session expiry) does
/// not hold the next call: that call refreshes the new version at once
/// instead of waiting for a change no replica is making.
#[tokio::test(start_paused = true)]
async fn a_completed_refresh_inside_the_margin_does_not_stall_the_next_call() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = expiring(&world, &id).await.csrf_token;
    world
        .client
        .refreshes
        .lock()
        .unwrap()
        .push_back(Answer::Rotate { lifetime: 10 });
    replica.bearer(&page_call(&id, &csrf)).await.unwrap();
    let started = tokio::time::Instant::now();
    replica.bearer(&page_call(&id, &csrf)).await.unwrap();
    assert_eq!(world.client.presented(), ["refresh-1", "refresh-2"]);
    assert!(
        started.elapsed() < REFRESH_POLL,
        "the call waited for a refresh nobody was making"
    );
}

/// A refresh started from a snapshot older than the session claims the
/// version it actually presents: the rotated token is never presented from
/// the stale snapshot.
#[tokio::test]
async fn a_stale_snapshot_presents_the_current_refresh_token() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let stale = expiring(&world, &id).await;
    // Another replica rotated `refresh-1` to a token near its end too.
    let store = world.store();
    let mut claims = stale.claims.clone();
    claims.exp = jiff::Timestamp::now().as_second() + 5;
    store
        .replace_tokens(
            &id,
            &"refresh-1".into(),
            "access-2".into(),
            Some("refresh-2".into()),
            claims,
        )
        .await
        .unwrap();
    replica.current_token(&id, stale).await.unwrap();
    assert_eq!(world.client.presented(), ["refresh-2"]);
}

/// A stale read whose session another replica already refreshed to a usable
/// token answers with that token and refreshes nothing.
#[tokio::test]
async fn a_usable_token_found_after_a_stale_read_is_not_refreshed() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let stale = expiring(&world, &id).await;
    let mut claims = stale.claims.clone();
    claims.exp = jiff::Timestamp::now().as_second() + 600;
    world
        .store()
        .replace_tokens(
            &id,
            &"refresh-1".into(),
            "access-2".into(),
            Some("refresh-2".into()),
            claims,
        )
        .await
        .unwrap();
    let token = replica.current_token(&id, stale).await.unwrap();
    assert_eq!(token.token().expose_secret(), "access-2");
    assert!(world.client.presented().is_empty());
}

/// A token the API refused is refreshed before the session is used again,
/// whatever its expiry.
#[tokio::test]
async fn a_refused_token_is_refreshed_before_the_next_use() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = world
        .store()
        .get_session(&id)
        .await
        .unwrap()
        .unwrap()
        .csrf_token;
    let bearer = replica.bearer(&page_call(&id, &csrf)).await.unwrap();
    replica.refused(&bearer).await.unwrap();
    let next = replica.bearer(&page_call(&id, &csrf)).await.unwrap();
    assert_ne!(next.token().expose_secret(), bearer.token().expose_secret());
    assert_eq!(world.client.presented(), ["refresh-1"]);
}

// ── Page checks ──

/// A call that can change something must come from the application's page
/// and echo the session's CSRF token; a safe one needs neither.
#[tokio::test]
async fn a_call_must_come_from_the_page_with_the_csrf_token() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = world
        .store()
        .get_session(&id)
        .await
        .unwrap()
        .unwrap()
        .csrf_token;

    let mut foreign = page_call(&id, &csrf);
    foreign.origins = vec![b"https://evil.example.com"];
    assert!(matches!(
        replica.bearer(&foreign).await,
        Err(SessionFailure::NotThePage)
    ));
    let mut none = page_call(&id, &csrf);
    none.origins.clear();
    assert!(matches!(
        replica.bearer(&none).await,
        Err(SessionFailure::NotThePage)
    ));
    assert!(matches!(
        replica.bearer(&page_call(&id, "guess")).await,
        Err(SessionFailure::CsrfMismatch)
    ));
    replica.bearer(&page_call(&id, &csrf)).await.unwrap();

    let safe = BrowserRequest {
        session: Some(id.clone()),
        safe: true,
        ..BrowserRequest::default()
    };
    replica.bearer(&safe).await.unwrap();
}

/// A session read, an API call and a sign-out each verify the exact Origin
/// before touching the session: a foreign, absent, `null` (Fetch §3.2.5) or
/// duplicated Origin is refused, and the session stays as it was. Only the
/// page's own origin, sent once, passes.
#[tokio::test]
async fn every_session_request_verifies_the_exact_origin() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = world
        .store()
        .get_session(&id)
        .await
        .unwrap()
        .unwrap()
        .csrf_token;
    let refused: [Vec<&[u8]>; 4] = [
        vec![b"https://evil.example.com"],
        vec![],
        vec![b"null"],
        vec![ORIGIN.as_bytes(), ORIGIN.as_bytes()],
    ];
    for origins in refused {
        let request = BrowserRequest {
            origins: origins.clone(),
            ..page_call(&id, &csrf)
        };
        assert!(
            matches!(
                replica.read(&request).await,
                Err(SessionFailure::NotThePage)
            ),
            "read {origins:?}"
        );
        assert!(
            matches!(
                replica.bearer(&request).await,
                Err(SessionFailure::NotThePage)
            ),
            "bearer {origins:?}"
        );
        assert!(
            matches!(replica.end(&request).await, Err(SessionFailure::NotThePage)),
            "end {origins:?}"
        );
    }
    assert!(world.store().get_session(&id).await.unwrap().is_some());
    replica.read(&page_call(&id, &csrf)).await.unwrap();
    replica.bearer(&page_call(&id, &csrf)).await.unwrap();
    replica.end(&page_call(&id, &csrf)).await.unwrap();
}

/// A session of another connection is not this one's.
#[tokio::test]
async fn a_session_of_another_connection_is_not_used() {
    let world = World::new();
    let replica = world.replica();
    let (id, csrf) = world
        .store()
        .create_session(
            "access".into(),
            None,
            world
                .store()
                .get_session(&sign_in(&world, &replica).await)
                .await
                .unwrap()
                .unwrap()
                .claims,
            "another connection",
        )
        .await
        .unwrap();
    assert!(matches!(
        replica.bearer(&page_call(&id, &csrf)).await,
        Err(SessionFailure::NotSignedIn)
    ));
    assert!(world.store().get_session(&id).await.unwrap().is_some());
}

// ── Sign-out ──

/// Sign-out ends the session and revokes its grant; a revocation answered
/// with a refusal leaves the grant alive, one whose answer was lost may have
/// taken effect.
#[tokio::test]
async fn sign_out_reports_what_became_of_the_grant() {
    for (failure, expected) in [
        (None, GrantOutcome::Revoked),
        (
            Some(GrantFailure::Refused("no".into())),
            GrantOutcome::NotRevoked,
        ),
        (
            Some(GrantFailure::Declined("busy".into())),
            GrantOutcome::NotRevoked,
        ),
        (
            Some(GrantFailure::NotSent("key".into())),
            GrantOutcome::NotRevoked,
        ),
        (
            Some(GrantFailure::Uncertain("lost".into())),
            GrantOutcome::Unknown,
        ),
    ] {
        let world = World::new();
        let replica = world.replica();
        let id = sign_in(&world, &replica).await;
        let csrf = world
            .store()
            .get_session(&id)
            .await
            .unwrap()
            .unwrap()
            .csrf_token;
        *world.client.revoke_failure.lock().unwrap() = failure;
        assert_eq!(replica.end(&page_call(&id, &csrf)).await.unwrap(), expected);
        assert!(world.store().get_session(&id).await.unwrap().is_none());
    }
}

/// Sign-out without the CSRF token leaves the session; a repeated sign-out
/// finds nothing and knows nothing of the grant.
#[tokio::test]
async fn sign_out_needs_the_csrf_token_and_repeats_harmlessly() {
    let world = World::new();
    let replica = world.replica();
    let id = sign_in(&world, &replica).await;
    let csrf = world
        .store()
        .get_session(&id)
        .await
        .unwrap()
        .unwrap()
        .csrf_token;
    assert!(matches!(
        replica.end(&page_call(&id, "guess")).await,
        Err(SessionFailure::CsrfMismatch)
    ));
    assert!(world.store().get_session(&id).await.unwrap().is_some());
    replica.end(&page_call(&id, &csrf)).await.unwrap();
    assert_eq!(
        replica.end(&page_call(&id, &csrf)).await.unwrap(),
        GrantOutcome::Unknown
    );
}

// ── Pure checks ──

/// A return path that leaves the origin would make the adapter an open
/// redirector (RFC 9700 §4.11): it falls back to the root.
#[test]
fn only_a_local_path_is_returned_to() {
    assert_eq!(local_path("/settings?tab=keys"), "/settings?tab=keys");
    assert_eq!(local_path("//evil.example"), "/");
    assert_eq!(local_path("/\\evil.example"), "/");
    assert_eq!(local_path("https://evil.example/"), "/");
    assert_eq!(local_path("/a\nb"), "/");
    assert_eq!(local_path(""), "/");
}

/// A cookie sent twice is ambiguous and names nothing; one sent once is
/// found in any of the request's `Cookie` headers.
#[test]
fn a_cookie_is_read_only_when_sent_once() {
    assert_eq!(
        cookie_value(["a=1; sid=xyz", "b=2"], "sid").as_deref(),
        Some("xyz")
    );
    assert_eq!(cookie_value(["sid=1", "sid=2"], "sid"), None);
    assert_eq!(cookie_value(["sid=1; sid=2"], "sid"), None);
    assert_eq!(cookie_value(["sidx=1"], "sid"), None);
}

/// The CSRF token must be echoed exactly once and exactly: a second header
/// could carry a guess beside the real one.
#[test]
fn the_csrf_token_matches_only_once_and_exactly() {
    assert!(csrf_matches(&[b"token"], "token"));
    assert!(!csrf_matches(&[b"token", b"token"], "token"));
    assert!(!csrf_matches(&[], "token"));
    assert!(!csrf_matches(&[b"toke"], "token"));
}

/// Only a failure after the sign-in was taken clears its correlation cookie:
/// one that never reached the store leaves the browser's sign-in in place.
#[test]
fn only_a_taken_sign_in_clears_its_correlation() {
    assert!(!SignInFailure::OtherBrowser.took_the_sign_in());
    assert!(!SignInFailure::ExpiredOrUsed.took_the_sign_in());
    assert!(!SignInFailure::Unavailable(String::new()).took_the_sign_in());
    assert!(!SignInFailure::NotProvisioned(String::new()).took_the_sign_in());
    assert!(SignInFailure::WrongIssuer.took_the_sign_in());
    assert!(SignInFailure::NoCode.took_the_sign_in());
    assert!(SignInFailure::IssuerFailed(String::new()).took_the_sign_in());
    assert!(SignInFailure::EndedAtIssuer.took_the_sign_in());
    assert!(SignInFailure::NotStored(String::new()).took_the_sign_in());
}
