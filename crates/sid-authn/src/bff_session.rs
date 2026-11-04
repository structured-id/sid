// SPDX-License-Identifier: AGPL-3.0-only
//! The session store of a relying party's browser adapter (BFF): the tokens
//! its issuer gave it, held server-side under an opaque cookie value, and the
//! sign-ins it has started and not yet completed.
//!
//! These records belong to the relying party, so they live in its
//! authoritative store ([`CeremonyStateStore`]: the application's PostgreSQL
//! for shared replicas, SQLite for a single instance), never in a cache alone:
//! the adapter runs behind a load balancer, a sign-in that lands on one
//! replica is completed by a request that lands on another, a rolling update
//! replaces every replica while sessions are open, and a cache restart loses
//! nothing. An unreachable store is reported, never read as "no session"
//! (every user would be signed out) or as an unused sign-in (its `state`
//! could be replayed).
//!
//! Timestamps are absolute (`DateTime<Utc>`), not `Instant`, because a
//! monotonic clock means nothing to the process that reads the value back.
//! Expiry is checked at use: the store refuses each entry past its idle
//! window, and the absolute deadline is checked against `created_at` on read.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rand::TryRng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sid_plugin::CeremonyStateStore;

use crate::jwt::AccessTokenClaims;

/// Namespace of sessions. Separate from pending sign-ins so one cannot be
/// read as the other. The namespaces of both records name their shape: a
/// change of shape takes a new namespace, so replicas of different versions
/// over one store never read each other's records, and the old ones expire
/// unread. While a rollout that changes the shape is in progress a browser
/// may be asked to sign in again on a replica of the other version; reading
/// both shapes would keep every former shape alive in the code.
const SESSIONS: &str = "bff_session_3";
/// Namespace of pending sign-ins, keyed by the digest of the sign-in binding
/// they were started under and their `state`.
const PENDING: &str = "bff_pending_4";
/// Namespace of refresh claims, keyed by session and refresh token version.
const REFRESH: &str = "bff_refresh_1";
/// Namespace of the issuer sessions the issuer's back-channel logouts ended.
const ENDED: &str = "bff_ended_1";
/// How many times a token replacement is applied again over concurrent idle
/// pushes before it is reported: each push is one write per half idle window
/// per replica, so a few attempts outlast any real interleaving.
const REPLACE_ATTEMPTS: usize = 4;

/// Failures of the session store. Callers decide what an outage means for
/// their request; the type makes them.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("session store unavailable: {0}")]
    Backend(#[from] sid_core::Error),

    #[error("stored session is unreadable: {0}")]
    Corrupt(#[from] serde_json::Error),
}

pub type SessionResult<T> = Result<T, SessionStoreError>;

/// What a session knows of its user: the claims of the access token its
/// issuer returned, with the profile claims of the sign-in's ID token, since
/// an access token carries none (RFC 9068 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    /// The subject as the issuer names it to this client.
    pub sub: String,
    pub iss: String,
    /// When the current access token expires (Unix seconds).
    pub exp: i64,
    pub iat: i64,
    /// When the user actually authenticated.
    pub auth_time: i64,
    pub acr: String,
    /// Space-separated scopes of the current access token.
    #[serde(default)]
    pub scope: String,
    /// Space-separated roles of the current access token.
    #[serde(default)]
    pub roles: String,
    /// The issuer's session, checked against revocations.
    pub sid: String,
    /// The current access token's id, checked against revocations.
    pub jti: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
}

impl From<AccessTokenClaims> for SessionClaims {
    /// An access token carries no profile claims; they come from the ID token.
    fn from(claims: AccessTokenClaims) -> Self {
        Self {
            sub: claims.sub,
            iss: claims.iss,
            exp: claims.exp,
            iat: claims.iat,
            auth_time: claims.auth_time,
            acr: claims.acr,
            scope: claims.scope,
            roles: claims.roles,
            sid: claims.sid,
            jti: claims.jti,
            email: None,
            name: None,
            preferred_username: None,
            groups: None,
        }
    }
}

impl SessionClaims {
    /// These claims of a refreshed access token, keeping the profile claims
    /// of `previous`: the refresh returns no ID token, and the user is the
    /// same.
    pub fn refreshed(mut self, previous: &SessionClaims) -> Self {
        self.email.clone_from(&previous.email);
        self.name.clone_from(&previous.name);
        self.preferred_username
            .clone_from(&previous.preferred_username);
        self.groups.clone_from(&previous.groups);
        self
    }
}

/// A sign-in started and not yet completed, held between the redirect to
/// the issuer and the callback.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingSignIn {
    /// The PKCE verifier (RFC 7636 §4.1).
    #[serde(with = "secret")]
    pub code_verifier: SecretString,
    /// The `nonce` sent with the authorization request, which the ID token
    /// must carry back (OIDC Core 1.0 §3.1.2.1, §3.1.3.7).
    pub nonce: String,
    /// The local path to return to.
    pub redirect_url: String,
    pub created_at: DateTime<Utc>,
}

/// A session: the tokens a browser never sees.
#[derive(Clone, Serialize, Deserialize)]
pub struct BffSession {
    #[serde(with = "secret")]
    pub access_token: SecretString,
    #[serde(with = "secret_opt")]
    pub refresh_token: Option<SecretString>,
    pub claims: SessionClaims,
    /// The synchronizer token the page echoes on every state-changing call.
    pub csrf_token: String,
    pub created_at: DateTime<Utc>,
    pub last_access: DateTime<Utc>,
    /// The connection its tokens were issued under; an adapter with another
    /// connection does not use the session.
    pub connection: String,
}

/// Hand-written so that a session reaching a log or an error message does not
/// carry the CSRF token; the tokens redact themselves.
impl std::fmt::Debug for BffSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BffSession")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("sub", &self.claims.sub)
            .field("csrf_token", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("last_access", &self.last_access)
            .finish()
    }
}

/// Session store over the application's authoritative store.
pub struct BffSessionStore {
    store: Arc<dyn CeremonyStateStore>,
    /// Absolute lifetime: a session is gone this long after it was created,
    /// however active it has been.
    max_age: Duration,
    /// Idle lifetime: a session is gone this long after its last use.
    idle_timeout: Duration,
    /// How long an unfinished sign-in may sit between the redirect and the
    /// callback that completes it.
    pending_ttl: Duration,
}

impl BffSessionStore {
    /// A store over `store`, with the deployment's session lifetimes.
    pub fn new(
        store: Arc<dyn CeremonyStateStore>,
        max_age: Duration,
        idle_timeout: Duration,
        pending_ttl: Duration,
    ) -> Self {
        Self {
            store,
            max_age,
            idle_timeout,
            pending_ttl,
        }
    }

    /// How long a started sign-in waits for its callback: the lifetime of
    /// anything a browser holds for it.
    pub fn pending_ttl(&self) -> Duration {
        self.pending_ttl
    }

    /// Store a new session issued under `connection`; returns
    /// (session id, CSRF token).
    pub async fn create_session(
        &self,
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        claims: SessionClaims,
        connection: &str,
    ) -> SessionResult<(String, String)> {
        let session_id = generate_token();
        let csrf_token = generate_token();
        let now = Utc::now();
        let session = BffSession {
            access_token,
            refresh_token,
            claims,
            csrf_token: csrf_token.clone(),
            created_at: now,
            last_access: now,
            connection: connection.to_owned(),
        };
        self.write(&session_id, &session).await?;
        Ok((session_id, csrf_token))
    }

    /// The session `id` names, its idle window pushed out. `None` for a
    /// session that never existed, that ended, or that has outlived
    /// `max_age`.
    pub async fn get_session(&self, id: &str) -> SessionResult<Option<BffSession>> {
        // The id arrives in a cookie, so it is whatever the client sent. Only
        // the shape the store issues can name a session; anything else never
        // reaches the store.
        if !is_issued_shape(id) {
            return Ok(None);
        }
        let Some(raw) = self.store.read_ceremony_state(SESSIONS, id).await? else {
            return Ok(None);
        };
        let mut session: BffSession = serde_json::from_slice(&raw)?;

        // The idle window is the entry's lifetime, the absolute deadline is
        // not: every access pushes the lifetime out, so without this check an
        // active session would never reach max_age.
        if age(session.created_at) >= self.max_age {
            self.store.take_ceremony_state(SESSIONS, id).await?;
            return Ok(None);
        }

        // Pushing the window out costs a write; doing it on every read would
        // add a round trip to every authenticated request. Half the window is
        // refresh enough: a session in use is rewritten long before its TTL
        // runs out, and one that goes quiet still expires on time.
        let now = Utc::now();
        let due = age(session.last_access) >= self.idle_timeout / 2;
        session.last_access = now;
        // The push replaces exactly what was read: a session another replica
        // destroyed or refreshed since is never written back over.
        if due && !self.rewrite(id, &raw, &session).await? {
            return self.read_current(id).await;
        }
        Ok(Some(session))
    }

    /// The session as it is now, read again after a write lost to another
    /// replica's, without pushing its window again: that replica just wrote it.
    async fn read_current(&self, id: &str) -> SessionResult<Option<BffSession>> {
        let Some(raw) = self.store.read_ceremony_state(SESSIONS, id).await? else {
            return Ok(None);
        };
        let session: BffSession = serde_json::from_slice(&raw)?;
        if age(session.created_at) >= self.max_age {
            return Ok(None);
        }
        Ok(Some(session))
    }

    /// Destroy a session. No-op if it is not there.
    pub async fn destroy_session(&self, id: &str) -> SessionResult<()> {
        self.store.take_ceremony_state(SESSIONS, id).await?;
        Ok(())
    }

    /// Claim the refresh of session `id`, read holding refresh token `read`,
    /// for `hold`, across every replica: [`RefreshClaim::Claimed`] for exactly
    /// one caller, with the session as it is now. The issuer rotates refresh
    /// tokens and treats a replayed one as theft, ending the grant, so two
    /// replicas refreshing one version at once would sign its user out.
    ///
    /// `read` may be older than the session: another replica may have
    /// refreshed since. The claim then moves to the version the session holds,
    /// so the claim always names the token the winner presents; a caller
    /// holding that version sees the refresh in flight instead of a finished
    /// one it may take over. A newer version `needs_refresh` declines is not
    /// claimed at all: it comes back as [`RefreshClaim::Current`], and no
    /// claim is left that a later caller would wait on with no refresh behind
    /// it.
    pub async fn claim_refresh(
        &self,
        id: &str,
        read: &SecretString,
        hold: Duration,
        needs_refresh: impl Fn(&BffSession) -> bool,
    ) -> SessionResult<RefreshClaim> {
        let mut from = read.clone();
        for _ in 0..REPLACE_ATTEMPTS {
            if !self.claim_version(id, &from, hold).await? {
                return Ok(RefreshClaim::HeldElsewhere);
            }
            let Some(session) = self.get_session(id).await? else {
                return Ok(RefreshClaim::Ended);
            };
            match &session.refresh_token {
                Some(current) if !session.holds_refresh_token(&from) => {
                    if !needs_refresh(&session) {
                        return Ok(RefreshClaim::Current(Box::new(session)));
                    }
                    from = current.clone();
                }
                _ => return Ok(RefreshClaim::Claimed(Box::new(session))),
            }
        }
        Err(SessionStoreError::Backend(sid_core::Error::Storage(
            format!("session {id} kept changing while its refresh was claimed"),
        )))
    }

    /// Claim the refresh of version `from` of session `id`: `true` for exactly
    /// one caller while the claim lives.
    ///
    /// Each version has a claim of its own. A claim left by the refresh of an
    /// earlier version does not hold the next one: a returned token may itself
    /// be near its end, capped by an approaching step-up or issuer-session
    /// expiry. A claim of a version in flight is never taken over, whatever
    /// version the caller read.
    ///
    /// The claim is never released, only outlived: a release could free a
    /// version that a later caller would then present again. `hold` outlasts
    /// a token endpoint call.
    async fn claim_version(
        &self,
        id: &str,
        from: &SecretString,
        hold: Duration,
    ) -> SessionResult<bool> {
        Ok(self
            .store
            .admit_once(REFRESH, &refresh_key(id, from), hold)
            .await?)
    }

    /// Replace the tokens of session `id` with those a refresh of
    /// `refreshed_from` returned, keeping its CSRF token and lifetimes.
    ///
    /// The result is stored only while the session still holds
    /// `refreshed_from`: a refresh claim is a lease that can expire, so
    /// another replica may have refreshed since, and its newer tokens must
    /// not be overwritten with this older result.
    pub async fn replace_tokens(
        &self,
        id: &str,
        refreshed_from: &SecretString,
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        claims: SessionClaims,
    ) -> SessionResult<TokenReplacement> {
        // Applied to the session as it is when written: a concurrent idle push
        // makes the write miss and it is applied again over that push; a
        // sign-out or a newer refresh ends the attempt.
        for _ in 0..REPLACE_ATTEMPTS {
            let Some(raw) = self.store.read_ceremony_state(SESSIONS, id).await? else {
                return Ok(TokenReplacement::Ended);
            };
            let mut session: BffSession = serde_json::from_slice(&raw)?;
            if !session.holds_refresh_token(refreshed_from) {
                return Ok(TokenReplacement::Superseded(Box::new(session)));
            }
            session.access_token = access_token.clone();
            session.refresh_token = refresh_token.clone();
            session.claims = claims.clone();
            if self.rewrite(id, &raw, &session).await? {
                return Ok(TokenReplacement::Replaced);
            }
        }
        Err(SessionStoreError::Backend(sid_core::Error::Storage(
            format!("session {id} kept changing while its tokens were replaced"),
        )))
    }

    /// Replace the stored form `read` of session `id` with `session`, under
    /// its current idle window: `false` when it was destroyed or rewritten
    /// since `read`.
    async fn rewrite(&self, id: &str, read: &[u8], session: &BffSession) -> SessionResult<bool> {
        Ok(self
            .store
            .replace_ceremony_state(
                SESSIONS,
                id,
                read,
                &serde_json::to_vec(session)?,
                self.idle_timeout,
            )
            .await?)
    }

    /// Store a sign-in started under the sign-in binding `connection`;
    /// returns its `state` parameter.
    pub async fn store_pending(
        &self,
        code_verifier: SecretString,
        nonce: String,
        redirect_url: String,
        connection: &str,
    ) -> SessionResult<String> {
        let state = generate_token();
        let pending = PendingSignIn {
            code_verifier,
            nonce,
            redirect_url,
            created_at: Utc::now(),
        };
        self.store
            .put_ceremony_state(
                PENDING,
                &pending_key(connection, &state),
                &serde_json::to_vec(&pending)?,
                self.pending_ttl,
            )
            .await?;
        Ok(state)
    }

    /// Take a sign-in started under the sign-in binding `connection`,
    /// exactly once across every replica.
    ///
    /// A read followed by a delete would let two callbacks carrying the same
    /// `state` both succeed, which is the replay `state` exists to prevent;
    /// the store's atomic take gives the value to one of them only. One
    /// started under another binding is not found and stays for a replica of
    /// that binding, which shares the store during a rollout.
    pub async fn take_pending(
        &self,
        state: &str,
        connection: &str,
    ) -> SessionResult<Option<PendingSignIn>> {
        if !is_issued_shape(state) {
            return Ok(None);
        }
        let Some(raw) = self
            .store
            .take_ceremony_state(PENDING, &pending_key(connection, state))
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    /// Record that the issuer ended its session `sid` of issuer `iss`
    /// (Back-Channel Logout 1.0 §2.7): every application session of it ends
    /// at its next use, and a sign-in completing afterwards for it opens
    /// nothing. The record's presence is all it says, so concurrent and
    /// repeated logouts all leave the same record. Kept as long as a session
    /// lives, so no session it ended outlives it.
    pub async fn record_issuer_logout(&self, iss: &str, sid: &str) -> SessionResult<()> {
        self.store
            .put_ceremony_state(ENDED, &ended_key(iss, sid), b"ended", self.max_age)
            .await?;
        Ok(())
    }

    /// Whether the issuer's back-channel logout ended the issuer session of
    /// `claims`.
    pub async fn ended_by_issuer(&self, claims: &SessionClaims) -> SessionResult<bool> {
        Ok(self
            .store
            .read_ceremony_state(ENDED, &ended_key(&claims.iss, &claims.sid))
            .await?
            .is_some())
    }

    /// Write a session under its current idle window.
    async fn write(&self, id: &str, session: &BffSession) -> SessionResult<()> {
        self.store
            .put_ceremony_state(
                SESSIONS,
                id,
                &serde_json::to_vec(session)?,
                self.idle_timeout,
            )
            .await?;
        Ok(())
    }
}

/// Written out rather than derived: a store handle has nothing readable to
/// print, and the state that holds this store derives `Debug`.
impl std::fmt::Debug for BffSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BffSessionStore")
            .field("max_age", &self.max_age)
            .field("idle_timeout", &self.idle_timeout)
            .field("pending_ttl", &self.pending_ttl)
            .finish_non_exhaustive()
    }
}

/// A secret stored in the shared session store: the store holds it because
/// the browser must not, so it is written as its value and read back into a
/// secret.
mod secret {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(value.expose_secret())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        String::deserialize(d).map(SecretString::from)
    }
}

/// [`secret`] for an optional value.
mod secret_opt {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<SecretString>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(secret) => s.serialize_some(secret.expose_secret()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
        Ok(Option::<String>::deserialize(d)?.map(SecretString::from))
    }
}

/// The key of a pending sign-in: its sign-in binding's SHA-256, so the key
/// stays short and carries no URL, then its state.
fn pending_key(connection: &str, state: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(connection.as_bytes()));
    format!("{digest}:{state}")
}

/// The key of the claim on the refresh of version `token` of session `id`:
/// the token's digest, so the key never holds the token itself.
fn refresh_key(id: &str, token: &SecretString) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let version = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(token.expose_secret().as_bytes()));
    format!("{id}:{version}")
}

/// The key of an ended issuer session: a digest of the issuer and the
/// session, each length prefixed, so no issuer's session names another's.
fn ended_key(iss: &str, sid: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    for part in [iss.as_bytes(), sid.as_bytes()] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
}

/// Elapsed time since `then`, zero for a clock that moved back: a timestamp
/// in the future has no age yet.
fn age(then: DateTime<Utc>) -> Duration {
    (Utc::now() - then).to_std().unwrap_or(Duration::ZERO)
}

/// Whether a value has the shape [`generate_token`] produces.
fn is_issued_shape(value: &str) -> bool {
    value.len() == TOKEN_HEX_LEN && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Length of the hex form of a 32-byte identifier.
const TOKEN_HEX_LEN: usize = 64;

/// A random 256-bit identifier, as lowercase hex.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    hex::encode(bytes)
}

impl BffSession {
    /// The access token, for the `Authorization` header of a forwarded call.
    pub fn bearer(&self) -> &str {
        self.access_token.expose_secret()
    }

    /// Whether this session's refresh token is `token`: the version of the
    /// tokens a refresh started from. Compared in constant time, as every
    /// comparison of a secret.
    pub fn holds_refresh_token(&self, token: &SecretString) -> bool {
        use subtle::ConstantTimeEq;
        self.refresh_token.as_ref().is_some_and(|held| {
            bool::from(
                held.expose_secret()
                    .as_bytes()
                    .ct_eq(token.expose_secret().as_bytes()),
            )
        })
    }
}

/// What became of a refresh result handed to
/// [`BffSessionStore::replace_tokens`].
#[derive(Debug)]
pub enum TokenReplacement {
    /// Stored: the session now holds the refreshed tokens.
    Replaced,
    /// Not stored: the session already holds newer tokens, here as they are.
    /// Boxed: the rare outcome should not size every answer.
    Superseded(Box<BffSession>),
    /// Not stored: the session ended meanwhile.
    Ended,
}

/// The outcome of [`BffSessionStore::claim_refresh`].
#[derive(Debug)]
pub enum RefreshClaim {
    /// This caller refreshes, from the session as it is now; the claim names
    /// its refresh token. Boxed: a session should not size every answer.
    Claimed(Box<BffSession>),
    /// Nothing to refresh: the session holds a newer version that needs no
    /// refresh yet, here as it is. Nothing was claimed for it.
    Current(Box<BffSession>),
    /// Another caller is refreshing the version the session holds.
    HeldElsewhere,
    /// The session ended meanwhile.
    Ended,
}

#[cfg(test)]
mod tests;
