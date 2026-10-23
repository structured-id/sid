// SPDX-License-Identifier: AGPL-3.0-only
//! The session store of a relying party's browser adapter (BFF): the tokens
//! its issuer gave it, held server-side under an opaque cookie value, and the
//! sign-ins it has started and not yet completed.
//!
//! Sessions live in a [`CacheBackend`] rather than in the process, because
//! the adapter runs behind a load balancer: a sign-in that lands on one
//! replica is completed by a request that lands on another, and a rolling
//! update replaces every replica while sessions are open. The cache is the
//! shared state, not an optimization: an unreachable cache is reported, never
//! read as "no session" (every user would be signed out) or as an unused
//! sign-in (its `state` could be replayed).
//!
//! Timestamps are absolute (`DateTime<Utc>`), not `Instant`, because a
//! monotonic clock means nothing to the process that reads the value back.
//! Expiry is the store's, not a sweeper's: the cache holds each entry for the
//! idle window and the absolute deadline is checked against `created_at` on
//! read.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rand::TryRng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sid_plugin::cache::{CacheBackend, CacheError};

use crate::jwt::AccessTokenClaims;

/// Key prefix for sessions. Separate from `pending` so one cannot be read as
/// the other, and from every other user of the same cache. The prefixes of
/// both records name their shape: a change of shape takes a new prefix, so
/// replicas of different versions over one cache never read each other's
/// records, and the old ones expire unread. While a rollout that changes the
/// shape is in progress a browser may be asked to sign in again on a replica
/// of the other version; reading both shapes would keep every former shape
/// alive in the code.
const SESSION_PREFIX: &str = "bff:sess:3:";
/// Key prefix for pending sign-ins, followed by the digest of the sign-in
/// binding they were started under.
const PENDING_PREFIX: &str = "bff:pending:4:";
/// Key prefix for the claim on a session's refresh.
const REFRESH_PREFIX: &str = "bff:refresh:";

/// Failures of the session store. Callers decide what an outage means for
/// their request; the type makes them.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("session store unavailable: {0}")]
    Backend(#[from] CacheError),

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

/// Session store over a shared cache.
pub struct BffSessionStore {
    cache: Arc<dyn CacheBackend>,
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
    /// A store over `cache`, with the deployment's session lifetimes.
    pub fn new(
        cache: Arc<dyn CacheBackend>,
        max_age: Duration,
        idle_timeout: Duration,
        pending_ttl: Duration,
    ) -> Self {
        Self {
            cache,
            max_age,
            idle_timeout,
            pending_ttl,
        }
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
    /// session that never existed, that the cache dropped, or that has
    /// outlived `max_age`.
    pub async fn get_session(&self, id: &str) -> SessionResult<Option<BffSession>> {
        // The id arrives in a cookie, so it is whatever the client sent. Only
        // the shape the store issues can name a session, and anything else
        // stays out of the key space of a cache shared with everything else.
        if !is_issued_shape(id) {
            return Ok(None);
        }
        let Some(raw) = self.cache.get(&session_key(id)).await? else {
            return Ok(None);
        };
        let mut session: BffSession = serde_json::from_slice(&raw)?;

        // The idle window is the cache's TTL, the absolute deadline is not:
        // every access pushes the TTL out, so without this check an active
        // session would never reach max_age.
        if age(session.created_at) >= self.max_age {
            self.cache.delete(&session_key(id)).await?;
            return Ok(None);
        }

        // Pushing the window out costs a write; doing it on every read would
        // add a round trip to every authenticated request. Half the window is
        // refresh enough: a session in use is rewritten long before its TTL
        // runs out, and one that goes quiet still expires on time.
        let now = Utc::now();
        if age(session.last_access) >= self.idle_timeout / 2 {
            session.last_access = now;
            self.write(id, &session).await?;
        } else {
            session.last_access = now;
        }
        Ok(Some(session))
    }

    /// Destroy a session. No-op if it is not there.
    pub async fn destroy_session(&self, id: &str) -> SessionResult<()> {
        self.cache.delete(&session_key(id)).await?;
        Ok(())
    }

    /// Claim the refresh of session `id` for `hold`, across every replica:
    /// `true` for exactly one caller. The issuer rotates refresh tokens and
    /// treats a replayed one as theft, ending the grant, so two replicas
    /// refreshing one session at once would sign its user out.
    ///
    /// The claim is never released, only outlived: a release could delete a
    /// later holder's claim after this one expired. `hold` outlasts a token
    /// endpoint call, and the session's next refresh comes when its new token
    /// nears expiry, long after.
    pub async fn claim_refresh(&self, id: &str, hold: Duration) -> SessionResult<bool> {
        Ok(self.cache.set_nx(&refresh_key(id), b"1", hold).await?)
    }

    /// Replace the tokens of session `id` after a refresh, keeping its CSRF
    /// token and lifetimes. `false` when the session ended meanwhile.
    pub async fn replace_tokens(
        &self,
        id: &str,
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        claims: SessionClaims,
    ) -> SessionResult<bool> {
        let Some(raw) = self.cache.get(&session_key(id)).await? else {
            return Ok(false);
        };
        let mut session: BffSession = serde_json::from_slice(&raw)?;
        session.access_token = access_token;
        session.refresh_token = refresh_token;
        session.claims = claims;
        self.write(id, &session).await?;
        Ok(true)
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
        self.cache
            .set(
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
    /// the cache's atomic take gives the value to one of them only. One
    /// started under another binding is not found and stays for a replica of
    /// that binding, which shares the cache during a rollout.
    pub async fn take_pending(
        &self,
        state: &str,
        connection: &str,
    ) -> SessionResult<Option<PendingSignIn>> {
        if !is_issued_shape(state) {
            return Ok(None);
        }
        let Some(raw) = self.cache.take(&pending_key(connection, state)).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    /// Write a session under its current idle window.
    async fn write(&self, id: &str, session: &BffSession) -> SessionResult<()> {
        self.cache
            .set(
                &session_key(id),
                &serde_json::to_vec(session)?,
                self.idle_timeout,
            )
            .await?;
        Ok(())
    }
}

/// Written out rather than derived: a cache handle has nothing readable to
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

fn session_key(id: &str) -> String {
    format!("{SESSION_PREFIX}{id}")
}

/// The key of a pending sign-in: its sign-in binding's SHA-256, so the key
/// stays short and carries no URL, then its state.
fn pending_key(connection: &str, state: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(connection.as_bytes()));
    format!("{PENDING_PREFIX}{digest}:{state}")
}

fn refresh_key(id: &str) -> String {
    format!("{REFRESH_PREFIX}{id}")
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
}

#[cfg(test)]
mod tests;
