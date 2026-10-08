// SPDX-License-Identifier: AGPL-3.0-only
//! BFF session store.
//!
//! Sessions live in a [`CacheBackend`] rather than in this process, because a
//! BFF runs behind a load balancer: a login that lands on one replica is
//! continued by a request that lands on another, and a rolling update replaces
//! every replica while sessions are open.
//!
//! Two consequences shape the types below. Timestamps are absolute
//! (`DateTime<Utc>`), not `Instant`, because a monotonic clock means nothing to
//! the process that reads the value back. And expiry is the store's, not a
//! sweeper's: the cache holds each entry for the idle window and the absolute
//! deadline is checked against `created_at` on read.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_plugin::cache::{CacheBackend, CacheError};

use sid_auth::auth::jwt::ForwardAuthClaims;

/// Key prefix for sessions. Separate from `pending` so one cannot be read as
/// the other, and from every other user of the same cache.
const SESSION_PREFIX: &str = "bff:sess:";
/// Key prefix for pending authorizations.
const PENDING_PREFIX: &str = "bff:pending:";
/// Key prefix for the claim on a session's refresh.
const REFRESH_PREFIX: &str = "bff:refresh:";

/// Failures of the session store.
///
/// A cache that is unreachable is not "no session": it must not log everyone
/// out, and above all it must not let a pending authorization be consumed
/// twice. Callers decide, and the type makes them.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("session store unavailable: {0}")]
    Backend(#[from] CacheError),

    #[error("stored session is unreadable: {0}")]
    Corrupt(#[from] serde_json::Error),
}

pub type SessionResult<T> = Result<T, SessionStoreError>;

/// Pending OAuth2 authorization, held between the login redirect and the
/// callback that completes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuth {
    pub code_verifier: String,
    /// The `nonce` sent with the authorization request, which the ID token
    /// must carry back (OIDC Core 1.0 §3.1.2.1, §3.1.3.7).
    pub nonce: String,
    pub redirect_url: String,
    pub created_at: DateTime<Utc>,
}

/// A BFF session: the tokens a browser never sees, held server-side under an
/// opaque cookie value.
#[derive(Clone, Serialize, Deserialize)]
pub struct BffSession {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub claims: ForwardAuthClaims,
    pub csrf_token: String,
    pub created_at: DateTime<Utc>,
    pub last_access: DateTime<Utc>,
}

/// Hand-written so that a session reaching a log or an error message does not
/// carry the tokens it exists to keep out of the browser.
impl std::fmt::Debug for BffSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BffSession")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
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
    /// How long an unfinished authorization may sit between the login redirect
    /// and the callback that completes it.
    pending_ttl: Duration,
}

impl BffSessionStore {
    /// Create a store over `cache`, with the deployment's session lifetimes.
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

    /// Store a new session, return (session_id, csrf_token).
    pub async fn create_session(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        claims: ForwardAuthClaims,
    ) -> SessionResult<(String, String)> {
        let session_id = generate_token();
        let csrf_token = generate_token(); // separate random token
        let now = Utc::now();
        let session = BffSession {
            access_token,
            refresh_token,
            claims,
            csrf_token: csrf_token.clone(),
            created_at: now,
            last_access: now,
        };
        self.write(&session_id, &session).await?;
        Ok((session_id, csrf_token))
    }

    /// Get a session by id, refreshing its idle window.
    ///
    /// Returns `None` for a session that never existed, that the cache has
    /// already dropped, or that has outlived `max_age`.
    pub async fn get_session(&self, id: &str) -> SessionResult<Option<BffSession>> {
        // The id arrives in a cookie, so it is whatever the client sent. Ours
        // are 64 hex characters; anything else cannot name a session we
        // issued, and turning it away here keeps arbitrary client input out of
        // the key space of a cache shared with everything else.
        if !is_issued_shape(id) {
            return Ok(None);
        }
        let Some(raw) = self.cache.get(&session_key(id)).await? else {
            return Ok(None);
        };
        let mut session: BffSession = serde_json::from_slice(&raw)?;

        // The idle window is the cache's TTL, but the absolute deadline is not:
        // every access pushes the TTL out, so without this check an active
        // session would never reach max_age.
        if age(session.created_at) >= self.max_age {
            self.cache.delete(&session_key(id)).await?;
            return Ok(None);
        }

        // Pushing the idle window out costs a write, and doing it on every
        // read means a second round trip to a shared store on every
        // authenticated request. Half the window is refresh enough: a session
        // in use is rewritten long before its TTL runs out, and one that goes
        // quiet still expires on time.
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
    /// `true` for exactly one caller. SID rotates refresh tokens and treats a
    /// replayed one as theft, ending the grant, so two replicas refreshing
    /// one session at once would sign its user out.
    ///
    /// The claim is never released, only outlived: a release could delete a
    /// later holder's claim after this one expired. `hold` outlasts a token
    /// endpoint call, and the next refresh of the session comes when its new
    /// token nears expiry, long after.
    pub async fn claim_refresh(&self, id: &str, hold: Duration) -> SessionResult<bool> {
        Ok(self.cache.set_nx(&refresh_key(id), b"1", hold).await?)
    }

    /// Replace the tokens of session `id` after a refresh, keeping its CSRF
    /// token and lifetimes. `false` when the session ended meanwhile.
    pub async fn replace_tokens(
        &self,
        id: &str,
        access_token: String,
        refresh_token: Option<String>,
        claims: ForwardAuthClaims,
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

    /// Store a pending OAuth2 authorization, return its `state` parameter.
    pub async fn store_pending(
        &self,
        code_verifier: String,
        nonce: String,
        redirect_url: String,
    ) -> SessionResult<String> {
        let state = generate_token();
        let pending = PendingAuth {
            code_verifier,
            nonce,
            redirect_url,
            created_at: Utc::now(),
        };
        self.cache
            .set(
                &pending_key(&state),
                &serde_json::to_vec(&pending)?,
                self.pending_ttl,
            )
            .await?;
        Ok(state)
    }

    /// Take a pending authorization, exactly once across every replica.
    ///
    /// A read followed by a delete would let two callbacks carrying the same
    /// `state` both succeed, which is the replay `state` exists to prevent; the
    /// cache's atomic take gives the value to one of them only.
    pub async fn take_pending(&self, state: &str) -> SessionResult<Option<PendingAuth>> {
        // Same reasoning as `get_session`: the state parameter comes back from
        // the browser, and only our own shape can name a pending flow.
        if !is_issued_shape(state) {
            return Ok(None);
        }
        let Some(raw) = self.cache.take(&pending_key(state)).await? else {
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

fn session_key(id: &str) -> String {
    format!("{SESSION_PREFIX}{id}")
}

fn pending_key(state: &str) -> String {
    format!("{PENDING_PREFIX}{state}")
}

fn refresh_key(id: &str) -> String {
    format!("{REFRESH_PREFIX}{id}")
}

/// Elapsed time since `then`, saturating at zero for a clock that moved back.
fn age(then: DateTime<Utc>) -> Duration {
    (Utc::now() - then).to_std().unwrap_or(Duration::ZERO)
}

/// Whether a value has the shape [`generate_token`] produces.
fn is_issued_shape(value: &str) -> bool {
    value.len() == TOKEN_HEX_LEN && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Length of the hex form of a 32-byte identifier.
const TOKEN_HEX_LEN: usize = 64;

/// Generate a cryptographically random identifier.
fn generate_token() -> String {
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    // Use getrandom for CSPRNG
    getrandom::fill(&mut bytes).expect("failed to generate random bytes");
    let mut hex = String::with_capacity(64);
    for b in &bytes {
        write!(hex, "{:02x}", b).unwrap();
    }
    hex
}

#[cfg(test)]
mod tests;
