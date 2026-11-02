// SPDX-License-Identifier: AGPL-3.0-only
//! Federated entry: this installation as the registered recipient of a
//! trusted issuer's selected-Profile issuance, through the authorization
//! code flow (OpenID Connect Core 1.0 §3.1).
//!
//! The issuer authenticates its holder and returns a code for the recipient's
//! exact redirect URI. The recipient exchanges it, validates the ID Token
//! against that issuer, and gets the subject the issuer names for this
//! recipient with the evidence of how it was authenticated. Admitting that
//! subject (which local identity it resolves to and whether the evidence
//! suffices) is the caller's decision. Nothing here links accounts, discovers
//! other issuers or provisions anyone.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sid_core::models::AuthLevel;
use sid_core::models::session::AcceptedEvidence;
use sid_keys::KeyManager;
use sid_plugin::cache::CacheBackend;

use crate::browser_session::{BrowserCookie, BrowserSecret};
use crate::challenge_store::{ChallengeStore, ChallengeStoreError};
use crate::upstream::oidc::{
    IdTokenExpectation, discover, fetch_key_set, pkce_challenge, random_token, validate_id_token,
};

/// How long a started entry waits for its return.
pub const PENDING_TTL: Duration = Duration::from_secs(600);

/// The cache namespace of pending entries.
const NAMESPACE: &str = "federated-entry";

/// What separates a correlation cookie's name from its session cookie's.
const ENTRY_INFIX: &str = "-entry-";

/// The bytes of the state's digest a correlation cookie's name carries.
const ENTRY_DIGEST_BYTES: usize = 8;

/// Whether `name` is the name of a correlation cookie of the entries an
/// issuer whose session cookie is `session` starts: that name, the infix
/// and the lowercase hex digest of one entry's state.
pub fn is_entry_cookie(session: &str, name: &str) -> bool {
    name.strip_prefix(session)
        .and_then(|rest| rest.strip_prefix(ENTRY_INFIX))
        .is_some_and(|digest| {
            digest.len() == 2 * ENTRY_DIGEST_BYTES
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The longest one code exchange may take: past it the token request is
/// abandoned as of unknown outcome.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an exchange's owner holds it: its timeout and the steps around
/// it, with margin for replicas' clock skew. A holder past it has stopped.
const EXCHANGE_LEASE: Duration = Duration::from_secs(40);

/// The issuer this installation receives issuance from, and its registered
/// client there.
#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    /// The issuer identifier, exactly as its ID Tokens name it.
    pub issuer: String,
    /// This installation's client id at the issuer.
    pub client_id: String,
    /// The client secret, sent as `client_secret_basic` (RFC 6749 §2.3.1).
    pub client_secret: SecretString,
}

/// What the request asks the issuer for, beyond the subject.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRequest {
    /// The assurance the issuer is asked to establish (`acr_values`, OpenID
    /// Connect Core 1.0 §3.1.2.1).
    pub acr: Option<AuthLevel>,
    /// The longest time since the holder's authentication at the issuer
    /// (`max_age`, §3.1.2.1). Every returned ID Token must state `auth_time`.
    pub max_age: Option<Duration>,
}

/// A started entry, kept until its return. Only this shape is read: an entry
/// stored in another one fails to decode and completes nothing, and lives no
/// longer than [`PENDING_TTL`].
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    /// The issuer and client the entry was started for: another relying
    /// party sharing the store never completes it.
    issuer: String,
    client_id: String,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    /// Where the caller continues once the entry is admitted.
    continuation: String,
    /// What the entry asked the issuer for.
    request: EntryRequest,
    /// The entry's end, fixed when it started; no later step extends it.
    deadline: DateTime<Utc>,
}

/// How far a returned entry has come, kept under the browser's binding so a
/// retry of its return resumes where the last one stopped and never redeems
/// its code twice (RFC 6749 §4.1.2).
#[derive(Clone, Serialize, Deserialize)]
enum Progress {
    /// Started; its return has not been exchanged.
    Pending(Pending),
    /// One attempt owns the exchange until `owned_until`; the code may be
    /// spent. Its exchange is bounded by [`EXCHANGE_TIMEOUT`], so an owner
    /// still holding it past the lease has stopped.
    Exchanging {
        pending: Pending,
        owned_until: DateTime<Utc>,
    },
    /// The token response arrived and is kept for validation.
    Received { pending: Pending, id_token: String },
    /// The ID Token was validated; admission resumes from here.
    Exchanged {
        pending: Pending,
        subject: String,
        evidence: AcceptedEvidence,
    },
    /// An exchange may have spent the code without a retained answer: the
    /// entry can only be started again, continuing where it would have.
    Ambiguous { continuation: String },
}

/// A started entry as the browser receives it.
#[derive(Debug, Clone)]
pub struct Started {
    /// The issuer's authorization URL to send the browser to.
    pub authorization_url: String,
    /// The `Set-Cookie` value that binds the entry to this browser.
    pub set_cookie: String,
}

/// A returned entry: the subject the issuer signed in for this recipient,
/// how it authenticated (the issuer's statement, not this installation's),
/// where the caller continues and what the entry asked the issuer for. The
/// same entry returns the same value to every retry of its return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Returned {
    pub subject: String,
    pub evidence: AcceptedEvidence,
    pub continuation: String,
    pub requested: EntryRequest,
    /// The entry's stable reference in this browser: the caller keys the
    /// session it admits by it, so a retry finds that session's result
    /// instead of admitting again.
    pub operation: String,
    /// The entry's end: whatever the caller keeps for its retries lives no
    /// longer.
    pub deadline: DateTime<Utc>,
}

/// Why an entry did not complete. Every case completes nothing.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// The state is unknown, expired, already taken or another browser's.
    #[error("the entry is unknown, expired or already completed")]
    Unknown,
    /// The return carries no correlation cookie of this entry: it reached a
    /// browser other than the one that started it.
    #[error("the entry was started in another browser")]
    OtherBrowser,
    /// The return does not name the redirect URI the entry was started for.
    #[error("the return names another redirect URI")]
    RedirectMismatch,
    /// The issuer could not be reached or answered unusably.
    #[error("the issuer: {0}")]
    Issuer(String),
    /// The ID Token is not this issuer's valid token for this entry.
    #[error("the ID Token: {0}")]
    Token(String),
    /// An exchange of this entry's code may have happened without a kept
    /// answer: its code is never redeemed again, and sign-in starts anew at
    /// the entry's continuation.
    #[error("the entry's exchange outcome is unknown")]
    Ambiguous { continuation: String },
    /// Another return of this entry is exchanging its code right now: this
    /// return is retried, and then completes the same entry.
    #[error("the entry's exchange is in progress")]
    InProgress,
    #[error(transparent)]
    Store(#[from] ChallengeStoreError),
}

/// The relying party of one trusted issuer.
pub struct FederatedEntry {
    trusted: TrustedIssuer,
    http: Client,
    pending: ChallengeStore<Progress>,
    /// The authority's browser-session cookie; an entry's correlation cookie
    /// is named after it, so authorities sharing a host never read each
    /// other's.
    cookie: BrowserCookie,
}

impl FederatedEntry {
    /// The relying party of `trusted`, reaching it over `http`, its pending
    /// entries in `cache` sealed under `keys`, for the authority whose
    /// browser-session cookie is `cookie`.
    pub fn new(
        trusted: TrustedIssuer,
        http: Client,
        cache: Arc<dyn CacheBackend>,
        keys: Arc<dyn KeyManager>,
        cookie: BrowserCookie,
    ) -> Self {
        Self {
            trusted,
            http,
            pending: ChallengeStore::new(cache, keys, NAMESPACE, PENDING_TTL),
            cookie,
        }
    }

    /// The correlation cookie of the entry `state` names: one per entry, so
    /// entries started at once in several tabs never replace each other's.
    /// The name is a digest of the state, a fixed short token whatever a
    /// return sends.
    fn correlation(&self, state: &str) -> BrowserCookie {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(state.as_bytes());
        BrowserCookie::new(&format!(
            "{}{ENTRY_INFIX}{}",
            self.cookie.name(),
            hex::encode(&digest[..ENTRY_DIGEST_BYTES])
        ))
        .expect("a __Host- token with a hex suffix is a __Host- token")
    }

    /// The `Set-Cookie` value that removes the correlation cookie of the
    /// entry `state` names; a return clears it whatever comes of it.
    pub fn clear_cookie(&self, state: &str) -> String {
        self.correlation(state).clear()
    }

    /// The trusted issuer's identifier.
    pub fn issuer(&self) -> &str {
        &self.trusted.issuer
    }

    /// Start an entry returning to `redirect_uri`, continuing at
    /// `continuation`: the authorization URL to send the browser to, and the
    /// cookie that binds the entry to that browser (RFC 9700 §4.7.1).
    pub async fn start(
        &self,
        redirect_uri: &str,
        continuation: &str,
        request: &EntryRequest,
    ) -> Result<Started, EntryError> {
        let discovery = discover(&self.http, &self.trusted.issuer)
            .await
            .map_err(|e| EntryError::Issuer(e.to_string()))?;
        let state = random_token();
        let nonce = random_token();
        let code_verifier = random_token();
        let challenge = pkce_challenge(&code_verifier);
        let mut params = vec![
            ("response_type", "code".to_owned()),
            ("client_id", self.trusted.client_id.clone()),
            ("redirect_uri", redirect_uri.to_owned()),
            ("scope", "openid".to_owned()),
            ("state", state.clone()),
            ("nonce", nonce.clone()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".to_owned()),
        ];
        if let Some(acr) = request.acr {
            params.push(("acr_values", acr.acr_value().to_owned()));
        }
        if let Some(max_age) = request.max_age {
            params.push(("max_age", max_age.as_secs().to_string()));
        }
        let url = reqwest::Url::parse_with_params(&discovery.authorization_endpoint, &params)
            .map_err(|e| EntryError::Issuer(format!("authorization endpoint: {e}")))?;
        let browser = BrowserSecret::generate();
        let deadline = Utc::now()
            + chrono::Duration::from_std(PENDING_TTL).expect("the pending lifetime fits");
        self.pending
            .insert_until(
                &self.key(&state, &browser),
                &Progress::Pending(Pending {
                    issuer: self.trusted.issuer.clone(),
                    client_id: self.trusted.client_id.clone(),
                    nonce,
                    code_verifier,
                    redirect_uri: redirect_uri.to_owned(),
                    continuation: continuation.to_owned(),
                    request: request.clone(),
                    deadline,
                }),
                deadline,
            )
            .await?;
        let lifetime = i64::try_from(PENDING_TTL.as_secs()).expect("the pending lifetime fits");
        Ok(Started {
            authorization_url: url.to_string(),
            set_cookie: self.correlation(&state).set(&browser, lifetime),
        })
    }

    /// Complete the entry `state` returned with `code` at `redirect_uri` to
    /// the browser whose `Cookie` header values are `cookies`. The entry is
    /// found only with the correlation cookie of the browser that started it
    /// (RFC 6749 §10.12, RFC 9700 §4.7.1): a return reaching another browser
    /// finds nothing and leaves the entry for its own.
    ///
    /// The entry's progress is kept until its deadline, so a retry of the
    /// same return resumes where the last attempt stopped (the recoverable
    /// federation callback completion contract): before the code is sent it
    /// exchanges again; once the token response or the validated evidence is
    /// kept it continues from that without another exchange; after an
    /// attempt that may have spent the code without a kept answer it is
    /// [`EntryError::Ambiguous`], never a second redemption. Concurrent
    /// returns exchange at most once: one meeting a live exchange is
    /// [`EntryError::InProgress`] and its retry completes the same entry.
    pub async fn complete<'a>(
        &self,
        state: &str,
        cookies: impl IntoIterator<Item = &'a str>,
        code: &str,
        redirect_uri: &str,
    ) -> Result<Returned, EntryError> {
        let browser = self
            .correlation(state)
            .secret(cookies)
            .ok_or(EntryError::OtherBrowser)?;
        let key = self.key(state, &browser);
        let operation = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(key.as_bytes()))
        };
        // Every step moves the progress forward by one compare-and-set; a
        // step lost to a concurrent return reads the progress again. The
        // bound is the longest chain of steps, so a lost race never loops.
        for _ in 0..5 {
            let read = self
                .pending
                .read_versioned(&key)
                .await?
                .ok_or(EntryError::Unknown)?;
            // Every step is bound to the entry's issuer, client and redirect
            // URI, a resumed one too: kept progress does not lift the binding.
            let bound = match &read.value {
                Progress::Pending(pending)
                | Progress::Exchanging { pending, .. }
                | Progress::Received { pending, .. }
                | Progress::Exchanged { pending, .. } => Some(pending),
                Progress::Ambiguous { .. } => None,
            };
            if let Some(pending) = bound {
                if pending.issuer != self.trusted.issuer
                    || pending.client_id != self.trusted.client_id
                {
                    return Err(EntryError::Unknown);
                }
                if pending.redirect_uri != redirect_uri {
                    // A return to another redirect URI ends an unexchanged
                    // entry; an exchanged one keeps what its own return needs.
                    if matches!(read.value, Progress::Pending(_)) {
                        self.pending.take(&key).await?;
                    }
                    return Err(EntryError::RedirectMismatch);
                }
            }
            match &read.value {
                Progress::Pending(pending) => {
                    let discovery = discover(&self.http, &self.trusted.issuer)
                        .await
                        .map_err(|e| EntryError::Issuer(e.to_string()))?;
                    let pending = pending.clone();
                    let owned = Progress::Exchanging {
                        pending: pending.clone(),
                        owned_until: Utc::now()
                            + chrono::Duration::from_std(EXCHANGE_LEASE)
                                .expect("the exchange lease fits"),
                    };
                    // The version this return stored is the one it owns:
                    // a state another return stores later is never adopted.
                    let Some(owned) = self
                        .pending
                        .replace(&key, &read, &owned, pending.deadline)
                        .await?
                    else {
                        continue;
                    };
                    let next = match self
                        .exchange(&discovery.token_endpoint, code, &pending)
                        .await
                    {
                        Exchange::Answered(id_token) => Progress::Received {
                            pending: pending.clone(),
                            id_token,
                        },
                        // The request never left: the code is unspent.
                        Exchange::NotSent(reason) => {
                            self.pending
                                .replace(
                                    &key,
                                    &owned,
                                    &Progress::Pending(pending.clone()),
                                    pending.deadline,
                                )
                                .await?;
                            return Err(EntryError::Issuer(reason));
                        }
                        Exchange::Refused(e) => {
                            self.pending.take(&key).await?;
                            return Err(e);
                        }
                        Exchange::Unknown => {
                            let continuation = pending.continuation.clone();
                            self.pending
                                .replace(
                                    &key,
                                    &owned,
                                    &Progress::Ambiguous {
                                        continuation: continuation.clone(),
                                    },
                                    pending.deadline,
                                )
                                .await?;
                            return Err(EntryError::Ambiguous { continuation });
                        }
                    };
                    if self
                        .pending
                        .replace(&key, &owned, &next, pending.deadline)
                        .await?
                        .is_none()
                    {
                        // Only the owning attempt moves an exchanging entry.
                        return Err(EntryError::Ambiguous {
                            continuation: pending.continuation,
                        });
                    }
                }
                // Another return owns the exchange: while its lease runs it
                // is live and this return retries; past it, it stopped with
                // the code possibly spent, which is recorded once.
                Progress::Exchanging {
                    pending,
                    owned_until,
                } => {
                    if *owned_until > Utc::now() {
                        return Err(EntryError::InProgress);
                    }
                    let continuation = pending.continuation.clone();
                    let lost = Progress::Ambiguous {
                        continuation: continuation.clone(),
                    };
                    if self
                        .pending
                        .replace(&key, &read, &lost, pending.deadline)
                        .await?
                        .is_some()
                    {
                        return Err(EntryError::Ambiguous { continuation });
                    }
                }
                Progress::Ambiguous { continuation } => {
                    return Err(EntryError::Ambiguous {
                        continuation: continuation.clone(),
                    });
                }
                Progress::Received { pending, id_token } => {
                    let pending = pending.clone();
                    let (subject, evidence) = match self.validate(id_token, &pending).await {
                        Ok(validated) => validated,
                        Err(e @ EntryError::Token(_)) => {
                            self.pending.take(&key).await?;
                            return Err(e);
                        }
                        Err(e) => return Err(e),
                    };
                    let next = Progress::Exchanged {
                        pending: pending.clone(),
                        subject,
                        evidence,
                    };
                    self.pending
                        .replace(&key, &read, &next, pending.deadline)
                        .await?;
                }
                Progress::Exchanged {
                    pending,
                    subject,
                    evidence,
                } => {
                    return Ok(Returned {
                        subject: subject.clone(),
                        evidence: evidence.clone(),
                        continuation: pending.continuation.clone(),
                        requested: pending.request.clone(),
                        operation,
                        deadline: pending.deadline,
                    });
                }
            }
        }
        // Every step lost to another return: that return owns the entry.
        Err(EntryError::Unknown)
    }

    /// The subject and evidence of `token`, the ID Token answered for
    /// `pending`, validated against the trusted issuer (OpenID Connect Core
    /// 1.0 §3.1.3.7).
    async fn validate(
        &self,
        token: &str,
        pending: &Pending,
    ) -> Result<(String, AcceptedEvidence), EntryError> {
        let discovery = discover(&self.http, &self.trusted.issuer)
            .await
            .map_err(|e| EntryError::Issuer(e.to_string()))?;
        let jwks_uri = discovery
            .jwks_uri
            .as_deref()
            .ok_or_else(|| EntryError::Issuer("no jwks_uri".into()))?;
        let keys = fetch_key_set(&self.http, jwks_uri)
            .await
            .map_err(|e| EntryError::Issuer(e.to_string()))?;
        let claims = validate_id_token(
            token,
            &keys,
            &IdTokenExpectation {
                issuer: &self.trusted.issuer,
                client_id: &self.trusted.client_id,
                nonce: &pending.nonce,
                algorithms: &discovery.id_token_signing_alg_values_supported,
                now: jsonwebtoken::get_current_timestamp(),
            },
        )
        .map_err(|e| EntryError::Token(e.to_string()))?;
        let subject = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| EntryError::Token("no subject".into()))?
            .to_owned();
        // The accepted authentication is bounded from when it happened, so an
        // ID Token that does not say when is refused, with or without max_age
        // (OpenID Connect Core 1.0 §2 makes it optional only for the issuer).
        let auth_time = claims
            .get("auth_time")
            .ok_or_else(|| EntryError::Token("no auth_time".into()))?
            .as_i64()
            .and_then(|t| Utc.timestamp_opt(t, 0).single())
            .ok_or_else(|| EntryError::Token("a malformed auth_time".into()))?;
        let amr = claims
            .get("amr")
            .and_then(serde_json::Value::as_array)
            .map(|methods| {
                methods
                    .iter()
                    .filter_map(|m| m.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let evidence = AcceptedEvidence::new(
            claims.get("acr").and_then(serde_json::Value::as_str),
            amr,
            auth_time,
        );
        Ok((subject, evidence))
    }

    /// The store key of `state` started in the browser holding `browser`:
    /// partitioned by this relying party's issuer and client, so relying
    /// parties of other issuers sharing the store neither find nor consume
    /// its entries (the mix-up attack class, RFC 9207 §1), and by the
    /// browser's secret hash, so a return to another browser takes nothing.
    fn key(&self, state: &str, browser: &BrowserSecret) -> String {
        use sha2::{Digest, Sha256};
        let mut partition = Sha256::new();
        partition.update(self.trusted.issuer.as_bytes());
        partition.update([0]);
        partition.update(self.trusted.client_id.as_bytes());
        format!(
            "{}:{state}:{}",
            hex::encode(partition.finalize()),
            hex::encode(browser.hash().as_bytes())
        )
    }

    /// Exchange `code` at `token_endpoint` (RFC 6749 §4.1.3, RFC 7636 §4.5),
    /// telling apart a request that never left, a refusal the issuer stated,
    /// an answer, and anything after which the code may be spent unseen.
    async fn exchange(&self, token_endpoint: &str, code: &str, pending: &Pending) -> Exchange {
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: Option<String>,
        }
        let sent = self
            .http
            .post(token_endpoint)
            .basic_auth(
                form_encode(&self.trusted.client_id),
                Some(form_encode(self.trusted.client_secret.expose_secret())),
            )
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", pending.redirect_uri.as_str()),
                ("code_verifier", pending.code_verifier.as_str()),
            ])
            .timeout(EXCHANGE_TIMEOUT)
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            // No connection was made: nothing reached the issuer.
            Err(e) if e.is_connect() => return Exchange::NotSent(format!("token request: {e}")),
            Err(_) => return Exchange::Unknown,
        };
        let status = response.status();
        // A client error is the issuer's statement that it took nothing for
        // this code (RFC 6749 §5.2); a server error says nothing about it.
        if status.is_client_error() {
            return Exchange::Refused(EntryError::Issuer(format!(
                "the token endpoint answered {status}"
            )));
        }
        if !status.is_success() {
            return Exchange::Unknown;
        }
        match response.json::<TokenResponse>().await {
            Ok(TokenResponse {
                id_token: Some(id_token),
            }) => Exchange::Answered(id_token),
            Ok(TokenResponse { id_token: None }) => Exchange::Refused(EntryError::Token(
                "the token response carries no ID Token".into(),
            )),
            Err(_) => Exchange::Unknown,
        }
    }
}

/// What came of one exchange attempt.
enum Exchange {
    /// The token response's ID Token.
    Answered(String),
    /// The request never reached the issuer; the code is unspent.
    NotSent(String),
    /// The issuer refused the code; the entry is over.
    Refused(EntryError),
    /// The code may have been spent without a usable answer.
    Unknown,
}

/// `value` form-urlencoded, as `client_secret_basic` encodes the client id
/// and secret before Basic encoding (RFC 6749 §2.3.1).
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests;
