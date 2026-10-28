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

use chrono::{TimeZone, Utc};
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
#[derive(Serialize, Deserialize)]
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
/// where the caller continues and what the entry asked the issuer for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Returned {
    pub subject: String,
    pub evidence: AcceptedEvidence,
    pub continuation: String,
    pub requested: EntryRequest,
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
    #[error(transparent)]
    Store(#[from] ChallengeStoreError),
}

/// The relying party of one trusted issuer.
pub struct FederatedEntry {
    trusted: TrustedIssuer,
    http: Client,
    pending: ChallengeStore<Pending>,
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
            "{}-entry-{}",
            self.cookie.name(),
            hex::encode(&digest[..8])
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
        self.pending
            .insert(
                &self.key(&state, &browser),
                &Pending {
                    issuer: self.trusted.issuer.clone(),
                    client_id: self.trusted.client_id.clone(),
                    nonce,
                    code_verifier,
                    redirect_uri: redirect_uri.to_owned(),
                    continuation: continuation.to_owned(),
                    request: request.clone(),
                },
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
    /// finds nothing and leaves the entry for its own. The state is taken
    /// first, so a replayed return completes nothing.
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
        let pending = self
            .pending
            .take(&self.key(state, &browser))
            .await?
            .ok_or(EntryError::Unknown)?;
        if pending.issuer != self.trusted.issuer || pending.client_id != self.trusted.client_id {
            return Err(EntryError::Unknown);
        }
        if pending.redirect_uri != redirect_uri {
            return Err(EntryError::RedirectMismatch);
        }
        let discovery = discover(&self.http, &self.trusted.issuer)
            .await
            .map_err(|e| EntryError::Issuer(e.to_string()))?;
        let token = self
            .exchange(&discovery.token_endpoint, code, &pending)
            .await?;
        let jwks_uri = discovery
            .jwks_uri
            .as_deref()
            .ok_or_else(|| EntryError::Issuer("no jwks_uri".into()))?;
        let keys = fetch_key_set(&self.http, jwks_uri)
            .await
            .map_err(|e| EntryError::Issuer(e.to_string()))?;
        let claims = validate_id_token(
            &token,
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
        Ok(Returned {
            subject,
            evidence,
            continuation: pending.continuation,
            requested: pending.request,
        })
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

    /// Exchange `code` at `token_endpoint` (RFC 6749 §4.1.3, RFC 7636 §4.5):
    /// the ID Token of the response.
    async fn exchange(
        &self,
        token_endpoint: &str,
        code: &str,
        pending: &Pending,
    ) -> Result<String, EntryError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: Option<String>,
        }
        let response = self
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
            .send()
            .await
            .map_err(|e| EntryError::Issuer(format!("token request: {e}")))?;
        if !response.status().is_success() {
            return Err(EntryError::Issuer(format!(
                "the token endpoint answered {}",
                response.status()
            )));
        }
        response
            .json::<TokenResponse>()
            .await
            .map_err(|e| EntryError::Issuer(format!("token response: {e}")))?
            .id_token
            .ok_or_else(|| EntryError::Token("the token response carries no ID Token".into()))
    }
}

/// `value` form-urlencoded, as `client_secret_basic` encodes the client id
/// and secret before Basic encoding (RFC 6749 §2.3.1).
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests;
