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
use sid_keys::KeyManager;
use sid_plugin::cache::CacheBackend;

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryRequest {
    /// The assurance the issuer is asked to establish (`acr_values`, OpenID
    /// Connect Core 1.0 §3.1.2.1).
    pub acr: Option<AuthLevel>,
    /// The longest time since the holder's authentication at the issuer
    /// (`max_age`, §3.1.2.1); when asked, the ID Token must state
    /// `auth_time` (§2).
    pub max_age: Option<Duration>,
}

/// A started entry, kept until its return.
#[derive(Serialize, Deserialize)]
struct Pending {
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    /// Where the caller continues once the entry is admitted.
    continuation: String,
    /// Whether `max_age` was asked for: then `auth_time` is required.
    max_age_requested: bool,
}

/// How the issuer authenticated the subject, as its validated ID Token
/// states it. The issuer's statement, not this installation's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The `acr` claim, when it names a level this installation knows.
    pub acr: Option<AuthLevel>,
    /// The `amr` claim (RFC 8176).
    pub amr: Vec<String>,
    /// The `auth_time` claim.
    pub auth_time: Option<DateTime<Utc>>,
}

/// A returned entry: the subject the issuer signed in for this recipient,
/// its evidence and where the caller continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Returned {
    pub subject: String,
    pub evidence: Evidence,
    pub continuation: String,
}

/// Why an entry did not complete. Every case completes nothing.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// The state is unknown, expired or already taken.
    #[error("the entry is unknown, expired or already completed")]
    Unknown,
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
}

impl FederatedEntry {
    /// The relying party of `trusted`, reaching it over `http`, its pending
    /// entries in `cache` sealed under `keys`.
    pub fn new(
        trusted: TrustedIssuer,
        http: Client,
        cache: Arc<dyn CacheBackend>,
        keys: Arc<dyn KeyManager>,
    ) -> Self {
        Self {
            trusted,
            http,
            pending: ChallengeStore::new(cache, keys, NAMESPACE, PENDING_TTL),
        }
    }

    /// The trusted issuer's identifier.
    pub fn issuer(&self) -> &str {
        &self.trusted.issuer
    }

    /// Start an entry returning to `redirect_uri`, continuing at
    /// `continuation`: the authorization URL to send the browser to.
    pub async fn start(
        &self,
        redirect_uri: &str,
        continuation: &str,
        request: &EntryRequest,
    ) -> Result<String, EntryError> {
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
        self.pending
            .insert(
                &state,
                &Pending {
                    nonce,
                    code_verifier,
                    redirect_uri: redirect_uri.to_owned(),
                    continuation: continuation.to_owned(),
                    max_age_requested: request.max_age.is_some(),
                },
            )
            .await?;
        Ok(url.to_string())
    }

    /// Complete the entry `state` returned with `code` at `redirect_uri`.
    /// The state is taken first, so a replayed return completes nothing.
    pub async fn complete(
        &self,
        state: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<Returned, EntryError> {
        let pending = self.pending.take(state).await?.ok_or(EntryError::Unknown)?;
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
        let auth_time = match claims.get("auth_time") {
            None => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .and_then(|t| Utc.timestamp_opt(t, 0).single())
                    .ok_or_else(|| EntryError::Token("a malformed auth_time".into()))?,
            ),
        };
        // OpenID Connect Core 1.0 §2: a request with max_age makes auth_time
        // required.
        if pending.max_age_requested && auth_time.is_none() {
            return Err(EntryError::Token(
                "no auth_time for a max_age request".into(),
            ));
        }
        let evidence = Evidence {
            acr: claims
                .get("acr")
                .and_then(serde_json::Value::as_str)
                .and_then(AuthLevel::from_acr_value),
            amr: claims
                .get("amr")
                .and_then(serde_json::Value::as_array)
                .map(|methods| {
                    methods
                        .iter()
                        .filter_map(|m| m.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            auth_time,
        };
        Ok(Returned {
            subject,
            evidence,
            continuation: pending.continuation,
        })
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
