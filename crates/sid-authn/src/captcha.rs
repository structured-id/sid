// SPDX-License-Identifier: AGPL-3.0-only
//! CAPTCHA providers for anomaly detection RequireCaptcha reaction.
//!
//! SID supports multiple CAPTCHA providers:
//! - **SID PoW** — stateless SHA-256 proof-of-work (zero third-party, air-gapped safe)
//! - **hCaptcha** — privacy-respecting third-party (free tier)
//! - **Cloudflare Turnstile** — invisible managed challenge (free)

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use sid_keys::KeyManager;
use sid_plugin::cache::CacheBackend;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::challenge_store::{ChallengeStore, ChallengeStoreError};

type HmacSha256 = Hmac<Sha256>;

/// Result of CAPTCHA verification.
#[derive(Debug, Clone)]
pub struct CaptchaVerification {
    pub success: bool,
    pub provider: String,
}

/// Errors from CAPTCHA operations.
#[derive(Debug, thiserror::Error)]
pub enum CaptchaError {
    #[error("challenge expired")]
    Expired,
    #[error("invalid challenge signature")]
    InvalidSignature,
    #[error("invalid solution: hash does not meet difficulty")]
    InvalidSolution,
    #[error("provider verification failed: {0}")]
    ProviderError(String),
    #[error("provider not configured")]
    NotConfigured,
}

/// CAPTCHA challenge sent to the client.
///
/// For SID PoW: contains prefix + difficulty for client to solve.
/// For third-party: contains site_key + provider info for widget rendering.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptchaChallenge {
    /// Challenge ID (opaque token for verification).
    pub challenge_id: String,
    /// Provider type: "sid_pow", "hcaptcha", "turnstile".
    pub provider: String,
    /// For third-party: public site key for widget.
    pub site_key: Option<String>,
    /// For SID PoW: difficulty (number of leading zero bits).
    pub difficulty: Option<u32>,
}

// ──────────────────────────────────────────────────────────────────────
// CaptchaProvider trait
// ──────────────────────────────────────────────────────────────────────

/// Trait for CAPTCHA verification providers.
///
/// SID ships with SID PoW, hCaptcha, and Turnstile.
#[async_trait::async_trait]
pub trait CaptchaProvider: Send + Sync {
    /// Provider identifier ("sid_pow", "hcaptcha", "turnstile").
    fn provider_id(&self) -> &str;

    /// Generate a new challenge for the client.
    fn create_challenge(&self) -> CaptchaChallenge;

    /// Verify a client's response to the challenge.
    async fn verify(
        &self,
        challenge_id: &str,
        token: &str,
        remote_ip: Option<&IpAddr>,
    ) -> Result<CaptchaVerification, CaptchaError>;
}

// ──────────────────────────────────────────────────────────────────────
// SID PoW Provider — stateless SHA-256 proof-of-work
// ──────────────────────────────────────────────────────────────────────

/// SID Proof-of-Work CAPTCHA provider.
///
/// Stateless: challenge is HMAC-signed, no server-side storage needed.
/// Multi-instance safe by design.
///
/// Flow:
/// 1. Server generates challenge: `{prefix, difficulty, expires, hmac}`
/// 2. Client finds nonce where `SHA256(prefix || nonce)` has N leading zero bits
/// 3. Client sends `challenge_id` (= signed challenge) + `nonce` (= solution)
/// 4. Server verifies HMAC + expiry + hash difficulty in O(1)
pub struct SidPowProvider {
    /// HMAC key for signing challenges, shared by every replica.
    secret: [u8; 32],
    /// Number of leading zero bits required (default 18 ≈ 200ms).
    difficulty: u32,
    /// Challenge validity duration in seconds.
    ttl_secs: u64,
}

impl SidPowProvider {
    pub fn new(secret: [u8; 32], difficulty: u32, ttl_secs: u64) -> Self {
        Self {
            secret,
            difficulty,
            ttl_secs,
        }
    }

    /// Create challenge token: `{prefix}:{difficulty}:{expires}:{hmac_hex}`
    fn make_challenge_token(&self) -> String {
        let prefix: [u8; 16] = rand::random();
        let prefix_hex = hex::encode(prefix);
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.ttl_secs;

        let payload = format!("{}:{}:{}", prefix_hex, self.difficulty, expires);

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        format!("{}:{}", payload, sig)
    }

    /// Parse and verify a challenge token. Returns (prefix_hex, difficulty, expires).
    fn parse_challenge_token(
        &self,
        challenge_id: &str,
    ) -> Result<(String, u32, u64), CaptchaError> {
        let parts: Vec<&str> = challenge_id.split(':').collect();
        if parts.len() != 4 {
            return Err(CaptchaError::InvalidSignature);
        }

        let prefix_hex = parts[0];
        let difficulty: u32 = parts[1]
            .parse()
            .map_err(|_| CaptchaError::InvalidSignature)?;
        let expires: u64 = parts[2]
            .parse()
            .map_err(|_| CaptchaError::InvalidSignature)?;
        let sig_hex = parts[3];

        // Verify HMAC
        let payload = format!("{}:{}:{}", prefix_hex, difficulty, expires);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());

        let expected_sig = hex::encode(mac.finalize().into_bytes());
        if !constant_time_eq(sig_hex.as_bytes(), expected_sig.as_bytes()) {
            return Err(CaptchaError::InvalidSignature);
        }

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > expires {
            return Err(CaptchaError::Expired);
        }

        Ok((prefix_hex.to_string(), difficulty, expires))
    }

    /// Verify that SHA256(prefix || nonce) has `difficulty` leading zero bits.
    fn verify_pow(prefix_hex: &str, nonce: &str, difficulty: u32) -> bool {
        let input = format!("{}{}", prefix_hex, nonce);
        let hash = Sha256::digest(input.as_bytes());

        // Check leading zero bits
        let mut zero_bits = 0u32;
        for byte in hash.iter() {
            if *byte == 0 {
                zero_bits += 8;
            } else {
                zero_bits += byte.leading_zeros();
                break;
            }
            if zero_bits >= difficulty {
                break;
            }
        }
        zero_bits >= difficulty
    }
}

#[async_trait::async_trait]
impl CaptchaProvider for SidPowProvider {
    fn provider_id(&self) -> &str {
        "sid_pow"
    }

    fn create_challenge(&self) -> CaptchaChallenge {
        CaptchaChallenge {
            challenge_id: self.make_challenge_token(),
            provider: "sid_pow".to_string(),
            site_key: None,
            difficulty: Some(self.difficulty),
        }
    }

    async fn verify(
        &self,
        challenge_id: &str,
        token: &str, // token = the nonce found by the client
        _remote_ip: Option<&IpAddr>,
    ) -> Result<CaptchaVerification, CaptchaError> {
        let (prefix_hex, difficulty, _expires) = self.parse_challenge_token(challenge_id)?;

        if !Self::verify_pow(&prefix_hex, token, difficulty) {
            return Err(CaptchaError::InvalidSolution);
        }

        Ok(CaptchaVerification {
            success: true,
            provider: "sid_pow".to_string(),
        })
    }
}

// ──────────────────────────────────────────────────────────────────────
// hCaptcha Provider
// ──────────────────────────────────────────────────────────────────────

/// hCaptcha verification provider.
///
/// Verifies tokens via POST to https://api.hcaptcha.com/siteverify.
pub struct HcaptchaProvider {
    site_key: String,
    secret_key: String,
    http: reqwest::Client,
}

impl HcaptchaProvider {
    pub fn new(site_key: String, secret_key: String) -> Self {
        Self {
            site_key,
            secret_key,
            http: sid_plugin::client_builder()
                .build()
                .expect("HTTP client build"),
        }
    }
}

#[async_trait::async_trait]
impl CaptchaProvider for HcaptchaProvider {
    fn provider_id(&self) -> &str {
        "hcaptcha"
    }

    fn create_challenge(&self) -> CaptchaChallenge {
        CaptchaChallenge {
            challenge_id: uuid::Uuid::now_v7().to_string(),
            provider: "hcaptcha".to_string(),
            site_key: Some(self.site_key.clone()),
            difficulty: None,
        }
    }

    async fn verify(
        &self,
        _challenge_id: &str,
        token: &str,
        remote_ip: Option<&IpAddr>,
    ) -> Result<CaptchaVerification, CaptchaError> {
        let mut params = vec![
            ("response", token.to_string()),
            ("secret", self.secret_key.clone()),
            ("sitekey", self.site_key.clone()),
        ];
        if let Some(ip) = remote_ip {
            params.push(("remoteip", ip.to_string()));
        }

        let resp = self
            .http
            .post("https://api.hcaptcha.com/siteverify")
            .form(&params)
            .send()
            .await
            .map_err(|e| CaptchaError::ProviderError(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CaptchaError::ProviderError(e.to_string()))?;

        let success = body
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(CaptchaVerification {
            success,
            provider: "hcaptcha".to_string(),
        })
    }
}

// ──────────────────────────────────────────────────────────────────────
// Cloudflare Turnstile Provider
// ──────────────────────────────────────────────────────────────────────

/// Cloudflare Turnstile verification provider.
///
/// Verifies tokens via POST to https://challenges.cloudflare.com/turnstile/v0/siteverify.
pub struct TurnstileProvider {
    site_key: String,
    secret_key: String,
    http: reqwest::Client,
}

impl TurnstileProvider {
    pub fn new(site_key: String, secret_key: String) -> Self {
        Self {
            site_key,
            secret_key,
            http: sid_plugin::client_builder()
                .build()
                .expect("HTTP client build"),
        }
    }
}

#[async_trait::async_trait]
impl CaptchaProvider for TurnstileProvider {
    fn provider_id(&self) -> &str {
        "turnstile"
    }

    fn create_challenge(&self) -> CaptchaChallenge {
        CaptchaChallenge {
            challenge_id: uuid::Uuid::now_v7().to_string(),
            provider: "turnstile".to_string(),
            site_key: Some(self.site_key.clone()),
            difficulty: None,
        }
    }

    async fn verify(
        &self,
        _challenge_id: &str,
        token: &str,
        remote_ip: Option<&IpAddr>,
    ) -> Result<CaptchaVerification, CaptchaError> {
        let mut params = vec![
            ("response", token.to_string()),
            ("secret", self.secret_key.clone()),
        ];
        if let Some(ip) = remote_ip {
            params.push(("remoteip", ip.to_string()));
        }

        let resp = self
            .http
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&params)
            .send()
            .await
            .map_err(|e| CaptchaError::ProviderError(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CaptchaError::ProviderError(e.to_string()))?;

        let success = body
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(CaptchaVerification {
            success,
            provider: "turnstile".to_string(),
        })
    }
}

// ──────────────────────────────────────────────────────────────────────
// Factory: build provider from env config
// ──────────────────────────────────────────────────────────────────────

/// Build a CaptchaProvider from environment variables.
///
/// Configuration:
/// - `SID_CAPTCHA_PROVIDER` — "sid_pow" (default), "hcaptcha", "turnstile"
/// - `SID_CAPTCHA_SITE_KEY` — public key (hCaptcha/Turnstile)
/// - `SID_CAPTCHA_SECRET_KEY` — secret key (hCaptcha/Turnstile)
/// - `SID_CAPTCHA_POW_DIFFICULTY` — PoW bits (default 18)
pub fn build_captcha_provider_from_env(
    pow_key: &[u8; 32],
) -> Result<Arc<dyn CaptchaProvider>, CaptchaConfigError> {
    captcha_provider_from(|name| std::env::var(name).ok(), pow_key)
}

/// The key signing PoW challenges, shared by every replica: created by the
/// first start and stored sealed, so a challenge issued by one replica
/// verifies on any other and is never signed with a guessable key.
pub async fn load_or_create_pow_key(
    storage: &dyn sid_plugin::StorageBackend,
    keys: &dyn sid_keys::KeyManager,
) -> Result<[u8; 32], crate::instance_secret::InstanceSecretError<std::convert::Infallible>> {
    let stored = crate::instance_secret::load_or_create(
        storage,
        keys,
        sid_core::models::InstanceSecret::CaptchaKey,
        || Ok(zeroize::Zeroizing::new(rand::random::<[u8; 32]>().to_vec())),
    )
    .await?;
    stored
        .as_slice()
        .try_into()
        .map_err(|_| crate::instance_secret::InstanceSecretError::Malformed)
}

/// Why the configured CAPTCHA provider cannot be built. A provider that was
/// asked for and cannot run stops startup instead of being replaced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptchaConfigError {
    #[error("SID_CAPTCHA_PROVIDER {0:?} names no provider (sid_pow, hcaptcha, turnstile)")]
    UnknownProvider(String),
    #[error("{0} needs SID_CAPTCHA_SITE_KEY and SID_CAPTCHA_SECRET_KEY")]
    MissingKeys(&'static str),
    #[error("SID_CAPTCHA_POW_DIFFICULTY must be a number of bits from 1 to 256, got {0:?}")]
    InvalidDifficulty(String),
}

/// The CAPTCHA provider the settings read through `var` select (PoW when
/// none is named).
pub fn captcha_provider_from(
    var: impl Fn(&str) -> Option<String>,
    pow_key: &[u8; 32],
) -> Result<Arc<dyn CaptchaProvider>, CaptchaConfigError> {
    let keys = |name: &'static str| match (
        var("SID_CAPTCHA_SITE_KEY").filter(|k| !k.is_empty()),
        var("SID_CAPTCHA_SECRET_KEY").filter(|k| !k.is_empty()),
    ) {
        (Some(site), Some(secret)) => Ok((site, secret)),
        _ => Err(CaptchaConfigError::MissingKeys(name)),
    };
    match var("SID_CAPTCHA_PROVIDER").as_deref() {
        None | Some("sid_pow") => {
            let difficulty = match var("SID_CAPTCHA_POW_DIFFICULTY") {
                None => 18,
                // 0 bits asks for no work; a SHA-256 digest has 256 bits.
                Some(v) => v
                    .parse()
                    .ok()
                    .filter(|bits| (1..=256).contains(bits))
                    .ok_or(CaptchaConfigError::InvalidDifficulty(v))?,
            };
            tracing::info!(difficulty, "CAPTCHA provider: SID PoW");
            Ok(Arc::new(SidPowProvider::new(*pow_key, difficulty, 300)))
        }
        Some("hcaptcha") => {
            let (site, secret) = keys("hcaptcha")?;
            tracing::info!("CAPTCHA provider: hCaptcha");
            Ok(Arc::new(HcaptchaProvider::new(site, secret)))
        }
        Some("turnstile") => {
            let (site, secret) = keys("turnstile")?;
            tracing::info!("CAPTCHA provider: Cloudflare Turnstile");
            Ok(Arc::new(TurnstileProvider::new(site, secret)))
        }
        Some(other) => Err(CaptchaConfigError::UnknownProvider(other.to_owned())),
    }
}

use std::sync::Arc;

/// Constant-time comparison of two signatures.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ──────────────────────────────────────────────────────────────────────
// Captcha gate: who a challenge was asked of, and the pass it earns
// ──────────────────────────────────────────────────────────────────────

/// The sign-in a CAPTCHA was asked for: the profile whose credentials were
/// presented and the client address they came from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaptchaSubject {
    pub profile_id: sid_core::models::ProfileId,
    pub client_ip: Option<IpAddr>,
}

/// Binds CAPTCHA challenges and the passes they earn to one sign-in, in the
/// shared cache so any replica can answer each step.
///
/// A challenge is recorded when it is asked, solved once into a pass, and the
/// pass satisfies one CAPTCHA requirement of the same profile from the same
/// client address.
pub struct CaptchaGate {
    challenges: ChallengeStore<CaptchaSubject>,
    passes: ChallengeStore<CaptchaSubject>,
}

/// How long a solved challenge may wait for the sign-in it was asked for.
pub const CAPTCHA_PASS_TTL: Duration = Duration::from_secs(60);

/// How long a challenge may wait to be solved; the PoW challenge expires then too.
pub const CAPTCHA_CHALLENGE_TTL: Duration = Duration::from_secs(300);

impl CaptchaGate {
    pub fn new(cache: Arc<dyn CacheBackend>, keys: Arc<dyn KeyManager>) -> Self {
        Self {
            challenges: ChallengeStore::new(
                cache.clone(),
                keys.clone(),
                "captcha-challenge",
                CAPTCHA_CHALLENGE_TTL,
            ),
            passes: ChallengeStore::new(cache, keys, "captcha-pass", CAPTCHA_PASS_TTL),
        }
    }

    /// Record that `challenge_id` was asked of `subject`.
    pub async fn asked(
        &self,
        challenge_id: &str,
        subject: &CaptchaSubject,
    ) -> Result<(), ChallengeStoreError> {
        self.challenges.insert(&key_of(challenge_id), subject).await
    }

    /// Exchange a solved challenge for a pass. `None` when the challenge was
    /// never asked here or was already exchanged: a solution counts once.
    pub async fn solved(&self, challenge_id: &str) -> Result<Option<String>, ChallengeStoreError> {
        let Some(subject) = self.challenges.take(&key_of(challenge_id)).await? else {
            return Ok(None);
        };
        let pass = hex::encode(rand::random::<[u8; 32]>());
        self.passes.insert(&key_of(&pass), &subject).await?;
        Ok(Some(pass))
    }

    /// Spend `pass` for `subject`. A pass is spent even when presented for
    /// another sign-in, so a leaked one cannot be tried twice.
    pub async fn redeem(
        &self,
        pass: &str,
        subject: &CaptchaSubject,
    ) -> Result<bool, ChallengeStoreError> {
        Ok(self
            .passes
            .take(&key_of(pass))
            .await?
            .is_some_and(|earned| earned == *subject))
    }
}

/// Cache key of a client-held value: its digest, so the cache never holds
/// the bearer value itself.
fn key_of(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests;
