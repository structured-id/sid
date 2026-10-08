// SPDX-License-Identifier: AGPL-3.0-only
//! A protected resource's check of the access tokens presented to it: signed
//! by one issuer of this installation (`at+jwt`, RFC 9068 §4) for exactly this
//! resource. What the token's subject stands for is the resource's own
//! decision, made from this verified context.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use jsonwebtoken::decode_header;
use sid_core::models::{OidcIssuer, ResourceIndicator};
use sid_core::{Error as SidError, Result as SidResult};

use crate::issuer::{IssuerRegistry, IssuerVerifier};
use crate::jwt::AccessTokenClaims;

/// Least time between two reloads of the issuer's keys for an unknown `kid`:
/// a rotation is picked up within it, and tokens naming made-up keys cannot
/// turn every request into a storage read.
const KEY_RELOAD_INTERVAL_SECS: i64 = 30;

/// Verifies one issuer's access tokens for one resource.
pub struct ResourceTokenVerifier {
    issuers: Arc<IssuerRegistry>,
    issuer: OidcIssuer,
    indicator: ResourceIndicator,
    keys: ArcSwap<IssuerVerifier>,
    /// Unix time of the last key reload.
    reloaded_at: AtomicI64,
}

impl std::fmt::Debug for ResourceTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceTokenVerifier")
            .field("issuer", &self.issuer.canonical_url)
            .field("indicator", &self.indicator)
            .finish_non_exhaustive()
    }
}

impl ResourceTokenVerifier {
    /// A verifier of `issuer`'s tokens for the resource `indicator`, with the
    /// issuer's current keys.
    pub async fn new(
        issuers: Arc<IssuerRegistry>,
        issuer: OidcIssuer,
        indicator: ResourceIndicator,
    ) -> SidResult<Self> {
        let keys = issuers.verifier(&issuer).await?;
        Ok(Self {
            issuers,
            issuer,
            indicator,
            keys: ArcSwap::from_pointee(keys),
            reloaded_at: AtomicI64::new(chrono::Utc::now().timestamp()),
        })
    }

    /// The exact issuer identifier whose tokens this verifier accepts.
    pub fn issuer(&self) -> &str {
        &self.issuer.canonical_url
    }

    /// The resource whose tokens this verifier accepts.
    pub fn indicator(&self) -> &ResourceIndicator {
        &self.indicator
    }

    /// The id of the issuer whose tokens this verifier accepts.
    pub fn issuer_id(&self) -> sid_core::models::IssuerId {
        self.issuer.id
    }

    /// The issuer whose tokens this verifier accepts.
    pub fn oidc_issuer(&self) -> &OidcIssuer {
        &self.issuer
    }

    /// The claims of `token` when the issuer signed it for this resource and
    /// it has not expired.
    pub async fn verify(&self, token: &str) -> SidResult<AccessTokenClaims> {
        self.verify_for(token, &self.indicator).await
    }

    /// The claims of `token` when the same issuer signed it for the
    /// resource `indicator` names instead, with the keys this verifier
    /// already holds: a token presented as evidence about its subject, not
    /// as a credential here.
    pub async fn verify_for(
        &self,
        token: &str,
        indicator: &ResourceIndicator,
    ) -> SidResult<AccessTokenClaims> {
        let refused = |why: &str| SidError::AuthenticationFailed(format!("Invalid token: {why}"));
        let kid = decode_header(token)
            .map_err(|e| refused(&e.to_string()))?
            .kid
            .ok_or_else(|| refused("names no key"))?;
        if !self.keys.load().knows(&kid) {
            self.reload().await?;
        }
        self.keys
            .load()
            .validate_access_token_for(token, indicator.as_str())
    }

    /// Load the issuer's keys again, at most once per reload interval.
    async fn reload(&self) -> SidResult<()> {
        let now = chrono::Utc::now().timestamp();
        let last = self.reloaded_at.load(Ordering::Acquire);
        if now - last < KEY_RELOAD_INTERVAL_SECS {
            return Ok(());
        }
        if self
            .reloaded_at
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Another request is reloading them.
            return Ok(());
        }
        let keys = self.issuers.verifier(&self.issuer).await?;
        self.keys.store(Arc::new(keys));
        Ok(())
    }
}
