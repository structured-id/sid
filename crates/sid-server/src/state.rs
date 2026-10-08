// SPDX-License-Identifier: AGPL-3.0-only
//! Application state shared across all request handlers.

use sid_authn::jwt::{AccessTokenClaims, JwtService};
use sid_authn::oauth2::OAuth2Server;
use sid_authn::opaque::OpaqueRouter;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::webauthn::WebAuthnServer;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::StorageBackend;
use std::sync::Arc;

use crate::feature_flags::FeatureFlagService;

/// Shared application state for all HTTP handlers.
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    pub oauth2: Arc<OAuth2Server>,
    pub webauthn: Arc<WebAuthnServer>,
    pub jwt: Arc<JwtService>,
    pub opaque_router: Arc<OpaqueRouter>,
    /// OPAQUE-ZKPP server (Pallas + Halo2 ZK proof verification).
    /// Starts as None during async keygen, hot-swapped to Some when ready.
    /// Enabled via `SID_ZKPP_ENABLED=true` env var.
    pub opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
    /// In-memory revocation cache for instant access token invalidation.
    pub revocation_cache: Arc<RevocationCache>,
    /// SHA-256 hash of the WebTransport certificate (if WebTransport is enabled).
    pub wt_cert_hash: Option<String>,
    /// Runtime feature flag service (polls GitLab Unleash).
    pub feature_flags: FeatureFlagService,
    /// Issuer URL (e.g., "https://sid.example.com"). Used for verification_uri in device auth.
    pub issuer: String,
    /// Prometheus metrics (available when compiled with `telemetry` feature).
    #[cfg(feature = "telemetry")]
    pub metrics: Arc<crate::metrics::SidMetrics>,
}

impl AppState {
    /// Validate an access token JWT and check the revocation cache.
    ///
    /// Returns claims if valid and not revoked.
    pub async fn validate_access_token(&self, token: &str) -> SidResult<AccessTokenClaims> {
        let claims = self.jwt.validate_access_token(token)?;
        let revoked = self
            .revocation_cache
            .is_revoked(&claims.jti, &claims.sid)
            .await
            .map_err(|e| SidError::Unavailable(format!("token revocation state: {e}")))?;
        if revoked {
            return Err(SidError::AuthenticationFailed(
                "Token has been revoked".to_string(),
            ));
        }
        Ok(claims)
    }

    /// Check maintenance mode. Returns error if active.
    pub async fn check_maintenance(&self) -> SidResult<()> {
        if self.feature_flags.is_maintenance_mode().await {
            Err(SidError::Unavailable(
                "Service is under maintenance".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Check registration enabled. Returns error if disabled.
    pub async fn check_registration_enabled(&self) -> SidResult<()> {
        if !self.feature_flags.is_registration_enabled().await {
            Err(SidError::AuthorizationDenied(
                "Registration is currently disabled".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}
