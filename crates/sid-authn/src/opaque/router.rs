// SPDX-License-Identifier: AGPL-3.0-only
//! OpaqueRouter — dispatches OPAQUE operations to curve-specific providers.
//!
//! Holds a **primary** provider (for new registrations) and **verifiers** for
//! all supported curves (for login and federation verification).

use std::collections::HashMap;

use sid_plugin::crypto::{
    CurveId, LoginState, OpaqueError, OpaqueOperations, OpaqueSetupHandle, SessionKey,
    StoredCredential,
};

/// Multi-curve OPAQUE router.
///
/// New registrations always use the **primary** provider (configured at startup).
/// Login dispatches to the correct provider based on the credential's stored `CurveId`.
///
/// # Setup Model
///
/// The router holds a single `OpaqueSetupHandle` for the primary curve.
pub struct OpaqueRouter {
    /// Provider for new profile registrations.
    primary: Box<dyn OpaqueOperations>,
    /// All available providers, keyed by CurveId.
    verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>>,
    /// Server setup handle (primary curve).
    setup: OpaqueSetupHandle,
}

impl OpaqueRouter {
    /// Create a new router.
    ///
    /// `primary` — used for new registrations, must match `setup`.
    /// `verifiers` — all curves supported for login/verification.
    ///   Must include the primary curve.
    /// `setup` — serialized `ServerSetup` for the primary curve.
    pub fn new(
        primary: Box<dyn OpaqueOperations>,
        verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>>,
        setup: OpaqueSetupHandle,
    ) -> Self {
        debug_assert!(
            verifiers.contains_key(&primary.curve_id()),
            "verifiers must include the primary curve"
        );
        Self {
            primary,
            verifiers,
            setup,
        }
    }

    /// Primary curve used for new registrations.
    pub fn primary_curve(&self) -> CurveId {
        self.primary.curve_id()
    }

    /// Whether the primary provider is FIPS-validated.
    pub fn is_fips(&self) -> bool {
        self.primary.is_fips()
    }

    /// Check if a curve is supported for verification.
    pub fn supports_curve(&self, curve: CurveId) -> bool {
        self.verifiers.contains_key(&curve)
    }

    /// List all supported curves.
    pub fn supported_curves(&self) -> Vec<CurveId> {
        self.verifiers.keys().copied().collect()
    }

    /// Access the server setup handle.
    pub fn setup(&self) -> &OpaqueSetupHandle {
        &self.setup
    }

    // ── Registration (always primary curve) ──

    /// Start OPAQUE registration using the primary curve.
    ///
    /// Returns `(response_bytes, state_bytes)`.
    pub fn registration_start(
        &self,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        self.primary
            .registration_start(&self.setup, request_bytes, credential_id)
    }

    /// Finish OPAQUE registration.
    ///
    /// Returns a [`StoredCredential`] with the primary curve's `CurveId`.
    pub fn registration_finish(
        &self,
        upload_bytes: &[u8],
    ) -> Result<StoredCredential, OpaqueError> {
        self.primary.registration_finish(upload_bytes)
    }

    // ── Login (dispatches by credential curve) ──

    /// Start OPAQUE login, dispatching to the correct curve provider.
    ///
    /// Returns `(response_bytes, login_state)`. The `LoginState` is prefixed
    /// with the `CurveId` byte for dispatch in [`login_finish`](Self::login_finish).
    pub fn login_start(
        &self,
        credential: &StoredCredential,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, LoginState), OpaqueError> {
        let provider = self
            .verifiers
            .get(&credential.curve)
            .ok_or(OpaqueError::UnsupportedCurve(credential.curve))?;
        provider.login_start(&self.setup, credential, request_bytes, credential_id)
    }

    /// Fake OPAQUE login start for anti-enumeration.
    ///
    /// Uses primary curve with `None` password file — produces a credential
    /// response with identical timing to a real login, but the client will
    /// fail at `login_finish`.
    pub fn fake_login_start(
        &self,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<Vec<u8>, OpaqueError> {
        self.primary
            .fake_login_start(&self.setup, request_bytes, credential_id)
    }

    /// Finish OPAQUE login, dispatching by the `CurveId` encoded in `LoginState`.
    ///
    /// Returns [`SessionKey`] on success.
    pub fn login_finish(
        &self,
        state: &LoginState,
        finalization_bytes: &[u8],
    ) -> Result<SessionKey, OpaqueError> {
        if state.0.is_empty() {
            return Err(OpaqueError::Deserialization(
                "empty login state".to_string(),
            ));
        }

        let curve_byte = state.0[0];
        let curve = CurveId::try_from(curve_byte).map_err(|_| {
            OpaqueError::Deserialization(format!("unknown curve id in login state: {}", curve_byte))
        })?;

        let provider = self
            .verifiers
            .get(&curve)
            .ok_or(OpaqueError::UnsupportedCurve(curve))?;
        provider.login_finish(state, finalization_bytes)
    }
}

#[cfg(test)]
mod tests;
