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
mod tests {
    use super::*;
    use crate::opaque::{P256Opaque, P384Opaque, P521Opaque, PallasOpaque, RistrettoOpaque};

    fn build_ristretto_router() -> OpaqueRouter {
        let primary = Box::new(RistrettoOpaque::new());
        let setup = primary.create_setup(None).unwrap();
        let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
        verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
        verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
        verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
        verifiers.insert(CurveId::P384, Box::new(P384Opaque::new()));
        verifiers.insert(CurveId::P521, Box::new(P521Opaque::new()));
        OpaqueRouter::new(primary, verifiers, setup)
    }

    fn build_pallas_router() -> OpaqueRouter {
        let primary = Box::new(PallasOpaque::new());
        let setup = primary.create_setup(None).unwrap();
        let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
        verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
        verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
        verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
        verifiers.insert(CurveId::P384, Box::new(P384Opaque::new()));
        verifiers.insert(CurveId::P521, Box::new(P521Opaque::new()));
        OpaqueRouter::new(primary, verifiers, setup)
    }

    #[test]
    fn test_primary_curve() {
        let router = build_ristretto_router();
        assert_eq!(router.primary_curve(), CurveId::Ristretto255);

        let router = build_pallas_router();
        assert_eq!(router.primary_curve(), CurveId::Pallas);
    }

    #[test]
    fn test_supports_curve() {
        let router = build_ristretto_router();
        assert!(router.supports_curve(CurveId::Ristretto255));
        assert!(router.supports_curve(CurveId::Pallas));
        assert!(router.supports_curve(CurveId::P256));
        assert!(router.supports_curve(CurveId::P384));
        assert!(router.supports_curve(CurveId::P521));
    }

    #[test]
    fn test_supported_curves() {
        let router = build_ristretto_router();
        let curves = router.supported_curves();
        assert!(curves.contains(&CurveId::Ristretto255));
        assert!(curves.contains(&CurveId::Pallas));
        assert!(curves.contains(&CurveId::P256));
        assert!(curves.contains(&CurveId::P384));
        assert!(curves.contains(&CurveId::P521));
        assert_eq!(curves.len(), 5);
    }

    #[test]
    fn test_full_flow_via_router() {
        use crate::opaque::ristretto::DefaultCipherSuite;
        use opaque_ke::{
            ClientLogin, ClientLoginFinishParameters, ClientRegistration,
            ClientRegistrationFinishParameters, rand::rngs::OsRng,
        };

        let router = build_ristretto_router();
        let credential_id = b"bob@sid.example.com";
        let password = b"hunter2-but-longer";

        // --- Registration via router ---
        let mut rng = OsRng;
        let client_reg_start =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let client_reg_request = client_reg_start.message.serialize().to_vec();

        let (server_reg_response, _) = router
            .registration_start(&client_reg_request, credential_id)
            .unwrap();

        let server_reg_msg = opaque_ke::RegistrationResponse::<DefaultCipherSuite>::deserialize(
            &server_reg_response,
        )
        .unwrap();
        let client_reg_finish = client_reg_start
            .state
            .finish(
                &mut rng,
                password,
                server_reg_msg,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let upload_bytes = client_reg_finish.message.serialize().to_vec();

        let stored = router.registration_finish(&upload_bytes).unwrap();
        assert_eq!(stored.curve, CurveId::Ristretto255);

        // --- Login via router ---
        let client_login_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let client_login_request = client_login_start.message.serialize().to_vec();

        let (server_login_response, login_state) = router
            .login_start(&stored, &client_login_request, credential_id)
            .unwrap();

        let server_login_msg = opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(
            &server_login_response,
        )
        .unwrap();
        let client_login_finish = client_login_start
            .state
            .finish(
                &mut OsRng,
                password,
                server_login_msg,
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        let finalization_bytes = client_login_finish.message.serialize().to_vec();

        let session_key = router
            .login_finish(&login_state, &finalization_bytes)
            .unwrap();
        assert_eq!(
            session_key.expose_secret(),
            &client_login_finish.session_key[..]
        );
    }

    #[test]
    fn test_unsupported_curve_rejected() {
        // Build a router with only Ristretto255 — P384 should be unsupported
        let primary = Box::new(RistrettoOpaque::new());
        let setup = primary.create_setup(None).unwrap();
        let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
        verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
        let router = OpaqueRouter::new(primary, verifiers, setup);

        let cred = StoredCredential {
            curve: CurveId::P384,
            data: vec![0; 64],
        };
        let result = router.login_start(&cred, b"request", b"id");
        assert!(matches!(result, Err(OpaqueError::UnsupportedCurve(_))));
    }

    #[test]
    fn test_empty_login_state_rejected() {
        let router = build_ristretto_router();
        let result = router.login_finish(&LoginState(vec![]), b"finalization");
        assert!(matches!(result, Err(OpaqueError::Deserialization(_))));
    }

    #[test]
    fn test_invalid_curve_byte_rejected() {
        let router = build_ristretto_router();
        let result = router.login_finish(&LoginState(vec![255, 0, 1, 2]), b"finalization");
        assert!(matches!(result, Err(OpaqueError::Deserialization(_))));
    }

    #[test]
    fn test_fake_login_start_returns_response() {
        use crate::opaque::ristretto::DefaultCipherSuite;
        use opaque_ke::{ClientLogin, rand::rngs::OsRng};

        let router = build_ristretto_router();
        let password = b"doesnt-matter-password";
        let fake_credential_id = b"nonexistent@sid.example.com";

        // Generate a real client login request
        let mut rng = OsRng;
        let client_login_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let client_request = client_login_start.message.serialize().to_vec();

        // Fake login should produce a response (not error)
        let response = router
            .fake_login_start(&client_request, fake_credential_id)
            .unwrap();
        assert!(!response.is_empty());

        // Response should be deserializable as a CredentialResponse
        let parsed = opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&response);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_fake_login_client_cannot_finish() {
        use crate::opaque::ristretto::DefaultCipherSuite;
        use opaque_ke::{ClientLogin, ClientLoginFinishParameters, rand::rngs::OsRng};

        let router = build_ristretto_router();
        let password = b"any-password";
        let fake_credential_id = b"nonexistent@sid.example.com";

        let mut rng = OsRng;
        let client_login_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let client_request = client_login_start.message.serialize().to_vec();

        let response = router
            .fake_login_start(&client_request, fake_credential_id)
            .unwrap();

        // Client should fail to finish login with fake response
        let server_msg =
            opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&response).unwrap();
        let result = client_login_start.state.finish(
            &mut OsRng,
            password,
            server_msg,
            ClientLoginFinishParameters::default(),
        );
        assert!(result.is_err());
    }
}
