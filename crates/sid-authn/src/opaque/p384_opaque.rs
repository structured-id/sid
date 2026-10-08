// SPDX-License-Identifier: AGPL-3.0-only
//! NIST P-384 OPAQUE provider (FIPS-approved curve).
//!
//! Uses `p384::NistP384` as both VOPRF and key exchange group.
//! PBKDF2-HMAC-SHA384 KSF (FIPS 800-132). 192-bit security.

use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    rand::rngs::OsRng,
};
use sid_plugin::crypto::{
    CurveId, LoginState, OpaqueError, OpaqueOperations, OpaqueSetupHandle, SessionKey,
    StoredCredential,
};

use super::pbkdf2_ksf::Pbkdf2HmacSha384;

/// P-384 cipher suite: NistP384 + TripleDH + PBKDF2-HMAC-SHA384.
#[derive(Debug, Clone, Copy)]
pub struct P384CipherSuite;

impl CipherSuite for P384CipherSuite {
    type OprfCs = p384::NistP384;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh<p384::NistP384, sha2::Sha384>;
    type Ksf = Pbkdf2HmacSha384;
}

/// NIST P-384 OPAQUE provider.
///
/// Implements [`OpaqueOperations`] for the NIST P-384 curve.
/// PBKDF2-HMAC-SHA384 KSF. 192-bit security. FIPS-approved curve.
pub struct P384Opaque;

impl P384Opaque {
    /// CE constructor: P-384 via RustCrypto `p384` crate.
    /// Not FIPS-validated, but pure Rust with no C dependencies.
    pub fn with_rustcrypto() -> Self {
        Self
    }

    /// Alias for `with_rustcrypto()`.
    pub fn new() -> Self {
        Self::with_rustcrypto()
    }
}

impl Default for P384Opaque {
    fn default() -> Self {
        Self::with_rustcrypto()
    }
}

impl OpaqueOperations for P384Opaque {
    fn curve_id(&self) -> CurveId {
        CurveId::P384
    }

    fn security_bits(&self) -> u32 {
        192
    }

    fn is_fips(&self) -> bool {
        false // RustCrypto p384 crate — not FIPS-validated. EE uses aws-lc-rs backend.
    }

    fn ksf_id(&self) -> &'static str {
        "pbkdf2-hmac-sha384"
    }

    fn create_setup(&self, rng_seed: Option<&[u8]>) -> Result<OpaqueSetupHandle, OpaqueError> {
        let setup = match rng_seed {
            Some(seed) => {
                let mut rng = super::seeded_rng(seed);
                ServerSetup::<P384CipherSuite>::new(&mut rng)
            }
            None => {
                let mut rng = OsRng;
                ServerSetup::<P384CipherSuite>::new(&mut rng)
            }
        };
        Ok(OpaqueSetupHandle(setup.serialize().to_vec()))
    }

    fn setup_from_bytes(&self, bytes: &[u8]) -> Result<OpaqueSetupHandle, OpaqueError> {
        ServerSetup::<P384CipherSuite>::deserialize(bytes)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        Ok(OpaqueSetupHandle(bytes.to_vec()))
    }

    fn registration_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        let server_setup = ServerSetup::<P384CipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = RegistrationRequest::<P384CipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result =
            ServerRegistration::<P384CipherSuite>::start(&server_setup, request, credential_id)
                .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok((result.message.serialize().to_vec(), vec![]))
    }

    fn registration_finish(&self, upload_bytes: &[u8]) -> Result<StoredCredential, OpaqueError> {
        let upload = RegistrationUpload::<P384CipherSuite>::deserialize(upload_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<P384CipherSuite>::finish(upload);

        Ok(StoredCredential {
            curve: CurveId::P384,
            data: password_file.serialize().to_vec(),
        })
    }

    fn login_start(
        &self,
        setup: &OpaqueSetupHandle,
        credential: &StoredCredential,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, LoginState), OpaqueError> {
        if credential.curve != CurveId::P384 {
            return Err(OpaqueError::CurveMismatch {
                expected: CurveId::P384,
                actual: credential.curve,
            });
        }

        let server_setup = ServerSetup::<P384CipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = CredentialRequest::<P384CipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<P384CipherSuite>::deserialize(&credential.data)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let mut rng = OsRng;
        let result = ServerLogin::<P384CipherSuite>::start(
            &mut rng,
            &server_setup,
            Some(password_file),
            request,
            credential_id,
            ServerLoginParameters::default(),
        )
        .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        let state_bytes = result.state.serialize().to_vec();
        let mut login_state = Vec::with_capacity(1 + state_bytes.len());
        login_state.push(CurveId::P384 as u8);
        login_state.extend_from_slice(&state_bytes);

        Ok((result.message.serialize().to_vec(), LoginState(login_state)))
    }

    fn fake_login_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<Vec<u8>, OpaqueError> {
        let server_setup = ServerSetup::<P384CipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        let request = CredentialRequest::<P384CipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;
        let mut rng = OsRng;
        let result = ServerLogin::<P384CipherSuite>::start(
            &mut rng,
            &server_setup,
            None,
            request,
            credential_id,
            ServerLoginParameters::default(),
        )
        .map_err(|e| OpaqueError::Protocol(e.to_string()))?;
        Ok(result.message.serialize().to_vec())
    }

    fn login_finish(
        &self,
        state: &LoginState,
        finalization_bytes: &[u8],
    ) -> Result<SessionKey, OpaqueError> {
        if state.0.is_empty() {
            return Err(OpaqueError::Deserialization(
                "empty login state".to_string(),
            ));
        }

        let state_bytes = &state.0[1..];

        let server_login = ServerLogin::<P384CipherSuite>::deserialize(state_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let finalization =
            CredentialFinalization::<P384CipherSuite>::deserialize(finalization_bytes)
                .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result = server_login
            .finish(finalization, ServerLoginParameters::default())
            .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok(SessionKey::new(result.session_key.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> P384Opaque {
        P384Opaque::new()
    }

    #[test]
    fn test_metadata() {
        let p = provider();
        assert_eq!(p.curve_id(), CurveId::P384);
        assert_eq!(p.security_bits(), 192);
        assert!(!p.is_fips());
        assert_eq!(p.ksf_id(), "pbkdf2-hmac-sha384");
    }

    #[test]
    fn test_create_setup() {
        let p = provider();
        let setup = p.create_setup(None).unwrap();
        assert!(!setup.0.is_empty());
    }

    #[test]
    fn test_setup_roundtrip() {
        let p = provider();
        let setup1 = p.create_setup(None).unwrap();
        let setup2 = p.setup_from_bytes(&setup1.0).unwrap();
        assert_eq!(setup1.0, setup2.0);
    }

    #[test]
    fn test_setup_from_invalid_bytes() {
        let p = provider();
        assert!(p.setup_from_bytes(b"garbage").is_err());
    }

    #[test]
    fn test_full_registration_login_flow() {
        use opaque_ke::{
            ClientLogin, ClientLoginFinishParameters, ClientRegistration,
            ClientRegistrationFinishParameters,
        };

        let p = provider();
        let setup = p.create_setup(None).unwrap();
        let credential_id = b"alice@sid.example.com";
        let password = b"correct-horse-battery-staple";

        // --- Registration ---
        let mut rng = OsRng;
        let client_reg_start =
            ClientRegistration::<P384CipherSuite>::start(&mut rng, password).unwrap();
        let client_reg_request = client_reg_start.message.serialize().to_vec();

        let (server_reg_response, _state) = p
            .registration_start(&setup, &client_reg_request, credential_id)
            .unwrap();

        let server_reg_msg =
            opaque_ke::RegistrationResponse::<P384CipherSuite>::deserialize(&server_reg_response)
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

        let stored = p.registration_finish(&upload_bytes).unwrap();
        assert_eq!(stored.curve, CurveId::P384);
        assert!(!stored.data.is_empty());

        // --- Login ---
        let client_login_start = ClientLogin::<P384CipherSuite>::start(&mut rng, password).unwrap();
        let client_login_request = client_login_start.message.serialize().to_vec();

        let (server_login_response, login_state) = p
            .login_start(&setup, &stored, &client_login_request, credential_id)
            .unwrap();

        assert_eq!(login_state.0[0], CurveId::P384 as u8);

        let server_login_msg =
            opaque_ke::CredentialResponse::<P384CipherSuite>::deserialize(&server_login_response)
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

        let session_key = p.login_finish(&login_state, &finalization_bytes).unwrap();
        assert!(!session_key.expose_secret().is_empty());
        assert_eq!(
            session_key.expose_secret(),
            &client_login_finish.session_key[..]
        );
    }

    #[test]
    fn test_curve_mismatch_rejected() {
        let p = provider();
        let setup = p.create_setup(None).unwrap();
        let wrong_curve = StoredCredential {
            curve: CurveId::Ristretto255,
            data: vec![0; 64],
        };
        let result = p.login_start(&setup, &wrong_curve, b"request", b"id");
        assert!(matches!(result, Err(OpaqueError::CurveMismatch { .. })));
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<P384Opaque>();
    }

    #[test]
    fn test_object_safety() {
        let _: Box<dyn OpaqueOperations> = Box::new(P384Opaque::new());
    }
}
