// SPDX-License-Identifier: AGPL-3.0-only
//! NIST P-384 OPAQUE provider (FIPS-approved curve).
//!
//! Uses `p384::NistP384` as both VOPRF and key exchange group.
//! PBKDF2-HMAC-SHA384 KSF (FIPS 800-132). 192-bit security.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
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
    type KeyExchange =
        sid_opaque_ke::key_exchange::tripledh::TripleDh<p384::NistP384, sha2::Sha384>;
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
        false // RustCrypto p384 crate — not FIPS-validated.
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
            None => ServerSetup::<P384CipherSuite>::new(&mut UnwrapErr(SysRng)),
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

        let result = ServerLogin::<P384CipherSuite>::start(
            &mut UnwrapErr(SysRng),
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
        let result = ServerLogin::<P384CipherSuite>::start(
            &mut UnwrapErr(SysRng),
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
mod tests;
