// SPDX-License-Identifier: AGPL-3.0-only
//! Pallas curve OPAQUE provider.
//!
//! Uses `PallasCipherSuite` from `sid-pake-core` (native Halo2 field).
//! Argon2 KSF. 128-bit security. Not FIPS-validated. CE default.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_plugin::crypto::{
    CurveId, LoginState, OpaqueError, OpaqueOperations, OpaqueSetupHandle, SessionKey,
    StoredCredential,
};

/// Pallas curve OPAQUE provider.
///
/// Implements [`OpaqueOperations`] for the Pallas cipher suite.
/// Uses Argon2 KSF. 128-bit security. Not FIPS-validated.
/// CE default — native field for Halo2 ZK proofs (ZKPP).
pub struct PallasOpaque;

impl PallasOpaque {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PallasOpaque {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueOperations for PallasOpaque {
    fn curve_id(&self) -> CurveId {
        CurveId::Pallas
    }

    fn security_bits(&self) -> u32 {
        128
    }

    fn is_fips(&self) -> bool {
        false
    }

    fn ksf_id(&self) -> &'static str {
        "argon2"
    }

    fn create_setup(&self, rng_seed: Option<&[u8]>) -> Result<OpaqueSetupHandle, OpaqueError> {
        let setup = match rng_seed {
            Some(seed) => {
                let mut rng = super::seeded_rng(seed);
                ServerSetup::<PallasCipherSuite>::new(&mut rng)
            }
            None => ServerSetup::<PallasCipherSuite>::new(&mut UnwrapErr(SysRng)),
        };
        Ok(OpaqueSetupHandle(setup.serialize().to_vec()))
    }

    fn setup_from_bytes(&self, bytes: &[u8]) -> Result<OpaqueSetupHandle, OpaqueError> {
        ServerSetup::<PallasCipherSuite>::deserialize(bytes)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        Ok(OpaqueSetupHandle(bytes.to_vec()))
    }

    fn registration_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        let server_setup = ServerSetup::<PallasCipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = RegistrationRequest::<PallasCipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result =
            ServerRegistration::<PallasCipherSuite>::start(&server_setup, request, credential_id)
                .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok((result.message.serialize().to_vec(), vec![]))
    }

    fn registration_finish(&self, upload_bytes: &[u8]) -> Result<StoredCredential, OpaqueError> {
        let upload = RegistrationUpload::<PallasCipherSuite>::deserialize(upload_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<PallasCipherSuite>::finish(upload);

        Ok(StoredCredential {
            curve: CurveId::Pallas,
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
        if credential.curve != CurveId::Pallas {
            return Err(OpaqueError::CurveMismatch {
                expected: CurveId::Pallas,
                actual: credential.curve,
            });
        }

        let server_setup = ServerSetup::<PallasCipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = CredentialRequest::<PallasCipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<PallasCipherSuite>::deserialize(&credential.data)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result = ServerLogin::<PallasCipherSuite>::start(
            &mut UnwrapErr(SysRng),
            &server_setup,
            Some(password_file),
            request,
            credential_id,
            ServerLoginParameters::default(),
        )
        .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        // Prepend CurveId byte for dispatch in login_finish
        let state_bytes = result.state.serialize().to_vec();
        let mut login_state = Vec::with_capacity(1 + state_bytes.len());
        login_state.push(CurveId::Pallas as u8);
        login_state.extend_from_slice(&state_bytes);

        Ok((result.message.serialize().to_vec(), LoginState(login_state)))
    }

    fn fake_login_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<Vec<u8>, OpaqueError> {
        let server_setup = ServerSetup::<PallasCipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        let request = CredentialRequest::<PallasCipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;
        let result = ServerLogin::<PallasCipherSuite>::start(
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

        // Skip CurveId prefix byte
        let state_bytes = &state.0[1..];

        let server_login = ServerLogin::<PallasCipherSuite>::deserialize(state_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let finalization =
            CredentialFinalization::<PallasCipherSuite>::deserialize(finalization_bytes)
                .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result = server_login
            .finish(finalization, ServerLoginParameters::default())
            .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok(SessionKey::new(result.session_key.to_vec()))
    }
}

#[cfg(test)]
mod tests;
