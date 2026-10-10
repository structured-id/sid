// SPDX-License-Identifier: AGPL-3.0-only
//! Ristretto255 OPAQUE provider (RFC 9807 standard suite).
//!
//! Uses `DefaultCipherSuite`: Ristretto255 + TripleDH + Argon2.
//! Not FIPS-validated. Suitable for all non-regulated deployments.

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

/// Default cipher suite: Ristretto255 + TripleDH + Argon2.
#[derive(Debug, Clone, Copy)]
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = sid_opaque_ke::Ristretto255;
    type KeyExchange =
        sid_opaque_ke::key_exchange::tripledh::TripleDh<sid_opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

/// Ristretto255 OPAQUE provider.
///
/// Implements [`OpaqueOperations`] for the RFC 9807 standard cipher suite.
/// Uses Argon2 KSF. 128-bit security. Not FIPS-validated.
pub struct RistrettoOpaque;

impl RistrettoOpaque {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RistrettoOpaque {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueOperations for RistrettoOpaque {
    fn curve_id(&self) -> CurveId {
        CurveId::Ristretto255
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
                ServerSetup::<DefaultCipherSuite>::new(&mut rng)
            }
            None => ServerSetup::<DefaultCipherSuite>::new(&mut UnwrapErr(SysRng)),
        };
        Ok(OpaqueSetupHandle(setup.serialize().to_vec()))
    }

    fn setup_from_bytes(&self, bytes: &[u8]) -> Result<OpaqueSetupHandle, OpaqueError> {
        // Validate by deserializing, then wrap
        ServerSetup::<DefaultCipherSuite>::deserialize(bytes)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        Ok(OpaqueSetupHandle(bytes.to_vec()))
    }

    fn registration_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = RegistrationRequest::<DefaultCipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result =
            ServerRegistration::<DefaultCipherSuite>::start(&server_setup, request, credential_id)
                .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        // OPAQUE registration has no server-side state between start and finish
        Ok((result.message.serialize().to_vec(), vec![]))
    }

    fn registration_finish(&self, upload_bytes: &[u8]) -> Result<StoredCredential, OpaqueError> {
        let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(upload_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(upload);

        Ok(StoredCredential {
            curve: CurveId::Ristretto255,
            data: password_file.serialize().to_vec(),
        })
    }

    fn login_start(
        &self,
        setup: &OpaqueSetupHandle,
        credential: &StoredCredential,
        request_bytes: &[u8],
        credential_id: &[u8],
        context: &[u8],
    ) -> Result<(Vec<u8>, LoginState), OpaqueError> {
        if credential.curve != CurveId::Ristretto255 {
            return Err(OpaqueError::CurveMismatch {
                expected: CurveId::Ristretto255,
                actual: credential.curve,
            });
        }

        let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = CredentialRequest::<DefaultCipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&credential.data)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result = ServerLogin::<DefaultCipherSuite>::start(
            &mut UnwrapErr(SysRng),
            &server_setup,
            Some(password_file),
            request,
            credential_id,
            ServerLoginParameters {
                context: Some(context),
                ..ServerLoginParameters::default()
            },
        )
        .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        // Prepend CurveId byte for dispatch in login_finish
        let state_bytes = result.state.serialize().to_vec();
        let mut login_state = Vec::with_capacity(1 + state_bytes.len());
        login_state.push(CurveId::Ristretto255 as u8);
        login_state.extend_from_slice(&state_bytes);

        Ok((result.message.serialize().to_vec(), LoginState(login_state)))
    }

    fn fake_login_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<Vec<u8>, OpaqueError> {
        let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        let request = CredentialRequest::<DefaultCipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;
        let result = ServerLogin::<DefaultCipherSuite>::start(
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
        context: &[u8],
    ) -> Result<SessionKey, OpaqueError> {
        if state.0.is_empty() {
            return Err(OpaqueError::Deserialization(
                "empty login state".to_string(),
            ));
        }

        // Skip CurveId prefix byte
        let state_bytes = &state.0[1..];

        let server_login = ServerLogin::<DefaultCipherSuite>::deserialize(state_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let finalization =
            CredentialFinalization::<DefaultCipherSuite>::deserialize(finalization_bytes)
                .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result = server_login
            .finish(
                finalization,
                ServerLoginParameters {
                    context: Some(context),
                    ..ServerLoginParameters::default()
                },
            )
            .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok(SessionKey::new(result.session_key.to_vec()))
    }
}

#[cfg(test)]
mod tests;
