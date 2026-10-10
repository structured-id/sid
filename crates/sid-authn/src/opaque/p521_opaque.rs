// SPDX-License-Identifier: AGPL-3.0-only
//! NIST P-521 OPAQUE provider (FIPS-approved curve).
//!
//! Uses `p521::NistP521` as both VOPRF and key exchange group.
//! PBKDF2-HMAC-SHA512 KSF (FIPS 800-132). 256-bit security.

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

use super::pbkdf2_ksf::Pbkdf2HmacSha512;

/// P-521 cipher suite: NistP521 + TripleDH + PBKDF2-HMAC-SHA512.
#[derive(Debug, Clone, Copy)]
pub struct P521CipherSuite;

impl CipherSuite for P521CipherSuite {
    type OprfCs = p521::NistP521;
    type KeyExchange =
        sid_opaque_ke::key_exchange::tripledh::TripleDh<p521::NistP521, sha2::Sha512>;
    type Ksf = Pbkdf2HmacSha512;
}

/// NIST P-521 OPAQUE provider.
///
/// Implements [`OpaqueOperations`] for the NIST P-521 curve.
/// PBKDF2-HMAC-SHA512 KSF. 256-bit security. FIPS-approved curve.
pub struct P521Opaque;

impl P521Opaque {
    /// CE constructor: P-521 via RustCrypto `p521` crate.
    /// Not FIPS-validated, but pure Rust with no C dependencies.
    pub fn with_rustcrypto() -> Self {
        Self
    }

    /// Alias for `with_rustcrypto()`.
    pub fn new() -> Self {
        Self::with_rustcrypto()
    }
}

impl Default for P521Opaque {
    fn default() -> Self {
        Self::with_rustcrypto()
    }
}

impl OpaqueOperations for P521Opaque {
    fn curve_id(&self) -> CurveId {
        CurveId::P521
    }

    fn security_bits(&self) -> u32 {
        256
    }

    fn is_fips(&self) -> bool {
        false // RustCrypto p521 crate — not FIPS-validated.
    }

    fn ksf_id(&self) -> &'static str {
        "pbkdf2-hmac-sha512"
    }

    fn create_setup(&self, rng_seed: Option<&[u8]>) -> Result<OpaqueSetupHandle, OpaqueError> {
        let setup = match rng_seed {
            Some(seed) => {
                let mut rng = super::seeded_rng(seed);
                ServerSetup::<P521CipherSuite>::new(&mut rng)
            }
            None => ServerSetup::<P521CipherSuite>::new(&mut UnwrapErr(SysRng)),
        };
        Ok(OpaqueSetupHandle(setup.serialize().to_vec()))
    }

    fn setup_from_bytes(&self, bytes: &[u8]) -> Result<OpaqueSetupHandle, OpaqueError> {
        ServerSetup::<P521CipherSuite>::deserialize(bytes)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        Ok(OpaqueSetupHandle(bytes.to_vec()))
    }

    fn registration_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        let server_setup = ServerSetup::<P521CipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = RegistrationRequest::<P521CipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result =
            ServerRegistration::<P521CipherSuite>::start(&server_setup, request, credential_id)
                .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok((result.message.serialize().to_vec(), vec![]))
    }

    fn registration_finish(&self, upload_bytes: &[u8]) -> Result<StoredCredential, OpaqueError> {
        let upload = RegistrationUpload::<P521CipherSuite>::deserialize(upload_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<P521CipherSuite>::finish(upload);

        Ok(StoredCredential {
            curve: CurveId::P521,
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
        if credential.curve != CurveId::P521 {
            return Err(OpaqueError::CurveMismatch {
                expected: CurveId::P521,
                actual: credential.curve,
            });
        }

        let server_setup = ServerSetup::<P521CipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;

        let request = CredentialRequest::<P521CipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let password_file = ServerRegistration::<P521CipherSuite>::deserialize(&credential.data)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let result = ServerLogin::<P521CipherSuite>::start(
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

        let state_bytes = result.state.serialize().to_vec();
        let mut login_state = Vec::with_capacity(1 + state_bytes.len());
        login_state.push(CurveId::P521 as u8);
        login_state.extend_from_slice(&state_bytes);

        Ok((result.message.serialize().to_vec(), LoginState(login_state)))
    }

    fn fake_login_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<Vec<u8>, OpaqueError> {
        let server_setup = ServerSetup::<P521CipherSuite>::deserialize(&setup.0)
            .map_err(|e| OpaqueError::InvalidSetup(e.to_string()))?;
        let request = CredentialRequest::<P521CipherSuite>::deserialize(request_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;
        let result = ServerLogin::<P521CipherSuite>::start(
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

        let state_bytes = &state.0[1..];

        let server_login = ServerLogin::<P521CipherSuite>::deserialize(state_bytes)
            .map_err(|e| OpaqueError::Deserialization(e.to_string()))?;

        let finalization =
            CredentialFinalization::<P521CipherSuite>::deserialize(finalization_bytes)
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
