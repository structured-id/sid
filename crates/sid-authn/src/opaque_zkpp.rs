// SPDX-License-Identifier: AGPL-3.0-only
//! OPAQUE-ZKPP: Pallas OPAQUE registration with a zero-knowledge proof that
//! the password satisfies policy and yields the operation's history tags.
//!
//! Registration, password change and authorized reset install a password the
//! same way: an OPAQUE start and finish on the installation's Pallas server
//! setup, and, when the client proves, one proof bound to the operation and to
//! its OPAQUE request. What differs between
//! them is authority and who owns the credential; that lives with the caller.

use group::GroupEncoding;
use pasta_curves::pallas;
use sid_core::{Error as SidError, Result as SidResult};
use sid_opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration, ServerSetup};
use sid_plugin::crypto::CurveId;

use crate::opaque::OpaqueRouter;
use sid_pake_core::{
    binding::operation_context, pallas_opaque::PallasCipherSuite, prover::BoundProof,
    types::ZkppPublicInputs, verifier::ZkppVerifier,
};

/// Configuration for ZKPP enforcement.
#[derive(Debug, Clone)]
pub struct ZkppConfig {
    /// If true, an installation REQUIRES a valid proof; if false, a client
    /// that cannot prove installs a policy-unverified password (D018).
    pub require_proof: bool,
    /// Policy version proofs are made for.
    pub policy_version: u32,
}

impl Default for ZkppConfig {
    fn default() -> Self {
        Self {
            require_proof: true,
            policy_version: 1,
        }
    }
}

/// Server side of OPAQUE-ZKPP on the installation's own Pallas setup, the
/// one [`OpaqueRouter`] signs in with, with one verifier per supported number
/// of history comparison domains.
pub struct ZkppOpaqueServer {
    server_setup: ServerSetup<PallasCipherSuite>,
    verifiers: Vec<ZkppVerifier>,
    config: ZkppConfig,
}

impl ZkppOpaqueServer {
    /// A ZKPP server on `router`'s server setup: a password it registers
    /// signs in through `router`, on any replica and after any restart.
    /// The router's primary curve must be Pallas, the curve the proofs bind.
    /// `verifiers` are the keys for the policy version, one per domain count;
    /// their compiled policy must match that version and domain counts must
    /// be unique, also when policy-unverified setup is permitted.
    /// Without one, only unproven installations are possible, so
    /// `config.require_proof` then refuses to start.
    pub fn new(
        router: &OpaqueRouter,
        verifiers: Vec<ZkppVerifier>,
        config: ZkppConfig,
    ) -> SidResult<Self> {
        if router.primary_curve() != CurveId::Pallas {
            return Err(SidError::Internal(format!(
                "ZKPP binds Pallas OPAQUE registrations; the primary curve is {:?}",
                router.primary_curve()
            )));
        }
        if config.require_proof && verifiers.is_empty() {
            return Err(SidError::Internal(
                "ZKPP requires proofs but has no verifier".to_string(),
            ));
        }
        if !verifiers.is_empty() {
            let policy = sid_pake_core::policy::get_policy(sid_pake_core::types::PolicyVersion(
                config.policy_version,
            ))
            .ok_or_else(|| SidError::Internal("unknown ZKPP policy version".into()))?;
            for (index, verifier) in verifiers.iter().enumerate() {
                let shape = verifier.shape();
                if shape.policy != policy {
                    return Err(SidError::Internal(
                        "ZKPP verifier does not enforce the configured policy".into(),
                    ));
                }
                if verifiers[..index]
                    .iter()
                    .any(|prior| prior.shape().history_domains == shape.history_domains)
                {
                    return Err(SidError::Internal(
                        "duplicate ZKPP verifier for a history domain count".into(),
                    ));
                }
            }
        }
        let server_setup = ServerSetup::<PallasCipherSuite>::deserialize(&router.setup().0)
            .map_err(|e| SidError::Internal(format!("Pallas server setup: {e}")))?;
        Ok(Self {
            server_setup,
            verifiers,
            config,
        })
    }

    /// Get current config.
    pub fn config(&self) -> &ZkppConfig {
        &self.config
    }

    /// Whether a proof over `domains` comparison domains can be verified.
    pub fn supports_domains(&self, domains: usize) -> bool {
        self.verifiers
            .iter()
            .any(|v| v.shape().history_domains == domains)
    }

    /// Exact wire lengths fixed by the accepted verifier, before allocating
    /// or decoding client-supplied instances. The client cannot select them.
    pub fn proof_lengths(&self, domains: usize) -> SidResult<(usize, usize)> {
        let verifier = self.verifier(domains)?;
        Ok((
            verifier.proof_len(),
            sid_pake_core::circuit::instance_count(verifier.shape().history_domains),
        ))
    }

    /// OPAQUE registration start for `credential_identifier`: the response
    /// the client finishes its record from.
    pub fn opaque_start(
        &self,
        registration_request_bytes: &[u8],
        credential_identifier: &[u8],
    ) -> SidResult<Vec<u8>> {
        let request = parse_registration_request(registration_request_bytes)?;
        let started = ServerRegistration::<PallasCipherSuite>::start(
            &self.server_setup,
            request,
            credential_identifier,
        )
        .map_err(|e| SidError::AuthenticationFailed(format!("Registration start failed: {e}")))?;
        Ok(started.message.serialize().to_vec())
    }

    /// OPAQUE registration finish: the password file to store.
    pub fn opaque_finish(&self, registration_upload_bytes: &[u8]) -> SidResult<Vec<u8>> {
        let upload =
            RegistrationUpload::<PallasCipherSuite>::deserialize(registration_upload_bytes)
                .map_err(|e| {
                    SidError::AuthenticationFailed(format!("Invalid registration upload: {e}"))
                })?;
        Ok(ServerRegistration::<PallasCipherSuite>::finish(upload)
            .serialize()
            .to_vec())
    }

    /// The history inputs `proof` claims for `domains` comparison domains,
    /// after the verifier's cheap form checks and without the SNARK: for
    /// comparing with the operation before paying for [`Self::verify`].
    /// Unverified.
    pub fn claimed_inputs(
        &self,
        proof: &BoundProof,
        domains: usize,
    ) -> SidResult<ZkppPublicInputs> {
        self.verifier(domains)?
            .claimed_inputs(proof)
            .map_err(|e| SidError::AuthenticationFailed(format!("ZKPP proof refused: {e}")))
    }

    fn verifier(&self, domains: usize) -> SidResult<&ZkppVerifier> {
        self.verifiers
            .iter()
            .find(|v| v.shape().history_domains == domains)
            .ok_or_else(|| {
                SidError::AuthenticationFailed(format!(
                    "no ZKPP verifier for {domains} history domains"
                ))
            })
    }

    /// Verify `proof` for the operation `operation_id`: the SNARK under the
    /// policy key for `domains` comparison domains, and its link to the
    /// element M of the operation's own OPAQUE request, bound to both the
    /// operation and the request bytes. Returns the history inputs for the
    /// checker and the artifact that accepted the proof; policy compliance is
    /// part of the key, so a password below policy has no valid proof.
    pub fn verify(
        &self,
        proof: &BoundProof,
        operation_id: &[u8; 16],
        registration_request_bytes: &[u8],
        domains: usize,
    ) -> SidResult<VerifiedProof> {
        let verifier = self.verifier(domains)?;
        let request = parse_registration_request(registration_request_bytes)?;
        let m = request_element(&request)?;
        let context = operation_context(operation_id, registration_request_bytes);
        let inputs = verifier.verify(proof, &context, m).map_err(|e| {
            SidError::AuthenticationFailed(format!("ZKPP proof verification failed: {e}"))
        })?;
        Ok(VerifiedProof {
            inputs,
            artifact: verifier.artifact(),
        })
    }
}

/// An accepted proof: its history inputs for the checker and the identity
/// of the verifying artifact, which the password's evidence records.
#[derive(Debug)]
pub struct VerifiedProof {
    pub inputs: ZkppPublicInputs,
    pub artifact: [u8; 32],
}

fn parse_registration_request(bytes: &[u8]) -> SidResult<RegistrationRequest<PallasCipherSuite>> {
    RegistrationRequest::<PallasCipherSuite>::deserialize(bytes)
        .map_err(|e| SidError::AuthenticationFailed(format!("Invalid registration request: {}", e)))
}

/// The OPRF element M the request carries: the one a proof must be bound to.
fn request_element(request: &RegistrationRequest<PallasCipherSuite>) -> SidResult<pallas::Affine> {
    let invalid = || SidError::AuthenticationFailed("Invalid registration element".to_string());
    let bytes: [u8; 32] = request
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| invalid())?;
    Option::from(pallas::Affine::from_bytes(&bytes)).ok_or_else(invalid)
}

#[cfg(test)]
mod tests;
