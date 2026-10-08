// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history, split along its authority boundary:
//!
//! - [`HistoryEvaluator`] holds the per-owner VOPRF keys: it prepares epochs
//!   and evaluates blinded requests. It never sees a tag or a retained entry.
//! - [`HistoryChecker`] verifies the evaluator's proofs and the tags of an
//!   accepted registration proof, runs the history KSF under a memory budget
//!   reserved before it starts, and compares with every retained entry. It
//!   never holds a key.
//!
//! A standalone CE installation runs both in one process; compromise of that
//! installation merges them. SaaS runs them as separate services.

use std::sync::Arc;
use std::time::Duration;

use ff::PrimeField;
use group::{Curve, Group, GroupEncoding};
use pasta_curves::pallas;
use rand::Rng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use sid_core::models::{
    HistoryEpoch, HistoryEpochId, HistoryEpochUse, HistoryKsf, HistorySuite, NewHistoryEpoch,
    PasswordHistory, ProfileId, WrappedHistoryKey,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::{EncryptedField, KeyManager};
use sid_pake_core::history::{self as relation, EvaluationProof, KsfParams};
use sid_pake_core::types::ZkppPublicInputs;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// Purpose of the owner-domain element.
const OWNER_DOMAIN_PURPOSE: &[u8] = b"SID-HISTORY-INPUT-v1";
/// Purpose of a comparison-domain element.
const COMPARISON_DOMAIN_PURPOSE: &[u8] = b"SID-HISTORY-TAG-v1";
/// Prefix of the key manager context an epoch key is sealed under.
const KEY_CONTEXT_PREFIX: &str = "password-history-key";

/// The most comparison domains one operation may require: the active epoch
/// and the rotated ones that still hold entries. Each is a proof slot and a
/// KSF run, so the bound caps both.
pub const MAX_HISTORY_DOMAINS: usize = 3;

/// The owner's history input domain `d`: the installation and the owner, so
/// the same password gives unrelated inputs for different owners or
/// installations. Little-endian canonical field element.
pub fn owner_domain(installation: &[u8; 16], owner: ProfileId) -> [u8; 32] {
    relation::domain_element(OWNER_DOMAIN_PURPOSE, &[installation, owner.as_bytes()]).to_repr()
}

/// The comparison-domain element `c` of an epoch: its suite, id and complete
/// KSF configuration, so tags of different epochs or KSF settings never
/// compare equal.
pub fn comparison_domain(epoch: &HistoryEpoch) -> [u8; 32] {
    let ksf = [
        epoch.ksf.memory_kib.to_le_bytes(),
        epoch.ksf.passes.to_le_bytes(),
        epoch.ksf.lanes.to_le_bytes(),
    ]
    .concat();
    relation::domain_element(
        COMPARISON_DOMAIN_PURPOSE,
        &[
            epoch.suite.as_str().as_bytes(),
            epoch.id.0.as_bytes(),
            &ksf,
            &epoch.ksf_salt,
        ],
    )
    .to_repr()
}

fn key_context(epoch: HistoryEpochId, owner: ProfileId) -> String {
    format!("{KEY_CONTEXT_PREFIX}:{}:{owner}", epoch.0)
}

fn point(bytes: &[u8; 32], what: &str) -> SidResult<pallas::Affine> {
    Option::<pallas::Affine>::from(pallas::Affine::from_bytes(bytes))
        .filter(|p| !bool::from(group::CurveAffine::is_identity(p)))
        .ok_or_else(|| SidError::Validation(format!("{what}: not a Pallas point")))
}

fn scalar(bytes: &[u8; 32], what: &str) -> SidResult<pallas::Scalar> {
    Option::from(pallas::Scalar::from_repr(*bytes))
        .ok_or_else(|| SidError::Validation(format!("{what}: not a Pallas scalar")))
}

/// One comparison domain as an operation carries it: the epoch, its public
/// key and its domain element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDomain {
    pub epoch: HistoryEpochId,
    pub public_key: [u8; 32],
    pub comparison_domain: [u8; 32],
}

impl OperationDomain {
    pub fn of(epoch: &HistoryEpoch) -> Self {
        Self {
            epoch: epoch.id,
            public_key: epoch.public_key,
            comparison_domain: comparison_domain(epoch),
        }
    }
}

/// The evaluator's answer for one domain, kept with the operation so an
/// exact retry returns it instead of evaluating again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEvaluation {
    pub evaluated: [u8; 32],
    pub challenge: [u8; 32],
    pub response: [u8; 32],
}

/// The evaluation of one operation: the blinded request and one answer per
/// required domain, in the operation's domain order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationEvaluation {
    pub blinded: [u8; 32],
    pub evaluations: Vec<DomainEvaluation>,
}

/// The VOPRF authority: prepares epoch keys and evaluates with them.
pub struct HistoryEvaluator {
    keys: Arc<dyn KeyManager>,
}

impl HistoryEvaluator {
    pub fn new(keys: Arc<dyn KeyManager>) -> Self {
        Self { keys }
    }

    /// A new active epoch for `owner`: a fresh random key, sealed, and a
    /// fresh KSF salt. Stored before the key is first used.
    pub async fn new_epoch(&self, owner: ProfileId, ksf: HistoryKsf) -> SidResult<NewHistoryEpoch> {
        let mut rng = UnwrapErr(SysRng);
        let k = <pallas::Scalar as ff::Field>::random(&mut rng);
        let public_key = (pallas::Point::generator() * k).to_affine().to_bytes();
        let mut ksf_salt = [0u8; 32];
        rng.fill_bytes(&mut ksf_salt);
        let id = HistoryEpochId::generate();
        let secret = Zeroizing::new(k.to_repr());
        let sealed = self
            .keys
            .encrypt(secret.as_ref(), &key_context(id, owner))
            .await
            .map_err(|e| SidError::Internal(format!("seal history key: {e}")))?;
        Ok(NewHistoryEpoch {
            epoch: HistoryEpoch {
                id,
                owner,
                suite: HistorySuite::PallasPoseidonV1,
                public_key,
                ksf,
                ksf_salt,
                status: HistoryEpochUse::Active,
                created_at: chrono::DateTime::from_timestamp_millis(
                    chrono::Utc::now().timestamp_millis(),
                )
                .expect("current time in range"),
            },
            key: WrappedHistoryKey(sealed.to_bytes()),
        })
    }

    /// Unseal `key` as the key of `epoch` of `owner`. A key sealed for any
    /// other epoch or owner is refused before use.
    async fn unseal(
        &self,
        epoch: HistoryEpochId,
        owner: ProfileId,
        key: &WrappedHistoryKey,
    ) -> SidResult<pallas::Scalar> {
        let field = EncryptedField::from_bytes(&key.0)
            .map_err(|e| SidError::Internal(format!("history key format: {e}")))?;
        if field.context != key_context(epoch, owner) {
            return Err(SidError::Internal(
                "history key sealed for another epoch or owner".into(),
            ));
        }
        let bytes = Zeroizing::new(
            self.keys
                .decrypt(&field)
                .await
                .map_err(|e| SidError::Internal(format!("unseal history key: {e}")))?,
        );
        let repr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SidError::Internal("history key length".into()))?;
        scalar(&repr, "history key").map_err(|_| SidError::Internal("history key value".into()))
    }

    /// Evaluate `blinded` under each `(epoch, owner, key)`, in order, with
    /// proofs bound to `context` (the operation). Every key is unsealed and
    /// checked before any evaluation; one bad key fails the whole request.
    pub async fn evaluate(
        &self,
        blinded: &[u8; 32],
        keys: &[(HistoryEpochId, ProfileId, WrappedHistoryKey)],
        context: &[u8],
    ) -> SidResult<OperationEvaluation> {
        let b = point(blinded, "blinded input")?;
        let mut scalars = Vec::with_capacity(keys.len());
        for (epoch, owner, key) in keys {
            scalars.push(self.unseal(*epoch, *owner, key).await?);
        }
        let evaluations = scalars
            .iter()
            .map(|k| {
                let (z, proof) = relation::evaluate_with_proof(*k, b, context, UnwrapErr(SysRng))
                    .ok_or_else(|| {
                    SidError::Validation("blinded input is degenerate".into())
                })?;
                Ok(DomainEvaluation {
                    evaluated: z.to_bytes(),
                    challenge: proof.c.to_repr(),
                    response: proof.s.to_repr(),
                })
            })
            .collect::<SidResult<_>>()?;
        Ok(OperationEvaluation {
            blinded: *blinded,
            evaluations,
        })
    }

    /// An evaluation under a key that exists nowhere, for a registration
    /// start that must look like any other while committing nothing.
    pub fn evaluate_decoy(
        &self,
        blinded: &[u8; 32],
        domains: usize,
        context: &[u8],
    ) -> SidResult<OperationEvaluation> {
        let b = point(blinded, "blinded input")?;
        let evaluations = (0..domains)
            .map(|_| {
                let k = <pallas::Scalar as ff::Field>::random(&mut UnwrapErr(SysRng));
                let (z, proof) = relation::evaluate_with_proof(k, b, context, UnwrapErr(SysRng))
                    .ok_or_else(|| SidError::Validation("blinded input is degenerate".into()))?;
                Ok(DomainEvaluation {
                    evaluated: z.to_bytes(),
                    challenge: proof.c.to_repr(),
                    response: proof.s.to_repr(),
                })
            })
            .collect::<SidResult<_>>()?;
        Ok(OperationEvaluation {
            blinded: *blinded,
            evaluations,
        })
    }
}

/// A public key and domain that look like a real epoch's, for a decoy
/// operation.
pub fn decoy_domain() -> OperationDomain {
    let mut rng = UnwrapErr(SysRng);
    let k = <pallas::Scalar as ff::Field>::random(&mut rng);
    let mut id = [0u8; 32];
    rng.fill_bytes(&mut id);
    OperationDomain {
        epoch: HistoryEpochId::generate(),
        public_key: (pallas::Point::generator() * k).to_affine().to_bytes(),
        comparison_domain: relation::domain_element(COMPARISON_DOMAIN_PURPOSE, &[&id]).to_repr(),
    }
}

/// Why the checker did not accept a proved password.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HistoryCheckError {
    /// The password matches a retained entry.
    #[error("password matches a retained history entry")]
    Reused,
    /// The proof's history inputs are not the operation's: another owner,
    /// domain, request or evaluation. Never the user's fault on an honest client.
    #[error("history inputs do not match the operation")]
    Mismatch,
    /// The evaluator's proof for a domain does not verify.
    #[error("history evaluation proof invalid")]
    EvaluationProof,
    /// No KSF capacity within the wait budget; retry later.
    #[error("history check capacity exhausted")]
    Busy,
    /// A required epoch's KSF parameters are unusable.
    #[error("history KSF misconfigured")]
    Ksf,
}

/// Bounds the memory the history KSF uses across concurrent checks: a check
/// reserves its epochs' KSF memory before any KSF starts, or waits up to
/// `max_wait` and then gives up. No blocking task starts without its
/// reservation, so a burst queues instead of exhausting the host.
pub struct KsfAdmission {
    permits: Arc<Semaphore>,
    budget_mib: u32,
    max_wait: Duration,
}

impl KsfAdmission {
    /// Admit at most `budget_mib` MiB of concurrent KSF memory.
    pub fn new(budget_mib: u32, max_wait: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(budget_mib as usize)),
            budget_mib,
            max_wait,
        }
    }

    /// Run the KSF over `t` for every domain in `jobs`, holding their memory.
    async fn run(
        &self,
        jobs: Vec<(Zeroizing<[u8; 32]>, [u8; 32], HistoryKsf)>,
    ) -> Result<Vec<[u8; 32]>, HistoryCheckError> {
        let mib: u32 = jobs
            .iter()
            .map(|(_, _, ksf)| ksf.memory_kib.div_ceil(1024))
            .sum();
        if mib > self.budget_mib {
            return Err(HistoryCheckError::Ksf);
        }
        let permit = tokio::time::timeout(
            self.max_wait,
            Arc::clone(&self.permits).acquire_many_owned(mib),
        )
        .await
        .map_err(|_| HistoryCheckError::Busy)?
        .map_err(|_| HistoryCheckError::Busy)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            jobs.iter()
                .map(|(t, salt, ksf)| {
                    let t = pallas::Base::from_repr(**t)
                        .into_option()
                        .ok_or(HistoryCheckError::Mismatch)?;
                    relation::ksf(
                        t,
                        salt,
                        KsfParams {
                            memory_kib: ksf.memory_kib,
                            passes: ksf.passes,
                            lanes: ksf.lanes,
                        },
                    )
                    .map_err(|_| HistoryCheckError::Ksf)
                })
                .collect()
        })
        .await
        .map_err(|_| HistoryCheckError::Busy)?
    }
}

/// What the checker compares a proof against: the operation as the server
/// prepared it, the evaluator's recorded answers, and the history snapshot
/// the operation was prepared from.
pub struct CheckRequest<'a> {
    pub owner_domain: [u8; 32],
    pub domains: &'a [OperationDomain],
    pub evaluation: &'a OperationEvaluation,
    /// The operation id the evaluator's proofs are bound to.
    pub context: &'a [u8],
    pub history: &'a PasswordHistory,
}

/// The checker's verdict on an accepted password: the entry to write under
/// the active epoch (`None` for a decoy operation's snapshot without one).
#[derive(Debug)]
pub struct CheckedPassword {
    pub new_entries: Vec<(HistoryEpochId, [u8; 32])>,
}

/// Whether a proof's history inputs are this operation's: its owner domain,
/// the blinded input the evaluator answered, and each comparison domain with
/// the evaluator's answer, in order. Compared in constant time. The server
/// holds all of these before the proof arrives, so it compares the claimed
/// inputs before the SNARK as well as the verified ones after it.
pub fn inputs_match(
    public: &ZkppPublicInputs,
    owner_domain: &[u8; 32],
    domains: &[OperationDomain],
    evaluation: &OperationEvaluation,
) -> bool {
    let eq = |a: &[u8; 32], b: &[u8; 32]| bool::from(a.ct_eq(b));
    eq(&public.owner_domain, owner_domain)
        && eq(&public.blinded, &evaluation.blinded)
        && public.domains.len() == domains.len()
        && evaluation.evaluations.len() == domains.len()
        && public
            .domains
            .iter()
            .zip(domains)
            .zip(&evaluation.evaluations)
            .all(|((proved, domain), answer)| {
                eq(&proved.comparison_domain, &domain.comparison_domain)
                    && eq(&proved.evaluated, &answer.evaluated)
            })
}

/// The history authority that sees tags and entries but no key.
pub struct HistoryChecker {
    admission: KsfAdmission,
}

impl HistoryChecker {
    pub fn new(admission: KsfAdmission) -> Self {
        Self { admission }
    }

    /// Check a verified proof's history inputs against the operation and
    /// compare each tag with every entry retained in its domain. The KSF runs
    /// once per domain; no candidate `s` survives a refusal.
    pub async fn check(
        &self,
        public: &ZkppPublicInputs,
        request: CheckRequest<'_>,
    ) -> Result<CheckedPassword, HistoryCheckError> {
        let CheckRequest {
            owner_domain,
            domains,
            evaluation,
            context,
            history,
        } = request;
        if !inputs_match(public, &owner_domain, domains, evaluation) {
            return Err(HistoryCheckError::Mismatch);
        }
        let b = point(&evaluation.blinded, "blinded").map_err(|_| HistoryCheckError::Mismatch)?;
        let mut jobs = Vec::with_capacity(domains.len());
        for ((proved, domain), answer) in public
            .domains
            .iter()
            .zip(domains)
            .zip(&evaluation.evaluations)
        {
            let pk = point(&domain.public_key, "key").map_err(|_| HistoryCheckError::Mismatch)?;
            let z =
                point(&answer.evaluated, "evaluation").map_err(|_| HistoryCheckError::Mismatch)?;
            let proof = EvaluationProof {
                c: scalar(&answer.challenge, "c")
                    .map_err(|_| HistoryCheckError::EvaluationProof)?,
                s: scalar(&answer.response, "s").map_err(|_| HistoryCheckError::EvaluationProof)?,
            };
            if !relation::verify_evaluation(pk, b, z, context, &proof) {
                return Err(HistoryCheckError::EvaluationProof);
            }
            let epoch = history.epochs.iter().find(|e| e.id == domain.epoch);
            // A new owner's first epoch is not stored yet: its KSF comes from
            // the operation's own epoch, which the caller passes as history.
            let epoch = epoch.ok_or(HistoryCheckError::Mismatch)?;
            jobs.push((
                Zeroizing::new(*proved.tag.expose()),
                epoch.ksf_salt,
                epoch.ksf,
            ));
        }
        let candidates = Zeroizing::new(self.admission.run(jobs).await?);
        let mut reused = subtle::Choice::from(0u8);
        for (domain, s) in domains.iter().zip(candidates.iter()) {
            for entry in history.entries_of(domain.epoch) {
                reused |= entry.entry.ct_eq(s);
            }
        }
        if bool::from(reused) {
            return Err(HistoryCheckError::Reused);
        }
        let active = history.active_epoch().map(|e| e.id);
        Ok(CheckedPassword {
            new_entries: domains
                .iter()
                .zip(candidates.iter())
                .filter(|(d, _)| Some(d.epoch) == active)
                .map(|(d, s)| (d.epoch, *s))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests;
