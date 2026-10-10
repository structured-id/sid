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
    HistoryEpochDescriptor, HistoryEpochId, HistoryEpochUse, HistoryKsf, HistorySuite, KeyEpoch,
    NewKeyEpoch, PasswordHistory, ProfileId, WrappedHistoryKey, history_key_context,
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

/// The owner's history input domain `d`: the installation and the owner, so
/// the same password gives unrelated inputs for different owners or
/// installations. Little-endian canonical field element.
pub fn owner_domain(installation: &[u8; 16], owner: ProfileId) -> [u8; 32] {
    relation::domain_element(OWNER_DOMAIN_PURPOSE, &[installation, owner.as_bytes()]).to_repr()
}

/// The comparison-domain element `c` of an epoch: its suite, id and complete
/// KSF configuration, so tags of different epochs or KSF settings never
/// compare equal.
pub fn comparison_domain(epoch: &HistoryEpochDescriptor) -> [u8; 32] {
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

/// When an owner's active epoch must be replaced before it takes another
/// entry: new epochs follow the current suite and KSF, and an operator may
/// set a cutoff (a suspected key compromise) before which every epoch is
/// replaced. A replaced epoch stays comparable while it retains entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochPolicy {
    pub ksf: HistoryKsf,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
}

impl EpochPolicy {
    /// Whether the write cutoff still permits new entries under `epoch`. A
    /// replaced epoch that passes may still be written by an operation that
    /// selected it; one created before the cutoff may not, whatever the
    /// operation's age.
    pub fn permits_writes(&self, epoch: &HistoryEpochDescriptor) -> bool {
        self.not_before
            .is_none_or(|cutoff| epoch.created_at >= cutoff)
    }

    /// Whether `epoch` may keep taking new entries.
    pub fn is_current(&self, epoch: &KeyEpoch) -> bool {
        epoch.suite == HistorySuite::PallasPoseidonV1
            && epoch.ksf == self.ksf
            && self
                .not_before
                .is_none_or(|cutoff| epoch.created_at >= cutoff)
    }
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
    pub fn of(epoch: &HistoryEpochDescriptor) -> Self {
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

    /// A new active epoch for the owner of `owner_domain`: a fresh random
    /// key, sealed for that epoch and owner, and a fresh KSF salt. Stored
    /// before the key is first used.
    pub async fn new_epoch(
        &self,
        owner_domain: [u8; 32],
        ksf: HistoryKsf,
    ) -> SidResult<NewKeyEpoch> {
        // The key's creation instant, fixed before the (asynchronous) seal so
        // a slow seal cannot move it past a write cutoff. Milliseconds,
        // truncated: earlier, never later, than the key's creation.
        let created_at =
            chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
                .expect("current time in range");
        let mut rng = UnwrapErr(SysRng);
        let k = <pallas::Scalar as ff::Field>::random(&mut rng);
        let public_key = (pallas::Point::generator() * k).to_affine().to_bytes();
        let mut ksf_salt = [0u8; 32];
        rng.fill_bytes(&mut ksf_salt);
        let id = HistoryEpochId::generate();
        let secret = Zeroizing::new(k.to_repr());
        let sealed = self
            .keys
            .encrypt(secret.as_ref(), &history_key_context(id, &owner_domain))
            .await
            .map_err(|e| SidError::Internal(format!("seal history key: {e}")))?;
        Ok(NewKeyEpoch {
            epoch: KeyEpoch {
                id,
                owner_domain,
                suite: HistorySuite::PallasPoseidonV1,
                public_key,
                ksf,
                ksf_salt,
                status: HistoryEpochUse::Active,
                created_at,
            },
            key: WrappedHistoryKey(sealed.to_bytes()),
        })
    }

    /// Unseal `key` as the key of `epoch` of the owner of `owner_domain`. A
    /// key sealed for any other epoch or owner is refused before use.
    async fn unseal(
        &self,
        epoch: HistoryEpochId,
        owner_domain: &[u8; 32],
        key: &WrappedHistoryKey,
    ) -> SidResult<pallas::Scalar> {
        let field = EncryptedField::from_bytes(&key.0)
            .map_err(|e| SidError::Internal(format!("history key format: {e}")))?;
        if field.context != history_key_context(epoch, owner_domain) {
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

    /// Evaluate `blinded` under each `(epoch, key)` of the owner of
    /// `owner_domain`, in order, with proofs bound to `context` (the
    /// operation). Every key is unsealed and checked before any evaluation;
    /// one bad key fails the whole request.
    pub async fn evaluate(
        &self,
        blinded: &[u8; 32],
        owner_domain: &[u8; 32],
        keys: &[(HistoryEpochId, WrappedHistoryKey)],
        context: &[u8],
    ) -> SidResult<OperationEvaluation> {
        let b = point(blinded, "blinded input")?;
        let mut scalars = Vec::with_capacity(keys.len());
        for (epoch, key) in keys {
            scalars.push(self.unseal(*epoch, owner_domain, key).await?);
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

    /// An evaluation under the throwaway keys of a decoy's domains (see
    /// [`decoy_epoch`]), for a registration start that must look like any
    /// other while committing nothing: each proof verifies under the public
    /// key the client was given, as a real one does.
    pub fn evaluate_decoy(
        &self,
        blinded: &[u8; 32],
        keys: &[[u8; 32]],
        context: &[u8],
    ) -> SidResult<OperationEvaluation> {
        let b = point(blinded, "blinded input")?;
        let evaluations = keys
            .iter()
            .map(|key| {
                let k = scalar(key, "decoy key")
                    .map_err(|_| SidError::Internal("decoy key value".into()))?;
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

/// An epoch description that looks like a real epoch's under `ksf`, for a
/// decoy operation, with the throwaway key the decoy is evaluated under. The
/// key belongs to no owner and protects nothing; it lives only as long as
/// the operation.
pub fn decoy_epoch(ksf: HistoryKsf) -> (HistoryEpochDescriptor, [u8; 32]) {
    let mut rng = UnwrapErr(SysRng);
    let k = <pallas::Scalar as ff::Field>::random(&mut rng);
    let mut ksf_salt = [0u8; 32];
    rng.fill_bytes(&mut ksf_salt);
    let epoch = HistoryEpochDescriptor {
        id: HistoryEpochId::generate(),
        suite: HistorySuite::PallasPoseidonV1,
        public_key: (pallas::Point::generator() * k).to_affine().to_bytes(),
        ksf,
        ksf_salt,
        created_at: chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .expect("current time in range"),
    };
    (epoch, k.to_repr())
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
    /// The memory of all domains is reserved together, so their KSFs run in
    /// parallel within it: a check takes one KSF's time, not one per domain.
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
        let permit = Arc::new(
            tokio::time::timeout(
                self.max_wait,
                Arc::clone(&self.permits).acquire_many_owned(mib),
            )
            .await
            .map_err(|_| HistoryCheckError::Busy)?
            .map_err(|_| HistoryCheckError::Busy)?,
        );
        // Each task holds the shared reservation until its own KSF ends, so
        // cancelling this future cannot release memory a KSF still uses.
        let tasks: Vec<_> = jobs
            .into_iter()
            .map(|(t, salt, ksf)| {
                let permit = Arc::clone(&permit);
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let t = pallas::Base::from_repr(*t)
                        .into_option()
                        .ok_or(HistoryCheckError::Mismatch)?;
                    relation::ksf(
                        t,
                        &salt,
                        KsfParams {
                            memory_kib: ksf.memory_kib,
                            passes: ksf.passes,
                            lanes: ksf.lanes,
                        },
                    )
                    .map_err(|_| HistoryCheckError::Ksf)
                })
            })
            .collect();
        drop(permit);
        let mut entries = Vec::with_capacity(tasks.len());
        for task in tasks {
            entries.push(task.await.map_err(|_| HistoryCheckError::Busy)??);
        }
        Ok(entries)
    }
}

/// One evaluator proof (Chaum-Pedersen DLEQ) as the client relays it with
/// the finish: the challenge and response scalars, little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayedProof {
    pub challenge: [u8; 32],
    pub response: [u8; 32],
}

/// What the checker compares a proof against: the operation as the server
/// prepared it, the evaluator's proofs the client relayed, and the history
/// snapshot the operation was prepared from.
pub struct CheckRequest<'a> {
    pub owner_domain: [u8; 32],
    pub domains: &'a [OperationDomain],
    /// The evaluator's descriptor of each domain's epoch, in the same order;
    /// the first is the epoch the accepted password's entry goes under.
    pub epochs: &'a [HistoryEpochDescriptor],
    /// One per domain, in the operation's domain order.
    pub proofs: &'a [RelayedProof],
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

/// Verify a proof's history inputs against the operation: its owner domain
/// and comparison domains (constant time, in the operation's order), and the
/// evaluator's relayed proof for each domain over the proof's own blinded
/// input B and evaluated element Z, under the domain key the server prepared
/// and bound to `context`. The client transport is untrusted: a missing,
/// extra, reordered or substituted proof, or one made for another operation,
/// fails. Cheap enough to run on the claimed inputs before the SNARK, and on
/// the verified ones after it.
pub fn verify_inputs(
    public: &ZkppPublicInputs,
    owner_domain: &[u8; 32],
    domains: &[OperationDomain],
    proofs: &[RelayedProof],
    context: &[u8],
) -> Result<(), HistoryCheckError> {
    let eq = |a: &[u8; 32], b: &[u8; 32]| bool::from(a.ct_eq(b));
    if !eq(&public.owner_domain, owner_domain)
        || public.domains.len() != domains.len()
        || proofs.len() != domains.len()
        || !public
            .domains
            .iter()
            .zip(domains)
            .all(|(proved, domain)| eq(&proved.comparison_domain, &domain.comparison_domain))
    {
        return Err(HistoryCheckError::Mismatch);
    }
    let b = point(&public.blinded, "blinded").map_err(|_| HistoryCheckError::Mismatch)?;
    for ((proved, domain), relayed) in public.domains.iter().zip(domains).zip(proofs) {
        let pk = point(&domain.public_key, "key").map_err(|_| HistoryCheckError::Mismatch)?;
        let z = point(&proved.evaluated, "evaluation").map_err(|_| HistoryCheckError::Mismatch)?;
        let proof = EvaluationProof {
            c: scalar(&relayed.challenge, "c").map_err(|_| HistoryCheckError::EvaluationProof)?,
            s: scalar(&relayed.response, "s").map_err(|_| HistoryCheckError::EvaluationProof)?,
        };
        if !relation::verify_evaluation(pk, b, z, context, &proof) {
            return Err(HistoryCheckError::EvaluationProof);
        }
    }
    Ok(())
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
            epochs,
            proofs,
            context,
            history,
        } = request;
        verify_inputs(public, &owner_domain, domains, proofs, context)?;
        // The descriptors are the operation's own: each must be the epoch of
        // its domain, so a mismatched set is refused, not compared.
        if epochs.len() != domains.len()
            || epochs
                .iter()
                .zip(domains)
                .any(|(epoch, domain)| OperationDomain::of(epoch) != *domain)
        {
            return Err(HistoryCheckError::Mismatch);
        }
        let mut jobs = Vec::with_capacity(domains.len());
        // The KSF job of each domain: the first (where the accepted entry
        // goes), and each other one that retains an entry. A domain whose
        // epoch holds nothing (retired after it was selected) has nothing to
        // compare and takes no entry, so it costs no KSF.
        let mut job_of = Vec::with_capacity(domains.len());
        for (i, (proved, epoch)) in public.domains.iter().zip(epochs).enumerate() {
            if i == 0 || history.entries_of(epoch.id).next().is_some() {
                job_of.push(Some(jobs.len()));
                jobs.push((
                    Zeroizing::new(*proved.tag.expose()),
                    epoch.ksf_salt,
                    epoch.ksf,
                ));
            } else {
                job_of.push(None);
            }
        }
        let candidates = Zeroizing::new(self.admission.run(jobs).await?);
        let candidate = |i: usize| job_of[i].map(|j| &candidates[j]);
        let mut reused = subtle::Choice::from(0u8);
        for (i, domain) in domains.iter().enumerate() {
            let Some(s) = candidate(i) else { continue };
            for entry in history.entries_of(domain.epoch) {
                reused |= entry.entry.ct_eq(s);
            }
        }
        if bool::from(reused) {
            return Err(HistoryCheckError::Reused);
        }
        // The operation's first domain is its active epoch: the accepted
        // password's one entry goes there.
        Ok(CheckedPassword {
            new_entries: candidate(0)
                .map(|s| (domains[0].epoch, *s))
                .into_iter()
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests;
