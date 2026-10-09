// SPDX-License-Identifier: AGPL-3.0-only
//! Load measurement of the password-history checker: concurrent checks with
//! a real KSF, real evaluator DLEQ proofs and a retained history, reporting
//! the latency distribution (queue wait included), refusals for lack of
//! capacity and the process's peak memory.
//!
//!   cargo run --release -p sid-authn --example history_checker_load -- \
//!     [--memory-kib 65536] [--passes 3] [--lanes 1] [--entries 1] \
//!     [--domains 1] [--concurrency 16] [--checks 64] \
//!     [--budget-mib 512] [--wait-ms 10000]
//!
//! The defaults are the server's history KSF and admission. Inputs are
//! prepared before timing: the client's proof and the evaluator are separate
//! components measured elsewhere. The candidate is never a retained password,
//! so every check runs the KSF for every domain and compares all entries.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas;
use sid_authn::password_history::{
    CheckRequest, HistoryCheckError, HistoryChecker, HistoryEvaluator, KsfAdmission,
    OperationDomain, OperationEvaluation, owner_domain,
};
use sid_core::models::{
    HistoryEntry, HistoryEpochUse, HistoryEvidence, HistoryKsf, NewHistoryEpoch, PasswordHistory,
    ProfileId,
};
use sid_pake_core::history as relation;
use sid_pake_core::types::{DomainPublicInputs, HistoryTag, ZkppPublicInputs};

const INSTALLATION: [u8; 16] = [7; 16];

struct Args {
    ksf: HistoryKsf,
    entries: usize,
    domains: usize,
    concurrency: usize,
    checks: usize,
    budget_mib: u32,
    wait: Duration,
}

fn args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str, default: u64| -> u64 {
        argv.iter()
            .position(|a| a == name)
            .map(|at| {
                argv.get(at + 1)
                    .unwrap_or_else(|| panic!("{name} needs a value"))
                    .parse()
                    .unwrap_or_else(|_| panic!("{name} must be a number"))
            })
            .unwrap_or(default)
    };
    let small = |name: &str, default: u64| -> u32 {
        u32::try_from(value(name, default)).unwrap_or_else(|_| panic!("{name} out of range"))
    };
    let count = |name: &str, default: u64| -> usize {
        usize::try_from(value(name, default)).unwrap_or_else(|_| panic!("{name} out of range"))
    };
    Args {
        ksf: HistoryKsf {
            memory_kib: small("--memory-kib", u64::from(HistoryKsf::DEFAULT.memory_kib)),
            passes: small("--passes", u64::from(HistoryKsf::DEFAULT.passes)),
            lanes: small("--lanes", u64::from(HistoryKsf::DEFAULT.lanes)),
        },
        entries: count("--entries", 1),
        domains: count("--domains", 1),
        concurrency: count("--concurrency", 16),
        checks: count("--checks", 64),
        budget_mib: small("--budget-mib", 512),
        wait: Duration::from_millis(value("--wait-ms", 10_000)),
    }
}

fn key_manager() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([3; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1; 32], "bench")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .expect("key manager"),
    )
}

/// One prepared check: the operation's domains and evaluation and the
/// client's proved inputs for a fresh password.
struct Prepared {
    domains: Vec<OperationDomain>,
    evaluation: OperationEvaluation,
    public: ZkppPublicInputs,
    context: Vec<u8>,
}

async fn prepare(
    evaluator: &HistoryEvaluator,
    owner: ProfileId,
    epochs: &[NewHistoryEpoch],
    index: usize,
) -> Prepared {
    let d = pallas::Base::from_repr(owner_domain(&INSTALLATION, owner)).unwrap();
    let password = format!("Candidate-{index}-Str0ng!");
    let u = relation::history_input(d, password.as_bytes());
    let r = relation::random_blind(rand::rng());
    let blinded = relation::blind_request(u, r).to_bytes();
    let context = format!("operation-{index}").into_bytes();
    let domains: Vec<_> = epochs
        .iter()
        .map(|e| OperationDomain::of(&e.epoch))
        .collect();
    let keys: Vec<_> = epochs
        .iter()
        .map(|e| (e.epoch.id, owner, e.key.clone()))
        .collect();
    let evaluation = evaluator
        .evaluate(&blinded, &keys, &context)
        .await
        .expect("evaluation");
    let public = ZkppPublicInputs {
        owner_domain: d.to_repr(),
        blinded: evaluation.blinded,
        domains: domains
            .iter()
            .zip(&evaluation.evaluations)
            .map(|(domain, answer)| {
                let c = pallas::Base::from_repr(domain.comparison_domain).unwrap();
                let z = pallas::Affine::from_bytes(&answer.evaluated).unwrap();
                DomainPublicInputs {
                    comparison_domain: domain.comparison_domain,
                    evaluated: answer.evaluated,
                    tag: HistoryTag::new(relation::finalize_tag(c, u, r, z).to_repr()),
                }
            })
            .collect(),
    };
    Prepared {
        domains,
        evaluation,
        public,
        context,
    }
}

/// The process's peak resident memory in MiB, where the platform reports it.
fn peak_rss_mib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let at = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[at]
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = args();
    assert!(
        (1..=sid_core::models::password_history::MAX_HISTORY_DOMAINS).contains(&args.domains),
        "--domains must be 1..={}",
        sid_core::models::password_history::MAX_HISTORY_DOMAINS
    );
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let mut epochs = Vec::with_capacity(args.domains);
    for index in 0..args.domains {
        let mut epoch = evaluator.new_epoch(owner, args.ksf).await.unwrap();
        if index > 0 {
            epoch.epoch.status = HistoryEpochUse::CompareOnly;
        }
        epochs.push(epoch);
    }
    // Retained entries spread over the domains; their values never match.
    let history = PasswordHistory {
        revision: 1,
        epochs: epochs.iter().map(|e| e.epoch.clone()).collect(),
        entries: (0..args.entries)
            .map(|i| HistoryEntry {
                epoch: epochs[i % epochs.len()].epoch.id,
                seq: i as i64 + 1,
                entry: rand::random(),
                evidence: HistoryEvidence {
                    operation: uuid::Uuid::now_v7(),
                    policy_version: 1,
                },
                created_at: chrono::Utc::now(),
            })
            .collect(),
    };
    let mut jobs = Vec::with_capacity(args.checks);
    for index in 0..args.checks {
        jobs.push(prepare(&evaluator, owner, &epochs, index).await);
    }

    let checker = Arc::new(HistoryChecker::new(KsfAdmission::new(
        args.budget_mib,
        args.wait,
    )));
    let history = Arc::new(history);
    let queue = Arc::new(std::sync::Mutex::new(jobs));
    let started = Instant::now();
    let workers: Vec<_> = (0..args.concurrency)
        .map(|_| {
            let (checker, history, queue) = (checker.clone(), history.clone(), queue.clone());
            tokio::spawn(async move {
                let mut latencies = Vec::new();
                let mut busy = 0usize;
                loop {
                    let Some(job) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let at = Instant::now();
                    let outcome = checker
                        .check(
                            &job.public,
                            CheckRequest {
                                owner_domain: job.public.owner_domain,
                                domains: &job.domains,
                                evaluation: &job.evaluation,
                                context: &job.context,
                                history: &history,
                            },
                        )
                        .await;
                    match outcome {
                        Ok(_) => latencies.push(at.elapsed()),
                        Err(HistoryCheckError::Busy) => busy += 1,
                        Err(other) => panic!("check failed: {other}"),
                    }
                }
                (latencies, busy)
            })
        })
        .collect();
    let mut latencies = Vec::new();
    let mut busy = 0;
    for worker in workers {
        let (done, refused) = worker.await.unwrap();
        latencies.extend(done);
        busy += refused;
    }
    let wall = started.elapsed();
    latencies.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let line = serde_json::json!({
        "ksf": {"memory_kib": args.ksf.memory_kib, "passes": args.ksf.passes, "lanes": args.ksf.lanes},
        "entries": args.entries,
        "domains": args.domains,
        "concurrency": args.concurrency,
        "checks": args.checks,
        "budget_mib": args.budget_mib,
        "wait_ms": args.wait.as_millis() as u64,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "completed": latencies.len(),
        "busy": busy,
        "wall_ms": ms(wall),
        "throughput_per_s": latencies.len() as f64 / wall.as_secs_f64(),
        "p50_ms": latencies.first().map(|_| ms(percentile(&latencies, 0.50))),
        "p95_ms": latencies.first().map(|_| ms(percentile(&latencies, 0.95))),
        "p99_ms": latencies.first().map(|_| ms(percentile(&latencies, 0.99))),
        "max_ms": latencies.last().map(|d| ms(*d)),
        "peak_rss_mib": peak_rss_mib(),
    });
    println!("{line}");
}
