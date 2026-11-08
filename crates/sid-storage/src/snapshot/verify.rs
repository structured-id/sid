// SPDX-License-Identifier: AGPL-3.0-only
//! Verification of a restored database against its source: identity,
//! issuers, sealed key material and key references, record counts and the
//! contents that must survive the move. It reads both sides and decrypts
//! nothing, so it proves neither key availability nor completeness after a
//! rollback.

use sid_plugin::SnapshotRules;
use tracing::info;

use super::{Result, SnapshotError, Store};

/// Result of a verification check.
#[derive(Debug)]
pub struct VerifyResult {
    /// Per-entity count comparisons.
    pub counts: Vec<CountCheck>,
    /// Integrity issues found.
    pub integrity_issues: Vec<String>,
    /// Whether verification passed.
    pub passed: bool,
}

/// Count comparison for a single entity type.
#[derive(Debug)]
pub struct CountCheck {
    pub entity: String,
    pub source_count: u64,
    pub target_count: u64,
    pub matches: bool,
}

impl CountCheck {
    fn of(entity: &str, source_count: u64, target_count: u64) -> Self {
        Self {
            entity: entity.into(),
            source_count,
            target_count,
            matches: source_count == target_count,
        }
    }
}

/// Verify that `target` holds what `source` held: every audit chain, the
/// same installation
/// organization and issuer registry with every sealed key generation, OPAQUE
/// setup, derivation parameters and cutoffs, each source profile with its
/// password history, history keys and device key bindings, and matching
/// counts.
pub async fn verify(
    source_store: Store<'_>,
    target_store: Store<'_>,
    rules: &dyn SnapshotRules,
) -> Result<VerifyResult> {
    let (source, source_keys) = (source_store.storage, source_store.history_keys);
    let (target, target_keys) = (target_store.storage, target_store.history_keys);
    let mut counts = Vec::new();
    let mut issues = Vec::new();
    // Every source chain is held by the target, continued at most by
    // records the import appended.
    for chain in source_store.audit.list_chain_ids().await? {
        let held = source_store.audit.export_chain(&chain).await?;
        match target_store.audit.export_chain(&chain).await {
            Ok(moved) if moved.holds(&held) => {}
            Ok(_) => issues.push(format!("audit chain {chain} differs")),
            Err(sid_core::models::audit::AuditError::ChainNotFound(_)) => {
                issues.push(format!("audit chain {chain} is missing on target"));
            }
            Err(e) => return Err(e.into()),
        }
        if !target_store.audit.verify_chain(&chain).await?.valid {
            issues.push(format!("audit chain {chain} does not verify on target"));
        }
    }
    let setup = sid_core::models::InstanceSecret::OpaqueServerSetup;
    if source.get_instance_secret(setup).await? != target.get_instance_secret(setup).await? {
        issues.push("OPAQUE server setup differs".into());
    }
    let organization = source.instance_organization().await?;
    if organization != target.instance_organization().await? {
        issues.push("installation organization differs".into());
    }
    let source_issuers = source.list_oidc_issuers().await?;
    let target_issuers = target.list_oidc_issuers().await?;
    counts.push(CountCheck::of(
        "oidc issuers",
        source_issuers.len() as u64,
        target_issuers.len() as u64,
    ));
    for issuer in &source_issuers {
        if !target_issuers.contains(issuer) {
            issues.push(format!("issuer {} differs or is missing", issuer.id));
        } else if source.oidc_issuer_signing_keys(issuer.id).await?
            != target.oidc_issuer_signing_keys(issuer.id).await?
        {
            issues.push(format!("signing keys of issuer {} differ", issuer.id));
        }
    }
    let target_versions = target.list_key_versions().await?;
    for params in source.list_key_versions().await? {
        if !target_versions.contains(&params) {
            issues.push(format!(
                "key derivation parameters differ for version {}",
                params.version
            ));
        }
    }
    let target_history_versions = target_keys.list_key_versions().await?;
    for params in source_keys.list_key_versions().await? {
        if !target_history_versions.contains(&params) {
            issues.push(format!(
                "history key derivation parameters differ for version {}",
                params.version
            ));
        }
    }
    // A target may be past a source's cutoff, never behind it: behind, it
    // would accept writes under a key the source had withdrawn.
    if source.history_write_cutoff().await? > target.history_write_cutoff().await? {
        issues.push("history write cutoff is lower in the target".into());
    }
    if source_keys.write_cutoff().await? > target_keys.write_cutoff().await? {
        issues.push("history key write cutoff is lower in the target".into());
    }
    let (source_records, target_records) = (
        source_keys.export_key_records().await?,
        target_keys.export_key_records().await?,
    );
    // The target's trail continues past the source's with the import's own.
    if source_records.abandoned != target_records.abandoned
        || source_records.purged != target_records.purged
        || !target_records.audit.starts_with(&source_records.audit)
    {
        issues.push("history key store fences or audit trail differ".into());
    }

    info!("verifying profiles...");
    // Walk the source: equal counts do not prove that the target holds the
    // owners whose retained history and keys must survive the move.
    let installation = organization.as_ref().map(|o| o.id);
    let mut offset = 0u64;
    loop {
        let batch = source.list_profiles(offset, 1000).await?;
        if batch.is_empty() {
            break;
        }
        offset += batch.len() as u64;
        for profile in batch {
            let pid = profile.id;
            if target.get_profile(pid).await?.is_none() {
                issues.push(format!("source profile {pid} is missing on target"));
                continue;
            }
            if source.export_password_history(pid).await?
                != target.export_password_history(pid).await?
            {
                issues.push(format!("password history differs for profile {pid}"));
            }
            if let Some(installation) = installation {
                let domain = rules.history_owner_domain(installation, pid);
                if source_keys.export_keys(&domain).await?
                    != target_keys.export_keys(&domain).await?
                {
                    issues.push(format!("password history keys differ for profile {pid}"));
                }
            }
            let mut source_bindings = source.list_device_attestations_by_profile(pid).await?;
            let mut target_bindings = target.list_device_attestations_by_profile(pid).await?;
            source_bindings.sort_by_key(|a| *a.id.as_uuid());
            target_bindings.sort_by_key(|a| *a.id.as_uuid());
            if source_bindings != target_bindings {
                issues.push(format!("device key bindings differ for profile {pid}"));
            }
            // Every record the target holds for the profile names it.
            for credential in target.get_credentials_by_profile(pid, None).await? {
                if credential.profile_id != pid {
                    issues.push(format!(
                        "credential {} is listed for profile {pid} but names {}",
                        credential.id.0, credential.profile_id
                    ));
                }
            }
            for session in target.list_sessions(&pid).await? {
                if session.profile_id != pid {
                    issues.push(format!(
                        "session {} is listed for profile {pid} but names {}",
                        session.id, session.profile_id
                    ));
                }
            }
            for principal in target.get_principals_by_profile(pid).await? {
                if principal.profile_id != pid {
                    issues.push(format!(
                        "principal {} is listed for profile {pid} but names {}",
                        principal.id.0, principal.profile_id
                    ));
                }
            }
        }
    }

    // Every collection a snapshot carries, read from both sides. Each store
    // keeps its own system project; the import leaves the target's in place.
    let own = |mut snapshot: super::Snapshot| {
        snapshot
            .projects
            .retain(|p| p.id != sid_core::models::ProjectId::SYSTEM);
        snapshot
    };
    let mut moved = own(super::export(source_store, rules).await?);
    let mut held = own(super::export(target_store, rules).await?);
    // Each export drops the ceremony records expired at its own moment: both
    // sides are compared at one later cutoff, so a deadline passing between
    // the two exports is no difference.
    let cutoff = chrono::Utc::now();
    moved.ceremony.retain_live_at(cutoff);
    held.ceremony.retain_live_at(cutoff);
    // A claim belongs to a worker of the store it was made in: every import
    // restores claimed work at rest, so both sides are compared at rest.
    for work in moved
        .durable_work
        .iter_mut()
        .chain(held.durable_work.iter_mut())
    {
        work.record = work.at_rest();
    }
    compare_contents(&moved, &held, &mut counts, &mut issues)?;

    let passed = counts.iter().all(|c| c.matches) && issues.is_empty();
    info!(
        passed,
        count_checks = counts.len(),
        integrity_issues = issues.len(),
        "verification complete"
    );
    Ok(VerifyResult {
        counts,
        integrity_issues: issues,
        passed,
    })
}

/// Fields compared above with their own rule: the snapshot's identity, the
/// audit chains and the evaluator's trail, which the import continues, the
/// installation's authority and key material, and the write cutoffs, which a
/// target may be past.
const COMPARED_APART: &[&str] = &[
    "metadata",
    "audit_chains",
    "history_key_records",
    "organization",
    "oidc_issuers",
    "key_versions",
    "history_key_versions",
    "opaque_server_setup",
    "history_write_cutoff",
    "history_key_write_cutoff",
];

/// Fields the target holds more of than its source: the import records its
/// own resume marker among the bound identifiers.
const CONTINUED: &[&str] = &["operation_resources"];

/// Compare every other field of the source's and the target's snapshots: a
/// collection as the multiset of its records, whatever order each store
/// lists them in, anything else as a value.
fn compare_contents(
    source: &super::Snapshot,
    target: &super::Snapshot,
    counts: &mut Vec<CountCheck>,
    issues: &mut Vec<String>,
) -> Result<()> {
    let encode = |snapshot: &super::Snapshot| {
        serde_json::to_value(snapshot).map_err(|e| SnapshotError::Invalid(format!("snapshot: {e}")))
    };
    let (source, target) = (encode(source)?, encode(target)?);
    let (Some(source), Some(target)) = (source.as_object(), target.as_object()) else {
        return Err(SnapshotError::Invalid("a snapshot is not an object".into()));
    };
    let records = |value: &serde_json::Value| -> Option<Vec<String>> {
        let mut all: Vec<String> = value.as_array()?.iter().map(|r| r.to_string()).collect();
        all.sort_unstable();
        Some(all)
    };
    for (field, moved) in source {
        if COMPARED_APART.contains(&field.as_str()) {
            continue;
        }
        let held = target.get(field).unwrap_or(&serde_json::Value::Null);
        match (records(moved), records(held)) {
            (Some(moved), Some(held)) => {
                let kept = moved
                    .iter()
                    .filter(|r| held.binary_search(r).is_ok())
                    .count();
                let complete = if CONTINUED.contains(&field.as_str()) {
                    kept == moved.len()
                } else {
                    moved == held
                };
                counts.push(CountCheck::of(
                    &field.replace('_', " "),
                    moved.len() as u64,
                    if complete { moved.len() } else { kept } as u64,
                ));
                if !complete {
                    issues.push(format!("{} differ on target", field.replace('_', " ")));
                }
            }
            _ if moved != held => {
                issues.push(format!("{} differs on target", field.replace('_', " ")))
            }
            _ => {}
        }
    }
    Ok(())
}

impl std::fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Verification Result: {}",
            if self.passed { "PASSED" } else { "FAILED" }
        )?;
        writeln!(f)?;
        writeln!(f, "Record Counts:")?;
        writeln!(
            f,
            "  {:<20} {:>10} {:>10} Status",
            "Entity", "Source", "Target"
        )?;
        for check in &self.counts {
            writeln!(
                f,
                "  {:<20} {:>10} {:>10} {}",
                check.entity,
                check.source_count,
                check.target_count,
                if check.matches { "OK" } else { "MISMATCH" },
            )?;
        }
        if !self.integrity_issues.is_empty() {
            writeln!(f)?;
            writeln!(f, "Integrity Issues:")?;
            for issue in &self.integrity_issues {
                writeln!(f, "  - {issue}")?;
            }
        }
        Ok(())
    }
}
