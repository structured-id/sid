// SPDX-License-Identifier: AGPL-3.0-only
//! Verification of a restored database against its source: identity,
//! issuers, sealed key material and key references, record counts and the
//! contents that must survive the move. It reads both sides and decrypts
//! nothing, so it proves neither key availability nor completeness after a
//! rollback.

use sid_plugin::SnapshotRules;
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use tracing::info;

use super::Result;

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

/// Verify that `target` holds what `source` held: the same installation
/// organization and issuer registry with every sealed key generation, OPAQUE
/// setup, derivation parameters and cutoffs, each source profile with its
/// password history, history keys and device key bindings, and matching
/// counts.
pub async fn verify(
    source: &dyn StorageBackend,
    source_keys: &dyn HistoryKeyStore,
    target: &dyn StorageBackend,
    target_keys: &dyn HistoryKeyStore,
    rules: &dyn SnapshotRules,
) -> Result<VerifyResult> {
    let mut counts = Vec::new();
    let mut issues = Vec::new();
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

    info!("verifying profiles...");
    counts.push(CountCheck::of(
        "profiles",
        source.count_profiles().await?,
        target.count_profiles().await?,
    ));
    counts.push(CountCheck::of(
        "projects",
        source.count_projects().await?,
        target.count_projects().await?,
    ));

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
