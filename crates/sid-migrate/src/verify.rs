// SPDX-License-Identifier: AGPL-3.0-only
//! Verification of data integrity between two storage backends.
//!
//! Compares record counts and checks referential integrity
//! (e.g., all credentials reference existing profiles).

use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use tracing::info;

/// Result of a verification check.
#[derive(Debug)]
pub struct VerifyResult {
    /// Per-entity count comparisons.
    pub counts: Vec<CountCheck>,
    /// Referential integrity issues found.
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

/// Verify that source and target backends have matching data.
///
/// Performs:
/// 1. Record count comparison for each entity type
/// 2. Referential integrity checks (credentials→profiles, sessions→profiles, etc.)
/// 3. Each source profile's password history and history evaluator keys
pub async fn verify_backends(
    source: &dyn StorageBackend,
    source_keys: &dyn HistoryKeyStore,
    target: &dyn StorageBackend,
    target_keys: &dyn HistoryKeyStore,
) -> anyhow::Result<VerifyResult> {
    let mut counts = Vec::new();
    let mut integrity_issues = Vec::new();
    let setup = sid_core::models::InstanceSecret::OpaqueServerSetup;
    if source.get_instance_secret(setup).await? != target.get_instance_secret(setup).await? {
        integrity_issues.push("OPAQUE server setup differs".into());
    }
    let installation = source.instance_organization().await?.map(|o| o.id);
    if installation != target.instance_organization().await?.map(|o| o.id) {
        integrity_issues.push("installation authority differs".into());
    }
    let target_versions = target.list_key_versions().await?;
    for params in source.list_key_versions().await? {
        if !target_versions.iter().any(|p| p == &params) {
            integrity_issues.push(format!(
                "key derivation parameters differ for version {}",
                params.version
            ));
        }
    }
    let target_history_versions = target_keys.list_key_versions().await?;
    for params in source_keys.list_key_versions().await? {
        if !target_history_versions.contains(&params) {
            integrity_issues.push(format!(
                "history key derivation parameters differ for version {}",
                params.version
            ));
        }
    }

    // Compare profile counts
    info!("verifying profiles...");
    let source_profiles = source.count_profiles().await?;
    let target_profiles = target.count_profiles().await?;
    counts.push(CountCheck {
        entity: "profiles".into(),
        source_count: source_profiles,
        target_count: target_profiles,
        matches: source_profiles == target_profiles,
    });

    // Compare project counts
    info!("verifying projects...");
    let source_projects = source.count_projects().await?;
    let target_projects = target.count_projects().await?;
    counts.push(CountCheck {
        entity: "projects".into(),
        source_count: source_projects,
        target_count: target_projects,
        matches: source_projects == target_projects,
    });

    // Walk the source too: equal profile counts do not prove that the target
    // contains the owners whose retained history must survive the move.
    let mut offset = 0u64;
    loop {
        let batch = source.list_profiles(offset, 1000).await?;
        if batch.is_empty() {
            break;
        }
        offset += batch.len() as u64;
        for profile in batch {
            if target.get_profile(profile.id).await?.is_none() {
                integrity_issues.push(format!(
                    "source profile {} is missing on target",
                    profile.id
                ));
            } else if source.export_password_history(profile.id).await?
                != target.export_password_history(profile.id).await?
            {
                integrity_issues.push(format!(
                    "password history differs for profile {}",
                    profile.id
                ));
            }
            if let Some(installation) = &installation {
                let domain =
                    sid_authn::password_history::owner_domain(installation.as_bytes(), profile.id);
                if source_keys.export_keys(&domain).await?
                    != target_keys.export_keys(&domain).await?
                {
                    integrity_issues.push(format!(
                        "password history keys differ for profile {}",
                        profile.id
                    ));
                }
            }
        }
    }

    // Verify referential integrity on target: every credential has a valid profile
    info!("checking referential integrity...");
    let target_profile_list = {
        let mut all = Vec::new();
        let mut offset = 0u64;
        loop {
            let batch = target.list_profiles(offset, 1000).await?;
            if batch.is_empty() {
                break;
            }
            offset += batch.len() as u64;
            all.extend(batch);
        }
        all
    };

    for profile in &target_profile_list {
        if source.export_password_history(profile.id).await?
            != target.export_password_history(profile.id).await?
        {
            integrity_issues.push(format!(
                "password history differs for profile {}",
                profile.id
            ));
        }
        // Check credentials reference valid profiles
        let creds = target.get_credentials_by_profile(profile.id, None).await?;
        for cred in &creds {
            if cred.profile_id != profile.id {
                integrity_issues.push(format!(
                    "credential {} references profile {} but was fetched for profile {}",
                    cred.id.0, cred.profile_id, profile.id,
                ));
            }
        }

        // Check sessions reference valid profiles
        let sessions = target.list_sessions_by_profile(profile.id).await?;
        for session in &sessions {
            if session.profile_id != profile.id {
                integrity_issues.push(format!(
                    "session {} references profile {} but was fetched for profile {}",
                    session.id, session.profile_id, profile.id,
                ));
            }
        }

        // Check principals reference valid profiles
        let identifiers = target.get_principals_by_profile(profile.id).await?;
        for ident in &identifiers {
            if ident.profile_id != profile.id {
                integrity_issues.push(format!(
                    "principal {} references profile {} but was fetched for profile {}",
                    ident.id.0, ident.profile_id, profile.id,
                ));
            }
        }
    }

    let passed = counts.iter().all(|c| c.matches) && integrity_issues.is_empty();

    info!(
        passed,
        count_checks = counts.len(),
        integrity_issues = integrity_issues.len(),
        "verification complete"
    );

    Ok(VerifyResult {
        counts,
        integrity_issues,
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
        writeln!(f, "  {}", "─".repeat(55))?;
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
            writeln!(f, "Referential Integrity Issues:")?;
            for issue in &self.integrity_issues {
                writeln!(f, "  - {issue}")?;
            }
        }

        Ok(())
    }
}
