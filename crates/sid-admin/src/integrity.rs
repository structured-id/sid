// SPDX-License-Identifier: AGPL-3.0-only
//! Data integrity verification for StructuredID CE.
//!
//! Five independent verification layers:
//! 1. Merkle tree — profile field hash tree integrity (SaaS/EE only, not CE Phase 1)
//! 2. Audit chain — hash chain continuity
//! 3. Blob integrity — encrypted blob decryption + hash verification (SaaS/EE only)
//! 4. Graph consistency — FK reference resolution (orphan detection)
//! 5. CA chain — certificate chain validation (federation only)
//!
//! CE Phase 1: layers 2 (audit chain) + 4 (graph consistency) are active.
//! Layers 1, 3, 5 return pass with 0 entities (no data to verify yet).
//!
//! CE: `sid-admin integrity check` (manual, recommended weekly).
//! EE: background worker with delta verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_plugin::audit::AuditLog;
use sid_plugin::storage::StorageBackend;
use std::sync::Arc;
use tracing::{info, warn};

/// Integrity verification layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationLayer {
    /// SHA-256 Merkle tree for profile fields.
    MerkleTree,
    /// Audit log hash chain continuity.
    AuditChain,
    /// Encrypted blob decryption + commitment hash.
    BlobIntegrity,
    /// FK reference resolution (orphan detection).
    GraphConsistency,
    /// X.509 certificate chain validation.
    CaChain,
}

impl std::fmt::Display for VerificationLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MerkleTree => write!(f, "merkle_tree"),
            Self::AuditChain => write!(f, "audit_chain"),
            Self::BlobIntegrity => write!(f, "blob_integrity"),
            Self::GraphConsistency => write!(f, "graph_consistency"),
            Self::CaChain => write!(f, "ca_chain"),
        }
    }
}

/// Severity of an integrity issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntegritySeverity {
    /// Informational — no data corruption, but worth noting.
    Info,
    /// Warning — potential issue, not confirmed corruption.
    Warning,
    /// Error — confirmed data corruption.
    Error,
    /// Critical — corruption in security-sensitive data.
    Critical,
}

/// A single integrity issue found during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityIssue {
    /// Which layer detected the issue.
    pub layer: VerificationLayer,
    /// Severity level.
    pub severity: IntegritySeverity,
    /// Entity type (e.g., "profile", "audit_record", "blob").
    pub entity_type: String,
    /// Entity identifier (e.g., profile ID, record ID).
    pub entity_id: String,
    /// Human-readable description of the issue.
    pub description: String,
    /// Whether auto-repair is possible.
    pub auto_repairable: bool,
}

/// Result of a single verification layer check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerResult {
    /// Which layer was checked.
    pub layer: VerificationLayer,
    /// Number of entities checked.
    pub entities_checked: u64,
    /// Number of entities that passed verification.
    pub entities_passed: u64,
    /// Number of issues found.
    pub issues_found: u64,
    /// Duration of this layer's check in milliseconds.
    pub duration_ms: u64,
    /// Issues found (if any).
    pub issues: Vec<IntegrityIssue>,
}

impl LayerResult {
    /// Whether this layer passed (no issues with severity >= Error).
    pub fn passed(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|i| i.severity >= IntegritySeverity::Error)
    }
}

/// Full integrity check report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// When the check started.
    pub started_at: DateTime<Utc>,
    /// When the check completed.
    pub completed_at: DateTime<Utc>,
    /// Which layers were checked.
    pub layers: Vec<LayerResult>,
    /// Overall verdict.
    pub passed: bool,
    /// Total entities checked across all layers.
    pub total_entities_checked: u64,
    /// Total issues found across all layers.
    pub total_issues_found: u64,
}

/// Integrity check request.
#[derive(Debug, Clone, Default)]
pub struct IntegrityCheckRequest {
    /// Which layers to check (empty = all).
    pub layers: Vec<VerificationLayer>,
    /// Maximum number of entities to check per layer (0 = unlimited).
    pub max_entities: u64,
    /// Whether to attempt auto-repair for repairable issues.
    pub auto_repair: bool,
}

/// CE Integrity Service.
///
/// Runs verification layers against real storage and produces integrity reports.
/// CE Phase 1: audit chain verification + graph consistency (orphan detection).
pub struct IntegrityService {
    audit_log: Arc<dyn AuditLog>,
    storage: Arc<dyn StorageBackend>,
}

impl IntegrityService {
    /// Create a new IntegrityService with storage and audit dependencies.
    pub fn new(audit_log: Arc<dyn AuditLog>, storage: Arc<dyn StorageBackend>) -> Self {
        Self { audit_log, storage }
    }

    /// Get the default set of all verification layers.
    pub fn all_layers() -> Vec<VerificationLayer> {
        vec![
            VerificationLayer::MerkleTree,
            VerificationLayer::AuditChain,
            VerificationLayer::BlobIntegrity,
            VerificationLayer::GraphConsistency,
            VerificationLayer::CaChain,
        ]
    }

    /// Resolve which layers to check based on the request.
    pub fn resolve_layers(request: &IntegrityCheckRequest) -> Vec<VerificationLayer> {
        if request.layers.is_empty() {
            Self::all_layers()
        } else {
            request.layers.clone()
        }
    }

    /// Run a full integrity check across requested layers.
    ///
    /// Each layer runs independently. Failures in one layer don't prevent others.
    pub async fn run_check(&self, request: &IntegrityCheckRequest) -> IntegrityReport {
        let started_at = Utc::now();
        let layers_to_check = Self::resolve_layers(request);
        let mut layer_results = Vec::with_capacity(layers_to_check.len());

        for layer in &layers_to_check {
            let result = match layer {
                VerificationLayer::AuditChain => self.verify_audit_chains().await,
                VerificationLayer::GraphConsistency => self.verify_graph_consistency().await,
                // CE Phase 1: layers without data return pass with 0 entities.
                VerificationLayer::MerkleTree
                | VerificationLayer::BlobIntegrity
                | VerificationLayer::CaChain => LayerResult {
                    layer: *layer,
                    entities_checked: 0,
                    entities_passed: 0,
                    issues_found: 0,
                    duration_ms: 0,
                    issues: Vec::new(),
                },
            };
            layer_results.push(result);
        }

        let completed_at = Utc::now();
        let total_entities_checked: u64 = layer_results.iter().map(|l| l.entities_checked).sum();
        let total_issues_found: u64 = layer_results.iter().map(|l| l.issues_found).sum();
        let passed = layer_results.iter().all(|l| l.passed());

        IntegrityReport {
            started_at,
            completed_at,
            layers: layer_results,
            passed,
            total_entities_checked,
            total_issues_found,
        }
    }

    /// Verify all audit hash chains.
    ///
    /// Enumerates all chain_ids from chain heads, then verifies each chain's
    /// hash linkage and record integrity.
    async fn verify_audit_chains(&self) -> LayerResult {
        let start = std::time::Instant::now();
        let mut issues = Vec::new();
        let mut chains_checked: u64 = 0;
        let mut chains_passed: u64 = 0;

        let chain_ids = match self.audit_log.list_chain_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!("Failed to list audit chain IDs: {}", e);
                return LayerResult {
                    layer: VerificationLayer::AuditChain,
                    entities_checked: 0,
                    entities_passed: 0,
                    issues_found: 1,
                    duration_ms: start.elapsed().as_millis() as u64,
                    issues: vec![IntegrityIssue {
                        layer: VerificationLayer::AuditChain,
                        severity: IntegritySeverity::Error,
                        entity_type: "audit_chain".into(),
                        entity_id: "all".into(),
                        description: format!("Failed to list chain IDs: {}", e),
                        auto_repairable: false,
                    }],
                };
            }
        };

        info!(chain_count = chain_ids.len(), "Verifying audit chains");

        for chain_id in &chain_ids {
            chains_checked += 1;
            match self.audit_log.verify_chain(chain_id).await {
                Ok(result) => {
                    if result.valid {
                        chains_passed += 1;
                    } else {
                        let broken_id = result
                            .first_broken_record
                            .unwrap_or_else(|| "unknown".into());
                        warn!(
                            chain_id,
                            broken_record = %broken_id,
                            "Audit chain integrity violation"
                        );
                        issues.push(IntegrityIssue {
                            layer: VerificationLayer::AuditChain,
                            severity: IntegritySeverity::Critical,
                            entity_type: "audit_chain".into(),
                            entity_id: chain_id.clone(),
                            description: format!("Hash chain broken at record {}", broken_id),
                            auto_repairable: false,
                        });
                    }
                }
                Err(e) => {
                    warn!(chain_id, error = %e, "Failed to verify audit chain");
                    issues.push(IntegrityIssue {
                        layer: VerificationLayer::AuditChain,
                        severity: IntegritySeverity::Error,
                        entity_type: "audit_chain".into(),
                        entity_id: chain_id.clone(),
                        description: format!("Verification failed: {}", e),
                        auto_repairable: false,
                    });
                }
            }
        }

        info!(
            chains_checked,
            chains_passed,
            issues = issues.len(),
            duration_ms = start.elapsed().as_millis(),
            "Audit chain verification complete"
        );

        LayerResult {
            layer: VerificationLayer::AuditChain,
            entities_checked: chains_checked,
            entities_passed: chains_passed,
            issues_found: issues.len() as u64,
            duration_ms: start.elapsed().as_millis() as u64,
            issues,
        }
    }

    /// Verify graph consistency (FK reference integrity).
    ///
    /// Checks for orphaned entities: sessions, credentials, and role assignments
    /// that reference non-existent profiles or roles.
    async fn verify_graph_consistency(&self) -> LayerResult {
        let start = std::time::Instant::now();
        let mut issues = Vec::new();
        let mut entities_checked: u64 = 0;

        // Check orphaned sessions.
        match self.storage.count_orphaned_sessions().await {
            Ok(count) => {
                entities_checked += 1;
                if count > 0 {
                    warn!(orphan_count = count, "Orphaned sessions detected");
                    issues.push(IntegrityIssue {
                        layer: VerificationLayer::GraphConsistency,
                        severity: IntegritySeverity::Warning,
                        entity_type: "session".into(),
                        entity_id: format!("{} orphans", count),
                        description: format!(
                            "{} sessions reference non-existent profiles (safe to delete)",
                            count
                        ),
                        auto_repairable: true,
                    });
                }
            }
            Err(e) => {
                issues.push(IntegrityIssue {
                    layer: VerificationLayer::GraphConsistency,
                    severity: IntegritySeverity::Error,
                    entity_type: "session".into(),
                    entity_id: "query_failed".into(),
                    description: format!("Orphan session query failed: {}", e),
                    auto_repairable: false,
                });
            }
        }

        // Check orphaned credentials.
        match self.storage.count_orphaned_credentials().await {
            Ok(count) => {
                entities_checked += 1;
                if count > 0 {
                    warn!(orphan_count = count, "Orphaned credentials detected");
                    issues.push(IntegrityIssue {
                        layer: VerificationLayer::GraphConsistency,
                        severity: IntegritySeverity::Error,
                        entity_type: "credential".into(),
                        entity_id: format!("{} orphans", count),
                        description: format!(
                            "{} credentials reference non-existent profiles",
                            count
                        ),
                        auto_repairable: false,
                    });
                }
            }
            Err(e) => {
                issues.push(IntegrityIssue {
                    layer: VerificationLayer::GraphConsistency,
                    severity: IntegritySeverity::Error,
                    entity_type: "credential".into(),
                    entity_id: "query_failed".into(),
                    description: format!("Orphan credential query failed: {}", e),
                    auto_repairable: false,
                });
            }
        }

        // Check orphaned role assignments.
        match self.storage.count_orphaned_role_assignments().await {
            Ok(count) => {
                entities_checked += 1;
                if count > 0 {
                    warn!(orphan_count = count, "Orphaned role assignments detected");
                    issues.push(IntegrityIssue {
                        layer: VerificationLayer::GraphConsistency,
                        severity: IntegritySeverity::Warning,
                        entity_type: "role_assignment".into(),
                        entity_id: format!("{} orphans", count),
                        description: format!(
                            "{} role assignments reference non-existent profiles or roles",
                            count
                        ),
                        auto_repairable: true,
                    });
                }
            }
            Err(e) => {
                issues.push(IntegrityIssue {
                    layer: VerificationLayer::GraphConsistency,
                    severity: IntegritySeverity::Error,
                    entity_type: "role_assignment".into(),
                    entity_id: "query_failed".into(),
                    description: format!("Orphan role assignment query failed: {}", e),
                    auto_repairable: false,
                });
            }
        }

        let entities_passed = entities_checked
            - issues
                .iter()
                .filter(|i| i.severity >= IntegritySeverity::Error)
                .count() as u64;

        info!(
            entities_checked,
            issues = issues.len(),
            duration_ms = start.elapsed().as_millis(),
            "Graph consistency verification complete"
        );

        LayerResult {
            layer: VerificationLayer::GraphConsistency,
            entities_checked,
            entities_passed,
            issues_found: issues.len() as u64,
            duration_ms: start.elapsed().as_millis() as u64,
            issues,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_layers() {
        let layers = IntegrityService::all_layers();
        assert_eq!(layers.len(), 5);
    }

    #[test]
    fn test_resolve_layers_empty() {
        let request = IntegrityCheckRequest::default();
        let layers = IntegrityService::resolve_layers(&request);
        assert_eq!(layers.len(), 5);
    }

    #[test]
    fn test_resolve_layers_specific() {
        let request = IntegrityCheckRequest {
            layers: vec![VerificationLayer::AuditChain],
            ..Default::default()
        };
        let layers = IntegrityService::resolve_layers(&request);
        assert_eq!(layers, vec![VerificationLayer::AuditChain]);
    }

    #[test]
    fn test_layer_result_passed_no_issues() {
        let result = LayerResult {
            layer: VerificationLayer::GraphConsistency,
            entities_checked: 100,
            entities_passed: 100,
            issues_found: 0,
            duration_ms: 500,
            issues: Vec::new(),
        };
        assert!(result.passed());
    }

    #[test]
    fn test_layer_result_passed_warnings_only() {
        let result = LayerResult {
            layer: VerificationLayer::GraphConsistency,
            entities_checked: 3,
            entities_passed: 3,
            issues_found: 1,
            duration_ms: 100,
            issues: vec![IntegrityIssue {
                layer: VerificationLayer::GraphConsistency,
                severity: IntegritySeverity::Warning,
                entity_type: "session".into(),
                entity_id: "2 orphans".into(),
                description: "2 sessions reference non-existent profiles".into(),
                auto_repairable: true,
            }],
        };
        assert!(result.passed());
    }

    #[test]
    fn test_layer_result_failed_errors() {
        let result = LayerResult {
            layer: VerificationLayer::AuditChain,
            entities_checked: 5,
            entities_passed: 4,
            issues_found: 1,
            duration_ms: 200,
            issues: vec![IntegrityIssue {
                layer: VerificationLayer::AuditChain,
                severity: IntegritySeverity::Critical,
                entity_type: "audit_chain".into(),
                entity_id: "profile:prof_123".into(),
                description: "Hash chain broken at record abc".into(),
                auto_repairable: false,
            }],
        };
        assert!(!result.passed());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(IntegritySeverity::Info < IntegritySeverity::Warning);
        assert!(IntegritySeverity::Warning < IntegritySeverity::Error);
        assert!(IntegritySeverity::Error < IntegritySeverity::Critical);
    }

    #[test]
    fn test_verification_layer_display() {
        assert_eq!(VerificationLayer::MerkleTree.to_string(), "merkle_tree");
        assert_eq!(VerificationLayer::AuditChain.to_string(), "audit_chain");
        assert_eq!(
            VerificationLayer::GraphConsistency.to_string(),
            "graph_consistency"
        );
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let report = IntegrityReport {
            started_at: Utc::now(),
            completed_at: Utc::now(),
            layers: vec![LayerResult {
                layer: VerificationLayer::AuditChain,
                entities_checked: 10,
                entities_passed: 10,
                issues_found: 0,
                duration_ms: 42,
                issues: Vec::new(),
            }],
            passed: true,
            total_entities_checked: 10,
            total_issues_found: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: IntegrityReport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.passed);
        assert_eq!(deserialized.total_entities_checked, 10);
    }
}
