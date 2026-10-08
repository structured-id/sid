// SPDX-License-Identifier: AGPL-3.0-only
//! Cross-instance linking for federation.
//!
//! Lets the holder of two BindingIds (from different instances) prove that
//! both belong to that same holder, scoped to a single service sector.
//!
//! ## Security Properties
//!
//! - **Dual-signature**: Both binding private keys must sign the linking statement.
//! - **Service-scoped**: Each link is bound to a specific service sector.
//! - **Replay-resistant**: Nonce + timestamp prevent reuse.
//! - **Revocable**: Single-signature revocation (either key can unlink).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a cross-instance link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkId(pub Uuid);

impl LinkId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for LinkId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for LinkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version prefix for the linking statement.
const LINKING_STATEMENT_PREFIX: &str = "sid:cross-link:v1";

/// A dual-signed proof that two BindingIds belong to the same holder.
///
/// Scoped to a single service sector — cannot be reused across services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossInstanceLinkingProof {
    pub id: LinkId,

    /// First binding identity.
    pub binding_a: String,

    /// Second binding identity.
    pub binding_b: String,

    /// Service sector this link is scoped to (e.g., "app.acme.com").
    pub service_sector: String,

    /// Canonical linking statement that was signed.
    pub statement: String,

    /// Signature from binding_a's private key over the statement.
    pub signature_a: Vec<u8>,

    /// Signature from binding_b's private key over the statement.
    pub signature_b: Vec<u8>,

    /// Random nonce for replay protection.
    pub nonce: String,

    /// Whether this link can be revoked later.
    pub revocable: bool,

    pub created_at: DateTime<Utc>,
}

/// Status of a cross-instance link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    /// Link is active and valid.
    Active,
    /// Link has been revoked by one of the parties.
    Revoked,
}

/// Revocation record for a cross-instance link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossInstanceLinkRevocation {
    /// Link being revoked.
    pub link_id: LinkId,

    /// Which binding is revoking (either side can revoke).
    pub revoking_binding: String,

    /// Signature from the revoking binding's private key.
    pub signature: Vec<u8>,

    /// Reason for revocation.
    pub reason: String,

    pub created_at: DateTime<Utc>,
}

/// Build the canonical linking statement for signing.
///
/// Format: `sid:cross-link:v1:{binding_a}:{binding_b}:{service_sector}:{nonce}`
///
/// The statement includes the nonce for replay protection.
pub fn build_linking_statement(
    binding_a: &str,
    binding_b: &str,
    service_sector: &str,
    nonce: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        LINKING_STATEMENT_PREFIX, binding_a, binding_b, service_sector, nonce
    )
}

/// Create a linking proof from pre-signed components.
///
/// Both signatures must be computed externally using each binding's private key.
pub fn create_linking_proof(
    binding_a: String,
    binding_b: String,
    service_sector: String,
    nonce: String,
    signature_a: Vec<u8>,
    signature_b: Vec<u8>,
    revocable: bool,
) -> CrossInstanceLinkingProof {
    let statement = build_linking_statement(&binding_a, &binding_b, &service_sector, &nonce);
    CrossInstanceLinkingProof {
        id: LinkId::new(),
        binding_a,
        binding_b,
        service_sector,
        statement,
        signature_a,
        signature_b,
        nonce,
        revocable,
        created_at: Utc::now(),
    }
}

/// Verify that a linking proof's statement matches its claimed bindings.
///
/// This checks the statement format only — actual signature verification
/// requires access to the binding certificates (caller's responsibility).
pub fn verify_proof_statement(proof: &CrossInstanceLinkingProof) -> bool {
    let expected = build_linking_statement(
        &proof.binding_a,
        &proof.binding_b,
        &proof.service_sector,
        &proof.nonce,
    );
    proof.statement == expected
}

/// Verify that a linking proof is scoped to the expected service sector.
pub fn verify_proof_sector(proof: &CrossInstanceLinkingProof, expected_sector: &str) -> bool {
    proof.service_sector == expected_sector
}

/// Create a revocation for a cross-instance link.
pub fn create_link_revocation(
    link_id: LinkId,
    revoking_binding: String,
    signature: Vec<u8>,
    reason: String,
) -> CrossInstanceLinkRevocation {
    CrossInstanceLinkRevocation {
        link_id,
        revoking_binding,
        signature,
        reason,
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_linking_statement() {
        let stmt = build_linking_statement("bind_a", "bind_b", "app.acme.com", "nonce123");
        assert_eq!(
            stmt,
            "sid:cross-link:v1:bind_a:bind_b:app.acme.com:nonce123"
        );
    }

    #[test]
    fn test_create_linking_proof() {
        let proof = create_linking_proof(
            "bind_a".to_string(),
            "bind_b".to_string(),
            "app.acme.com".to_string(),
            "nonce123".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            true,
        );
        assert_eq!(proof.binding_a, "bind_a");
        assert_eq!(proof.binding_b, "bind_b");
        assert_eq!(proof.service_sector, "app.acme.com");
        assert!(proof.revocable);
        assert!(verify_proof_statement(&proof));
    }

    #[test]
    fn test_verify_proof_statement_valid() {
        let proof = create_linking_proof(
            "a".to_string(),
            "b".to_string(),
            "sector".to_string(),
            "n".to_string(),
            vec![],
            vec![],
            false,
        );
        assert!(verify_proof_statement(&proof));
    }

    #[test]
    fn test_verify_proof_statement_tampered() {
        let mut proof = create_linking_proof(
            "a".to_string(),
            "b".to_string(),
            "sector".to_string(),
            "n".to_string(),
            vec![],
            vec![],
            false,
        );
        proof.binding_a = "tampered".to_string();
        assert!(!verify_proof_statement(&proof));
    }

    #[test]
    fn test_verify_proof_sector() {
        let proof = create_linking_proof(
            "a".to_string(),
            "b".to_string(),
            "app.acme.com".to_string(),
            "n".to_string(),
            vec![],
            vec![],
            false,
        );
        assert!(verify_proof_sector(&proof, "app.acme.com"));
        assert!(!verify_proof_sector(&proof, "other.service.com"));
    }

    #[test]
    fn test_create_link_revocation() {
        let link_id = LinkId::new();
        let revocation = create_link_revocation(
            link_id,
            "bind_a".to_string(),
            vec![7, 8, 9],
            "no longer needed".to_string(),
        );
        assert_eq!(revocation.link_id, link_id);
        assert_eq!(revocation.revoking_binding, "bind_a");
        assert_eq!(revocation.reason, "no longer needed");
    }

    #[test]
    fn test_link_id_unique() {
        let id1 = LinkId::new();
        let id2 = LinkId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_link_status_serde() {
        let status = LinkStatus::Active;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"active\"");
        let parsed: LinkStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, LinkStatus::Active);
    }

    #[test]
    fn test_linking_proof_serde_roundtrip() {
        let proof = create_linking_proof(
            "bind_a".to_string(),
            "bind_b".to_string(),
            "sector".to_string(),
            "nonce".to_string(),
            vec![1, 2],
            vec![3, 4],
            true,
        );
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: CrossInstanceLinkingProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.binding_a, proof.binding_a);
        assert_eq!(parsed.service_sector, proof.service_sector);
    }
}
