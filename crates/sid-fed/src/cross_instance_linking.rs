// SPDX-License-Identifier: AGPL-3.0-only
//! Cross-instance linking for federation.
//!
//! Lets the holder of two Bindings (from different instances) prove to one
//! recipient organization that both belong to the same holder.
//!
//! ## Security Properties
//!
//! - **Dual-signature**: Both binding private keys must sign the linking statement.
//! - **Recipient-scoped**: Link and unlink name the recipient's registered OrgId,
//!   never a domain, so a later owner of a domain cannot reuse them.
//! - **Unambiguous**: One versioned statement covers every field; free text is
//!   length-prefixed, so no two field tuples share an encoding.
//! - **Replay-resistant**: Nonce + creation time prevent reuse.
//! - **Revocable**: Single-signature revocation (either key can unlink).

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sid_core::models::{BindingId, OrgId};

/// Version prefix of the linking statement.
const LINKING_STATEMENT_PREFIX: &str = "sid:cross-link:v1";

/// Version prefix of the unlinking statement.
const UNLINKING_STATEMENT_PREFIX: &str = "sid:cross-unlink:v1";

/// A dual-signed proof that two Bindings belong to the same holder, for one
/// recipient organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossInstanceLinkingProof {
    /// First Binding.
    pub binding_a: BindingId,

    /// Second Binding.
    pub binding_b: BindingId,

    /// The recipient organization's registered OrgId the link is for.
    pub recipient_org: OrgId,

    /// Canonical linking statement both Bindings signed.
    pub statement: String,

    /// Signature from binding_a's private key over the statement.
    pub signature_a: Vec<u8>,

    /// Signature from binding_b's private key over the statement.
    pub signature_b: Vec<u8>,

    /// Random nonce for replay protection.
    pub nonce: String,

    /// Whether either Binding alone can revoke the link later.
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

/// Revocation of the link between two Bindings at one recipient, signed by
/// either of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossInstanceLinkRevocation {
    pub binding_a: BindingId,
    pub binding_b: BindingId,
    pub recipient_org: OrgId,

    /// Reason for revocation, e.g. "user_requested" or "binding_revoked".
    pub reason: String,

    /// Signature from the signing Binding's private key over
    /// [`revocation_statement`].
    pub signature: Vec<u8>,

    /// Which of the two Bindings signed.
    pub signing_binding: BindingId,

    pub created_at: DateTime<Utc>,
}

/// Why a link record was not built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkingError {
    /// The signing Binding is not one of the two linked Bindings.
    #[error("the signing Binding is not a party to the link")]
    NotAParty,
}

/// One line per fixed-format field; UUIDs and an RFC 3339 time contain no
/// newline, and the trailing free text is length-prefixed.
fn statement(prefix: &str, fields: &[String], text: &str) -> String {
    let mut out = String::from(prefix);
    for field in fields {
        out.push('\n');
        out.push_str(field);
    }
    out.push('\n');
    out.push_str(&text.len().to_string());
    out.push(':');
    out.push_str(text);
    out
}

/// The exact text form of a time, every fractional digit included, so two
/// distinct times never share it.
fn time(at: &DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

/// Build the canonical linking statement both Bindings sign: both Bindings,
/// the recipient OrgId, the creation time, the revocable flag and the nonce.
pub fn build_linking_statement(
    binding_a: &BindingId,
    binding_b: &BindingId,
    recipient_org: &OrgId,
    created_at: &DateTime<Utc>,
    revocable: bool,
    nonce: &str,
) -> String {
    statement(
        LINKING_STATEMENT_PREFIX,
        &[
            binding_a.to_string(),
            binding_b.to_string(),
            recipient_org.to_string(),
            time(created_at),
            u8::from(revocable).to_string(),
        ],
        nonce,
    )
}

/// Create a linking proof from components both Bindings signed externally
/// over [`build_linking_statement`] of the same values.
#[allow(clippy::too_many_arguments)]
pub fn create_linking_proof(
    binding_a: BindingId,
    binding_b: BindingId,
    recipient_org: OrgId,
    created_at: DateTime<Utc>,
    revocable: bool,
    nonce: String,
    signature_a: Vec<u8>,
    signature_b: Vec<u8>,
) -> CrossInstanceLinkingProof {
    let statement = build_linking_statement(
        &binding_a,
        &binding_b,
        &recipient_org,
        &created_at,
        revocable,
        &nonce,
    );
    CrossInstanceLinkingProof {
        binding_a,
        binding_b,
        recipient_org,
        statement,
        signature_a,
        signature_b,
        nonce,
        revocable,
        created_at,
    }
}

/// Whether a proof's statement is exactly the one its fields produce.
///
/// This checks the statement only; signature verification needs the
/// Bindings' certificates (the caller's responsibility).
pub fn verify_proof_statement(proof: &CrossInstanceLinkingProof) -> bool {
    proof.statement
        == build_linking_statement(
            &proof.binding_a,
            &proof.binding_b,
            &proof.recipient_org,
            &proof.created_at,
            proof.revocable,
            &proof.nonce,
        )
}

/// Whether a proof is for the recipient organization `expected`.
pub fn verify_proof_recipient(proof: &CrossInstanceLinkingProof, expected: &OrgId) -> bool {
    proof.recipient_org == *expected
}

/// The statement the signing Binding signs to revoke a link.
pub fn revocation_statement(revocation: &CrossInstanceLinkRevocation) -> String {
    statement(
        UNLINKING_STATEMENT_PREFIX,
        &[
            revocation.binding_a.to_string(),
            revocation.binding_b.to_string(),
            revocation.recipient_org.to_string(),
            revocation.signing_binding.to_string(),
            time(&revocation.created_at),
        ],
        &revocation.reason,
    )
}

/// Create a revocation signed by `signing_binding`, which must be one of the
/// two linked Bindings.
pub fn create_link_revocation(
    binding_a: BindingId,
    binding_b: BindingId,
    recipient_org: OrgId,
    signing_binding: BindingId,
    reason: String,
    created_at: DateTime<Utc>,
    signature: Vec<u8>,
) -> Result<CrossInstanceLinkRevocation, LinkingError> {
    if signing_binding != binding_a && signing_binding != binding_b {
        return Err(LinkingError::NotAParty);
    }
    Ok(CrossInstanceLinkRevocation {
        binding_a,
        binding_b,
        recipient_org,
        reason,
        signature,
        signing_binding,
        created_at,
    })
}

#[cfg(test)]
mod tests;
