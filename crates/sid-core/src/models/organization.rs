// SPDX-License-Identifier: AGPL-3.0-only
//! Organizations: every structural formation, as opposed to an individual
//! user.
//!
//! Every deployment has at least one. A CE installation is a single implicit
//! Community organization created at first boot.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use sid_ids::OrgId;

/// Kind of organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgType {
    /// Personal relationships with guardian semantics (SaaS only).
    Family,
    /// Non-commercial: communities, personal sites, a CE installation.
    Community,
    /// Enterprise, active with an EE license.
    Commercial,
    /// Commercial with regulated capabilities.
    Government,
}

impl OrgType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Family => "family",
            Self::Community => "community",
            Self::Commercial => "commercial",
            Self::Government => "government",
        }
    }
}

parse_stored!(
    OrgType,
    "organization type",
    [Family, Community, Commercial, Government]
);

/// Lifecycle state of an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgStatus {
    /// Waiting for domain verification.
    PendingDns,
    /// Government stub waiting for its official claim.
    PendingClaim,
    /// Commercial 30-day trial after DNS verification.
    ActiveTrial,
    Active,
    Suspended,
    /// Data deletion in progress.
    Deprovisioning,
    /// Record kept for audit.
    Deleted,
}

impl OrgStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingDns => "pending_dns",
            Self::PendingClaim => "pending_claim",
            Self::ActiveTrial => "active_trial",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deprovisioning => "deprovisioning",
            Self::Deleted => "deleted",
        }
    }
}

parse_stored!(
    OrgStatus,
    "organization status",
    [
        PendingDns,
        PendingClaim,
        ActiveTrial,
        Active,
        Suspended,
        Deprovisioning,
        Deleted
    ]
);

/// An organization. `id` never changes; domains, including the canonical
/// one, may.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrgId,
    pub org_type: OrgType,
    pub status: OrgStatus,
    /// The domain shown in binding certificates; never part of identity.
    pub canonical_domain: String,
    pub created_at: DateTime<Utc>,
}

impl Organization {
    /// The implicit Community organization of a CE installation, active from
    /// first boot, with the instance's domain as canonical domain.
    pub fn implicit_community(canonical_domain: impl Into<String>) -> Self {
        Self {
            id: OrgId::generate(),
            org_type: OrgType::Community,
            status: OrgStatus::Active,
            canonical_domain: canonical_domain.into(),
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests;
