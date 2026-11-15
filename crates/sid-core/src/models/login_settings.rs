// SPDX-License-Identifier: AGPL-3.0-only
//! The login settings of the organization an installation serves.

use serde::{Deserialize, Serialize};

use super::OrgId;

/// How many source organizations the settings may admit: keeps the stored
/// record, and a signed copy of it, within one bounded message.
pub const MAX_ADMITTED_SOURCES: usize = 1024;

/// The organizations whose Corporate Profiles the recipient admits: sorted
/// by id, each once, at most [`MAX_ADMITTED_SOURCES`]. Empty admits none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<OrgId>", into = "Vec<OrgId>")]
pub struct AdmittedSources(Vec<OrgId>);

/// More source organizations than the settings may admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("at most {MAX_ADMITTED_SOURCES} source organizations are admitted")]
pub struct TooManySources;

/// Stored bytes that are not a list of organization ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("stored admitted sources are not a list of organization ids")]
pub struct MalformedSources;

impl AdmittedSources {
    /// The admitted organizations, in id order.
    pub fn as_slice(&self) -> &[OrgId] {
        &self.0
    }

    /// Whether `source` is admitted.
    pub fn contains(&self, source: OrgId) -> bool {
        self.0.binary_search(&source).is_ok()
    }

    /// The ids one after another, 16 bytes each, in id order: the stored form
    /// of a backend without an array type.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|id| *id.as_bytes()).collect()
    }

    /// The set stored as [`Self::to_bytes`] wrote it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MalformedSources> {
        let (ids, rest) = bytes.as_chunks::<16>();
        if !rest.is_empty() {
            return Err(MalformedSources);
        }
        let ids = ids
            .iter()
            .map(|id| OrgId::from_bytes(*id).map_err(|_| MalformedSources))
            .collect::<Result<Vec<_>, _>>()?;
        Self::try_from(ids).map_err(|_| MalformedSources)
    }
}

impl TryFrom<Vec<OrgId>> for AdmittedSources {
    type Error = TooManySources;

    /// `sources` in id order with repeats counted once.
    fn try_from(mut sources: Vec<OrgId>) -> Result<Self, TooManySources> {
        sources.sort_unstable();
        sources.dedup();
        if sources.len() > MAX_ADMITTED_SOURCES {
            return Err(TooManySources);
        }
        Ok(Self(sources))
    }
}

impl From<AdmittedSources> for Vec<OrgId> {
    fn from(sources: AdmittedSources) -> Self {
        sources.0
    }
}

/// Whose identity a verified Binding Passport certifies, seen from the
/// recipient organization: one the recipient did not issue. The source is
/// read from the passport after its path was accepted, never from a hint of
/// the caller or the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A Personal Profile: no organization issued it.
    Personal,
    /// A Corporate Profile issued by this other organization.
    Corporate(OrgId),
}

impl Origin {
    /// The origin of an identity whose accepted passport names `source` as
    /// its issuing organization, at the recipient organization `recipient`;
    /// `None` for one the recipient issued itself, which is not an outside
    /// identity and is governed by no incoming setting.
    pub fn of(source: Option<OrgId>, recipient: OrgId) -> Option<Self> {
        match source {
            None => Some(Self::Personal),
            Some(source) if source == recipient => None,
            Some(source) => Some(Self::Corporate(source)),
        }
    }
}

/// Which incoming external identities the organization, as the recipient of
/// a federated sign-in, admits. The two kinds are independent, and incoming
/// federated sign-in is available when either is on. Both concern the
/// sign-in of an existing external identity: neither is a registration mode
/// or federation enrollment, and a Profile the organization issued itself is
/// governed by neither. Off until an administrator turns them on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSettings {
    /// Personal Profiles are admitted.
    pub allow_personal_profiles: bool,
    /// Corporate Profiles issued by other organizations are admitted, from
    /// the organizations in `admitted_sources` only.
    pub allow_foreign_corporate_profiles: bool,
    /// The organizations whose Corporate Profiles are admitted while
    /// `allow_foreign_corporate_profiles` is on. Admission is a sign-in
    /// decision: it gives no role or permission.
    pub admitted_sources: AdmittedSources,
    /// What must be known of withdrawals before an admitted identity's
    /// Binding Passport is relied on. Admission and this are separate
    /// decisions: the policy admits nobody, and a missing list never makes
    /// the installation more permissive than the policy stored here.
    pub status_policy: super::StatusPolicy,
    /// The number of the change that left these settings: 1 after the first.
    pub revision: u64,
}

impl LoginSettings {
    /// Whether any incoming federated sign-in is admitted: derived, never
    /// stored.
    pub const fn admits_federated_sign_in(&self) -> bool {
        self.allow_personal_profiles || self.allow_foreign_corporate_profiles
    }

    /// Whether a Corporate Profile issued by `source`, another organization,
    /// is admitted: the kind is on and that organization is named.
    pub fn admits_corporate_of(&self, source: OrgId) -> bool {
        self.allow_foreign_corporate_profiles && self.admitted_sources.contains(source)
    }

    /// Whether an outside identity of `origin` is admitted. The two kinds
    /// are decided independently: neither switch stands in for the other.
    pub fn admits(&self, origin: Origin) -> bool {
        match origin {
            Origin::Personal => self.allow_personal_profiles,
            Origin::Corporate(source) => self.admits_corporate_of(source),
        }
    }
}

#[cfg(test)]
mod tests;
