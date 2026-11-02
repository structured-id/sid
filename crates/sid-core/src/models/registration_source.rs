// SPDX-License-Identifier: AGPL-3.0-only
//! Registration source tracking.
//!
//! Records how each profile was created — self-signup, invite, admin,
//! SCIM provisioning, federation, or identity brokering. Stored as
//! metadata on the profile for admin analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::profile::ProfileId;

// ── Source type enum ────────────────────────────────────────────

/// How a profile was created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationSourceType {
    /// Self-registration (open mode).
    #[default]
    SelfSignup,
    /// Registration with invite code.
    Invite,
    /// Admin created profile manually.
    AdminCreated,
    /// SCIM provisioning.
    ScimProvisioned,
    /// Federation: an external user linked to this org, known by its
    /// pairwise BindingId.
    Federation,
    /// Identity brokering (upstream IdP).
    IdentityBrokered,
}

impl RegistrationSourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SelfSignup => "self_signup",
            Self::Invite => "invite",
            Self::AdminCreated => "admin_created",
            Self::ScimProvisioned => "scim_provisioned",
            Self::Federation => "federation",
            Self::IdentityBrokered => "identity_brokered",
        }
    }
}

impl std::str::FromStr for RegistrationSourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "self_signup" => Ok(Self::SelfSignup),
            "invite" => Ok(Self::Invite),
            "admin_created" => Ok(Self::AdminCreated),
            "scim_provisioned" => Ok(Self::ScimProvisioned),
            "federation" => Ok(Self::Federation),
            "identity_brokered" => Ok(Self::IdentityBrokered),
            other => Err(format!("unknown registration source type: {other}")),
        }
    }
}

impl std::fmt::Display for RegistrationSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── UTM params ──────────────────────────────────────────────────

/// UTM tracking parameters captured from registration URL.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtmParams {
    pub source: String,
    pub medium: String,
    pub campaign: String,
    pub term: String,
    pub content: String,
}

impl UtmParams {
    /// Check if any UTM parameter is set.
    pub fn is_empty(&self) -> bool {
        self.source.is_empty()
            && self.medium.is_empty()
            && self.campaign.is_empty()
            && self.term.is_empty()
            && self.content.is_empty()
    }
}

// ── Registration source entity ──────────────────────────────────

/// How a profile was created. Stored as metadata on the profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationSource {
    /// Source type.
    pub source_type: RegistrationSourceType,

    /// Raw source identifier.
    /// Format: `invite:{code}`, `scim:{provider}`, `admin:{admin_profile_id}`,
    /// `federation:{idp_id}`, `self:{client_id}`.
    pub source_id: String,

    /// Referrer profile ID (if provided during registration).
    pub referrer_id: Option<ProfileId>,

    /// UTM parameters (if captured from registration URL).
    pub utm: UtmParams,

    /// Client application through which registration occurred.
    pub client_id: Option<String>,

    pub created_at: DateTime<Utc>,
}

impl RegistrationSource {
    /// Create a self-signup source.
    pub fn self_signup(client_id: Option<String>) -> Self {
        Self {
            source_type: RegistrationSourceType::SelfSignup,
            source_id: format!("self:{}", client_id.as_deref().unwrap_or("direct")),
            referrer_id: None,
            utm: UtmParams::default(),
            client_id,
            created_at: Utc::now(),
        }
    }

    /// Create an invite-based source.
    pub fn from_invite(invite_code: &str, client_id: Option<String>) -> Self {
        Self {
            source_type: RegistrationSourceType::Invite,
            source_id: format!("invite:{}", invite_code),
            referrer_id: None,
            utm: UtmParams::default(),
            client_id,
            created_at: Utc::now(),
        }
    }

    /// Create an admin-created source.
    pub fn admin_created(admin_id: ProfileId) -> Self {
        Self {
            source_type: RegistrationSourceType::AdminCreated,
            source_id: format!("admin:{admin_id}"),
            referrer_id: None,
            utm: UtmParams::default(),
            client_id: None,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests;
