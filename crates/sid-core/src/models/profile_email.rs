// SPDX-License-Identifier: AGPL-3.0-only
//! Multi-valued email contact for a Profile.
//!
//! Replaces scalar `Profile.email` / `Profile.email_verified` with a 1:N table.
//!
//! See: `arch/identity/contact-model.md`

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Unique identifier for a profile email entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileEmailId(pub Uuid);

impl ProfileEmailId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ProfileEmailId {
    fn default() -> Self {
        Self::new()
    }
}

/// An email address associated with a profile.
///
/// The validated mailbox in the spelling given (local-part case, dots and
/// `+tag` preserved; the domain in its canonical ASCII form): the address
/// mail goes to. A login handle's resolution key is the principal's, never
/// this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEmail {
    pub id: ProfileEmailId,
    pub profile_id: ProfileId,

    /// The validated email address, its local-part spelling preserved.
    pub email: String,

    /// Label from predefined set or custom.
    pub label: EmailLabel,

    /// User-defined label text. Only used when `label == EmailLabel::Custom`.
    pub custom_label: Option<String>,

    /// At most one email per profile can be primary.
    /// Primary email is used for OIDC `email` claim.
    pub is_primary: bool,

    /// Whether email ownership has been verified (e.g., email OTP).
    pub verified: bool,

    /// When verification was last confirmed.
    pub verified_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The owner's edit of an email's label: each field given replaces the
/// stored one. The address, its verification and the primary flag never
/// change here.
#[derive(Debug, Clone, Default)]
pub struct EmailSettings {
    pub label: Option<EmailLabel>,
    /// `Some(None)` clears the custom label.
    pub custom_label: Option<Option<String>>,
}

/// Predefined email label types (matches SCIM `type` + vCard `TYPE`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailLabel {
    #[default]
    Personal,
    Work,
    School,
    Other,
    /// User-defined label. `ProfileEmail.custom_label` holds the text.
    Custom,
}

impl EmailLabel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Personal => "personal",
            Self::Work => "work",
            Self::School => "school",
            Self::Other => "other",
            Self::Custom => "custom",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "personal" | "home" => Self::Personal,
            "work" => Self::Work,
            "school" => Self::School,
            "other" => Self::Other,
            "custom" => Self::Custom,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_label_roundtrip() {
        for label in [
            EmailLabel::Personal,
            EmailLabel::Work,
            EmailLabel::School,
            EmailLabel::Other,
            EmailLabel::Custom,
        ] {
            let s = label.as_str();
            let parsed = EmailLabel::from_str_lossy(s);
            assert_eq!(parsed, label);
        }
    }

    #[test]
    fn test_email_label_scim_home_maps_to_personal() {
        assert_eq!(EmailLabel::from_str_lossy("home"), EmailLabel::Personal);
    }

    #[test]
    fn test_email_label_serde() {
        let json = serde_json::to_string(&EmailLabel::Work).unwrap();
        assert_eq!(json, r#""work""#);
        let parsed: EmailLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EmailLabel::Work);
    }

    #[test]
    fn test_profile_email_id_unique() {
        let a = ProfileEmailId::new();
        let b = ProfileEmailId::new();
        assert_ne!(a, b);
    }
}
