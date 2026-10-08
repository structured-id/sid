// SPDX-License-Identifier: AGPL-3.0-only
//! Multi-valued phone contact for a Profile.
//!
//! Replaces scalar `Profile.phone` / `Profile.phone_verified` with a 1:N table.
//! Phone number stored as BIGINT e164 (digits only, no `+`).
//! Extension stored as INTEGER (digits only).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Unique identifier for a profile phone entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfilePhoneId(pub Uuid);

impl ProfilePhoneId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ProfilePhoneId {
    fn default() -> Self {
        Self::new()
    }
}

/// A phone number associated with a profile.
///
/// E.164 number stored as digits (BIGINT), formatted with `+` prefix at display/serialization time.
/// Extension stored separately from the main number (RFC 3966 `;ext=N`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePhone {
    pub id: ProfilePhoneId,
    pub profile_id: ProfileId,

    /// E.164 number as digits only (no `+`). Example: `380501234567`.
    pub e164: u64,

    /// Phone extension (RFC 3966). Example: `5678`. Stored separately for clean indexing.
    pub extension: Option<u32>,

    /// Label from predefined set or custom.
    pub label: PhoneLabel,

    /// User-defined label text. Only used when `label == PhoneLabel::Custom`.
    pub custom_label: Option<String>,

    /// At most one phone per profile can be primary.
    /// Primary phone is used for OIDC `phone_number` claim.
    pub is_primary: bool,

    /// Phone accepts SMS delivery. Verifiable through OTP.
    pub can_receive_sms: bool,

    /// Phone accepts fax delivery. User declaration (not verifiable).
    pub can_receive_fax: bool,

    /// Phone accepts voice calls. User declaration.
    pub can_receive_voice: bool,

    /// Whether phone ownership has been verified (e.g., SMS OTP).
    pub verified: bool,

    /// When verification was last confirmed.
    pub verified_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The owner's edit of a phone's settings: each field given replaces the
/// stored one. The number, its verification and the primary flag are not
/// settings and never change here.
#[derive(Debug, Clone, Default)]
pub struct PhoneSettings {
    pub label: Option<PhoneLabel>,
    /// `Some(None)` clears the custom label.
    pub custom_label: Option<Option<String>>,
    pub can_receive_sms: Option<bool>,
    pub can_receive_fax: Option<bool>,
    pub can_receive_voice: Option<bool>,
}

impl ProfilePhone {
    /// Format the phone number for OIDC `phone_number` claim (E.164 with optional extension).
    ///
    /// Returns `+{e164}` or `+{e164};ext={extension}` per RFC 3966.
    pub fn formatted_e164(&self) -> String {
        match self.extension {
            Some(ext) => format!("+{};ext={}", self.e164, ext),
            None => format!("+{}", self.e164),
        }
    }
}

/// Predefined phone label types (matches SCIM `type` + vCard `TYPE` + Apple Contacts).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhoneLabel {
    #[default]
    Mobile,
    Home,
    Work,
    Fax,
    Pager,
    Main,
    Other,
    /// User-defined label. `ProfilePhone.custom_label` holds the text.
    Custom,
}

impl PhoneLabel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Mobile => "mobile",
            Self::Home => "home",
            Self::Work => "work",
            Self::Fax => "fax",
            Self::Pager => "pager",
            Self::Main => "main",
            Self::Other => "other",
            Self::Custom => "custom",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mobile" | "cell" => Self::Mobile,
            "home" => Self::Home,
            "work" => Self::Work,
            "fax" => Self::Fax,
            "pager" => Self::Pager,
            "main" => Self::Main,
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
    fn test_formatted_e164_without_extension() {
        let phone = ProfilePhone {
            id: ProfilePhoneId::new(),
            profile_id: ProfileId::generate(),
            e164: 380501234567,
            extension: None,
            label: PhoneLabel::Mobile,
            custom_label: None,
            is_primary: true,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
            verified: true,
            verified_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(phone.formatted_e164(), "+380501234567");
    }

    #[test]
    fn test_formatted_e164_with_extension() {
        let phone = ProfilePhone {
            id: ProfilePhoneId::new(),
            profile_id: ProfileId::generate(),
            e164: 14185551234,
            extension: Some(102),
            label: PhoneLabel::Work,
            custom_label: None,
            is_primary: false,
            can_receive_sms: false,
            can_receive_fax: true,
            can_receive_voice: true,
            verified: false,
            verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(phone.formatted_e164(), "+14185551234;ext=102");
    }

    #[test]
    fn test_phone_label_roundtrip() {
        for label in [
            PhoneLabel::Mobile,
            PhoneLabel::Home,
            PhoneLabel::Work,
            PhoneLabel::Fax,
            PhoneLabel::Pager,
            PhoneLabel::Main,
            PhoneLabel::Other,
            PhoneLabel::Custom,
        ] {
            let s = label.as_str();
            let parsed = PhoneLabel::from_str_lossy(s);
            assert_eq!(parsed, label);
        }
    }

    #[test]
    fn test_phone_label_from_scim_type() {
        assert_eq!(PhoneLabel::from_str_lossy("cell"), PhoneLabel::Mobile);
        assert_eq!(PhoneLabel::from_str_lossy("WORK"), PhoneLabel::Work);
        assert_eq!(PhoneLabel::from_str_lossy("unknown"), PhoneLabel::Other);
    }

    #[test]
    fn test_phone_label_serde() {
        let json = serde_json::to_string(&PhoneLabel::Mobile).unwrap();
        assert_eq!(json, r#""mobile""#);
        let parsed: PhoneLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PhoneLabel::Mobile);
    }

    #[test]
    fn test_profile_phone_id_unique() {
        let a = ProfilePhoneId::new();
        let b = ProfilePhoneId::new();
        assert_ne!(a, b);
    }
}
