// SPDX-License-Identifier: AGPL-3.0-only
//! Device domain model.
//!
//! Tracks known devices per profile for trust management,
//! anomaly detection, and session scoping.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ProfileId;

/// Validated UUIDv7 identifier of a device; construction and decoding go through `sid_ids`.
pub use sid_ids::DeviceId;

/// Device type classification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Desktop or laptop browser.
    #[default]
    Desktop,
    /// Mobile phone or tablet.
    Mobile,
    /// Headless browser or API client.
    Browser,
    /// IoT device (smart lock, terminal).
    Iot,
    /// Embedded system (POS terminal, kiosk).
    Embedded,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
            Self::Browser => "browser",
            Self::Iot => "iot",
            Self::Embedded => "embedded",
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Device assurance level — how much the system trusts this device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAssurance {
    /// Never seen before or unverified.
    #[default]
    Unknown,
    /// Seen before, device fingerprint matches.
    Recognized,
    /// User explicitly trusted this device.
    Trusted,
    /// Managed by organization (MDM-enrolled).
    Managed,
}

impl DeviceAssurance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Recognized => "recognized",
            Self::Trusted => "trusted",
            Self::Managed => "managed",
        }
    }

    /// Minimum assurance for skipping step-up on sensitive operations.
    pub fn satisfies_step_up(&self) -> bool {
        matches!(self, Self::Trusted | Self::Managed)
    }
}

parse_stored!(
    DeviceType,
    "device type",
    [Desktop, Mobile, Browser, Iot, Embedded]
);
parse_stored!(
    DeviceAssurance,
    "device assurance",
    [Unknown, Recognized, Trusted, Managed]
);

impl std::fmt::Display for DeviceAssurance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Known device associated with a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub profile_id: ProfileId,

    /// User-provided label (e.g., "iPhone 15 Pro", "Work Laptop").
    pub display_name: Option<String>,

    pub device_type: DeviceType,

    /// Operating system (e.g., "macOS 15", "iOS 18", "Windows 11").
    pub os_info: Option<String>,

    /// Device assurance level.
    pub assurance: DeviceAssurance,

    /// Whether the user explicitly trusted this device
    /// (e.g., "remember this device" checkbox).
    pub trusted: bool,

    /// Whether hardware attestation was verified.
    pub hardware_attested: bool,

    /// Opaque fingerprint for device recognition.
    /// Not stored in plaintext — hashed or encrypted.
    pub fingerprint_hash: Option<String>,

    /// Last known geographic location (country/region).
    /// NOT the exact IP — used for anomaly detection.
    pub last_ip_geo: Option<String>,

    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl Device {
    pub fn new(profile_id: ProfileId, device_type: DeviceType) -> Self {
        let now = Utc::now();
        Self {
            id: DeviceId::generate(),
            profile_id,
            display_name: None,
            device_type,
            os_info: None,
            assurance: DeviceAssurance::Unknown,
            trusted: false,
            hardware_attested: false,
            fingerprint_hash: None,
            last_ip_geo: None,
            first_seen_at: now,
            last_seen_at: now,
        }
    }

    /// Record activity — update last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen_at = Utc::now();
    }

    /// Mark as trusted by user.
    pub fn trust(&mut self) {
        self.trusted = true;
        if self.assurance == DeviceAssurance::Unknown
            || self.assurance == DeviceAssurance::Recognized
        {
            self.assurance = DeviceAssurance::Trusted;
        }
        self.last_seen_at = Utc::now();
    }

    /// Revoke trust.
    pub fn revoke_trust(&mut self) {
        self.trusted = false;
        if self.assurance == DeviceAssurance::Trusted {
            self.assurance = DeviceAssurance::Recognized;
        }
        self.last_seen_at = Utc::now();
    }

    /// Days since last activity.
    pub fn days_inactive(&self) -> i64 {
        (Utc::now() - self.last_seen_at).num_days()
    }
}

/// CE hardcoded device policy.
pub const MAX_TRUSTED_DEVICES: usize = 10;
pub const DEVICE_INACTIVITY_DAYS: u32 = 90;

/// The outcome of trusting or distrusting a stored device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTrustChange {
    /// The device's trust changed.
    Changed,
    /// The device already had the requested trust.
    Unchanged,
    /// No such device.
    NotFound,
    /// Its profile already trusts the maximum number of devices.
    LimitReached,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device() -> Device {
        Device::new(ProfileId::generate(), DeviceType::Mobile)
    }

    #[test]
    fn test_device_new_defaults() {
        let d = make_device();
        assert_eq!(d.device_type, DeviceType::Mobile);
        assert_eq!(d.assurance, DeviceAssurance::Unknown);
        assert!(!d.trusted);
        assert!(!d.hardware_attested);
        assert!(d.display_name.is_none());
        assert!(d.os_info.is_none());
        assert!(d.fingerprint_hash.is_none());
        assert!(d.last_ip_geo.is_none());
    }

    #[test]
    fn test_device_trust() {
        let mut d = make_device();
        assert!(!d.trusted);
        assert_eq!(d.assurance, DeviceAssurance::Unknown);

        d.trust();
        assert!(d.trusted);
        assert_eq!(d.assurance, DeviceAssurance::Trusted);
    }

    #[test]
    fn test_device_trust_does_not_downgrade_managed() {
        let mut d = make_device();
        d.assurance = DeviceAssurance::Managed;
        d.trust();
        // Managed stays managed.
        assert_eq!(d.assurance, DeviceAssurance::Managed);
        assert!(d.trusted);
    }

    #[test]
    fn test_device_revoke_trust() {
        let mut d = make_device();
        d.trust();
        assert!(d.trusted);
        assert_eq!(d.assurance, DeviceAssurance::Trusted);

        d.revoke_trust();
        assert!(!d.trusted);
        assert_eq!(d.assurance, DeviceAssurance::Recognized);
    }

    #[test]
    fn test_device_revoke_trust_managed_stays() {
        let mut d = make_device();
        d.assurance = DeviceAssurance::Managed;
        d.trusted = true;
        d.revoke_trust();
        assert!(!d.trusted);
        // Managed doesn't drop to Recognized.
        assert_eq!(d.assurance, DeviceAssurance::Managed);
    }

    #[test]
    fn test_assurance_step_up() {
        assert!(!DeviceAssurance::Unknown.satisfies_step_up());
        assert!(!DeviceAssurance::Recognized.satisfies_step_up());
        assert!(DeviceAssurance::Trusted.satisfies_step_up());
        assert!(DeviceAssurance::Managed.satisfies_step_up());
    }

    #[test]
    fn test_device_touch() {
        let mut d = make_device();
        let before = d.last_seen_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        d.touch();
        assert!(d.last_seen_at >= before);
    }

    #[test]
    fn test_device_type_serde() {
        let t = DeviceType::Embedded;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"embedded\"");
        let parsed: DeviceType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DeviceType::Embedded);
    }

    #[test]
    fn test_device_assurance_serde() {
        let a = DeviceAssurance::Managed;
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"managed\"");
        let parsed: DeviceAssurance = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DeviceAssurance::Managed);
    }

    #[test]
    fn test_device_id_unique() {
        let id1 = DeviceId::generate();
        let id2 = DeviceId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_device_serde_roundtrip() {
        let mut d = make_device();
        d.display_name = Some("iPhone 15".into());
        d.os_info = Some("iOS 18".into());
        d.last_ip_geo = Some("UA/Kyiv".into());
        d.trusted = true;

        let json = serde_json::to_string(&d).unwrap();
        let parsed: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.display_name.as_deref(), Some("iPhone 15"));
        assert_eq!(parsed.os_info.as_deref(), Some("iOS 18"));
        assert_eq!(parsed.last_ip_geo.as_deref(), Some("UA/Kyiv"));
        assert!(parsed.trusted);
    }

    #[test]
    fn test_device_constants() {
        assert_eq!(MAX_TRUSTED_DEVICES, 10);
        assert_eq!(DEVICE_INACTIVITY_DAYS, 90);
    }
}
