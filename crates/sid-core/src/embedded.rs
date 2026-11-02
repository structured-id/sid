// SPDX-License-Identifier: AGPL-3.0-only
//! Embedded hub and device configuration types.
//!
//! Supports two deployment profiles:
//! - `embedded-hub`: SQLite-backed hub with RBAC and upstream sync (~5-8 MB)
//! - `device-auth`: Minimal token validation only (~1-2 MB)
//!
//! Feature flags control compile-time exclusion of unused code.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ────────────────── Configuration ──────────────────

/// Top-level embedded hub configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedConfig {
    /// Storage backend settings.
    pub storage: EmbeddedStorageConfig,
    /// Upstream sync settings.
    pub upstream: UpstreamSyncConfig,
    /// Local RBAC configuration.
    pub local_rbac: LocalRbacConfig,
    /// Device fleet management.
    pub device_fleet: DeviceFleetConfig,
}

/// Embedded storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedStorageConfig {
    /// Storage backend type.
    pub backend: EmbeddedBackendType,
    /// Database file path (SQLite).
    pub path: String,
    /// Enable WAL mode for concurrent reads.
    pub wal_mode: bool,
    /// Maximum database size in MB (alert threshold).
    pub max_size_mb: u64,
}

impl Default for EmbeddedStorageConfig {
    fn default() -> Self {
        Self {
            backend: EmbeddedBackendType::Sqlite,
            path: "/var/lib/sid/hub.db".to_string(),
            wal_mode: true,
            max_size_mb: 512,
        }
    }
}

/// Embedded storage backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedBackendType {
    Sqlite,
}

/// Upstream synchronization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamSyncConfig {
    /// Upstream SID instance URL.
    pub url: String,
    /// Sync interval in seconds.
    pub sync_interval_secs: u64,
    /// Offline grace period in seconds (default: 72h = 259200).
    pub offline_grace_period_secs: u64,
}

impl Default for UpstreamSyncConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            sync_interval_secs: 300,           // 5 minutes
            offline_grace_period_secs: 259200, // 72 hours
        }
    }
}

impl UpstreamSyncConfig {
    /// Default offline grace period (72 hours).
    pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 259200;
}

/// Local RBAC configuration (hub-specific roles, not synced from upstream).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalRbacConfig {
    /// Role definitions.
    pub roles: Vec<RoleDefinition>,
}

/// A role definition for local RBAC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// Role name.
    pub name: String,
    /// Permissions granted by this role.
    pub permissions: Vec<String>,
}

/// Device fleet management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFleetConfig {
    /// Maximum number of managed devices.
    pub max_devices: u32,
    /// Auto-enroll new devices on first connection.
    pub auto_enroll: bool,
    /// Credential TTL in seconds.
    pub credential_ttl_secs: u64,
    /// Credential rotation window in seconds.
    pub rotation_window_secs: u64,
}

impl Default for DeviceFleetConfig {
    fn default() -> Self {
        Self {
            max_devices: 1000,
            auto_enroll: false,
            credential_ttl_secs: 86400 * 30, // 30 days
            rotation_window_secs: 86400 * 7, // 7 days before expiry
        }
    }
}

// ────────────────── Profile Types ──────────────────

/// Embedded hub profile type (simplified from full SID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HubProfileType {
    /// IoT device.
    Device,
    /// Human operator.
    Operator,
    /// Hub administrator.
    Admin,
}

/// Embedded credential type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedCredentialType {
    /// X.509 client certificate.
    ClientCert,
    /// Bearer token (JWT or opaque).
    Token,
    /// Pre-shared key.
    Psk,
}

// ────────────────── Upstream Cache ──────────────────

/// Cached data from upstream SID instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamCacheEntry {
    /// Cache key (e.g., "crl", "ca_pubkeys", "policies").
    pub key: String,
    /// Cached value (JSON-encoded).
    pub value: String,
    /// When this entry was fetched from upstream.
    pub fetched_at: DateTime<Utc>,
    /// When this entry expires.
    pub expires_at: DateTime<Utc>,
}

impl UpstreamCacheEntry {
    pub fn new(key: impl Into<String>, value: impl Into<String>, ttl_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            key: key.into(),
            value: value.into(),
            fetched_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        }
    }

    /// Whether this cache entry has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Whether this entry is within the grace period.
    pub fn is_within_grace(&self, grace_secs: u64) -> bool {
        let grace_deadline = self.expires_at + chrono::Duration::seconds(grace_secs as i64);
        Utc::now() <= grace_deadline
    }
}

// ────────────────── Offline Status ──────────────────

/// Offline status of the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineStatus {
    /// Connected to upstream, operating normally.
    Online,
    /// Disconnected but within grace period.
    OfflineGrace,
    /// Disconnected and grace period expired.
    OfflineExpired,
}

/// Hub connectivity and sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubSyncState {
    /// Current offline status.
    pub status: OfflineStatus,
    /// Last successful sync time.
    pub last_sync: Option<DateTime<Utc>>,
    /// Number of consecutive sync failures.
    pub consecutive_failures: u32,
    /// Pending changes to push to upstream.
    pub pending_changes: u64,
}

impl HubSyncState {
    /// Create initial sync state (not yet synced).
    pub fn new() -> Self {
        Self {
            status: OfflineStatus::OfflineExpired,
            last_sync: None,
            consecutive_failures: 0,
            pending_changes: 0,
        }
    }

    /// Record a successful sync.
    pub fn record_sync_success(&mut self) {
        self.status = OfflineStatus::Online;
        self.last_sync = Some(Utc::now());
        self.consecutive_failures = 0;
    }

    /// Record a sync failure.
    pub fn record_sync_failure(&mut self, grace_period_secs: u64) {
        self.consecutive_failures += 1;
        self.status = match self.last_sync {
            Some(last) => {
                let elapsed = (Utc::now() - last).num_seconds() as u64;
                if elapsed <= grace_period_secs {
                    OfflineStatus::OfflineGrace
                } else {
                    OfflineStatus::OfflineExpired
                }
            }
            None => OfflineStatus::OfflineExpired,
        };
    }

    /// Whether new device enrollments should be blocked.
    pub fn should_block_new_enrollments(&self) -> bool {
        self.status == OfflineStatus::OfflineExpired
    }
}

impl Default for HubSyncState {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────── Local Audit ──────────────────

/// Local audit entry (simplified, no tamper-evidence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuditEntry {
    /// Sequential ID.
    pub id: u64,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Actor who performed the action.
    pub actor_id: String,
    /// Action performed.
    pub action: String,
    /// Target of the action.
    pub target: Option<String>,
    /// Additional detail (JSON).
    pub detail: Option<HashMap<String, String>>,
}

impl LocalAuditEntry {
    pub fn new(id: u64, actor_id: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            id,
            timestamp: Utc::now(),
            actor_id: actor_id.into(),
            action: action.into(),
            target: None,
            detail: None,
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.detail
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }
}

// ────────────────── Device Registration ──────────────────

/// Device registration record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    /// Unique device ID.
    pub device_id: Uuid,
    /// Device name/label.
    pub name: String,
    /// Profile type.
    pub profile_type: HubProfileType,
    /// Credential type used.
    pub credential_type: EmbeddedCredentialType,
    /// When the device was enrolled.
    pub enrolled_at: DateTime<Utc>,
    /// When the credential expires.
    pub credential_expires_at: Option<DateTime<Utc>>,
    /// Whether the device is active.
    pub active: bool,
}

impl DeviceRegistration {
    pub fn new(
        name: impl Into<String>,
        profile_type: HubProfileType,
        credential_type: EmbeddedCredentialType,
    ) -> Self {
        Self {
            device_id: Uuid::new_v4(),
            name: name.into(),
            profile_type,
            credential_type,
            enrolled_at: Utc::now(),
            credential_expires_at: None,
            active: true,
        }
    }

    /// Whether the credential has expired.
    pub fn is_credential_expired(&self) -> bool {
        self.credential_expires_at
            .is_some_and(|exp| Utc::now() > exp)
    }

    /// Whether this device needs credential rotation.
    pub fn needs_rotation(&self, rotation_window_secs: u64) -> bool {
        match self.credential_expires_at {
            Some(exp) => {
                let rotate_at = exp - chrono::Duration::seconds(rotation_window_secs as i64);
                Utc::now() >= rotate_at
            }
            None => false,
        }
    }

    /// Deactivate the device.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_storage_config() {
        let config = EmbeddedStorageConfig::default();
        assert_eq!(config.backend, EmbeddedBackendType::Sqlite);
        assert!(config.wal_mode);
        assert_eq!(config.max_size_mb, 512);
    }

    #[test]
    fn test_default_upstream_sync_config() {
        let config = UpstreamSyncConfig::default();
        assert_eq!(config.offline_grace_period_secs, 259200); // 72h
        assert_eq!(config.sync_interval_secs, 300);
    }

    #[test]
    fn test_default_device_fleet_config() {
        let config = DeviceFleetConfig::default();
        assert_eq!(config.max_devices, 1000);
        assert!(!config.auto_enroll);
    }

    #[test]
    fn test_upstream_cache_entry() {
        let entry = UpstreamCacheEntry::new("crl", "{}", 3600);
        assert!(!entry.is_expired());
        assert!(entry.is_within_grace(3600));
    }

    #[test]
    fn test_upstream_cache_expired() {
        let mut entry = UpstreamCacheEntry::new("crl", "{}", 3600);
        // Simulate expiry
        entry.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(entry.is_expired());
        // But within grace
        assert!(entry.is_within_grace(3600));
    }

    #[test]
    fn test_hub_sync_state_new() {
        let state = HubSyncState::new();
        assert_eq!(state.status, OfflineStatus::OfflineExpired);
        assert!(state.last_sync.is_none());
        assert!(state.should_block_new_enrollments());
    }

    #[test]
    fn test_hub_sync_success() {
        let mut state = HubSyncState::new();
        state.record_sync_success();
        assert_eq!(state.status, OfflineStatus::Online);
        assert!(state.last_sync.is_some());
        assert!(!state.should_block_new_enrollments());
    }

    #[test]
    fn test_hub_sync_failure_within_grace() {
        let mut state = HubSyncState::new();
        state.record_sync_success();
        state.record_sync_failure(259200); // 72h grace
        assert_eq!(state.status, OfflineStatus::OfflineGrace);
        assert!(!state.should_block_new_enrollments());
    }

    #[test]
    fn test_device_registration() {
        let device = DeviceRegistration::new(
            "sensor-001",
            HubProfileType::Device,
            EmbeddedCredentialType::ClientCert,
        );
        assert!(device.active);
        assert!(!device.is_credential_expired());
    }

    #[test]
    fn test_device_deactivation() {
        let mut device = DeviceRegistration::new(
            "sensor-002",
            HubProfileType::Device,
            EmbeddedCredentialType::Psk,
        );
        device.deactivate();
        assert!(!device.active);
    }

    #[test]
    fn test_device_credential_expiry() {
        let mut device = DeviceRegistration::new(
            "sensor-003",
            HubProfileType::Device,
            EmbeddedCredentialType::Token,
        );
        device.credential_expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(device.is_credential_expired());
    }

    #[test]
    fn test_device_needs_rotation() {
        let mut device = DeviceRegistration::new(
            "sensor-004",
            HubProfileType::Device,
            EmbeddedCredentialType::ClientCert,
        );
        // Expires in 3 days, rotation window is 7 days → needs rotation
        device.credential_expires_at = Some(Utc::now() + chrono::Duration::days(3));
        assert!(device.needs_rotation(7 * 86400));
    }

    #[test]
    fn test_local_audit_entry() {
        let entry = LocalAuditEntry::new(1, "admin", "device.enroll")
            .with_target("sensor-001")
            .with_detail("ip", "192.168.1.100");
        assert_eq!(entry.action, "device.enroll");
        assert_eq!(entry.target.as_deref(), Some("sensor-001"));
        assert!(entry.detail.unwrap().contains_key("ip"));
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = EmbeddedConfig {
            storage: EmbeddedStorageConfig::default(),
            upstream: UpstreamSyncConfig::default(),
            local_rbac: LocalRbacConfig {
                roles: vec![RoleDefinition {
                    name: "operator".to_string(),
                    permissions: vec!["device:read".to_string(), "device:control".to_string()],
                }],
            },
            device_fleet: DeviceFleetConfig::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: EmbeddedConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.local_rbac.roles.len(), 1);
        assert_eq!(parsed.local_rbac.roles[0].permissions.len(), 2);
    }

    #[test]
    fn test_offline_status_serde() {
        let statuses = vec![
            OfflineStatus::Online,
            OfflineStatus::OfflineGrace,
            OfflineStatus::OfflineExpired,
        ];
        for s in statuses {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: OfflineStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn test_hub_profile_type_serde() {
        let types = vec![
            HubProfileType::Device,
            HubProfileType::Operator,
            HubProfileType::Admin,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let parsed: HubProfileType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, t);
        }
    }

    #[test]
    fn test_credential_type_serde() {
        let types = vec![
            EmbeddedCredentialType::ClientCert,
            EmbeddedCredentialType::Token,
            EmbeddedCredentialType::Psk,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let parsed: EmbeddedCredentialType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, t);
        }
    }
}
