// SPDX-License-Identifier: AGPL-3.0-only
//! Notification delivery domain model.
//!
//! Core types for sid-notify integration. Notifications are published
//! to NATS JetStream and consumed by the sid-notify autonomous binary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Unique identifier for a notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NotificationId(pub Uuid);

impl NotificationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for NotificationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Delivery channel for notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    /// Email (SMTP).
    Email,
    /// SMS (via provider API).
    Sms,
    /// Web push notification (RFC 8030).
    WebPush,
    /// In-app push (SID app via FCM/APNs).
    AppPush,
    /// Webhook (HTTP POST to registered URL).
    Webhook,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
            Self::WebPush => "web_push",
            Self::AppPush => "app_push",
            Self::Webhook => "webhook",
        }
    }
}

impl std::fmt::Display for NotificationChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Notification priority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPriority {
    /// Best-effort, may be batched.
    Low,
    /// Normal delivery.
    #[default]
    Normal,
    /// Immediate delivery (MFA codes, security alerts).
    High,
    /// Critical system alerts (breach notification, emergency revocation).
    Critical,
}

impl NotificationPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for NotificationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Delivery status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Queued for delivery.
    #[default]
    Pending,
    /// Sent to provider (in-flight).
    Sent,
    /// Confirmed delivered.
    Delivered,
    /// Delivery failed (all retries exhausted).
    Failed,
    /// Skipped (user opted out of this channel).
    Skipped,
}

impl DeliveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Delivered | Self::Failed | Self::Skipped)
    }
}

impl std::fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Notification request — published to NATS for sid-notify to process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRequest {
    pub id: NotificationId,

    /// Target profile (used to resolve delivery addresses).
    pub profile_id: ProfileId,

    /// Notification type (e.g., "mfa_code", "password_reset", "security_alert").
    pub notification_type: String,

    /// Delivery channel.
    pub channel: NotificationChannel,

    /// Priority level.
    pub priority: NotificationPriority,

    /// Template parameters (JSON key-value pairs for template rendering).
    pub params: std::collections::HashMap<String, String>,

    /// Explicit delivery address (overrides profile lookup).
    /// Used for email confirmation to unverified addresses.
    pub delivery_address: Option<String>,

    pub created_at: DateTime<Utc>,
    /// TTL — notification becomes irrelevant after this time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl NotificationRequest {
    pub fn new(
        profile_id: ProfileId,
        notification_type: impl Into<String>,
        channel: NotificationChannel,
    ) -> Self {
        Self {
            id: NotificationId::new(),
            profile_id,
            notification_type: notification_type.into(),
            channel,
            priority: NotificationPriority::Normal,
            params: std::collections::HashMap::new(),
            delivery_address: None,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    pub fn with_priority(mut self, priority: NotificationPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    pub fn with_delivery_address(mut self, address: impl Into<String>) -> Self {
        self.delivery_address = Some(address.into());
        self
    }

    pub fn with_ttl(mut self, ttl_seconds: i64) -> Self {
        self.expires_at = Some(self.created_at + chrono::Duration::seconds(ttl_seconds));
        self
    }

    /// Whether this notification has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() >= exp)
            .unwrap_or(false)
    }
}

/// Delivery result — recorded after sid-notify processes the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    pub notification_id: NotificationId,
    pub status: DeliveryStatus,

    /// Number of delivery attempts.
    pub attempt_count: u32,

    /// Provider-specific message ID (e.g., SMTP Message-ID, SMS provider ID).
    pub provider_id: Option<String>,

    /// Error message (if failed).
    pub error: Option<String>,

    pub delivered_at: Option<DateTime<Utc>>,
}

impl DeliveryResult {
    pub fn pending(notification_id: NotificationId) -> Self {
        Self {
            notification_id,
            status: DeliveryStatus::Pending,
            attempt_count: 0,
            provider_id: None,
            error: None,
            delivered_at: None,
        }
    }

    pub fn delivered(notification_id: NotificationId, provider_id: impl Into<String>) -> Self {
        Self {
            notification_id,
            status: DeliveryStatus::Delivered,
            attempt_count: 1,
            provider_id: Some(provider_id.into()),
            error: None,
            delivered_at: Some(Utc::now()),
        }
    }

    pub fn failed(
        notification_id: NotificationId,
        error: impl Into<String>,
        attempts: u32,
    ) -> Self {
        Self {
            notification_id,
            status: DeliveryStatus::Failed,
            attempt_count: attempts,
            provider_id: None,
            error: Some(error.into()),
            delivered_at: None,
        }
    }
}

/// CE hardcoded notification policy.
/// Retry schedule: immediate, 1s, 5s, 30s, 2m, 10m, 1h → DLQ.
pub const MAX_RETRY_ATTEMPTS: u32 = 7;
pub const MFA_CODE_TTL_SECONDS: i64 = 600; // 10 minutes

// ── Delivery Preferences ──────────────────────────────────────

/// Notification category for preference control.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationCategory {
    /// Security alerts: new login, password change, MFA change.
    /// MANDATORY — cannot be disabled by user.
    SecurityAlerts,
    /// Login notifications: successful login from new device.
    LoginNotifications,
    /// Session expiry reminders.
    SessionReminders,
    /// Product updates, feature announcements.
    Marketing,
}

impl NotificationCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SecurityAlerts => "security_alerts",
            Self::LoginNotifications => "login_notifications",
            Self::SessionReminders => "session_reminders",
            Self::Marketing => "marketing",
        }
    }

    /// Whether this category is mandatory (cannot be disabled by user).
    pub fn is_mandatory(&self) -> bool {
        matches!(self, Self::SecurityAlerts)
    }

    /// All defined categories.
    pub fn all() -> Vec<Self> {
        vec![
            Self::SecurityAlerts,
            Self::LoginNotifications,
            Self::SessionReminders,
            Self::Marketing,
        ]
    }
}

impl std::fmt::Display for NotificationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-category preference: which channels are enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryPreference {
    /// Notification category.
    pub category: NotificationCategory,
    /// Whether this category is enabled (mandatory categories ignore this).
    pub enabled: bool,
    /// Preferred delivery channels for this category.
    pub channels: Vec<NotificationChannel>,
}

impl CategoryPreference {
    /// Check if a specific channel is enabled for this category.
    pub fn is_channel_enabled(&self, channel: NotificationChannel) -> bool {
        if self.category.is_mandatory() {
            // Mandatory categories: all specified channels always active.
            self.channels.contains(&channel)
        } else {
            self.enabled && self.channels.contains(&channel)
        }
    }
}

/// Per-profile notification preferences.
///
/// Controls which notification categories are enabled and via which channels.
/// Security-critical categories (SecurityAlerts) cannot be disabled — the
/// `enabled` field is ignored for mandatory categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreferences {
    /// Profile these preferences belong to.
    pub profile_id: ProfileId,
    /// Per-category settings.
    pub categories: Vec<CategoryPreference>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl NotificationPreferences {
    /// Create default preferences for a new profile.
    ///
    /// All categories enabled, security alerts on email+push,
    /// others on email only.
    pub fn defaults(profile_id: ProfileId) -> Self {
        Self {
            profile_id,
            categories: vec![
                CategoryPreference {
                    category: NotificationCategory::SecurityAlerts,
                    enabled: true, // ignored — mandatory
                    channels: vec![NotificationChannel::Email, NotificationChannel::WebPush],
                },
                CategoryPreference {
                    category: NotificationCategory::LoginNotifications,
                    enabled: true,
                    channels: vec![NotificationChannel::WebPush],
                },
                CategoryPreference {
                    category: NotificationCategory::SessionReminders,
                    enabled: true,
                    channels: vec![NotificationChannel::Email],
                },
                CategoryPreference {
                    category: NotificationCategory::Marketing,
                    enabled: false,
                    channels: vec![NotificationChannel::Email],
                },
            ],
            updated_at: Utc::now(),
        }
    }

    /// Check if a notification should be delivered on a specific channel.
    pub fn should_deliver(
        &self,
        category: &NotificationCategory,
        channel: NotificationChannel,
    ) -> bool {
        // Mandatory categories always deliver on their configured channels.
        if category.is_mandatory() {
            return self
                .categories
                .iter()
                .find(|c| &c.category == category)
                .map(|c| c.channels.contains(&channel))
                .unwrap_or(true); // Default: deliver if no preference set
        }

        // Non-mandatory: check enabled + channel.
        self.categories
            .iter()
            .find(|c| &c.category == category)
            .map(|c| c.is_channel_enabled(channel))
            .unwrap_or(true) // Default: deliver if no preference set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_notification() -> NotificationRequest {
        NotificationRequest::new(
            ProfileId::generate(),
            "mfa_code",
            NotificationChannel::Email,
        )
    }

    #[test]
    fn test_notification_new() {
        let n = make_notification();
        assert_eq!(n.notification_type, "mfa_code");
        assert_eq!(n.channel, NotificationChannel::Email);
        assert_eq!(n.priority, NotificationPriority::Normal);
        assert!(n.params.is_empty());
        assert!(n.delivery_address.is_none());
        assert!(n.expires_at.is_none());
        assert!(!n.is_expired());
    }

    #[test]
    fn test_notification_builder() {
        let n = NotificationRequest::new(
            ProfileId::generate(),
            "security_alert",
            NotificationChannel::AppPush,
        )
        .with_priority(NotificationPriority::Critical)
        .with_param("device", "iPhone 15")
        .with_param("location", "Kyiv, UA")
        .with_ttl(3600);

        assert_eq!(n.priority, NotificationPriority::Critical);
        assert_eq!(n.params.get("device").unwrap(), "iPhone 15");
        assert_eq!(n.params.get("location").unwrap(), "Kyiv, UA");
        assert!(n.expires_at.is_some());
        assert!(!n.is_expired());
    }

    #[test]
    fn test_notification_expired() {
        let n = make_notification().with_ttl(-1);
        assert!(n.is_expired());
    }

    #[test]
    fn test_notification_delivery_address() {
        let n = make_notification().with_delivery_address("unverified@sid.example.com");
        assert_eq!(
            n.delivery_address.as_deref(),
            Some("unverified@sid.example.com")
        );
    }

    #[test]
    fn test_delivery_result_pending() {
        let r = DeliveryResult::pending(NotificationId::new());
        assert_eq!(r.status, DeliveryStatus::Pending);
        assert_eq!(r.attempt_count, 0);
        assert!(r.provider_id.is_none());
    }

    #[test]
    fn test_delivery_result_delivered() {
        let r = DeliveryResult::delivered(NotificationId::new(), "smtp-msg-123");
        assert_eq!(r.status, DeliveryStatus::Delivered);
        assert_eq!(r.provider_id.as_deref(), Some("smtp-msg-123"));
        assert!(r.delivered_at.is_some());
    }

    #[test]
    fn test_delivery_result_failed() {
        let r = DeliveryResult::failed(NotificationId::new(), "SMTP timeout", 3);
        assert_eq!(r.status, DeliveryStatus::Failed);
        assert_eq!(r.attempt_count, 3);
        assert_eq!(r.error.as_deref(), Some("SMTP timeout"));
    }

    #[test]
    fn test_delivery_status_terminal() {
        assert!(!DeliveryStatus::Pending.is_terminal());
        assert!(!DeliveryStatus::Sent.is_terminal());
        assert!(DeliveryStatus::Delivered.is_terminal());
        assert!(DeliveryStatus::Failed.is_terminal());
        assert!(DeliveryStatus::Skipped.is_terminal());
    }

    #[test]
    fn test_channel_serde() {
        let c = NotificationChannel::WebPush;
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"web_push\"");
        let parsed: NotificationChannel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, NotificationChannel::WebPush);
    }

    #[test]
    fn test_priority_serde() {
        let p = NotificationPriority::Critical;
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"critical\"");
        let parsed: NotificationPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, NotificationPriority::Critical);
    }

    #[test]
    fn test_notification_serde_roundtrip() {
        let n = make_notification()
            .with_param("code", "123456")
            .with_priority(NotificationPriority::High);

        let json = serde_json::to_string(&n).unwrap();
        let parsed: NotificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.notification_type, "mfa_code");
        assert_eq!(parsed.priority, NotificationPriority::High);
        assert_eq!(parsed.params.get("code").unwrap(), "123456");
    }

    #[test]
    fn test_notification_id_unique() {
        let id1 = NotificationId::new();
        let id2 = NotificationId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_RETRY_ATTEMPTS, 7);
        assert_eq!(MFA_CODE_TTL_SECONDS, 600);
    }

    // ── Delivery Preferences tests ──

    #[test]
    fn test_security_alerts_is_mandatory() {
        assert!(NotificationCategory::SecurityAlerts.is_mandatory());
        assert!(!NotificationCategory::LoginNotifications.is_mandatory());
        assert!(!NotificationCategory::Marketing.is_mandatory());
    }

    #[test]
    fn test_all_categories() {
        let all = NotificationCategory::all();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_default_preferences() {
        let prefs = NotificationPreferences::defaults(ProfileId::generate());
        assert_eq!(prefs.categories.len(), 4);

        // Security alerts: email + push, mandatory
        let security = prefs
            .categories
            .iter()
            .find(|c| c.category == NotificationCategory::SecurityAlerts)
            .unwrap();
        assert!(security.channels.contains(&NotificationChannel::Email));
        assert!(security.channels.contains(&NotificationChannel::WebPush));

        // Marketing: disabled by default
        let marketing = prefs
            .categories
            .iter()
            .find(|c| c.category == NotificationCategory::Marketing)
            .unwrap();
        assert!(!marketing.enabled);
    }

    #[test]
    fn test_should_deliver_mandatory_always() {
        let mut prefs = NotificationPreferences::defaults(ProfileId::generate());
        // Even if user sets enabled=false for security_alerts, it should still deliver.
        if let Some(cat) = prefs
            .categories
            .iter_mut()
            .find(|c| c.category == NotificationCategory::SecurityAlerts)
        {
            cat.enabled = false;
        }
        assert!(prefs.should_deliver(
            &NotificationCategory::SecurityAlerts,
            NotificationChannel::Email
        ));
    }

    #[test]
    fn test_should_deliver_disabled_category() {
        let prefs = NotificationPreferences::defaults(ProfileId::generate());
        // Marketing is disabled by default.
        assert!(
            !prefs.should_deliver(&NotificationCategory::Marketing, NotificationChannel::Email)
        );
    }

    #[test]
    fn test_should_deliver_channel_not_configured() {
        let prefs = NotificationPreferences::defaults(ProfileId::generate());
        // Login notifications default to push only — email not configured.
        assert!(!prefs.should_deliver(
            &NotificationCategory::LoginNotifications,
            NotificationChannel::Email
        ));
        assert!(prefs.should_deliver(
            &NotificationCategory::LoginNotifications,
            NotificationChannel::WebPush
        ));
    }

    #[test]
    fn test_category_preference_serde_roundtrip() {
        let pref = CategoryPreference {
            category: NotificationCategory::SecurityAlerts,
            enabled: true,
            channels: vec![NotificationChannel::Email, NotificationChannel::Sms],
        };
        let json = serde_json::to_string(&pref).unwrap();
        let parsed: CategoryPreference = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.category, NotificationCategory::SecurityAlerts);
        assert_eq!(parsed.channels.len(), 2);
    }

    #[test]
    fn test_preferences_serde_roundtrip() {
        let prefs = NotificationPreferences::defaults(ProfileId::generate());
        let json = serde_json::to_string(&prefs).unwrap();
        let parsed: NotificationPreferences = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.categories.len(), 4);
        assert_eq!(parsed.profile_id, prefs.profile_id);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(
            NotificationCategory::SecurityAlerts.as_str(),
            "security_alerts"
        );
        assert_eq!(NotificationCategory::Marketing.as_str(), "marketing");
    }
}
