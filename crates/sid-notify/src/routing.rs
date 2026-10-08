// SPDX-License-Identifier: AGPL-3.0-only
//! Event-to-channel routing rules.
//!
//! Determines which notification channels handle which event types,
//! with priority filtering and recipient resolution.

use serde::{Deserialize, Serialize};
use sid_core::models::event::Event;
use sid_plugin::notification::NotificationPriority;

/// A routing rule mapping event patterns to notification channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Human-readable rule name.
    pub name: String,

    /// Event type patterns to match (e.g., "sid.security.*", "sid.session.created.v1").
    /// Uses the same wildcard syntax as EventFilter.
    pub event_patterns: Vec<String>,

    /// Target channel IDs to route matched events to.
    pub channels: Vec<String>,

    /// Notification priority for matched events.
    pub priority: NotificationPriority,

    /// Template name to use for rendering.
    pub template: String,

    /// Whether this rule is enabled.
    pub enabled: bool,
}

impl RoutingRule {
    /// Check if this rule matches an event.
    pub fn matches(&self, event: &Event) -> bool {
        if !self.enabled {
            return false;
        }

        self.event_patterns.iter().any(|pattern| {
            if pattern.ends_with(".*") || pattern.ends_with(".>") {
                let prefix = &pattern[..pattern.len() - 2];
                event.event_type.starts_with(prefix)
            } else {
                event.event_type == *pattern
            }
        })
    }
}

/// Table of routing rules evaluated in order.
///
/// First matching rule wins. Events with no matching rule are dropped
/// (not all events need notifications).
#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    rules: Vec<RoutingRule>,
}

impl RoutingTable {
    /// Create a new empty routing table.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a routing rule.
    pub fn add_rule(&mut self, rule: RoutingRule) {
        self.rules.push(rule);
    }

    /// Find the first matching rule for an event.
    pub fn route(&self, event: &Event) -> Option<&RoutingRule> {
        self.rules.iter().find(|rule| rule.matches(event))
    }

    /// Get all matching rules for an event (for fan-out to multiple channels).
    pub fn route_all(&self, event: &Event) -> Vec<&RoutingRule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(event))
            .collect()
    }

    /// Get the number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Create a default CE routing table with standard security notifications.
    pub fn default_ce_rules() -> Self {
        let mut table = Self::new();

        table.add_rule(RoutingRule {
            name: "security_alerts".into(),
            event_patterns: vec!["sid.security.*".into()],
            channels: vec!["email".into(), "webhook".into()],
            priority: NotificationPriority::Critical,
            template: "security_alert".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "session_notifications".into(),
            event_patterns: vec!["sid.session.created.v1".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Informational,
            template: "new_session".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "credential_events".into(),
            event_patterns: vec![
                "sid.credential.revoked.v1".into(),
                "sid.security.credential_rotated.v1".into(),
            ],
            channels: vec!["email".into()],
            priority: NotificationPriority::Transactional,
            template: "credential_change".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "mfa_events".into(),
            event_patterns: vec!["sid.mfa.*".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Transactional,
            template: "mfa_change".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "cert_expiry".into(),
            event_patterns: vec!["sid.cert.expiring.v1".into()],
            channels: vec!["email".into(), "webhook".into()],
            priority: NotificationPriority::Critical,
            template: "cert_expiry".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "role_expiry".into(),
            event_patterns: vec![
                "sid.governance.role_expiring.v1".into(),
                "sid.governance.role_expired.v1".into(),
            ],
            channels: vec!["email".into(), "webhook".into()],
            priority: NotificationPriority::Transactional,
            template: "role_expiry".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "scim_outbound_failure".into(),
            event_patterns: vec!["sid.scim.outbound_failed.v1".into()],
            channels: vec!["email".into(), "webhook".into()],
            priority: NotificationPriority::Critical,
            template: "scim_outbound_failure".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "principal_contested".into(),
            event_patterns: vec!["sid.principal.contested.v1".into()],
            // Email is safe — recipient is the existing holder, not the contesting party.
            channels: vec!["email".into(), "push".into()],
            priority: NotificationPriority::Transactional,
            template: "principal_contested".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "principal_lost".into(),
            event_patterns: vec!["sid.principal.lost.v1".into()],
            // Push only — contested address cannot reliably reach the losing profile.
            channels: vec!["push".into()],
            priority: NotificationPriority::Transactional,
            template: "principal_lost".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "principal_ownership_superseded".into(),
            event_patterns: vec!["sid.principal.ownership_superseded.v1".into()],
            // Push only — old verified owner should be notified via device push.
            channels: vec!["push".into()],
            priority: NotificationPriority::Transactional,
            template: "principal_ownership_superseded".into(),
            enabled: true,
        });

        table.add_rule(RoutingRule {
            name: "trial_onboarding".into(),
            event_patterns: vec!["sid.organization.trial_activated.v1".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Transactional,
            template: "trial_onboarding".into(),
            enabled: true,
        });

        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_core::models::event::{Event, event_types};

    #[test]
    fn test_routing_rule_matches_exact() {
        let rule = RoutingRule {
            name: "test".into(),
            event_patterns: vec!["sid.user.created.v1".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Transactional,
            template: "welcome".into(),
            enabled: true,
        };

        assert!(rule.matches(&Event::new("src", event_types::USER_CREATED)));
        assert!(!rule.matches(&Event::new("src", event_types::USER_DELETED)));
    }

    #[test]
    fn test_routing_rule_matches_wildcard() {
        let rule = RoutingRule {
            name: "test".into(),
            event_patterns: vec!["sid.security.*".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Critical,
            template: "alert".into(),
            enabled: true,
        };

        assert!(rule.matches(&Event::new("src", event_types::SECURITY_BRUTE_FORCE)));
        assert!(rule.matches(&Event::new("src", event_types::SECURITY_SUSPICIOUS_LOGIN)));
        assert!(!rule.matches(&Event::new("src", event_types::USER_CREATED)));
    }

    #[test]
    fn test_routing_rule_disabled() {
        let rule = RoutingRule {
            name: "test".into(),
            event_patterns: vec!["sid.user.*".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Informational,
            template: "test".into(),
            enabled: false,
        };

        assert!(!rule.matches(&Event::new("src", event_types::USER_CREATED)));
    }

    #[test]
    fn test_routing_table_first_match() {
        let mut table = RoutingTable::new();
        table.add_rule(RoutingRule {
            name: "specific".into(),
            event_patterns: vec!["sid.user.created.v1".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Transactional,
            template: "welcome".into(),
            enabled: true,
        });
        table.add_rule(RoutingRule {
            name: "generic".into(),
            event_patterns: vec!["sid.user.*".into()],
            channels: vec!["webhook".into()],
            priority: NotificationPriority::Informational,
            template: "user_event".into(),
            enabled: true,
        });

        let event = Event::new("src", event_types::USER_CREATED);
        let matched = table.route(&event).unwrap();
        assert_eq!(matched.name, "specific");
    }

    #[test]
    fn test_routing_table_route_all() {
        let mut table = RoutingTable::new();
        table.add_rule(RoutingRule {
            name: "email".into(),
            event_patterns: vec!["sid.security.*".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Critical,
            template: "alert".into(),
            enabled: true,
        });
        table.add_rule(RoutingRule {
            name: "webhook".into(),
            event_patterns: vec!["sid.security.*".into()],
            channels: vec!["webhook".into()],
            priority: NotificationPriority::Critical,
            template: "alert_webhook".into(),
            enabled: true,
        });

        let event = Event::new("src", event_types::SECURITY_BRUTE_FORCE);
        let matches = table.route_all(&event);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_routing_table_no_match() {
        let table = RoutingTable::new();
        let event = Event::new("src", event_types::USER_CREATED);
        assert!(table.route(&event).is_none());
    }

    #[test]
    fn test_default_ce_rules() {
        let table = RoutingTable::default_ce_rules();
        assert!(!table.is_empty());

        // Security events should match
        let security_event = Event::new("src", event_types::SECURITY_BRUTE_FORCE);
        let rule = table.route(&security_event).unwrap();
        assert_eq!(rule.priority, NotificationPriority::Critical);
        assert!(rule.channels.contains(&"email".to_string()));

        // Session events should match
        let session_event = Event::new("src", event_types::SESSION_CREATED);
        assert!(table.route(&session_event).is_some());

        // Role expiry events should match
        let role_expiring = Event::new("src", event_types::GOVERNANCE_ROLE_EXPIRING);
        let role_rule = table.route(&role_expiring).unwrap();
        assert_eq!(role_rule.name, "role_expiry");
        assert_eq!(role_rule.priority, NotificationPriority::Transactional);
        assert!(role_rule.channels.contains(&"email".to_string()));
        assert!(role_rule.channels.contains(&"webhook".to_string()));

        let role_expired = Event::new("src", event_types::GOVERNANCE_ROLE_EXPIRED);
        assert!(table.route(&role_expired).is_some());

        // SCIM outbound failure events should match
        let scim_event = Event::new("src", "sid.scim.outbound_failed.v1");
        let scim_rule = table.route(&scim_event).unwrap();
        assert_eq!(scim_rule.name, "scim_outbound_failure");
        assert_eq!(scim_rule.priority, NotificationPriority::Critical);
        assert!(scim_rule.channels.contains(&"email".to_string()));
        assert!(scim_rule.channels.contains(&"webhook".to_string()));

        // Trial activation events should match
        let trial_event = Event::new("sid-server", event_types::ORG_TRIAL_ACTIVATED);
        let trial_rule = table.route(&trial_event).unwrap();
        assert_eq!(trial_rule.name, "trial_onboarding");
        assert_eq!(trial_rule.priority, NotificationPriority::Transactional);
        assert!(trial_rule.channels.contains(&"email".to_string()));

        // Random federation events should not match
        let fed_event = Event::new("src", event_types::FEDERATION_SYNC_COMPLETED);
        assert!(table.route(&fed_event).is_none());
    }

    #[test]
    fn test_routing_rule_serde() {
        let rule = RoutingRule {
            name: "test".into(),
            event_patterns: vec!["sid.security.*".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Critical,
            template: "alert".into(),
            enabled: true,
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: RoutingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
        assert_eq!(deserialized.priority, NotificationPriority::Critical);
    }

    #[test]
    fn test_routing_table_len() {
        let mut table = RoutingTable::new();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());

        table.add_rule(RoutingRule {
            name: "test".into(),
            event_patterns: vec!["sid.*".into()],
            channels: vec!["email".into()],
            priority: NotificationPriority::Informational,
            template: "test".into(),
            enabled: true,
        });
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_default_ce_rules_contestation_events() {
        let table = RoutingTable::default_ce_rules();

        // PRINCIPAL_CONTESTED → email + push
        let contested = Event::new("sid-identity", event_types::PRINCIPAL_CONTESTED);
        let rule = table.route(&contested).unwrap();
        assert_eq!(rule.name, "principal_contested");
        assert!(rule.channels.contains(&"email".to_string()));
        assert!(rule.channels.contains(&"push".to_string()));
        assert_eq!(rule.priority, NotificationPriority::Transactional);
        assert_eq!(rule.template, "principal_contested");

        // PRINCIPAL_LOST → push only
        let lost = Event::new("sid-identity", event_types::PRINCIPAL_LOST);
        let rule = table.route(&lost).unwrap();
        assert_eq!(rule.name, "principal_lost");
        assert!(rule.channels.contains(&"push".to_string()));
        assert!(!rule.channels.contains(&"email".to_string()));
        assert_eq!(rule.priority, NotificationPriority::Transactional);
        assert_eq!(rule.template, "principal_lost");

        // PRINCIPAL_OWNERSHIP_SUPERSEDED → push only
        let superseded = Event::new("sid-identity", event_types::PRINCIPAL_OWNERSHIP_SUPERSEDED);
        let rule = table.route(&superseded).unwrap();
        assert_eq!(rule.name, "principal_ownership_superseded");
        assert!(rule.channels.contains(&"push".to_string()));
        assert!(!rule.channels.contains(&"email".to_string()));
        assert_eq!(rule.priority, NotificationPriority::Transactional);
        assert_eq!(rule.template, "principal_ownership_superseded");
    }
}
