// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 outbound provisioning domain types.
//!
//! Outbound provisioning pushes corporate profile changes to downstream apps
//! (Slack, GitHub Enterprise, Google Workspace, ACS platforms, etc.).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::project::ProjectId;

/// Unique identifier for a SCIM outbound target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScimOutboundTargetId(pub Uuid);

impl ScimOutboundTargetId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ScimOutboundTargetId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ScimOutboundTargetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SCIM outbound target — a downstream app that receives provisioned users/groups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimOutboundTarget {
    pub id: ScimOutboundTargetId,
    /// OAuth2 client_id of the downstream app (links to OAuth2Client).
    pub client_id: String,
    /// Project scope for this target.
    pub project_id: ProjectId,
    /// Human-readable name (e.g., "Slack Enterprise", "GitHub").
    pub display_name: String,
    /// SCIM 2.0 endpoint base URL (e.g., "https://api.slack.com/scim/v2").
    pub endpoint_url: String,
    /// Authentication configuration for the downstream SCIM API.
    pub auth: OutboundAuthConfig,
    /// Attribute mapping: SCIM attribute path → SID profile field expression.
    pub attribute_mapping: AttributeMapping,
    /// Group push configuration.
    pub group_push: GroupPushConfig,
    /// Sync and retry configuration.
    pub sync_config: OutboundSyncConfig,
    /// Whether this target is active.
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Authentication for downstream SCIM API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundAuthConfig {
    /// Static bearer token.
    Bearer {
        /// Encrypted token value (stored via EncryptedField or vault reference).
        token_secret: String,
    },
    /// OAuth2 client_credentials grant for auto-refreshing tokens (EE).
    OAuth2ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
    },
}

/// Attribute mapping from SID profile fields to SCIM User attributes.
///
/// Keys are SCIM attribute paths (e.g., "userName", "name.givenName", "emails").
/// Values are mapping expressions that resolve against SID profile data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeMapping {
    pub mappings: Vec<AttributeMappingEntry>,
}

/// Single attribute mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMappingEntry {
    /// SCIM attribute path (e.g., "userName", "name.givenName", "emails[0].value").
    pub scim_path: String,
    /// SID profile field expression.
    pub source: MappingSource,
}

/// Source expression for attribute mapping.
///
/// CE supports only `Path` (direct field reference).
/// EE adds `Expression` (DSL with transforms like split, join, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MappingSource {
    /// Direct field path: "profile.login", "profile.email", "metadata.employee_id".
    Path { path: String },
    /// Static literal value.
    Literal { value: serde_json::Value },
    /// Boolean expression: "profile.status == 'active'".
    StatusCheck { active_value: String },
}

/// Group push configuration for outbound provisioning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupPushConfig {
    /// Whether group push is enabled for this target.
    pub enabled: bool,
    /// Static 1:1 group name mapping: SID group name → downstream group identifier.
    /// CE only supports flat mapping.
    pub mapping: Vec<GroupMappingEntry>,
}

/// Single group mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMappingEntry {
    /// SID group display name.
    pub sid_group: String,
    /// Downstream group identifier or name.
    pub target_group: String,
}

/// Sync and retry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSyncConfig {
    /// Maximum retry attempts before sending to DLQ.
    pub max_retry_attempts: u32,
    /// Base backoff duration in seconds (exponential: base * 2^attempt).
    pub retry_backoff_base_secs: u64,
}

impl Default for OutboundSyncConfig {
    fn default() -> Self {
        Self {
            max_retry_attempts: 5,
            retry_backoff_base_secs: 1,
        }
    }
}

/// Tracks the mapping between a SID entity and its downstream SCIM representation.
///
/// Stores the downstream `id` returned by the app's SCIM API after POST /Users or POST /Groups.
/// Used for subsequent PATCH/DELETE operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimOutboundRecord {
    /// Target this record belongs to.
    pub target_id: ScimOutboundTargetId,
    /// SID entity ID (profile_id or group_id).
    pub sid_entity_id: Uuid,
    /// Entity type (User or Group).
    pub entity_type: OutboundEntityType,
    /// Downstream SCIM resource ID (returned by the app).
    pub downstream_id: String,
    /// Last successful sync timestamp.
    pub last_synced_at: DateTime<Utc>,
    /// Last error message (None if last sync succeeded).
    pub last_error: Option<String>,
    /// Number of consecutive failures.
    pub failure_count: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Entity type for outbound records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundEntityType {
    User,
    Group,
}

impl OutboundEntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }
}

impl std::str::FromStr for OutboundEntityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "group" => Ok(Self::Group),
            other => Err(format!("unknown outbound entity type: {other}")),
        }
    }
}

impl std::fmt::Display for OutboundEntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Dead letter queue entry for failed outbound deliveries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundDlqEntry {
    pub id: Uuid,
    pub target_id: ScimOutboundTargetId,
    /// The event that triggered this outbound attempt.
    pub event_type: String,
    /// JSON payload that was being sent.
    pub payload: serde_json::Value,
    /// SID entity ID.
    pub sid_entity_id: Uuid,
    pub entity_type: OutboundEntityType,
    /// Error description.
    pub error: String,
    /// Total attempts made.
    pub attempts: u32,
    pub first_attempt: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
}

#[cfg(test)]
mod tests;
