// SPDX-License-Identifier: AGPL-3.0-only
//! Profile metadata domain model.
//!
//! CE: free-form key-value pairs. No schema validation.
//! Keys are arbitrary strings, values are JSON.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ProfileId;

/// A single metadata entry on a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub profile_id: ProfileId,
    pub key: String,
    pub value: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfileMetadata {
    /// Create a new metadata entry.
    pub fn new(profile_id: ProfileId, key: impl Into<String>, value: serde_json::Value) -> Self {
        let now = Utc::now();
        Self {
            profile_id,
            key: key.into(),
            value,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_metadata_new() {
        let profile_id = ProfileId::generate();
        let value = serde_json::json!({"department": "Engineering"});
        let meta = ProfileMetadata::new(profile_id, "employee_info", value.clone());

        assert_eq!(meta.profile_id, profile_id);
        assert_eq!(meta.key, "employee_info");
        assert_eq!(meta.value, value);
    }

    #[test]
    fn test_profile_metadata_string_value() {
        let meta = ProfileMetadata::new(
            ProfileId::generate(),
            "employee_id",
            serde_json::json!("EMP-4521"),
        );
        assert_eq!(meta.value, serde_json::json!("EMP-4521"));
    }

    #[test]
    fn test_profile_metadata_numeric_value() {
        let meta = ProfileMetadata::new(ProfileId::generate(), "badge_level", serde_json::json!(3));
        assert_eq!(meta.value, serde_json::json!(3));
    }

    #[test]
    fn test_profile_metadata_null_value() {
        let meta = ProfileMetadata::new(
            ProfileId::generate(),
            "optional_field",
            serde_json::Value::Null,
        );
        assert!(meta.value.is_null());
    }

    #[test]
    fn test_profile_metadata_serde_roundtrip() {
        let meta = ProfileMetadata::new(
            ProfileId::generate(),
            "test_key",
            serde_json::json!({"nested": true, "count": 42}),
        );
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ProfileMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.key, "test_key");
        assert_eq!(
            parsed.value,
            serde_json::json!({"nested": true, "count": 42})
        );
    }
}
