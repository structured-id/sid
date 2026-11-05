// SPDX-License-Identifier: AGPL-3.0-only
//! Project domain model.
//!
//! Project = container for related applications (OAuth2 clients)
//! that share authorization scope (roles, policies, grants).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ProfileId;

/// Validated identifier of a project: a UUIDv7, or the nil UUID of the system
/// project ([`ProjectId::SYSTEM`]); construction and decoding go through `sid_ids`.
pub use sid_ids::ProjectId;

/// Edit of a user project: each field given replaces the stored one, the
/// others stay as stored.
#[derive(Debug, Clone)]
pub struct ProjectChange {
    pub name: Option<String>,
    pub description: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Project represents a container for OAuth2/OIDC applications.
///
/// Every OAuth2Client belongs to exactly one Project.
/// The system project "SID" is created automatically and cannot be deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    pub description: String,
    /// Profile that created the project. None for the system project.
    pub owner_id: Option<ProfileId>,
    /// System projects cannot be deleted.
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Project {
    /// Create the default system project ("SID").
    pub fn system() -> Self {
        let now = Utc::now();
        Self {
            id: ProjectId::SYSTEM,
            name: "SID".to_string(),
            description: "Default system project".to_string(),
            owner_id: None,
            is_system: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new user project.
    pub fn new(name: impl Into<String>, owner_id: Option<ProfileId>) -> Self {
        let now = Utc::now();
        Self {
            id: ProjectId::generate(),
            name: name.into(),
            description: String::new(),
            owner_id,
            is_system: false,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_project() {
        let project = Project::system();
        assert_eq!(project.name, "SID");
        assert!(project.is_system);
        assert!(project.id.is_system());
        assert!(project.owner_id.is_none());
    }

    #[test]
    fn test_new_project() {
        let owner = ProfileId::generate();
        let project = Project::new("My App", Some(owner));
        assert_eq!(project.name, "My App");
        assert!(!project.is_system);
        assert!(!project.id.is_system());
        assert_eq!(project.owner_id, Some(owner));
        assert!(project.description.is_empty());
    }

    #[test]
    fn test_new_project_without_owner() {
        let project = Project::new("Shared", None);
        assert!(project.owner_id.is_none());
        assert!(!project.is_system);
    }

    #[test]
    fn test_project_id_unique() {
        let id1 = ProjectId::generate();
        let id2 = ProjectId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_system_project_id() {
        let id = ProjectId::SYSTEM;
        assert!(id.is_system());
        assert!(id.as_uuid().is_nil());
    }

    #[test]
    fn test_regular_project_id_not_system() {
        let id = ProjectId::generate();
        assert!(!id.is_system());
    }
}
