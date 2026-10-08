// SPDX-License-Identifier: AGPL-3.0-only
//! CE flat group service.
//!
//! Groups are flat in CE — no parent-child hierarchy, no transitive membership.
//! All membership checks are single-level.
//! EE extends with nested groups via parent_group_id + group_closure table.

use std::sync::Arc;

use sid_core::models::{AuditEntry, Group, GroupId, GroupMember, ProfileId, ProjectId};
use sid_core::{Error, Result};
use sid_plugin::StorageBackend;

/// CE Group service — flat groups only.
pub struct GroupService<S: StorageBackend> {
    storage: Arc<S>,
}

impl<S: StorageBackend> GroupService<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    /// Create a new group within a project.
    ///
    /// CE enforces flat groups: parent_group_id is always None.
    pub async fn create_group(
        &self,
        project_id: ProjectId,
        name: impl Into<String>,
        description: Option<String>,
    ) -> Result<Group> {
        let mut group = Group::new(project_id, name);
        group.description = description;
        self.storage
            .create_group(
                &group,
                AuditEntry::system("group.create", &group.name).into(),
            )
            .await?;
        Ok(group)
    }

    /// Add a profile to a group.
    pub async fn add_member(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
    ) -> Result<GroupMember> {
        // Verify group exists.
        self.storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("group {}", group_id.0)))?;

        // Check for duplicate membership.
        let existing = self.storage.list_group_members(group_id).await?;
        if existing.iter().any(|m| m.profile_id == profile_id) {
            return Err(Error::Conflict(format!(
                "profile {} already in group {}",
                profile_id, group_id.0
            )));
        }

        let member = GroupMember::new(group_id, profile_id);
        self.storage
            .add_to_group(
                &member,
                AuditEntry::system("group.add_member", group_id.0.to_string()).into(),
            )
            .await?;
        Ok(member)
    }

    /// Remove a profile from a group.
    pub async fn remove_member(&self, group_id: GroupId, profile_id: ProfileId) -> Result<()> {
        self.storage
            .remove_from_group(
                group_id,
                profile_id,
                AuditEntry::system("group.remove_member", group_id.0.to_string()).into(),
            )
            .await
    }

    /// Check if a profile is a member of a group.
    pub async fn is_member(&self, group_id: GroupId, profile_id: ProfileId) -> Result<bool> {
        let members = self.storage.list_group_members(group_id).await?;
        Ok(members.iter().any(|m| m.profile_id == profile_id))
    }

    /// List all members of a group.
    pub async fn list_members(&self, group_id: GroupId) -> Result<Vec<GroupMember>> {
        self.storage.list_group_members(group_id).await
    }

    /// List all groups a profile belongs to.
    pub async fn list_groups_for_profile(&self, profile_id: ProfileId) -> Result<Vec<Group>> {
        self.storage.list_groups_for_profile(profile_id).await
    }

    /// List all groups in a project.
    pub async fn list_groups_in_project(&self, project_id: ProjectId) -> Result<Vec<Group>> {
        self.storage.list_groups(project_id).await
    }

    /// Delete a group.
    pub async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        self.storage
            .delete_group(
                group_id,
                AuditEntry::system("group.delete", group_id.0.to_string()).into(),
            )
            .await
    }
}

#[cfg(test)]
mod tests;
