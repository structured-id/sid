// SPDX-License-Identifier: AGPL-3.0-only
//! Writes a directory (SCIM) makes to one user or group: everything a
//! request changes is applied in one transaction with the request's audit
//! entry and event, so a crash leaves the whole change or none of it.

use super::{
    Group, GroupMember, Principal, PrincipalId, Profile, ProfileEmail, ProfileEmailId, ProfileId,
    ProfileMetadata, ProfilePhone, ProfilePhoneId, SessionEnd,
};

/// Whether a directory write creates its resource or changes an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryWriteMode {
    /// The resource must not exist yet; a login handle already taken refuses
    /// the whole write.
    Create,
    /// The resource must exist.
    Update,
}

/// One directory write to a user account.
#[derive(Debug, Clone)]
pub struct DirectoryUserWrite {
    pub mode: DirectoryWriteMode,
    /// The account as it stands after the write.
    pub profile: Profile,
    /// Principals the account comes to hold. A `Username` principal is the
    /// account's login handle and is never shared: on create it must be free.
    pub bind: Vec<Principal>,
    /// Principals the account stops holding (other holders keep theirs).
    pub unbind: Vec<PrincipalId>,
    pub add_emails: Vec<ProfileEmail>,
    pub remove_emails: Vec<ProfileEmailId>,
    pub add_phones: Vec<ProfilePhone>,
    pub remove_phones: Vec<ProfilePhoneId>,
    pub set_metadata: Vec<ProfileMetadata>,
    pub remove_metadata: Vec<String>,
    /// Deprovisioning: every session of the account ends and every active
    /// personal access token is revoked, in the same transaction.
    pub end_access: Option<SessionEnd>,
}

impl DirectoryUserWrite {
    /// A write that changes nothing but `profile` yet.
    pub fn new(mode: DirectoryWriteMode, profile: Profile) -> Self {
        Self {
            mode,
            profile,
            bind: Vec::new(),
            unbind: Vec::new(),
            add_emails: Vec::new(),
            remove_emails: Vec::new(),
            add_phones: Vec::new(),
            remove_phones: Vec::new(),
            set_metadata: Vec::new(),
            remove_metadata: Vec::new(),
            end_access: None,
        }
    }

    pub fn profile_id(&self) -> ProfileId {
        self.profile.id
    }
}

/// One directory write to a group.
#[derive(Debug, Clone)]
pub struct DirectoryGroupWrite {
    pub mode: DirectoryWriteMode,
    /// The group as it stands after the write.
    pub group: Group,
    pub add_members: Vec<GroupMember>,
    pub remove_members: Vec<ProfileId>,
}

impl DirectoryGroupWrite {
    /// A write that changes nothing but `group` yet.
    pub fn new(mode: DirectoryWriteMode, group: Group) -> Self {
        Self {
            mode,
            group,
            add_members: Vec::new(),
            remove_members: Vec::new(),
        }
    }
}
