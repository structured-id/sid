// SPDX-License-Identifier: AGPL-3.0-only
//! Writes a directory (SCIM) makes to one user or group: everything a
//! request changes is applied in one transaction with the request's audit
//! entry and event, so a crash leaves the whole change or none of it.

use super::{
    Group, GroupMember, Principal, PrincipalId, Profile, ProfileEmail, ProfileEmailId, ProfileId,
    ProfileMetadata, ProfilePhone, ProfilePhoneId, SessionEnd,
};

/// The identifier the directory assigns to a user resource (RFC 7643 3.1):
/// what a SCIM client knows the user by. It is not the account's identifier
/// and is never given to another resource, also after a deletion.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct DirectoryUserId(pub uuid::Uuid);

impl DirectoryUserId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    /// The identifier written as a SCIM `id`; `None` for anything else.
    pub fn parse(id: &str) -> Option<Self> {
        uuid::Uuid::parse_str(id).ok().map(Self)
    }
}

impl Default for DirectoryUserId {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for DirectoryUserId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// A user resource of the directory: the resource a client addresses, apart
/// from the account it stands for. A deleted resource stays stored, so its
/// identifier is never reused, and is served by no read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryResource {
    pub id: DirectoryUserId,
    /// The local account the resource stands for.
    pub profile_id: ProfileId,
    /// Moved on by every change of the resource itself.
    pub revision: u64,
    pub deleted_at: Option<jiff::Timestamp>,
}

impl DirectoryResource {
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

/// A provisioning source's correlation with a user resource: which connector
/// knows the resource and by what identifier of its own (RFC 7643 3.1
/// `externalId`, scoped to that source). It records where a resource came
/// from; it is neither a condition of reading the resource nor, by itself,
/// authority to change it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectorySource {
    pub resource: DirectoryUserId,
    pub connector: super::ProvisioningConnectorId,
    /// The source's own identifier of the resource, when it gave one. Unique
    /// within the connector among live resources; another connector may use
    /// the same value.
    pub external_id: Option<String>,
    /// Set with the resource's deletion: the provenance stays, and the
    /// source may give its identifier to a new resource.
    pub retired: bool,
}

/// What a directory write records about the source making it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceWrite {
    pub connector: super::ProvisioningConnectorId,
    /// The source's identifier of the resource after the write; `None`
    /// clears it.
    pub external_id: Option<String>,
}

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
    /// The directory resource an update is made through: the write applies
    /// only while that resource is live and stands for this account, and
    /// refuses with `NotFound` otherwise. `None` on create and for a write
    /// that is not a directory client's.
    pub resource: Option<DirectoryUserId>,
    /// Delete `resource`: it is served by no read afterwards and its
    /// identifier is never given out again. The account itself stays, as
    /// the rest of the write leaves it.
    pub delete_resource: bool,
    /// The provisioning source making the write. A create records its
    /// correlation with the new resource in the same commit. An update
    /// changes only a correlation that source already has with `resource`:
    /// it never creates one, so no source takes a resource over by writing
    /// to it. `None` for a write that is no provisioning source's.
    pub source: Option<SourceWrite>,
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
            resource: None,
            delete_resource: false,
            source: None,
        }
    }

    /// A write made by the provisioning source `connector`, which knows the
    /// resource as `external_id`.
    pub fn by_source(
        mut self,
        connector: super::ProvisioningConnectorId,
        external_id: Option<String>,
    ) -> Self {
        self.source = Some(SourceWrite {
            connector,
            external_id,
        });
        self
    }

    /// An update made through the live directory resource `resource`.
    pub fn through(mut self, resource: DirectoryUserId) -> Self {
        self.resource = Some(resource);
        self
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
