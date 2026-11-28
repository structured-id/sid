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
    /// Whether the directory relationship itself is active: one state of
    /// the user, the same for every reader. A resource whose account the
    /// directory manages whole is deactivated through the account's own
    /// state and keeps this true; a relationship with an identity that
    /// signs in elsewhere is deactivated here, and the identity's account
    /// and its other grounds of access are left as they are.
    pub active: bool,
}

impl DirectoryResource {
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// SCIM `active` of the user this resource serves for `account`. A
    /// relationship shows its own state, whatever the identity's account
    /// is; a managed account shows whether it can be used. One definition
    /// for a single read, a page and a filter. It tells what the directory
    /// holds, not whether a sign-in would succeed.
    pub fn shows_active(&self, account: &Profile) -> bool {
        match DirectoryTarget::of(account) {
            DirectoryTarget::Relationship => self.active,
            DirectoryTarget::Account => account.status.is_in_use(),
        }
    }
}

/// What a directory user stands for, which decides what its `active` tells
/// and what deactivating or deleting it ends. Derived from the account as
/// stored now, never from a request or from the rights a caller holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryTarget {
    /// A local account the directory's organization manages whole: its own
    /// lifecycle is the user's state.
    Account,
    /// A relationship with an identity that signs in elsewhere and may hold
    /// access here on other grounds: the directory owns the relationship,
    /// not the identity's account.
    Relationship,
}

impl DirectoryTarget {
    pub fn of(account: &Profile) -> Self {
        // A record without local credentials is this installation's
        // reference to an identity another installation signs in.
        if account.profile_type.is_local() {
            Self::Account
        } else {
            Self::Relationship
        }
    }
}

/// One thing a provisioning connector may change of a user it manages. A
/// right bounds the user and the part of it; the action itself still needs
/// the connector's role on the directory resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum DirectoryRight {
    /// The name: its components and the display name.
    Name = 1 << 0,
    /// Email addresses, with the login handles made of them.
    Emails = 1 << 1,
    /// Phone numbers, with the login handles made of them.
    PhoneNumbers = 1 << 2,
    Title = 1 << 3,
    Department = 1 << 4,
    EmployeeNumber = 1 << 5,
    CostCenter = 1 << 6,
    Organization = 1 << 7,
    Division = 1 << 8,
    /// The connector's own identifier of the user (`externalId`).
    ExternalId = 1 << 9,
    /// Deactivate and reactivate the user. What that ends follows what the
    /// resource stands for: an account the directory manages whole is
    /// suspended with every sign-in and token of it, a relationship with an
    /// identity that signs in elsewhere only changes its own state.
    Active = 1 << 10,
    /// Delete the user resource. For a relationship that is the whole of
    /// it; deleting a managed account also ends its access, which takes
    /// [`Self::Active`] as well.
    Delete = 1 << 11,
    /// Rename the login the organization issued to the user (`userName`).
    /// Nothing over the login of an identity that signs in elsewhere.
    UserName = 1 << 12,
}

impl DirectoryRight {
    pub const ALL: [Self; 13] = [
        Self::Name,
        Self::Emails,
        Self::PhoneNumbers,
        Self::Title,
        Self::Department,
        Self::EmployeeNumber,
        Self::CostCenter,
        Self::Organization,
        Self::Division,
        Self::ExternalId,
        Self::Active,
        Self::Delete,
        Self::UserName,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Emails => "emails",
            Self::PhoneNumbers => "phone_numbers",
            Self::Title => "title",
            Self::Department => "department",
            Self::EmployeeNumber => "employee_number",
            Self::CostCenter => "cost_center",
            Self::Organization => "organization",
            Self::Division => "division",
            Self::ExternalId => "external_id",
            Self::Active => "active",
            Self::Delete => "delete",
            Self::UserName => "user_name",
        }
    }
}

/// A set of [`DirectoryRight`]: what a connector may change of one user, of
/// every user of the directory, or what one request changes. Empty means
/// nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "i32", into = "i32")]
pub struct DirectoryRights(u16);

impl DirectoryRights {
    pub const NONE: Self = Self(0);

    pub fn of(rights: &[DirectoryRight]) -> Self {
        rights
            .iter()
            .fold(Self::NONE, |set, right| set.with(*right))
    }

    #[must_use]
    pub fn with(self, right: DirectoryRight) -> Self {
        Self(self.0 | right as u16)
    }

    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn contains(self, right: DirectoryRight) -> bool {
        self.0 & right as u16 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The rights of `needed` this set lacks; empty when it covers them all.
    #[must_use]
    pub fn lacking(self, needed: Self) -> Self {
        Self(needed.0 & !self.0)
    }

    pub fn iter(self) -> impl Iterator<Item = DirectoryRight> {
        DirectoryRight::ALL
            .into_iter()
            .filter(move |right| self.contains(*right))
    }

    /// The set as stores keep it.
    pub fn bits(self) -> i32 {
        i32::from(self.0)
    }

    /// The set a store kept as `bits`; a bit that is no right is refused.
    pub fn from_bits(bits: i32) -> Option<Self> {
        let known = DirectoryRight::ALL
            .iter()
            .fold(0u16, |all, right| all | *right as u16);
        u16::try_from(bits)
            .ok()
            .filter(|bits| bits & !known == 0)
            .map(Self)
    }
}

impl From<DirectoryRights> for i32 {
    fn from(rights: DirectoryRights) -> Self {
        rights.bits()
    }
}

impl TryFrom<i32> for DirectoryRights {
    type Error = String;

    fn try_from(bits: i32) -> Result<Self, Self::Error> {
        Self::from_bits(bits).ok_or_else(|| format!("directory rights: unknown bits in {bits}"))
    }
}

/// What an assignment or a withdrawal of one user did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementOutcome {
    /// The assignment is as the command asked, and the connector's revision
    /// moved.
    Applied,
    /// A withdrawal found no assignment: nothing changed, the revision
    /// included.
    NothingToWithdraw,
    /// The connector moved past the revision the command named.
    Stale,
}

/// A provisioning source's correlation with a user resource: which connector
/// knows the resource and by what identifier of its own (RFC 7643 3.1
/// `externalId`, scoped to that source), and what the directory's manager
/// assigned the connector of this one user. Knowing a resource, also having
/// created it, is neither a condition of reading it nor authority to change
/// it: only `managed` and the connector's directory-wide selection are.
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
    /// Whether this source created the resource. Provenance only.
    pub created: bool,
    /// What the connector was assigned of this user; empty once withdrawn
    /// or when it was never assigned.
    pub managed: DirectoryRights,
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
    /// Set the activity of the relationship `resource` itself, moving the
    /// resource's revision. `None` leaves it.
    pub resource_active: Option<bool>,
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
            resource_active: None,
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
    /// Whose assignments the members above are: an inbound connector's own
    /// (each resting on the member's directory resource), or, absent, ones
    /// made locally. A member belongs to the group while any assignment of
    /// it stands; a connector's stands while its resource is live and
    /// active. Removing touches this origin's assignment only.
    pub source: Option<super::ProvisioningConnectorId>,
}

impl DirectoryGroupWrite {
    /// A write that changes nothing but `group` yet.
    pub fn new(mode: DirectoryWriteMode, group: Group) -> Self {
        Self {
            mode,
            group,
            add_members: Vec::new(),
            remove_members: Vec::new(),
            source: None,
        }
    }

    /// The same write, its members being the assignments of `connector`.
    pub fn by_source(mut self, connector: super::ProvisioningConnectorId) -> Self {
        self.source = Some(connector);
        self
    }
}
