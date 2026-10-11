// SPDX-License-Identifier: AGPL-3.0-only
//! A query over the installation's user directory, as a SCIM service provider
//! answers `GET /Users` (RFC 7644 §3.4.2): a filter applied by storage before
//! pagination, the total of the whole matching set, and one page of users
//! read in batches.

use crate::models::{Principal, Profile, ProfileEmail, ProfileMetadata};

/// An attribute a directory filter compares, with the SCIM attribute it
/// stands for (RFC 7643 §4.1, enterprise extension §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryAttribute {
    /// `userName`: the corporate login without its `#domain` suffix.
    UserName,
    /// `displayName`: the formatted name.
    DisplayName,
    /// `name.givenName`.
    GivenName,
    /// `name.familyName`.
    FamilyName,
    /// `name.formatted`: present only with a given or family name.
    FormattedName,
    /// `externalId`: the source's own identifier, compared case-exactly.
    ExternalId,
    /// `title`.
    Title,
    /// `department` (enterprise extension).
    Department,
    /// `active`: compared with `true` or `false` only.
    Active,
    /// `emails.value`: multi-valued.
    Email,
    /// `phoneNumbers.value`: multi-valued.
    Phone,
}

impl DirectoryAttribute {
    /// Whether values compare case-exactly. RFC 7643 §4.1.1 marks
    /// `externalId` `caseExact: true`; every other attribute here `false`.
    pub fn case_exact(self) -> bool {
        matches!(self, Self::ExternalId)
    }

    /// Whether the attribute holds several values, matched when any does
    /// (RFC 7644 §3.4.2.2).
    pub fn multi_valued(self) -> bool {
        matches!(self, Self::Email | Self::Phone)
    }
}

/// A comparison operator (RFC 7644 §3.4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryOperator {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

/// A directory filter. A comparison of an attribute without a value matches
/// nothing; a multi-valued attribute matches when any of its values does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryFilter {
    Compare {
        attribute: DirectoryAttribute,
        operator: DirectoryOperator,
        value: String,
    },
    /// `pr`: the attribute has a non-empty value.
    Present(DirectoryAttribute),
    And(Box<DirectoryFilter>, Box<DirectoryFilter>),
    Or(Box<DirectoryFilter>, Box<DirectoryFilter>),
    Not(Box<DirectoryFilter>),
}

/// One page of the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryQuery {
    /// The installation's organization domain: a corporate login is
    /// `{userName}#{domain}`.
    pub org_domain: String,
    pub filter: Option<DirectoryFilter>,
    /// Matching users skipped before the page (`startIndex - 1`).
    pub offset: u64,
    /// Users in the page at most; 0 asks only for the total.
    pub limit: u64,
}

/// A user of the directory with what its SCIM resource is built from.
#[derive(Debug, Clone)]
pub struct DirectoryUser {
    pub profile: Profile,
    pub principals: Vec<Principal>,
    pub emails: Vec<ProfileEmail>,
    pub metadata: Vec<ProfileMetadata>,
}

/// The answer to a [`DirectoryQuery`].
#[derive(Debug, Clone)]
pub struct DirectoryPage {
    /// Users matching the filter in the whole directory, not only the page.
    pub total: u64,
    pub users: Vec<DirectoryUser>,
}

/// Metadata keys a directory user's SCIM attributes are read from.
pub mod metadata_keys {
    /// `externalId`.
    pub const EXTERNAL_ID: &str = "employee_id";
    /// `department`.
    pub const DEPARTMENT: &str = "department";
    /// `title`.
    pub const TITLE: &str = "title";
}
