// SPDX-License-Identifier: AGPL-3.0-only
//! How an installation gets its first administrator (enrollment-policy.md,
//! First Administrator).

/// The installation's bootstrap policy, chosen by the installation's
/// configuration, never inferred from its name, host, edition or an empty
/// administrator set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BootstrapPolicy {
    /// Its own claim token makes its first administrator.
    SelfManaged,
    /// Administration comes through authorized provisioning by a central
    /// management authority; it never offers a local claim, and once
    /// recorded this never changes.
    CentrallyManaged,
}

impl BootstrapPolicy {
    /// Stable storage name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelfManaged => "self_managed",
            Self::CentrallyManaged => "centrally_managed",
        }
    }
}

parse_stored!(
    BootstrapPolicy,
    "bootstrap policy",
    [SelfManaged, CentrallyManaged]
);

impl core::fmt::Display for BootstrapPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of recording an installation as centrally managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CentralAdoption {
    /// Recorded now; a stored local claim token was removed with it.
    Adopted,
    /// It already was.
    AlreadyCentral,
    /// Refused, nothing changed: the installation already has a local
    /// administrator, so it is a claimed self-managed installation.
    LocalAdministrator,
}
