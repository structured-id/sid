// SPDX-License-Identifier: AGPL-3.0-only
//! The login settings of the organization an installation serves.

use serde::{Deserialize, Serialize};

/// Which incoming external identities the organization, as the recipient of
/// a federated sign-in, admits. The two are independent, and incoming
/// federated sign-in is available when either is on. Both concern the
/// sign-in of an existing external identity: neither is a registration mode
/// or federation enrollment, and a Profile the organization issued itself is
/// governed by neither. Off until an administrator turns them on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSettings {
    /// Personal Profiles are admitted.
    pub allow_personal_profiles: bool,
    /// Corporate Profiles issued by other organizations are admitted.
    pub allow_foreign_corporate_profiles: bool,
}

impl LoginSettings {
    /// Whether any incoming federated sign-in is admitted: derived, never
    /// stored.
    pub const fn admits_federated_sign_in(self) -> bool {
        self.allow_personal_profiles || self.allow_foreign_corporate_profiles
    }
}

#[cfg(test)]
mod tests;
