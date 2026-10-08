// SPDX-License-Identifier: AGPL-3.0-only
//! New-account unit committed by the storage layer in one transaction.

use super::{
    Credential, EmailLabel, HistoryCommit, PhoneLabel, Principal, PrincipalId, PrincipalType,
    Profile, ProfileEmail, ProfileEmailId, ProfilePhone, ProfilePhoneId, RegistrationSource,
};
use crate::{Error, Result};

/// The identifier a new account signs up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupIdentifier<'a> {
    /// An email: `key` is the resolution key the principal stores, derived
    /// under the email policy `revision`; `address` the validated mailbox in
    /// the spelling given, which the contact stores and mail goes to.
    Email {
        key: &'a str,
        address: &'a str,
        revision: i64,
    },
    /// An E.164 phone number.
    Phone(&'a str),
    /// A username, global or federated.
    Username(&'a str),
}

impl SignupIdentifier<'_> {
    /// The principal type this identifier signs up.
    pub fn principal_type(&self) -> PrincipalType {
        match self {
            Self::Email { .. } => PrincipalType::Email,
            Self::Phone(_) => PrincipalType::Phone,
            Self::Username(_) => PrincipalType::Username,
        }
    }

    /// The value the principal stores: the resolution key.
    pub fn key(&self) -> &str {
        match self {
            Self::Email { key, .. } => key,
            Self::Phone(value) | Self::Username(value) => value,
        }
    }
}

/// Everything a new account starts with: the profile, its single signup
/// principal, the contact rows, the first credential (absent when an
/// administrator provisions the account and its owner sets one up later) and
/// where the account came from, when the site tracks it.
///
/// Stored all-or-nothing; the principal must not exist yet, so a registration can
/// never attach a credential to an account that already holds the identifier.
#[derive(Debug, Clone)]
pub struct NewRegistration {
    pub profile: Profile,
    pub principal: Principal,
    pub email: Option<ProfileEmail>,
    pub phone: Option<ProfilePhone>,
    pub credential: Option<Credential>,
    pub source: Option<RegistrationSource>,
    /// The sealed instance claim the registrant proved: the account becomes the
    /// first administrator and the claim is consumed in the same transaction,
    /// which fails if that claim is no longer stored or an administrator exists.
    pub instance_claim: Option<Vec<u8>>,
    /// The first history epoch and entry of a password registered with an
    /// accepted proof, written with the account. Absent for an unproven
    /// password (D018: no trusted history) or no password.
    pub history: Option<HistoryCommit>,
}

impl NewRegistration {
    /// Attach the history the registered password's accepted proof writes;
    /// it must be the new profile's.
    pub fn with_history(mut self, history: HistoryCommit) -> Result<Self> {
        if history.owner != self.profile.id {
            return Err(Error::Validation(
                "a registration writes history only for its own profile".into(),
            ));
        }
        history.validate()?;
        self.history = Some(history);
        Ok(self)
    }

    /// A new account whose single signup principal is `identifier`. An email
    /// or phone identifier gets its contact row, linked to the principal and
    /// unverified until delivered to; a username is chosen, not delivered to,
    /// so it is verified by construction.
    pub fn new(
        profile: Profile,
        identifier: SignupIdentifier<'_>,
        credential: Option<Credential>,
    ) -> Result<Self> {
        let profile_id = profile.id;
        let now = profile.created_at;
        let mut registration = Self {
            principal: Principal {
                id: PrincipalId::new(),
                profile_id,
                principal_type: identifier.principal_type(),
                value: identifier.key().to_string(),
                verified: false,
                verified_at: None,
                verification_expires: None,
                assigned_profile_id: None,
                assignment_revision: 0,
                email_policy_revision: match identifier {
                    SignupIdentifier::Email { revision, .. } => Some(revision),
                    SignupIdentifier::Phone(_) | SignupIdentifier::Username(_) => None,
                },
                is_primary: true,
                source_field: None,
                source_email_id: None,
                source_phone_id: None,
                created_at: now,
                updated_at: now,
            },
            profile,
            email: None,
            phone: None,
            credential,
            source: None,
            instance_claim: None,
            history: None,
        };
        match identifier {
            SignupIdentifier::Username(_) => {
                registration.principal.verified = true;
                registration.principal.verified_at = Some(now);
                registration.principal.assigned_profile_id = Some(profile_id);
                registration.principal.source_field = Some("username".into());
            }
            SignupIdentifier::Email { address, .. } => {
                registration = registration.with_email(address);
                registration.principal.source_field = Some("email".into());
                registration.principal.source_email_id = registration.email.as_ref().map(|e| e.id);
            }
            SignupIdentifier::Phone(value) => {
                registration = registration.with_phone(parse_e164(value)?);
                registration.principal.source_field = Some("phone".into());
                registration.principal.source_phone_id = registration.phone.as_ref().map(|p| p.id);
            }
        }
        Ok(registration)
    }

    /// Add the primary email contact (unverified).
    pub fn with_email(mut self, email: &str) -> Self {
        let now = self.profile.created_at;
        self.email = Some(ProfileEmail {
            id: ProfileEmailId::new(),
            profile_id: self.profile.id,
            email: email.to_string(),
            label: EmailLabel::Personal,
            custom_label: None,
            is_primary: true,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        });
        self
    }

    /// Record where the account came from, stored with it.
    pub fn with_source(mut self, source: RegistrationSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Register the installation's first administrator with the sealed claim
    /// value the registrant proved (see [`NewRegistration::instance_claim`]).
    pub fn claiming_instance(mut self, sealed_claim: Vec<u8>) -> Self {
        if !self.profile.is_admin() {
            self.profile.roles.push("admin".to_string());
        }
        self.instance_claim = Some(sealed_claim);
        self
    }

    /// Add the primary phone contact (unverified).
    pub fn with_phone(mut self, e164: u64) -> Self {
        let now = self.profile.created_at;
        self.phone = Some(ProfilePhone {
            id: ProfilePhoneId::new(),
            profile_id: self.profile.id,
            e164,
            extension: None,
            label: PhoneLabel::Mobile,
            custom_label: None,
            is_primary: true,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        });
        self
    }
}

#[cfg(test)]
mod tests;

/// An E.164 number (`+` and digits) as its digits.
pub fn parse_e164(value: &str) -> Result<u64> {
    value
        .trim_start_matches('+')
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Validation("invalid phone number".into()))
}
