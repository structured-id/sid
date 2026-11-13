// SPDX-License-Identifier: AGPL-3.0-only
//! The SID identity purposes a certificate's key is bound to, as explicit
//! extended key usages: the issuer roles of the platform intermediate and of
//! an organization's authority, and the leaf purposes, read under one
//! explicit allocation. Production has none until its allocation is
//! registered, so it accepts no SID purpose, and a development purpose is
//! refused under any other allocation, on an intermediate or anchor as on a
//! leaf.
//!
//! Reading a role from a certificate tells a verifier what that authority
//! may have issued. It gives the reader no authority or key to issue.

use der::Decode;
use der::asn1::ObjectIdentifier;
use der::oid::AssociatedOid;
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::allocation::ContextAllocation;

/// The identifiers the SID purposes are written and read under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposeProfile {
    /// `id-sid-platform-intermediate`: the platform's issuing intermediate.
    pub platform_intermediate: ObjectIdentifier,
    /// `id-sid-organization-ca`: an organization's delegated authority.
    pub organization_ca: ObjectIdentifier,
    /// `id-sid-agent-member-issuer`: an agent candidate authority.
    pub agent_member_issuer: ObjectIdentifier,
    /// `id-sid-key-association`: an authorized key-association signer.
    pub key_association: ObjectIdentifier,
    /// `id-sid-agent-part`: an agent part's credential.
    pub agent_part: ObjectIdentifier,
}

/// The temporary allocation of development installations, continuing the
/// Binding Passport's documentation arc (RFC 5612).
pub const DEVELOPMENT_PURPOSES: PurposeProfile = PurposeProfile {
    platform_intermediate: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.6"),
    organization_ca: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.7"),
    agent_member_issuer: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.8"),
    key_association: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.9"),
    agent_part: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.10"),
};

/// The registered structured.id allocation: none until the enterprise number
/// is assigned.
pub const SID_PURPOSES: Option<PurposeProfile> = None;

/// Why a purpose was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurposeError {
    /// Production has no registered allocation yet.
    #[error("no registered SID purpose identifier allocation")]
    NoAllocation,
    /// A certificate carries a development purpose read under another
    /// allocation.
    #[error("a development SID purpose is not accepted under this allocation")]
    DevelopmentPurpose,
    /// The certificate's extended key usage does not decode.
    #[error("the extended key usage is malformed")]
    Malformed,
}

/// The SID role a certificate's key holds as an issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerRole {
    PlatformIntermediate,
    OrganizationCa,
    AgentMemberIssuer,
}

/// What a SID issuer issues: an authority in an issuer role, or a Binding
/// Passport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issued {
    Ca(IssuerRole),
    /// A Personal passport: no source organization.
    PersonalPassport,
    /// A Corporate passport: issued for a source organization.
    CorporatePassport,
}

impl IssuerRole {
    /// The SID issuance transitions: the platform intermediate issues
    /// organization authorities and Personal passports; an organization's
    /// authority issues its Corporate passports and an agent candidate
    /// authority. Nothing else.
    pub fn may_issue(self, issued: Issued) -> bool {
        matches!(
            (self, issued),
            (
                Self::PlatformIntermediate,
                Issued::Ca(Self::OrganizationCa) | Issued::PersonalPassport
            ) | (
                Self::OrganizationCa,
                Issued::CorporatePassport | Issued::Ca(Self::AgentMemberIssuer)
            )
        )
    }
}

impl PurposeProfile {
    /// The profile of `allocation`; production refuses without its
    /// registered allocation, and never takes the development one.
    pub fn of(allocation: ContextAllocation) -> Result<Self, PurposeError> {
        match allocation {
            ContextAllocation::Development => Ok(DEVELOPMENT_PURPOSES),
            ContextAllocation::Production => SID_PURPOSES
                .filter(|p| !p.shares_identifiers_with(&DEVELOPMENT_PURPOSES))
                .ok_or(PurposeError::NoAllocation),
        }
    }

    fn identifiers(&self) -> [ObjectIdentifier; 5] {
        [
            self.platform_intermediate,
            self.organization_ca,
            self.agent_member_issuer,
            self.key_association,
            self.agent_part,
        ]
    }

    fn shares_identifiers_with(&self, other: &Self) -> bool {
        self.identifiers()
            .iter()
            .any(|oid| other.identifiers().contains(oid))
    }

    /// The extended key usage that names `role`.
    pub fn issuer_usage(&self, role: IssuerRole) -> ExtendedKeyUsage {
        ExtendedKeyUsage(vec![match role {
            IssuerRole::PlatformIntermediate => self.platform_intermediate,
            IssuerRole::OrganizationCa => self.organization_ca,
            IssuerRole::AgentMemberIssuer => self.agent_member_issuer,
        }])
    }

    /// `issuer` holds a role that may issue `issued`.
    pub fn may_issue(&self, issuer: &Certificate, issued: Issued) -> Result<bool, PurposeError> {
        Ok(self
            .issuer_roles(issuer)?
            .into_iter()
            .any(|role| role.may_issue(issued)))
    }

    /// The issuer roles `certificate` holds under this profile: none when it
    /// names no extended key usage, which is no SID authority. A development
    /// purpose read under another profile is refused.
    pub fn issuer_roles(&self, certificate: &Certificate) -> Result<Vec<IssuerRole>, PurposeError> {
        let usages = usages(certificate)?;
        if *self != DEVELOPMENT_PURPOSES
            && usages
                .iter()
                .any(|oid| DEVELOPMENT_PURPOSES.identifiers().contains(oid))
        {
            return Err(PurposeError::DevelopmentPurpose);
        }
        Ok(usages
            .iter()
            .filter_map(|oid| {
                if *oid == self.platform_intermediate {
                    Some(IssuerRole::PlatformIntermediate)
                } else if *oid == self.organization_ca {
                    Some(IssuerRole::OrganizationCa)
                } else if *oid == self.agent_member_issuer {
                    Some(IssuerRole::AgentMemberIssuer)
                } else {
                    None
                }
            })
            .collect())
    }
}

/// The extended key usages `certificate` names; none when it has no such
/// extension. More than one such extension is malformed (RFC 5280 §4.2).
fn usages(certificate: &Certificate) -> Result<Vec<ObjectIdentifier>, PurposeError> {
    let Some(extensions) = certificate.tbs_certificate().extensions() else {
        return Ok(Vec::new());
    };
    let mut found = extensions
        .iter()
        .filter(|e| e.extn_id == ExtendedKeyUsage::OID);
    let Some(extension) = found.next() else {
        return Ok(Vec::new());
    };
    if found.next().is_some() {
        return Err(PurposeError::Malformed);
    }
    ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())
        .map(|usage| usage.0)
        .map_err(|_| PurposeError::Malformed)
}

#[cfg(test)]
mod tests;
