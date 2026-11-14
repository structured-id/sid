// SPDX-License-Identifier: AGPL-3.0-only
//! Who a returned federated entry signs in, and whether it is let in.
//!
//! In plain words: a browser came back from another SID installation with
//! that installation's word that it signed somebody in. Two kinds of
//! identity can come back.
//!
//! One of this organization's own Profiles, returning through the authority
//! the installation's provisioning set: its organization confirmed
//! beforehand which Profile that subject is, and it signs in as that
//! Profile.
//!
//! An identity this organization did not issue: someone's own (a Personal
//! Profile), or one another organization gave its employee (that
//! organization's Corporate Profile). The organization decides in its login
//! settings whether it admits either kind at all. When it does, the visitor
//! must show that the identity is really theirs for this one sign-in: the
//! issuer's token alone is not that proof. Only then does the installation
//! keep a record of its own for the visitor, and that record grants nothing
//! by itself.

use std::time::SystemTime;

use sid_authn::federated_entry::Returned;
use sid_core::models::{
    AuditEntry, ConnectionOwner, EntryConnection, OidcIssuer, OrgId, Origin,
    PrincipalAssignmentFence, PrincipalType, Profile, federated_subject_value,
};
use sid_fed::binding_passport::Passport;
use sid_fed::presentation::Expected;
use sid_fed::recipient::{PresentedIdentities, RecipientError};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use crate::federated_record::{Record, RecordError, record_of};

/// The origin of the accepted `passport` at the recipient `organization`,
/// decided by the organization the passport names as its source; `Ok(None)`
/// for a passport the organization's own authority issued, which is not an
/// outside identity. A source that is no organization id names no origin at
/// all.
fn origin(passport: &Passport, organization: OrgId) -> Result<Option<Origin>, Refused> {
    let source = passport
        .source_org
        .map(|uuid| OrgId::from_uuid(uuid).map_err(|_| Refused::NotAdmitted))
        .transpose()?;
    Ok(Origin::of(source, organization))
}

/// Why a returned entry signs nobody in.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    /// The issuer's subject is not a Binding.
    #[error("the subject the issuer signed in is no Binding")]
    NoBinding,
    /// The organization admits no outside identity of this kind.
    #[error("the organization's login settings do not admit this identity")]
    NotAdmitted,
    /// The issuer returned no presentation: its token alone proves no
    /// holder.
    #[error("the sign-in carried no presentation of the identity")]
    NoPresentation,
    /// The presentation is not its holder's answer to this sign-in, or its
    /// passport is not accepted.
    #[error("the presentation is refused: {0}")]
    Presentation(RecipientError),
    /// The presentation certifies another identity than the one the issuer
    /// signed in.
    #[error("the presentation is of another identity than the one signed in")]
    AnotherIdentity,
    /// The connection is registered for one organization, and the Corporate
    /// Profile presented through it is another's.
    #[error("the Corporate Profile is of another organization than the connection's")]
    AnotherSource,
    /// The passport is the organization's own: its holder signs in through
    /// the assignment the organization confirmed, never as an outside one.
    #[error("the identity is the organization's own")]
    Own,
    /// A dependency could not answer; the same return may be retried.
    #[error("not decided now: {0}")]
    Unavailable(String),
}

impl Refused {
    /// Whether the same return may be retried: nothing was refused.
    pub const fn retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

fn unavailable(e: impl std::fmt::Display) -> Refused {
    Refused::Unavailable(e.to_string())
}

/// What a returned entry carries for the admission of an outside identity.
#[derive(Debug, Clone, Copy)]
pub struct Pending<'a> {
    /// The presentation the issuer returned, as received.
    pub presentation: Option<&'a [u8]>,
    /// The entry's one-time challenge.
    pub challenge: &'a str,
    /// The verifier context the entry was started for.
    pub verifier_context: &'a str,
}

impl<'a> From<&'a Returned> for Pending<'a> {
    fn from(returned: &'a Returned) -> Self {
        Self {
            presentation: returned.presentation.as_deref(),
            challenge: &returned.challenge,
            verifier_context: &returned.verifier_context,
        }
    }
}

/// The Profile the entry `returned` through `connection` signs in at the
/// installation issuer `issuer`, with the assignment its session commits
/// under.
///
/// A subject the organization assigned to one of its own Profiles resolves
/// to it on the issuer's evidence alone, and only through the provisioned
/// authority: a connection an administrator registered never reaches those
/// assignments. Any other subject is an identity the organization did not
/// issue, admitted on every entry only through [`admit`], whether or not
/// its record exists yet.
pub async fn resolve(
    storage: &dyn StorageBackend,
    identities: &dyn PresentedIdentities,
    issuer: &OidcIssuer,
    connection: &EntryConnection,
    returned: &Returned,
    at: SystemTime,
) -> Result<(Profile, PrincipalAssignmentFence), Refused> {
    // The subject is the recipient Binding the issuer signs the holder in
    // as, in the canonical form its assignment was recorded under.
    let subject = Uuid::parse_str(&returned.subject).map_err(|_| Refused::NoBinding)?;
    if connection.owner == ConnectionOwner::Provisioning {
        let principal = storage
            .get_principal_by_value(
                PrincipalType::FederatedSubject,
                &federated_subject_value(&connection.issuer, &subject.to_string()),
            )
            .await
            .map_err(unavailable)?;
        // The assignment the session commits under: retired or moved before
        // the commit, nothing is signed in.
        if let Some(assignment) = principal.as_ref().and_then(PrincipalAssignmentFence::of) {
            let profile = storage
                .get_profile(assignment.profile)
                .await
                .map_err(unavailable)?
                .ok_or(Refused::NotAdmitted)?;
            if profile.profile_type.is_local() {
                return Ok((profile, assignment));
            }
        }
    }
    let record = admit(
        storage,
        identities,
        issuer.recipient_org,
        connection,
        subject,
        returned.into(),
        at,
    )
    .await?;
    Ok((record.profile, record.assignment))
}

/// Admit the outside identity the issuer of `connection` signed in as
/// `subject` on the entry `returned`, for the recipient `organization`: its
/// login settings admit some outside identity, the presentation is the
/// holder's answer to exactly this entry, it certifies that same subject,
/// a Corporate Profile is of the organization the connection is registered
/// for, the settings admit its origin, and then its record is found or
/// created.
pub async fn admit(
    storage: &dyn StorageBackend,
    identities: &dyn PresentedIdentities,
    organization: OrgId,
    connection: &EntryConnection,
    subject: Uuid,
    returned: Pending<'_>,
    at: SystemTime,
) -> Result<Record, Refused> {
    let settings = crate::login_settings::in_force(storage)
        .await
        .map_err(unavailable)?;
    // Nothing is verified for an organization that admits nobody.
    if !settings.admits_federated_sign_in() {
        return Err(Refused::NotAdmitted);
    }
    let presentation = returned.presentation.ok_or(Refused::NoPresentation)?;
    // Verified under the allocation of the platform intermediates this
    // installation holds: admitting an outside identity needs no
    // organization authority of its own.
    let allocation = identities
        .platform_allocation(at)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("no platform CA set to verify under"))?;
    let expected = Expected {
        recipient: organization.into(),
        challenge: returned.challenge,
        domain: returned.verifier_context,
    };
    let passport = identities
        .accept_presentation(allocation, presentation, &expected, at)
        .await
        .map_err(|e| {
            // The evidence to decide on is missing now, not refused.
            if e.undecided() {
                unavailable(e)
            } else {
                Refused::Presentation(e)
            }
        })?;
    // The token's subject and the passport's Binding are one identity.
    if passport.binding_id != subject {
        return Err(Refused::AnotherIdentity);
    }
    // Decided on the settings read for this completion, by the organization
    // the accepted passport names: a Corporate Profile is admitted only from
    // a source the recipient named, whatever the Personal switch says.
    let origin = origin(&passport, organization)?.ok_or(Refused::Own)?;
    // A connection registered for one organization brings in no other
    // organization's Corporate Profile, though the settings name that one.
    if let (Some(registered), Origin::Corporate(source)) = (connection.source, origin)
        && registered != source
    {
        return Err(Refused::AnotherSource);
    }
    if !settings.admits(origin) {
        return Err(Refused::NotAdmitted);
    }
    let ctx = AuditEntry::system("federated_entry.admit", format!("subject/{subject}")).into();
    record_of(storage, &connection.issuer, subject, ctx)
        .await
        .map_err(|e| match e {
            RecordError::OwnProfile => Refused::Own,
            RecordError::Released | RecordError::Storage(_) => unavailable(e),
        })
}

#[cfg(test)]
mod tests;
