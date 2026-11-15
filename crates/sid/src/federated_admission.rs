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
    ActorFence, AuditEntry, ConnectionOwner, EntryConnection, OidcIssuer, OrgId, Origin,
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
    /// The connection the entry went through was disabled, changed or
    /// removed since the entry used it: nothing is completed through it.
    #[error("the entry connection was withdrawn or changed")]
    ConnectionChanged,
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

/// Who a returned entry signs in and what its session commits under.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub profile: Profile,
    /// The assignment of the issuer's subject to `profile`.
    pub assignment: PrincipalAssignmentFence,
    /// The login settings an outside identity was admitted under: its
    /// session commits only while no settings write moved them on. None for
    /// the organization's own Profile, which the settings do not decide.
    pub admission: Option<ActorFence>,
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
) -> Result<Resolved, Refused> {
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
                return Ok(Resolved {
                    profile,
                    assignment,
                    admission: None,
                });
            }
        }
    }
    let admitted = admit(
        storage,
        identities,
        issuer.recipient_org,
        connection,
        subject,
        returned.into(),
        at,
    )
    .await?;
    Ok(Resolved {
        profile: admitted.record.profile,
        assignment: admitted.record.assignment,
        admission: admitted.fence,
    })
}

/// An admitted outside identity: its record and the login settings it was
/// admitted under.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub record: Record,
    /// The login-policy epoch read before the settings this admission was
    /// decided on; none while no settings were ever written.
    pub fence: Option<ActorFence>,
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
) -> Result<Admitted, Refused> {
    // Every settings write moves the epoch on: read before the settings, it
    // holds the session commit to them. A write in between moves it past
    // this read, which then fences the commit.
    let fence = storage
        .export_login_policy_epoch()
        .await
        .map_err(unavailable)?
        .map(|epoch| ActorFence::LoginPolicy { epoch });
    // The connection as the entry used it, read again after the epoch: a
    // change or removal that landed meanwhile refuses here, and one landing
    // later moves the epoch past this read and fences the commit.
    let current = storage
        .entry_connection(connection.handle)
        .await
        .map_err(unavailable)?;
    if !current.is_some_and(|c| c.enabled && c.revision == connection.revision) {
        return Err(Refused::ConnectionChanged);
    }
    let settings = crate::login_settings::in_force(storage)
        .await
        .map_err(unavailable)?;
    // Nothing is verified for an organization that admits nobody.
    if !settings.admits_federated_sign_in() {
        return Err(Refused::NotAdmitted);
    }
    let presentation = returned.presentation.ok_or(Refused::NoPresentation)?;
    let expected = Expected {
        recipient: organization.into(),
        challenge: returned.challenge,
        domain: returned.verifier_context,
    };
    // Verified under the platform intermediates this installation holds:
    // admitting an outside identity needs no organization authority of its
    // own. What must be known of withdrawals is the installation's stored
    // policy, read with the settings for this completion: an issuer that
    // cannot be reached never makes it more permissive.
    let accepted = identities
        .accept_presentation(presentation, &expected, &settings.status_policy, at)
        .await
        .map_err(|e| {
            // The evidence to decide on is missing now, not refused.
            if e.undecided() {
                unavailable(e)
            } else {
                Refused::Presentation(e)
            }
        })?;
    let passport = &accepted.passport;
    // The token's subject and the passport's Binding are one identity.
    if passport.binding_id != subject {
        return Err(Refused::AnotherIdentity);
    }
    // Decided on the settings read for this completion, by the organization
    // the accepted passport names: a Corporate Profile is admitted only from
    // a source the recipient named, whatever the Personal switch says.
    let origin = origin(passport, organization)?.ok_or(Refused::Own)?;
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
    // The record of the admission says what was known of withdrawals and
    // under which policy: stale or unknown status the policy admitted is
    // never recorded as shown good.
    let ctx = AuditEntry::system("federated_entry.admit", format!("subject/{subject}"))
        .with_metadata(serde_json::json!({
            "status_policy": settings.status_policy,
            "issuer_status": accepted.issuer,
            "authorities_status": accepted.authorities,
        }))
        .into();
    let record = record_of(storage, &connection.issuer, subject, ctx)
        .await
        .map_err(|e| match e {
            RecordError::OwnProfile => Refused::Own,
            RecordError::Released | RecordError::Storage(_) => unavailable(e),
        })?;
    Ok(Admitted { record, fence })
}

#[cfg(test)]
mod tests;
