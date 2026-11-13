// SPDX-License-Identifier: AGPL-3.0-only
//! The local record of an identity admitted through federation.
//!
//! In plain words: when someone signs in here with an identity that another
//! SID installation vouches for, this installation needs something of its
//! own to attach that visitor's sessions and permissions to. That is a
//! Profile record of type [`ProfileType::Federated`]: a reference to the
//! outside identity, with no password, passkey, login name or key here. It
//! is found only by the pair the trusted issuer signs in: its own
//! identifier and the subject it names for this installation.
//!
//! The record comes into being on the first admitted entry and is the same
//! one on every later entry. Creating it grants nothing: roles and access
//! are given separately.
//!
//! This module does not decide whether an identity is admitted. Its caller
//! has already verified the issuer's evidence and applied the installation's
//! incoming login settings; an identity of the installation's own
//! organization never comes here, it resolves through the assignment its
//! organization confirmed beforehand.

use sid_core::models::{
    MutationContext, NewRegistration, Principal, PrincipalAssignmentFence, PrincipalType, Profile,
    ProfileType, SourceRecording, federated_subject_value,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

/// Why an admitted identity got no record.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The issuer's subject is assigned to one of this installation's own
    /// Profiles: it is not an outside identity, and is never turned into a
    /// reference.
    #[error("the subject is assigned to one of the installation's own Profiles")]
    OwnProfile,
    /// The issuer's subject is known here and routes to no Profile at this
    /// moment: its assignment is being released or its record is gone
    /// while the subject is still held. Nothing is created over it; the
    /// entry can be made again.
    #[error("the identity's assignment routes to no record")]
    Released,
    #[error(transparent)]
    Storage(#[from] sid_core::Error),
}

/// The record of one admitted identity and the assignment a session of it
/// commits under.
#[derive(Debug, Clone)]
pub struct Record {
    pub profile: Profile,
    pub assignment: PrincipalAssignmentFence,
    /// Whether this call created the record.
    pub created: bool,
}

/// The record of the identity `issuer` signs in as `subject`, created with
/// its assignment in one transaction the first time. Two first entries at
/// once end at one record: the assignment's uniqueness decides, and the one
/// that lost reads the winner's.
pub async fn record_of(
    storage: &dyn StorageBackend,
    issuer: &str,
    subject: Uuid,
    ctx: MutationContext,
) -> Result<Record, RecordError> {
    let value = federated_subject_value(issuer, &subject.to_string());
    if let Some(found) = existing(storage, &value).await? {
        return Ok(found);
    }
    let mut profile = Profile::new(None::<&str>);
    profile.profile_type = ProfileType::Federated;
    let principal = Principal::new_federated_subject(profile.id, issuer, &subject.to_string());
    let registration = NewRegistration {
        profile: profile.clone(),
        principal,
        email: None,
        phone: None,
        credential: None,
        source: None,
        instance_claim: None,
        history: None,
        enrollment: None,
        source_recording: SourceRecording::AsGiven,
    };
    match storage.register_profile(&registration, ctx).await {
        Ok(()) => {}
        // Another entry of the same identity created it first.
        Err(sid_core::Error::Conflict(_)) => {
            return existing(storage, &value)
                .await?
                .ok_or(RecordError::Released);
        }
        Err(e) => return Err(e.into()),
    }
    let mut created = existing(storage, &value)
        .await?
        .ok_or(RecordError::Released)?;
    created.created = true;
    Ok(created)
}

/// The record `value` is assigned to, if the assignment exists.
async fn existing(
    storage: &dyn StorageBackend,
    value: &str,
) -> Result<Option<Record>, RecordError> {
    let Some(principal) = storage
        .get_principal_by_value(PrincipalType::FederatedSubject, value)
        .await?
    else {
        return Ok(None);
    };
    let assignment = PrincipalAssignmentFence::of(&principal).ok_or(RecordError::Released)?;
    let profile = storage
        .get_profile(assignment.profile)
        .await?
        .ok_or(RecordError::Released)?;
    if profile.profile_type != ProfileType::Federated {
        return Err(RecordError::OwnProfile);
    }
    Ok(Some(Record {
        profile,
        assignment,
        created: false,
    }))
}

#[cfg(test)]
mod tests;
