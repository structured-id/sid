// SPDX-License-Identifier: AGPL-3.0-only
//! Profiles, their principals, credentials and devices as the identity API's
//! messages. A stored value that does not convert (an identifier of the wrong
//! kind, a corrupt passkey record, an unknown OPAQUE curve) is an internal
//! failure, never sent as it is.

use sid_core::models::{Device, Profile, ProfileEmail, ProfilePhone, profile::ExportStatus};
use sid_proto::sid::v1;

use super::{IdentityError, internal};
use crate::wire::{stored_id, to_timestamp};

/// A stored reference of kind `D` as its message `W`.
fn stored<D, W>(id: uuid::Uuid) -> Result<Option<W>, IdentityError>
where
    D: TryFrom<uuid::Uuid, Error = sid_ids::IdError>,
    W: From<D>,
{
    stored_id::<D, W>(id).map_err(|e| internal("stored identifier", e))
}

pub(crate) fn export_status_to_proto(status: &ExportStatus) -> v1::ExportStatus {
    match status {
        ExportStatus::NotStarted => v1::ExportStatus::NotStarted,
        ExportStatus::Preparing => v1::ExportStatus::Preparing,
        ExportStatus::Ready => v1::ExportStatus::Ready,
        ExportStatus::Downloaded => v1::ExportStatus::Downloaded,
        ExportStatus::Expired => v1::ExportStatus::Expired,
    }
}

/// `p` without its contacts.
pub(crate) fn profile_to_proto(p: &Profile) -> v1::Profile {
    profile_to_proto_with_contacts(p, None, None)
}

/// `p` with its primary email and phone.
pub(crate) fn profile_to_proto_with_contacts(
    p: &Profile,
    primary_email: Option<&ProfileEmail>,
    primary_phone: Option<&ProfilePhone>,
) -> v1::Profile {
    use sid_core::models::{ProfileStatus, ProfileType, ProfileVisibility};

    let profile_type = match p.profile_type {
        ProfileType::Personal => v1::ProfileType::Personal,
        ProfileType::Corporate => v1::ProfileType::Corporate,
    };
    let status = match p.status {
        ProfileStatus::Active => v1::ProfileStatus::Active,
        ProfileStatus::Provisioned => v1::ProfileStatus::Provisioned,
        ProfileStatus::Suspended => v1::ProfileStatus::Suspended,
        ProfileStatus::ClosureRequested => v1::ProfileStatus::ClosureRequested,
        ProfileStatus::ExportAvailable => v1::ProfileStatus::ExportAvailable,
        ProfileStatus::GracePeriod => v1::ProfileStatus::GracePeriod,
        ProfileStatus::LegalHold => v1::ProfileStatus::LegalHold,
        ProfileStatus::Closed => v1::ProfileStatus::Closed,
        ProfileStatus::Purged => v1::ProfileStatus::Purged,
    };
    let visibility = match p.visibility {
        ProfileVisibility::Public => v1::ProfileVisibility::Public,
        ProfileVisibility::Private => v1::ProfileVisibility::Private,
    };

    v1::Profile {
        id: Some(p.id.into()),
        profile_type: profile_type.into(),
        username: p.username.clone(),
        email: primary_email.map(|e| e.email.clone()),
        email_verified: primary_email.is_some_and(|e| e.verified),
        phone: primary_phone.map(|p| p.formatted_e164()),
        phone_verified: primary_phone.is_some_and(|p| p.verified),
        given_name: p.given_name.clone(),
        family_name: p.family_name.clone(),
        middle_name: p.middle_name.clone(),
        honorific_prefix: p.honorific_prefix.clone(),
        honorific_suffix: p.honorific_suffix.clone(),
        formatted_name: p.formatted_name(),
        avatar_url: None,
        status: status.into(),
        visibility: visibility.into(),
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
        last_login_at: None,
        principals: vec![],
    }
}

/// `p` as a login handle its holder manages; none for a federated subject,
/// which is a federation association.
pub(crate) fn principal_to_proto(
    p: &sid_core::models::Principal,
) -> Result<Option<v1::Principal>, IdentityError> {
    use sid_core::models::PrincipalType;

    let principal_type = match p.principal_type {
        PrincipalType::Email => v1::PrincipalType::Email,
        PrincipalType::Phone => v1::PrincipalType::Phone,
        PrincipalType::Username => v1::PrincipalType::Username,
        PrincipalType::FaceEmbedding => v1::PrincipalType::FaceEmbedding,
        PrincipalType::NfcTag => v1::PrincipalType::NfcTag,
        PrincipalType::FederatedSubject => return Ok(None),
    };
    let source_email_id = match p.source_email_id {
        Some(id) => stored::<sid_ids::ProfileEmailId, _>(id.0)?,
        None => None,
    };

    Ok(Some(v1::Principal {
        id: stored::<sid_ids::PrincipalId, _>(p.id.0)?,
        r#type: principal_type.into(),
        value: p.value.clone(),
        verified: p.verified,
        is_primary: p.is_primary,
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
        source_field: p.source_field.clone(),
        source_email_id,
        // An email key of another revision than this build derives keys
        // under routes nothing until its address is established again.
        needs_address_confirmation: p.principal_type == PrincipalType::Email
            && p.email_policy_revision
                != Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION),
    }))
}

/// Display-safe facts of a stored passkey record. A record that does not
/// decode is an error: it is corrupt, not "no info".
pub(crate) fn extract_webauthn_info(data: &[u8]) -> sid_core::Result<v1::credential::Info> {
    use sid_authn::webauthn::{PasskeyAttachment, PasskeyTransport, passkey_info};
    use v1::{AuthenticatorAttachment, AuthenticatorTransport, WebAuthnCredentialInfo};

    let info = passkey_info(data)?;
    let transports = info
        .transports
        .iter()
        .filter_map(|t| match t {
            PasskeyTransport::Usb => Some(AuthenticatorTransport::Usb as i32),
            PasskeyTransport::Nfc => Some(AuthenticatorTransport::Nfc as i32),
            PasskeyTransport::Ble => Some(AuthenticatorTransport::Ble as i32),
            PasskeyTransport::Internal => Some(AuthenticatorTransport::Internal as i32),
            PasskeyTransport::Hybrid => Some(AuthenticatorTransport::Hybrid as i32),
            // The wire enum has no smart-card value; the hint is display-only.
            PasskeyTransport::SmartCard => None,
        })
        .collect();
    let attachment = match info.attachment {
        PasskeyAttachment::Unknown => AuthenticatorAttachment::Unspecified,
        PasskeyAttachment::Platform => AuthenticatorAttachment::Platform,
        PasskeyAttachment::CrossPlatform => AuthenticatorAttachment::CrossPlatform,
    } as i32;
    Ok(v1::credential::Info::WebauthnInfo(WebAuthnCredentialInfo {
        transports,
        backup_eligible: info.backup_eligible,
        backup_state: info.backed_up,
        attachment,
        attestation_format: info.attestation_format.to_string(),
        user_verified: info.user_verified,
    }))
}

/// The curve recorded with an OPAQUE credential, which sign-in and the
/// reported configuration both use. Never the deployment's current primary
/// for new passwords: a record without its configuration, or with one this
/// build does not know, is an error, so a setting change cannot alter how an
/// existing password signs in.
pub(crate) fn opaque_curve(
    c: &sid_core::models::Credential,
) -> Result<sid_plugin::crypto::CurveId, IdentityError> {
    let Some(raw) = c.opaque_curve else {
        return Err(internal(
            "read OPAQUE curve",
            format!("credential {} has no recorded configuration", c.id.0),
        ));
    };
    sid_plugin::crypto::CurveId::try_from(raw).map_err(|_| {
        internal(
            "read OPAQUE curve",
            format!("credential {} has curve {raw}", c.id.0),
        )
    })
}

/// The `info` of a credential's message: its passkey facts for a WebAuthn
/// credential, its OPAQUE configuration for a password, nothing for another
/// type.
pub(crate) fn credential_info(
    c: &sid_core::models::Credential,
) -> Result<Option<v1::credential::Info>, IdentityError> {
    use sid_core::models::CredentialType;
    use sid_plugin::crypto::CurveId;
    use v1::{OpaqueCredentialInfo, OpaqueSuite, credential::Info};
    match c.credential_type {
        CredentialType::WebAuthn => extract_webauthn_info(c.data.expose())
            .map(Some)
            .map_err(|e| internal("read stored passkey", e)),
        CredentialType::Opaque => {
            let suite = match opaque_curve(c)? {
                CurveId::Pallas => OpaqueSuite::PallasV1,
                CurveId::Ristretto255 => OpaqueSuite::Ristretto255V1,
                CurveId::P256 => OpaqueSuite::P256V1,
                CurveId::P384 => OpaqueSuite::P384V1,
                CurveId::P521 => OpaqueSuite::P521V1,
            };
            Ok(Some(Info::OpaqueInfo(OpaqueCredentialInfo {
                suite: suite as i32,
            })))
        }
        _ => Ok(None),
    }
}

/// `cred` as the wire carries it: never its secret material.
pub(crate) fn credential_to_proto(
    cred: sid_core::models::Credential,
) -> Result<v1::Credential, IdentityError> {
    use sid_core::models::CredentialType as Domain;
    let info = credential_info(&cred)?;
    Ok(v1::Credential {
        id: stored::<sid_ids::CredentialId, _>(cred.id.0)?,
        r#type: match cred.credential_type {
            Domain::Opaque => v1::CredentialType::Opaque,
            Domain::WebAuthn => v1::CredentialType::Webauthn,
            Domain::Totp => v1::CredentialType::Totp,
            Domain::Recovery => v1::CredentialType::Recovery,
            Domain::LegacyHash => v1::CredentialType::LegacyHash,
        }
        .into(),
        data: vec![],
        label: cred.label,
        created_at: Some(to_timestamp(cred.created_at)),
        last_used_at: cred.last_used_at.map(to_timestamp),
        info,
    })
}

pub(crate) fn device_to_proto(d: &Device) -> v1::Device {
    use sid_core::models::device::{DeviceAssurance, DeviceType};

    let device_type = match d.device_type {
        DeviceType::Desktop => v1::DeviceType::Desktop,
        DeviceType::Mobile => v1::DeviceType::Mobile,
        DeviceType::Browser => v1::DeviceType::Browser,
        DeviceType::Iot => v1::DeviceType::Iot,
        DeviceType::Embedded => v1::DeviceType::Embedded,
    };
    let assurance = match d.assurance {
        DeviceAssurance::Unknown => v1::DeviceAssurance::Unknown,
        DeviceAssurance::Recognized => v1::DeviceAssurance::Recognized,
        DeviceAssurance::Trusted => v1::DeviceAssurance::Trusted,
        DeviceAssurance::Managed => v1::DeviceAssurance::Managed,
    };

    v1::Device {
        id: Some(d.id.into()),
        display_name: d.display_name.clone(),
        device_type: device_type.into(),
        os_info: d.os_info.clone(),
        assurance: assurance.into(),
        trusted: d.trusted,
        hardware_attested: d.hardware_attested,
        last_ip_geo: d.last_ip_geo.clone(),
        first_seen_at: Some(to_timestamp(d.first_seen_at)),
        last_seen_at: Some(to_timestamp(d.last_seen_at)),
    }
}

#[cfg(test)]
mod tests;
