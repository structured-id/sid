// SPDX-License-Identifier: AGPL-3.0-only
//! Converters between `sid_core::models` and `sid_proto::sid::v1` types.

use chrono::{DateTime, Utc};
use sid_core::models::{
    Device, Profile, ProfileEmail, ProfileId, ProfilePhone, profile::ExportStatus,
};

/// Convert `chrono::DateTime<Utc>` to `prost_types::Timestamp`.
pub(crate) fn to_timestamp(dt: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// Convert core `ExportStatus` to proto `ExportStatus` enum.
pub(crate) fn export_status_to_proto(status: &ExportStatus) -> sid_proto::sid::v1::ExportStatus {
    match status {
        ExportStatus::NotStarted => sid_proto::sid::v1::ExportStatus::NotStarted,
        ExportStatus::Preparing => sid_proto::sid::v1::ExportStatus::Preparing,
        ExportStatus::Ready => sid_proto::sid::v1::ExportStatus::Ready,
        ExportStatus::Downloaded => sid_proto::sid::v1::ExportStatus::Downloaded,
        ExportStatus::Expired => sid_proto::sid::v1::ExportStatus::Expired,
    }
}

/// Convert core `Profile` to proto `Profile`.
///
/// Primary email/phone populated from profile_emails/profile_phones tables.
pub(crate) fn profile_to_proto(p: &Profile) -> sid_proto::sid::v1::Profile {
    profile_to_proto_with_contacts(p, None, None)
}

/// Convert core `Profile` to proto `Profile` with primary contacts.
pub(crate) fn profile_to_proto_with_contacts(
    p: &Profile,
    primary_email: Option<&ProfileEmail>,
    primary_phone: Option<&ProfilePhone>,
) -> sid_proto::sid::v1::Profile {
    use sid_core::models::{ProfileStatus, ProfileType, ProfileVisibility};

    let proto_type = match p.profile_type {
        ProfileType::Personal => sid_proto::sid::v1::ProfileType::Personal,
        ProfileType::Corporate => sid_proto::sid::v1::ProfileType::Corporate,
    };

    let proto_status = match p.status {
        ProfileStatus::Active => sid_proto::sid::v1::ProfileStatus::Active,
        ProfileStatus::Provisioned => sid_proto::sid::v1::ProfileStatus::Provisioned,
        ProfileStatus::Suspended => sid_proto::sid::v1::ProfileStatus::Suspended,
        ProfileStatus::ClosureRequested => sid_proto::sid::v1::ProfileStatus::ClosureRequested,
        ProfileStatus::ExportAvailable => sid_proto::sid::v1::ProfileStatus::ExportAvailable,
        ProfileStatus::GracePeriod => sid_proto::sid::v1::ProfileStatus::GracePeriod,
        ProfileStatus::LegalHold => sid_proto::sid::v1::ProfileStatus::LegalHold,
        ProfileStatus::Closed => sid_proto::sid::v1::ProfileStatus::Closed,
        ProfileStatus::Purged => sid_proto::sid::v1::ProfileStatus::Purged,
    };

    let proto_visibility = match p.visibility {
        ProfileVisibility::Public => sid_proto::sid::v1::ProfileVisibility::Public,
        ProfileVisibility::Private => sid_proto::sid::v1::ProfileVisibility::Private,
    };

    sid_proto::sid::v1::Profile {
        id: p.id.to_string(),
        profile_type: proto_type.into(),
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
        status: proto_status.into(),
        visibility: proto_visibility.into(),
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
        last_login_at: None,
        principals: vec![],
    }
}

/// Convert core `Principal` to proto `Principal`.
pub(crate) fn principal_to_proto(p: &sid_core::models::Principal) -> sid_proto::sid::v1::Principal {
    use sid_core::models::PrincipalType;

    let proto_type = match p.principal_type {
        PrincipalType::Email => sid_proto::sid::v1::PrincipalType::Email,
        PrincipalType::Phone => sid_proto::sid::v1::PrincipalType::Phone,
        PrincipalType::Username => sid_proto::sid::v1::PrincipalType::Username,
        PrincipalType::FaceEmbedding => sid_proto::sid::v1::PrincipalType::FaceEmbedding,
        PrincipalType::NfcTag => sid_proto::sid::v1::PrincipalType::NfcTag,
    };

    sid_proto::sid::v1::Principal {
        id: p.id.0.to_string(),
        r#type: proto_type.into(),
        value: p.value.clone(),
        verified: p.verified,
        is_primary: p.is_primary,
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
        source_field: p.source_field.clone(),
        source_email_id: p.source_email_id.map(|id| id.0.to_string()),
        // An email key of another revision than this build derives keys
        // under routes nothing until its address is established again.
        needs_address_confirmation: p.principal_type == PrincipalType::Email
            && p.email_policy_revision
                != Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION),
    }
}

/// Convert domain `ProfilePhone` to proto `ProfilePhone`.
pub(crate) fn phone_to_proto(p: &ProfilePhone) -> sid_proto::sid::v1::ProfilePhone {
    use sid_core::models::profile_phone::PhoneLabel;

    let proto_label = match p.label {
        PhoneLabel::Mobile => sid_proto::sid::v1::PhoneLabel::Mobile,
        PhoneLabel::Home => sid_proto::sid::v1::PhoneLabel::Home,
        PhoneLabel::Work => sid_proto::sid::v1::PhoneLabel::Work,
        PhoneLabel::Fax => sid_proto::sid::v1::PhoneLabel::Fax,
        PhoneLabel::Pager => sid_proto::sid::v1::PhoneLabel::Pager,
        PhoneLabel::Main => sid_proto::sid::v1::PhoneLabel::Main,
        PhoneLabel::Other => sid_proto::sid::v1::PhoneLabel::Other,
        PhoneLabel::Custom => sid_proto::sid::v1::PhoneLabel::Custom,
    };

    sid_proto::sid::v1::ProfilePhone {
        id: p.id.0.to_string(),
        e164: p.e164,
        extension: p.extension,
        label: proto_label.into(),
        custom_label: p.custom_label.clone(),
        is_primary: p.is_primary,
        can_receive_sms: p.can_receive_sms,
        can_receive_fax: p.can_receive_fax,
        can_receive_voice: p.can_receive_voice,
        verified: p.verified,
        verified_at: p.verified_at.map(to_timestamp),
    }
}

/// Convert domain `ProfileEmail` to proto `ProfileEmail`.
pub(crate) fn email_to_proto(e: &ProfileEmail) -> sid_proto::sid::v1::ProfileEmail {
    use sid_core::models::profile_email::EmailLabel;

    let proto_label = match e.label {
        EmailLabel::Personal => sid_proto::sid::v1::EmailLabel::Personal,
        EmailLabel::Work => sid_proto::sid::v1::EmailLabel::Work,
        EmailLabel::School => sid_proto::sid::v1::EmailLabel::School,
        EmailLabel::Other => sid_proto::sid::v1::EmailLabel::Other,
        EmailLabel::Custom => sid_proto::sid::v1::EmailLabel::Custom,
    };

    sid_proto::sid::v1::ProfileEmail {
        id: e.id.0.to_string(),
        email: e.email.clone(),
        label: proto_label.into(),
        custom_label: e.custom_label.clone(),
        is_primary: e.is_primary,
        verified: e.verified,
        verified_at: e.verified_at.map(to_timestamp),
    }
}

/// Parse a profile ID string, returning a tonic status on failure.
#[allow(clippy::result_large_err)]
pub(crate) fn parse_profile_id(id: &str) -> Result<ProfileId, tonic::Status> {
    ProfileId::parse(id).map_err(|_| {
        sid_core::grpc_error::refuse::invalid_field("profile_id", "not a profile identifier")
    })
}

/// Display-safe WebAuthn credential info from a stored passkey record. A
/// record that does not decode is an error: it is corrupt, not "no info".
pub(crate) fn extract_webauthn_info(
    data: &[u8],
) -> sid_core::Result<sid_proto::sid::v1::credential::Info> {
    use sid_authn::webauthn::{PasskeyAttachment, PasskeyTransport, passkey_info};
    use sid_proto::sid::v1::{
        AuthenticatorAttachment, AuthenticatorTransport, WebAuthnCredentialInfo,
    };

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
    Ok(sid_proto::sid::v1::credential::Info::WebauthnInfo(
        WebAuthnCredentialInfo {
            transports,
            backup_eligible: info.backup_eligible,
            backup_state: info.backed_up,
            attachment,
            attestation_format: info.attestation_format.to_string(),
            user_verified: info.user_verified,
        },
    ))
}

/// The `info` of a credential's proto: its passkey facts for a WebAuthn
/// credential, its OPAQUE suite for a password, nothing for another type.
#[allow(clippy::result_large_err)]
pub(crate) fn credential_info(
    c: &sid_core::models::Credential,
) -> Result<Option<sid_proto::sid::v1::credential::Info>, tonic::Status> {
    use sid_core::models::CredentialType;
    use sid_plugin::crypto::CurveId;
    use sid_proto::sid::v1::{OpaqueCredentialInfo, OpaqueSuite, credential::Info};
    match c.credential_type {
        CredentialType::WebAuthn => extract_webauthn_info(c.data.expose())
            .map(Some)
            .map_err(|e| sid_core::grpc_error::refuse::internal("read stored passkey", e)),
        CredentialType::Opaque => {
            // A credential stored before its curve was recorded is in the
            // primary suite, Pallas.
            let curve = match c.opaque_curve {
                None => CurveId::Pallas,
                Some(raw) => CurveId::try_from(raw).map_err(|_| {
                    sid_core::grpc_error::refuse::internal(
                        "read OPAQUE curve",
                        format!("credential {} has curve {raw}", c.id.0),
                    )
                })?,
            };
            let suite = match curve {
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

/// Convert core `Device` to proto `Device`.
pub(crate) fn device_to_proto(d: &Device) -> sid_proto::sid::v1::Device {
    use sid_core::models::device::{DeviceAssurance, DeviceType};

    let device_type = match d.device_type {
        DeviceType::Desktop => sid_proto::sid::v1::DeviceType::Desktop,
        DeviceType::Mobile => sid_proto::sid::v1::DeviceType::Mobile,
        DeviceType::Browser => sid_proto::sid::v1::DeviceType::Browser,
        DeviceType::Iot => sid_proto::sid::v1::DeviceType::Iot,
        DeviceType::Embedded => sid_proto::sid::v1::DeviceType::Embedded,
    };

    let assurance = match d.assurance {
        DeviceAssurance::Unknown => sid_proto::sid::v1::DeviceAssurance::Unknown,
        DeviceAssurance::Recognized => sid_proto::sid::v1::DeviceAssurance::Recognized,
        DeviceAssurance::Trusted => sid_proto::sid::v1::DeviceAssurance::Trusted,
        DeviceAssurance::Managed => sid_proto::sid::v1::DeviceAssurance::Managed,
    };

    sid_proto::sid::v1::Device {
        id: d.id.to_string(),
        profile_id: d.profile_id.to_string(),
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
