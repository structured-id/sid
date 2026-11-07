// SPDX-License-Identifier: AGPL-3.0-only
//! Converters between `sid_core::models` and `sid_proto::sid::v1` types the
//! service handlers share. Profiles, principals, credentials and devices are
//! the [`sid::identity`] library's.

use chrono::{DateTime, Utc};
use sid_core::models::{ProfileEmail, ProfilePhone};

/// Convert `chrono::DateTime<Utc>` to `prost_types::Timestamp`.
pub(crate) fn to_timestamp(dt: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// Convert domain `ProfilePhone` to proto `ProfilePhone`.
#[allow(clippy::result_large_err)]
pub(crate) fn phone_to_proto(
    p: &ProfilePhone,
) -> Result<sid_proto::sid::v1::ProfilePhone, tonic::Status> {
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

    Ok(sid_proto::sid::v1::ProfilePhone {
        id: stored_id::<sid_ids::ProfilePhoneId, _>(p.id.0)?,
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
    })
}

/// Convert domain `ProfileEmail` to proto `ProfileEmail`.
#[allow(clippy::result_large_err)]
pub(crate) fn email_to_proto(
    e: &ProfileEmail,
) -> Result<sid_proto::sid::v1::ProfileEmail, tonic::Status> {
    use sid_core::models::profile_email::EmailLabel;

    let proto_label = match e.label {
        EmailLabel::Personal => sid_proto::sid::v1::EmailLabel::Personal,
        EmailLabel::Work => sid_proto::sid::v1::EmailLabel::Work,
        EmailLabel::School => sid_proto::sid::v1::EmailLabel::School,
        EmailLabel::Other => sid_proto::sid::v1::EmailLabel::Other,
        EmailLabel::Custom => sid_proto::sid::v1::EmailLabel::Custom,
    };

    Ok(sid_proto::sid::v1::ProfileEmail {
        id: stored_id::<sid_ids::ProfileEmailId, _>(e.id.0)?,
        email: e.email.clone(),
        label: proto_label.into(),
        custom_label: e.custom_label.clone(),
        is_primary: e.is_primary,
        verified: e.verified,
        verified_at: e.verified_at.map(to_timestamp),
    })
}

/// The identifier a request names in `field`, validated before any lookup:
/// an absent or malformed one is refused on that field.
#[allow(clippy::result_large_err)]
pub(crate) fn wire_id<W: sid_ids_proto::WireId>(
    value: Option<&W>,
    field: &'static str,
) -> Result<W::Domain, tonic::Status> {
    sid_ids_proto::required(value)
        .map_err(|e| sid_infra::grpc_error::refuse::invalid_field(field, format!("{field}: {e}")))
}

/// A stored reference as an answer carries it. A stored value that is not a
/// valid identifier of its kind is corruption, never sent as it is.
#[allow(clippy::result_large_err)]
pub(crate) fn stored_id<D, W>(id: uuid::Uuid) -> Result<Option<W>, tonic::Status>
where
    D: TryFrom<uuid::Uuid, Error = sid_ids::IdError>,
    W: From<D>,
{
    D::try_from(id)
        .map(|d| Some(W::from(d)))
        .map_err(|e| sid_infra::grpc_error::refuse::internal("stored identifier", e))
}

#[cfg(test)]
mod tests;
