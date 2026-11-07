// SPDX-License-Identifier: AGPL-3.0-only
//! Converters between `sid_core::models` and `sid_proto::sid::v1` types the
//! service handlers share. Profiles, principals, credentials and devices are
//! the [`sid::identity`] library's, contact phones and emails
//! [`sid::account`]'s.

use chrono::{DateTime, Utc};

/// Convert `chrono::DateTime<Utc>` to `prost_types::Timestamp`.
pub(crate) fn to_timestamp(dt: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
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
