// SPDX-License-Identifier: AGPL-3.0-only
//! How the engine's operations read identifiers from and write times into the
//! request and response messages they take and return.

/// A field of a request that names no valid identifier of its kind.
#[derive(Debug)]
pub(crate) struct FieldError {
    pub(crate) field: &'static str,
    pub(crate) reason: String,
}

/// The identifier `field` of a request names, validated before any lookup.
pub(crate) fn wire_id<W: sid_ids_proto::WireId>(
    value: Option<&W>,
    field: &'static str,
) -> Result<W::Domain, FieldError> {
    sid_ids_proto::required(value).map_err(|e| FieldError {
        field,
        reason: format!("{field}: {e}"),
    })
}

/// A stored reference as an answer carries it. A stored value that is not a
/// valid identifier of its kind is corruption, never sent as it is.
pub(crate) fn stored_id<D, W>(id: uuid::Uuid) -> Result<Option<W>, sid_ids::IdError>
where
    D: TryFrom<uuid::Uuid, Error = sid_ids::IdError>,
    W: From<D>,
{
    D::try_from(id).map(|d| Some(W::from(d)))
}

/// `at` as a protobuf timestamp.
pub(crate) fn to_timestamp(at: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: at.timestamp(),
        // Sub-second nanoseconds are below 2·10⁹ (a leap second), within i32.
        nanos: at.timestamp_subsec_nanos() as i32,
    }
}
