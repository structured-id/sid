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

/// A JSON value as a protobuf `Value`. A number travels as a double, the
/// only number `google.protobuf.Value` has.
pub(crate) fn json_to_value(v: serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match v {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Kind::StringValue(s),
        serde_json::Value::Array(arr) => Kind::ListValue(prost_types::ListValue {
            values: arr.into_iter().map(json_to_value).collect(),
        }),
        serde_json::Value::Object(map) => Kind::StructValue(json_object_to_struct(map)),
    };
    prost_types::Value { kind: Some(kind) }
}

/// A JSON object as a protobuf `Struct`.
pub(crate) fn json_object_to_struct(
    map: serde_json::Map<String, serde_json::Value>,
) -> prost_types::Struct {
    prost_types::Struct {
        fields: map
            .into_iter()
            .map(|(k, v)| (k, json_to_value(v)))
            .collect(),
    }
}

/// A protobuf `Value` as JSON; a non-finite double, which JSON cannot hold,
/// is 0.
pub(crate) fn value_to_json(v: prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match v.kind {
        Some(Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(b),
        Some(Kind::NumberValue(n)) => {
            serde_json::Value::Number(serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()))
        }
        Some(Kind::StringValue(s)) => serde_json::Value::String(s),
        Some(Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.into_iter().map(value_to_json).collect())
        }
        Some(Kind::StructValue(s)) => struct_to_json(s),
    }
}

/// A protobuf `Struct` as a JSON object.
pub(crate) fn struct_to_json(s: prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .into_iter()
            .map(|(k, v)| (k, value_to_json(v)))
            .collect(),
    )
}

/// `at` as a protobuf timestamp.
pub(crate) fn to_timestamp(at: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: at.timestamp(),
        // Sub-second nanoseconds are below 2·10⁹ (a leap second), within i32.
        nanos: at.timestamp_subsec_nanos() as i32,
    }
}
