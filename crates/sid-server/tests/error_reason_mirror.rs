//! `sid_core::grpc_error::ErrorReason` mirrors `sid.v1.common.ErrorReason`:
//! a reason the proto adds without the mirror could never be returned, and a
//! mirror reason missing from the proto would reach clients as a string they
//! cannot decode.

use std::collections::BTreeSet;

use sid_core::grpc_error::ErrorReason;
use sid_proto::sid::v1::common::ErrorReason as ProtoReason;

/// Every proto reason name, read from the generated enum.
fn proto_names() -> BTreeSet<&'static str> {
    // Proto enum values are small; the range covers every number the enum
    // can hold today with room to grow.
    (1..=1000)
        .filter_map(|n| ProtoReason::try_from(n).ok())
        .map(|r| r.as_str_name())
        .collect()
}

/// The proto and the mirror name exactly the same reasons.
#[test]
fn mirror_matches_proto_reasons() {
    let proto = proto_names();
    let mirror: BTreeSet<&'static str> = ErrorReason::ALL.iter().map(|r| r.as_str()).collect();
    let missing_in_mirror: Vec<_> = proto.difference(&mirror).collect();
    let missing_in_proto: Vec<_> = mirror.difference(&proto).collect();
    assert!(
        missing_in_mirror.is_empty() && missing_in_proto.is_empty(),
        "mirror lacks {missing_in_mirror:?}; proto lacks {missing_in_proto:?}"
    );
}
