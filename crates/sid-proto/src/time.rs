// SPDX-License-Identifier: AGPL-3.0-only
//! Instants on the wire: `google.protobuf.Timestamp` counts whole seconds
//! from the Unix epoch and nanoseconds forward from that second, 0 to
//! 999,999,999, also before 1970.

use jiff::Timestamp;

/// `at` as a `google.protobuf.Timestamp`.
pub fn to_proto(at: Timestamp) -> prost_types::Timestamp {
    let (seconds, nanos) = match at.subsec_nanosecond() {
        // jiff keeps the sign of the instant in both parts; the wire counts
        // forward from the second below.
        n if n < 0 => (at.as_second() - 1, n + 1_000_000_000),
        n => (at.as_second(), n),
    };
    prost_types::Timestamp { seconds, nanos }
}

/// The instant a `google.protobuf.Timestamp` names; `None` when its
/// nanoseconds are outside 0..10⁹ or it is outside the representable range.
pub fn from_proto(t: &prost_types::Timestamp) -> Option<Timestamp> {
    if !(0..1_000_000_000).contains(&t.nanos) {
        return None;
    }
    Timestamp::new(t.seconds, t.nanos).ok()
}

#[cfg(test)]
mod tests;
