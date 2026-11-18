// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// An instant after 1970 travels as its second and the nanoseconds past it,
/// and reads back unchanged.
#[test]
fn an_instant_round_trips() {
    let at = Timestamp::new(1_790_000_000, 123_456_789).unwrap();
    let wire = to_proto(at);
    assert_eq!((wire.seconds, wire.nanos), (1_790_000_000, 123_456_789));
    assert_eq!(from_proto(&wire), Some(at));
}

/// Half a second before the epoch is second -1 plus 0.5 s on the wire, never
/// negative nanoseconds, and reads back as the same instant.
#[test]
fn an_instant_before_1970_counts_nanoseconds_forward() {
    let at = Timestamp::new(0, -500_000_000).unwrap();
    let wire = to_proto(at);
    assert_eq!((wire.seconds, wire.nanos), (-1, 500_000_000));
    assert_eq!(from_proto(&wire), Some(at));
}

/// Nanoseconds outside 0..10⁹ are malformed, not normalized.
#[test]
fn malformed_nanoseconds_are_refused() {
    for nanos in [-1, 1_000_000_000] {
        let wire = prost_types::Timestamp {
            seconds: 1_790_000_000,
            nanos,
        };
        assert_eq!(from_proto(&wire), None, "{nanos}");
    }
}
