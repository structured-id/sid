use super::*;

/// The shares of every capacity, small or not a multiple of the places, add
/// up to it exactly: counting in places neither loses nor adds room.
#[cfg(feature = "storage-coordinode")]
#[test]
fn shares_add_up_to_the_capacity() {
    for capacity in [1, 7, 8, 31, 32, 33, 100, 100_000] {
        let total: i64 = (0..PLACES).map(|p| share(p, capacity)).sum();
        assert_eq!(total, capacity, "capacity {capacity}");
    }
}

/// Every digest names a place that exists, and different digests spread
/// over more than one place.
#[test]
fn digests_name_existing_places() {
    let places: std::collections::HashSet<i16> = (0u8..=255)
        .map(|b| place_of(&[b, b.wrapping_mul(7)]))
        .inspect(|p| assert!((0..PLACES).contains(p)))
        .collect();
    assert!(places.len() > 1);
    assert_eq!(place_of(&[]), 0);
}
