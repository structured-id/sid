// SPDX-License-Identifier: AGPL-3.0-only
//! The places a period's keyed completions are counted in, for the stores
//! whose concurrent commits would otherwise all write one period record.
//! Each place holds its share of the capacity and the shares add up to it,
//! so counting in places keeps the period's bound exact.

/// How many places a period has: up to this many commits under one period
/// count at once.
pub(crate) const PLACES: i16 = 32;

/// The place a completion with `fingerprint` counts in first: its inputs'
/// digest spreads concurrent commands over the places.
pub(crate) fn place_of(fingerprint: &[u8]) -> i16 {
    let spread = fingerprint
        .iter()
        .take(2)
        .fold(0u16, |n, b| (n << 8) | u16::from(*b));
    // A value below PLACES, which is positive and fits i16.
    (spread % PLACES as u16) as i16
}

/// `place`'s share of `capacity`: `capacity / PLACES`, one more for each of
/// the first `capacity % PLACES` places. The PostgreSQL store computes it in
/// its statements.
#[cfg(feature = "storage-coordinode")]
pub(crate) fn share(place: i16, capacity: i64) -> i64 {
    let places = i64::from(PLACES);
    capacity / places + i64::from(i64::from(place) < capacity % places)
}

#[cfg(test)]
mod tests;
