// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// The stored hash is the hex SHA-256 of the token as the link carries it,
/// so a verification hashing the presented token compares equal.
#[test]
fn token_hash_is_hex_sha256() {
    assert_eq!(
        token_hash("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
