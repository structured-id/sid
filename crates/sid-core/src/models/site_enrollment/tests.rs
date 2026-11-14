// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn enrolled(chain: Vec<Vec<u8>>) -> SiteEnrollment {
    SiteEnrollment {
        certificate: vec![0x30, 1, 2],
        chain,
    }
}

// The chain is read back exactly as it was stored, an empty one included,
// and a stored value that is not a whole chain is not read as a shorter
// one. Bug prevented: a truncated or padded value yielding a chain that
// lacks or gains a certificate.
#[test]
fn the_chain_is_stored_whole() {
    for chain in [
        vec![],
        vec![vec![7; 3]],
        vec![vec![1], vec![2; 300], vec![3; 70_000 % MAX_CERTIFICATE]],
    ] {
        let stored = enrolled(chain.clone()).chain_bytes();
        assert_eq!(SiteEnrollment::chain_from_bytes(&stored), Some(chain));
    }
    let stored = enrolled(vec![vec![9; 5], vec![8; 6]]).chain_bytes();
    for cut in [1, 3, 4, 8, stored.len() - 1] {
        assert_eq!(
            SiteEnrollment::chain_from_bytes(&stored[..cut]),
            None,
            "{cut}"
        );
    }
    let mut padded = stored.clone();
    padded.push(0);
    assert_eq!(SiteEnrollment::chain_from_bytes(&padded), None);
    // A zero-length entry is no certificate.
    assert_eq!(SiteEnrollment::chain_from_bytes(&[0, 0, 0, 0]), None);
}

// An enrollment has a certificate and a bounded chain of non-empty
// certificates. Bug prevented: an empty or unbounded value kept as the
// site's identity.
#[test]
fn an_enrollment_is_bounded() {
    assert!(enrolled(vec![vec![1]; MAX_CHAIN]).check().is_ok());
    assert!(enrolled(vec![vec![1]; MAX_CHAIN + 1]).check().is_err());
    assert!(enrolled(vec![vec![]]).check().is_err());
    assert!(
        enrolled(vec![vec![0; MAX_CERTIFICATE + 1]])
            .check()
            .is_err()
    );
    let empty = SiteEnrollment {
        certificate: vec![],
        chain: vec![],
    };
    assert!(empty.check().is_err());
    let over = vec![0u8; 4 + MAX_CERTIFICATE + 1];
    let mut stored = u32::try_from(MAX_CERTIFICATE + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    stored.extend_from_slice(&over[4..]);
    assert_eq!(SiteEnrollment::chain_from_bytes(&stored), None);
}
