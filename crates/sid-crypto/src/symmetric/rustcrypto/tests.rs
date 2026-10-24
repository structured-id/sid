// SPDX-License-Identifier: Apache-2.0

use getrandom::rand_core::{TryCryptoRng, TryRng};

struct FailedEntropy;

impl TryRng for FailedEntropy {
    type Error = core::fmt::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(core::fmt::Error)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(core::fmt::Error)
    }

    fn try_fill_bytes(&mut self, _bytes: &mut [u8]) -> Result<(), Self::Error> {
        Err(core::fmt::Error)
    }
}

impl TryCryptoRng for FailedEntropy {}

// An unavailable entropy source is a typed refusal, never replacement nonce bytes.
#[test]
fn entropy_failure_is_returned_without_replacement_bytes() {
    let mut bytes = [0xa5; 12];
    assert!(matches!(
        super::fill_entropy(&mut FailedEntropy, &mut bytes),
        Err(crate::CryptoError::Entropy)
    ));
    assert_eq!(bytes, [0xa5; 12]);
}
