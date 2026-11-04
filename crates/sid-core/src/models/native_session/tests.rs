// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// An exchange is exactly its 16 bytes: a shorter or longer reference names
/// no exchange, so a truncated retry cannot match another one.
#[test]
fn exchange_is_sixteen_bytes() {
    let bytes = [7u8; NATIVE_EXCHANGE_LEN];
    assert_eq!(
        NativeExchange::from_bytes(&bytes).unwrap().as_bytes(),
        &bytes
    );
    assert!(NativeExchange::from_bytes(&bytes[..15]).is_none());
    assert!(NativeExchange::from_bytes(&[7u8; 17]).is_none());
    assert!(NativeExchange::from_bytes(&[]).is_none());
}
