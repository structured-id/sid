// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// A context is stored under its secret's hash: the key names the context
/// without being the secret, and two secrets never share a key.
#[test]
fn a_context_is_keyed_by_its_secrets_hash() {
    let (a, b) = (BrowserSecret::generate(), BrowserSecret::generate());
    let key = context_key(&a);
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        key,
        context_key(&BrowserSecret::decode(&a.encode()).unwrap())
    );
    assert_ne!(key, context_key(&b));
    assert_ne!(key.as_str(), a.encode().as_str());
}
