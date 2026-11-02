// SPDX-License-Identifier: AGPL-3.0-only
//! The software key manager through the key manager conformance scenarios.

use std::sync::Arc;

use secrecy::SecretBox;
use sid_crypto::RustCryptoPrimitives;
use sid_keys::{KeyVersionParams, SoftwareKeyManager};
use sid_plugin::conformance::key_manager;

fn manager(versions: &[u32]) -> SoftwareKeyManager {
    let params = versions
        .iter()
        .map(|&v| KeyVersionParams::new(v, vec![v as u8; 16], format!("key-v{v}")))
        .collect();
    SoftwareKeyManager::new(
        SecretBox::new(Box::new([0x42; 32])),
        params,
        Arc::new(RustCryptoPrimitives::new()),
    )
    .unwrap()
}

#[tokio::test]
async fn expected_context_is_enforced() {
    key_manager::expected_context_is_enforced(&manager(&[1, 2])).await;
}

#[tokio::test]
async fn retained_versions_decrypt_and_rotate() {
    key_manager::retained_versions_decrypt_and_rotate(&manager(&[1]), &manager(&[1, 2])).await;
}

#[tokio::test]
async fn missing_key_fails() {
    key_manager::missing_key_fails(&manager(&[1]), &manager(&[2])).await;
}
