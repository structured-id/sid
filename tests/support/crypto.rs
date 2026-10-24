// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit provider selection by the test application, never by a library.

/// Each test process owns one host selection, shared by its fixture instances.
pub fn install_tls() {
    static SELECT: std::sync::Once = std::sync::Once::new();
    SELECT.call_once(|| {
        sid_crypto::tls::aws_lc::provider()
            .install_default()
            .unwrap();
    });
}

/// Construct a fixture after the test application has selected its TLS backend.
pub fn with_tls<T, E: std::fmt::Debug>(construct: impl FnOnce() -> Result<T, E>) -> T {
    install_tls();
    construct().unwrap()
}
