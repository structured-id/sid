//! Another provider in place is never silently kept or replaced: the host
//! learns it cannot have aws-lc.

use jsonwebtoken::crypto::CryptoProvider;
use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER;
use sid_crypto::jwt::{ProviderConflict, install_jwt_provider};

#[test]
fn another_installed_provider_is_refused() {
    let other: &'static CryptoProvider = Box::leak(Box::new(DEFAULT_PROVIDER.clone()));
    other.install_default().unwrap();
    assert!(matches!(install_jwt_provider(), Err(ProviderConflict)));
}
