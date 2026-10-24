//! The host's installation is the only one: a second one does not pass as if
//! it had chosen the provider.

use sid_crypto::jwt::{ProviderConflict, install_jwt_provider};

#[test]
fn a_second_installation_is_refused() {
    install_jwt_provider().unwrap();
    assert!(matches!(install_jwt_provider(), Err(ProviderConflict)));
}
