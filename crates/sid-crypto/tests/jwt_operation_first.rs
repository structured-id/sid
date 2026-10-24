//! A JWT operation before the host installed the provider fixes the choice
//! without the host; the host then learns it did not choose.

mod common;

use common::{claims, keys};
use jsonwebtoken::{Algorithm, Header, encode};
use sid_crypto::jwt::{ProviderConflict, install_jwt_provider};

#[test]
fn a_provider_chosen_by_an_earlier_operation_is_refused() {
    let (sign, _) = keys(Algorithm::ES256);
    encode(&Header::new(Algorithm::ES256), &claims(), &sign).unwrap();
    assert!(matches!(install_jwt_provider(), Err(ProviderConflict)));
}
