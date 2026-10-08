// SPDX-License-Identifier: AGPL-3.0-only
//! OPAQUE envelopes are stored sealed under the key manager (defense in
//! depth: the protocol already keeps the password from the server, and the
//! sealing keeps a database dump from yielding the records an offline attack
//! would start from).

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::opaque_client::{login, register};
use sid_core::models::{CredentialType, PrincipalType};

const PASSWORD: &[u8] = b"sealed-envelope-password-2026";

async fn stored_envelope(svc: &TestServices, principal: &str) -> Vec<u8> {
    let profile_id = svc
        .storage
        .get_principal_by_value(PrincipalType::Email, principal)
        .await
        .unwrap()
        .and_then(|p| p.assigned_profile_id)
        .expect("registered principal");
    svc.storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Opaque))
        .await
        .unwrap()
        .pop()
        .expect("OPAQUE credential stored")
        .data
        .expose()
        .to_vec()
}

/// A registered envelope is stored sealed, and the password still signs in.
#[tokio::test]
async fn registered_envelope_is_stored_sealed() {
    let svc = TestServices::new(MockStorage::new());
    let principal = "sealed@sid.example.com";
    register(&svc, &svc, principal, PASSWORD).await;

    let stored = stored_envelope(&svc, principal).await;
    assert!(
        sid_authn::sealed_secret::is_sealed(&stored),
        "the envelope is stored in clear"
    );
    login(&svc, principal, PASSWORD)
        .await
        .expect("the sealed envelope still signs in");
}
