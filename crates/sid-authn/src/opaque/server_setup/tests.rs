// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::opaque::PallasOpaque;
use crate::sealed_secret::{self, SealedSecretError};
use crate::test_support::key_manager;
use sid_core::models::AuditEntry;
use sid_storage::sqlite::SqliteBackend;

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

/// A restart loads the setup stored by the first start, byte for byte, so
/// password records registered before it still verify.
#[tokio::test]
async fn restart_loads_the_stored_setup() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let first = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap();
    let again = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap();
    assert_eq!(first.0, again.0);
}

/// Replicas starting at the same time end up with one setup.
#[tokio::test]
async fn concurrent_starts_agree_on_one_setup() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let (a, b) = tokio::join!(
        load_or_create(&storage, keys.as_ref(), &pallas),
        load_or_create(&storage, keys.as_ref(), &pallas),
    );
    assert_eq!(a.unwrap().0, b.unwrap().0);
}

/// The database holds the setup only sealed: a dump alone does not yield it.
#[tokio::test]
async fn setup_is_stored_sealed() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let setup = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap();
    let stored = storage
        .get_instance_secret(InstanceSecret::OpaqueServerSetup)
        .await
        .unwrap()
        .unwrap();
    assert!(sealed_secret::is_sealed(&stored));
    assert!(!stored.windows(setup.0.len()).any(|w| w == setup.0));
}

/// A sealed value bound to another record is refused rather than used as the
/// setup, and nothing replaces it.
#[tokio::test]
async fn value_sealed_for_another_record_is_refused() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let foreign = sealed_secret::seal(keys.as_ref(), "totp:someone", &[7u8; 64])
        .await
        .unwrap();
    storage
        .insert_instance_secret(
            InstanceSecret::OpaqueServerSetup,
            &foreign,
            AuditEntry::system("test", "setup").into(),
        )
        .await
        .unwrap();

    let err = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServerSetupError::Stored(InstanceSecretError::Sealed(
            SealedSecretError::ContextMismatch
        ))
    ));
}

/// The deployment's router registers new passwords on Pallas and verifies
/// every curve this build implements; a password registered through one
/// replica's router signs in through another's over the same store.
#[tokio::test]
async fn replicas_share_the_router_setup() {
    use rand::rand_core::UnwrapErr;
    use rand::rngs::SysRng;
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;
    use sid_plugin::crypto::CurveId;

    let (storage, keys) = (storage().await, key_manager());
    let first = router(&storage, keys.as_ref()).await.unwrap();
    let second = router(&storage, keys.as_ref()).await.unwrap();
    assert_eq!(first.primary_curve(), CurveId::Pallas);
    let mut curves = second.supported_curves();
    curves.sort_by_key(|c| *c as u8);
    assert_eq!(
        curves,
        vec![
            CurveId::Pallas,
            CurveId::Ristretto255,
            CurveId::P256,
            CurveId::P384,
            CurveId::P521
        ]
    );

    let (identifier, password) = (b"credential-1", b"correct horse");
    let mut rng = UnwrapErr(SysRng);
    let client = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let (response, _) = first
        .registration_start(&client.message.serialize(), identifier)
        .unwrap();
    let upload = client
        .state
        .finish(
            &mut rng,
            password,
            RegistrationResponse::deserialize(&response).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let stored = first
        .registration_finish(&upload.message.serialize())
        .unwrap();
    assert_eq!(stored.curve, CurveId::Pallas);

    let client = ClientLogin::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let (response, state) = second
        .login_start(&stored, &client.message.serialize(), identifier, &[])
        .unwrap();
    let finish = client
        .state
        .finish(
            &mut rng,
            password,
            CredentialResponse::deserialize(&response).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    second
        .login_finish(&state, &finish.message.serialize(), &[])
        .unwrap();
}

/// A replica holding a different master secret cannot open the setup and
/// fails to start instead of serving logins that could never succeed.
#[tokio::test]
async fn different_master_secret_fails_to_start() {
    let (storage, pallas) = (storage().await, PallasOpaque::new());
    load_or_create(&storage, key_manager().as_ref(), &pallas)
        .await
        .unwrap();
    let other: std::sync::Arc<dyn KeyManager> = std::sync::Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([9u8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
            std::sync::Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    );

    let err = load_or_create(&storage, other.as_ref(), &pallas)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServerSetupError::Stored(InstanceSecretError::Sealed(_))
    ));
}
