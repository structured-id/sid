use std::sync::Arc;

use sid_core::models::AuditEntry;
use sid_plugin::storage::StorageBackend;

use super::*;
use crate::test_support::{keys, sign_in, storage, stored_credential, stored_profile};

fn passkeys(storage: Arc<dyn StorageBackend>) -> Passkeys {
    let origin = url::Url::parse("https://sid.example.com").unwrap();
    let webauthn = WebAuthnServer::new("sid.example.com", &origin, storage.clone(), keys())
        .expect("WebAuthn relying party");
    Passkeys::new(Arc::new(webauthn), storage, keys())
}

/// Only passkeys that may still sign in count: a revoked one, and a
/// credential of another type, are left out.
#[tokio::test]
async fn active_passkeys_leave_out_revoked_and_other_types() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let kept = stored_credential(storage.as_ref(), alice, CredentialType::WebAuthn).await;
    let revoked = stored_credential(storage.as_ref(), alice, CredentialType::WebAuthn).await;
    stored_credential(storage.as_ref(), alice, CredentialType::Opaque).await;
    storage
        .revoke_credential(revoked.id, AuditEntry::system("test", "revoke").into())
        .await
        .unwrap();
    let ids: Vec<_> = active(storage.as_ref(), alice)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(ids, vec![kept.id]);
}

/// A sign-in for an unknown account and for an account without passkeys
/// starts alike as a failed authentication, so the start tells nothing about
/// which accounts exist or what they enrolled.
#[tokio::test]
async fn sign_in_start_tells_nothing_about_the_account() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let passkeys = passkeys(storage.clone());
    stored_profile(storage.as_ref(), "alice").await;
    for principal in ["nobody", "alice"] {
        assert!(matches!(
            passkeys
                .authentication_start(
                    &sign_in,
                    WebAuthnAuthenticationStartRequest {
                        principal: Some(principal.to_string()),
                    },
                )
                .await,
            Err(PasskeyError::AuthenticationFailed)
        ));
    }
}

/// Bytes that are no WebAuthn response are refused on their field before
/// any ceremony is looked up or consumed.
#[test]
fn malformed_assertion_is_refused_on_its_field() {
    for principal in [Some("alice".to_string()), None] {
        assert!(matches!(
            Assertion::parse(principal, b"not json"),
            Err(PasskeyError::InvalidField {
                field: "credential",
                ..
            })
        ));
    }
}
