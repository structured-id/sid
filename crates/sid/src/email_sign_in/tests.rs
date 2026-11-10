use std::sync::Arc;

use sid_plugin::storage::StorageBackend;

use super::*;
use crate::test_support::{fixed_policy, keys, sign_in, storage};

fn codes(storage: Arc<dyn StorageBackend>) -> OtpService {
    OtpService::new(storage, sid_authn::otp::CodeDelivery { keys: keys() })
}

fn attempt() -> Attempt<'static> {
    Attempt {
        client: CeremonyClient::Native,
        client_ip: None,
        context: AttemptContext::default(),
    }
}

/// A code goes only to an email address: another principal is refused on
/// its field before anything is stored.
#[tokio::test]
async fn code_is_requested_for_an_email_address() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let policy = fixed_policy();
    let email = EmailSignIn::new(&sign_in, &policy);
    assert!(matches!(
        email.request_code(&codes(storage), "alice").await,
        Err(EmailSignInError::InvalidField {
            field: "principal",
            ..
        })
    ));
}

/// An address with no account gets a real pending code like any other, so
/// the answer tells nothing; its code signs nobody in.
#[tokio::test]
async fn unknown_address_gets_a_code_that_signs_nobody_in() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let policy = fixed_policy();
    let email = EmailSignIn::new(&sign_in, &policy);
    let codes = codes(storage);
    let requested = email
        .request_code(&codes, "nobody@example.com")
        .await
        .unwrap();
    assert!(requested.otp_session_id.is_some());
    assert!(requested.code_length > 0);
    assert!(
        email
            .verify_code(
                &codes,
                attempt(),
                VerifyOtpRequest {
                    otp_session_id: requested.otp_session_id,
                    code: "000000".to_string(),
                },
            )
            .await
            .unwrap()
            .is_none()
    );
}

/// A code session that does not exist answers as expired: a new code is
/// requested.
#[tokio::test]
async fn unknown_code_session_is_expired() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let policy = fixed_policy();
    let email = EmailSignIn::new(&sign_in, &policy);
    let codes = codes(storage);
    let unknown = Some(sid_ids::OtpSessionId::generate().into());
    assert!(matches!(
        email
            .verify_code(
                &codes,
                attempt(),
                VerifyOtpRequest {
                    otp_session_id: unknown.clone(),
                    code: "000000".to_string(),
                },
            )
            .await,
        Err(EmailSignInError::CodeSessionExpired)
    ));
    assert!(matches!(
        email.resend_code(&codes, unknown.as_ref()).await,
        Err(EmailSignInError::CodeSessionExpired)
    ));
}
