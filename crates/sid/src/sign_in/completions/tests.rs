use std::net::{IpAddr, Ipv4Addr};

use sid_authn::sign_in_delivery::{CeremonyClient, Delivery};
use sid_core::models::session::{AuthLevel, SessionAuthentication};
use sid_core::models::{PrincipalAssignmentFence, PrincipalId, ProfileStatus};
use sid_plugin::GrantStore as _;
use sid_plugin::storage::StorageBackend as _;

use super::*;
use crate::test_support::{fixed_policy, sign_in, storage, stored_profile};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

fn browser() -> Completer<'static> {
    Completer {
        client: CeremonyClient::Browser,
        client_ip: Some(CLIENT_IP),
        context: AttemptContext::default(),
    }
}

fn evidence() -> SessionAuthentication {
    SessionAuthentication {
        assurance_level: AuthLevel::Standard,
        elevation: None,
        authenticated_at: Utc::now(),
        amr: vec!["pwd".to_string(), "otp".to_string()],
    }
}

fn assignment_of(profile: ProfileId) -> PrincipalAssignmentFence {
    PrincipalAssignmentFence {
        principal: PrincipalId::new(),
        profile,
        revision: 1,
    }
}

// An upstream sign-in records the provider's verification as basic
// assurance without an `amr` method SID did not verify, from the browser's
// address, and delivers the IdP session cookie.
#[tokio::test]
async fn upstream_sign_in_stores_a_basic_session_without_amr() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "alice").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();

    let signed_in = sign_in
        .upstream_sign_in(&fixed_policy(), &profile, browser())
        .await
        .unwrap();

    assert!(matches!(signed_in.delivery, Delivery::Cookie(_)));
    let session = storage
        .get_session(signed_in.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.profile_id, id);
    assert_eq!(session.assurance_level, AuthLevel::Basic);
    assert!(session.amr.is_empty());
    assert_eq!(session.ip_address, Some(CLIENT_IP));
}

// An account that can no longer authenticate gets no upstream session,
// answered as any failed authentication.
#[tokio::test]
async fn upstream_sign_in_refuses_a_suspended_account() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "bob").await;
    let mut profile = storage.get_profile(id).await.unwrap().unwrap();
    profile.status = ProfileStatus::Suspended;

    let refused = sign_in
        .upstream_sign_in(&fixed_policy(), &profile, browser())
        .await;

    assert!(matches!(refused, Err(SignInError::AuthenticationFailed)));
}

// Admitted evidence signs in only the Profile its assignment resolves: an
// assignment of another Profile admits nothing.
#[tokio::test]
async fn admitted_sign_in_refuses_an_assignment_of_another_profile() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "carol").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();

    let refused = sign_in
        .admitted_sign_in(
            &fixed_policy(),
            &profile,
            assignment_of(ProfileId::generate()),
            &evidence(),
            "app",
            None,
            Some(CLIENT_IP),
            AttemptContext::default(),
        )
        .await;

    assert!(matches!(refused, Err(SignInError::AuthenticationFailed)));
}

// An operation past its deadline admits neither a new sign-in nor a repeat.
#[tokio::test]
async fn admitted_sign_in_refuses_an_operation_past_its_deadline() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "dave").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();
    let operation = "federated-return-1";

    let refused = sign_in
        .admitted_sign_in(
            &fixed_policy(),
            &profile,
            assignment_of(id),
            &evidence(),
            "app",
            Some(AdmittedCompletion {
                operation,
                deadline: Utc::now() - chrono::Duration::seconds(1),
            }),
            Some(CLIENT_IP),
            AttemptContext::default(),
        )
        .await;

    assert!(matches!(refused, Err(SignInError::AuthenticationFailed)));
}
