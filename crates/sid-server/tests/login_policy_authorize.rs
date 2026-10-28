// SPDX-License-Identifier: AGPL-3.0-only
//! Every authorization over an existing session is checked against the
//! host's login policy as it is now, not as it was when the session began: a
//! requirement added later asks the user to step up, naming each unmet one by
//! kind, and a policy that cannot be read admits nothing.

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use common::mock_storage::MockStorage;
use common::{TestServices, test_client, test_profile};
use sid_authn::login_policy::{LoginPolicySource, LoginPolicyUnavailable, LoginRequirements};
use sid_core::models::AuthLevel;
use sid_core::models::security_policy::EnforcementMode;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;
use tonic_types::StatusExt;

/// A host policy the test changes between sign-in and authorization; None
/// stands for a policy store that cannot be read.
struct HostPolicy(Mutex<Option<LoginRequirements>>);

impl HostPolicy {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(baseline()))))
    }

    fn set(&self, requirements: Option<LoginRequirements>) {
        *self.0.lock().unwrap() = requirements;
    }
}

#[async_trait]
impl LoginPolicySource for HostPolicy {
    async fn requirements(
        &self,
        _client_id: Option<&str>,
    ) -> Result<LoginRequirements, LoginPolicyUnavailable> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| LoginPolicyUnavailable("policy store down".to_string()))
    }
}

/// A basic sign-in, hard enforcement, nothing else required.
fn baseline() -> LoginRequirements {
    LoginRequirements {
        min_acr: AuthLevel::Basic,
        required_amr: BTreeSet::new(),
        max_authentication_age: None,
        enforcement: EnforcementMode::Hard,
        fence: None,
    }
}

/// The services, the host policy they read and a bearer token of a basic
/// password session that began `minutes_ago`.
async fn signed_in(minutes_ago: i64) -> (TestServices, Arc<HostPolicy>, String) {
    let profile = test_profile();
    let policy = HostPolicy::new();
    let svc = TestServices::with_login_policy(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client()),
        policy.clone(),
    );
    let mut session = common::authenticated_session(&profile, AuthLevel::Basic, minutes_ago);
    session.amr = vec!["pwd".to_string()];
    let token = common::stored_session_token(&svc, &profile, session).await;
    (svc, policy, token)
}

async fn authorize(svc: &TestServices, token: &str) -> Result<(), tonic::Status> {
    let mut request = Request::new(OAuth2AuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        response_type: "code".to_string(),
        scope: Some("openid".to_string()),
        state: Some("xyz".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: Some("n-0S6_WzA2Mj".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    svc.auth.o_auth2_authorize(request).await.map(|_| ())
}

fn reason(status: &tonic::Status) -> Option<String> {
    status.get_details_error_info().map(|info| info.reason)
}

/// The (type, subject) of every precondition a refusal names.
fn preconditions(status: &tonic::Status) -> Vec<(String, String)> {
    status
        .get_details_precondition_failure()
        .map(|failure| {
            failure
                .violations
                .into_iter()
                .map(|v| (v.r#type, v.subject))
                .collect()
        })
        .unwrap_or_default()
}

/// The session meets the policy in force: the code is issued.
#[tokio::test]
async fn a_session_meeting_the_policy_is_authorized() {
    let (svc, _policy, token) = signed_in(0).await;

    authorize(&svc, &token).await.unwrap();
}

/// A higher level required after the session began is asked for at the next
/// authorization; the session does not carry the policy it started under.
#[tokio::test]
async fn a_level_required_later_asks_an_existing_session_to_step_up() {
    let (svc, policy, token) = signed_in(0).await;
    policy.set(Some(LoginRequirements {
        min_acr: AuthLevel::Elevated,
        ..baseline()
    }));

    let err = authorize(&svc, &token).await.unwrap_err();

    assert_eq!(reason(&err).as_deref(), Some("STEP_UP_REQUIRED"));
    assert_eq!(
        preconditions(&err),
        vec![(
            "acr".to_string(),
            AuthLevel::Elevated.acr_value().to_string()
        )]
    );
}

/// A method the session did not use is named by its amr value, not folded
/// into a level.
#[tokio::test]
async fn a_required_method_the_session_did_not_use_is_named() {
    let (svc, policy, token) = signed_in(0).await;
    policy.set(Some(LoginRequirements {
        required_amr: BTreeSet::from(["hwk".to_string()]),
        ..baseline()
    }));

    let err = authorize(&svc, &token).await.unwrap_err();

    assert_eq!(reason(&err).as_deref(), Some("STEP_UP_REQUIRED"));
    assert_eq!(
        preconditions(&err),
        vec![("amr".to_string(), "hwk".to_string())]
    );
}

/// An authentication older than the policy allows is asked to be repeated,
/// with the bound in seconds.
#[tokio::test]
async fn an_authentication_older_than_the_policy_allows_is_repeated() {
    let (svc, policy, token) = signed_in(30).await;
    policy.set(Some(LoginRequirements {
        max_authentication_age: Some(Duration::from_secs(300)),
        ..baseline()
    }));

    let err = authorize(&svc, &token).await.unwrap_err();

    assert_eq!(reason(&err).as_deref(), Some("STEP_UP_REQUIRED"));
    assert_eq!(
        preconditions(&err),
        vec![("max_age".to_string(), "300".to_string())]
    );
}

/// Audit enforcement reports an unmet requirement and still authorizes.
#[tokio::test]
async fn audit_enforcement_authorizes_an_unmet_session() {
    let (svc, policy, token) = signed_in(0).await;
    policy.set(Some(LoginRequirements {
        min_acr: AuthLevel::Elevated,
        enforcement: EnforcementMode::Audit,
        ..baseline()
    }));

    authorize(&svc, &token).await.unwrap();
}

/// A policy that cannot be read admits nothing: no fallback to a baseline
/// the host never stated.
#[tokio::test]
async fn an_unreadable_policy_authorizes_nothing() {
    let (svc, policy, token) = signed_in(0).await;
    policy.set(None);

    let err = authorize(&svc, &token).await.unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert_ne!(reason(&err).as_deref(), Some("STEP_UP_REQUIRED"));
}

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// A device authorization started for `test-client`, registered for the
/// device grant, its user code and device code.
async fn device_request(svc: &TestServices) -> (String, String) {
    let started = svc
        .auth
        .start_device_authorization(Request::new(DeviceAuthorizationRequest {
            client_id: Some("test-client".to_string()),
            scope: Some("openid".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .expect("device authorization starts")
        .into_inner();
    (started.user_code, started.device_code)
}

/// The services with a device-grant client, the host policy and a bearer
/// token of a basic password session.
async fn signed_in_with_device_client() -> (TestServices, Arc<HostPolicy>, String) {
    let profile = test_profile();
    let policy = HostPolicy::new();
    let mut client = test_client();
    client.grant_types.push(DEVICE_GRANT.into());
    let svc = TestServices::with_login_policy(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(client),
        policy.clone(),
    );
    let mut session = common::authenticated_session(&profile, AuthLevel::Basic, 0);
    session.amr = vec!["pwd".to_string()];
    let token = common::stored_session_token(&svc, &profile, session).await;
    (svc, policy, token)
}

async fn approve_device(
    svc: &TestServices,
    user_code: &str,
    token: &str,
) -> Result<(), tonic::Status> {
    let mut request = Request::new(SubmitDeviceUserCodeRequest {
        user_code: user_code.to_string(),
        approve: true,
    });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    svc.auth.submit_device_user_code(request).await.map(|_| ())
}

async fn redeem_device(svc: &TestServices, device_code: &str) -> Result<(), tonic::Status> {
    svc.mock_storage.age_device_polls();
    svc.auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: DEVICE_GRANT.to_string(),
            device_code: Some(device_code.to_string()),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .map(|_| ())
}

/// A device approval grants an application access as an authorization does:
/// a session short of the application's requirements now is asked to step
/// up, and the device gets nothing. The approval used to check only that the
/// caller was signed in.
#[tokio::test]
async fn a_device_approval_by_a_session_short_of_the_policy_asks_to_step_up() {
    let (svc, policy, token) = signed_in_with_device_client().await;
    let (user_code, device_code) = device_request(&svc).await;
    policy.set(Some(LoginRequirements {
        min_acr: AuthLevel::Elevated,
        ..baseline()
    }));

    let err = approve_device(&svc, &user_code, &token).await.unwrap_err();

    assert_eq!(reason(&err).as_deref(), Some("STEP_UP_REQUIRED"));
    let refused = redeem_device(&svc, &device_code).await.unwrap_err();
    assert_eq!(
        common::oauth_error(&refused).as_deref(),
        Some("authorization_pending"),
        "the refused approval decided nothing"
    );
}

/// An unreadable policy approves no device: no fallback baseline.
#[tokio::test]
async fn an_unreadable_policy_approves_no_device() {
    let (svc, policy, token) = signed_in_with_device_client().await;
    let (user_code, _) = device_request(&svc).await;
    policy.set(None);

    let err = approve_device(&svc, &user_code, &token).await.unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unavailable);
}

/// The device's tokens are issued only while the policy can be read: a store
/// down at the poll issues nothing, and the approval stands for a later poll.
#[tokio::test]
async fn an_unreadable_policy_issues_the_device_nothing() {
    let (svc, policy, token) = signed_in_with_device_client().await;
    let (user_code, device_code) = device_request(&svc).await;
    approve_device(&svc, &user_code, &token).await.unwrap();
    policy.set(None);

    let err = redeem_device(&svc, &device_code).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);

    policy.set(Some(baseline()));
    redeem_device(&svc, &device_code)
        .await
        .expect("the approval stands once the policy is readable");
}

/// A session meeting the policy approves, and the device gets its tokens.
#[tokio::test]
async fn a_device_approval_meeting_the_policy_issues_tokens() {
    let (svc, _policy, token) = signed_in_with_device_client().await;
    let (user_code, device_code) = device_request(&svc).await;

    approve_device(&svc, &user_code, &token).await.unwrap();
    redeem_device(&svc, &device_code).await.unwrap();
}
