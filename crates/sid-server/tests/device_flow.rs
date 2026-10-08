// SPDX-License-Identifier: AGPL-3.0-only
//! Device Authorization Grant (RFC 8628) through the handlers: a device
//! starts, the user approves the displayed code, the device gets tokens once
//! from the token endpoint's device_code grant (RFC 8628 §3.4). Every refusal
//! names its RFC 8628 §3.5 or RFC 6749 §5.2 code in `oauthError`.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, oauth_error, test_client, test_profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::{
    DeviceAuthorizationRequest, DeviceAuthorizationResponse, OAuth2TokenRequest,
    SubmitDeviceUserCodeRequest,
};
use tonic::{Code, Request, Status};
use tonic_types::StatusExt;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn assert_refused(status: Status, code: Code, error: &str) {
    assert_eq!(status.code(), code, "{status:?}");
    assert_eq!(oauth_error(&status).as_deref(), Some(error), "{status:?}");
}

/// A public client registered for the device grant.
fn device_client() -> sid_core::models::OAuth2Client {
    let mut client = test_client();
    client.grant_types.push(DEVICE_GRANT.into());
    client
}

fn services(client: &sid_core::models::OAuth2Client) -> (TestServices, sid_core::models::Profile) {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_client(client.clone());
    (TestServices::new(storage), profile)
}

fn start_request(svc: &TestServices, client_id: &str) -> Request<DeviceAuthorizationRequest> {
    Request::new(DeviceAuthorizationRequest {
        client_id: Some(client_id.to_string()),
        scope: Some("openid".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}

async fn start(svc: &TestServices, client_id: &str) -> DeviceAuthorizationResponse {
    svc.auth
        .start_device_authorization(start_request(svc, client_id))
        .await
        .expect("device authorization starts")
        .into_inner()
}

/// A poll at the token endpoint of the installation's issuer.
fn poll(svc: &TestServices, device_code: &str, client_id: &str) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: DEVICE_GRANT.to_string(),
        device_code: Some(device_code.to_string()),
        client_id: Some(client_id.to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}

fn approve(user_code: &str, approve: bool, bearer: &str) -> Request<SubmitDeviceUserCodeRequest> {
    authed(
        SubmitDeviceUserCodeRequest {
            user_code: user_code.to_string(),
            approve,
        },
        bearer,
    )
}

/// The code shown to the user is accepted as shown; after approval the
/// device gets tokens once, and a second exchange of the same device code is
/// refused and ends the session the first one opened.
#[tokio::test]
async fn test_device_flow_issues_tokens_once() {
    let client = device_client();
    let (svc, profile) = services(&client);
    let started = start(&svc, &client.client_id).await;
    assert!(started.user_code.contains('-'), "{}", started.user_code);

    let err = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .expect_err("pending before approval");
    assert_refused(err, Code::FailedPrecondition, "authorization_pending");

    let bearer = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    svc.auth
        .submit_device_user_code(approve(&started.user_code, true, &bearer))
        .await
        .expect("the displayed code is accepted");

    // The poll interval is not the point here: wait it out.
    svc.mock_storage.age_device_polls();
    // At another issuer's endpoint the client is unknown, and the code goes
    // nowhere.
    let mut elsewhere = poll(&svc, &started.device_code, &client.client_id);
    elsewhere.get_mut().issuer_handle = sid_core::models::IssuerHandle::generate().to_string();
    let err = svc
        .auth
        .o_auth2_token(elsewhere)
        .await
        .expect_err("unknown at another issuer");
    assert_refused(err, Code::Unauthenticated, "invalid_client");

    let tokens = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .expect("tokens after approval")
        .into_inner();
    // Issued by the application's issuer.
    let claims = svc
        .issuers
        .verifier(&svc.issuer)
        .await
        .unwrap()
        .validate_access_token(&tokens.access_token)
        .expect("the issuer's key signed the device's token");
    assert_eq!(claims.iss, svc.issuer.canonical_url);
    let sessions = svc
        .storage
        .list_sessions_by_profile(profile.id)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1, "one session for the device");

    let err = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .expect_err("a redeemed device code issues nothing");
    assert_refused(err, Code::InvalidArgument, "invalid_grant");
    assert!(
        svc.storage
            .list_sessions_by_profile(profile.id)
            .await
            .unwrap()
            .is_empty(),
        "the reused code's session was not ended"
    );
}

/// A denied request gives the device no tokens, and the same code cannot be
/// approved afterwards.
#[tokio::test]
async fn test_denied_device_code_stays_denied() {
    let client = device_client();
    let (svc, profile) = services(&client);
    let started = start(&svc, &client.client_id).await;
    let bearer = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    svc.auth
        .submit_device_user_code(approve(&started.user_code, false, &bearer))
        .await
        .expect("denied");
    let err = svc
        .auth
        .submit_device_user_code(approve(&started.user_code, true, &bearer))
        .await
        .expect_err("a decided code takes no second decision");
    assert_eq!(err.code(), Code::FailedPrecondition, "{err:?}");

    let err = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .expect_err("no tokens for a denied code");
    assert_refused(err, Code::PermissionDenied, "access_denied");
}

/// Polling faster than the interval is `slow_down` (RFC 8628 §3.5), with the
/// wait before the next poll in RetryInfo.
#[tokio::test]
async fn test_fast_poll_is_slow_down() {
    let client = device_client();
    let (svc, _) = services(&client);
    let started = start(&svc, &client.client_id).await;

    let first = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .expect_err("pending");
    assert_eq!(
        oauth_error(&first).as_deref(),
        Some("authorization_pending")
    );
    let err = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .expect_err("too fast");
    assert!(err.get_details_retry_info().is_some(), "{err:?}");
    assert_refused(err, Code::ResourceExhausted, "slow_down");
}

/// A device code redeemed by a client other than the one it was issued to is
/// `invalid_grant` (RFC 6749 §5.2), and a poll without the device code is
/// `invalid_request`.
#[tokio::test]
async fn test_poll_needs_the_codes_own_client() {
    let client = device_client();
    let mut other = device_client();
    other.client_id = "other-device-app".into();
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile)
            .with_client(client.clone())
            .with_client(other.clone()),
    );
    let started = start(&svc, &client.client_id).await;

    let err = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &other.client_id))
        .await
        .expect_err("another client's code");
    assert_refused(err, Code::InvalidArgument, "invalid_grant");

    let mut no_code = poll(&svc, "", &client.client_id);
    no_code.get_mut().device_code = None;
    let err = svc.auth.o_auth2_token(no_code).await.unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_request");
}

/// A client not registered for the device grant cannot start it
/// (`unauthorized_client`), and a confidential client must authenticate to
/// start it (RFC 8628 §3.1, RFC 6749 §2.3).
#[tokio::test]
async fn test_start_checks_the_client() {
    let plain = test_client();
    let (svc, _) = services(&plain);
    let err = svc
        .auth
        .start_device_authorization(start_request(&svc, &plain.client_id))
        .await
        .unwrap_err();
    assert_refused(err, Code::PermissionDenied, "unauthorized_client");

    let mut confidential = device_client();
    confidential.client_id = "tv-app".into();
    confidential.client_secret_hash = Some(
        sid_authn::oauth2::OAuth2Server::hash_client_secret("tv-secret")
            .unwrap()
            .into_bytes(),
    );
    confidential.token_endpoint_auth_method =
        sid_core::models::TokenEndpointAuthMethod::ClientSecretPost;
    let (svc, _) = services(&confidential);
    let err = svc
        .auth
        .start_device_authorization(start_request(&svc, &confidential.client_id))
        .await
        .unwrap_err();
    assert_refused(err, Code::Unauthenticated, "invalid_client");

    let mut authenticated = start_request(&svc, &confidential.client_id);
    authenticated.get_mut().client_secret = Some("tv-secret".into());
    svc.auth
        .start_device_authorization(authenticated)
        .await
        .expect("an authenticated confidential client starts");
}

/// A device gets only the scopes its client is allowed, as an authorization
/// request does: the rest of what it asked for is left out, and the token
/// response says what was granted (RFC 6749 §3.3). An approval can never
/// grant a scope the client was not registered for.
#[tokio::test]
async fn test_device_gets_only_the_clients_scopes() {
    let client = device_client();
    let (svc, profile) = services(&client);
    let mut request = start_request(&svc, &client.client_id);
    request.get_mut().scope = Some("openid admin".into());
    let started = svc
        .auth
        .start_device_authorization(request)
        .await
        .unwrap()
        .into_inner();
    let bearer = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    svc.auth
        .submit_device_user_code(approve(&started.user_code, true, &bearer))
        .await
        .unwrap();
    svc.mock_storage.age_device_polls();

    let tokens = svc
        .auth
        .o_auth2_token(poll(&svc, &started.device_code, &client.client_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(tokens.scope.as_deref(), Some("openid"));
}
