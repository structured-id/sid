// SPDX-License-Identifier: AGPL-3.0-only
//! Native session renewal (native_session.proto) end to end: a password
//! sign-in that proves the application key gets a refresh generation bound
//! to it; RefreshNativeSession rotates it once, delivers the committed
//! generation again for a retried exchange, ends the session on a retired
//! credential, and checks the proof against the request as addressed.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::native_client::{Binds, ORIGIN, generation, proof, rpc_uri, with_proof};
use common::opaque_client::{bearer, register, start_login};
use sid_authn::native_session::REFRESH_METADATA;
use sid_core::models::ProfileId;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Response, Status};

const PRINCIPAL: &str = "native@sid.example.com";
const PASSWORD: &[u8] = b"native-session-password-2026";

async fn services() -> (TestServices, ProfileId) {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, PRINCIPAL, PASSWORD).await;
    let profile = svc
        .storage
        .get_profile_by_email(PRINCIPAL)
        .await
        .unwrap()
        .unwrap()
        .id;
    (svc, profile)
}

/// A native password sign-in whose finish proves the test key over the bytes
/// of its `login_id`.
async fn renewable_sign_in(svc: &TestServices) -> Response<OpaqueLoginFinishResponse> {
    let finish = start_login(svc, PRINCIPAL, PASSWORD).await;
    let proof = proof(
        &rpc_uri("OpaqueLoginFinish"),
        Binds::Ceremony(&finish.login_id.as_ref().unwrap().value),
    );
    svc.auth
        .opaque_login_finish(with_proof(finish, &proof))
        .await
        .expect("signed in")
}

/// RefreshNativeSession presenting `credential` in `exchange` with a fresh
/// proof for `htu`.
fn refresh_request(
    credential: &str,
    exchange: &[u8],
    htu: &str,
) -> Request<RefreshNativeSessionRequest> {
    let proof = proof(
        htu,
        Binds::Refresh {
            credential,
            exchange,
        },
    );
    let mut request = with_proof(
        RefreshNativeSessionRequest {
            exchange: exchange.to_vec(),
        },
        &proof,
    );
    request
        .metadata_mut()
        .insert(REFRESH_METADATA, credential.parse().unwrap());
    request
}

async fn refresh(
    svc: &TestServices,
    credential: &str,
    exchange: &[u8],
) -> Result<Response<RefreshNativeSessionResponse>, Status> {
    svc.auth
        .refresh_native_session(refresh_request(
            credential,
            exchange,
            &rpc_uri("RefreshNativeSession"),
        ))
        .await
}

/// The sign-in gets the policy's generation (CE: two credentials) beside its
/// access token, and the refresh renews the same session with the next one
/// and a new access token for it.
#[tokio::test]
async fn a_proved_sign_in_renews_its_session() {
    let (svc, profile) = services().await;
    let signed_in = renewable_sign_in(&svc).await;
    let first = generation(&signed_in).expect("a refresh generation");
    assert_eq!(first.refresh_credentials.len(), 2);
    assert_eq!(first.redelivery_window, 30);
    assert!(first.expires_in > 0);
    let session_id = signed_in.into_inner().session_id;

    let refreshed = refresh(&svc, &first.refresh_credentials[0], &[1; 16])
        .await
        .expect("refreshed");
    let next = generation(&refreshed).expect("the next generation");
    assert!(
        next.refresh_credentials
            .iter()
            .all(|c| !first.refresh_credentials.contains(c))
    );
    let token = bearer(&refreshed);
    let claims = svc.jwt.validate_access_token(&token).unwrap();
    assert_eq!(
        claims.sid,
        common::opaque_client::session_text(session_id.as_ref())
    );
    assert_eq!(refreshed.into_inner().session_id, session_id);
    assert_eq!(svc.mock_storage.sessions_of(profile), 1);
}

/// A native sign-in without a proof is answered as before: an access token
/// and no generation.
#[tokio::test]
async fn a_sign_in_without_a_proof_gets_no_generation() {
    let (svc, _) = services().await;
    let finish = start_login(&svc, PRINCIPAL, PASSWORD).await;
    let response = svc
        .auth
        .opaque_login_finish(Request::new(finish))
        .await
        .unwrap();
    assert!(generation(&response).is_none());
    bearer(&response);
}

/// A proof bound to another ceremony fails the sign-in before the ceremony
/// is consumed: no session exists without the binding it asked for.
#[tokio::test]
async fn a_proof_of_another_ceremony_signs_nobody_in() {
    let (svc, profile) = services().await;
    let finish = start_login(&svc, PRINCIPAL, PASSWORD).await;
    let proof = proof(
        &rpc_uri("OpaqueLoginFinish"),
        Binds::Ceremony(b"another ceremony"),
    );
    let refused = svc
        .auth
        .opaque_login_finish(with_proof(finish, &proof))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);
    assert_eq!(svc.mock_storage.sessions_of(profile), 0);
}

/// A lost refresh response: the retry of the same exchange with the spare
/// credential gets the very generation the first attempt committed.
#[tokio::test]
async fn a_retried_exchange_gets_the_committed_generation() {
    let (svc, _) = services().await;
    let first = generation(&renewable_sign_in(&svc).await).unwrap();
    let lost = refresh(&svc, &first.refresh_credentials[0], &[2; 16])
        .await
        .unwrap();
    let retried = refresh(&svc, &first.refresh_credentials[1], &[2; 16])
        .await
        .expect("redelivered");
    assert_eq!(generation(&retried), generation(&lost));
}

/// A retired credential presented with the session's key in a new exchange
/// ends the session; its holder signs in again.
#[tokio::test]
async fn a_retired_credential_ends_the_session() {
    let (svc, profile) = services().await;
    let first = generation(&renewable_sign_in(&svc).await).unwrap();
    refresh(&svc, &first.refresh_credentials[0], &[3; 16])
        .await
        .unwrap();
    let refused = refresh(&svc, &first.refresh_credentials[1], &[4; 16])
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated);
    assert_eq!(svc.mock_storage.sessions_of(profile), 0);
}

/// Over REST the proof names the HTTP route the transcoder served, and a
/// proof naming the gRPC path instead is refused there, renewing nothing.
#[tokio::test]
async fn a_rest_refresh_names_its_route() {
    let (svc, _) = services().await;
    let first = generation(&renewable_sign_in(&svc).await).unwrap();
    let route = "/v1/auth/native-session/refresh";

    let mut wrong = refresh_request(
        &first.refresh_credentials[0],
        &[5; 16],
        &rpc_uri("RefreshNativeSession"),
    );
    wrong
        .extensions_mut()
        .insert(sid_infra::authn::resource::TranscodedRequest::new(
            "POST", route,
        ));
    let refused = svc.auth.refresh_native_session(wrong).await.unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);

    let mut right = refresh_request(
        &first.refresh_credentials[0],
        &[5; 16],
        &format!("{ORIGIN}{route}"),
    );
    right
        .extensions_mut()
        .insert(sid_infra::authn::resource::TranscodedRequest::new(
            "POST", route,
        ));
    let refreshed = svc.auth.refresh_native_session(right).await.unwrap();
    assert!(generation(&refreshed).is_some());
}

/// A refresh without its proof, or with a malformed exchange, is refused
/// before anything is read; a credential no generation holds is answered as
/// an ended session.
#[tokio::test]
async fn malformed_and_unknown_refreshes_are_refused() {
    let (svc, _) = services().await;
    let first = generation(&renewable_sign_in(&svc).await).unwrap();

    let mut no_proof = Request::new(RefreshNativeSessionRequest {
        exchange: vec![6; 16],
    });
    no_proof.metadata_mut().insert(
        REFRESH_METADATA,
        first.refresh_credentials[0].parse().unwrap(),
    );
    let refused = svc.auth.refresh_native_session(no_proof).await.unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);

    let refused = refresh(&svc, &first.refresh_credentials[0], &[6; 15])
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);

    let refused = refresh(&svc, "never-issued", &[6; 16]).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated);

    // None of it used the credential.
    refresh(&svc, &first.refresh_credentials[0], &[7; 16])
        .await
        .expect("still current");
}

/// A session that ended takes its generation with it.
#[tokio::test]
async fn an_ended_session_renews_no_more() {
    let (svc, _) = services().await;
    let signed_in = renewable_sign_in(&svc).await;
    let first = generation(&signed_in).unwrap();
    let session = sid_ids_proto::required(signed_in.into_inner().session_id.as_ref()).unwrap();
    svc.storage
        .delete_session(
            session,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            sid_core::models::AuditEntry::system("test", "logout").into(),
        )
        .await
        .unwrap();
    let refused = refresh(&svc, &first.refresh_credentials[0], &[8; 16])
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated);
}
