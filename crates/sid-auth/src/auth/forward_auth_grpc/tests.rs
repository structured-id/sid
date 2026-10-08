// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::auth::decision::tests::{ISSUER, ORDERS, SUBJECT, access_token, fixture};
use tonic_types::StatusExt;

fn verify_request(application: &str, metadata: &[(&'static str, &str)]) -> Request<VerifyRequest> {
    let mut request = Request::new(VerifyRequest {
        application: application.into(),
    });
    for (name, value) in metadata {
        request.metadata_mut().insert(*name, value.parse().unwrap());
    }
    request
}

fn http_code(response: &Response<HttpBody>) -> &str {
    response
        .metadata()
        .get("x-http-code")
        .unwrap()
        .to_str()
        .unwrap()
}

/// The verdict travels as the `x-http-code` status and response metadata
/// headers of an empty body: an allowed request carries the identity.
#[tokio::test]
async fn allowed_request_answers_200_with_identity() {
    let f = fixture();
    let service = ForwardAuthServiceImpl::new(Arc::new(f.pdp));
    let bearer = format!("Bearer {}", access_token(&f.key, ISSUER, ORDERS, 300));
    let response = service
        .verify(verify_request(
            "orders",
            &[
                ("authorization", &bearer),
                ("x-original-uri", "/dashboard"),
                ("x-original-method", "GET"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(http_code(&response), "200");
    assert_eq!(
        response.metadata().get("x-forwarded-user").unwrap(),
        SUBJECT
    );
    assert!(response.get_ref().data.is_empty());
}

/// A refused request is still an answer, 401 with its challenge, not a gRPC
/// error: the proxy needs the status and headers.
#[tokio::test]
async fn refused_request_answers_401_with_challenge() {
    let f = fixture();
    let service = ForwardAuthServiceImpl::new(Arc::new(f.pdp));
    let response = service
        .verify(verify_request(
            "orders",
            &[("x-forwarded-uri", "/dashboard")],
        ))
        .await
        .unwrap();
    assert_eq!(http_code(&response), "401");
    assert_eq!(
        response.metadata().get("www-authenticate").unwrap(),
        "Bearer"
    );
}

/// The original method and path come from `x-original-*`, else
/// `x-forwarded-*`: a public GET route admits while the POST route refuses.
#[tokio::test]
async fn original_method_and_path_choose_the_route() {
    let f = fixture();
    let service = ForwardAuthServiceImpl::new(Arc::new(f.pdp));
    let get = service
        .verify(verify_request(
            "orders",
            &[
                ("x-forwarded-uri", "/api/data"),
                ("x-forwarded-method", "GET"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(http_code(&get), "200");
    let post = service
        .verify(verify_request(
            "orders",
            &[
                ("x-original-uri", "/api/data"),
                ("x-original-method", "POST"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(http_code(&post), "401");
}

/// An application the route configuration lacks is NOT_FOUND with its
/// reason and name, never a verdict.
#[tokio::test]
async fn unknown_application_is_not_found() {
    let f = fixture();
    let service = ForwardAuthServiceImpl::new(Arc::new(f.pdp));
    let status = service
        .verify(verify_request("ghost", &[]))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    let info = status.get_details_error_info().expect("ErrorInfo");
    assert_eq!(info.reason, "FORWARD_AUTH_APPLICATION_NOT_FOUND");
    let resource = status.get_details_resource_info().expect("ResourceInfo");
    assert_eq!(resource.resource_name, "ghost");
}

/// A check that cannot be answered is UNAVAILABLE: the proxy denies.
#[tokio::test]
async fn unanswerable_check_is_unavailable() {
    let f = fixture();
    let service = ForwardAuthServiceImpl::new(Arc::new(f.pdp));
    let bearer = format!("Bearer {}", access_token(&f.key, ISSUER, ORDERS, 300));
    let status = service
        .verify(verify_request(
            "orders",
            &[("authorization", &bearer), ("x-original-uri", "/checked/x")],
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
}
