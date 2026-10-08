// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::auth::decision::tests::{ISSUER, ORDERS, SUBJECT, access_token, fixture};
use envoy_types::pb::envoy::config::core::v3::HeaderMap as EnvoyHeaderMap;
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::Request as AttributeRequest;

fn check_request(
    application: Option<&str>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Request<CheckRequest> {
    let mut context_extensions = std::collections::HashMap::new();
    if let Some(application) = application {
        context_extensions.insert(APPLICATION_EXTENSION.to_owned(), application.to_owned());
    }
    Request::new(CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(AttributeRequest {
                http: Some(HttpRequest {
                    method: method.into(),
                    path: path.into(),
                    headers: headers
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            context_extensions,
            ..Default::default()
        }),
    })
}

fn header<'a>(options: &'a [HeaderValueOption], name: &str) -> Option<&'a str> {
    options
        .iter()
        .filter_map(|o| o.header.as_ref())
        .find(|h| h.key == name)
        .map(|h| h.value.as_str())
}

/// Allowed: OK status, the identity headers set, and every other identity
/// header removed from the client's request so none can be forged.
#[tokio::test]
async fn allowed_sets_identity_and_removes_the_rest() {
    let f = fixture();
    let service = ExtAuthzImpl::new(Arc::new(f.pdp));
    let bearer = format!("Bearer {}", access_token(&f.key, ISSUER, ORDERS, 300));
    let response = service
        .check(check_request(
            Some("orders"),
            "GET",
            "/dashboard",
            &[
                ("authorization", &bearer),
                ("x-auth-request-email", "forged"),
            ],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status.unwrap().code, 0);
    let Some(HttpResponse::OkResponse(ok)) = response.http_response else {
        panic!("expected an OK response");
    };
    assert_eq!(header(&ok.headers, "x-forwarded-user"), Some(SUBJECT));
    assert!(
        ok.headers_to_remove
            .iter()
            .any(|h| h == "x-auth-request-email")
    );
    assert!(!ok.headers_to_remove.iter().any(|h| h == "x-forwarded-user"));
}

/// Refused: a denied response with the verdict's status and challenge.
#[tokio::test]
async fn refused_is_denied_with_its_status() {
    let f = fixture();
    let service = ExtAuthzImpl::new(Arc::new(f.pdp));
    let response = service
        .check(check_request(Some("orders"), "GET", "/dashboard", &[]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.status.unwrap().code,
        tonic::Code::Unauthenticated as i32
    );
    let Some(HttpResponse::DeniedResponse(denied)) = response.http_response else {
        panic!("expected a denied response");
    };
    assert_eq!(denied.status.unwrap().code, 401);
    assert_eq!(header(&denied.headers, "www-authenticate"), Some("Bearer"));
}

/// The application comes only from the Envoy route's context extension; a
/// route that names none has no decision.
#[tokio::test]
async fn route_without_application_is_refused() {
    let f = fixture();
    let service = ExtAuthzImpl::new(Arc::new(f.pdp));
    let status = service
        .check(check_request(None, "GET", "/dashboard", &[]))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    let status = service
        .check(check_request(Some("ghost"), "GET", "/", &[]))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

/// Two DPoP headers in Envoy's raw header list stay two, and the merged map
/// joins them into a value no proof parses: either way the request is not
/// taken for one with a single proof.
#[test]
fn raw_headers_keep_repeated_values() {
    let http = HttpRequest {
        header_map: Some(EnvoyHeaderMap {
            headers: vec![
                EnvoyHeaderValue {
                    key: "dpop".into(),
                    raw_value: b"proof-a".to_vec(),
                    ..Default::default()
                },
                EnvoyHeaderValue {
                    key: "dpop".into(),
                    raw_value: b"proof-b".to_vec(),
                    ..Default::default()
                },
            ],
        }),
        ..Default::default()
    };
    let headers = request_headers(&http);
    assert_eq!(headers.get_all("dpop").iter().count(), 2);
}
