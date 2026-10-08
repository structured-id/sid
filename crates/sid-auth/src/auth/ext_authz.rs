// SPDX-License-Identifier: AGPL-3.0-only
//! Envoy ext_authz (`envoy.service.auth.v3.Authorization/Check`): the same
//! forward-auth decision for Envoy, which asks over gRPC with the original
//! request's attributes.
//!
//! The protected application comes from the route's
//! `typed_per_filter_config` context extension `application`: Envoy's own
//! configuration, never the client's request.

use std::sync::Arc;

use envoy_types::pb::envoy::config::core::v3::{
    HeaderValue as EnvoyHeaderValue, HeaderValueOption, header_value_option::HeaderAppendAction,
};
use envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest;
use envoy_types::pb::envoy::service::auth::v3::authorization_server::Authorization;
use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
use envoy_types::pb::envoy::service::auth::v3::{
    CheckRequest, CheckResponse, DeniedHttpResponse, OkHttpResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;
use envoy_types::pb::google::rpc::Status as RpcStatus;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use sid_core::grpc_error::{ApiError, ErrorReason};
use tonic::{Request, Response, Status};

use super::decision::{OriginalRequest, Pdp, Verdict};
use super::forward_auth_grpc::decision_status;
use super::headers::IDENTITY_HEADERS;

/// Context extension naming the protected application on an Envoy route.
pub const APPLICATION_EXTENSION: &str = "application";

pub struct ExtAuthzImpl {
    pdp: Arc<Pdp>,
}

impl ExtAuthzImpl {
    pub fn new(pdp: Arc<Pdp>) -> Self {
        Self { pdp }
    }
}

/// The original request's headers. The raw header list keeps repeated
/// headers apart, as a proof count needs (RFC 9449 §4.3 refuses two DPoP
/// headers); the merged map joins them with commas, which no single proof
/// survives, so a repeated proof is refused either way.
fn request_headers(http: &HttpRequest) -> HeaderMap {
    let mut headers = HeaderMap::new();
    match &http.header_map {
        Some(raw) if !raw.headers.is_empty() => {
            for header in &raw.headers {
                let value = if header.raw_value.is_empty() {
                    header.value.as_bytes()
                } else {
                    &header.raw_value
                };
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(header.key.as_bytes()),
                    HeaderValue::from_bytes(value),
                ) {
                    headers.append(name, value);
                }
            }
        }
        _ => {
            for (key, value) in &http.headers {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    headers.append(name, value);
                }
            }
        }
    }
    headers
}

fn header_options(headers: &HeaderMap) -> Vec<HeaderValueOption> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            Some(HeaderValueOption {
                header: Some(EnvoyHeaderValue {
                    key: name.as_str().to_owned(),
                    value: value.to_str().ok()?.to_owned(),
                    ..Default::default()
                }),
                append_action: HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
                ..Default::default()
            })
        })
        .collect()
}

/// The verdict as a Check answer: allowed with the identity headers set and
/// every client-supplied identity header removed, or denied with its status
/// and headers.
fn check_response(verdict: Verdict) -> CheckResponse {
    if verdict.allowed() {
        return CheckResponse {
            status: Some(RpcStatus {
                code: tonic::Code::Ok as i32,
                ..Default::default()
            }),
            http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
                headers: header_options(&verdict.headers),
                headers_to_remove: IDENTITY_HEADERS
                    .iter()
                    .filter(|name| !verdict.headers.contains_key(**name))
                    .map(|name| (*name).to_owned())
                    .collect(),
                ..Default::default()
            })),
            ..Default::default()
        };
    }
    let code = match verdict.status.as_u16() {
        401 => tonic::Code::Unauthenticated,
        _ => tonic::Code::PermissionDenied,
    };
    CheckResponse {
        status: Some(RpcStatus {
            code: code as i32,
            ..Default::default()
        }),
        http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
            status: Some(HttpStatus {
                code: i32::from(verdict.status.as_u16()),
            }),
            headers: header_options(&verdict.headers),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[tonic::async_trait]
impl Authorization for ExtAuthzImpl {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let attributes = request.into_inner().attributes.unwrap_or_default();
        let Some(application) = attributes.context_extensions.get(APPLICATION_EXTENSION) else {
            // The route's configuration, not the client's request, is wrong.
            return Err(ApiError::new(
                ErrorReason::FeatureNotConfigured,
                "the Envoy route names no protected application (context extension `application`)",
            )
            .with_metadata("feature", "ext_authz_route")
            .into());
        };
        let http = attributes
            .request
            .and_then(|request| request.http)
            .unwrap_or_default();
        let method = http.method.parse::<Method>().unwrap_or(Method::GET);
        let headers = request_headers(&http);
        let path = if http.path.is_empty() {
            "/"
        } else {
            &http.path
        };
        let verdict = self
            .pdp
            .decide(
                application,
                OriginalRequest {
                    method: &method,
                    path,
                    headers: &headers,
                },
            )
            .await
            .map_err(decision_status)?;
        Ok(Response::new(check_response(verdict)))
    }
}

#[cfg(test)]
mod tests;
