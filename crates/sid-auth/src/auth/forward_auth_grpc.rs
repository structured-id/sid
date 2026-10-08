// SPDX-License-Identifier: AGPL-3.0-only
//! `ForwardAuthService.Verify`: the forward-auth decision for reverse
//! proxies. The transcoder serves it as `/auth/verify/{application}`; the
//! original request arrives as request metadata and the verdict leaves as the
//! `x-http-code` status and response metadata headers of an empty body.

use std::sync::Arc;

use http::{HeaderMap, Method};
use sid_core::grpc_error::refuse::dependency_unavailable;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::authz::VerifyRequest;
use sid_proto::sid::v1::authz::forward_auth_service_server::ForwardAuthService;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Response, Status};

use super::decision::{DecisionError, OriginalRequest, Pdp, Verdict};

pub struct ForwardAuthServiceImpl {
    pdp: Arc<Pdp>,
}

impl ForwardAuthServiceImpl {
    pub fn new(pdp: Arc<Pdp>) -> Self {
        Self { pdp }
    }
}

/// The first value among `names`, as the proxy forwards the original request.
fn forwarded<'a>(headers: &'a HeaderMap, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| headers.get(*name)?.to_str().ok())
        .filter(|value| !value.is_empty())
}

/// The status of a decision the proxy cannot receive as a verdict.
pub(crate) fn decision_status(error: DecisionError) -> Status {
    match error {
        DecisionError::UnknownApplication(name) => ApiError::new(
            ErrorReason::ForwardAuthApplicationNotFound,
            "no protected application of this name",
        )
        .with_resource("ForwardAuthApplication", name)
        .into(),
        // The decision logged its cause where it failed.
        DecisionError::Unavailable(what) => dependency_unavailable(what, "decision refused"),
    }
}

/// The verdict as an empty `HttpBody` with its status in `x-http-code` and
/// its headers as response metadata.
fn verdict_response(verdict: Verdict) -> Response<HttpBody> {
    let mut metadata = MetadataMap::from_headers(verdict.headers);
    metadata.insert("x-http-code", MetadataValue::from(verdict.status.as_u16()));
    let mut response = Response::new(HttpBody::default());
    *response.metadata_mut() = metadata;
    response
}

#[tonic::async_trait]
impl ForwardAuthService for ForwardAuthServiceImpl {
    async fn verify(&self, request: Request<VerifyRequest>) -> Result<Response<HttpBody>, Status> {
        let (metadata, _, request) = request.into_parts();
        let headers = metadata.into_headers();
        let path = forwarded(&headers, &["x-original-uri", "x-forwarded-uri"]).unwrap_or("/");
        let method = forwarded(&headers, &["x-original-method", "x-forwarded-method"])
            .and_then(|m| m.parse::<Method>().ok())
            .unwrap_or(Method::GET);
        let verdict = self
            .pdp
            .decide(
                &request.application,
                OriginalRequest {
                    method: &method,
                    path,
                    headers: &headers,
                },
            )
            .await
            .map_err(decision_status)?;
        Ok(verdict_response(verdict))
    }
}

#[cfg(test)]
mod tests;
