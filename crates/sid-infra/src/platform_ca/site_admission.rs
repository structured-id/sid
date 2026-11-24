// SPDX-License-Identifier: AGPL-3.0-only
//! The transport of a site's admission statements to the platform this
//! build was made for: `POST {platform}/api/v1/federation/site-admissions`
//! (`sid.v1.federation.SiteAdmissionService.PublishSiteAdmission`, its
//! proto3 JSON mapping).
//!
//! It follows no redirect and bounds the time of an answer. How the
//! platform answered is read from the HTTP status and the error's
//! `google.rpc.ErrorInfo` reason, the stable part of a refusal.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sid_plugin::site_admission::{AdmissionPublisher, PublishError, Published};

use super::{CONNECT_TIMEOUT, PublicationError, TIMEOUT, build_platform};

/// Where below the platform's origin statements are published.
const PUBLISH_PATH: &str = "/v1/federation/site-admissions";

/// The reason of a refusal because a newer revision already stands, as the
/// CE proto names it: this transport reads JSON, not the gRPC error model.
fn superseded() -> &'static str {
    sid_proto::sid::v1::common::ErrorReason::SiteAdmissionSuperseded.as_str_name()
}

/// The longest refusal read for its reason.
const MAX_ERROR_BODY: usize = 1 << 16;

/// The platform this build names, taking statements.
pub struct PlatformAdmissions {
    client: reqwest::Client,
    endpoint: url::Url,
}

impl PlatformAdmissions {
    /// The platform this build was made for; `None` for a build made for
    /// none, which has nobody to tell.
    pub fn of_build() -> Result<Option<Self>, PublicationError> {
        build_platform()?.map(Self::at).transpose()
    }

    /// The platform whose public origin is `platform`.
    pub fn at(platform: url::Url) -> Result<Self, PublicationError> {
        let endpoint = endpoint_of(&platform)?;
        let client = sid_plugin::client_builder()
            .map_err(|e| PublicationError::Client(e.to_string()))?
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| PublicationError::Client(e.to_string()))?;
        Ok(Self { client, endpoint })
    }
}

/// Where the platform at the public origin `platform` takes statements: its
/// public API route, `https` only.
fn endpoint_of(platform: &url::Url) -> Result<url::Url, PublicationError> {
    let endpoint = platform
        .join(&format!("{}{PUBLISH_PATH}", crate::route::API_MOUNT))
        .map_err(|_| PublicationError::NotHttps)?;
    if endpoint.scheme() != "https" {
        return Err(PublicationError::NotHttps);
    }
    Ok(endpoint)
}

/// How the platform's answer of `status` with `body` reads.
fn answer(status: reqwest::StatusCode, body: &[u8]) -> Result<Published, PublishError> {
    if status.is_success() {
        return Ok(Published::Held);
    }
    let reason = refusal_reason(body);
    if reason.as_deref() == Some(superseded()) {
        return Ok(Published::Superseded);
    }
    let described = format!(
        "{} {}",
        status.as_u16(),
        reason.as_deref().unwrap_or("without a reason")
    );
    // A platform that does not answer, is overloaded or does not serve the
    // route yet is asked again; a refusal of the statement itself is final.
    if status.is_server_error()
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::NOT_FOUND
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
    {
        Err(PublishError::Unavailable(described))
    } else {
        Err(PublishError::Refused(described))
    }
}

/// The `google.rpc.ErrorInfo` reason of a refusal's `google.rpc.Status`
/// JSON body, when it carries one.
fn refusal_reason(body: &[u8]) -> Option<String> {
    let status: serde_json::Value = serde_json::from_slice(body).ok()?;
    status
        .get("details")?
        .as_array()?
        .iter()
        .find(|detail| {
            detail.get("@type").and_then(serde_json::Value::as_str)
                == Some("type.googleapis.com/google.rpc.ErrorInfo")
        })?
        .get("reason")?
        .as_str()
        .map(str::to_owned)
}

#[async_trait::async_trait]
impl AdmissionPublisher for PlatformAdmissions {
    async fn publish(&self, statement: &[u8]) -> Result<Published, PublishError> {
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .json(&serde_json::json!({ "statement": STANDARD.encode(statement) }))
            .send()
            .await
            .map_err(|e| PublishError::Unavailable(e.to_string()))?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| PublishError::Unavailable(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_ERROR_BODY {
                break;
            }
            body.extend_from_slice(&chunk);
        }
        answer(status, &body)
    }
}

#[cfg(test)]
mod tests;
