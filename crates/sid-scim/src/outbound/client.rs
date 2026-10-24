// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM HTTP client for outbound provisioning.
//!
//! Sends SCIM requests to a downstream app endpoint, one attempt each:
//! retrying is the delivery's, so an attempt never outlives the hold that
//! keeps the event from another replica.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::Value;
use sid_core::models::{OutboundAuthConfig, ScimOutboundTarget};
use sid_plugin::event_bus::Hold;
use tracing::warn;

use super::mapper::{ScimGroupPayload, ScimPatchPayload, ScimUserPayload};

/// The longest one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The hold a request needs before it is sent: its timeout and the time to
/// get it on the wire.
pub const REQUEST_SPAN: Duration = Duration::from_secs(25);

/// Error types for SCIM outbound operations.
#[derive(Debug, thiserror::Error)]
pub enum ScimClientError {
    #[error("downstream unreachable: {0}")]
    Unreachable(String),
    #[error("downstream rejected request (HTTP {status}): {body}")]
    Rejected { status: u16, body: String },
    #[error("rate limited (HTTP 429), retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("conflict (HTTP 409): {body}")]
    Conflict { body: String },
    #[error("auth expired or invalid (HTTP {status})")]
    AuthFailed { status: u16 },
    #[error("serialization error: {0}")]
    Serialization(String),
    /// A successful response that is not what the request returns; a later
    /// attempt may get a readable one.
    #[error("unreadable response: {0}")]
    Malformed(String),
    /// SID's own storage failed: no failure of the target, which may not
    /// even have been asked.
    #[error("storage error: {0}")]
    Storage(String),
    /// The event may go to another replica before a request would end: none
    /// is sent, so two replicas never write the same resource at once.
    #[error("the delivery is no longer certainly held")]
    NotHeld,
}

impl ScimClientError {
    /// Whether a later attempt may succeed where this one did not.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Unreachable(_)
            | Self::RateLimited { .. }
            | Self::NotHeld
            | Self::Malformed(_)
            | Self::Storage(_) => true,
            Self::Rejected { status, .. } => *status >= 500,
            Self::Conflict { .. } | Self::AuthFailed { .. } | Self::Serialization(_) => false,
        }
    }
}

/// SCIM HTTP client for a single outbound target.
pub struct ScimHttpClient {
    http: Client,
    endpoint_url: String,
    auth: OutboundAuthConfig,
    /// How long the delivery being dispatched is this replica's alone.
    hold: Hold,
}

impl ScimHttpClient {
    pub fn new(
        target: &ScimOutboundTarget,
        hold: Hold,
    ) -> Result<Self, sid_plugin::http::HttpClientError> {
        let http = sid_plugin::client_builder()?
            .timeout(REQUEST_TIMEOUT)
            .build()?;

        Ok(Self {
            http,
            endpoint_url: target.endpoint_url.trim_end_matches('/').to_string(),
            auth: target.auth.clone(),
            hold,
        })
    }

    /// POST /Users: the id the downstream app assigned, when it returned one.
    pub async fn create_user(
        &self,
        payload: &ScimUserPayload,
    ) -> Result<Option<String>, ScimClientError> {
        let url = format!("{}/Users", self.endpoint_url);
        Ok(resource_id(
            self.send("POST", &url, Some(payload), &[]).await?,
        ))
    }

    /// PATCH /Users/{id} replacing every mapped attribute with `payload` and
    /// removing the mapped attributes at `absent`, which the user no longer
    /// carries.
    pub async fn replace_user(
        &self,
        downstream_id: &str,
        payload: &ScimUserPayload,
        absent: &[String],
    ) -> Result<(), ScimClientError> {
        let url = format!("{}/Users/{}", self.endpoint_url, downstream_id);
        let patch = ScimPatchPayload::replace_user(payload)?;
        self.send("PATCH", &url, Some(&patch), &[]).await?;
        self.remove_paths(&url, absent).await
    }

    /// The id of the one user named `user_name` (RFC 7644 §3.4.2.2 filter).
    pub async fn find_user(&self, user_name: &str) -> Result<Option<String>, ScimClientError> {
        self.find("Users", "userName", user_name).await
    }

    /// POST /Groups: the id the downstream app assigned, when it returned one.
    pub async fn create_group(
        &self,
        payload: &ScimGroupPayload,
    ) -> Result<Option<String>, ScimClientError> {
        let url = format!("{}/Groups", self.endpoint_url);
        Ok(resource_id(
            self.send("POST", &url, Some(payload), &[]).await?,
        ))
    }

    /// PATCH /Groups/{id} replacing its name and its whole membership; an
    /// empty membership is a second PATCH removing the members, which a group
    /// that has none may answer with `noTarget` (RFC 7644 §3.12): nothing to
    /// remove is the state wanted.
    pub async fn replace_group(
        &self,
        downstream_id: &str,
        payload: &ScimGroupPayload,
    ) -> Result<(), ScimClientError> {
        let url = format!("{}/Groups/{}", self.endpoint_url, downstream_id);
        let patch = ScimPatchPayload::replace_group(payload);
        self.send("PATCH", &url, Some(&patch), &[]).await?;
        if payload.members.is_empty() {
            self.remove_paths(&url, &["members".to_string()]).await?;
        }
        Ok(())
    }

    /// PATCH the resource at `url` removing the attributes at `paths`. A
    /// server that refuses one it has nothing at as `noTarget` (RFC 7644
    /// §3.12; §3.5.2.2 has such a removal succeed) refuses the whole atomic
    /// patch, so the paths then go one by one, a `noTarget` meaning that one
    /// is already gone.
    async fn remove_paths(&self, url: &str, paths: &[String]) -> Result<(), ScimClientError> {
        if paths.is_empty() {
            return Ok(());
        }
        match self
            .send("PATCH", url, Some(&ScimPatchPayload::remove(paths)), &[])
            .await
        {
            Ok(_) => return Ok(()),
            Err(ScimClientError::Rejected { status: 400, body }) if no_target(&body) => {}
            Err(e) => return Err(e),
        }
        for path in paths {
            let one = ScimPatchPayload::remove(std::slice::from_ref(path));
            match self.send("PATCH", url, Some(&one), &[]).await {
                Ok(_) => {}
                Err(ScimClientError::Rejected { status: 400, body }) if no_target(&body) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// The id of the one group named `display_name`.
    pub async fn find_group(&self, display_name: &str) -> Result<Option<String>, ScimClientError> {
        self.find("Groups", "displayName", display_name).await
    }

    /// DELETE /Groups/{id}. One already gone (404, RFC 7644 §3.6) is deleted.
    pub async fn delete_group(&self, downstream_id: &str) -> Result<(), ScimClientError> {
        let url = format!("{}/Groups/{}", self.endpoint_url, downstream_id);
        match self.send::<()>("DELETE", &url, None, &[]).await {
            Ok(_) | Err(ScimClientError::Rejected { status: 404, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The id of the one `resource` whose `attribute` equals `value`; more
    /// than one is a conflict, not a guess.
    async fn find(
        &self,
        resource: &str,
        attribute: &str,
        value: &str,
    ) -> Result<Option<String>, ScimClientError> {
        let url = format!("{}/{resource}", self.endpoint_url);
        // A filter compares to a JSON string literal (RFC 7644 §3.4.2.2).
        let literal = serde_json::to_string(value)
            .map_err(|e| ScimClientError::Serialization(e.to_string()))?;
        let filter = format!("{attribute} eq {literal}");
        let found = self
            .send::<()>("GET", &url, None, &[("filter", &filter)])
            .await?;
        single_match(found).map_err(|e| match e {
            ScimClientError::Conflict { body } => ScimClientError::Conflict {
                body: format!("{body} {resource} match {filter}"),
            },
            other => other,
        })
    }

    /// Send one SCIM request: the response body, if any.
    async fn send<T: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<&T>,
        query: &[(&str, &str)],
    ) -> Result<Option<Value>, ScimClientError> {
        if !self.hold.lasts(REQUEST_SPAN) {
            return Err(ScimClientError::NotHeld);
        }
        let mut request = match method {
            "GET" => self.http.get(
                reqwest::Url::parse_with_params(url, query)
                    .map_err(|e| ScimClientError::Serialization(format!("query: {e}")))?,
            ),
            "POST" => self.http.post(url),
            "PATCH" => self.http.patch(url),
            "PUT" => self.http.put(url),
            "DELETE" => self.http.delete(url),
            _ => {
                return Err(ScimClientError::Serialization(format!(
                    "unsupported method: {method}"
                )));
            }
        };

        // Set auth header
        request = match &self.auth {
            OutboundAuthConfig::Bearer { token_secret } => {
                request.header(AUTHORIZATION, format!("Bearer {token_secret}"))
            }
            OutboundAuthConfig::OAuth2ClientCredentials { .. } => {
                // Not supported: treated as misconfigured.
                warn!("OAuth2 client_credentials auth not supported, skipping auth header");
                request
            }
        };

        request = request.header(CONTENT_TYPE, "application/scim+json");

        if let Some(body) = body {
            let json = serde_json::to_string(body)
                .map_err(|e| ScimClientError::Serialization(e.to_string()))?;
            request = request.body(json);
        }

        let response = request
            .send()
            .await
            .map_err(|e| ScimClientError::Unreachable(e.to_string()))?;

        let status = response.status();
        let status_code = status.as_u16();

        match status {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK | StatusCode::CREATED => Ok(response.json::<Value>().await.ok()),
            StatusCode::TOO_MANY_REQUESTS => {
                let retry_after = response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(30);
                Err(ScimClientError::RateLimited {
                    retry_after_secs: retry_after,
                })
            }
            StatusCode::CONFLICT => {
                let body = response.text().await.unwrap_or_default();
                Err(ScimClientError::Conflict { body })
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ScimClientError::AuthFailed {
                status: status_code,
            }),
            _ => {
                let body = response.text().await.unwrap_or_default();
                Err(ScimClientError::Rejected {
                    status: status_code,
                    body,
                })
            }
        }
    }
}

/// The `id` of a returned SCIM resource.
fn resource_id(body: Option<Value>) -> Option<String> {
    body?.get("id")?.as_str().map(String::from)
}

/// Whether an error response is `noTarget`: the path matched nothing
/// (RFC 7644 §3.12).
fn no_target(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|error| error.get("scimType")?.as_str().map(|t| t == "noTarget"))
        .unwrap_or(false)
}

/// The id of the one resource a filtered query found: `None` only for a
/// well-formed empty ListResponse (RFC 7644 §3.4.2: `totalResults` always,
/// `Resources` whenever it is not zero). Anything else is no proof that the
/// resource is absent, and taking it for one would create it a second time.
fn single_match(body: Option<Value>) -> Result<Option<String>, ScimClientError> {
    let malformed = |why: &str| Err(ScimClientError::Malformed(format!("list response: {why}")));
    let Some(body) = body else {
        return malformed("no JSON body");
    };
    let Some(total) = body.get("totalResults").and_then(Value::as_u64) else {
        return malformed("no totalResults");
    };
    let resources = match body.get("Resources") {
        None if total == 0 => &[][..],
        Some(Value::Array(resources)) => resources.as_slice(),
        _ => return malformed("no Resources list"),
    };
    match (total, resources) {
        (0, []) => Ok(None),
        (1, [one]) => match one.get("id").and_then(Value::as_str) {
            Some(id) => Ok(Some(id.to_string())),
            None => malformed("a match without id"),
        },
        (0 | 1, _) => malformed("totalResults disagrees with Resources"),
        (more, _) => Err(ScimClientError::Conflict {
            body: more.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests;
