// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM HTTP client for outbound provisioning.
//!
//! Sends SCIM requests (POST/PATCH/DELETE) to downstream app endpoints.
//! Handles authentication, retries with exponential backoff, and error classification.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use sid_core::models::{OutboundAuthConfig, OutboundSyncConfig, ScimOutboundTarget};
use tracing::{debug, warn};

use super::mapper::{ScimGroupPayload, ScimPatchPayload, ScimUserPayload};

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
}

/// Response from a successful SCIM operation.
#[derive(Debug, Clone)]
pub struct ScimResponse {
    /// Resource ID returned by the downstream app.
    pub id: Option<String>,
    /// HTTP status code.
    pub status: u16,
}

/// SCIM HTTP client for a single outbound target.
pub struct ScimHttpClient {
    http: Client,
    endpoint_url: String,
    auth: OutboundAuthConfig,
    sync_config: OutboundSyncConfig,
}

impl ScimHttpClient {
    pub fn new(target: &ScimOutboundTarget) -> Self {
        let http = sid_plugin::client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to create HTTP client");

        Self {
            http,
            endpoint_url: target.endpoint_url.trim_end_matches('/').to_string(),
            auth: target.auth.clone(),
            sync_config: target.sync_config.clone(),
        }
    }

    /// POST /Users — create a user in the downstream app.
    /// Returns the downstream SCIM resource ID.
    pub async fn create_user(
        &self,
        payload: &ScimUserPayload,
    ) -> Result<ScimResponse, ScimClientError> {
        let url = format!("{}/Users", self.endpoint_url);
        self.send_with_retry("POST", &url, Some(payload), None)
            .await
    }

    /// PATCH /Users/{id} — update a user in the downstream app.
    pub async fn update_user(
        &self,
        downstream_id: &str,
        patch: &ScimPatchPayload,
    ) -> Result<ScimResponse, ScimClientError> {
        let url = format!("{}/Users/{}", self.endpoint_url, downstream_id);
        self.send_with_retry("PATCH", &url, Some(patch), None).await
    }

    /// PATCH /Users/{id} with active=false — deactivate a user.
    pub async fn deactivate_user(
        &self,
        downstream_id: &str,
    ) -> Result<ScimResponse, ScimClientError> {
        let patch = ScimPatchPayload::deactivate();
        self.update_user(downstream_id, &patch).await
    }

    /// POST /Groups — create a group in the downstream app.
    pub async fn create_group(
        &self,
        payload: &ScimGroupPayload,
    ) -> Result<ScimResponse, ScimClientError> {
        let url = format!("{}/Groups", self.endpoint_url);
        self.send_with_retry("POST", &url, Some(payload), None)
            .await
    }

    /// PATCH /Groups/{id} — update group members.
    pub async fn update_group(
        &self,
        downstream_id: &str,
        patch: &ScimPatchPayload,
    ) -> Result<ScimResponse, ScimClientError> {
        let url = format!("{}/Groups/{}", self.endpoint_url, downstream_id);
        self.send_with_retry("PATCH", &url, Some(patch), None).await
    }

    /// DELETE /Groups/{id} — delete a group.
    pub async fn delete_group(&self, downstream_id: &str) -> Result<ScimResponse, ScimClientError> {
        let url = format!("{}/Groups/{}", self.endpoint_url, downstream_id);
        self.send_with_retry::<()>("DELETE", &url, None, None).await
    }

    /// Send a request with exponential backoff retry.
    async fn send_with_retry<T: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<&T>,
        retry_after_override: Option<u64>,
    ) -> Result<ScimResponse, ScimClientError> {
        let max_attempts = self.sync_config.max_retry_attempts;
        let base_secs = self.sync_config.retry_backoff_base_secs;
        let mut next_delay_override: Option<u64> = retry_after_override;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = next_delay_override
                    .take()
                    .unwrap_or_else(|| base_secs * 2u64.pow(attempt.saturating_sub(1)));
                debug!(attempt, delay_secs = delay, url, "retrying SCIM request");
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }

            match self.send_once(method, url, body).await {
                Ok(response) => return Ok(response),
                Err(ScimClientError::RateLimited { retry_after_secs }) => {
                    if attempt + 1 < max_attempts {
                        warn!(attempt, retry_after_secs, url, "rate limited, will retry");
                        next_delay_override = Some(retry_after_secs);
                        continue;
                    }
                    return Err(ScimClientError::RateLimited { retry_after_secs });
                }
                Err(ScimClientError::Unreachable(msg)) => {
                    if attempt + 1 < max_attempts {
                        warn!(attempt, %msg, url, "downstream unreachable, will retry");
                        continue;
                    }
                    return Err(ScimClientError::Unreachable(msg));
                }
                Err(e @ ScimClientError::Rejected { status, .. }) if status >= 500 => {
                    if attempt + 1 < max_attempts {
                        warn!(attempt, status, url, "server error, will retry");
                        continue;
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(ScimClientError::Unreachable(
            "max retry attempts exhausted".into(),
        ))
    }

    /// Send a single SCIM request (no retry).
    async fn send_once<T: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<&T>,
    ) -> Result<ScimResponse, ScimClientError> {
        let mut request = match method {
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
                // EE: would fetch token via client_credentials grant
                // CE: not supported, treat as misconfigured
                warn!("OAuth2 client_credentials auth not supported in CE, skipping auth header");
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
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {
                let id = if status != StatusCode::NO_CONTENT {
                    // Try to extract resource ID from response body
                    response
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|v| v.get("id").and_then(|id| id.as_str().map(String::from)))
                } else {
                    None
                };
                Ok(ScimResponse {
                    id,
                    status: status_code,
                })
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sid_core::models::{
        AttributeMapping, GroupPushConfig, OutboundSyncConfig, ProjectId, ScimOutboundTarget,
        ScimOutboundTargetId,
    };

    fn test_target() -> ScimOutboundTarget {
        ScimOutboundTarget {
            id: ScimOutboundTargetId::new(),
            client_id: "test-app".into(),
            project_id: ProjectId::system(),
            display_name: "Test App".into(),
            endpoint_url: "https://scim.example.com/v2".into(),
            auth: OutboundAuthConfig::Bearer {
                token_secret: "test-token".into(),
            },
            attribute_mapping: AttributeMapping::default(),
            group_push: GroupPushConfig::default(),
            sync_config: OutboundSyncConfig {
                max_retry_attempts: 3,
                retry_backoff_base_secs: 1,
            },
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_client_construction() {
        let target = test_target();
        let client = ScimHttpClient::new(&target);
        assert_eq!(client.endpoint_url, "https://scim.example.com/v2");
    }

    #[test]
    fn test_client_strips_trailing_slash() {
        let mut target = test_target();
        target.endpoint_url = "https://scim.example.com/v2/".into();
        let client = ScimHttpClient::new(&target);
        assert_eq!(client.endpoint_url, "https://scim.example.com/v2");
    }

    #[test]
    fn test_scim_client_error_display() {
        let err = ScimClientError::Unreachable("connection refused".into());
        assert!(err.to_string().contains("connection refused"));

        let err = ScimClientError::RateLimited {
            retry_after_secs: 30,
        };
        assert!(err.to_string().contains("429"));

        let err = ScimClientError::AuthFailed { status: 401 };
        assert!(err.to_string().contains("401"));
    }

    #[test]
    fn test_scim_response_debug() {
        let resp = ScimResponse {
            id: Some("downstream-123".into()),
            status: 201,
        };
        assert_eq!(resp.id.as_deref(), Some("downstream-123"));
        assert_eq!(resp.status, 201);
    }
}
