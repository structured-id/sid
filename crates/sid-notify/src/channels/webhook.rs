// SPDX-License-Identifier: AGPL-3.0-only
//! Webhook delivery channel with HMAC-SHA256 signatures.
//!
//! Delivers notification events as HTTP POST with:
//! - `X-SID-Signature` header: HMAC-SHA256(secret, body)
//! - `X-SID-Event` header: event type
//! - `X-SID-Delivery` header: unique delivery ID
//! - CloudEvents JSON body

use core::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use sha2::Sha256;
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};

type HmacSha256 = Hmac<Sha256>;

/// Webhook endpoint configuration.
#[derive(Debug, Clone)]
pub struct WebhookEndpoint {
    /// Target URL.
    pub url: String,
    /// HMAC-SHA256 signing secret.
    pub secret: String,
    /// Optional custom headers.
    pub headers: Vec<(String, String)>,
    /// Whether this endpoint is active.
    pub active: bool,
}

/// How long an endpoint has to answer one delivery.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Webhook delivery channel.
///
/// Sends notification payloads to registered HTTP endpoints
/// with HMAC-SHA256 signatures for authenticity verification.
pub struct WebhookChannel {
    endpoints: Vec<WebhookEndpoint>,
    http: reqwest::Client,
}

/// Which of several endpoint failures decides the delivery: an error that a
/// retry can fix outranks an unknown outcome, which outranks a refusal.
fn precedence(error: &DeliveryError) -> u8 {
    match error {
        DeliveryError::Rejected(_)
        | DeliveryError::NotReachable
        | DeliveryError::InvalidRecipient(_)
        | DeliveryError::NotConfigured => 0,
        DeliveryError::Ambiguous(_) => 1,
        DeliveryError::Failed(_) | DeliveryError::RateLimited | DeliveryError::Internal(_) => 2,
    }
}

/// Maps an endpoint's HTTP answer onto the delivery outcome.
fn classify_status(status: StatusCode) -> Result<(), DeliveryError> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        Err(DeliveryError::RateLimited)
    } else if status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
        Err(DeliveryError::Failed(format!("endpoint answered {status}")))
    } else {
        Err(DeliveryError::Rejected(format!(
            "endpoint answered {status}"
        )))
    }
}

impl WebhookChannel {
    /// Create a new webhook channel with endpoints.
    ///
    /// Redirects are not followed: an endpoint answers for itself.
    pub fn new(endpoints: Vec<WebhookEndpoint>) -> Result<Self, DeliveryError> {
        let http = sid_plugin::http::client_builder()
            .timeout(DELIVERY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| DeliveryError::Internal(format!("webhook HTTP client: {e}")))?;
        Ok(Self { endpoints, http })
    }

    /// POSTs the signed payload to one endpoint.
    async fn post(
        &self,
        endpoint: &WebhookEndpoint,
        delivery_id: &str,
        message: &RenderedMessage,
        payload: &[u8],
    ) -> Result<(), DeliveryError> {
        let signature = Self::sign(&endpoint.secret, payload);
        let mut request = self
            .http
            .post(&endpoint.url)
            .header(CONTENT_TYPE, "application/json")
            .header("X-SID-Signature", format!("sha256={signature}"))
            .header("X-SID-Event", &message.event_type)
            .header("X-SID-Delivery", delivery_id);
        for (name, value) in &endpoint.headers {
            request = request.header(name, value);
        }
        let response = request.body(payload.to_vec()).send().await.map_err(|e| {
            // A timeout once the request left means the endpoint may have
            // acted on it; anything earlier never reached it.
            if e.is_timeout() && !e.is_connect() {
                DeliveryError::Ambiguous(e.to_string())
            } else {
                DeliveryError::Failed(e.to_string())
            }
        })?;
        classify_status(response.status())
    }

    /// Get registered endpoints.
    pub fn endpoints(&self) -> &[WebhookEndpoint] {
        &self.endpoints
    }

    /// Compute HMAC-SHA256 signature for a payload.
    pub fn sign(secret: &str, payload: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(payload);
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Verify an HMAC-SHA256 signature.
    pub fn verify(secret: &str, payload: &[u8], signature: &str) -> bool {
        let expected = Self::sign(secret, payload);
        // Constant-time comparison.
        if expected.len() != signature.len() {
            return false;
        }
        expected
            .bytes()
            .zip(signature.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

#[async_trait]
impl NotificationChannel for WebhookChannel {
    fn channel_id(&self) -> &str {
        "webhook"
    }

    async fn deliver(
        &self,
        _recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let active_endpoints: Vec<_> = self.endpoints.iter().filter(|e| e.active).collect();

        if active_endpoints.is_empty() {
            return Err(DeliveryError::NotConfigured);
        }

        let delivery_id = uuid::Uuid::now_v7().to_string();
        let payload =
            serde_json::to_vec(message).map_err(|e| DeliveryError::Internal(e.to_string()))?;

        // Every endpoint is attempted; the message counts as delivered only
        // when all of them accepted it. A retry re-sends to endpoints that
        // already accepted, which at-least-once delivery allows.
        let mut worst: Option<DeliveryError> = None;
        for endpoint in &active_endpoints {
            if let Err(e) = self.post(endpoint, &delivery_id, message, &payload).await {
                tracing::warn!(
                    channel = "webhook",
                    url = %endpoint.url,
                    delivery_id = %delivery_id,
                    error = %e,
                    "webhook delivery failed"
                );
                worst = Some(match worst {
                    Some(prev) if precedence(&prev) >= precedence(&e) => prev,
                    _ => e,
                });
            }
        }
        if let Some(e) = worst {
            return Err(e);
        }

        Ok(DeliveryReceipt {
            message_id: delivery_id,
            channel: "webhook".into(),
            timestamp: Utc::now(),
            provider: format!("webhook:{}", active_endpoints.len()),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        let active_count = self.endpoints.iter().filter(|e| e.active).count();
        Ok(ChannelHealth {
            healthy: active_count > 0,
            message: Some(format!("{active_count} active endpoints")),
            last_success: None,
        })
    }
}

#[cfg(test)]
mod tests;
