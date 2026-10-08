// SPDX-License-Identifier: AGPL-3.0-only
//! Web Push (VAPID) notification channel.
//!
//! Delivers push notifications to web browsers via the Push API.
//! Uses VAPID (Voluntary Application Server Identification) for
//! authentication with push services.

use async_trait::async_trait;
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};

/// VAPID configuration for Web Push.
#[derive(Debug, Clone)]
pub struct VapidConfig {
    /// VAPID subject (mailto: or https: URL).
    pub subject: String,
    /// VAPID public key (base64url-encoded).
    pub public_key: String,
    /// VAPID private key (base64url-encoded).
    pub private_key: String,
}

/// Web Push delivery channel using VAPID.
pub struct WebPushChannel {
    config: VapidConfig,
}

impl WebPushChannel {
    /// Create a new Web Push channel.
    pub fn new(config: VapidConfig) -> Self {
        Self { config }
    }

    /// Get the VAPID public key for client-side subscription.
    pub fn public_key(&self) -> &str {
        &self.config.public_key
    }
}

#[async_trait]
impl NotificationChannel for WebPushChannel {
    fn channel_id(&self) -> &str {
        "web_push"
    }

    async fn deliver(
        &self,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let endpoint = recipient
            .push_endpoint
            .as_deref()
            .ok_or(DeliveryError::NotReachable)?;

        if endpoint.is_empty() {
            return Err(DeliveryError::InvalidRecipient(
                "empty push endpoint".into(),
            ));
        }

        // The payload must be encrypted to the subscription's own keys
        // (RFC 8291 §3), and a recipient carries only the endpoint, so
        // nothing can be sent: refuse rather than issue a receipt.
        tracing::warn!(
            channel = "web_push",
            event_type = %message.event_type,
            "web push delivery unavailable: recipient carries no subscription keys"
        );
        Err(DeliveryError::NotConfigured)
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        let configured = !self.config.public_key.is_empty() && !self.config.private_key.is_empty();

        Ok(ChannelHealth {
            healthy: false,
            message: Some(if configured {
                "VAPID configured, delivery unavailable: no subscription keys".into()
            } else {
                "VAPID keys not configured".into()
            }),
            last_success: None,
        })
    }
}

#[cfg(test)]
mod tests;
