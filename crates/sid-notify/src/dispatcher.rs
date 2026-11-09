// SPDX-License-Identifier: AGPL-3.0-only
//! Notification channels.
//!
//! Holds the registered delivery channels. Rendering reads the stored
//! templates when a delivery runs (see [`crate::delivery`]); routing, retries
//! and outcomes belong to the durable delivery jobs.

use sid_plugin::notification::{
    DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Registered channels.
#[derive(Default)]
pub struct NotificationDispatcher {
    channels: HashMap<String, Arc<dyn NotificationChannel>>,
}

impl NotificationDispatcher {
    /// A dispatcher with no channel registered yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a notification channel.
    pub fn register_channel(&mut self, channel: Arc<dyn NotificationChannel>) {
        self.channels
            .insert(channel.channel_id().to_string(), channel);
    }

    /// Get registered channel IDs.
    pub fn channel_ids(&self) -> Vec<String> {
        self.channels.keys().cloned().collect()
    }

    /// Deliver a rendered message through one channel.
    pub async fn deliver_to_channel(
        &self,
        channel_id: &str,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let channel = self
            .channels
            .get(channel_id)
            .ok_or(DeliveryError::NotConfigured)?;
        channel.deliver(recipient, message).await
    }

    /// Health check all channels.
    pub async fn health_check(&self) -> HashMap<String, bool> {
        let mut results = HashMap::new();
        for (id, channel) in &self.channels {
            let healthy = channel.health().await.map(|h| h.healthy).unwrap_or(false);
            results.insert(id.clone(), healthy);
        }
        results
    }
}

#[cfg(test)]
mod tests;
