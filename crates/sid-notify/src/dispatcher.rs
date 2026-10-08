// SPDX-License-Identifier: AGPL-3.0-only
//! Notification channels and message rendering.
//!
//! Holds the registered delivery channels and renders messages from the
//! shared template engine, the one administrators customize. Routing,
//! retries and outcomes belong to the durable delivery jobs
//! (see [`crate::delivery`]).

use crate::template::{TemplateEngine, TemplateError};
use sid_core::models::event::Event;
use sid_plugin::notification::{
    DeliveryError, DeliveryReceipt, NotificationChannel, NotificationPriority, Recipient,
    RenderedMessage,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Registered channels plus the template engine they render from.
pub struct NotificationDispatcher {
    channels: HashMap<String, Arc<dyn NotificationChannel>>,
    templates: Arc<RwLock<TemplateEngine>>,
}

impl NotificationDispatcher {
    /// A dispatcher rendering from `templates`, the engine the template
    /// store keeps customizations in.
    pub fn new(templates: Arc<RwLock<TemplateEngine>>) -> Self {
        Self {
            channels: HashMap::new(),
            templates,
        }
    }

    /// Register a notification channel.
    pub fn register_channel(&mut self, channel: Arc<dyn NotificationChannel>) {
        self.channels
            .insert(channel.channel_id().to_string(), channel);
    }

    /// Render `template` for `event`.
    pub async fn render(
        &self,
        template: &str,
        event: &Event,
        priority: NotificationPriority,
    ) -> Result<RenderedMessage, TemplateError> {
        self.templates
            .read()
            .await
            .render(template, event, priority)
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
