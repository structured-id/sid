// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Notification Service.
//!
//! Autonomous binary consuming domain events from NATS JetStream
//! and delivering notifications through configured channels.
//!
//! ## Architecture
//!
//! ```text
//! NATS JetStream ──► NotifyServer ──► NotificationDispatcher ──┬── SmtpChannel
//!                        │                                      ├── WebhookChannel
//!                     gRPC API                                  └── WebPushChannel
//!                  (template mgmt)
//! ```
//!
//! CE channels: Email (SMTP), Webhook (HMAC-SHA256), Web Push (VAPID).
//! EE channels: SMS (Twilio/Vonage), Mobile Push (FCM/APNs), Custom.

pub mod channels;
pub mod config;
pub mod delivery;
pub mod dispatcher;
pub(crate) mod recipient_resolver;
pub mod routing;
pub mod server;
pub mod template;
pub(crate) mod template_store;

pub use config::NotifyConfig;
pub use dispatcher::NotificationDispatcher;
pub use routing::{RoutingRule, RoutingTable};
pub use server::NotifyServer;
pub use template::TemplateEngine;
