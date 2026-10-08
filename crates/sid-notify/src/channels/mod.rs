// SPDX-License-Identifier: AGPL-3.0-only
//! CE notification channel implementations.
//!
//! - `smtp`: Email delivery via SMTP.
//! - `webhook`: HTTP webhook with HMAC-SHA256 signatures.
//! - `web_push`: Web Push (VAPID) notifications.

pub mod smtp;
pub mod web_push;
pub mod webhook;
pub mod xoauth2;

pub use smtp::{EmailAuthMethod, SmtpBuildError, SmtpChannel, SmtpConfig, SmtpTlsMode};
pub use web_push::WebPushChannel;
pub use webhook::WebhookChannel;
pub use xoauth2::{
    GoogleTokenProvider, M365TokenProvider, XOAuth2Error, XOAuth2SmtpChannel, XOAuth2SmtpConfig,
    XOAuth2TokenProvider, channel_from_email_config,
};
