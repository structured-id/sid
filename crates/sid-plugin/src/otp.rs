// SPDX-License-Identifier: AGPL-3.0-only
//! OTP Transport plugin traits.
//!
//! Extensible OTP delivery: implement `OtpTransport` to add new delivery
//! channels (email, SMS, etc.) to StructuredID.
//! CE ships with built-in email OTP. EE adds SMS via `SmsProvider` plugins.

use async_trait::async_trait;

/// OTP delivery channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtpChannel {
    Email,
    Sms,
}

impl OtpChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }
}

impl std::fmt::Display for OtpChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Context provided to OTP transports during delivery.
#[derive(Debug, Clone)]
pub struct OtpContext {
    /// Client IP address (for logging/audit).
    pub client_ip: Option<String>,
    /// Site identifier requesting the OTP.
    pub site_id: Option<String>,
}

/// Locale for OTP message localization.
#[derive(Debug, Clone)]
pub struct Locale {
    /// BCP 47 language tag (e.g., "en", "ru", "de").
    pub language: String,
}

impl Default for Locale {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
        }
    }
}

/// Result of successful OTP delivery.
#[derive(Debug, Clone)]
pub struct OtpDeliveryResult {
    /// Provider-assigned message ID (for tracking).
    pub message_id: String,
    /// Provider name (e.g., "smtp", "twilio").
    pub provider: String,
    /// Delivery cost in microcents (0 for email).
    pub cost_microcents: u64,
}

/// Error during OTP transport operations.
#[derive(Debug, thiserror::Error)]
pub enum OtpTransportError {
    #[error("delivery failed: {0}")]
    DeliveryFailed(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("channel unavailable: {0}")]
    ChannelUnavailable(String),
    #[error("rate limited")]
    RateLimited,
    #[error("internal error: {0}")]
    Internal(String),
}

/// OTP transport plugin trait.
///
/// Implement this trait to add new OTP delivery channels to StructuredID.
/// CE includes built-in `EmailOtp` transport.
/// EE adds SMS via `SmsProvider` plugins.
#[async_trait]
pub trait OtpTransport: Send + Sync {
    /// Transport identifier (e.g., "email", "sms").
    fn channel(&self) -> OtpChannel;

    /// Priority for transport selection. Higher wins when multiple
    /// transports serve the same channel (EE override of CE transport).
    fn priority(&self) -> i32 {
        0
    }

    /// Send OTP code to target (email address or phone number).
    async fn send(
        &self,
        target: &str,
        code: &str,
        locale: &Locale,
        ctx: &OtpContext,
    ) -> Result<OtpDeliveryResult, OtpTransportError>;

    /// Check if this transport can reach the given target.
    fn supports(&self, target: &str) -> bool;
}

/// Mask a target for display (e.g., "alice@example.com" → "a****@example.com").
pub fn mask_target(target: &str, channel: OtpChannel) -> String {
    match channel {
        OtpChannel::Email => mask_email(target),
        OtpChannel::Sms => mask_phone(target),
    }
}

fn mask_email(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        if local.len() <= 1 {
            format!("*@{}", domain)
        } else {
            let first = &local[..1];
            format!("{}****@{}", first, domain)
        }
    } else {
        "****".to_string()
    }
}

fn mask_phone(phone: &str) -> String {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "****".to_string();
    }
    let last_two = &digits[digits.len() - 2..];
    let prefix = if phone.starts_with('+') {
        &phone[..phone.find(|c: char| c.is_ascii_digit()).unwrap_or(1)]
    } else {
        ""
    };
    format!("{}*** *** **{}", prefix, last_two)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_channel_as_str() {
        assert_eq!(OtpChannel::Email.as_str(), "email");
        assert_eq!(OtpChannel::Sms.as_str(), "sms");
    }

    #[test]
    fn test_locale_default() {
        let locale = Locale::default();
        assert_eq!(locale.language, "en");
    }

    #[test]
    fn test_mask_email() {
        assert_eq!(mask_email("alice@example.com"), "a****@example.com");
        assert_eq!(mask_email("a@example.com"), "*@example.com");
        assert_eq!(mask_email("bob.smith@gmail.com"), "b****@gmail.com");
        assert_eq!(mask_email("invalid"), "****");
    }

    #[test]
    fn test_mask_phone() {
        assert_eq!(mask_phone("+79161234567"), "+*** *** **67");
        assert_eq!(mask_phone("1234567890"), "*** *** **90");
        assert_eq!(mask_phone("12"), "****");
    }

    #[test]
    fn test_mask_target_delegates() {
        assert_eq!(
            mask_target("alice@example.com", OtpChannel::Email),
            "a****@example.com"
        );
        assert_eq!(
            mask_target("+79161234567", OtpChannel::Sms),
            "+*** *** **67"
        );
    }

    #[test]
    fn test_otp_transport_error_display() {
        let err = OtpTransportError::DeliveryFailed("timeout".into());
        assert_eq!(err.to_string(), "delivery failed: timeout");

        let err = OtpTransportError::RateLimited;
        assert_eq!(err.to_string(), "rate limited");
    }
}
