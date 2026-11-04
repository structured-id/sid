// SPDX-License-Identifier: AGPL-3.0-only
//! Where a delivery pipeline finds the recipient of an event.
//!
//! The standalone notifier resolves Profiles through the identity service
//! ([`crate::recipient_resolver`]); a host composing the pipeline in its own
//! process supplies the source its recipients come from and their authority
//! is decided by.

use async_trait::async_trait;
use sid_core::models::event::Event;
use sid_plugin::notification::Recipient;

/// The recipient of each routed event, and whether it still is one when a
/// delivery runs.
#[async_trait]
pub trait RecipientSource: Send + Sync {
    /// The recipient `event` is delivered to.
    async fn resolve(&self, event: &Event) -> Result<Recipient, ResolveError>;

    /// Whether `recipient`, resolved when `event` was routed, may still
    /// receive it: asked before every delivery attempt, so authority that
    /// ended in between delivers nothing.
    async fn still_recipient(
        &self,
        _event: &Event,
        _recipient: &Recipient,
    ) -> Result<bool, ResolveError> {
        Ok(true)
    }

    /// `event` was routed: a source caching contact details drops what the
    /// event made stale.
    async fn observed(&self, _event: &Event) {}
}

/// Why a recipient could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The event has no recipient any more (its subject is gone or has no
    /// one to receive it): nothing is delivered.
    #[error("no recipient: {0}")]
    ProfileGone(String),
    /// The source did not answer usefully; worth another try.
    #[error("recipient lookup failed: {0}")]
    Unavailable(String),
}
