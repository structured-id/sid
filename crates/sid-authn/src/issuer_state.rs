// SPDX-License-Identifier: AGPL-3.0-only
//! Where a resource apart from its issuer learns a token's state: the exact
//! issuer, which applies its own current-state rule to its records, asked
//! over its authenticated integration (RFC 7662).

/// The issuer could not say whether a token is active: the request it was
/// asked for has no verdict.
#[derive(Debug, thiserror::Error)]
#[error("token state unavailable: {0}")]
pub struct IssuerStateUnavailable(pub String);

/// A token's state at its exact issuer.
#[async_trait::async_trait]
pub trait IssuerState: Send + Sync {
    /// The exact issuer whose tokens this source answers for.
    fn issuer(&self) -> &str;

    /// Whether `token` is active at its issuer now.
    async fn active(&self, token: &str) -> Result<bool, IssuerStateUnavailable>;
}
