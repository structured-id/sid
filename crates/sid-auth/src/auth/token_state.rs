// SPDX-License-Identifier: AGPL-3.0-only
//! A token's current state, as its issuer decides it now. A local revocation
//! view only refuses what it already knows; whether a token is still active
//! (its grant, session and actor) comes from the exact issuer, over its
//! authenticated integration or, composed in one process, directly.

use std::sync::Arc;

/// The issuer could not answer; the request it was asked for has no verdict.
#[derive(Debug, thiserror::Error)]
#[error("token state unavailable: {0}")]
pub struct TokenStateUnavailable(pub String);

/// Where a verifier learns whether a token is active.
#[async_trait::async_trait]
pub trait TokenState: Send + Sync {
    /// The exact issuer whose tokens this source answers for.
    fn issuer(&self) -> &str;

    /// Whether `token` is active at its issuer now.
    async fn active(&self, token: &str) -> Result<bool, TokenStateUnavailable>;
}

/// A remote issuer's introspection (RFC 7662), asked with this service's own
/// client.
#[async_trait::async_trait]
impl TokenState for sid_infra::client_credential::ClientCredential {
    fn issuer(&self) -> &str {
        sid_infra::client_credential::ClientCredential::issuer(self)
    }

    async fn active(&self, token: &str) -> Result<bool, TokenStateUnavailable> {
        self.introspect(token)
            .await
            .map_err(|e| TokenStateUnavailable(e.to_string()))
    }
}

/// The token state source of a credential, when the service holds one.
pub fn of(
    credential: &Option<Arc<sid_infra::client_credential::ClientCredential>>,
) -> Option<Arc<dyn TokenState>> {
    credential
        .clone()
        .map(|credential| credential as Arc<dyn TokenState>)
}
