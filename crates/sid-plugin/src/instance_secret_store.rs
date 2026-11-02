// SPDX-License-Identifier: AGPL-3.0-only
//! Instance secret capability: the sealed secrets every replica of one
//! authority shares, created once by the first replica to start.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{InstanceSecret, MutationContext};

#[async_trait]
pub trait InstanceSecretStore: Send + Sync {
    /// The sealed value of an instance secret, if one was stored.
    async fn get_instance_secret(&self, secret: InstanceSecret) -> Result<Option<Vec<u8>>>;

    /// Store an instance secret. Returns `false`, writing nothing, when it
    /// already exists: concurrent starters agree on the first value stored.
    /// An admin claim is refused (an error) on a centrally managed
    /// installation, whichever build writes it.
    async fn insert_instance_secret(
        &self,
        secret: InstanceSecret,
        sealed: &[u8],
        ctx: MutationContext,
    ) -> Result<bool>;
}
