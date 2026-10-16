// SPDX-License-Identifier: AGPL-3.0-only
//! Client and resource registry capability: what issuance and target
//! selection read about OAuth clients, protected resources and the access
//! between them. A host that keeps only authorization-server state provides
//! this without the rest of [`crate::StorageBackend`].

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{
    IssuerId, OAuth2Client, ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator,
};

#[async_trait]
pub trait ClientResourceRegistry: Send + Sync {
    /// Get an OAuth2 client by client_id.
    async fn get_oauth2_client(&self, client_id: &str) -> Result<Option<OAuth2Client>>;

    /// A protected resource by id, retired ones included.
    async fn get_protected_resource(&self, id: ResourceId) -> Result<Option<ProtectedResource>>;

    /// The resource `indicator` names under `issuer`, retired ones included.
    async fn protected_resource_by_indicator(
        &self,
        issuer: IssuerId,
        indicator: &ResourceIndicator,
    ) -> Result<Option<ProtectedResource>>;

    /// The access `client_id` has to `resource`, if any.
    async fn resource_access(
        &self,
        client_id: &str,
        resource: ResourceId,
    ) -> Result<Option<ResourceAccess>>;
}
