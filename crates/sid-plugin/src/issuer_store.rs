// SPDX-License-Identifier: AGPL-3.0-only
//! Issuer store capability: the OIDC issuers a token service signs as and
//! their signing keys. A host that keeps only authorization-server state
//! provides this without the rest of [`crate::StorageBackend`].

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{
    IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, MutationContext, OidcIssuer, OrgId,
};

#[async_trait]
pub trait IssuerStore: Send + Sync {
    /// The issuer of `authority` for `recipient_org`, once provisioned.
    async fn oidc_issuer_for(
        &self,
        authority: IssuerAuthority,
        recipient_org: OrgId,
    ) -> Result<Option<OidcIssuer>>;

    /// The issuer named by `handle`.
    async fn oidc_issuer_by_handle(&self, handle: &IssuerHandle) -> Result<Option<OidcIssuer>>;

    /// Store `issuer` with its generation-1 signing key in one transaction.
    /// Returns `false`, writing nothing, when its authority and organization
    /// already have an issuer: concurrent provisioners agree on the first.
    /// A key of another issuer or generation is a validation error.
    async fn insert_oidc_issuer(
        &self,
        issuer: &OidcIssuer,
        first_key: &IssuerSigningKey,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Every signing key of `issuer`, ascending by generation.
    async fn oidc_issuer_signing_keys(&self, issuer: IssuerId) -> Result<Vec<IssuerSigningKey>>;
}
