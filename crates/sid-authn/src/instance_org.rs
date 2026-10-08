// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's own organization.
//!
//! A CE installation is one implicit Community organization, created by the
//! first replica to start and read back by every later start. Its id keys the
//! pairwise subjects of every application registered here.

use sid_core::models::{AuditEntry, Organization};
use sid_plugin::StorageBackend;

/// The installation's organization, created with `canonical_domain` on the
/// first start. A later start keeps the stored one, whatever domain it is
/// given: the organization's id never changes.
pub async fn ensure(
    storage: &dyn StorageBackend,
    canonical_domain: &str,
) -> sid_core::Result<Organization> {
    if let Some(org) = storage.instance_organization().await? {
        return Ok(org);
    }
    let fresh = Organization::implicit_community(canonical_domain);
    // Replicas starting together race here: the first insert is kept and
    // every one of them reads that one back below.
    storage
        .insert_instance_organization(
            &fresh,
            AuditEntry::system("organization.created", fresh.id.to_string()).into(),
        )
        .await?;
    storage.instance_organization().await?.ok_or_else(|| {
        sid_core::Error::Storage("instance organization missing right after it was stored".into())
    })
}

#[cfg(test)]
mod tests;
