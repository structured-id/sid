// SPDX-License-Identifier: AGPL-3.0-only
//! Where an issuing organization's own publication is read
//! (`arch/auth/org-ca-architecture.md` §organization-status-publication):
//! at the installation this one is connected to for that organization. The
//! entry connection an administrator registered for exactly that source
//! organization is the installation's association with it; its issuer's
//! origin serves the organization's CA generations and their lists in the
//! platform publication's format. Where the publication is read grants
//! nothing: the recipient checks every certificate and list as it checks
//! any.

use std::sync::Arc;

use sid_fed::recipient::OrganizationPublications;
use sid_infra::platform_ca::{PlatformCaPublication, publication_at, set_of};
use sid_plugin::entry_connection::EntryConnectionStore;
use sid_plugin::platform_ca::PlatformCaSet;
use uuid::Uuid;

/// Organizations' publications at the installations of their registered
/// entry connections.
pub struct ConnectedPublications {
    connections: Arc<dyn EntryConnectionStore>,
}

impl ConnectedPublications {
    pub fn new(connections: Arc<dyn EntryConnectionStore>) -> Self {
        Self { connections }
    }
}

#[async_trait::async_trait]
impl OrganizationPublications for ConnectedPublications {
    async fn fetch(&self, organization: Uuid) -> Result<Option<PlatformCaSet>, String> {
        // Only connections registered for exactly this organization: one
        // that brings identities of several organizations (the platform's)
        // is no association with any of them. The enabled ones first; each
        // is asked in turn until one answers.
        let mut connections: Vec<_> = self
            .connections
            .list_entry_connections()
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|c| {
                c.source
                    .is_some_and(|source| source.into_uuid() == organization)
            })
            .collect();
        connections.sort_by_key(|c| !c.enabled);
        let mut failed = None;
        for connection in &connections {
            match read(&connection.issuer).await {
                Ok(set) => return Ok(Some(set)),
                Err(reason) => failed = Some(reason),
            }
        }
        match failed {
            Some(reason) => Err(reason),
            None => Ok(None),
        }
    }
}

/// The publication at the installation whose issuer is `issuer`.
async fn read(issuer: &str) -> Result<PlatformCaSet, String> {
    let issuer = url::Url::parse(issuer).map_err(|e| e.to_string())?;
    let publication =
        PlatformCaPublication::new(publication_at(&issuer).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let wire = publication.fetch().await.map_err(|e| e.to_string())?;
    set_of(wire).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;
