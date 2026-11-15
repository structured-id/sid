// SPDX-License-Identifier: AGPL-3.0-only
//! Where an issuing organization's own publication is read: at the
//! installation this one is connected to for that organization. The
//! entry connection an administrator registered for exactly that source
//! organization is the installation's association with it; its issuer's
//! origin serves the organization's CA generations in the platform
//! publication's format, and each generation's CRL apart from them. Where
//! they are read grants nothing: the recipient checks every certificate and
//! list as it checks any.

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

    /// The publications at the installations of the connections registered
    /// for exactly `organization`, the enabled ones first. One that brings
    /// identities of several organizations (the platform's) is no
    /// association with any of them.
    async fn publications(&self, organization: Uuid) -> Result<Vec<PlatformCaPublication>, String> {
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
        connections
            .iter()
            .map(|connection| publication(&connection.issuer))
            .collect()
    }
}

#[async_trait::async_trait]
impl OrganizationPublications for ConnectedPublications {
    async fn fetch(&self, organization: Uuid) -> Result<Option<PlatformCaSet>, String> {
        // Each is asked in turn until one answers.
        let mut failed = None;
        for publication in self.publications(organization).await? {
            match publication.fetch().await {
                Ok(wire) => return set_of(wire).map(Some).map_err(|e| e.to_string()),
                Err(reason) => failed = Some(reason.to_string()),
            }
        }
        failed.map_or(Ok(None), Err)
    }

    async fn crl(&self, organization: Uuid, generation: u32) -> Result<Option<Vec<u8>>, String> {
        let mut failed = None;
        for publication in self.publications(organization).await? {
            match publication.fetch_crl(generation).await {
                Ok(crl) => return Ok(Some(crl)),
                Err(reason) => failed = Some(reason.to_string()),
            }
        }
        failed.map_or(Ok(None), Err)
    }
}

/// The publication at the installation whose issuer is `issuer`.
fn publication(issuer: &str) -> Result<PlatformCaPublication, String> {
    let issuer = url::Url::parse(issuer).map_err(|e| e.to_string())?;
    PlatformCaPublication::new(publication_at(&issuer).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;
