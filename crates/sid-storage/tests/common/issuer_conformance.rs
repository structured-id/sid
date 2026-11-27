// SPDX-License-Identifier: AGPL-3.0-only
//! The issuer store conformance harness of this crate's backends: issuers
//! serve the installation organization, so each scenario runs on a backend
//! of its own (an isolated schema or a fresh database).

use async_trait::async_trait;
use sid_core::models::OrgId;
use sid_plugin::conformance::issuer_store::IssuerHarness;
use sid_plugin::{IssuerStore, StorageBackend};

use super::instance_org;

pub struct InstanceIssuers<'a>(pub &'a dyn StorageBackend);

#[async_trait]
impl IssuerHarness for InstanceIssuers<'_> {
    fn store(&self) -> &dyn IssuerStore {
        self.0
    }

    async fn organization(&self) -> OrgId {
        instance_org(self.0).await
    }

    /// A foreign recipient registered beside the installation's own
    /// organization, as a site registered here is.
    async fn other_organization(&self) -> OrgId {
        let reference = sid_core::models::OrganizationReference::new(OrgId::generate());
        assert!(
            self.0
                .insert_organization_reference(&reference, super::test_audit())
                .await
                .expect("a stored organization reference")
        );
        reference.id
    }
}
