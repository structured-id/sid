// SPDX-License-Identifier: AGPL-3.0-only
//! The client and resource registry conformance harness of this crate's
//! backends: registration goes through the administrative application API,
//! each client and resource under an application of its own in the system
//! project, retirement by removing the resource's application.

use async_trait::async_trait;
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    Application, ApplicationId, IssuerId, OAuth2Client, OrgId, ProjectId, ProtectedResource,
    ResourceAccess, ResourceId,
};
use sid_plugin::conformance::client_registry::RegistryHarness;
use sid_plugin::{ClientResourceRegistry, StorageBackend};

use super::application::{instance_issuer, store_client};
use super::{instance_org, test_audit};

pub struct AdminRegistry<'a>(pub &'a dyn StorageBackend);

fn application(id: ApplicationId, name: &str) -> Application {
    let now = Utc::now().trunc_subsecs(3);
    Application {
        id,
        project_id: ProjectId::system(),
        name: name.to_owned(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

#[async_trait]
impl RegistryHarness for AdminRegistry<'_> {
    fn registry(&self) -> &dyn ClientResourceRegistry {
        self.0
    }

    async fn issuer(&self) -> IssuerId {
        instance_issuer(self.0).await
    }

    /// An issuer that serves no organization of this store: it exists only
    /// to name an indicator nothing is registered under.
    async fn other_issuer(&self) -> IssuerId {
        IssuerId::generate()
    }

    async fn organization(&self) -> OrgId {
        instance_org(self.0).await
    }

    async fn register_client(&self, client: &OAuth2Client) {
        self.0.ensure_system_project(test_audit()).await.unwrap();
        store_client(self.0, client, test_audit()).await.unwrap();
    }

    async fn register_resource(&self, resource: &ProtectedResource) {
        self.0.ensure_system_project(test_audit()).await.unwrap();
        let app_id = resource
            .application_id
            .expect("a registered resource names its application");
        self.0
            .create_application(
                &application(app_id, "Conformance resource"),
                None,
                Some(resource),
                test_audit(),
            )
            .await
            .unwrap();
    }

    async fn grant_access(&self, access: &ResourceAccess) {
        self.0
            .set_resource_access(access, test_audit())
            .await
            .unwrap();
    }

    async fn retire_resource(&self, resource: ResourceId) {
        let app_id = self
            .0
            .get_protected_resource(resource)
            .await
            .unwrap()
            .and_then(|r| r.application_id)
            .expect("an active resource with its application");
        assert!(
            self.0
                .delete_application(app_id, test_audit())
                .await
                .unwrap()
        );
    }
}
