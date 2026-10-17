// SPDX-License-Identifier: AGPL-3.0-only
//! The issuer store conformance harness of this crate's backends: issuers
//! serve the installation organization, so each scenario runs on a backend
//! of its own (an isolated schema or a fresh database).

use async_trait::async_trait;
use sid_core::models::{
    AuditEntry, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, OidcIssuer, OrgId,
};
use sid_plugin::conformance::issuer_store::IssuerHarness;
use sid_plugin::{IssuerStore, StorageBackend};

use super::instance_org;

pub struct InstanceIssuers<'a>(pub &'a dyn StorageBackend);

#[async_trait]
impl IssuerHarness for InstanceIssuers<'_> {
    type Recipient = OrgId;

    fn store(&self) -> &dyn IssuerStore {
        self.0
    }

    async fn recipient(&self) -> OrgId {
        instance_org(self.0).await
    }
}

/// These stores issue for organizations they hold: an issuer of an
/// organization the store does not know is refused, nothing stored.
pub async fn unknown_organization_refused(store: &dyn StorageBackend) {
    let id = IssuerId::generate();
    let handle = IssuerHandle::generate();
    let now = chrono::Utc::now();
    let unknown = OidcIssuer {
        id,
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient: OrgId::generate(),
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: id,
        generation: 1,
        key_id: format!("kid-{id}"),
        public_key: [9; 32],
        sealed_private_key: vec![1, 2, 3, 4],
        created_at: now,
    };
    assert!(
        store
            .insert_oidc_issuer(
                &unknown,
                &key,
                AuditEntry::system("conformance", "issuer_store").into()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .oidc_issuer_by_handle(&unknown.handle)
            .await
            .unwrap()
            .is_none()
    );
}
