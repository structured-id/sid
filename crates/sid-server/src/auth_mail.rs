// SPDX-License-Identifier: AGPL-3.0-only
//! This server's transport of the authentication mails the engine owes
//! ([`sid::auth_mail`]): the email provider read from the installation's
//! stored settings at every attempt, so all replicas send alike and a change
//! applies to the next attempt.

use std::sync::Arc;

use async_trait::async_trait;
use sid::auth_mail::{MailTransport, StandardMail};
use sid::email_provider::ProviderError;
use sid_plugin::notification::NotificationChannel;
use sid_plugin::storage::StorageBackend;

use crate::grpc::realm_service::email_channel;

/// The installation's configured email provider.
pub struct StoredProvider {
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn sid_keys::KeyManager>,
}

impl StoredProvider {
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        Self { storage, keys }
    }
}

#[async_trait]
impl MailTransport for StoredProvider {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
        // No provider yet, or one an administrator must correct, leaves the
        // work waiting for it until its secret expires.
        let cfg = sid::email_provider::stored(self.storage.as_ref(), self.keys.as_ref())
            .await
            .map_err(|e: ProviderError| e.to_string())?
            .ok_or("no email provider is configured")?;
        email_channel(&cfg)
    }
}

/// The standard authentication mail over the stored provider.
pub fn stored_mail(
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn sid_keys::KeyManager>,
) -> StandardMail {
    StandardMail::new(Arc::new(StoredProvider::new(storage, keys)))
}
