// SPDX-License-Identifier: AGPL-3.0-only
//! OIDC Back-Channel Logout (OpenID Connect Back-Channel Logout 1.0).
//!
//! Every ended session issued to a client owes that client a `logout_token`
//! POST; the storage commits the owed delivery with the session's deletion,
//! and this handler performs one attempt of it for the durable work runner,
//! which retries it (1 s, 2 s, 4 s, 8 s, 16 s) and records it failed after
//! the last attempt: the durable dead-letter record.

use crate::issuer::IssuerRegistry;
use crate::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, LOGOUT_DELIVERY_KIND, LogoutDelivery, NewWork, ProfileId, WorkKind,
};
use sid_plugin::StorageBackend;
use std::sync::Arc;
use std::time::Duration;

/// How long one delivery waits for the RP before it counts as unknown.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Delays between attempts: exponential from 1 s, five retries.
pub const LOGOUT_RETRY: RetrySchedule = RetrySchedule::new(&[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
]);

/// Delivers owed back-channel logouts.
pub struct BackChannelLogoutHandler {
    kind: WorkKind,
    issuers: Arc<IssuerRegistry>,
    storage: Arc<dyn StorageBackend>,
    http: reqwest::Client,
}

impl BackChannelLogoutHandler {
    /// A handler issuing each logout token as the client's issuer, naming the
    /// subject as the client's ID tokens did.
    pub fn new(issuers: Arc<IssuerRegistry>, storage: Arc<dyn StorageBackend>) -> Self {
        let http = sid_plugin::client_builder()
            .timeout(DELIVERY_TIMEOUT)
            .build()
            .expect("HTTP client creation should not fail");
        Self {
            kind: WorkKind::new(LOGOUT_DELIVERY_KIND).expect("the logout kind is valid"),
            issuers,
            storage,
            http,
        }
    }
}

#[async_trait]
impl WorkHandler for BackChannelLogoutHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        LOGOUT_RETRY
    }

    /// The failed work is the durable dead-letter record; an administrator
    /// alert event is not raised here.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let delivery: LogoutDelivery = match serde_json::from_slice(&work.payload) {
            Ok(delivery) => delivery,
            Err(e) => return WorkOutcome::Permanent(format!("malformed logout delivery: {e}")),
        };
        let client = match self.storage.get_oauth2_client(&delivery.client_id).await {
            Ok(Some(client)) => client,
            // A removed client holds no session to end.
            Ok(None) => return WorkOutcome::Done(Some("client removed".into())),
            Err(e) => return WorkOutcome::Retry(format!("client lookup: {e}")),
        };
        let Some(logout_uri) = client.backchannel_logout_uri.as_deref() else {
            return WorkOutcome::Done(Some("no back-channel logout endpoint".into()));
        };
        let profile_id = match ProfileId::parse(&delivery.profile_id) {
            Ok(id) => id,
            Err(e) => return WorkOutcome::Permanent(format!("bad profile id: {e}")),
        };
        // Signed by the issuer the client's tokens came from, whose keys the
        // RP trusts.
        let issuer = match client.org_id {
            Some(org) => match self.issuers.of_org(org).await {
                Ok(Some(issuer)) => issuer,
                Ok(None) => return WorkOutcome::Done(Some("client has no issuer".into())),
                Err(e) => return WorkOutcome::Retry(format!("issuer lookup: {e}")),
            },
            None => return WorkOutcome::Done(Some("client has no issuer".into())),
        };
        // The subject is the one this client's ID tokens carried, under the
        // rule of the same hop.
        let rule = match crate::subject::SubjectRule::for_hop(&issuer, &client) {
            Ok(rule) => rule,
            Err(e) => return WorkOutcome::Permanent(format!("subject rule: {e}")),
        };
        let sub =
            match crate::subject::known_subject(self.storage.as_ref(), profile_id, &client, rule)
                .await
            {
                Ok(Some(sub)) => sub,
                // No binding: the client never received a token for this profile.
                Ok(None) => return WorkOutcome::Done(Some("client never saw this profile".into())),
                Err(e) => return WorkOutcome::Retry(format!("subject lookup: {e}")),
            };
        let signer = match self.issuers.signer(&issuer).await {
            Ok(signer) => signer,
            Err(e) => return WorkOutcome::Retry(format!("issuer signing key: {e}")),
        };
        let token = match crate::jwt::logout_token_signed_by(
            signer.as_ref(),
            &sub,
            &client.client_id,
            Some(&delivery.session_id),
        ) {
            Ok(token) => token,
            Err(e) => return WorkOutcome::Retry(format!("logout token: {e}")),
        };
        match self
            .http
            .post(logout_uri)
            .form(&[("logout_token", token.as_str())])
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                WorkOutcome::Done(Some(format!("HTTP {}", resp.status().as_u16())))
            }
            Ok(resp) => WorkOutcome::Retry(format!("RP answered HTTP {}", resp.status().as_u16())),
            // The request may have reached the RP; a repeated logout of an
            // ended session is harmless to it.
            Err(e) if e.is_timeout() => WorkOutcome::Ambiguous(format!("RP timed out: {e}")),
            Err(e) => WorkOutcome::Retry(format!("RP unreachable: {e}")),
        }
    }
}

#[cfg(test)]
mod tests;
