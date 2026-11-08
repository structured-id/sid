// SPDX-License-Identifier: AGPL-3.0-only
//! The work a CE installation owes and the maintenance it runs, assembled
//! once from the installation's parts and its host's capabilities: the
//! service host and an embedding application start the same engine.

use std::sync::Arc;
use std::time::Duration;

use sid_authn::account_closure::AccountClosureService;
use sid_authn::backchannel_logout::BackChannelLogoutHandler;
use sid_authn::event_relay::{EventDeliveryHandler, EventFanoutHandler, EventRelayHandler};
use sid_authn::issuer::IssuerRegistry;
use sid_authn::password_operation::{
    EnrollmentHandler, EvaluatorDelivery, HistoryEvaluation, OwnerPurgeHandler,
};
use sid_authn::principal_contest::PrincipalContestHandler;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::session_revocation::SessionRevocationHandler;
use sid_authn::work_runner::WorkHandler;
use sid_core::models::RequiredReceiver;
use sid_plugin::event_bus::EventBus;
use sid_plugin::storage::StorageBackend;

use crate::auth_mail::{CodeMail, MagicLinkMail, ResetMail};
use crate::maintenance::{AuditRetention, CeMaintenance, FirstRun, Job, Maintenance};

/// The authentication mail an installation owes: sign-in codes always, and
/// sign-in and reset links where those are enabled. The host builds them
/// over the services its requests use and its own delivery.
pub struct CeMail {
    pub codes: Arc<CodeMail>,
    pub magic_links: Option<Arc<MagicLinkMail>>,
    pub resets: Option<Arc<ResetMail>>,
}

/// What the CE work is assembled from.
pub struct CeWorkParts {
    pub storage: Arc<dyn StorageBackend>,
    /// The installation's issuers, whose relying parties are owed logouts.
    pub issuers: Arc<IssuerRegistry>,
    /// Where ended sessions' tokens stop, in every process.
    pub revocation: Arc<RevocationCache>,
    /// Where committed facts are announced.
    pub event_bus: Arc<dyn EventBus>,
    /// The receivers every committed fact is owed to, running or not.
    pub required_receivers: Vec<RequiredReceiver>,
    /// The password history evaluator, when it runs in this process;
    /// otherwise its settlements are relayed under `issuer`.
    pub history_evaluation: Option<Arc<HistoryEvaluation>>,
    /// This credential authority, as a relayed settlement names it.
    pub issuer: String,
    pub closures: Arc<AccountClosureService>,
    pub mail: CeMail,
    pub audit_retention: AuditRetention,
    pub migration_deadline_days: i64,
    /// The source the maintenance's alerts name.
    pub source: String,
}

/// The CE work handlers and maintenance, for [`crate::EngineParts`].
pub struct CeWork {
    pub handlers: Vec<Arc<dyn WorkHandler>>,
    pub maintenance: Maintenance,
}

/// Why the CE work could not be assembled.
#[derive(Debug, thiserror::Error)]
pub enum CeWorkError {
    /// The client of the relying parties' logout endpoints.
    #[error("back-channel logout client: {0}")]
    LogoutClient(#[from] sid_plugin::http::HttpClientError),
}

impl CeWork {
    /// Every handler of the work a CE installation owes, and its
    /// maintenance with the purge of ended authentication mail.
    pub fn assemble(parts: CeWorkParts) -> Result<Self, CeWorkError> {
        let CeWorkParts {
            storage,
            issuers,
            revocation,
            event_bus,
            required_receivers,
            history_evaluation,
            issuer,
            closures,
            mail,
            audit_retention,
            migration_deadline_days,
            source,
        } = parts;
        let evaluator = match history_evaluation.clone() {
            Some(evaluation) => EvaluatorDelivery::InProcess(evaluation),
            None => EvaluatorDelivery::Relay { source: issuer },
        };
        let mut handlers: Vec<Arc<dyn WorkHandler>> = vec![
            Arc::new(BackChannelLogoutHandler::new(issuers, storage.clone())?),
            Arc::new(EventRelayHandler::new(
                storage.clone(),
                required_receivers,
                sid_plugin::OWED_WORK_CAPACITY,
            )),
            Arc::new(EventFanoutHandler::new(
                event_bus.clone(),
                storage.clone(),
                sid_plugin::OWED_WORK_CAPACITY,
            )),
            Arc::new(EventDeliveryHandler::new(event_bus)),
            Arc::new(PrincipalContestHandler::new(storage.clone())),
            Arc::new(SessionRevocationHandler::new(revocation)),
            Arc::new(EnrollmentHandler::new(storage.clone(), evaluator.clone())),
            Arc::new(OwnerPurgeHandler::new(storage.clone(), evaluator)),
            mail.codes,
        ];
        if let Some(links) = mail.magic_links {
            handlers.push(links);
        }
        if let Some(resets) = mail.resets {
            handlers.push(resets);
        }
        let mail_purge = {
            // Ended authentication mail records. Idempotent, so no job lock.
            let storage = storage.clone();
            Job::shared(
                "authentication_mail_purge",
                Duration::from_secs(3600),
                FirstRun::AfterInterval,
                Arc::new(move || {
                    let storage = storage.clone();
                    Box::pin(async move {
                        match crate::auth_mail::purge_ended_mail(
                            storage.as_ref(),
                            chrono::Utc::now(),
                        )
                        .await
                        {
                            Ok(0) => {}
                            Ok(n) => {
                                tracing::info!("Dropped {n} ended authentication mail records")
                            }
                            Err(e) => tracing::warn!("authentication mail purge failed: {e}"),
                        }
                    })
                }),
            )
        };
        let maintenance = Maintenance::ce(CeMaintenance {
            storage,
            closures,
            history_evaluation,
            audit_retention,
            migration_deadline_days,
            source,
        })
        .with(mail_purge);
        Ok(Self {
            handlers,
            maintenance,
        })
    }
}

#[cfg(test)]
mod tests;
