// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's public UI settings: the effective choices a sign-in or
//! registration page follows before anyone signs in, kept in memory as one
//! projection. A request is answered from that projection and reads no store.
//!
//! The projection follows the stored enrollment policy by its revision: the
//! process that commits a change reads it at once ([`PublicSettings::refresh`]),
//! and every other process over the same store learns it from its periodic
//! read ([`PublicSettings::follow`]).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sid_core::models::{EnrollmentMode, EnrollmentPolicy, SecurityPolicy};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::identity::PrincipalType;
use sid_proto::sid::v1::ui::PublicUiSettings;
use tokio::sync::watch;

/// How often a process reads the stored revision by default: the longest a
/// change committed elsewhere stays unseen here.
pub const DEFAULT_FOLLOW_INTERVAL: Duration = Duration::from_secs(15);

/// How many times a refresh reads the policy again when the revision moved
/// under it, before it leaves the rest to the next refresh.
const CONSISTENT_READS: usize = 3;

/// What this composition of the engine serves, beyond what the store holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Served {
    /// Whether self-service password reset is composed in: without a way to
    /// deliver the reset message the engine refuses the request.
    pub password_reset: bool,
}

/// The principal types the engine starts an account from and signs in with.
fn principal_types() -> Vec<i32> {
    vec![
        PrincipalType::Email as i32,
        PrincipalType::Phone as i32,
        PrincipalType::Username as i32,
    ]
}

/// Whether an unauthenticated visitor may start a registration under `mode`:
/// an invitation and an administrator's own creation have their own entries.
const fn open_to_visitors(mode: EnrollmentMode) -> bool {
    matches!(
        mode,
        EnrollmentMode::Open | EnrollmentMode::DomainRestricted
    )
}

/// The projection of `policy`, stored at `revision`, in a composition that
/// serves `served`.
pub fn projection(policy: &EnrollmentPolicy, revision: u64, served: Served) -> PublicUiSettings {
    PublicUiSettings {
        revision,
        registration_principal_types: principal_types(),
        registration_username_min_length: u32::try_from(sid_authn::normalize::USERNAME_MIN_LENGTH)
            .expect("the username minimum is a small constant"),
        sign_in_principal_types: principal_types(),
        registration_open: open_to_visitors(policy.mode),
        sign_in_methods: crate::sign_in::LOCAL_SIGN_IN_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect(),
        password_reset_open: served.password_reset,
    }
}

/// The installation's public UI settings, in memory.
pub struct PublicSettings {
    storage: Arc<dyn StorageBackend>,
    served: Served,
    current: watch::Sender<PublicUiSettings>,
}

impl std::fmt::Debug for PublicSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicSettings")
            .field("served", &self.served)
            .field("revision", &self.current.borrow().revision)
            .finish_non_exhaustive()
    }
}

impl PublicSettings {
    /// The settings as the store holds them now. A store that cannot be read
    /// gives no settings: nothing is projected from a default instead.
    pub async fn open(
        storage: Arc<dyn StorageBackend>,
        served: Served,
    ) -> sid_core::Result<Arc<Self>> {
        let first = stored(storage.as_ref(), served).await?.ok_or_else(|| {
            sid_core::Error::Storage("the enrollment policy kept changing while it was read".into())
        })?;
        let (current, _) = watch::channel(first);
        Ok(Arc::new(Self {
            storage,
            served,
            current,
        }))
    }

    /// The current projection, from memory.
    pub fn current(&self) -> PublicUiSettings {
        self.current.borrow().clone()
    }

    /// The current projection and each newer one: a reader that falls behind
    /// sees the latest only.
    pub fn subscribe(&self) -> watch::Receiver<PublicUiSettings> {
        self.current.subscribe()
    }

    /// Read the store and serve its policy when it is newer than the one
    /// served. A read that cannot be made consistent now changes nothing: the
    /// projection served stays, and the next refresh reads again.
    pub async fn refresh(&self) -> sid_core::Result<()> {
        if self.storage.enrollment_policy_revision().await? == self.current.borrow().revision {
            return Ok(());
        }
        if let Some(read) = stored(self.storage.as_ref(), self.served).await? {
            self.current.send_if_modified(|served| {
                // Two refreshes may finish out of order: the older one is
                // dropped, never served over the newer.
                let newer = read.revision > served.revision;
                if newer {
                    *served = read;
                }
                newer
            });
        }
        Ok(())
    }

    /// Refresh every `every` until `stop` completes, so a change committed by
    /// another process over the same store is served here too. A failed read
    /// keeps the projection served and is tried again at the next turn.
    pub async fn follow(&self, every: Duration, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        let mut turns = tokio::time::interval(every);
        turns.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = &mut stop => return,
                _ = turns.tick() => {
                    if let Err(e) = self.refresh().await {
                        tracing::warn!("public UI settings not refreshed: {e}");
                    }
                }
            }
        }
    }
}

/// [`PublicSettings::follow`] for a host without a stop signal of its own:
/// refreshes `settings` every `every` for as long as anything else holds
/// them, and ends once the last holder dropped them.
pub async fn follow_while_held(settings: std::sync::Weak<PublicSettings>, every: Duration) {
    let mut turns = tokio::time::interval(every);
    turns.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        turns.tick().await;
        let Some(held) = settings.upgrade() else {
            return;
        };
        if let Err(e) = held.refresh().await {
            tracing::warn!("public UI settings not refreshed: {e}");
        }
    }
}

/// The stored policy with the revision it was stored at: read again when a
/// change lands between the two reads. `None` when it kept changing.
async fn stored(
    storage: &dyn StorageBackend,
    served: Served,
) -> sid_core::Result<Option<PublicUiSettings>> {
    for _ in 0..CONSISTENT_READS {
        let revision = storage.enrollment_policy_revision().await?;
        let policy = storage
            .enrollment_policy()
            .await?
            .unwrap_or_else(|| SecurityPolicy::ce_default().enrollment);
        if storage.enrollment_policy_revision().await? == revision {
            return Ok(Some(projection(&policy, revision, served)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
