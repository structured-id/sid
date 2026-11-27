// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's public UI settings: the effective choices a sign-in or
//! registration page follows before anyone signs in, kept in memory as one
//! projection. A request is answered from that projection and reads no store.
//!
//! The projection follows the stored enrollment policy by its revision: the
//! process that commits a change reads it at once ([`PublicSettings::refresh`]),
//! and every other process over the same store learns it from its periodic
//! read ([`PublicSettings::follow`]). What the host itself decides (whether it
//! takes registrations at all, whether it mails password resets) it states
//! with [`PublicSettings::serve`].

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
    /// Whether the host takes self-registrations at all: its own switch,
    /// which the registration API refuses under whatever the policy says.
    pub registration: bool,
    /// Whether self-service password reset is composed in: without a way to
    /// deliver the reset message the engine refuses the request.
    pub password_reset: bool,
}

/// The principal types the engine signs in with, and starts an account from
/// where the mode leaves the choice to the registrant.
fn principal_types() -> Vec<i32> {
    vec![
        PrincipalType::Email as i32,
        PrincipalType::Phone as i32,
        PrincipalType::Username as i32,
    ]
}

/// The principal types a self-registration may use under `mode`: any where a
/// visitor or an invited registrant chooses; the email alone where the mode
/// admits by the email's domain, which no other type carries; none where
/// only an administrator creates accounts.
fn registration_types(mode: EnrollmentMode) -> Vec<i32> {
    match mode {
        EnrollmentMode::Open | EnrollmentMode::InviteOnly => principal_types(),
        EnrollmentMode::DomainRestricted => vec![PrincipalType::Email as i32],
        EnrollmentMode::AdminOnly => Vec::new(),
    }
}

/// Whether an unauthenticated visitor may start a registration under `mode`:
/// an invitation and an administrator's own creation have their own entries.
const fn open_to_visitors(mode: EnrollmentMode) -> bool {
    matches!(
        mode,
        EnrollmentMode::Open | EnrollmentMode::DomainRestricted
    )
}

/// The projection, at `revision`, of `policy` in a composition that serves
/// `served`.
pub fn projection(policy: &EnrollmentPolicy, revision: u64, served: Served) -> PublicUiSettings {
    // A host that takes no self-registration admits none under any mode: a
    // new account registering with an invitation is a self-registration
    // too, refused at its start and at its commit.
    let registration = if served.registration {
        registration_types(policy.mode)
    } else {
        Vec::new()
    };
    let usernames = registration.contains(&(PrincipalType::Username as i32));
    PublicUiSettings {
        revision,
        registration_username_min_length: if usernames {
            u32::try_from(sid_authn::normalize::USERNAME_MIN_LENGTH)
                .expect("the username minimum is a small constant")
        } else {
            0
        },
        registration_principal_types: registration,
        sign_in_principal_types: principal_types(),
        registration_open: served.registration && open_to_visitors(policy.mode),
        sign_in_methods: crate::sign_in::LOCAL_SIGN_IN_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect(),
        password_reset_open: served.password_reset,
    }
}

/// What the projection is made of.
struct Inputs {
    policy: EnrollmentPolicy,
    /// The stored revision `policy` was read at.
    policy_revision: u64,
    served: Served,
    /// How many times this process changed `served`: with the stored
    /// revision it makes the projection's own, which only grows here.
    served_changes: u64,
}

impl Inputs {
    fn projection(&self) -> PublicUiSettings {
        projection(
            &self.policy,
            self.policy_revision + self.served_changes,
            self.served,
        )
    }
}

/// The installation's public UI settings, in memory.
pub struct PublicSettings {
    storage: Arc<dyn StorageBackend>,
    /// Changed only together with the projection published from them
    /// (`send_modify` admits one change at a time), never across an await.
    inputs: watch::Sender<Inputs>,
    current: watch::Sender<PublicUiSettings>,
}

impl std::fmt::Debug for PublicSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicSettings")
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
        let (policy, policy_revision) = stored(storage.as_ref()).await?.ok_or_else(|| {
            sid_core::Error::Storage("the enrollment policy kept changing while it was read".into())
        })?;
        let inputs = Inputs {
            policy,
            policy_revision,
            served,
            served_changes: 0,
        };
        let (current, _) = watch::channel(inputs.projection());
        let (inputs, _) = watch::channel(inputs);
        Ok(Arc::new(Self {
            storage,
            inputs,
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

    /// State what the host serves now. A change is projected at once, at a
    /// newer revision; the same statement again changes nothing.
    pub fn serve(&self, served: Served) {
        self.inputs.send_if_modified(|inputs| {
            let changed = inputs.served != served;
            if changed {
                inputs.served = served;
                inputs.served_changes += 1;
                self.current.send_replace(inputs.projection());
            }
            changed
        });
    }

    /// Read the store and serve its policy when it is newer than the one
    /// served. A read that cannot be made consistent now changes nothing: the
    /// projection served stays, and the next refresh reads again.
    pub async fn refresh(&self) -> sid_core::Result<()> {
        let held = self.inputs.borrow().policy_revision;
        if self.storage.enrollment_policy_revision().await? == held {
            return Ok(());
        }
        if let Some((policy, revision)) = stored(self.storage.as_ref()).await? {
            self.inputs.send_if_modified(|inputs| {
                // Two refreshes may finish out of order: the older read is
                // dropped, never served over the newer.
                let newer = revision > inputs.policy_revision;
                if newer {
                    inputs.policy = policy;
                    inputs.policy_revision = revision;
                    self.current.send_replace(inputs.projection());
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
async fn stored(storage: &dyn StorageBackend) -> sid_core::Result<Option<(EnrollmentPolicy, u64)>> {
    for _ in 0..CONSISTENT_READS {
        let revision = storage.enrollment_policy_revision().await?;
        let policy = storage
            .enrollment_policy()
            .await?
            .unwrap_or_else(|| SecurityPolicy::ce_default().enrollment);
        if storage.enrollment_policy_revision().await? == revision {
            return Ok(Some((policy, revision)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
