// SPDX-License-Identifier: AGPL-3.0-only
//! The login settings of the organization this installation serves, as an
//! administrator reads and changes them: which incoming external identities
//! (Personal Profiles, Corporate Profiles issued by other organizations) the
//! organization admits as the recipient of a federated sign-in. The other
//! settings of the login page are not served by this build: they are absent
//! on a read, and a change naming one is refused with nothing changed.

use std::sync::Arc;

use prost::Message;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::{AuditEntry, LoginSettings, MutationContext, OperationContext};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::realm_service as keyed;
use sid_proto::sid::v1::admin::{LoginSettings as LoginSettingsView, UpdateLoginSettingsRequest};

/// How many times a change is decided again when another change lands
/// between its read and its write. Each retry follows a write that landed,
/// so changes always make progress.
const WRITE_ATTEMPTS: usize = 8;

/// Why a login settings operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum LoginSettingsError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// The change names a setting this build does not serve.
    #[error("{0} is not served by this build")]
    NotServed(&'static str),
    /// Other changes kept landing between this one's read and its write.
    #[error("the login settings kept changing")]
    Contended,
}

impl From<LoginSettingsError> for Effect<LoginSettingsError> {
    fn from(e: LoginSettingsError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<LoginSettingsError>> for LoginSettingsError {
    fn from(e: CommandError<LoginSettingsError>) -> Self {
        e.refusal()
    }
}

/// The settings as an administrator reads them: the two admissions, and no
/// value for a setting this build does not serve.
fn view(settings: LoginSettings) -> LoginSettingsView {
    LoginSettingsView {
        allow_personal_profiles: settings.allow_personal_profiles,
        allow_foreign_corporate_profiles: settings.allow_foreign_corporate_profiles,
        ..LoginSettingsView::default()
    }
}

/// The first setting `req` names that this build does not serve.
fn unserved(req: &UpdateLoginSettingsRequest) -> Option<&'static str> {
    [
        ("self_registration", req.self_registration.is_some()),
        ("forgot_password", req.forgot_password.is_some()),
        ("remember_me", req.remember_me.is_some()),
        ("verify_email", req.verify_email.is_some()),
        ("login_with_email", req.login_with_email.is_some()),
        ("identity_first_login", req.identity_first_login.is_some()),
        ("default_roles", !req.default_roles.is_empty()),
        ("default_groups", !req.default_groups.is_empty()),
        ("required_actions", !req.required_actions.is_empty()),
    ]
    .into_iter()
    .find_map(|(name, named)| named.then_some(name))
}

/// The installation's login settings in force: the stored ones, else the
/// defaults (nothing admitted). The recipient's sign-in decision reads them
/// here.
pub async fn in_force(storage: &dyn StorageBackend) -> Result<LoginSettings, SidError> {
    Ok(storage.login_settings().await?.unwrap_or_default())
}

/// The login settings of one installation.
pub struct LoginSettingsAdmin {
    storage: Arc<dyn StorageBackend>,
}

impl LoginSettingsAdmin {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// The settings in force, for an administrator.
    pub async fn settings(&self, caller: &Caller) -> Result<LoginSettingsView, LoginSettingsError> {
        caller.require_admin()?;
        Ok(view(in_force(self.storage.as_ref()).await?))
    }

    /// Change the settings `req` names and keep the others as stored. A
    /// change of one admission never overwrites a concurrent change of the
    /// other: it is written against the settings it read, and decided again
    /// when those changed. A retry of a completed change answers with the
    /// settings that change left and never writes them over a later change.
    pub async fn update(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateLoginSettingsRequest,
    ) -> Result<LoginSettingsView, LoginSettingsError> {
        caller.require_admin()?;
        if let Some(setting) = unserved(&req) {
            return Err(LoginSettingsError::NotServed(setting));
        }
        let command = KeyedCommand::by_profile::<keyed::UpdateLoginSettings>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                for _ in 0..WRITE_ATTEMPTS {
                    let stored = self.storage.login_settings().await?;
                    let held = stored.unwrap_or_default();
                    let changed = LoginSettings {
                        allow_personal_profiles: req
                            .allow_personal_profiles
                            .unwrap_or(held.allow_personal_profiles),
                        allow_foreign_corporate_profiles: req
                            .allow_foreign_corporate_profiles
                            .unwrap_or(held.allow_foreign_corporate_profiles),
                    };
                    let response = view(changed);
                    let audit = MutationContext::from(AuditEntry::admin(
                        caller.profile_id.to_string(),
                        "login_settings.update",
                        "login_settings",
                    ))
                    .with_operation(command.completion(response.encode_to_vec()));
                    if self
                        .storage
                        .set_login_settings(&changed, stored.as_ref(), audit)
                        .await?
                    {
                        tracing::info!(
                            allow_personal_profiles = changed.allow_personal_profiles,
                            allow_foreign_corporate_profiles =
                                changed.allow_foreign_corporate_profiles,
                            "login settings updated"
                        );
                        return Ok(response);
                    }
                }
                Err(LoginSettingsError::Contended.into())
            })
            .await
            .map_err(CommandError::<LoginSettingsError>::refusal)
    }
}
