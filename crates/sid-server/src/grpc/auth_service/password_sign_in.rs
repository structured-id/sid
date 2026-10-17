// SPDX-License-Identifier: AGPL-3.0-only
//! Password sign-in, run by the shared sign-in engine with this server's
//! storage and its Profile accounts.

use sid_authn::challenge_store::ChallengeStore;
use sid_authn::opaque::OpaqueRouter;
use sid_authn::password_sign_in::{PasswordSignInError, PasswordSignInHost, PendingSignIn};
use sid_core::grpc_error::refuse::storage_failure;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{Credential, Profile, ProfileId};
use sid_plugin::CredentialStore;
use sid_plugin::crypto::StoredCredential;
use tonic::Status;

use super::AuthServiceImpl;
use super::refusal::{authentication_failed, ceremony_expired};

/// A sign-in refusal or failure as this server answers it.
pub(super) struct SignInStatus(pub(super) Status);

impl From<Status> for SignInStatus {
    fn from(status: Status) -> Self {
        Self(status)
    }
}

impl From<PasswordSignInError> for SignInStatus {
    fn from(e: PasswordSignInError) -> Self {
        Self(match e {
            PasswordSignInError::AuthenticationFailed => authentication_failed(),
            PasswordSignInError::MigrationRequired => ApiError::new(
                ErrorReason::LegacyMigrationRequired,
                "the password must be migrated before signing in",
            )
            .with_precondition(
                "legacy_migration",
                "credential",
                "complete the password migration flow",
            )
            .into(),
            PasswordSignInError::Expired => ceremony_expired("sign-in"),
            PasswordSignInError::Storage(e) => storage_failure(e),
            PasswordSignInError::State(e) => e.into(),
        })
    }
}

/// One password sign-in request of a local Profile.
pub(super) struct ProfileSignIn<'a> {
    pub(super) service: &'a AuthServiceImpl,
    pub(super) client_ip: Option<std::net::IpAddr>,
}

#[async_trait::async_trait]
impl PasswordSignInHost for ProfileSignIn<'_> {
    type Owner = ProfileId;
    type Account = Profile;
    type Error = SignInStatus;

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        self.service.storage.as_ref()
    }

    fn opaque(&self) -> &OpaqueRouter {
        &self.service.opaque_router
    }

    fn pending(&self) -> &ChallengeStore<PendingSignIn<ProfileId>> {
        &self.service.login_state
    }

    async fn resolve(&self, principal: &str) -> Result<Option<ProfileId>, SignInStatus> {
        Ok(self
            .service
            .resolve_profile_optional(principal)
            .await?
            .map(|p| p.id))
    }

    async fn refuse_if_locked(&self, identity: &str) -> Result<(), SignInStatus> {
        Ok(self.service.refuse_if_locked(identity).await?)
    }

    async fn record_failure(&self, identity: &str) -> Result<(), SignInStatus> {
        Ok(self
            .service
            .record_failed_login(identity, self.client_ip)
            .await?)
    }

    async fn stored_password(
        &self,
        credential: &Credential<ProfileId>,
    ) -> Result<StoredCredential, SignInStatus> {
        Ok(self.service.stored_password(credential).await?)
    }

    fn opaque_credential_identifier(&self, credential: &Credential<ProfileId>) -> [u8; 16] {
        credential.opaque_credential_identifier()
    }

    async fn account(&self, owner: &ProfileId) -> Result<Option<Profile>, SignInStatus> {
        self.service
            .storage
            .get_profile(*owner)
            .await
            .map_err(|e| SignInStatus(storage_failure(e)))
    }
}
