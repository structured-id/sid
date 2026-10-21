// SPDX-License-Identifier: AGPL-3.0-only
//! Password sign-in, run by the shared sign-in engine with this server's
//! storage and its Profile accounts.

use sid_authn::challenge_store::ChallengeStore;
use sid_authn::opaque::OpaqueRouter;
use sid_authn::password_sign_in::{
    OpenedPassword, PasswordSignInError, PasswordSignInHost, PendingSignIn,
};
use sid_core::grpc_error::refuse::storage_failure;
use sid_core::models::{Credential, Profile, ProfileId};
use sid_plugin::CredentialStore;
use tonic::Status;

use super::AuthServiceImpl;

/// A sign-in refusal or failure as this server answers it.
pub(super) struct SignInStatus(pub(super) Status);

impl From<Status> for SignInStatus {
    fn from(status: Status) -> Self {
        Self(status)
    }
}

impl From<PasswordSignInError> for SignInStatus {
    fn from(e: PasswordSignInError) -> Self {
        Self(e.into())
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

    /// CE counts the attempt for the lockout; it keeps no per-account
    /// activity, so the account is not needed here.
    async fn record_failure(
        &self,
        identity: &str,
        _owner: Option<&ProfileId>,
    ) -> Result<(), SignInStatus> {
        Ok(self
            .service
            .record_failed_login(identity, self.client_ip)
            .await?)
    }

    async fn stored_password(
        &self,
        credential: &Credential<ProfileId>,
    ) -> Result<OpenedPassword, SignInStatus> {
        let (record, stored) = self.service.stored_password(credential).await?;
        Ok(OpenedPassword { record, stored })
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
