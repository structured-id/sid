// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AccountService implementation (CE): authenticates the caller and
//! answers through [`sid::account`] (consents, phones, emails). Activity
//! history, linked accounts, the app launcher, notification preferences and
//! passwordless are not part of this build.

use sid::account::{Account, AccountError};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    invalid_field, missing_field, not_found, not_in_this_build, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::account::account_service_server::AccountService;
use sid_proto::sid::v1::account::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The status an account refusal answers with.
fn refusal(e: AccountError) -> Status {
    match e {
        AccountError::Operation(e) => e.into_status(),
        AccountError::Store(e) => storage_failure(e),
        AccountError::Internal => ApiError::internal().into(),
        AccountError::MissingField(field) => missing_field(field),
        AccountError::InvalidField { field, reason } => invalid_field(field, reason),
        AccountError::ConsentNotFound(site_id) => {
            not_found(ErrorReason::ConsentNotFound, "Consent", site_id)
        }
        AccountError::ConsentInactive(site_id) => ApiError::new(
            ErrorReason::InvalidState,
            "an inactive consent takes no claim changes",
        )
        .with_precondition("CONSENT_STATE", site_id, "inactive")
        .into(),
        AccountError::PhoneNotFound(id) => {
            not_found(ErrorReason::PhoneNotFound, "ProfilePhone", id.0.to_string())
        }
        AccountError::EmailNotFound(id) => {
            not_found(ErrorReason::EmailNotFound, "ProfileEmail", id.0.to_string())
        }
    }
}

pub struct AccountServiceImpl {
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    account: Account,
}

impl AccountServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            account: Account::new(storage),
        }
    }

    async fn caller<T>(&self, req: &Request<T>) -> Result<Caller, Status> {
        authenticate(req, self.jwt.verifier(), &self.revocation).await
    }
}

#[tonic::async_trait]
impl AccountService for AccountServiceImpl {
    // ── Consents ──

    async fn list_consents(
        &self,
        request: Request<ListConsentsRequest>,
    ) -> Result<Response<ListConsentsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.account
            .list_consents(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn get_consent_detail(
        &self,
        request: Request<GetConsentDetailRequest>,
    ) -> Result<Response<GetConsentDetailResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.account
            .consent_detail(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn update_claim_consent(
        &self,
        request: Request<UpdateClaimConsentRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .update_claim_consent(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn disconnect_site(
        &self,
        request: Request<DisconnectSiteRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .disconnect_site(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    // ── Phone Management ──

    async fn add_phone(
        &self,
        request: Request<AddPhoneRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfilePhone>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .add_phone(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn remove_phone(
        &self,
        request: Request<RemovePhoneRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .remove_phone(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn update_phone(
        &self,
        request: Request<UpdatePhoneRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfilePhone>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .update_phone(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn set_primary_phone(
        &self,
        request: Request<SetPrimaryPhoneRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfilePhone>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .set_primary_phone(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn list_phones(
        &self,
        request: Request<()>,
    ) -> Result<Response<ListPhonesResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.account
            .list_phones(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    // ── Email Management ──

    async fn add_email(
        &self,
        request: Request<AddEmailRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfileEmail>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .add_email(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn remove_email(
        &self,
        request: Request<RemoveEmailRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .remove_email(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn update_email(
        &self,
        request: Request<UpdateEmailRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfileEmail>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .update_email(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn set_primary_email(
        &self,
        request: Request<SetPrimaryEmailRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfileEmail>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.account
            .set_primary_email(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn list_emails(
        &self,
        request: Request<()>,
    ) -> Result<Response<ListEmailsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.account
            .list_emails(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    // ── Activity History (not in this build) ──

    async fn list_activity_events(
        &self,
        _request: Request<ListActivityEventsRequest>,
    ) -> Result<Response<ListActivityEventsResponse>, Status> {
        Err(not_in_this_build("activity_history"))
    }

    async fn get_activity_event_detail(
        &self,
        _request: Request<GetActivityEventDetailRequest>,
    ) -> Result<Response<ActivityEvent>, Status> {
        Err(not_in_this_build("activity_history"))
    }

    async fn report_suspicious_event(
        &self,
        _request: Request<ReportSuspiciousEventRequest>,
    ) -> Result<Response<()>, Status> {
        Err(not_in_this_build("activity_history"))
    }

    // ── Linked Accounts (not in this build) ──

    async fn list_linked_accounts(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ListLinkedAccountsResponse>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    async fn link_account(
        &self,
        _request: Request<LinkAccountRequest>,
    ) -> Result<Response<LinkAccountResponse>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    async fn unlink_account(
        &self,
        _request: Request<UnlinkAccountRequest>,
    ) -> Result<Response<()>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    async fn reauthenticate_link(
        &self,
        _request: Request<ReauthenticateLinkRequest>,
    ) -> Result<Response<ReauthenticateLinkResponse>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    // ── App Launcher (not in this build) ──

    async fn list_available_apps(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ListAvailableAppsResponse>, Status> {
        Err(not_in_this_build("app_launcher"))
    }

    async fn launch_app(
        &self,
        _request: Request<LaunchAppRequest>,
    ) -> Result<Response<LaunchAppResponse>, Status> {
        Err(not_in_this_build("app_launcher"))
    }

    // ── Notification Preferences (not in this build) ──

    async fn get_notification_preferences(
        &self,
        _request: Request<()>,
    ) -> Result<Response<NotificationPreferences>, Status> {
        Err(not_in_this_build("notification_preferences"))
    }

    async fn update_notification_preferences(
        &self,
        _request: Request<UpdateNotificationPreferencesRequest>,
    ) -> Result<Response<NotificationPreferences>, Status> {
        Err(not_in_this_build("notification_preferences"))
    }

    // ── Passwordless (not in this build) ──

    async fn get_passwordless_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<PasswordlessStatus>, Status> {
        Err(not_in_this_build("passwordless"))
    }

    async fn enable_passwordless(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        Err(not_in_this_build("passwordless"))
    }

    async fn disable_passwordless(
        &self,
        _request: Request<()>,
    ) -> Result<Response<DisablePasswordlessResponse>, Status> {
        Err(not_in_this_build("passwordless"))
    }
}

#[cfg(test)]
mod tests;
