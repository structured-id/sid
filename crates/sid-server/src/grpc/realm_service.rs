// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC RealmService implementation.
//!
//! Implements instance-level admin settings: email provider config, realm
//! settings, login/session/token config, localization, import/export.
//!
//! The email provider (PLAIN/LOGIN and XOAUTH2 for Microsoft 365 / Google
//! Workspace) is configured through [`sid::email_provider`] and tested here
//! over the delivery channel; the other settings are not part of this build
//! and answer FEATURE_NOT_AVAILABLE.

use secrecy::ExposeSecret;
use sid::email_provider::{EmailProvider, EmailProviderError};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{EmailProviderConfig, SmtpAuthMethod, SmtpEncryption};
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, not_configured, not_in_this_build,
    storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_notify::channels::{
    EmailAuthMethod, SmtpChannel, SmtpConfig, SmtpTlsMode, channel_from_email_config,
};
use sid_plugin::notification::NotificationChannel;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::{EmailSettings, realm_service_server::RealmService};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

pub struct RealmServiceImpl {
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    email: EmailProvider,
}

/// The status an email provider refusal answers with.
fn refusal(e: EmailProviderError) -> Status {
    match e {
        EmailProviderError::Caller(e) => e.into_status(),
        EmailProviderError::Operation(e) => e.into_status(),
        EmailProviderError::Store(e) => storage_failure(e),
        EmailProviderError::Internal => ApiError::internal().into(),
        EmailProviderError::InvalidField { field, reason } => invalid_field(field, reason),
        EmailProviderError::NotConfigured => not_configured("email"),
    }
}

impl RealmServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            email: EmailProvider::new(storage, keys),
        }
    }

    async fn caller<T>(&self, req: &Request<T>) -> Result<Caller, Status> {
        authenticate(req, self.jwt.verifier(), &self.revocation).await
    }
}

/// The channel mail goes out on under `cfg`: XOAUTH2 when configured, plain
/// SMTP otherwise. An error names what an administrator must correct.
pub(crate) fn email_channel(
    cfg: &EmailProviderConfig,
) -> Result<Arc<dyn NotificationChannel>, String> {
    if cfg.auth_type == SmtpAuthMethod::XOAuth2 {
        let channel = channel_from_email_config(cfg)
            .map_err(|e| format!("XOAUTH2 HTTP client: {e}"))?
            .ok_or("the XOAUTH2 configuration is incomplete")?;
        Ok(Arc::new(channel))
    } else {
        Ok(Arc::new(
            SmtpChannel::new(config_to_smtp_config(cfg))
                .map_err(|e| format!("the SMTP configuration is invalid: {e}"))?,
        ))
    }
}

/// INVALID_STATE: the stored email provider configuration cannot be used
/// until an administrator corrects it.
fn unusable_provider(why: &'static str) -> Status {
    ApiError::new(ErrorReason::InvalidState, why)
        .with_precondition("EMAIL_PROVIDER", "email_provider_config", why)
        .into()
}

/// Map domain `EmailProviderConfig` to `SmtpConfig` for PLAIN/LOGIN connection testing.
///
/// Only called when `auth_type` is `None` or `UsernamePassword`.
/// XOAUTH2 uses `channel_from_email_config` instead.
fn config_to_smtp_config(cfg: &EmailProviderConfig) -> SmtpConfig {
    SmtpConfig {
        host: cfg.smtp_host.clone(),
        port: cfg.smtp_port,
        tls_mode: match cfg.encryption {
            SmtpEncryption::SslTls => SmtpTlsMode::Tls,
            SmtpEncryption::Starttls => SmtpTlsMode::StartTls,
            SmtpEncryption::None => SmtpTlsMode::None,
        },
        auth_method: match cfg.auth_type {
            SmtpAuthMethod::UsernamePassword => EmailAuthMethod::Plain,
            _ => EmailAuthMethod::None,
        },
        username: if cfg.username.is_empty() {
            None
        } else {
            Some(cfg.username.clone())
        },
        password: if cfg.password.expose_secret().is_empty() {
            None
        } else {
            Some(cfg.password.expose_secret().clone())
        },
        from_address: cfg.from_address.clone(),
        from_name: cfg.from_display_name.clone(),
        ..SmtpConfig::default()
    }
}

// ── gRPC handler implementation ───────────────────────────────────────────────

#[tonic::async_trait]
impl RealmService for RealmServiceImpl {
    // ── Email settings ───────────────────────────────────

    #[instrument(skip(self, request), fields(rpc = "GetEmailSettings"))]
    async fn get_email_settings(
        &self,
        request: Request<()>,
    ) -> Result<Response<EmailSettings>, Status> {
        let caller = self.caller(&request).await?;
        self.email
            .settings(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, request), fields(rpc = "UpdateEmailSettings"))]
    async fn update_email_settings(
        &self,
        request: Request<EmailSettings>,
    ) -> Result<Response<EmailSettings>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        self.email
            .update(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, request), fields(rpc = "TestEmailConnection"))]
    async fn test_email_connection(&self, request: Request<()>) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let cfg = self.email.configured(&caller).await.map_err(refusal)?;

        // The XOAUTH2 channel when configured, plain SMTP otherwise.
        let health = if cfg.auth_type == SmtpAuthMethod::XOAuth2 {
            channel_from_email_config(&cfg)
                .map_err(|e| internal("initialize XOAUTH2 HTTP client", e))?
                .ok_or_else(|| unusable_provider("the XOAUTH2 configuration is incomplete"))?
                .health()
                .await
        } else {
            SmtpChannel::new(config_to_smtp_config(&cfg))
                .map_err(|e| {
                    warn!(error = %e, "SMTP config invalid for connection test");
                    unusable_provider("the SMTP configuration is invalid")
                })?
                .health()
                .await
        };

        // The provider's own text stays in the log: it names hosts and
        // accounts the response does not need to carry.
        match health {
            Ok(h) if h.healthy => {
                info!(host = %cfg.smtp_host, auth = ?cfg.auth_type, "SMTP connection test succeeded");
                Ok(Response::new(()))
            }
            Ok(h) => Err(dependency_unavailable(
                "email provider",
                h.message.unwrap_or_default(),
            )),
            Err(e) => Err(dependency_unavailable("email provider", e)),
        }
    }

    // ── Settings this build does not implement ───────────────────────────────

    async fn get_realm(
        &self,
        _request: Request<sid_proto::sid::v1::admin::GetRealmRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::RealmSettings>, Status> {
        Err(not_in_this_build("realm_settings"))
    }

    async fn update_realm(
        &self,
        _request: Request<sid_proto::sid::v1::admin::UpdateRealmRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::RealmSettings>, Status> {
        Err(not_in_this_build("realm_settings"))
    }

    async fn get_login_settings(
        &self,
        _request: Request<sid_proto::sid::v1::admin::GetLoginSettingsRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::LoginSettings>, Status> {
        Err(not_in_this_build("login_settings"))
    }

    async fn update_login_settings(
        &self,
        _request: Request<sid_proto::sid::v1::admin::UpdateLoginSettingsRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::LoginSettings>, Status> {
        Err(not_in_this_build("login_settings"))
    }

    async fn get_localization_settings(
        &self,
        _request: Request<()>,
    ) -> Result<Response<sid_proto::sid::v1::admin::LocalizationSettings>, Status> {
        Err(not_in_this_build("localization_settings"))
    }

    async fn update_localization_settings(
        &self,
        _request: Request<sid_proto::sid::v1::admin::LocalizationSettings>,
    ) -> Result<Response<sid_proto::sid::v1::admin::LocalizationSettings>, Status> {
        Err(not_in_this_build("localization_settings"))
    }

    async fn list_translation_overrides(
        &self,
        _request: Request<sid_proto::sid::v1::admin::ListTranslationOverridesRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ListTranslationOverridesResponse>, Status> {
        Err(not_in_this_build("translation_overrides"))
    }

    async fn set_translation_override(
        &self,
        _request: Request<sid_proto::sid::v1::admin::SetTranslationOverrideRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::TranslationOverride>, Status> {
        Err(not_in_this_build("translation_overrides"))
    }

    async fn delete_translation_override(
        &self,
        _request: Request<sid_proto::sid::v1::admin::DeleteTranslationOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        Err(not_in_this_build("translation_overrides"))
    }

    async fn export_realm(
        &self,
        _request: Request<sid_proto::sid::v1::admin::ExportRealmRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ExportRealmResponse>, Status> {
        Err(not_in_this_build("realm_import_export"))
    }

    async fn import_realm(
        &self,
        _request: Request<sid_proto::sid::v1::admin::ImportRealmRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ImportRealmResponse>, Status> {
        Err(not_in_this_build("realm_import_export"))
    }

    async fn preview_import(
        &self,
        _request: Request<sid_proto::sid::v1::admin::ImportRealmRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ImportPreviewResponse>, Status> {
        Err(not_in_this_build("realm_import_export"))
    }

    async fn get_session_config(
        &self,
        _request: Request<()>,
    ) -> Result<Response<sid_proto::sid::v1::admin::SessionConfig>, Status> {
        Err(not_in_this_build("session_config"))
    }

    async fn update_session_config(
        &self,
        _request: Request<sid_proto::sid::v1::admin::SessionConfig>,
    ) -> Result<Response<sid_proto::sid::v1::admin::SessionConfig>, Status> {
        Err(not_in_this_build("session_config"))
    }

    async fn get_token_config(
        &self,
        _request: Request<()>,
    ) -> Result<Response<sid_proto::sid::v1::admin::TokenConfig>, Status> {
        Err(not_in_this_build("token_config"))
    }

    async fn update_token_config(
        &self,
        _request: Request<sid_proto::sid::v1::admin::TokenConfig>,
    ) -> Result<Response<sid_proto::sid::v1::admin::TokenConfig>, Status> {
        Err(not_in_this_build("token_config"))
    }
}

#[cfg(test)]
mod tests;
