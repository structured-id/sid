// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC RealmService implementation.
//!
//! Implements instance-level admin settings: email provider config, realm
//! settings, login/session/token config, localization, import/export.
//!
//! The email provider (PLAIN/LOGIN and XOAUTH2 for Microsoft 365 / Google
//! Workspace) is configured and tested here; the other settings are not part
//! of this build and answer FEATURE_NOT_AVAILABLE.

use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretBox};
use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, not_configured, not_in_this_build,
    storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{
    AuditEntry, EmailProviderConfig, MutationContext, SmtpAuthMethod, SmtpEncryption,
    XOAuth2Config, XOAuth2Provider,
};
use sid_notify::channels::{
    EmailAuthMethod, SmtpChannel, SmtpConfig, SmtpTlsMode, channel_from_email_config,
};
use sid_plugin::notification::NotificationChannel;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::{
    EmailSettings, SmtpAuthType, SmtpEncryptionType, XoAuth2ProviderType,
    realm_service_server::RealmService,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

pub struct RealmServiceImpl {
    pub(crate) storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// Seals the provider's credentials before they are stored.
    keys: Arc<dyn sid_keys::KeyManager>,
}

/// Sealing contexts of the stored email provider credentials: a value sealed
/// for one field is never accepted as another.
pub const SMTP_PASSWORD_CONTEXT: &str = "email_provider:smtp_password";
pub const XOAUTH2_CLIENT_SECRET_CONTEXT: &str = "email_provider:xoauth2_client_secret";
pub const XOAUTH2_SERVICE_ACCOUNT_KEY_CONTEXT: &str = "email_provider:xoauth2_service_account_key";

impl RealmServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
            keys,
        }
    }

    /// `secret` sealed for `context`, as the text the store keeps. An empty
    /// value (no credential) stays empty.
    async fn seal(
        &self,
        context: &str,
        secret: &SecretBox<String>,
    ) -> Result<SecretBox<String>, Status> {
        if secret.expose_secret().is_empty() {
            return Ok(SecretBox::new(Box::new(String::new())));
        }
        let sealed = sid_authn::sealed_secret::seal(
            self.keys.as_ref(),
            context,
            secret.expose_secret().as_bytes(),
        )
        .await
        .map_err(|e| internal("seal email provider credential", e))?;
        Ok(SecretBox::new(Box::new(STANDARD.encode(sealed))))
    }

    /// The credential a stored value holds. A value that is not sealed for
    /// `context` is refused rather than used as the credential.
    async fn open(
        &self,
        context: &str,
        stored: &SecretBox<String>,
    ) -> Result<SecretBox<String>, Status> {
        if stored.expose_secret().is_empty() {
            return Ok(SecretBox::new(Box::new(String::new())));
        }
        let refused =
            |e: &dyn std::fmt::Display| internal("open stored email provider credential", e);
        let bytes = STANDARD
            .decode(stored.expose_secret())
            .map_err(|e| refused(&e))?;
        let opened = sid_authn::sealed_secret::open(self.keys.as_ref(), context, &bytes)
            .await
            .map_err(|e| refused(&e))?;
        let text = String::from_utf8(opened.secret.to_vec()).map_err(|e| refused(&e))?;
        Ok(SecretBox::new(Box::new(text)))
    }

    /// The stored config with its credentials opened.
    async fn load(&self) -> Result<Option<EmailProviderConfig>, Status> {
        let Some(mut cfg) = self
            .storage
            .get_email_provider_config()
            .await
            .map_err(storage_failure)?
        else {
            return Ok(None);
        };
        cfg.password = self.open(SMTP_PASSWORD_CONTEXT, &cfg.password).await?;
        if let Some(x) = cfg.xoauth2.as_mut() {
            x.client_secret = self
                .open(XOAUTH2_CLIENT_SECRET_CONTEXT, &x.client_secret)
                .await?;
            if let Some(key) = x.service_account_key.as_ref() {
                x.service_account_key =
                    Some(self.open(XOAUTH2_SERVICE_ACCOUNT_KEY_CONTEXT, key).await?);
            }
        }
        Ok(Some(cfg))
    }

    /// `cfg` with its credentials sealed, as it is stored.
    async fn sealed(&self, cfg: &EmailProviderConfig) -> Result<EmailProviderConfig, Status> {
        let mut stored = cfg.clone();
        stored.password = self.seal(SMTP_PASSWORD_CONTEXT, &cfg.password).await?;
        if let (Some(x), Some(plain)) = (stored.xoauth2.as_mut(), cfg.xoauth2.as_ref()) {
            x.client_secret = self
                .seal(XOAUTH2_CLIENT_SECRET_CONTEXT, &plain.client_secret)
                .await?;
            if let Some(key) = plain.service_account_key.as_ref() {
                x.service_account_key =
                    Some(self.seal(XOAUTH2_SERVICE_ACCOUNT_KEY_CONTEXT, key).await?);
            }
        }
        Ok(stored)
    }

    /// Authenticate the caller and require the administrator role; returns the
    /// caller's profile id as the audit actor.
    #[allow(clippy::result_large_err)]
    async fn require_admin<T>(&self, req: &Request<T>) -> Result<String, Status> {
        let caller = authenticate(req, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller.profile_id.to_string())
    }
}

/// INVALID_STATE: the stored email provider configuration cannot be used
/// until an administrator corrects it.
fn unusable_provider(why: &'static str) -> Status {
    ApiError::new(ErrorReason::InvalidState, why)
        .with_precondition("EMAIL_PROVIDER", "email_provider_config", why)
        .into()
}

// ── Proto ↔ domain conversion helpers ────────────────────────────────────────

/// Convert proto `SmtpEncryptionType` to domain `SmtpEncryption`.
fn encryption_from_proto(enc: i32) -> SmtpEncryption {
    match SmtpEncryptionType::try_from(enc).unwrap_or(SmtpEncryptionType::Unspecified) {
        SmtpEncryptionType::SslTls => SmtpEncryption::SslTls,
        SmtpEncryptionType::Starttls => SmtpEncryption::Starttls,
        _ => SmtpEncryption::None,
    }
}

/// Convert domain `SmtpEncryption` to proto `SmtpEncryptionType` i32.
fn encryption_to_proto(enc: SmtpEncryption) -> i32 {
    match enc {
        SmtpEncryption::SslTls => SmtpEncryptionType::SslTls as i32,
        SmtpEncryption::Starttls => SmtpEncryptionType::Starttls as i32,
        SmtpEncryption::None => SmtpEncryptionType::None as i32,
    }
}

/// Convert proto `SmtpAuthType` to domain `SmtpAuthMethod`.
fn auth_from_proto(auth: i32) -> SmtpAuthMethod {
    match SmtpAuthType::try_from(auth).unwrap_or(SmtpAuthType::Unspecified) {
        SmtpAuthType::UsernamePassword => SmtpAuthMethod::UsernamePassword,
        SmtpAuthType::Xoauth2 => SmtpAuthMethod::XOAuth2,
        _ => SmtpAuthMethod::None,
    }
}

/// Convert domain `SmtpAuthMethod` to proto `SmtpAuthType` i32.
fn auth_to_proto(auth: SmtpAuthMethod) -> i32 {
    match auth {
        SmtpAuthMethod::UsernamePassword => SmtpAuthType::UsernamePassword as i32,
        SmtpAuthMethod::XOAuth2 => SmtpAuthType::Xoauth2 as i32,
        SmtpAuthMethod::None => SmtpAuthType::None as i32,
    }
}

/// Convert proto `XoAuth2ProviderType` to domain `XOAuth2Provider`.
/// Returns `None` for `Unspecified` (no XOAUTH2 provider set).
fn xoauth2_provider_from_proto(v: i32) -> Option<XOAuth2Provider> {
    match XoAuth2ProviderType::try_from(v)
        .unwrap_or(XoAuth2ProviderType::Xoauth2ProviderTypeUnspecified)
    {
        XoAuth2ProviderType::Xoauth2ProviderTypeM365 => Some(XOAuth2Provider::M365),
        XoAuth2ProviderType::Xoauth2ProviderTypeGoogle => Some(XOAuth2Provider::Google),
        XoAuth2ProviderType::Xoauth2ProviderTypeUnspecified => None,
    }
}

/// Convert domain `XOAuth2Provider` to proto `XoAuth2ProviderType` i32.
fn xoauth2_provider_to_proto(p: XOAuth2Provider) -> i32 {
    match p {
        XOAuth2Provider::M365 => XoAuth2ProviderType::Xoauth2ProviderTypeM365 as i32,
        XOAuth2Provider::Google => XoAuth2ProviderType::Xoauth2ProviderTypeGoogle as i32,
    }
}

/// Build `EmailSettings` proto response from domain model.
///
/// Write-only fields are never returned: `password`, `xoauth2_client_secret`,
/// `xoauth2_service_account_key`.
fn config_to_proto(cfg: &EmailProviderConfig) -> EmailSettings {
    let (xoauth2_provider, xoauth2_tenant_id, xoauth2_client_id, xoauth2_token_endpoint) =
        if let Some(ref x) = cfg.xoauth2 {
            (
                xoauth2_provider_to_proto(x.provider),
                x.tenant_id.clone().unwrap_or_default(),
                x.client_id.clone(),
                x.token_endpoint.clone().unwrap_or_default(),
            )
        } else {
            (0, String::new(), String::new(), String::new())
        };

    EmailSettings {
        smtp_host: cfg.smtp_host.clone(),
        smtp_port: cfg.smtp_port as u32,
        from_address: cfg.from_address.clone(),
        from_display_name: cfg.from_display_name.clone(),
        reply_to: cfg.reply_to.clone(),
        encryption: encryption_to_proto(cfg.encryption),
        auth_type: auth_to_proto(cfg.auth_type),
        // username / password never returned — write-only
        username: String::new(),
        password: String::new(),
        xoauth2_provider,
        xoauth2_tenant_id,
        xoauth2_client_id,
        // write-only secrets — never returned
        xoauth2_client_secret: String::new(),
        xoauth2_service_account_key: String::new(),
        xoauth2_token_endpoint,
    }
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

/// Build `XOAuth2Config` from proto `EmailSettings` fields.
///
/// Preserves existing secrets when the client sends empty strings
/// (update without rotating credentials).
fn xoauth2_config_from_proto(
    req: &EmailSettings,
    existing: Option<&XOAuth2Config>,
) -> Option<XOAuth2Config> {
    let provider = xoauth2_provider_from_proto(req.xoauth2_provider)?;

    let client_secret = if req.xoauth2_client_secret.is_empty() {
        existing
            .map(|x| SecretBox::new(Box::new(x.client_secret.expose_secret().clone())))
            .unwrap_or_else(|| SecretBox::new(Box::new(String::new())))
    } else {
        SecretBox::new(Box::new(req.xoauth2_client_secret.clone()))
    };

    let service_account_key = if req.xoauth2_service_account_key.is_empty() {
        existing.and_then(|x| {
            x.service_account_key
                .as_ref()
                .map(|k| SecretBox::new(Box::new(k.expose_secret().clone())))
        })
    } else {
        Some(SecretBox::new(Box::new(
            req.xoauth2_service_account_key.clone(),
        )))
    };

    let tenant_id = if req.xoauth2_tenant_id.is_empty() {
        existing.and_then(|x| x.tenant_id.clone())
    } else {
        Some(req.xoauth2_tenant_id.clone())
    };

    let token_endpoint = if req.xoauth2_token_endpoint.is_empty() {
        existing.and_then(|x| x.token_endpoint.clone())
    } else {
        Some(req.xoauth2_token_endpoint.clone())
    };

    // `username` field carries the SMTP user email for XOAUTH2.
    let user_email = if req.username.is_empty() {
        existing.map(|x| x.user_email.clone()).unwrap_or_default()
    } else {
        req.username.clone()
    };

    Some(XOAuth2Config {
        provider,
        tenant_id,
        client_id: if req.xoauth2_client_id.is_empty() {
            existing.map(|x| x.client_id.clone()).unwrap_or_default()
        } else {
            req.xoauth2_client_id.clone()
        },
        client_secret,
        service_account_key,
        token_endpoint,
        user_email,
    })
}

// ── gRPC handler implementation ───────────────────────────────────────────────

#[tonic::async_trait]
impl RealmService for RealmServiceImpl {
    // ── Email settings (task #742 + #743) ───────────────────────────────────

    #[instrument(skip(self, request), fields(rpc = "GetEmailSettings"))]
    async fn get_email_settings(
        &self,
        request: Request<()>,
    ) -> Result<Response<EmailSettings>, Status> {
        self.require_admin(&request).await?;
        match self.load().await? {
            Some(cfg) => Ok(Response::new(config_to_proto(&cfg))),
            None => Ok(Response::new(EmailSettings::default())),
        }
    }

    #[instrument(skip(self, request), fields(rpc = "UpdateEmailSettings"))]
    async fn update_email_settings(
        &self,
        request: Request<EmailSettings>,
    ) -> Result<Response<EmailSettings>, Status> {
        let admin_id = self.require_admin(&request).await?;
        let req = request.into_inner();

        // Fetch existing config to preserve secrets on update-without-rotate.
        let existing = self.load().await?;

        let auth_type = auth_from_proto(req.auth_type);

        // Preserve SMTP password when client sends empty string.
        let password = if req.password.is_empty() {
            existing
                .as_ref()
                .map(|c| SecretBox::new(Box::new(c.password.expose_secret().clone())))
                .unwrap_or_else(|| SecretBox::new(Box::new(String::new())))
        } else {
            SecretBox::new(Box::new(req.password.clone()))
        };

        // Build XOAUTH2 config when auth_type == XOAUTH2.
        let xoauth2 = if auth_type == SmtpAuthMethod::XOAuth2 {
            let existing_xoauth2 = existing.as_ref().and_then(|c| c.xoauth2.as_ref());
            let config = xoauth2_config_from_proto(&req, existing_xoauth2).ok_or_else(|| {
                invalid_field("xoauth2_provider", "required when auth_type is XOAUTH2")
            })?;
            Some(config)
        } else {
            None
        };

        let cfg = EmailProviderConfig {
            smtp_host: req.smtp_host.clone(),
            smtp_port: req.smtp_port as u16,
            from_address: req.from_address.clone(),
            from_display_name: req.from_display_name.clone(),
            reply_to: req.reply_to.clone(),
            encryption: encryption_from_proto(req.encryption),
            auth_type,
            username: req.username.clone(),
            password,
            xoauth2,
        };

        let audit: MutationContext = AuditEntry::admin(
            admin_id,
            "email_provider_config.update",
            "email_provider_config",
        )
        .into();

        self.storage
            .upsert_email_provider_config(&self.sealed(&cfg).await?, audit)
            .await
            .map_err(storage_failure)?;

        info!(host = %cfg.smtp_host, port = cfg.smtp_port, auth = ?cfg.auth_type, "Email provider config updated");
        Ok(Response::new(config_to_proto(&cfg)))
    }

    #[instrument(skip(self, request), fields(rpc = "TestEmailConnection"))]
    async fn test_email_connection(&self, request: Request<()>) -> Result<Response<()>, Status> {
        self.require_admin(&request).await?;

        let cfg = self.load().await?.ok_or_else(|| not_configured("email"))?;

        // The XOAUTH2 channel when configured, plain SMTP otherwise.
        let health = if cfg.auth_type == SmtpAuthMethod::XOAuth2 {
            channel_from_email_config(&cfg)
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
