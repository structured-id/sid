// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's email provider: its settings as an administrator reads
//! and replaces them, and the stored configuration with its credentials
//! opened for the host's delivery adapter. The credentials (SMTP password,
//! XOAUTH2 client secret and service-account key) are stored only sealed
//! under the key manager: whoever holds them sends mail as the instance.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretBox};
use sid_authn::caller::{Caller, CallerError};
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, EmailProviderConfig, MutationContext, SmtpAuthMethod, SmtpEncryption,
    XOAuth2Config, XOAuth2Provider,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::{
    EmailSettings, SmtpAuthType, SmtpEncryptionType, XoAuth2ProviderType,
};
use tracing::info;

/// Sealing contexts of the stored email provider credentials: a value sealed
/// for one field is never accepted as another.
pub const SMTP_PASSWORD_CONTEXT: &str = "email_provider:smtp_password";
pub const XOAUTH2_CLIENT_SECRET_CONTEXT: &str = "email_provider:xoauth2_client_secret";
pub const XOAUTH2_SERVICE_ACCOUNT_KEY_CONTEXT: &str = "email_provider:xoauth2_service_account_key";

/// Why the stored email provider could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("read the email provider: {0}")]
    Storage(SidError),
    /// A stored credential that is not sealed for its field, or that the
    /// keys cannot open now.
    #[error("open an email provider credential: {0}")]
    Credential(String),
}

/// Why an email provider operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EmailProviderError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation (a credential that cannot be sealed or
    /// opened); its cause is in the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// No email provider is configured.
    #[error("no email provider is configured")]
    NotConfigured,
}

impl From<ProviderError> for EmailProviderError {
    fn from(e: ProviderError) -> Self {
        match e {
            ProviderError::Storage(e) => Self::Store(e),
            ProviderError::Credential(cause) => {
                internal("open stored email provider credential", cause)
            }
        }
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> EmailProviderError {
    tracing::error!(operation, error = %cause, "internal failure");
    EmailProviderError::Internal
}

/// The credential a stored value holds. A value that is not sealed for
/// `context` is refused rather than used as the credential.
async fn open_credential(
    keys: &dyn sid_keys::KeyManager,
    context: &str,
    stored: &SecretBox<String>,
) -> Result<SecretBox<String>, ProviderError> {
    if stored.expose_secret().is_empty() {
        return Ok(SecretBox::new(Box::new(String::new())));
    }
    let refused = |e: &dyn std::fmt::Display| ProviderError::Credential(e.to_string());
    let bytes = STANDARD
        .decode(stored.expose_secret())
        .map_err(|e| refused(&e))?;
    let opened = sid_authn::sealed_secret::open(keys, context, &bytes)
        .await
        .map_err(|e| refused(&e))?;
    let text = String::from_utf8(opened.secret.to_vec()).map_err(|e| refused(&e))?;
    Ok(SecretBox::new(Box::new(text)))
}

/// The installation's stored email provider with its credentials opened,
/// `None` when none is configured.
pub async fn stored(
    storage: &dyn StorageBackend,
    keys: &dyn sid_keys::KeyManager,
) -> Result<Option<EmailProviderConfig>, ProviderError> {
    let Some(mut cfg) = storage
        .get_email_provider_config()
        .await
        .map_err(ProviderError::Storage)?
    else {
        return Ok(None);
    };
    cfg.password = open_credential(keys, SMTP_PASSWORD_CONTEXT, &cfg.password).await?;
    if let Some(x) = cfg.xoauth2.as_mut() {
        x.client_secret =
            open_credential(keys, XOAUTH2_CLIENT_SECRET_CONTEXT, &x.client_secret).await?;
        if let Some(key) = x.service_account_key.as_ref() {
            x.service_account_key =
                Some(open_credential(keys, XOAUTH2_SERVICE_ACCOUNT_KEY_CONTEXT, key).await?);
        }
    }
    Ok(Some(cfg))
}

/// The email provider of one installation.
pub struct EmailProvider {
    storage: Arc<dyn StorageBackend>,
    /// Seals the provider's credentials before they are stored.
    keys: Arc<dyn sid_keys::KeyManager>,
}

impl EmailProvider {
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        Self { storage, keys }
    }

    /// `secret` sealed for `context`, as the text the store keeps. An empty
    /// value (no credential) stays empty.
    async fn seal(
        &self,
        context: &str,
        secret: &SecretBox<String>,
    ) -> Result<SecretBox<String>, EmailProviderError> {
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

    /// `cfg` with its credentials sealed, as it is stored.
    async fn sealed(
        &self,
        cfg: &EmailProviderConfig,
    ) -> Result<EmailProviderConfig, EmailProviderError> {
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

    async fn load(&self) -> Result<Option<EmailProviderConfig>, EmailProviderError> {
        Ok(stored(self.storage.as_ref(), self.keys.as_ref()).await?)
    }

    /// The settings an administrator reads, without the write-only
    /// credentials; empty while none is configured.
    pub async fn settings(&self, caller: &Caller) -> Result<EmailSettings, EmailProviderError> {
        caller.require_admin()?;
        Ok(self
            .load()
            .await?
            .map(|cfg| config_to_proto(&cfg))
            .unwrap_or_default())
    }

    /// The configuration an administrator tests the connection with, its
    /// credentials opened.
    pub async fn configured(
        &self,
        caller: &Caller,
    ) -> Result<EmailProviderConfig, EmailProviderError> {
        caller.require_admin()?;
        self.load().await?.ok_or(EmailProviderError::NotConfigured)
    }

    /// Replace the settings. An empty credential keeps the stored one
    /// (an update without rotation).
    pub async fn update(
        &self,
        caller: &Caller,
        req: EmailSettings,
    ) -> Result<EmailSettings, EmailProviderError> {
        caller.require_admin()?;
        let existing = self.load().await?;
        let auth_type = auth_from_proto(req.auth_type);
        let password = if req.password.is_empty() {
            existing
                .as_ref()
                .map(|c| SecretBox::new(Box::new(c.password.expose_secret().clone())))
                .unwrap_or_else(|| SecretBox::new(Box::new(String::new())))
        } else {
            SecretBox::new(Box::new(req.password.clone()))
        };
        let xoauth2 = if auth_type == SmtpAuthMethod::XOAuth2 {
            let existing_xoauth2 = existing.as_ref().and_then(|c| c.xoauth2.as_ref());
            Some(
                xoauth2_config_from_proto(&req, existing_xoauth2).ok_or_else(|| {
                    EmailProviderError::InvalidField {
                        field: "xoauth2_provider",
                        reason: "required when auth_type is XOAUTH2".into(),
                    }
                })?,
            )
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
            caller.profile_id.to_string(),
            "email_provider_config.update",
            "email_provider_config",
        )
        .into();
        self.storage
            .upsert_email_provider_config(&self.sealed(&cfg).await?, audit)
            .await?;
        info!(host = %cfg.smtp_host, port = cfg.smtp_port, auth = ?cfg.auth_type, "Email provider config updated");
        Ok(config_to_proto(&cfg))
    }
}

// ── Messages ────────────────────────────────────────────────────────

fn encryption_from_proto(enc: i32) -> SmtpEncryption {
    match SmtpEncryptionType::try_from(enc).unwrap_or(SmtpEncryptionType::Unspecified) {
        SmtpEncryptionType::SslTls => SmtpEncryption::SslTls,
        SmtpEncryptionType::Starttls => SmtpEncryption::Starttls,
        _ => SmtpEncryption::None,
    }
}

fn encryption_to_proto(enc: SmtpEncryption) -> i32 {
    match enc {
        SmtpEncryption::SslTls => SmtpEncryptionType::SslTls as i32,
        SmtpEncryption::Starttls => SmtpEncryptionType::Starttls as i32,
        SmtpEncryption::None => SmtpEncryptionType::None as i32,
    }
}

fn auth_from_proto(auth: i32) -> SmtpAuthMethod {
    match SmtpAuthType::try_from(auth).unwrap_or(SmtpAuthType::Unspecified) {
        SmtpAuthType::UsernamePassword => SmtpAuthMethod::UsernamePassword,
        SmtpAuthType::Xoauth2 => SmtpAuthMethod::XOAuth2,
        _ => SmtpAuthMethod::None,
    }
}

fn auth_to_proto(auth: SmtpAuthMethod) -> i32 {
    match auth {
        SmtpAuthMethod::UsernamePassword => SmtpAuthType::UsernamePassword as i32,
        SmtpAuthMethod::XOAuth2 => SmtpAuthType::Xoauth2 as i32,
        SmtpAuthMethod::None => SmtpAuthType::None as i32,
    }
}

/// `None` for `Unspecified` (no XOAUTH2 provider set).
fn xoauth2_provider_from_proto(v: i32) -> Option<XOAuth2Provider> {
    match XoAuth2ProviderType::try_from(v)
        .unwrap_or(XoAuth2ProviderType::Xoauth2ProviderTypeUnspecified)
    {
        XoAuth2ProviderType::Xoauth2ProviderTypeM365 => Some(XOAuth2Provider::M365),
        XoAuth2ProviderType::Xoauth2ProviderTypeGoogle => Some(XOAuth2Provider::Google),
        XoAuth2ProviderType::Xoauth2ProviderTypeUnspecified => None,
    }
}

fn xoauth2_provider_to_proto(p: XOAuth2Provider) -> i32 {
    match p {
        XOAuth2Provider::M365 => XoAuth2ProviderType::Xoauth2ProviderTypeM365 as i32,
        XOAuth2Provider::Google => XoAuth2ProviderType::Xoauth2ProviderTypeGoogle as i32,
    }
}

/// The settings as the API returns them: the write-only `username`,
/// `password`, `xoauth2_client_secret` and `xoauth2_service_account_key` are
/// never returned.
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
        username: String::new(),
        password: String::new(),
        xoauth2_provider,
        xoauth2_tenant_id,
        xoauth2_client_id,
        xoauth2_client_secret: String::new(),
        xoauth2_service_account_key: String::new(),
        xoauth2_token_endpoint,
    }
}

/// The XOAUTH2 configuration a request gives; an empty field keeps the
/// existing value (an update without rotating credentials).
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
    // `username` carries the SMTP user email for XOAUTH2.
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

#[cfg(test)]
mod tests;
