// SPDX-License-Identifier: AGPL-3.0-only
//! Per-project branding: design tokens, assets, text and dark mode, through a
//! draft, published and archived lifecycle. The published branding of a
//! project is public (the sign-in page shows it); everything else is
//! instance administration. A keyed operation commits its change, audit and
//! completion together and answers a retry with what the first attempt
//! recorded.

use std::sync::Arc;

use prost::Message;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, BackgroundConfig, BrandingAssets, BrandingConfig, BrandingConfigId, BrandingStatus,
    BrandingText, ButtonStyle, DarkModeConfig, DarkModeTokens, DesignTokens, MutationContext,
    OperationContext,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::branding_service as keyed;
use sid_proto::sid::v1 as pb;

use crate::wire::{FieldError, to_timestamp, wire_id};

/// Why a branding operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum BrandingError {
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
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// No branding config of this name (a config id, or a project without
    /// published branding).
    #[error("branding {0} not found")]
    NotFound(String),
    /// Only a draft is edited or published.
    #[error("branding config {0} is not a draft")]
    NotADraft(BrandingConfigId),
    /// A published config is not deleted; another is published first.
    #[error("branding config {0} is published")]
    Published(BrandingConfigId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<BrandingError> for Effect<BrandingError> {
    fn from(e: BrandingError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<BrandingError>> for BrandingError {
    fn from(e: CommandError<BrandingError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for BrandingError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

/// The branding of one installation's projects.
pub struct Branding {
    storage: Arc<dyn StorageBackend>,
}

impl Branding {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// The published branding of a project: public, the sign-in page shows
    /// it.
    pub async fn published(
        &self,
        req: pb::GetPublishedBrandingRequest,
    ) -> Result<pb::BrandingConfig, BrandingError> {
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let config = self
            .storage
            .get_published_branding(project_id)
            .await?
            .ok_or_else(|| BrandingError::NotFound(format!("project:{project_id}")))?;
        Ok(domain_to_proto(&config))
    }

    pub async fn config(
        &self,
        caller: &Caller,
        req: pb::GetBrandingConfigRequest,
    ) -> Result<pb::BrandingConfig, BrandingError> {
        caller.require_admin()?;
        let config_id = wire_id(req.config_id.as_ref(), "config_id")?;
        let config = self
            .storage
            .get_branding_config(config_id)
            .await?
            .ok_or_else(|| BrandingError::NotFound(config_id.to_string()))?;
        Ok(domain_to_proto(&config))
    }

    pub async fn list(
        &self,
        caller: &Caller,
        req: pb::ListBrandingConfigsRequest,
    ) -> Result<pb::ListBrandingConfigsResponse, BrandingError> {
        caller.require_admin()?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let configs = self.storage.list_branding_configs(project_id).await?;
        Ok(pb::ListBrandingConfigsResponse {
            configs: configs.iter().map(domain_to_proto).collect(),
        })
    }

    /// Create a draft. A retry of a completed creation answers with the
    /// config it created and creates no second one.
    pub async fn create(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::CreateBrandingConfigRequest,
    ) -> Result<pb::BrandingConfig, BrandingError> {
        caller.require_admin()?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let admin = caller.profile_id.to_string();
        let command = KeyedCommand::by_profile::<keyed::CreateBrandingConfig>(
            caller.profile_id,
            operation,
            &req,
        );
        let now = chrono::Utc::now();
        let config = BrandingConfig {
            id: BrandingConfigId::generate(),
            project_id,
            status: BrandingStatus::Draft,
            tokens: req
                .tokens
                .as_ref()
                .map(tokens_from_proto)
                .unwrap_or_default(),
            assets: req
                .assets
                .as_ref()
                .map(assets_from_proto)
                .unwrap_or_default(),
            dark_mode: req
                .dark_mode
                .as_ref()
                .map(dark_mode_from_proto)
                .unwrap_or_default(),
            text: req.text.as_ref().map(text_from_proto).unwrap_or_default(),
            revision: 0,
            created_at: now,
            updated_at: now,
        };
        command
            .execute(&*self.storage, || async {
                let response = domain_to_proto(&config);
                let audit = MutationContext::from(AuditEntry::admin(
                    &admin,
                    "branding.create",
                    config.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.create_branding_config(&config, audit).await?;
                Ok(response)
            })
            .await
            .map_err(CommandError::<BrandingError>::refusal)
    }

    /// Edit a draft: the parts given replace the draft's. A retry of a
    /// completed edit answers with the draft as that edit left it and never
    /// writes it over a later edit.
    pub async fn update(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::UpdateBrandingConfigRequest,
    ) -> Result<pb::BrandingConfig, BrandingError> {
        caller.require_admin()?;
        let config_id = wire_id(req.config_id.as_ref(), "config_id")?;
        let admin = caller.profile_id.to_string();
        let command = KeyedCommand::by_profile::<keyed::UpdateBrandingConfig>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                let mut config = self
                    .storage
                    .get_branding_config(config_id)
                    .await?
                    .ok_or_else(|| BrandingError::NotFound(config_id.to_string()))?;
                // Only a draft is edited; a published or archived config
                // changes through a new draft and its publication.
                if config.status != BrandingStatus::Draft {
                    return Err(BrandingError::NotADraft(config_id).into());
                }
                if let Some(tokens) = &req.tokens {
                    config.tokens = tokens_from_proto(tokens);
                }
                if let Some(assets) = &req.assets {
                    config.assets = assets_from_proto(assets);
                }
                if let Some(dark_mode) = &req.dark_mode {
                    config.dark_mode = dark_mode_from_proto(dark_mode);
                }
                if let Some(text) = &req.text {
                    config.text = text_from_proto(text);
                }
                config.updated_at = chrono::Utc::now();
                let response = domain_to_proto(&config);
                let audit = MutationContext::from(AuditEntry::admin(
                    &admin,
                    "branding.update",
                    config.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                if !self.storage.update_branding_draft(&config, audit).await? {
                    // Published, deleted or edited since it was read.
                    return Err(BrandingError::ChangedConcurrently.into());
                }
                Ok(response)
            })
            .await
            .map_err(CommandError::<BrandingError>::refusal)
    }

    /// Publish a draft in its own project, archiving the project's published
    /// config in the same write. A retry of a completed publication answers
    /// as it did, not as a config no longer a draft, and never publishes it
    /// again over a later one.
    pub async fn publish(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::PublishBrandingConfigRequest,
    ) -> Result<pb::BrandingConfig, BrandingError> {
        caller.require_admin()?;
        let config_id = wire_id(req.config_id.as_ref(), "config_id")?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let admin = caller.profile_id.to_string();
        let command = KeyedCommand::by_profile::<keyed::PublishBrandingConfig>(
            caller.profile_id,
            operation,
            &req,
        );
        let published: BrandingConfig = command
            .execute_recorded(&*self.storage, || async {
                let config = self
                    .storage
                    .get_branding_config(config_id)
                    .await?
                    .ok_or_else(|| BrandingError::NotFound(config_id.to_string()))?;
                // Publishing a draft under another project would archive that
                // project's branding.
                if config.project_id != project_id {
                    return Err(BrandingError::NotFound(config_id.to_string()).into());
                }
                if config.status != BrandingStatus::Draft {
                    return Err(BrandingError::NotADraft(config_id).into());
                }
                // The answer is the config as the publishing write leaves it,
                // an edit made since this read included.
                let audit = MutationContext::from(AuditEntry::admin(
                    &admin,
                    "branding.publish",
                    config.id.to_string(),
                ))
                .with_operation(command.effect_completion());
                if !self
                    .storage
                    .publish_branding_config(config_id, project_id, chrono::Utc::now(), audit)
                    .await?
                {
                    // Published or deleted since it was read.
                    return Err(BrandingError::NotADraft(config_id).into());
                }
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::<BrandingError>::refusal)?;
        Ok(domain_to_proto(&published))
    }

    /// Delete a config that is not published; the store refuses one
    /// published meanwhile.
    pub async fn delete(
        &self,
        caller: &Caller,
        req: pb::DeleteBrandingConfigRequest,
    ) -> Result<(), BrandingError> {
        caller.require_admin()?;
        let config_id = wire_id(req.config_id.as_ref(), "config_id")?;
        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "branding.delete",
            config_id.to_string(),
        )
        .into();
        let deleted = self
            .storage
            .delete_branding_config(config_id, audit)
            .await?;
        if !deleted
            && self
                .storage
                .get_branding_config(config_id)
                .await?
                .is_some_and(|c| c.status == BrandingStatus::Published)
        {
            return Err(BrandingError::Published(config_id));
        }
        Ok(())
    }

    /// The WCAG 2.1 contrast of each pair and the level it meets.
    pub fn validate_contrast(
        &self,
        caller: &Caller,
        req: pb::ValidateContrastRequest,
    ) -> Result<pb::ValidateContrastResponse, BrandingError> {
        caller.require_admin()?;
        let results = req
            .pairs
            .iter()
            .map(contrast_check)
            .collect::<Result<_, _>>()?;
        Ok(pb::ValidateContrastResponse { results })
    }
}

// ── Messages ──

fn domain_to_proto(config: &BrandingConfig) -> pb::BrandingConfig {
    pb::BrandingConfig {
        id: Some(config.id.into()),
        project_id: Some(config.project_id.into()),
        status: match config.status {
            BrandingStatus::Draft => pb::BrandingStatus::Draft.into(),
            BrandingStatus::Published => pb::BrandingStatus::Published.into(),
            BrandingStatus::Archived => pb::BrandingStatus::Archived.into(),
        },
        tokens: Some(tokens_to_proto(&config.tokens)),
        assets: Some(assets_to_proto(&config.assets)),
        dark_mode: Some(dark_mode_to_proto(&config.dark_mode)),
        text: Some(text_to_proto(&config.text)),
        created_at: Some(to_timestamp(config.created_at)),
        updated_at: Some(to_timestamp(config.updated_at)),
    }
}

fn tokens_to_proto(t: &DesignTokens) -> pb::DesignTokens {
    pb::DesignTokens {
        color_primary: t.color_primary.clone(),
        color_primary_hover: t.color_primary_hover.clone(),
        color_background: t.color_background.clone(),
        color_surface: t.color_surface.clone(),
        color_text: t.color_text.clone(),
        color_error: t.color_error.clone(),
        color_warning: String::new(),
        color_success: String::new(),
        color_text_secondary: String::new(),
        font_family: t.font_family.clone(),
        font_size_base: t.font_size_base.clone(),
        border_radius: t.border_radius.clone(),
        spacing_unit: t.spacing_unit.clone(),
        button_style: match t.button_style {
            ButtonStyle::Rounded => pb::ButtonStyle::Rounded.into(),
            ButtonStyle::Square => pb::ButtonStyle::Square.into(),
            ButtonStyle::Pill => pb::ButtonStyle::Pill.into(),
        },
        custom: t.custom.clone(),
    }
}

/// Tokens a request gives; an empty one is the default.
fn tokens_from_proto(t: &pb::DesignTokens) -> DesignTokens {
    let defaults = DesignTokens::default();
    DesignTokens {
        color_primary: non_empty_or(&t.color_primary, &defaults.color_primary),
        color_primary_hover: non_empty_or(&t.color_primary_hover, &defaults.color_primary_hover),
        color_background: non_empty_or(&t.color_background, &defaults.color_background),
        color_surface: non_empty_or(&t.color_surface, &defaults.color_surface),
        color_text: non_empty_or(&t.color_text, &defaults.color_text),
        color_error: non_empty_or(&t.color_error, &defaults.color_error),
        font_family: non_empty_or(&t.font_family, &defaults.font_family),
        font_size_base: non_empty_or(&t.font_size_base, &defaults.font_size_base),
        border_radius: non_empty_or(&t.border_radius, &defaults.border_radius),
        spacing_unit: non_empty_or(&t.spacing_unit, &defaults.spacing_unit),
        button_style: match pb::ButtonStyle::try_from(t.button_style) {
            Ok(pb::ButtonStyle::Square) => ButtonStyle::Square,
            Ok(pb::ButtonStyle::Pill) => ButtonStyle::Pill,
            _ => ButtonStyle::Rounded,
        },
        custom: t.custom.clone(),
    }
}

fn non_empty_or(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

fn opt_string(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn assets_to_proto(a: &BrandingAssets) -> pb::BrandingAssets {
    use pb::background_config::Background;
    pb::BrandingAssets {
        logo_url: a.logo_url.clone().unwrap_or_default(),
        logo_dark_url: String::new(),
        favicon_url: a.favicon_url.clone().unwrap_or_default(),
        background: a.background.as_ref().map(|bg| pb::BackgroundConfig {
            background: Some(match bg {
                BackgroundConfig::Color { value } => Background::Color(value.clone()),
                BackgroundConfig::Image { url } => Background::ImageUrl(url.clone()),
                BackgroundConfig::Gradient { value } => Background::Gradient(value.clone()),
            }),
        }),
    }
}

fn assets_from_proto(a: &pb::BrandingAssets) -> BrandingAssets {
    use pb::background_config::Background;
    BrandingAssets {
        logo_url: opt_string(&a.logo_url),
        favicon_url: opt_string(&a.favicon_url),
        background: a.background.as_ref().and_then(|bg| {
            bg.background.as_ref().map(|b| match b {
                Background::Color(v) => BackgroundConfig::Color { value: v.clone() },
                Background::ImageUrl(v) => BackgroundConfig::Image { url: v.clone() },
                Background::Gradient(v) => BackgroundConfig::Gradient { value: v.clone() },
            })
        }),
    }
}

fn dark_mode_to_proto(d: &DarkModeConfig) -> pb::DarkModeConfig {
    pb::DarkModeConfig {
        enabled: d.enabled,
        tokens: Some(pb::DarkModeTokens {
            color_background: d.tokens.color_background.clone().unwrap_or_default(),
            color_surface: d.tokens.color_surface.clone().unwrap_or_default(),
            color_text: d.tokens.color_text.clone().unwrap_or_default(),
            color_text_secondary: String::new(),
            color_primary: d.tokens.color_primary.clone().unwrap_or_default(),
            color_primary_hover: d.tokens.color_primary_hover.clone().unwrap_or_default(),
            color_error: d.tokens.color_error.clone().unwrap_or_default(),
            color_warning: String::new(),
            color_success: String::new(),
            custom: d.tokens.custom.clone(),
        }),
    }
}

fn dark_mode_from_proto(d: &pb::DarkModeConfig) -> DarkModeConfig {
    DarkModeConfig {
        enabled: d.enabled,
        tokens: d
            .tokens
            .as_ref()
            .map(|t| DarkModeTokens {
                color_background: opt_string(&t.color_background),
                color_surface: opt_string(&t.color_surface),
                color_text: opt_string(&t.color_text),
                color_primary: opt_string(&t.color_primary),
                color_primary_hover: opt_string(&t.color_primary_hover),
                color_error: opt_string(&t.color_error),
                custom: t.custom.clone(),
            })
            .unwrap_or_default(),
    }
}

fn text_to_proto(t: &BrandingText) -> pb::BrandingText {
    pb::BrandingText {
        login_title: t.login_title.clone().unwrap_or_default(),
        login_subtitle: t.login_subtitle.clone().unwrap_or_default(),
        footer_text: t.footer_text.clone().unwrap_or_default(),
        terms_url: t.terms_url.clone().unwrap_or_default(),
        privacy_url: t.privacy_url.clone().unwrap_or_default(),
        help_url: t.help_url.clone().unwrap_or_default(),
    }
}

fn text_from_proto(t: &pb::BrandingText) -> BrandingText {
    BrandingText {
        login_title: opt_string(&t.login_title),
        login_subtitle: opt_string(&t.login_subtitle),
        footer_text: opt_string(&t.footer_text),
        terms_url: opt_string(&t.terms_url),
        privacy_url: opt_string(&t.privacy_url),
        help_url: opt_string(&t.help_url),
    }
}

// ── Contrast ──

/// The sRGB channels of a `#rgb` or `#rrggbb` color.
fn parse_hex_color(color: &str) -> Option<[u8; 3]> {
    let hex = color.strip_prefix('#')?;
    let digit = |i: usize| u8::from_str_radix(hex.get(i..=i)?, 16).ok();
    match hex.len() {
        3 => Some([digit(0)? * 17, digit(1)? * 17, digit(2)? * 17]),
        6 => Some([
            digit(0)? * 16 + digit(1)?,
            digit(2)? * 16 + digit(3)?,
            digit(4)? * 16 + digit(5)?,
        ]),
        _ => None,
    }
}

/// Relative luminance, WCAG 2.1 §1.4.3 (definition of relative luminance),
/// with the sRGB threshold 0.04045 of IEC 61966-2-1.
fn relative_luminance([r, g, b]: [u8; 3]) -> f64 {
    let linear = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

/// The contrast ratio of a pair and the level it meets: WCAG 2.1 SC 1.4.3
/// asks 4.5:1 for normal text and 3:1 for large text.
fn contrast_check(pair: &pb::ColorPair) -> Result<pb::ContrastCheck, BrandingError> {
    let unreadable = || BrandingError::InvalidField {
        field: "pairs",
        reason: "a color is not #rgb or #rrggbb".into(),
    };
    let fg = relative_luminance(parse_hex_color(&pair.foreground).ok_or_else(unreadable)?);
    let bg = relative_luminance(parse_hex_color(&pair.background).ok_or_else(unreadable)?);
    let (light, dark) = if fg >= bg { (fg, bg) } else { (bg, fg) };
    let ratio = (light + 0.05) / (dark + 0.05);
    let level = if ratio >= 4.5 {
        pb::WcagLevel::AaNormal
    } else if ratio >= 3.0 {
        pb::WcagLevel::AaLargeOnly
    } else {
        pb::WcagLevel::Fail
    };
    Ok(pb::ContrastCheck {
        foreground: pair.foreground.clone(),
        background: pair.background.clone(),
        ratio,
        level: level as i32,
    })
}

#[cfg(test)]
mod tests;
