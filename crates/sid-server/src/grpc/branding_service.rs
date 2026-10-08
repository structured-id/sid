// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC BrandingService implementation.
//!
//! Per-project branding CRUD: design tokens, assets, text, dark mode.
//! Draft/published/archived lifecycle. Admin role required.

use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{
    changed_concurrently, invalid_field, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{
    AuditEntry, BackgroundConfig, BrandingAssets, BrandingConfig, BrandingConfigId, BrandingStatus,
    BrandingText, ButtonStyle, DarkModeConfig, DarkModeTokens, DesignTokens, MutationContext,
    ProjectId,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::branding_service_server::BrandingService;
use sid_proto::sid::v1::{self as pb};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;
use uuid::Uuid;

/// BRANDING_NOT_FOUND for `name` (a config id, or a project without
/// published branding).
fn branding_not_found(name: impl Into<String>) -> Status {
    not_found(ErrorReason::BrandingNotFound, "BrandingConfig", name)
}

/// INVALID_STATE: the branding config is `state` where the call needs
/// another.
fn branding_state(id: BrandingConfigId, state: &'static str, why: &'static str) -> Status {
    ApiError::new(ErrorReason::InvalidState, why)
        .with_precondition("BRANDING_STATUS", id.0.to_string(), state)
        .into()
}

/// A draft is the only config edited or published.
fn not_a_draft(id: BrandingConfigId) -> Status {
    branding_state(id, "not a draft", "only a draft branding config changes")
}

pub struct BrandingServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl BrandingServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
        }
    }

    /// Authenticate the caller and require the administrator role; returns the
    /// caller's ProfileId as the audit actor.
    #[allow(clippy::result_large_err)]
    async fn require_admin<T>(&self, req: &Request<T>) -> Result<String, Status> {
        let caller = authenticate(req, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller.profile_id.to_string())
    }

    #[allow(clippy::result_large_err)]
    fn parse_project_id(s: &str) -> Result<ProjectId, Status> {
        Uuid::parse_str(s)
            .map(ProjectId)
            .map_err(|_| invalid_field("project_id", "not a project identifier"))
    }

    #[allow(clippy::result_large_err)]
    fn parse_config_id(s: &str) -> Result<BrandingConfigId, Status> {
        Uuid::parse_str(s)
            .map(BrandingConfigId)
            .map_err(|_| invalid_field("config_id", "not a branding config identifier"))
    }
}

// ── Proto ↔ Domain conversions ──

fn domain_to_proto(config: &BrandingConfig) -> pb::BrandingConfig {
    pb::BrandingConfig {
        id: config.id.0.to_string(),
        project_id: config.project_id.0.to_string(),
        status: match config.status {
            BrandingStatus::Draft => pb::BrandingStatus::Draft.into(),
            BrandingStatus::Published => pb::BrandingStatus::Published.into(),
            BrandingStatus::Archived => pb::BrandingStatus::Archived.into(),
        },
        tokens: Some(tokens_to_proto(&config.tokens)),
        assets: Some(assets_to_proto(&config.assets)),
        dark_mode: Some(dark_mode_to_proto(&config.dark_mode)),
        text: Some(text_to_proto(&config.text)),
        created_at: Some(prost_types::Timestamp {
            seconds: config.created_at.timestamp(),
            nanos: config.created_at.timestamp_subsec_nanos() as i32,
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: config.updated_at.timestamp(),
            nanos: config.updated_at.timestamp_subsec_nanos() as i32,
        }),
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

fn assets_to_proto(a: &BrandingAssets) -> pb::BrandingAssets {
    pb::BrandingAssets {
        logo_url: a.logo_url.clone().unwrap_or_default(),
        logo_dark_url: String::new(),
        favicon_url: a.favicon_url.clone().unwrap_or_default(),
        background: a.background.as_ref().map(|bg| match bg {
            BackgroundConfig::Color { value } => pb::BackgroundConfig {
                background: Some(pb::background_config::Background::Color(value.clone())),
            },
            BackgroundConfig::Image { url } => pb::BackgroundConfig {
                background: Some(pb::background_config::Background::ImageUrl(url.clone())),
            },
            BackgroundConfig::Gradient { value } => pb::BackgroundConfig {
                background: Some(pb::background_config::Background::Gradient(value.clone())),
            },
        }),
    }
}

fn assets_from_proto(a: &pb::BrandingAssets) -> BrandingAssets {
    BrandingAssets {
        logo_url: if a.logo_url.is_empty() {
            None
        } else {
            Some(a.logo_url.clone())
        },
        favicon_url: if a.favicon_url.is_empty() {
            None
        } else {
            Some(a.favicon_url.clone())
        },
        background: a.background.as_ref().and_then(|bg| {
            bg.background.as_ref().map(|b| match b {
                pb::background_config::Background::Color(v) => {
                    BackgroundConfig::Color { value: v.clone() }
                }
                pb::background_config::Background::ImageUrl(v) => {
                    BackgroundConfig::Image { url: v.clone() }
                }
                pb::background_config::Background::Gradient(v) => {
                    BackgroundConfig::Gradient { value: v.clone() }
                }
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

fn opt_string(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
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

// ── Service implementation ──

#[tonic::async_trait]
impl BrandingService for BrandingServiceImpl {
    #[instrument(skip_all, name = "branding.get_published")]
    async fn get_published_branding(
        &self,
        request: Request<pb::GetPublishedBrandingRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        // Published branding is readable without admin (login page needs it).
        let req = request.into_inner();
        let project_id = Self::parse_project_id(&req.project_id)?;

        let config = self
            .storage
            .get_published_branding(project_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| branding_not_found(format!("project:{}", project_id.0)))?;

        Ok(Response::new(domain_to_proto(&config)))
    }

    #[instrument(skip_all, name = "branding.get_config")]
    async fn get_branding_config(
        &self,
        request: Request<pb::GetBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();
        let config_id = Self::parse_config_id(&req.config_id)?;

        let config = self
            .storage
            .get_branding_config(config_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| branding_not_found(config_id.0.to_string()))?;

        Ok(Response::new(domain_to_proto(&config)))
    }

    #[instrument(skip_all, name = "branding.list")]
    async fn list_branding_configs(
        &self,
        request: Request<pb::ListBrandingConfigsRequest>,
    ) -> Result<Response<pb::ListBrandingConfigsResponse>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();
        let project_id = Self::parse_project_id(&req.project_id)?;

        let configs = self
            .storage
            .list_branding_configs(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(pb::ListBrandingConfigsResponse {
            configs: configs.iter().map(domain_to_proto).collect(),
        }))
    }

    #[instrument(skip_all, name = "branding.create")]
    async fn create_branding_config(
        &self,
        request: Request<pb::CreateBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let admin_sub = self.require_admin(&request).await?;
        let req = request.into_inner();
        let project_id = Self::parse_project_id(&req.project_id)?;
        let now = chrono::Utc::now();

        let config = BrandingConfig {
            id: BrandingConfigId::new(),
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

        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "branding.create", config.id.to_string()).into();
        self.storage
            .create_branding_config(&config, audit)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(domain_to_proto(&config)))
    }

    #[instrument(skip_all, name = "branding.update")]
    async fn update_branding_config(
        &self,
        request: Request<pb::UpdateBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let admin_sub = self.require_admin(&request).await?;
        let req = request.into_inner();
        let config_id = Self::parse_config_id(&req.config_id)?;

        let mut config = self
            .storage
            .get_branding_config(config_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| branding_not_found(config_id.0.to_string()))?;

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
        // Only a draft is edited; a published or archived config changes
        // through a new draft and its publication.
        if config.status != BrandingStatus::Draft {
            return Err(not_a_draft(config_id));
        }
        config.updated_at = chrono::Utc::now();

        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "branding.update", config.id.to_string()).into();
        let updated = self
            .storage
            .update_branding_draft(&config, audit)
            .await
            .map_err(storage_failure)?;
        if !updated {
            // Published, deleted or edited since it was read.
            return Err(changed_concurrently());
        }
        config.revision += 1;

        Ok(Response::new(domain_to_proto(&config)))
    }

    #[instrument(skip_all, name = "branding.publish")]
    async fn publish_branding_config(
        &self,
        request: Request<pb::PublishBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let admin_sub = self.require_admin(&request).await?;
        let req = request.into_inner();
        let config_id = Self::parse_config_id(&req.config_id)?;
        let project_id = Self::parse_project_id(&req.project_id)?;

        let config = self
            .storage
            .get_branding_config(config_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| branding_not_found(config_id.0.to_string()))?;
        // The draft is published in its own project only: publishing it under
        // another project would archive that project's branding.
        if config.project_id != project_id {
            return Err(branding_not_found(config_id.0.to_string()));
        }
        if config.status != BrandingStatus::Draft {
            return Err(not_a_draft(config_id));
        }

        // Archiving the published config and publishing the draft is one write.
        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "branding.publish", config.id.to_string()).into();
        let published = self
            .storage
            .publish_branding_config(config_id, project_id, chrono::Utc::now(), audit)
            .await
            .map_err(storage_failure)?;
        if !published {
            // Published, edited or deleted since it was read.
            return Err(not_a_draft(config_id));
        }

        let stored = self
            .storage
            .get_branding_config(config_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| branding_not_found(config_id.0.to_string()))?;
        Ok(Response::new(domain_to_proto(&stored)))
    }

    #[instrument(skip_all, name = "branding.delete")]
    async fn delete_branding_config(
        &self,
        request: Request<pb::DeleteBrandingConfigRequest>,
    ) -> Result<Response<()>, Status> {
        let admin_sub = self.require_admin(&request).await?;
        let req = request.into_inner();
        let config_id = Self::parse_config_id(&req.config_id)?;

        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "branding.delete", config_id.to_string()).into();
        // The store refuses a published config, including one published meanwhile.
        let deleted = self
            .storage
            .delete_branding_config(config_id, audit)
            .await
            .map_err(storage_failure)?;
        if !deleted
            && self
                .storage
                .get_branding_config(config_id)
                .await
                .map_err(storage_failure)?
                .is_some_and(|c| c.status == BrandingStatus::Published)
        {
            return Err(branding_state(
                config_id,
                "published",
                "a published branding config is not deleted; publish another first",
            ));
        }

        Ok(Response::new(()))
    }

    #[instrument(skip_all, name = "branding.validate_contrast")]
    async fn validate_contrast(
        &self,
        request: Request<pb::ValidateContrastRequest>,
    ) -> Result<Response<pb::ValidateContrastResponse>, Status> {
        self.require_admin(&request).await?;
        let results = request
            .into_inner()
            .pairs
            .iter()
            .map(contrast_check)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(pb::ValidateContrastResponse { results }))
    }
}

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
#[allow(clippy::result_large_err)]
fn contrast_check(pair: &pb::ColorPair) -> Result<pb::ContrastCheck, Status> {
    let unreadable = || invalid_field("pairs", "a color is not #rgb or #rrggbb");
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
