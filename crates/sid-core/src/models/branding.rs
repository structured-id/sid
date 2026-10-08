// SPDX-License-Identifier: AGPL-3.0-only
//! Branding & theming configuration.
//!
//! Design tokens, assets, and configurable text for the built-in login UI.
//! Applied via CSS custom properties — no rebuild required to change branding.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::project::ProjectId;

/// Unique identifier for a branding configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BrandingConfigId(pub Uuid);

impl BrandingConfigId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for BrandingConfigId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BrandingConfigId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Branding configuration for a project's login/consent UI.
///
/// Stored per-project. Each project can have one active branding config
/// and optional draft configs for preview before publishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingConfig {
    pub id: BrandingConfigId,

    /// Project this branding belongs to.
    pub project_id: ProjectId,

    /// Whether this is the active (published) config or a draft.
    pub status: BrandingStatus,

    /// Visual assets (logo, favicon, background).
    pub assets: BrandingAssets,

    /// Design tokens (colors, fonts, spacing) — mapped to CSS custom properties.
    pub tokens: DesignTokens,

    /// Dark mode design tokens override. When `enabled`, these tokens
    /// are applied when `prefers-color-scheme: dark` is active.
    pub dark_mode: DarkModeConfig,

    /// Configurable text (titles, links, footer).
    pub text: BrandingText,

    /// Stored revision: 0 for a new config, moved on by every write. A draft
    /// edit applies only over the revision it was read at.
    #[serde(default)]
    pub revision: u64,

    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Branding lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrandingStatus {
    /// Draft — visible only in admin preview, not applied to login pages.
    Draft,
    /// Published — actively applied to all login/consent pages for this project.
    Published,
    /// Archived — previous published version, kept for rollback.
    Archived,
}

impl BrandingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Archived => "archived",
        }
    }
}

parse_stored!(
    BrandingStatus,
    "branding status",
    [Draft, Published, Archived]
);

impl std::fmt::Display for BrandingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Visual assets for branding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrandingAssets {
    /// Logo URL (SVG or PNG recommended). Displayed on login page header.
    pub logo_url: Option<String>,

    /// Favicon URL.
    pub favicon_url: Option<String>,

    /// Background configuration.
    pub background: Option<BackgroundConfig>,
}

/// Background configuration for login pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackgroundConfig {
    /// Solid color background.
    Color { value: String },
    /// Background image URL.
    Image { url: String },
    /// CSS gradient.
    Gradient { value: String },
}

/// Design tokens — CSS custom property values.
///
/// All values are CSS-compatible strings (e.g., "#1a73e8", "Inter, sans-serif", "8px").
/// Applied as `--sid-{token-name}: {value}` custom properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesignTokens {
    /// Primary brand color (buttons, links, active states).
    #[serde(default = "defaults::color_primary")]
    pub color_primary: String,

    /// Primary color hover state.
    #[serde(default = "defaults::color_primary_hover")]
    pub color_primary_hover: String,

    /// Page background color.
    #[serde(default = "defaults::color_background")]
    pub color_background: String,

    /// Surface/card background color.
    #[serde(default = "defaults::color_surface")]
    pub color_surface: String,

    /// Primary text color.
    #[serde(default = "defaults::color_text")]
    pub color_text: String,

    /// Error/danger color.
    #[serde(default = "defaults::color_error")]
    pub color_error: String,

    /// Font family stack.
    #[serde(default = "defaults::font_family")]
    pub font_family: String,

    /// Base font size.
    #[serde(default = "defaults::font_size_base")]
    pub font_size_base: String,

    /// Border radius for inputs, buttons, cards.
    #[serde(default = "defaults::border_radius")]
    pub border_radius: String,

    /// Base spacing unit (used as multiplier).
    #[serde(default = "defaults::spacing_unit")]
    pub spacing_unit: String,

    /// Button style variant.
    #[serde(default)]
    pub button_style: ButtonStyle,

    /// Additional custom tokens (for extensibility).
    #[serde(default)]
    pub custom: HashMap<String, String>,
}

impl Default for DesignTokens {
    fn default() -> Self {
        Self {
            color_primary: defaults::color_primary(),
            color_primary_hover: defaults::color_primary_hover(),
            color_background: defaults::color_background(),
            color_surface: defaults::color_surface(),
            color_text: defaults::color_text(),
            color_error: defaults::color_error(),
            font_family: defaults::font_family(),
            font_size_base: defaults::font_size_base(),
            border_radius: defaults::border_radius(),
            spacing_unit: defaults::spacing_unit(),
            button_style: ButtonStyle::default(),
            custom: HashMap::new(),
        }
    }
}

/// Button visual style.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ButtonStyle {
    /// Standard rounded corners (border-radius from token).
    #[default]
    Rounded,
    /// Sharp square corners.
    Square,
    /// Fully rounded pill shape.
    Pill,
}

/// Dark mode configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DarkModeConfig {
    /// Whether dark mode is enabled.
    pub enabled: bool,

    /// Token overrides for dark mode. Only specified tokens are overridden;
    /// unspecified tokens fall through to the light mode values.
    #[serde(default)]
    pub tokens: DarkModeTokens,
}

/// Dark mode token overrides (only the tokens that differ from light mode).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DarkModeTokens {
    pub color_background: Option<String>,
    pub color_surface: Option<String>,
    pub color_text: Option<String>,
    pub color_primary: Option<String>,
    pub color_primary_hover: Option<String>,
    pub color_error: Option<String>,
    /// Additional custom dark mode tokens.
    #[serde(default)]
    pub custom: HashMap<String, String>,
}

/// Configurable text for login/consent UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrandingText {
    /// Login page title (e.g., "Sign in to Acme").
    pub login_title: Option<String>,

    /// Login page subtitle.
    pub login_subtitle: Option<String>,

    /// Footer text (e.g., "© 2026 Acme Corp").
    pub footer_text: Option<String>,

    /// Terms of service URL.
    pub terms_url: Option<String>,

    /// Privacy policy URL.
    pub privacy_url: Option<String>,

    /// Help/support URL.
    pub help_url: Option<String>,
}

/// Default token values — SID's built-in neutral theme.
mod defaults {
    pub fn color_primary() -> String {
        "#1a73e8".into()
    }
    pub fn color_primary_hover() -> String {
        "#1557b0".into()
    }
    pub fn color_background() -> String {
        "#ffffff".into()
    }
    pub fn color_surface() -> String {
        "#f8f9fa".into()
    }
    pub fn color_text() -> String {
        "#202124".into()
    }
    pub fn color_error() -> String {
        "#d93025".into()
    }
    pub fn font_family() -> String {
        "Inter, system-ui, sans-serif".into()
    }
    pub fn font_size_base() -> String {
        "14px".into()
    }
    pub fn border_radius() -> String {
        "8px".into()
    }
    pub fn spacing_unit() -> String {
        "8px".into()
    }
}

/// Compute WCAG 2.1 relative luminance for a hex color.
///
/// Returns luminance in range [0.0, 1.0] where 0 = black, 1 = white.
/// Returns `None` if the color string is not a valid hex color.
pub fn relative_luminance(hex_color: &str) -> Option<f64> {
    let hex = hex_color.strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }

    let r = u8::from_str_radix(&hex[0..2], 16).ok()? as f64 / 255.0;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()? as f64 / 255.0;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()? as f64 / 255.0;

    let linearize = |c: f64| -> f64 {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };

    Some(0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b))
}

/// Compute WCAG 2.1 contrast ratio between two hex colors.
///
/// Returns ratio in range [1.0, 21.0].
/// WCAG AA requires ≥4.5:1 for normal text, ≥3:1 for large text.
pub fn contrast_ratio(color1: &str, color2: &str) -> Option<f64> {
    let l1 = relative_luminance(color1)?;
    let l2 = relative_luminance(color2)?;
    let lighter = l1.max(l2);
    let darker = l1.min(l2);
    Some((lighter + 0.05) / (darker + 0.05))
}

/// WCAG AA compliance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WcagLevel {
    /// Passes AA for normal text (≥4.5:1).
    AaNormal,
    /// Passes AA for large text only (≥3:1 but <4.5:1).
    AaLargeOnly,
    /// Fails AA (< 3:1).
    Fail,
}

/// Check WCAG AA compliance for a foreground/background color pair.
pub fn check_contrast(foreground: &str, background: &str) -> Option<WcagLevel> {
    let ratio = contrast_ratio(foreground, background)?;
    Some(if ratio >= 4.5 {
        WcagLevel::AaNormal
    } else if ratio >= 3.0 {
        WcagLevel::AaLargeOnly
    } else {
        WcagLevel::Fail
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_design_tokens_default() {
        let tokens = DesignTokens::default();
        assert_eq!(tokens.color_primary, "#1a73e8");
        assert_eq!(tokens.color_background, "#ffffff");
        assert_eq!(tokens.button_style, ButtonStyle::Rounded);
    }

    #[test]
    fn test_branding_config_serde() {
        let config = BrandingConfig {
            id: BrandingConfigId::new(),
            project_id: ProjectId::new(),
            status: BrandingStatus::Draft,
            revision: 0,
            assets: BrandingAssets {
                logo_url: Some("https://acme.com/logo.svg".into()),
                favicon_url: None,
                background: Some(BackgroundConfig::Color {
                    value: "#f5f5f5".into(),
                }),
            },
            tokens: DesignTokens::default(),
            dark_mode: DarkModeConfig {
                enabled: true,
                tokens: DarkModeTokens {
                    color_background: Some("#1e1e1e".into()),
                    color_text: Some("#e8eaed".into()),
                    ..Default::default()
                },
            },
            text: BrandingText {
                login_title: Some("Sign in to Acme".into()),
                ..Default::default()
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: BrandingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, BrandingStatus::Draft);
        assert_eq!(
            parsed.assets.logo_url.as_deref(),
            Some("https://acme.com/logo.svg")
        );
        assert!(parsed.dark_mode.enabled);
    }

    #[test]
    fn test_background_config_variants() {
        let color = BackgroundConfig::Color {
            value: "#ffffff".into(),
        };
        let json = serde_json::to_string(&color).unwrap();
        assert!(json.contains("\"type\":\"color\""));

        let image = BackgroundConfig::Image {
            url: "https://example.com/bg.jpg".into(),
        };
        let json = serde_json::to_string(&image).unwrap();
        assert!(json.contains("\"type\":\"image\""));

        let gradient = BackgroundConfig::Gradient {
            value: "linear-gradient(135deg, #667eea, #764ba2)".into(),
        };
        let json = serde_json::to_string(&gradient).unwrap();
        assert!(json.contains("\"type\":\"gradient\""));
    }

    #[test]
    fn test_branding_status_display() {
        assert_eq!(BrandingStatus::Draft.to_string(), "draft");
        assert_eq!(BrandingStatus::Published.to_string(), "published");
        assert_eq!(BrandingStatus::Archived.to_string(), "archived");
    }

    #[test]
    fn test_button_style_serde() {
        let styles = [ButtonStyle::Rounded, ButtonStyle::Square, ButtonStyle::Pill];
        for style in &styles {
            let json = serde_json::to_string(style).unwrap();
            let parsed: ButtonStyle = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, style);
        }
    }

    #[test]
    fn test_relative_luminance() {
        // White = 1.0
        let white = relative_luminance("#ffffff").unwrap();
        assert!((white - 1.0).abs() < 0.001);

        // Black = 0.0
        let black = relative_luminance("#000000").unwrap();
        assert!(black.abs() < 0.001);

        // Invalid
        assert!(relative_luminance("not-a-color").is_none());
        assert!(relative_luminance("#fff").is_none()); // 3-digit not supported
    }

    #[test]
    fn test_contrast_ratio_black_white() {
        let ratio = contrast_ratio("#000000", "#ffffff").unwrap();
        assert!((ratio - 21.0).abs() < 0.1);
    }

    #[test]
    fn test_contrast_ratio_same_color() {
        let ratio = contrast_ratio("#1a73e8", "#1a73e8").unwrap();
        assert!((ratio - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_check_contrast_aa() {
        // Black on white = 21:1 → AA normal pass
        assert_eq!(
            check_contrast("#000000", "#ffffff"),
            Some(WcagLevel::AaNormal)
        );

        // Light gray on white → likely fail
        let level = check_contrast("#cccccc", "#ffffff").unwrap();
        assert_eq!(level, WcagLevel::Fail);
    }

    #[test]
    fn test_default_theme_contrast() {
        // Verify SID default theme passes WCAG AA
        let tokens = DesignTokens::default();
        let level = check_contrast(&tokens.color_text, &tokens.color_background).unwrap();
        assert_eq!(level, WcagLevel::AaNormal);
    }

    #[test]
    fn test_design_tokens_serde_with_defaults() {
        // Deserialize with missing fields should use defaults
        let json = r##"{"color_primary": "#ff0000"}"##;
        let tokens: DesignTokens = serde_json::from_str(json).unwrap();
        assert_eq!(tokens.color_primary, "#ff0000");
        assert_eq!(tokens.color_background, "#ffffff"); // default
        assert_eq!(tokens.font_family, "Inter, system-ui, sans-serif"); // default
    }

    #[test]
    fn test_dark_mode_config_default() {
        let dark = DarkModeConfig::default();
        assert!(!dark.enabled);
        assert!(dark.tokens.color_background.is_none());
    }

    #[test]
    fn test_branding_text_default() {
        let text = BrandingText::default();
        assert!(text.login_title.is_none());
        assert!(text.terms_url.is_none());
    }

    #[test]
    fn test_branding_config_id_unique() {
        let id1 = BrandingConfigId::new();
        let id2 = BrandingConfigId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_custom_tokens() {
        let mut tokens = DesignTokens::default();
        tokens
            .custom
            .insert("color-accent".into(), "#e91e63".into());
        tokens
            .custom
            .insert("shadow-depth".into(), "0 2px 4px rgba(0,0,0,0.1)".into());

        let json = serde_json::to_string(&tokens).unwrap();
        let parsed: DesignTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.custom.get("color-accent").unwrap(), "#e91e63");
    }
}
