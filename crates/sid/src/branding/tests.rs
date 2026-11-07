use super::*;
use sid_core::models::ProjectId;

#[test]
fn test_tokens_roundtrip() {
    let domain = DesignTokens::default();
    let proto = tokens_to_proto(&domain);
    let back = tokens_from_proto(&proto);
    assert_eq!(back.color_primary, domain.color_primary);
    assert_eq!(back.color_background, domain.color_background);
    assert_eq!(back.button_style, domain.button_style);
}

#[test]
fn test_tokens_empty_uses_defaults() {
    let domain = tokens_from_proto(&pb::DesignTokens::default());
    assert_eq!(domain.color_primary, "#1a73e8");
    assert_eq!(domain.font_family, "Inter, system-ui, sans-serif");
}

#[test]
fn test_assets_roundtrip() {
    let domain = BrandingAssets {
        logo_url: Some("https://example.com/logo.svg".into()),
        favicon_url: None,
        background: Some(BackgroundConfig::Gradient {
            value: "linear-gradient(135deg, #667eea, #764ba2)".into(),
        }),
    };
    let back = assets_from_proto(&assets_to_proto(&domain));
    assert_eq!(back.logo_url, domain.logo_url);
    assert!(back.favicon_url.is_none());
    assert!(matches!(
        back.background,
        Some(BackgroundConfig::Gradient { .. })
    ));
}

#[test]
fn test_dark_mode_roundtrip() {
    let domain = DarkModeConfig {
        enabled: true,
        tokens: DarkModeTokens {
            color_background: Some("#1e1e1e".into()),
            color_text: Some("#e8eaed".into()),
            ..Default::default()
        },
    };
    let back = dark_mode_from_proto(&dark_mode_to_proto(&domain));
    assert!(back.enabled);
    assert_eq!(back.tokens.color_background.as_deref(), Some("#1e1e1e"));
    assert_eq!(back.tokens.color_text.as_deref(), Some("#e8eaed"));
    assert!(back.tokens.color_surface.is_none());
}

#[test]
fn test_text_roundtrip() {
    let domain = BrandingText {
        login_title: Some("Sign in".into()),
        terms_url: Some("https://example.com/terms".into()),
        ..Default::default()
    };
    let back = text_from_proto(&text_to_proto(&domain));
    assert_eq!(back.login_title.as_deref(), Some("Sign in"));
    assert_eq!(back.terms_url.as_deref(), Some("https://example.com/terms"));
    assert!(back.login_subtitle.is_none());
}

#[test]
fn test_domain_to_proto_status() {
    let config = BrandingConfig {
        id: BrandingConfigId::generate(),
        project_id: ProjectId::generate(),
        status: BrandingStatus::Published,
        revision: 0,
        tokens: DesignTokens::default(),
        assets: BrandingAssets::default(),
        dark_mode: DarkModeConfig::default(),
        text: BrandingText::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    assert_eq!(
        domain_to_proto(&config).status,
        i32::from(pb::BrandingStatus::Published)
    );
}

#[test]
fn test_opt_string() {
    assert_eq!(opt_string(""), None);
    assert_eq!(opt_string("hello"), Some("hello".to_string()));
}

#[test]
fn test_non_empty_or() {
    assert_eq!(non_empty_or("", "default"), "default");
    assert_eq!(non_empty_or("value", "default"), "value");
}

fn pair(foreground: &str, background: &str) -> pb::ColorPair {
    pb::ColorPair {
        foreground: foreground.into(),
        background: background.into(),
    }
}

/// WCAG 2.1 contrast of known pairs, in either order, with its level:
/// black on white is the maximum 21:1; #767676 on white is the lightest grey
/// that passes AA for normal text (4.54:1); #777777 passes only for large
/// text (4.48:1); #aaaaaa fails (2.32:1). The shorthand #fff is #ffffff.
#[test]
fn test_contrast_of_known_pairs() {
    let cases = [
        ("#000000", "#ffffff", 21.0, pb::WcagLevel::AaNormal),
        ("#fff", "#000", 21.0, pb::WcagLevel::AaNormal),
        ("#767676", "#FFFFFF", 4.54, pb::WcagLevel::AaNormal),
        ("#777777", "#ffffff", 4.48, pb::WcagLevel::AaLargeOnly),
        ("#aaaaaa", "#ffffff", 2.32, pb::WcagLevel::Fail),
    ];
    for (fg, bg, ratio, level) in cases {
        let check = contrast_check(&pair(fg, bg)).unwrap();
        assert!(
            (check.ratio - ratio).abs() < 0.01,
            "{fg} on {bg}: {}",
            check.ratio
        );
        assert_eq!(check.level, level as i32, "{fg} on {bg}");
        assert_eq!(
            (check.foreground.as_str(), check.background.as_str()),
            (fg, bg)
        );
    }
}

/// A color that is not #rgb or #rrggbb is refused naming the field, without
/// repeating the value.
#[test]
fn test_contrast_refuses_a_color_it_cannot_read() {
    for (fg, bg) in [
        ("red", "#ffffff"),
        ("#ffffff", "#12345"),
        ("#gggggg", "#000"),
    ] {
        match contrast_check(&pair(fg, bg)) {
            Err(BrandingError::InvalidField { field, reason }) => {
                assert_eq!(field, "pairs");
                assert!(!reason.contains("gggggg"));
            }
            other => panic!("{fg} on {bg}: {other:?}"),
        }
    }
}
