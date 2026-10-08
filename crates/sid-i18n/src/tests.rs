use super::*;

#[test]
fn test_available_locales_contains_en() {
    let locales = available_locales();
    assert!(locales.contains(&"en"));
}

#[test]
fn test_load_locale_en_auth() {
    let json = load_locale("en", "auth");
    assert!(json.is_some());
    let parsed: serde_json::Value = serde_json::from_str(json.unwrap()).unwrap();
    assert!(parsed.get("login").is_some());
    assert!(parsed["login"]["title"].as_str() == Some("Sign in"));
}

#[test]
fn test_load_locale_en_errors() {
    let json = load_locale("en", "errors");
    assert!(json.is_some());
    let parsed: serde_json::Value = serde_json::from_str(json.unwrap()).unwrap();
    assert!(parsed["auth"]["invalid_credentials"].as_str().is_some());
}

#[test]
fn test_load_locale_unknown() {
    assert!(load_locale("xx", "auth").is_none());
    assert!(load_locale("en", "nonexistent").is_none());
}

#[test]
fn test_is_locale_available() {
    assert!(is_locale_available("en"));
    assert!(!is_locale_available("xx"));
}

#[test]
fn test_t_basic() {
    let msg = t("en", "errors.auth.invalid_credentials");
    assert_eq!(msg, Some("Invalid email or password"));
}

/// Regression: a lookup returns the string stored once at initialization. It
/// must not allocate (and leak) a new copy on every call, which grew memory
/// with every localized error a service returned.
#[test]
fn test_t_returns_stored_string_without_allocating() {
    let first = t("en", "errors.auth.invalid_credentials").unwrap();
    let second = t("en", "errors.auth.invalid_credentials").unwrap();
    assert!(std::ptr::eq(first, second));
    let fallback_first = t("xx", "errors.auth.invalid_credentials").unwrap();
    assert!(std::ptr::eq(first, fallback_first));
}

#[test]
fn test_t_nested_key() {
    let msg = t("en", "auth.login.title");
    assert_eq!(msg, Some("Sign in"));
}

#[test]
fn test_t_missing_key() {
    assert!(t("en", "nonexistent.key").is_none());
}

#[test]
fn test_t_fallback_to_en() {
    // Unknown locale falls back to English
    let msg = t("xx", "errors.auth.invalid_credentials");
    assert_eq!(msg, Some("Invalid email or password"));
}

#[test]
fn test_t_fmt_substitution() {
    let msg = t_fmt("en", "errors.auth.account_locked", &[("minutes", "15")]);
    assert!(msg.is_some());
    let text = msg.unwrap();
    assert!(text.contains("15 minutes"), "got: {text}");
}

#[test]
fn test_t_fmt_multiple_params() {
    let msg = t_fmt(
        "en",
        "errors.validation.too_short",
        &[("field", "Password"), ("min", "8")],
    );
    assert!(msg.is_some());
    let text = msg.unwrap();
    assert!(text.contains("Password"), "got: {text}");
    assert!(text.contains("8"), "got: {text}");
}

#[test]
fn test_all_namespaces_loadable() {
    for &ns in NAMESPACES {
        let json = load_locale("en", ns);
        assert!(json.is_some(), "namespace {ns} should be loadable");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json.unwrap());
        assert!(parsed.is_ok(), "namespace {ns} should be valid JSON");
    }
}

#[test]
fn test_consent_strings() {
    let msg = t("en", "consent.title");
    assert!(msg.is_some());
    assert!(msg.unwrap().contains("access your account"));
}

#[test]
fn test_common_buttons() {
    assert_eq!(t("en", "common.buttons.save"), Some("Save"));
    assert_eq!(t("en", "common.buttons.cancel"), Some("Cancel"));
    assert_eq!(t("en", "common.buttons.delete"), Some("Delete"));
}

#[test]
fn test_admin_nav() {
    assert_eq!(t("en", "admin.nav.dashboard"), Some("Dashboard"));
    assert_eq!(t("en", "admin.nav.profiles"), Some("Users"));
}

#[test]
fn test_scim_errors() {
    let msg = t("en", "scim.errors.invalid_filter");
    assert_eq!(msg, Some("Invalid SCIM filter expression"));
}

#[test]
fn test_saml_errors() {
    let msg = t("en", "saml.errors.invalid_response");
    assert_eq!(msg, Some("Invalid SAML response"));
}

// Ukrainian locale tests (require i18n-uk feature)
#[cfg(feature = "i18n-uk")]
mod uk_tests {
    use super::super::*;

    #[test]
    fn test_uk_available() {
        assert!(is_locale_available("uk"));
    }

    #[test]
    fn test_uk_all_namespaces_loadable() {
        for &ns in NAMESPACES {
            let json = load_locale("uk", ns);
            assert!(json.is_some(), "uk namespace {ns} should be loadable");
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(json.unwrap());
            assert!(parsed.is_ok(), "uk namespace {ns} should be valid JSON");
        }
    }

    #[test]
    fn test_uk_t_basic() {
        let msg = t("uk", "errors.auth.invalid_credentials");
        assert!(msg.is_some());
        assert_ne!(msg, t("en", "errors.auth.invalid_credentials"));
    }

    #[test]
    fn test_uk_auth_login() {
        assert_eq!(t("uk", "auth.login.title"), Some("Вхід"));
        assert_eq!(t("uk", "auth.login.submit"), Some("Увійти"));
    }

    #[test]
    fn test_uk_common_buttons() {
        assert_eq!(t("uk", "common.buttons.save"), Some("Зберегти"));
        assert_eq!(t("uk", "common.buttons.cancel"), Some("Скасувати"));
        assert_eq!(t("uk", "common.buttons.delete"), Some("Видалити"));
    }

    #[test]
    fn test_uk_consent() {
        let msg = t("uk", "consent.approve");
        assert_eq!(msg, Some("Дозволити"));
    }

    #[test]
    fn test_uk_admin_nav() {
        assert_eq!(t("uk", "admin.nav.dashboard"), Some("Панель керування"));
        assert_eq!(t("uk", "admin.nav.profiles"), Some("Користувачі"));
    }

    #[test]
    fn test_uk_t_fmt_substitution() {
        let msg = t_fmt("uk", "errors.auth.account_locked", &[("minutes", "15")]);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("15"));
    }

    #[test]
    fn test_uk_negotiate() {
        assert_eq!(negotiate_locale("uk"), "uk");
        assert_eq!(negotiate_locale("uk-UA"), "uk");
    }

    #[test]
    fn test_uk_key_parity_with_en() {
        // Every English key should exist in Ukrainian
        let cache = LOCALE_CACHE.get_or_init(init_cache);
        let en_flat = cache.get("en").expect("en locale must exist");
        let uk_flat = cache.get("uk").expect("uk locale must exist");

        let mut missing = Vec::new();
        for key in en_flat.keys() {
            if !uk_flat.contains_key(key) {
                missing.push(*key);
            }
        }
        assert!(
            missing.is_empty(),
            "Ukrainian locale is missing keys present in English: {:?}",
            missing
        );
    }
}
