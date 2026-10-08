// SPDX-License-Identifier: AGPL-3.0-only
//! Auth translation — header and cookie modes for upstream apps.
//!
//! CE supports two modes:
//! - **header**: template-based header injection (e.g., `X-WEBAUTH-USER: "{{ .Email }}"`)
//! - **cookie**: set session cookie on upstream domain with JWT

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

use sid_auth::auth::jwt::ForwardAuthClaims;

/// Auth translation configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthTranslation {
    pub mode: TranslationMode,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub cookie: Option<CookieTranslation>,
}

/// Translation mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranslationMode {
    Header,
    Cookie,
}

/// Cookie translation config.
#[derive(Debug, Clone, Deserialize)]
pub struct CookieTranslation {
    pub name: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_true")]
    pub secure: bool,
    #[serde(default = "default_true")]
    pub http_only: bool,
    #[serde(default = "default_same_site")]
    pub same_site: String,
    #[serde(default = "default_content")]
    pub content: String,
}

fn default_true() -> bool {
    true
}
fn default_same_site() -> String {
    "lax".into()
}
fn default_content() -> String {
    "jwt".into()
}

/// Apply auth translation to produce headers for the upstream.
pub fn translate(
    claims: &ForwardAuthClaims,
    config: &AuthTranslation,
    raw_token: Option<&str>,
) -> HeaderMap {
    match config.mode {
        TranslationMode::Header => translate_headers(claims, &config.headers),
        TranslationMode::Cookie => translate_cookie(config, raw_token),
    }
}

/// Header mode: render templates in header values.
fn translate_headers(
    claims: &ForwardAuthClaims,
    templates: &std::collections::HashMap<String, String>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for (name, template) in templates {
        let value = render_template(template, claims);
        if let (Ok(name), Ok(val)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, val);
        }
    }

    headers
}

/// Cookie mode: set a cookie with the JWT.
fn translate_cookie(config: &AuthTranslation, raw_token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let (Some(cookie_config), Some(token)) = (&config.cookie, raw_token) {
        let mut cookie = format!("{}={}", cookie_config.name, token);
        if let Some(domain) = &cookie_config.domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }
        if cookie_config.secure {
            cookie.push_str("; Secure");
        }
        if cookie_config.http_only {
            cookie.push_str("; HttpOnly");
        }
        cookie.push_str(&format!("; SameSite={}", cookie_config.same_site));
        cookie.push_str("; Path=/");

        if let Ok(val) = HeaderValue::from_str(&cookie) {
            headers.insert("set-cookie", val);
        }
    }

    headers
}

/// Simple template renderer for auth translation headers.
///
/// Supported placeholders:
/// - `{{ .Email }}` — primary email
/// - `{{ .Subject }}` — OIDC `sub` claim (polymorphic: UUID or pairwise hash)
/// - `{{ .User }}` — **deprecated alias** for `{{ .Subject }}` (backwards compat)
/// - `{{ .DisplayName }}` — display name
/// - `{{ .Groups }}` — comma-separated roles
/// - `{{ .Groups | join ';' }}` — semicolon-separated roles
/// - `{{ .PreferredUsername }}` — username
fn render_template(template: &str, claims: &ForwardAuthClaims) -> String {
    let mut result = template.to_string();

    result = result.replace("{{ .Email }}", claims.email.as_deref().unwrap_or(""));
    result = result.replace("{{ .Subject }}", &claims.sub);
    // Backwards compatibility: {{ .User }} is deprecated alias for {{ .Subject }}
    result = result.replace("{{ .User }}", &claims.sub);
    result = result.replace("{{ .DisplayName }}", claims.name.as_deref().unwrap_or(""));
    result = result.replace(
        "{{ .PreferredUsername }}",
        claims.preferred_username.as_deref().unwrap_or(""),
    );

    // Groups with custom separator
    if result.contains("{{ .Groups | join ';' }}") {
        let groups = claims.roles.replace(' ', ";");
        result = result.replace("{{ .Groups | join ';' }}", &groups);
    }
    if result.contains("{{ .Groups | join ',' }}") {
        let groups = claims.roles.replace(' ', ",");
        result = result.replace("{{ .Groups | join ',' }}", &groups);
    }
    // Default groups (comma-separated)
    if result.contains("{{ .Groups }}") {
        let groups = claims.roles.replace(' ', ",");
        result = result.replace("{{ .Groups }}", &groups);
    }

    result
}

#[cfg(test)]
mod tests;
