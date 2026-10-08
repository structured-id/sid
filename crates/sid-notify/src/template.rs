// SPDX-License-Identifier: AGPL-3.0-only
//! Template engine for notification rendering.
//!
//! Renders event data into channel-specific messages using Handlebars templates.
//! Templates support `{{variable}}` substitution, conditionals (`{{#if}}`),
//! loops (`{{#each}}`), and nested field access (`{{data.field}}`).
//!
//! Legacy `{variable}` syntax is auto-converted to `{{variable}}` for
//! backward compatibility with templates stored in the database.

use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sid_core::models::event::Event;
use sid_plugin::notification::{NotificationPriority, RenderedMessage};
use std::collections::HashMap;
use thiserror::Error;

/// Template rendering error.
#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("template not found: {0}")]
    NotFound(String),

    #[error("render error: {0}")]
    RenderFailed(String),
}

/// A notification template with channel-specific variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTemplate {
    /// Template identifier.
    pub name: String,

    /// Email subject template (supports `{{variable}}` substitution).
    pub subject: Option<String>,

    /// HTML body template.
    pub body_html: String,

    /// Plain text body template.
    pub body_text: String,

    /// Default priority (can be overridden by routing rule).
    pub default_priority: NotificationPriority,
}

/// Template engine managing notification templates.
pub struct TemplateEngine {
    templates: HashMap<String, NotificationTemplate>,
    hbs: Handlebars<'static>,
}

impl TemplateEngine {
    /// Create a new template engine.
    pub fn new() -> Self {
        let mut hbs = Handlebars::new();
        // Disable HTML escaping — templates render for email/SMS/push,
        // variables come from SID's own events, not user input.
        hbs.set_strict_mode(false);
        hbs.register_escape_fn(handlebars::no_escape);

        Self {
            templates: HashMap::new(),
            hbs,
        }
    }

    /// Register a template.
    pub fn register(&mut self, template: NotificationTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    /// Get a template by name.
    pub fn get(&self, name: &str) -> Option<&NotificationTemplate> {
        self.templates.get(name)
    }

    /// Render an event into a notification message using the named template.
    pub fn render(
        &self,
        template_name: &str,
        event: &Event,
        priority: NotificationPriority,
    ) -> Result<RenderedMessage, TemplateError> {
        let template = self
            .templates
            .get(template_name)
            .ok_or_else(|| TemplateError::NotFound(template_name.to_string()))?;

        let ctx = build_context(event);

        let subject = template
            .subject
            .as_ref()
            .map(|s| render_handlebars(&self.hbs, s, &ctx))
            .transpose()?;
        let body = render_handlebars(&self.hbs, &template.body_html, &ctx)?;
        let body_text = Some(render_handlebars(&self.hbs, &template.body_text, &ctx)?);

        Ok(RenderedMessage {
            subject,
            body,
            body_text,
            priority,
            event_type: event.event_type.clone(),
        })
    }

    /// Number of registered templates.
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Check if no templates are registered.
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// Create a template engine with default CE templates.
    pub fn with_default_ce_templates() -> Self {
        let mut engine = Self::new();

        engine.register(NotificationTemplate {
            name: "security_alert".into(),
            subject: Some("Security Alert: {{event_type}}".into()),
            body_html: "<h2>Security Alert</h2><p>Event: {{event_type}}</p><p>Source: {{source}}</p><p>Time: {{time}}</p><p>Details: {{data_json}}</p>".into(),
            body_text: "Security Alert\n\nEvent: {{event_type}}\nSource: {{source}}\nTime: {{time}}\nDetails: {{data_json}}".into(),
            default_priority: NotificationPriority::Critical,
        });

        engine.register(NotificationTemplate {
            name: "new_session".into(),
            subject: Some("New login to your account".into()),
            body_html: "<h2>New Login Detected</h2><p>A new session was created for your account.</p><p>Time: {{time}}</p><p>Details: {{data_json}}</p>".into(),
            body_text: "New Login Detected\n\nA new session was created for your account.\nTime: {{time}}\nDetails: {{data_json}}".into(),
            default_priority: NotificationPriority::Informational,
        });

        engine.register(NotificationTemplate {
            name: "credential_change".into(),
            subject: Some("Credential change on your account".into()),
            body_html: "<h2>Credential Changed</h2><p>A credential was modified on your account.</p><p>Event: {{event_type}}</p><p>Time: {{time}}</p>".into(),
            body_text: "Credential Changed\n\nA credential was modified on your account.\nEvent: {{event_type}}\nTime: {{time}}".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "mfa_change".into(),
            subject: Some("MFA settings changed".into()),
            body_html: "<h2>MFA Change</h2><p>Your multi-factor authentication settings were updated.</p><p>Event: {{event_type}}</p><p>Time: {{time}}</p>".into(),
            body_text: "MFA Change\n\nYour multi-factor authentication settings were updated.\nEvent: {{event_type}}\nTime: {{time}}".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "cert_expiry".into(),
            subject: Some("Certificate expiring soon".into()),
            body_html: "<h2>Certificate Expiry Warning</h2><p>A certificate is about to expire.</p><p>Details: {{data_json}}</p><p>Time: {{time}}</p>".into(),
            body_text: "Certificate Expiry Warning\n\nA certificate is about to expire.\nDetails: {{data_json}}\nTime: {{time}}".into(),
            default_priority: NotificationPriority::Critical,
        });

        engine.register(NotificationTemplate {
            name: "role_expiry".into(),
            subject: Some("Role assignment expiring: {{data.role}}".into()),
            body_html: "<h2>Role Expiry</h2><p>A temporary role assignment is expiring.</p><p>Event: {{event_type}}</p><p>Details: {{data_json}}</p><p>Time: {{time}}</p>".into(),
            body_text: "Role Expiry\n\nA temporary role assignment is expiring.\nEvent: {{event_type}}\nDetails: {{data_json}}\nTime: {{time}}".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "trial_onboarding".into(),
            subject: Some("Welcome to StructuredID — {{data.org_name}} trial activated".into()),
            body_html: "<h2>Welcome to StructuredID</h2>\
                <p>Your organization <strong>{{data.org_name}}</strong> is now active on <code>{{data.domain}}</code>.</p>\
                <h3>Getting Started</h3>\
                <ul>\
                <li>Sign in to your admin dashboard at <code>{{data.domain}}</code></li>\
                <li>Create your first application (OAuth2 client)</li>\
                <li>Invite team members (up to {{data.trial_users_limit}} during trial)</li>\
                <li>Configure authentication policies</li>\
                </ul>\
                <p>Your trial runs for {{data.trial_days_remaining}} days (until {{data.trial_end_date}}).</p>\
                <p>Need help? Visit our documentation or contact support.</p>".into(),
            body_text: "Welcome to StructuredID\n\n\
                Your organization {{data.org_name}} is now active on {{data.domain}}.\n\n\
                Getting Started:\n\
                - Sign in to your admin dashboard at {{data.domain}}\n\
                - Create your first application (OAuth2 client)\n\
                - Invite team members (up to {{data.trial_users_limit}} during trial)\n\
                - Configure authentication policies\n\n\
                Your trial runs for {{data.trial_days_remaining}} days (until {{data.trial_end_date}}).\n\n\
                Need help? Visit our documentation or contact support.".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "principal_contested".into(),
            subject: Some("Someone is claiming your {{data.principal_type}}: {{data.principal_value}}".into()),
            body_html: "<h2>Principal Ownership Contested</h2>\
                <p>Another account has bound your {{data.principal_type}} <strong>{{data.principal_value}}</strong> to their profile.</p>\
                <p>Until this is resolved, only the verified owner can use it to sign in.</p>\
                <p>To establish priority, verify your ownership by confirming the {{data.principal_type}} in your account settings.</p>\
                <p>Time: {{time}}</p>".into(),
            body_text: "Principal Ownership Contested\n\n\
                Another account has bound your {{data.principal_type}} {{data.principal_value}} to their profile.\n\
                Until this is resolved, only the verified owner can use it to sign in.\n\
                To establish priority, verify your ownership in your account settings.\n\
                Time: {{time}}".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "principal_lost".into(),
            subject: None, // push only — no email subject needed
            body_html: "<h2>Login Method Access Lost</h2>\
                <p>You no longer have verified access to <strong>{{data.principal_value}}</strong> ({{data.principal_type}}) as a login method.</p>\
                <p>Another profile has become the verified owner. You may re-add and verify it if you still control this {{data.principal_type}}.</p>".into(),
            body_text: "Login Method Access Lost\n\n\
                You no longer have verified access to {{data.principal_value}} ({{data.principal_type}}) as a login method.\n\
                Another profile has become the verified owner.\n\
                You may re-add and verify it if you still control this {{data.principal_type}}.".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "principal_ownership_superseded".into(),
            subject: None, // push only — no email subject needed
            body_html: "<h2>Verified Ownership Superseded</h2>\
                <p>Your verified ownership of <strong>{{data.principal_value}}</strong> ({{data.principal_type}}) has been superseded by another account.</p>\
                <p>This {{data.principal_type}} can no longer be used as your primary login method until you re-verify it.</p>".into(),
            body_text: "Verified Ownership Superseded\n\n\
                Your verified ownership of {{data.principal_value}} ({{data.principal_type}}) has been superseded by another account.\n\
                This {{data.principal_type}} can no longer be used as your primary login method until you re-verify it.".into(),
            default_priority: NotificationPriority::Transactional,
        });

        engine.register(NotificationTemplate {
            name: "scim_outbound_failure".into(),
            subject: Some("SCIM provisioning failed: {{data.target_name}}".into()),
            body_html: "<h2>SCIM Outbound Failure</h2><p>Failed to provision to downstream app <strong>{{data.target_name}}</strong>.</p><p>Event: {{data.event_type}}</p><p>Error: {{data.error}}</p><p>Error class: {{data.error_class}}</p><p>Time: {{time}}</p>".into(),
            body_text: "SCIM Outbound Failure\n\nFailed to provision to downstream app: {{data.target_name}}\nEvent: {{data.event_type}}\nError: {{data.error}}\nError class: {{data.error_class}}\nTime: {{time}}".into(),
            default_priority: NotificationPriority::Critical,
        });

        engine
    }
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a Handlebars context from an event.
///
/// Context structure:
/// - `event_type`, `source`, `time`, `id`, `subject` — top-level strings
/// - `data` — the raw event data object (nested field access via `{{data.field}}`)
/// - `data_json` — serialized data as string (for templates that want raw JSON)
fn build_context(event: &Event) -> serde_json::Value {
    let data_json = if event.data.is_null() {
        String::new()
    } else {
        serde_json::to_string(&event.data).unwrap_or_default()
    };

    let mut ctx = json!({
        "event_type": event.event_type,
        "source": event.source,
        "time": event.time.to_rfc3339(),
        "id": event.id,
        "data": event.data,
        "data_json": data_json,
    });

    if let Some(ref subject) = event.subject {
        ctx["subject"] = json!(subject);
    }

    ctx
}

/// Render a Handlebars template string with the given context.
///
/// Auto-converts legacy `{var}` syntax to `{{var}}` for backward compatibility.
fn render_handlebars(
    hbs: &Handlebars<'_>,
    template: &str,
    ctx: &serde_json::Value,
) -> Result<String, TemplateError> {
    let converted = convert_legacy_syntax(template);
    hbs.render_template(&converted, ctx)
        .map_err(|e| TemplateError::RenderFailed(e.to_string()))
}

/// Convert legacy `{variable}` syntax to Handlebars `{{variable}}` syntax.
///
/// Only converts patterns that look like template variables (alphanumeric + dot + underscore).
/// Skips sequences that are already Handlebars syntax (`{{...}}`).
///
/// Uses byte offsets throughout to avoid panics with multi-byte UTF-8 characters.
pub(crate) fn convert_legacy_syntax(template: &str) -> String {
    let bytes = template.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'{' {
            // Already Handlebars syntax — skip `{{...}}`
            if i + 1 < len
                && bytes[i + 1] == b'{'
                && let Some(end) = template[i + 2..].find("}}")
            {
                let end_pos = i + 2 + end + 2;
                result.push_str(&template[i..end_pos]);
                i = end_pos;
                continue;
            }

            // Legacy syntax — single `{var}`: convert to `{{var}}`
            if let Some(end) = template[i + 1..].find('}') {
                let var_name = &template[i + 1..i + 1 + end];
                // Only convert if it looks like a variable name (ASCII only)
                if !var_name.is_empty()
                    && var_name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                {
                    result.push_str("{{");
                    result.push_str(var_name);
                    result.push_str("}}");
                    i = i + 1 + end + 1;
                    continue;
                }
            }
        }

        // Advance by one UTF-8 character (may be multi-byte)
        let ch_len = utf8_char_len(bytes[i]);
        result.push_str(&template[i..i + ch_len]);
        i += ch_len;
    }

    result
}

/// Return the byte length of a UTF-8 character from its leading byte.
fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

/// Render a template string with variables for preview/test.
///
/// Used by `TemplateStore::render_preview()` and gRPC handlers.
pub(crate) fn render_with_vars(template: &str, vars: &HashMap<String, String>) -> String {
    let hbs = Handlebars::new();
    let converted = convert_legacy_syntax(template);
    // Build a JSON context from the flat variable map, supporting dot-notation keys.
    let ctx = vars_to_context(vars);
    hbs.render_template(&converted, &ctx)
        .unwrap_or_else(|_| template.to_string())
}

/// Convert a flat `HashMap<String, String>` to a nested JSON context.
///
/// Keys with dots (e.g., `data.ip`) are nested: `{"data": {"ip": "..."}}`
fn vars_to_context(vars: &HashMap<String, String>) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    for (key, value) in vars {
        if let Some((prefix, suffix)) = key.split_once('.') {
            let nested = root.entry(prefix).or_insert_with(|| json!({}));
            if let Some(obj) = nested.as_object_mut() {
                obj.insert(suffix.to_string(), json!(value));
            }
        } else {
            root.insert(key.clone(), json!(value));
        }
    }

    serde_json::Value::Object(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_core::models::event::{Event, event_types};

    #[test]
    fn test_template_engine_register_and_get() {
        let mut engine = TemplateEngine::new();
        assert!(engine.is_empty());

        engine.register(NotificationTemplate {
            name: "test".into(),
            subject: Some("Test".into()),
            body_html: "<p>Test</p>".into(),
            body_text: "Test".into(),
            default_priority: NotificationPriority::Informational,
        });

        assert_eq!(engine.len(), 1);
        assert!(engine.get("test").is_some());
        assert!(engine.get("nonexistent").is_none());
    }

    #[test]
    fn test_render_basic() {
        let mut engine = TemplateEngine::new();
        engine.register(NotificationTemplate {
            name: "alert".into(),
            subject: Some("Alert: {{event_type}}".into()),
            body_html: "<p>Event: {{event_type}}, Source: {{source}}</p>".into(),
            body_text: "Event: {{event_type}}, Source: {{source}}".into(),
            default_priority: NotificationPriority::Critical,
        });

        let event = Event::new("sid-identity.test", event_types::SECURITY_BRUTE_FORCE);
        let msg = engine
            .render("alert", &event, NotificationPriority::Critical)
            .unwrap();

        assert_eq!(
            msg.subject.as_deref(),
            Some("Alert: sid.security.brute_force.v1")
        );
        assert!(msg.body.contains("sid.security.brute_force.v1"));
        assert!(msg.body.contains("sid-identity.test"));
        assert_eq!(msg.priority, NotificationPriority::Critical);
        assert_eq!(msg.event_type, event_types::SECURITY_BRUTE_FORCE);
    }

    #[test]
    fn test_render_with_data_fields() {
        let mut engine = TemplateEngine::new();
        engine.register(NotificationTemplate {
            name: "login".into(),
            subject: Some("Login from {{data.ip}}".into()),
            body_html: "<p>IP: {{data.ip}}, UA: {{data.user_agent}}</p>".into(),
            body_text: "IP: {{data.ip}}".into(),
            default_priority: NotificationPriority::Informational,
        });

        let event = Event::new("src", event_types::SESSION_CREATED)
            .with_data(serde_json::json!({"ip": "1.2.3.4", "user_agent": "Firefox"}));

        let msg = engine
            .render("login", &event, NotificationPriority::Informational)
            .unwrap();

        assert_eq!(msg.subject.as_deref(), Some("Login from 1.2.3.4"));
        assert!(msg.body.contains("1.2.3.4"));
        assert!(msg.body.contains("Firefox"));
    }

    #[test]
    fn test_render_not_found() {
        let engine = TemplateEngine::new();
        let event = Event::new("src", "test.event.v1");
        let err = engine
            .render("missing", &event, NotificationPriority::Informational)
            .unwrap_err();
        assert!(err.to_string().contains("template not found"));
    }

    #[test]
    fn test_default_ce_templates() {
        let engine = TemplateEngine::with_default_ce_templates();
        assert!(engine.len() >= 7);

        assert!(engine.get("security_alert").is_some());
        assert!(engine.get("new_session").is_some());
        assert!(engine.get("credential_change").is_some());
        assert!(engine.get("mfa_change").is_some());
        assert!(engine.get("cert_expiry").is_some());
        assert!(engine.get("role_expiry").is_some());
        assert!(engine.get("scim_outbound_failure").is_some());
    }

    #[test]
    fn test_default_templates_render() {
        let engine = TemplateEngine::with_default_ce_templates();
        let event = Event::new("sid-identity", event_types::SECURITY_BRUTE_FORCE)
            .with_data(serde_json::json!({"ip": "1.2.3.4"}));

        let msg = engine
            .render("security_alert", &event, NotificationPriority::Critical)
            .unwrap();
        assert!(msg.subject.unwrap().contains("sid.security.brute_force.v1"));
        assert!(msg.body.contains("Security Alert"));
    }

    #[test]
    fn test_build_context() {
        let event = Event::new("src", "test.v1")
            .with_subject("profile/123")
            .with_data(serde_json::json!({"key": "value", "num": 42}));

        let ctx = build_context(&event);
        assert_eq!(ctx["event_type"], "test.v1");
        assert_eq!(ctx["source"], "src");
        assert_eq!(ctx["subject"], "profile/123");
        assert_eq!(ctx["data"]["key"], "value");
        assert_eq!(ctx["data"]["num"], 42);
        assert!(ctx["data_json"].as_str().unwrap().contains("key"));
    }

    #[test]
    fn test_convert_legacy_syntax() {
        // Single-brace → double-brace
        assert_eq!(convert_legacy_syntax("Hello {name}"), "Hello {{name}}");
        assert_eq!(convert_legacy_syntax("{a} and {b.c}"), "{{a}} and {{b.c}}");

        // Already Handlebars — no change
        assert_eq!(convert_legacy_syntax("Hello {{name}}"), "Hello {{name}}");
        assert_eq!(
            convert_legacy_syntax("{{#if data.ip}}yes{{/if}}"),
            "{{#if data.ip}}yes{{/if}}"
        );

        // Mixed — only convert legacy
        assert_eq!(
            convert_legacy_syntax("{legacy} and {{modern}}"),
            "{{legacy}} and {{modern}}"
        );

        // No variables
        assert_eq!(convert_legacy_syntax("plain text"), "plain text");

        // CSS/JSON braces not converted (contain spaces/special chars)
        assert_eq!(
            convert_legacy_syntax("style={color: red}"),
            "style={color: red}"
        );

        // Multi-byte UTF-8 before variables — must not panic
        assert_eq!(convert_legacy_syntax("Привет {name}!"), "Привет {{name}}!");
        assert_eq!(
            convert_legacy_syntax("Welcome — {name} activated"),
            "Welcome — {{name}} activated"
        );
        assert_eq!(
            convert_legacy_syntax("🎉 {event_type} 🎉"),
            "🎉 {{event_type}} 🎉"
        );

        // Multi-byte with Handlebars syntax
        assert_eq!(
            convert_legacy_syntax("Добро пожаловать — {{data.org_name}}"),
            "Добро пожаловать — {{data.org_name}}"
        );

        // Multi-byte only, no variables
        assert_eq!(convert_legacy_syntax("Привет мир! 🌍"), "Привет мир! 🌍");
    }

    #[test]
    fn test_legacy_syntax_backward_compat() {
        let mut engine = TemplateEngine::new();
        engine.register(NotificationTemplate {
            name: "legacy".into(),
            subject: Some("Alert: {event_type}".into()),
            body_html: "<p>IP: {data.ip}</p>".into(),
            body_text: "IP: {data.ip}".into(),
            default_priority: NotificationPriority::Critical,
        });

        let event =
            Event::new("src", "test.alert.v1").with_data(serde_json::json!({"ip": "10.0.0.1"}));

        let msg = engine
            .render("legacy", &event, NotificationPriority::Critical)
            .unwrap();

        assert_eq!(msg.subject.as_deref(), Some("Alert: test.alert.v1"));
        assert!(msg.body.contains("10.0.0.1"));
    }

    #[test]
    fn test_handlebars_conditional() {
        let mut engine = TemplateEngine::new();
        engine.register(NotificationTemplate {
            name: "conditional".into(),
            subject: Some("Alert".into()),
            body_html: "{{#if data.ip}}IP: {{data.ip}}{{else}}No IP{{/if}}".into(),
            body_text: "test".into(),
            default_priority: NotificationPriority::Informational,
        });

        // With IP
        let event = Event::new("src", "test.v1").with_data(serde_json::json!({"ip": "1.2.3.4"}));
        let msg = engine
            .render("conditional", &event, NotificationPriority::Informational)
            .unwrap();
        assert_eq!(msg.body, "IP: 1.2.3.4");

        // Without IP
        let event_no_ip =
            Event::new("src", "test.v1").with_data(serde_json::json!({"other": "val"}));
        let msg_no_ip = engine
            .render(
                "conditional",
                &event_no_ip,
                NotificationPriority::Informational,
            )
            .unwrap();
        assert_eq!(msg_no_ip.body, "No IP");
    }

    #[test]
    fn test_handlebars_missing_var_renders_empty() {
        let mut engine = TemplateEngine::new();
        engine.register(NotificationTemplate {
            name: "missing".into(),
            subject: Some("Alert".into()),
            body_html: "Hello {{nonexistent}}!".into(),
            body_text: "test".into(),
            default_priority: NotificationPriority::Informational,
        });

        let event = Event::new("src", "test.v1");
        let msg = engine
            .render("missing", &event, NotificationPriority::Informational)
            .unwrap();
        assert_eq!(msg.body, "Hello !");
    }

    #[test]
    fn test_render_with_vars() {
        let mut vars = HashMap::new();
        vars.insert("name".into(), "Alice".into());
        vars.insert("data.ip".into(), "10.0.0.1".into());

        // Legacy syntax
        assert_eq!(
            render_with_vars("Hello {name}, IP: {data.ip}", &vars),
            "Hello Alice, IP: 10.0.0.1"
        );

        // Handlebars syntax
        assert_eq!(
            render_with_vars("Hello {{name}}, IP: {{data.ip}}", &vars),
            "Hello Alice, IP: 10.0.0.1"
        );
    }

    #[test]
    fn test_vars_to_context() {
        let mut vars = HashMap::new();
        vars.insert("name".into(), "Alice".into());
        vars.insert("data.ip".into(), "10.0.0.1".into());
        vars.insert("data.city".into(), "Berlin".into());

        let ctx = vars_to_context(&vars);
        assert_eq!(ctx["name"], "Alice");
        assert_eq!(ctx["data"]["ip"], "10.0.0.1");
        assert_eq!(ctx["data"]["city"], "Berlin");
    }

    #[test]
    fn test_trial_onboarding_template_exists() {
        let engine = TemplateEngine::with_default_ce_templates();
        assert!(engine.get("trial_onboarding").is_some());
    }

    #[test]
    fn test_trial_onboarding_template_renders() {
        let engine = TemplateEngine::with_default_ce_templates();
        let event = Event::new("sid-server", "sid.organization.trial_activated.v1")
            .with_subject("org/01234567-89ab-cdef-0123-456789abcdef")
            .with_data(serde_json::json!({
                "org_id": "01234567-89ab-cdef-0123-456789abcdef",
                "org_name": "Acme Corp",
                "domain": "id.acme.com",
                "trial_days_remaining": 30,
                "trial_users_limit": 25,
                "trial_end_date": "2026-04-22",
            }));

        let msg = engine
            .render(
                "trial_onboarding",
                &event,
                NotificationPriority::Transactional,
            )
            .unwrap();

        let subject = msg.subject.unwrap();
        assert!(
            subject.contains("Acme Corp"),
            "subject should contain org name"
        );
        assert!(
            msg.body.contains("id.acme.com"),
            "body should contain domain"
        );
        assert!(
            msg.body.contains("25"),
            "body should contain trial users limit"
        );
        assert!(msg.body.contains("30"), "body should contain trial days");
        assert!(
            msg.body.contains("2026-04-22"),
            "body should contain trial end date"
        );
    }

    #[test]
    fn test_template_serde() {
        let template = NotificationTemplate {
            name: "test".into(),
            subject: Some("Subject".into()),
            body_html: "<p>Body</p>".into(),
            body_text: "Body".into(),
            default_priority: NotificationPriority::Transactional,
        };

        let json = serde_json::to_string(&template).unwrap();
        let deserialized: NotificationTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
    }

    #[test]
    fn test_contestation_templates_exist() {
        let engine = TemplateEngine::with_default_ce_templates();
        assert!(engine.get("principal_contested").is_some());
        assert!(engine.get("principal_lost").is_some());
        assert!(engine.get("principal_ownership_superseded").is_some());
    }

    #[test]
    fn test_principal_contested_template_renders() {
        let engine = TemplateEngine::with_default_ce_templates();
        let event = Event::new("sid-identity", event_types::PRINCIPAL_CONTESTED)
            .with_subject("profile/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            .with_data(serde_json::json!({
                "profile_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "principal_type": "email",
                "principal_value": "alice@example.com",
                "new_claimer_profile_id": "11111111-2222-3333-4444-555555555555",
            }));

        let msg = engine
            .render(
                "principal_contested",
                &event,
                NotificationPriority::Transactional,
            )
            .unwrap();

        let subject = msg.subject.unwrap();
        assert!(
            subject.contains("email"),
            "subject should mention principal type"
        );
        assert!(
            subject.contains("alice@example.com"),
            "subject should contain principal value"
        );
        assert!(
            msg.body.contains("alice@example.com"),
            "body should contain principal value"
        );
        assert!(
            msg.body.contains("email"),
            "body should mention principal type"
        );
        assert_eq!(msg.priority, NotificationPriority::Transactional);
    }

    #[test]
    fn test_principal_lost_template_no_subject() {
        let engine = TemplateEngine::with_default_ce_templates();
        let tmpl = engine.get("principal_lost").unwrap();
        assert!(
            tmpl.subject.is_none(),
            "principal_lost has no email subject (push-only channel)"
        );
    }

    #[test]
    fn test_principal_ownership_superseded_template_no_subject() {
        let engine = TemplateEngine::with_default_ce_templates();
        let tmpl = engine.get("principal_ownership_superseded").unwrap();
        assert!(
            tmpl.subject.is_none(),
            "principal_ownership_superseded has no email subject (push-only channel)"
        );
    }

    #[test]
    fn test_principal_lost_template_renders() {
        let engine = TemplateEngine::with_default_ce_templates();
        let event = Event::new("sid-identity", event_types::PRINCIPAL_LOST)
            .with_subject("profile/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            .with_data(serde_json::json!({
                "profile_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "principal_type": "phone",
                "principal_value": "+380501234567",
            }));

        let msg = engine
            .render(
                "principal_lost",
                &event,
                NotificationPriority::Transactional,
            )
            .unwrap();

        assert!(
            msg.body.contains("+380501234567"),
            "body should contain principal value"
        );
        assert!(
            msg.body.contains("phone"),
            "body should mention principal type"
        );
    }
}
