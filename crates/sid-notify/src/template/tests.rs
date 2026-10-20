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

    let event = Event::new("src", "test.alert.v1").with_data(serde_json::json!({"ip": "10.0.0.1"}));

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
    let event_no_ip = Event::new("src", "test.v1").with_data(serde_json::json!({"other": "val"}));
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

// The password reset mail places the link its producer built and the link's
// lifetime, in both bodies, exactly as given: the template builds no URL
// (notifications.md, template management: password_reset is a CE default).
#[test]
fn test_password_reset_template_places_the_link() {
    let engine = TemplateEngine::with_default_ce_templates();
    let link = "https://id.sid.example.com/account/reset?session_id=s-1&token=t-2";
    let event = Event::new("sid-identity", event_types::PASSWORD_RESET_REQUESTED)
        .with_data(serde_json::json!({ "link": link, "expires_minutes": 30 }));

    let msg = engine
        .render(
            "password_reset",
            &event,
            NotificationPriority::Transactional,
        )
        .unwrap();

    assert_eq!(msg.subject.as_deref(), Some("Reset your password"));
    assert!(
        msg.body.contains(&format!("href=\"{link}\"")),
        "{}",
        msg.body
    );
    let text = msg.body_text.unwrap();
    assert!(text.contains(link), "{text}");
    assert!(text.contains("30 minutes"), "{text}");
    assert!(msg.body.contains("30 minutes"), "{}", msg.body);
    assert_eq!(msg.priority, NotificationPriority::Transactional);
}
