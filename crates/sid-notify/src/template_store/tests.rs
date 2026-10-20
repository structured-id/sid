use super::*;

fn test_engine() -> Arc<RwLock<TemplateEngine>> {
    Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()))
}

#[tokio::test]
async fn test_list_all_defaults() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();
    let templates = store.list_templates(None, false).await;
    assert_eq!(templates.len(), 9);
    assert!(templates.iter().all(|t| !t.customized));
}

// Every template the engine ships is managed like the others: the password
// reset default is listed, fetched with its own variables (the link and its
// lifetime besides the event fields) and customizable.
#[tokio::test]
async fn test_password_reset_default_is_managed() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();

    let listed = store.list_templates(None, false).await;
    assert!(listed.iter().any(|t| t.template_id == "password_reset"));
    let (content, customized, meta) = store
        .get_template("password_reset", Channel::Email, "en")
        .await
        .expect("the reset default is managed");
    assert!(!customized);
    assert!(content.text_body.contains("{{data.link}}"));
    let names: Vec<&str> = meta.variables.iter().map(|v| v.name.as_str()).collect();
    for name in ["data.link", "data.expires_minutes", "event_type"] {
        assert!(names.contains(&name), "{name} in {names:?}");
    }

    let custom = StoredContent {
        subject: "Reset".into(),
        html_body: "<a href=\"{{data.link}}\">Reset</a>".into(),
        text_body: "{{data.link}}".into(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    store
        .update_template("password_reset", Channel::Email, "en", custom)
        .await
        .expect("the reset default is customizable");
}

#[tokio::test]
async fn test_list_customized_only_empty() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();
    let templates = store.list_templates(None, true).await;
    assert!(templates.is_empty());
}

#[tokio::test]
async fn test_get_default_template() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();
    let result = store
        .get_template("security_alert", Channel::Email, "en")
        .await;
    assert!(result.is_some());
    let (content, is_customized, meta) = result.unwrap();
    assert!(!is_customized);
    assert!(content.subject.contains("Security Alert"));
    assert_eq!(meta.template_id, "security_alert");
}

#[tokio::test]
async fn test_get_nonexistent_template() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();
    let result = store
        .get_template("nonexistent", Channel::Email, "en")
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_in_memory_only() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();

    let content = StoredContent {
        subject: "Custom Subject".into(),
        html_body: "<p>Custom body</p>".into(),
        text_body: "Custom body".into(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    store
        .update_template("security_alert", Channel::Email, "en", content)
        .await
        .unwrap();

    let (got, customized, _) = store
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap();
    assert!(customized);
    assert_eq!(got.subject, "Custom Subject");
}

#[tokio::test]
async fn test_update_nonexistent_fails() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();

    let content = StoredContent {
        subject: "X".into(),
        html_body: String::new(),
        text_body: String::new(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    let err = store
        .update_template("nonexistent", Channel::Email, "en", content)
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_reset_removes_override() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();

    // Customize then reset.
    let content = StoredContent {
        subject: "Custom".into(),
        html_body: "<p>Custom</p>".into(),
        text_body: "Custom".into(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    store
        .update_template("security_alert", Channel::Email, "en", content)
        .await
        .unwrap();
    store
        .reset_template("security_alert", Channel::Email, "en")
        .await
        .unwrap();

    let (got, customized, _) = store
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap();
    assert!(!customized);
    assert!(got.subject.contains("Security Alert"));
}

#[tokio::test]
async fn test_render_preview_email() {
    let content = StoredContent {
        subject: "Alert: {event_type}".into(),
        html_body: "<p>Hello {name}</p>".into(),
        text_body: "Hello {name}".into(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    let mut vars = HashMap::new();
    vars.insert("event_type".into(), "sid.security.brute_force.v1".into());
    vars.insert("name".into(), "Alice".into());

    let (subj, body, text) = TemplateStore::render_preview(&content, Channel::Email, &vars);
    assert_eq!(subj, "Alert: sid.security.brute_force.v1");
    assert_eq!(body, "<p>Hello Alice</p>");
    assert_eq!(text, "Hello Alice");
}

#[tokio::test]
async fn test_render_preview_sms() {
    let content = StoredContent {
        subject: String::new(),
        html_body: String::new(),
        text_body: String::new(),
        sms_body: "Code: {code}".into(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    let mut vars = HashMap::new();
    vars.insert("code".into(), "123456".into());

    let (subj, body, _) = TemplateStore::render_preview(&content, Channel::Sms, &vars);
    assert!(subj.is_empty());
    assert_eq!(body, "Code: 123456");
}

#[tokio::test]
async fn test_available_locales_default() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();
    let locales = store.available_locales("security_alert").await;
    assert_eq!(locales, vec!["en"]);
}

#[tokio::test]
async fn test_list_filter_by_channel() {
    let engine = test_engine();
    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, engine, None).await.unwrap();

    // All defaults are email-only, so filtering by SMS should return empty.
    let sms_templates = store.list_templates(Some(Channel::Sms), false).await;
    assert!(sms_templates.is_empty());

    // Email filter should return every default.
    let email_templates = store.list_templates(Some(Channel::Email), false).await;
    assert_eq!(email_templates.len(), 9);
}
