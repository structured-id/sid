use super::*;

fn test_engine() -> Arc<RwLock<TemplateEngine>> {
    Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()))
}

/// A store over a fresh schema.
async fn store() -> TemplateStore {
    store_on(crate::test_db::pool().await).await
}

async fn store_on(pool: sqlx::PgPool) -> TemplateStore {
    TemplateStore::new(&RoutingTable::default_ce_rules(), test_engine(), pool)
        .await
        .unwrap()
}

fn content(subject: &str) -> StoredContent {
    StoredContent {
        subject: subject.into(),
        html_body: format!("<p>{subject}</p>"),
        text_body: subject.into(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    }
}

/// A change committed alone, without a keyed command's completion.
fn alone(_: &Effective, _: &TemplateMeta) -> ((), Option<OperationCompletion>) {
    ((), None)
}

#[tokio::test]
async fn test_list_all_defaults() {
    let store = store().await;
    let templates = store.list_templates(None, false).await.unwrap();
    assert_eq!(templates.len(), 9);
    assert!(templates.iter().all(|t| !t.customized));
}

// The one-time code default is managed like the others, with the code, its
// purpose and its lifetime among its variables.
#[tokio::test]
async fn test_otp_default_is_managed() {
    let store = store().await;
    let (content, customized, meta) = store
        .get_template("otp", Channel::Email, "en")
        .await
        .unwrap()
        .expect("the code default is managed");
    assert!(!customized);
    assert!(content.text_body.contains("{{data.code}}"));
    let names: Vec<&str> = meta.variables.iter().map(|v| v.name.as_str()).collect();
    for name in ["data.code", "data.purpose", "data.expires_minutes"] {
        assert!(names.contains(&name), "{name} in {names:?}");
    }
}

// Every template the engine ships is managed like the others: the password
// reset default is listed, fetched with its own variables (the link and its
// lifetime besides the event fields) and customizable.
#[tokio::test]
async fn test_password_reset_default_is_managed() {
    let store = store().await;
    let listed = store.list_templates(None, false).await.unwrap();
    assert!(listed.iter().any(|t| t.template_id == "password_reset"));
    let (default, customized, meta) = store
        .get_template("password_reset", Channel::Email, "en")
        .await
        .unwrap()
        .expect("the reset default is managed");
    assert!(!customized);
    assert!(default.text_body.contains("{{data.link}}"));
    let names: Vec<&str> = meta.variables.iter().map(|v| v.name.as_str()).collect();
    for name in ["data.link", "data.expires_minutes", "event_type"] {
        assert!(names.contains(&name), "{name} in {names:?}");
    }

    let custom = StoredContent {
        html_body: "<a href=\"{{data.link}}\">Reset</a>".into(),
        text_body: "{{data.link}}".into(),
        ..content("Reset")
    };
    store
        .update_template("password_reset", Channel::Email, "en", custom, alone)
        .await
        .expect("the reset default is customizable");
}

#[tokio::test]
async fn test_list_customized_only_empty() {
    let store = store().await;
    assert!(store.list_templates(None, true).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_get_default_template() {
    let store = store().await;
    let (content, is_customized, meta) = store
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap()
        .expect("a shipped template");
    assert!(!is_customized);
    assert!(content.subject.contains("Security Alert"));
    assert_eq!(meta.template_id, "security_alert");
}

#[tokio::test]
async fn test_get_nonexistent_template() {
    let store = store().await;
    let result = store
        .get_template("nonexistent", Channel::Email, "en")
        .await
        .unwrap();
    assert!(result.is_none());
}

/// A customization answers instead of the default.
#[tokio::test]
async fn test_update_answers_the_customization() {
    let store = store().await;
    store
        .update_template(
            "security_alert",
            Channel::Email,
            "en",
            content("Custom Subject"),
            alone,
        )
        .await
        .unwrap();

    let (got, customized, _) = store
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap()
        .unwrap();
    assert!(customized);
    assert_eq!(got.subject, "Custom Subject");
}

#[tokio::test]
async fn test_update_nonexistent_fails() {
    let store = store().await;
    let err = store
        .update_template("nonexistent", Channel::Email, "en", content("X"), alone)
        .await;
    assert!(matches!(err, Err(TemplateStoreError::NotFound(_))));
}

#[tokio::test]
async fn test_reset_removes_override() {
    let store = store().await;
    store
        .update_template(
            "security_alert",
            Channel::Email,
            "en",
            content("Custom"),
            alone,
        )
        .await
        .unwrap();
    store
        .reset_template("security_alert", Channel::Email, "en", alone)
        .await
        .unwrap();

    let (got, customized, _) = store
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap()
        .unwrap();
    assert!(!customized);
    assert!(got.subject.contains("Security Alert"));
}

/// Regression: each instance answered from the customizations it loaded at
/// start, so a change taken by one replica stayed unseen by another until it
/// restarted. Both instances over one database answer with what was
/// committed, a change and a reset alike.
#[tokio::test]
async fn test_another_replica_answers_with_the_committed_change() {
    let pool = crate::test_db::pool().await;
    let (one, other) = (store_on(pool.clone()).await, store_on(pool).await);

    one.update_template(
        "security_alert",
        Channel::Email,
        "en",
        content("From one"),
        alone,
    )
    .await
    .unwrap();
    let (got, customized, _) = other
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap()
        .unwrap();
    assert!(customized, "the other replica answered with the default");
    assert_eq!(got.subject, "From one");
    assert!(
        other
            .list_templates(None, true)
            .await
            .unwrap()
            .iter()
            .any(|t| t.template_id == "security_alert")
    );

    one.reset_template("security_alert", Channel::Email, "en", alone)
        .await
        .unwrap();
    let (_, customized, _) = other
        .get_template("security_alert", Channel::Email, "en")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !customized,
        "the other replica kept a removed customization"
    );
}

/// What a change answers with is what its own transaction left: a reset in
/// a locale falls back to the `en` customization.
#[tokio::test]
async fn test_a_change_answers_with_what_it_left() {
    let store = store().await;
    store
        .update_template(
            "mfa_change",
            Channel::Email,
            "en",
            content("English"),
            alone,
        )
        .await
        .unwrap();
    let written = store
        .update_template(
            "mfa_change",
            Channel::Email,
            "fr",
            content("French"),
            |left, _| (left.clone(), None),
        )
        .await
        .unwrap();
    assert!(written.customized);
    assert_eq!(written.content.unwrap().subject, "French");
    assert_eq!(written.locales, ["en", "fr"]);

    let reset = store
        .reset_template("mfa_change", Channel::Email, "fr", |left, _| {
            (left.clone(), None)
        })
        .await
        .unwrap();
    assert!(reset.customized, "the en customization answers");
    assert_eq!(reset.content.unwrap().subject, "English");
    assert_eq!(reset.locales, ["en"]);
}

/// Regression: resetting the only customization of a channel with no default
/// (SMS here) was refused and rolled back, so it could not be removed. The
/// removal commits and the channel answers with nothing.
#[tokio::test]
async fn test_a_channel_without_a_default_can_be_reset() {
    let store = store().await;
    let sms = StoredContent {
        sms_body: "Code {code}".into(),
        ..content("")
    };
    store
        .update_template("security_alert", Channel::Sms, "en", sms, alone)
        .await
        .unwrap();
    let left = store
        .reset_template("security_alert", Channel::Sms, "en", |left, _| {
            (left.clone(), None)
        })
        .await
        .expect("the reset commits");
    assert!(left.content.is_none());
    assert!(!left.customized);
    assert!(
        store
            .get_template("security_alert", Channel::Sms, "en")
            .await
            .unwrap()
            .is_none(),
        "the SMS customization stayed"
    );
}

/// Customizing one template, channel and locale twice keeps one row, the
/// later content.
#[tokio::test]
async fn test_a_customization_is_replaced_in_place() {
    let pool = crate::test_db::pool().await;
    let store = store_on(pool.clone()).await;
    for subject in ["v1", "v2"] {
        store
            .update_template("cert_expiry", Channel::Email, "en", content(subject), alone)
            .await
            .unwrap();
    }
    let (got, _, _) = store
        .get_template("cert_expiry", Channel::Email, "en")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.subject, "v2");
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_template_overrides WHERE template_id = 'cert_expiry'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1);
}

/// Each locale keeps its own customization; the template lists both.
#[tokio::test]
async fn test_locales_are_customized_apart() {
    let store = store().await;
    store
        .update_template(
            "mfa_change",
            Channel::Email,
            "en",
            content("MFA English"),
            alone,
        )
        .await
        .unwrap();
    store
        .update_template(
            "mfa_change",
            Channel::Email,
            "fr",
            content("MFA French"),
            alone,
        )
        .await
        .unwrap();
    for (locale, subject) in [("en", "MFA English"), ("fr", "MFA French")] {
        let (got, _, _) = store
            .get_template("mfa_change", Channel::Email, locale)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.subject, subject);
    }
    assert_eq!(
        store.available_locales("mfa_change").await.unwrap(),
        ["en", "fr"]
    );
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
    let store = store().await;
    let locales = store.available_locales("security_alert").await.unwrap();
    assert_eq!(locales, vec!["en"]);
}

#[tokio::test]
async fn test_list_filter_by_channel() {
    let store = store().await;
    // All defaults are email-only, so filtering by SMS should return empty.
    let sms_templates = store
        .list_templates(Some(Channel::Sms), false)
        .await
        .unwrap();
    assert!(sms_templates.is_empty());

    // Email filter should return every default.
    let email_templates = store
        .list_templates(Some(Channel::Email), false)
        .await
        .unwrap();
    assert_eq!(email_templates.len(), 9);
}
