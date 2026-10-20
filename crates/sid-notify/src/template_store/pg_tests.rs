use super::*;

const TEST_DB_URL: &str = "postgres://sid:sid_dev@localhost:54399/sid";

async fn pg_pool() -> Option<sqlx::PgPool> {
    sqlx::PgPool::connect(TEST_DB_URL).await.ok()
}

async fn cleanup_prefix(pool: &sqlx::PgPool, prefix: &str) {
    let _ = sqlx::query("DELETE FROM notification_template_overrides WHERE template_id = $1")
        .bind(prefix)
        .execute(pool)
        .await;
}

fn test_engine() -> Arc<RwLock<TemplateEngine>> {
    Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()))
}

#[tokio::test]
async fn test_pg_update_persists_and_loads() {
    let Some(pool) = pg_pool().await else {
        eprintln!("SKIP: PostgreSQL not available at {TEST_DB_URL}");
        return;
    };
    cleanup_prefix(&pool, "security_alert").await;

    let routing = RoutingTable::default_ce_rules();

    // Create store, update a template.
    {
        let store = TemplateStore::new(&routing, test_engine(), Some(pool.clone()))
            .await
            .unwrap();

        let content = StoredContent {
            subject: "PG Custom Subject".into(),
            html_body: "<p>PG Custom</p>".into(),
            text_body: "PG Custom".into(),
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
    }

    // Create a NEW store from the same pool — it should load the override.
    {
        let store2 = TemplateStore::new(&routing, test_engine(), Some(pool.clone()))
            .await
            .unwrap();

        let (got, customized, _) = store2
            .get_template("security_alert", Channel::Email, "en")
            .await
            .unwrap();
        assert!(customized, "override should be loaded from DB");
        assert_eq!(got.subject, "PG Custom Subject");
    }

    cleanup_prefix(&pool, "security_alert").await;
}

#[tokio::test]
async fn test_pg_reset_removes_override() {
    let Some(pool) = pg_pool().await else {
        eprintln!("SKIP: PostgreSQL not available at {TEST_DB_URL}");
        return;
    };
    cleanup_prefix(&pool, "new_session").await;

    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, test_engine(), Some(pool.clone()))
        .await
        .unwrap();

    // Customize.
    let content = StoredContent {
        subject: "Temp".into(),
        html_body: "<p>Temp</p>".into(),
        text_body: "Temp".into(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };
    store
        .update_template("new_session", Channel::Email, "en", content)
        .await
        .unwrap();

    // Reset.
    store
        .reset_template("new_session", Channel::Email, "en")
        .await
        .unwrap();

    // Verify DB is clean — new store should NOT see override.
    let store2 = TemplateStore::new(&routing, test_engine(), Some(pool.clone()))
        .await
        .unwrap();
    let (_, customized, _) = store2
        .get_template("new_session", Channel::Email, "en")
        .await
        .unwrap();
    assert!(!customized, "override should be deleted from DB");

    cleanup_prefix(&pool, "new_session").await;
}

#[tokio::test]
async fn test_pg_upsert_idempotent() {
    let Some(pool) = pg_pool().await else {
        eprintln!("SKIP: PostgreSQL not available at {TEST_DB_URL}");
        return;
    };
    cleanup_prefix(&pool, "cert_expiry").await;

    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, test_engine(), Some(pool.clone()))
        .await
        .unwrap();

    let mk_content = |subject: &str| StoredContent {
        subject: subject.into(),
        html_body: String::new(),
        text_body: String::new(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };

    // Update twice with different content.
    store
        .update_template("cert_expiry", Channel::Email, "en", mk_content("v1"))
        .await
        .unwrap();
    store
        .update_template("cert_expiry", Channel::Email, "en", mk_content("v2"))
        .await
        .unwrap();

    // Should see v2.
    let (got, _, _) = store
        .get_template("cert_expiry", Channel::Email, "en")
        .await
        .unwrap();
    assert_eq!(got.subject, "v2");

    // DB should have exactly 1 row.
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notification_template_overrides WHERE template_id = 'cert_expiry'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1);

    cleanup_prefix(&pool, "cert_expiry").await;
}

#[tokio::test]
async fn test_pg_multi_locale_override() {
    let Some(pool) = pg_pool().await else {
        eprintln!("SKIP: PostgreSQL not available at {TEST_DB_URL}");
        return;
    };
    cleanup_prefix(&pool, "mfa_change").await;

    let routing = RoutingTable::default_ce_rules();
    let store = TemplateStore::new(&routing, test_engine(), Some(pool.clone()))
        .await
        .unwrap();

    let mk = |subject: &str| StoredContent {
        subject: subject.into(),
        html_body: String::new(),
        text_body: String::new(),
        sms_body: String::new(),
        push_title: String::new(),
        push_body: String::new(),
        push_action_url: String::new(),
        updated_at: Utc::now(),
    };

    store
        .update_template("mfa_change", Channel::Email, "en", mk("MFA English"))
        .await
        .unwrap();
    store
        .update_template("mfa_change", Channel::Email, "fr", mk("MFA French"))
        .await
        .unwrap();

    // Verify both locales.
    let (en, _, _) = store
        .get_template("mfa_change", Channel::Email, "en")
        .await
        .unwrap();
    assert_eq!(en.subject, "MFA English");

    let (fr, _, _) = store
        .get_template("mfa_change", Channel::Email, "fr")
        .await
        .unwrap();
    assert_eq!(fr.subject, "MFA French");

    // Available locales should include both.
    let locales = store.available_locales("mfa_change").await;
    assert!(locales.contains(&"en".to_string()));
    assert!(locales.contains(&"fr".to_string()));

    // List should show customized.
    let list = store.list_templates(None, true).await;
    assert!(
        list.iter()
            .any(|t| t.template_id == "mfa_change" && t.customized)
    );

    cleanup_prefix(&pool, "mfa_change").await;
}
