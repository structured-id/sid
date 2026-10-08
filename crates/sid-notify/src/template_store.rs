// SPDX-License-Identifier: AGPL-3.0-only
//! Persistent template storage with PostgreSQL overlay on in-memory defaults.
//!
//! Default CE templates are loaded in-memory at startup. Admin customizations
//! are stored in PostgreSQL and overlaid on top. Reset = delete DB row (revert
//! to default). Without `SID_NOTIFY_DATABASE_URL`, operates in-memory only.

use crate::routing::RoutingTable;
use crate::template::{NotificationTemplate as InternalTemplate, TemplateEngine};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Channel identifier matching proto `NotificationChannel` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i16)]
pub(crate) enum Channel {
    Email = 1,
    Sms = 2,
    Push = 3,
}

impl Channel {
    pub(crate) fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::Email),
            2 => Some(Self::Sms),
            3 => Some(Self::Push),
            _ => None,
        }
    }

    pub(crate) fn as_i16(self) -> i16 {
        self as i16
    }
}

/// Stored content for a specific template + channel + locale combination.
#[derive(Debug, Clone)]
pub(crate) struct StoredContent {
    pub(crate) subject: String,
    pub(crate) html_body: String,
    pub(crate) text_body: String,
    pub(crate) sms_body: String,
    pub(crate) push_title: String,
    pub(crate) push_body: String,
    pub(crate) push_action_url: String,
    pub(crate) updated_at: DateTime<Utc>,
}

/// Template metadata for listing.
#[derive(Debug, Clone)]
pub(crate) struct TemplateMeta {
    pub(crate) template_id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) channels: Vec<Channel>,
    pub(crate) trigger: String,
    pub(crate) variables: Vec<TemplateVar>,
}

/// Template variable definition.
#[derive(Debug, Clone)]
pub(crate) struct TemplateVar {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) example: String,
}

/// Key for custom override lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OverrideKey {
    template_id: String,
    channel: Channel,
    locale: String,
}

/// Persistent template store with default overlay.
pub(crate) struct TemplateStore {
    /// In-memory default templates (CE shipped).
    defaults: Vec<TemplateMeta>,
    /// Default content by (template_id, channel).
    default_content: HashMap<(String, Channel), StoredContent>,
    /// Custom overrides from PostgreSQL (cached in memory).
    overrides: RwLock<HashMap<OverrideKey, StoredContent>>,
    /// PostgreSQL pool (None = in-memory only).
    pool: Option<sqlx::PgPool>,
    /// Reference to template engine for rendering.
    engine: Arc<RwLock<TemplateEngine>>,
}

impl TemplateStore {
    /// Create a new template store from routing table and optional DB pool.
    pub(crate) async fn new(
        _routing: &RoutingTable,
        engine: Arc<RwLock<TemplateEngine>>,
        pool: Option<sqlx::PgPool>,
    ) -> Result<Self, sqlx::Error> {
        // Run migrations if DB is available.
        if let Some(ref pool) = pool {
            sqlx::migrate!("./migrations").run(pool).await?;
        }

        // Build default template metadata from engine + routing.
        let (defaults, default_content) = Self::build_defaults(&engine).await;

        let mut store = Self {
            defaults,
            default_content,
            overrides: RwLock::new(HashMap::new()),
            pool,
            engine,
        };

        // Load custom overrides from DB.
        store.load_overrides().await?;

        Ok(store)
    }

    /// Build default template metadata and content from the in-memory engine.
    async fn build_defaults(
        engine: &Arc<RwLock<TemplateEngine>>,
    ) -> (Vec<TemplateMeta>, HashMap<(String, Channel), StoredContent>) {
        let engine_guard = engine.read().await;
        let mut metas = Vec::new();
        let mut contents = HashMap::new();

        // Standard variables available in all templates.
        let standard_vars = vec![
            TemplateVar {
                name: "event_type".into(),
                description: "Event type identifier".into(),
                example: "sid.security.brute_force.v1".into(),
            },
            TemplateVar {
                name: "source".into(),
                description: "Originating service".into(),
                example: "sid-server".into(),
            },
            TemplateVar {
                name: "time".into(),
                description: "ISO 8601 timestamp".into(),
                example: "2026-03-22T10:30:00Z".into(),
            },
            TemplateVar {
                name: "id".into(),
                description: "Event ID".into(),
                example: "evt_01HY9K".into(),
            },
            TemplateVar {
                name: "data".into(),
                description: "Event data as JSON".into(),
                example: r#"{"ip":"1.2.3.4"}"#.into(),
            },
        ];

        // Map template names to trigger patterns and descriptions.
        let template_info: HashMap<&str, (&str, &str)> = HashMap::from([
            (
                "security_alert",
                (
                    "sid.security.*",
                    "Security alert notifications (brute force, anomaly, etc.)",
                ),
            ),
            (
                "new_session",
                ("sid.session.created.v1", "New login session notifications"),
            ),
            (
                "credential_change",
                (
                    "sid.credential.revoked.v1",
                    "Credential change notifications (password, key rotation)",
                ),
            ),
            (
                "mfa_change",
                ("sid.mfa.*", "MFA settings change notifications"),
            ),
            (
                "cert_expiry",
                ("sid.cert.expiring.v1", "Certificate expiration warnings"),
            ),
            (
                "role_expiry",
                (
                    "sid.governance.role_expiring.v1",
                    "Temporary role expiry notifications",
                ),
            ),
            (
                "scim_outbound_failure",
                (
                    "sid.scim.outbound_failed.v1",
                    "SCIM outbound provisioning failure alerts",
                ),
            ),
            (
                "trial_onboarding",
                (
                    "sid.organization.trial_activated.v1",
                    "Trial activation onboarding email",
                ),
            ),
        ]);

        for (name, (trigger, description)) in &template_info {
            if let Some(tmpl) = engine_guard.get(name) {
                // All defaults are email-only currently.
                let channels = vec![Channel::Email];
                let now = Utc::now();

                metas.push(TemplateMeta {
                    template_id: name.to_string(),
                    name: tmpl.subject.clone().unwrap_or_else(|| name.to_string()),
                    description: description.to_string(),
                    channels: channels.clone(),
                    trigger: trigger.to_string(),
                    variables: standard_vars.clone(),
                });

                // Store default email content.
                contents.insert(
                    (name.to_string(), Channel::Email),
                    StoredContent {
                        subject: tmpl.subject.clone().unwrap_or_default(),
                        html_body: tmpl.body_html.clone(),
                        text_body: tmpl.body_text.clone(),
                        sms_body: String::new(),
                        push_title: String::new(),
                        push_body: String::new(),
                        push_action_url: String::new(),
                        updated_at: now,
                    },
                );
            }
        }

        (metas, contents)
    }

    /// Load custom overrides from PostgreSQL into memory.
    async fn load_overrides(&mut self) -> Result<(), sqlx::Error> {
        let Some(ref pool) = self.pool else {
            return Ok(());
        };

        let rows = sqlx::query_as::<_, OverrideRow>(
            "SELECT template_id, channel, locale, subject, html_body, text_body,
                    sms_body, push_title, push_body, push_action_url, updated_at
             FROM notification_template_overrides",
        )
        .fetch_all(pool)
        .await?;

        let mut overrides = self.overrides.write().await;
        for row in rows {
            let Some(channel) = Channel::from_i32(row.channel as i32) else {
                continue;
            };
            overrides.insert(
                OverrideKey {
                    template_id: row.template_id,
                    channel,
                    locale: row.locale,
                },
                StoredContent {
                    subject: row.subject,
                    html_body: row.html_body,
                    text_body: row.text_body,
                    sms_body: row.sms_body,
                    push_title: row.push_title,
                    push_body: row.push_body,
                    push_action_url: row.push_action_url,
                    updated_at: row.updated_at,
                },
            );
        }

        Ok(())
    }

    /// List all templates with customization status.
    pub(crate) async fn list_templates(
        &self,
        channel_filter: Option<Channel>,
        customized_only: bool,
    ) -> Vec<TemplateSummary> {
        let overrides = self.overrides.read().await;
        let mut result = Vec::new();

        for meta in &self.defaults {
            // Filter by channel if specified.
            if let Some(ch) = channel_filter
                && !meta.channels.contains(&ch)
            {
                continue;
            }

            // Check if any override exists for this template.
            let is_customized = overrides.keys().any(|k| k.template_id == meta.template_id);

            if customized_only && !is_customized {
                continue;
            }

            // Find the latest updated_at from overrides (if any).
            let updated_at = overrides
                .iter()
                .filter(|(k, _)| k.template_id == meta.template_id)
                .map(|(_, v)| v.updated_at)
                .max();

            result.push(TemplateSummary {
                template_id: meta.template_id.clone(),
                name: meta.name.clone(),
                description: meta.description.clone(),
                channels: meta.channels.clone(),
                trigger: meta.trigger.clone(),
                customized: is_customized,
                updated_at,
            });
        }

        result
    }

    /// Get template content for a specific channel + locale.
    /// Returns (content, is_customized, meta).
    pub(crate) async fn get_template(
        &self,
        template_id: &str,
        channel: Channel,
        locale: &str,
    ) -> Option<(StoredContent, bool, &TemplateMeta)> {
        let meta = self
            .defaults
            .iter()
            .find(|m| m.template_id == template_id)?;
        let overrides = self.overrides.read().await;

        // Try exact locale match in overrides.
        let key = OverrideKey {
            template_id: template_id.to_string(),
            channel,
            locale: locale.to_string(),
        };
        if let Some(content) = overrides.get(&key) {
            return Some((content.clone(), true, meta));
        }

        // Fallback to "en" locale in overrides.
        if locale != "en" {
            let en_key = OverrideKey {
                template_id: template_id.to_string(),
                channel,
                locale: "en".to_string(),
            };
            if let Some(content) = overrides.get(&en_key) {
                return Some((content.clone(), true, meta));
            }
        }

        // Fallback to default content.
        self.default_content
            .get(&(template_id.to_string(), channel))
            .map(|c| (c.clone(), false, meta))
    }

    /// Get available locales for a template.
    pub(crate) async fn available_locales(&self, template_id: &str) -> Vec<String> {
        let overrides = self.overrides.read().await;
        let mut locales: Vec<String> = overrides
            .keys()
            .filter(|k| k.template_id == template_id)
            .map(|k| k.locale.clone())
            .collect();

        // Always include "en" as default.
        if !locales.contains(&"en".to_string()) {
            locales.push("en".to_string());
        }
        locales.sort();
        locales.dedup();
        locales
    }

    /// Update (UPSERT) template content for a specific channel + locale.
    pub(crate) async fn update_template(
        &self,
        template_id: &str,
        channel: Channel,
        locale: &str,
        content: StoredContent,
    ) -> Result<(), TemplateStoreError> {
        // Verify template exists.
        if !self.defaults.iter().any(|m| m.template_id == template_id) {
            return Err(TemplateStoreError::NotFound(template_id.to_string()));
        }

        // Persist to DB if available.
        if let Some(ref pool) = self.pool {
            sqlx::query(
                "INSERT INTO notification_template_overrides
                     (template_id, channel, locale, subject, html_body, text_body,
                      sms_body, push_title, push_body, push_action_url, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (template_id, channel, locale) DO UPDATE SET
                     subject = EXCLUDED.subject,
                     html_body = EXCLUDED.html_body,
                     text_body = EXCLUDED.text_body,
                     sms_body = EXCLUDED.sms_body,
                     push_title = EXCLUDED.push_title,
                     push_body = EXCLUDED.push_body,
                     push_action_url = EXCLUDED.push_action_url,
                     updated_at = EXCLUDED.updated_at",
            )
            .bind(template_id)
            .bind(channel.as_i16())
            .bind(locale)
            .bind(&content.subject)
            .bind(&content.html_body)
            .bind(&content.text_body)
            .bind(&content.sms_body)
            .bind(&content.push_title)
            .bind(&content.push_body)
            .bind(&content.push_action_url)
            .bind(content.updated_at)
            .execute(pool)
            .await
            .map_err(|e| TemplateStoreError::Database(e.to_string()))?;
        }

        // Update in-memory cache.
        let key = OverrideKey {
            template_id: template_id.to_string(),
            channel,
            locale: locale.to_string(),
        };
        self.overrides.write().await.insert(key, content);

        // Also update the TemplateEngine if this is the email channel for "en" locale,
        // so NATS dispatch uses the updated content immediately.
        if channel == Channel::Email
            && locale == "en"
            && let Some(override_content) = self.overrides.read().await.get(&OverrideKey {
                template_id: template_id.to_string(),
                channel: Channel::Email,
                locale: "en".to_string(),
            })
        {
            let mut engine = self.engine.write().await;
            engine.register(InternalTemplate {
                name: template_id.to_string(),
                subject: if override_content.subject.is_empty() {
                    None
                } else {
                    Some(override_content.subject.clone())
                },
                body_html: override_content.html_body.clone(),
                body_text: override_content.text_body.clone(),
                default_priority: sid_plugin::notification::NotificationPriority::Transactional,
            });
        }

        Ok(())
    }

    /// Reset template to default for a specific channel + locale (delete override).
    pub(crate) async fn reset_template(
        &self,
        template_id: &str,
        channel: Channel,
        locale: &str,
    ) -> Result<(), TemplateStoreError> {
        // Verify template exists.
        if !self.defaults.iter().any(|m| m.template_id == template_id) {
            return Err(TemplateStoreError::NotFound(template_id.to_string()));
        }

        // Delete from DB.
        if let Some(ref pool) = self.pool {
            sqlx::query(
                "DELETE FROM notification_template_overrides
                 WHERE template_id = $1 AND channel = $2 AND locale = $3",
            )
            .bind(template_id)
            .bind(channel.as_i16())
            .bind(locale)
            .execute(pool)
            .await
            .map_err(|e| TemplateStoreError::Database(e.to_string()))?;
        }

        // Remove from in-memory cache.
        let key = OverrideKey {
            template_id: template_id.to_string(),
            channel,
            locale: locale.to_string(),
        };
        self.overrides.write().await.remove(&key);

        // Restore default in TemplateEngine.
        if channel == Channel::Email
            && locale == "en"
            && let Some(default_content) = self
                .default_content
                .get(&(template_id.to_string(), channel))
        {
            let mut engine = self.engine.write().await;
            engine.register(InternalTemplate {
                name: template_id.to_string(),
                subject: if default_content.subject.is_empty() {
                    None
                } else {
                    Some(default_content.subject.clone())
                },
                body_html: default_content.html_body.clone(),
                body_text: default_content.text_body.clone(),
                default_priority: sid_plugin::notification::NotificationPriority::Transactional,
            });
        }

        Ok(())
    }

    /// Render template with variables for preview.
    pub(crate) fn render_preview(
        content: &StoredContent,
        channel: Channel,
        vars: &HashMap<String, String>,
    ) -> (String, String, String) {
        use crate::template::render_with_vars;

        match channel {
            Channel::Email => (
                render_with_vars(&content.subject, vars),
                render_with_vars(&content.html_body, vars),
                render_with_vars(&content.text_body, vars),
            ),
            Channel::Sms => (
                String::new(),
                render_with_vars(&content.sms_body, vars),
                String::new(),
            ),
            Channel::Push => (
                String::new(),
                render_with_vars(&content.push_body, vars),
                render_with_vars(&content.push_title, vars),
            ),
        }
    }
}

/// Summary for template listing.
#[derive(Debug, Clone)]
pub(crate) struct TemplateSummary {
    pub(crate) template_id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) channels: Vec<Channel>,
    pub(crate) trigger: String,
    pub(crate) customized: bool,
    pub(crate) updated_at: Option<DateTime<Utc>>,
}

/// Template store errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TemplateStoreError {
    #[error("template not found: {0}")]
    NotFound(String),

    #[error("database error: {0}")]
    Database(String),
}

/// Row type for sqlx query.
#[derive(sqlx::FromRow)]
struct OverrideRow {
    template_id: String,
    channel: i16,
    locale: String,
    subject: String,
    html_body: String,
    text_body: String,
    sms_body: String,
    push_title: String,
    push_body: String,
    push_action_url: String,
    updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
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
        assert_eq!(templates.len(), 8);
        assert!(templates.iter().all(|t| !t.customized));
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

        // Email filter should return all 7.
        let email_templates = store.list_templates(Some(Channel::Email), false).await;
        assert_eq!(email_templates.len(), 8);
    }
}

/// PostgreSQL integration tests.
/// Require: `cd sid && docker compose -f docker-compose.test.yml up -d` (port 54399).
/// Each test uses a unique template_id suffix to avoid parallel test interference.
#[cfg(test)]
mod pg_tests {
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
}
