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
        let standard_vars = [
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

        // Variables a template reads beyond the standard ones.
        let reset_vars = [
            TemplateVar {
                name: "data.link".into(),
                description: "Link that continues the password reset".into(),
                example: "https://sid.example.com/account/reset?session_id=...&token=...".into(),
            },
            TemplateVar {
                name: "data.expires_minutes".into(),
                description: "Minutes until the link expires".into(),
                example: "30".into(),
            },
        ];
        let otp_vars = [
            TemplateVar {
                name: "data.code".into(),
                description: "The one-time code".into(),
                example: "04821937".into(),
            },
            TemplateVar {
                name: "data.purpose".into(),
                description: "What the code does, completing \"Use this code to …\"".into(),
                example: "confirm your email address".into(),
            },
            TemplateVar {
                name: "data.expires_minutes".into(),
                description: "Minutes until the code expires".into(),
                example: "10".into(),
            },
        ];
        let extra_vars: HashMap<&str, &[TemplateVar]> = HashMap::from([
            ("password_reset", reset_vars.as_slice()),
            ("otp", otp_vars.as_slice()),
        ]);

        // Map template names to trigger patterns and descriptions.
        let template_info: HashMap<&str, (&str, &str)> = HashMap::from([
            (
                "password_reset",
                (
                    sid_core::models::event::event_types::PASSWORD_RESET_REQUESTED,
                    "Password reset link",
                ),
            ),
            (
                "otp",
                (
                    sid_core::models::event::event_types::OTP_REQUESTED,
                    "One-time code",
                ),
            ),
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
                    variables: standard_vars
                        .iter()
                        .chain(extra_vars.get(name).copied().unwrap_or_default())
                        .cloned()
                        .collect(),
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
mod tests;

/// PostgreSQL integration tests.
/// Require: `cd sid && docker compose -f docker-compose.test.yml up -d` (port 54399).
/// Each test uses a unique template_id suffix to avoid parallel test interference.
#[cfg(test)]
mod pg_tests;
