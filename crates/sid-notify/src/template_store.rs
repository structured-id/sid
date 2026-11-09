// SPDX-License-Identifier: AGPL-3.0-only
//! Template storage: the shipped defaults with the administrators'
//! customizations from this service's PostgreSQL database over them.
//!
//! Every read takes the customizations from the database, so each replica
//! answers with what was committed. A change and the completion of the
//! keyed command that made it commit in one transaction. Reset deletes the
//! customization, so the default answers again.

use crate::routing::RoutingTable;
use crate::template::{NotificationTemplate as InternalTemplate, TemplateEngine};
use chrono::{DateTime, Utc};
use sid_core::models::OperationCompletion;
use sqlx::PgConnection;
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

/// What a template answers with for one channel and locale, as one read or
/// write of the store left it.
#[derive(Debug, Clone)]
pub(crate) struct Effective {
    /// `None` when nothing answers on the channel: its customization was
    /// removed and the channel has no default.
    pub(crate) content: Option<StoredContent>,
    /// Whether a customization answers rather than the default.
    pub(crate) customized: bool,
    /// The locales the template has, `en` always among them.
    pub(crate) locales: Vec<String>,
}

/// The template store: shipped defaults, customizations in the database.
pub(crate) struct TemplateStore {
    /// In-memory default templates (CE shipped).
    defaults: Vec<TemplateMeta>,
    /// Default content by (template_id, channel).
    default_content: HashMap<(String, Channel), StoredContent>,
    /// This service's database, holding the customizations.
    pool: sqlx::PgPool,
    /// Reference to template engine for rendering.
    engine: Arc<RwLock<TemplateEngine>>,
}

impl TemplateStore {
    /// The store over `pool`, its tables created when absent.
    pub(crate) async fn new(
        _routing: &RoutingTable,
        engine: Arc<RwLock<TemplateEngine>>,
        pool: sqlx::PgPool,
    ) -> Result<Self, sqlx::Error> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let (defaults, default_content) = Self::build_defaults(&engine).await;
        Ok(Self {
            defaults,
            default_content,
            pool,
            engine,
        })
    }

    /// The metadata of the shipped template `template_id`.
    pub(crate) fn meta(&self, template_id: &str) -> Option<&TemplateMeta> {
        self.defaults.iter().find(|m| m.template_id == template_id)
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

    /// List all templates with customization status.
    pub(crate) async fn list_templates(
        &self,
        channel_filter: Option<Channel>,
        customized_only: bool,
    ) -> Result<Vec<TemplateSummary>, TemplateStoreError> {
        // The latest customization of each customized template.
        let customized: HashMap<String, DateTime<Utc>> =
            sqlx::query_as::<_, (String, DateTime<Utc>)>(
                "SELECT template_id, max(updated_at) FROM notification_template_overrides
             GROUP BY template_id",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| store_error("list template customizations", e))?
            .into_iter()
            .collect();

        let mut result = Vec::new();
        for meta in &self.defaults {
            if let Some(ch) = channel_filter
                && !meta.channels.contains(&ch)
            {
                continue;
            }
            let updated_at = customized.get(&meta.template_id).copied();
            if customized_only && updated_at.is_none() {
                continue;
            }
            result.push(TemplateSummary {
                template_id: meta.template_id.clone(),
                name: meta.name.clone(),
                description: meta.description.clone(),
                channels: meta.channels.clone(),
                trigger: meta.trigger.clone(),
                customized: updated_at.is_some(),
                updated_at,
            });
        }
        Ok(result)
    }

    /// Template content for a channel and locale: its customization in that
    /// locale, else its `en` customization, else the default; `None` for a
    /// template this service does not ship.
    pub(crate) async fn get_template(
        &self,
        template_id: &str,
        channel: Channel,
        locale: &str,
    ) -> Result<Option<(StoredContent, bool, &TemplateMeta)>, TemplateStoreError> {
        let Some(meta) = self.meta(template_id) else {
            return Ok(None);
        };
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| store_error("read a template", e))?;
        Ok(self
            .effective_in(&mut conn, template_id, channel, locale)
            .await?
            .map(|(content, customized)| (content, customized, meta)))
    }

    /// The locales template `template_id` has, `en` always among them.
    pub(crate) async fn available_locales(
        &self,
        template_id: &str,
    ) -> Result<Vec<String>, TemplateStoreError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| store_error("read template locales", e))?;
        locales_in(&mut conn, template_id).await
    }

    /// The content `template_id` answers with on `channel` in `locale`, read
    /// in `conn`, and whether a customization answers.
    async fn effective_in(
        &self,
        conn: &mut PgConnection,
        template_id: &str,
        channel: Channel,
        locale: &str,
    ) -> Result<Option<(StoredContent, bool)>, TemplateStoreError> {
        if let Some(content) = override_in(conn, template_id, channel, locale).await? {
            return Ok(Some((content, true)));
        }
        if locale != "en"
            && let Some(content) = override_in(conn, template_id, channel, "en").await?
        {
            return Ok(Some((content, true)));
        }
        Ok(self
            .default_content
            .get(&(template_id.to_string(), channel))
            .map(|c| (c.clone(), false)))
    }

    /// Customize `template_id` on `channel` in `locale` with `content`. In
    /// the same transaction, `complete` receives what the template answers
    /// with after the change and gives the caller's answer with the
    /// completion of the keyed command making it, which commits with the
    /// change; `None` commits the change alone.
    pub(crate) async fn update_template<R>(
        &self,
        template_id: &str,
        channel: Channel,
        locale: &str,
        content: StoredContent,
        complete: impl FnOnce(&Effective, &TemplateMeta) -> (R, Option<OperationCompletion>),
    ) -> Result<R, TemplateStoreError> {
        let meta = self
            .meta(template_id)
            .ok_or_else(|| TemplateStoreError::NotFound(template_id.to_string()))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| store_error("begin a template change", e))?;
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
        .execute(&mut *tx)
        .await
        .map_err(|e| store_error("store a template customization", e))?;
        let effective = Effective {
            content: Some(content.clone()),
            customized: true,
            locales: locales_in(&mut tx, template_id).await?,
        };
        let (answer, completion) = complete(&effective, meta);
        if let Some(completion) = completion {
            sid_storage::PgOperationStore::record_in_tx(&mut tx, &completion)
                .await
                .map_err(TemplateStoreError::Store)?;
        }
        tx.commit()
            .await
            .map_err(|e| store_error("commit a template change", e))?;

        // The engine delivery renders from takes the email `en` content.
        if channel == Channel::Email && locale == "en" {
            self.render_from(template_id, &content).await;
        }
        Ok(answer)
    }

    /// Remove the customization of `template_id` on `channel` in `locale`,
    /// so its `en` customization or its default answers again; `complete`
    /// as for [`Self::update_template`].
    pub(crate) async fn reset_template<R>(
        &self,
        template_id: &str,
        channel: Channel,
        locale: &str,
        complete: impl FnOnce(&Effective, &TemplateMeta) -> (R, Option<OperationCompletion>),
    ) -> Result<R, TemplateStoreError> {
        let meta = self
            .meta(template_id)
            .ok_or_else(|| TemplateStoreError::NotFound(template_id.to_string()))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| store_error("begin a template reset", e))?;
        sqlx::query(
            "DELETE FROM notification_template_overrides
             WHERE template_id = $1 AND channel = $2 AND locale = $3",
        )
        .bind(template_id)
        .bind(channel.as_i16())
        .bind(locale)
        .execute(&mut *tx)
        .await
        .map_err(|e| store_error("remove a template customization", e))?;
        // A channel with no default answers with nothing once its last
        // customization is gone; the removal still commits.
        let (content, customized) = match self
            .effective_in(&mut tx, template_id, channel, locale)
            .await?
        {
            Some((content, customized)) => (Some(content), customized),
            None => (None, false),
        };
        let effective = Effective {
            content,
            customized,
            locales: locales_in(&mut tx, template_id).await?,
        };
        let (answer, completion) = complete(&effective, meta);
        if let Some(completion) = completion {
            sid_storage::PgOperationStore::record_in_tx(&mut tx, &completion)
                .await
                .map_err(TemplateStoreError::Store)?;
        }
        tx.commit()
            .await
            .map_err(|e| store_error("commit a template reset", e))?;

        if channel == Channel::Email
            && locale == "en"
            && let Some(default_content) = self
                .default_content
                .get(&(template_id.to_string(), channel))
        {
            self.render_from(template_id, default_content).await;
        }
        Ok(answer)
    }

    /// Have the engine delivery renders from use `content` for `template_id`.
    async fn render_from(&self, template_id: &str, content: &StoredContent) {
        self.engine.write().await.register(InternalTemplate {
            name: template_id.to_string(),
            subject: (!content.subject.is_empty()).then(|| content.subject.clone()),
            body_html: content.html_body.clone(),
            body_text: content.text_body.clone(),
            default_priority: sid_plugin::notification::NotificationPriority::Transactional,
        });
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

    /// The store failed, or the keyed command's completion was refused
    /// (already completed by another attempt, a period no longer admitted).
    #[error(transparent)]
    Store(sid_core::Error),
}

fn store_error(operation: &str, e: sqlx::Error) -> TemplateStoreError {
    TemplateStoreError::Store(sid_core::Error::Storage(format!("{operation}: {e}")))
}

/// A customization's content.
#[derive(sqlx::FromRow)]
struct OverrideRow {
    subject: String,
    html_body: String,
    text_body: String,
    sms_body: String,
    push_title: String,
    push_body: String,
    push_action_url: String,
    updated_at: DateTime<Utc>,
}

/// The customization of `template_id` on `channel` in `locale`, read in
/// `conn`.
async fn override_in(
    conn: &mut PgConnection,
    template_id: &str,
    channel: Channel,
    locale: &str,
) -> Result<Option<StoredContent>, TemplateStoreError> {
    let row = sqlx::query_as::<_, OverrideRow>(
        "SELECT subject, html_body, text_body, sms_body, push_title, push_body,
                push_action_url, updated_at
         FROM notification_template_overrides
         WHERE template_id = $1 AND channel = $2 AND locale = $3",
    )
    .bind(template_id)
    .bind(channel.as_i16())
    .bind(locale)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| store_error("read a template customization", e))?;
    Ok(row.map(|row| StoredContent {
        subject: row.subject,
        html_body: row.html_body,
        text_body: row.text_body,
        sms_body: row.sms_body,
        push_title: row.push_title,
        push_body: row.push_body,
        push_action_url: row.push_action_url,
        updated_at: row.updated_at,
    }))
}

/// The locales `template_id` is customized in, read in `conn`, with `en`,
/// sorted.
async fn locales_in(
    conn: &mut PgConnection,
    template_id: &str,
) -> Result<Vec<String>, TemplateStoreError> {
    let mut locales: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT locale FROM notification_template_overrides WHERE template_id = $1",
    )
    .bind(template_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| store_error("read template locales", e))?;
    locales.push("en".to_string());
    locales.sort();
    locales.dedup();
    Ok(locales)
}

#[cfg(test)]
mod tests;
