// SPDX-License-Identifier: AGPL-3.0-only
//! A profile's own phones and emails for the SQLite backend: created once,
//! settings changed field by field, one primary moved in a single write
//! (`BEGIN IMMEDIATE` serializes the writers).

use chrono::{DateTime, Utc};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        EmailSettings, MutationContext, PhoneSettings, ProfileEmail, ProfileEmailId, ProfileId,
        ProfilePhone, ProfilePhoneId,
    },
};

use super::{SqliteBackend, fmt_dt, fmt_dt_opt, insert_error};

impl SqliteBackend {
    pub(crate) async fn create_profile_phone_impl(
        &self,
        phone: &ProfilePhone,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let at = fmt_dt(&phone.updated_at);
        let mut tx = self.begin_write().await?;
        if phone.is_primary {
            sqlx::query(
                "UPDATE profile_phones SET is_primary = 0, updated_at = ?
                 WHERE profile_id = ? AND is_primary = 1",
            )
            .bind(&at)
            .bind(phone.profile_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("clear primary phone: {e}")))?;
        }
        sqlx::query(
            "INSERT INTO profile_phones (id, profile_id, e164, extension, label, custom_label,
                is_primary, can_receive_sms, can_receive_fax, can_receive_voice, verified,
                verified_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(phone.id.0.to_string())
        .bind(phone.profile_id)
        .bind(i64::try_from(phone.e164).map_err(|e| SidError::Validation(format!("e164: {e}")))?)
        .bind(phone.extension.map(i64::from))
        .bind(phone.label.as_str())
        .bind(&phone.custom_label)
        .bind(phone.is_primary)
        .bind(phone.can_receive_sms)
        .bind(phone.can_receive_fax)
        .bind(phone.can_receive_voice)
        .bind(phone.verified)
        .bind(fmt_dt_opt(phone.verified_at))
        .bind(fmt_dt(&phone.created_at))
        .bind(&at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("profile phone", e))?;
        Self::commit_mutation(tx, &format!("profile_phone:{}", phone.id.0), ctx).await
    }

    pub(crate) async fn update_profile_phone_settings_impl(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        settings: &PhoneSettings,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query(
            "UPDATE profile_phones SET label = COALESCE(?, label),
                custom_label = CASE WHEN ? THEN ? ELSE custom_label END,
                can_receive_sms = COALESCE(?, can_receive_sms),
                can_receive_fax = COALESCE(?, can_receive_fax),
                can_receive_voice = COALESCE(?, can_receive_voice),
                updated_at = ?
             WHERE id = ? AND profile_id = ?",
        )
        .bind(settings.label.as_ref().map(|l| l.as_str()))
        .bind(settings.custom_label.is_some())
        .bind(settings.custom_label.clone().flatten())
        .bind(settings.can_receive_sms)
        .bind(settings.can_receive_fax)
        .bind(settings.can_receive_voice)
        .bind(fmt_dt(&at))
        .bind(id.0.to_string())
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update phone: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("profile_phone:{}", id.0), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn set_primary_profile_phone_impl(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let at = fmt_dt(&at);
        let mut tx = self.begin_write().await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM profile_phones WHERE id = ? AND profile_id = ?)",
        )
        .bind(id.0.to_string())
        .bind(profile_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("find phone: {e}")))?;
        if !exists {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE profile_phones SET is_primary = 0, updated_at = ?
             WHERE profile_id = ? AND is_primary = 1",
        )
        .bind(&at)
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("clear primary phone: {e}")))?;
        sqlx::query("UPDATE profile_phones SET is_primary = 1, updated_at = ? WHERE id = ?")
            .bind(&at)
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("set primary phone: {e}")))?;
        Self::commit_mutation(tx, &format!("profile_phone:{}", id.0), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn create_profile_email_impl(
        &self,
        email: &ProfileEmail,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let at = fmt_dt(&email.updated_at);
        let mut tx = self.begin_write().await?;
        if email.is_primary {
            sqlx::query(
                "UPDATE profile_emails SET is_primary = 0, updated_at = ?
                 WHERE profile_id = ? AND is_primary = 1",
            )
            .bind(&at)
            .bind(email.profile_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("clear primary email: {e}")))?;
        }
        sqlx::query(
            "INSERT INTO profile_emails (id, profile_id, email, label, custom_label, is_primary,
                verified, verified_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(email.id.0.to_string())
        .bind(email.profile_id)
        .bind(&email.email)
        .bind(email.label.as_str())
        .bind(&email.custom_label)
        .bind(email.is_primary)
        .bind(email.verified)
        .bind(fmt_dt_opt(email.verified_at))
        .bind(fmt_dt(&email.created_at))
        .bind(&at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("profile email", e))?;
        Self::commit_mutation(tx, &format!("profile_email:{}", email.id.0), ctx).await
    }

    pub(crate) async fn update_profile_email_settings_impl(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        settings: &EmailSettings,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query(
            "UPDATE profile_emails SET label = COALESCE(?, label),
                custom_label = CASE WHEN ? THEN ? ELSE custom_label END,
                updated_at = ?
             WHERE id = ? AND profile_id = ?",
        )
        .bind(settings.label.as_ref().map(|l| l.as_str()))
        .bind(settings.custom_label.is_some())
        .bind(settings.custom_label.clone().flatten())
        .bind(fmt_dt(&at))
        .bind(id.0.to_string())
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update email: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("profile_email:{}", id.0), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn set_primary_profile_email_impl(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let at = fmt_dt(&at);
        let mut tx = self.begin_write().await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM profile_emails WHERE id = ? AND profile_id = ?)",
        )
        .bind(id.0.to_string())
        .bind(profile_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("find email: {e}")))?;
        if !exists {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE profile_emails SET is_primary = 0, updated_at = ?
             WHERE profile_id = ? AND is_primary = 1",
        )
        .bind(&at)
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("clear primary email: {e}")))?;
        sqlx::query("UPDATE profile_emails SET is_primary = 1, updated_at = ? WHERE id = ?")
            .bind(&at)
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("set primary email: {e}")))?;
        Self::commit_mutation(tx, &format!("profile_email:{}", id.0), ctx).await?;
        Ok(true)
    }
}
