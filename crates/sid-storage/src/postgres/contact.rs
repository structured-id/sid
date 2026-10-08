// SPDX-License-Identifier: AGPL-3.0-only
//! A profile's own phones and emails: created once, and one primary per
//! profile moved in a single write.

use chrono::{DateTime, Utc};
use sid_core::models::{ProfileEmail, ProfileId, ProfilePhone};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::insert_error;

type Tx<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// The two contact tables that hold a primary flag.
#[derive(Clone, Copy)]
pub(super) enum Contacts {
    Phones,
    Emails,
}

impl Contacts {
    fn lock(self) -> &'static str {
        match self {
            Self::Phones => {
                "SELECT id FROM profile_phones WHERE profile_id = $1 ORDER BY id FOR UPDATE"
            }
            Self::Emails => {
                "SELECT id FROM profile_emails WHERE profile_id = $1 ORDER BY id FOR UPDATE"
            }
        }
    }

    fn exists(self) -> &'static str {
        match self {
            Self::Phones => {
                "SELECT EXISTS (SELECT 1 FROM profile_phones WHERE id = $1 AND profile_id = $2)"
            }
            Self::Emails => {
                "SELECT EXISTS (SELECT 1 FROM profile_emails WHERE id = $1 AND profile_id = $2)"
            }
        }
    }

    fn clear(self) -> &'static str {
        match self {
            Self::Phones => {
                "UPDATE profile_phones SET is_primary = false, updated_at = $2
                 WHERE profile_id = $1 AND is_primary"
            }
            Self::Emails => {
                "UPDATE profile_emails SET is_primary = false, updated_at = $2
                 WHERE profile_id = $1 AND is_primary"
            }
        }
    }

    fn set(self) -> &'static str {
        match self {
            Self::Phones => {
                "UPDATE profile_phones SET is_primary = true, updated_at = $3
                 WHERE id = $1 AND profile_id = $2"
            }
            Self::Emails => {
                "UPDATE profile_emails SET is_primary = true, updated_at = $3
                 WHERE id = $1 AND profile_id = $2"
            }
        }
    }
}

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

/// Lock every contact of the profile in one order, so concurrent primary
/// moves in a profile run one after the other.
async fn lock(tx: &mut Tx<'_>, contacts: Contacts, profile_id: ProfileId) -> SidResult<()> {
    sqlx::query(contacts.lock())
        .bind(profile_id)
        .execute(&mut **tx)
        .await
        .map_err(storage("lock contacts"))?;
    Ok(())
}

/// Take the primary flag from the profile's current primary contact.
pub(super) async fn clear_primary(
    tx: &mut Tx<'_>,
    contacts: Contacts,
    profile_id: ProfileId,
    at: DateTime<Utc>,
) -> SidResult<()> {
    lock(tx, contacts, profile_id).await?;
    sqlx::query(contacts.clear())
        .bind(profile_id)
        .bind(at)
        .execute(&mut **tx)
        .await
        .map_err(storage("clear primary"))?;
    Ok(())
}

/// Make contact `id` the profile's primary; `false` when the profile has no
/// such contact (nothing is changed then).
pub(super) async fn make_primary(
    tx: &mut Tx<'_>,
    contacts: Contacts,
    profile_id: ProfileId,
    id: Uuid,
    at: DateTime<Utc>,
) -> SidResult<bool> {
    lock(tx, contacts, profile_id).await?;
    let exists: bool = sqlx::query_scalar(contacts.exists())
        .bind(id)
        .bind(profile_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage("find contact"))?;
    if !exists {
        return Ok(false);
    }
    sqlx::query(contacts.clear())
        .bind(profile_id)
        .bind(at)
        .execute(&mut **tx)
        .await
        .map_err(storage("clear primary"))?;
    sqlx::query(contacts.set())
        .bind(id)
        .bind(profile_id)
        .bind(at)
        .execute(&mut **tx)
        .await
        .map_err(storage("set primary"))?;
    Ok(true)
}

pub(super) async fn insert_phone(tx: &mut Tx<'_>, phone: &ProfilePhone) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_phones (
            id, profile_id, e164, extension, label, custom_label,
            is_primary, can_receive_sms, can_receive_fax, can_receive_voice,
            verified, verified_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(phone.id.0)
    .bind(phone.profile_id)
    .bind(i64::try_from(phone.e164).map_err(|e| SidError::Validation(format!("e164: {e}")))?)
    .bind(
        phone
            .extension
            .map(i32::try_from)
            .transpose()
            .map_err(|e| SidError::Validation(format!("phone extension: {e}")))?,
    )
    .bind(phone.label.as_str())
    .bind(&phone.custom_label)
    .bind(phone.is_primary)
    .bind(phone.can_receive_sms)
    .bind(phone.can_receive_fax)
    .bind(phone.can_receive_voice)
    .bind(phone.verified)
    .bind(phone.verified_at)
    .bind(phone.created_at)
    .bind(phone.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("profile phone", e))?;
    Ok(())
}

pub(super) async fn insert_email(tx: &mut Tx<'_>, email: &ProfileEmail) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_emails (
            id, profile_id, email, label, custom_label,
            is_primary, verified, verified_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(email.id.0)
    .bind(email.profile_id)
    .bind(&email.email)
    .bind(email.label.as_str())
    .bind(&email.custom_label)
    .bind(email.is_primary)
    .bind(email.verified)
    .bind(email.verified_at)
    .bind(email.created_at)
    .bind(email.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("profile email", e))?;
    Ok(())
}
