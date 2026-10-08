// SPDX-License-Identifier: AGPL-3.0-only
//! Login history the anomaly rules read (recent IPs and devices, designated
//! countries) for SQLite backend.

use sid_core::{Error as SidError, Result as SidResult, models::ProfileId};
use sqlx::Row;

use super::{SqliteBackend, col, fmt_dt, parse_dt};

/// The instant `window` ago, as stored timestamps are written.
fn since(window: std::time::Duration) -> SidResult<String> {
    let window = chrono::Duration::from_std(window)
        .map_err(|e| SidError::Storage(format!("history window: {e}")))?;
    Ok(fmt_dt(&(chrono::Utc::now() - window)))
}

impl SqliteBackend {
    pub(crate) async fn get_most_recent_session_ip_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<(String, chrono::DateTime<chrono::Utc>)>> {
        let row = sqlx::query(
            "SELECT ip_address, created_at FROM sessions WHERE profile_id = ? \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.map(|row| {
            Ok((
                col(&row, "ip_address")?,
                parse_dt(&row.get::<String, _>("created_at")),
            ))
        })
        .transpose()
    }

    pub(crate) async fn has_recent_session_from_ip_impl(
        &self,
        profile_id: ProfileId,
        ip: &str,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sessions \
             WHERE profile_id = ? AND ip_address = ? AND created_at > ?)",
        )
        .bind(profile_id)
        .bind(ip)
        .bind(since(window)?)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(crate) async fn has_recent_session_from_device_impl(
        &self,
        profile_id: ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sessions \
             WHERE profile_id = ? AND device_id = ? AND created_at > ?)",
        )
        .bind(profile_id)
        .bind(device_id.to_string())
        .bind(since(window)?)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))
    }

    /// Count a login from `country`; it becomes designated once its logins
    /// reach `designated_threshold`.
    pub(crate) async fn record_login_location_impl(
        &self,
        profile_id: ProfileId,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> SidResult<()> {
        let now = fmt_dt(&chrono::Utc::now());
        sqlx::query(
            "INSERT INTO profile_locations (profile_id, country, latitude, longitude, login_count, first_seen, last_seen, designated) \
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, 1 >= ?6) \
             ON CONFLICT(profile_id, country) DO UPDATE SET \
                login_count = login_count + 1, last_seen = ?5, \
                latitude = ?3, longitude = ?4, \
                designated = login_count + 1 >= ?6",
        )
        .bind(profile_id)
        .bind(country)
        .bind(latitude)
        .bind(longitude)
        .bind(now)
        .bind(i64::from(designated_threshold))
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Record login location failed: {e}")))?;
        Ok(())
    }

    pub(crate) async fn get_designated_countries_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<String>> {
        sqlx::query_scalar(
            "SELECT country FROM profile_locations WHERE profile_id = ? AND designated = 1 \
             ORDER BY country",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))
    }
}
