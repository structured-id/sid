// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in history of local Profiles (`SignInHistoryStore`).

use async_trait::async_trait;
use sid_core::models::ProfileId;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::{LoginLocation, SignInHistoryStore};

use super::PostgresBackend;

#[async_trait]
impl SignInHistoryStore for PostgresBackend {
    type Owner = ProfileId;

    async fn get_most_recent_session_ip(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<(std::net::IpAddr, chrono::DateTime<chrono::Utc>)>> {
        // A sign-in still owing its second factor is no history.
        let row: Option<(std::net::IpAddr, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT ip_address, created_at FROM sessions WHERE profile_id = $1 \
             AND ip_address IS NOT NULL AND NOT (is_provisional AND scopes = $2) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(profile_id)
        .bind(sid_core::models::session::SECOND_FACTOR_SCOPE)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row)
    }

    async fn has_recent_session_from_ip(
        &self,
        profile_id: ProfileId,
        ip: std::net::IpAddr,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window.as_secs() as i64);
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE profile_id = $1 AND ip_address = $2 AND created_at > $3 \
             AND NOT (is_provisional AND scopes = $4))",
        ).bind(profile_id)
        .bind(ip)
        .bind(cutoff)
        .bind(sid_core::models::session::SECOND_FACTOR_SCOPE)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0)
    }

    async fn has_recent_session_from_device(
        &self,
        profile_id: ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window.as_secs() as i64);
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE profile_id = $1 AND device_id = $2 AND created_at > $3 \
             AND NOT (is_provisional AND scopes = $4))",
        ).bind(profile_id)
        .bind(device_id)
        .bind(cutoff)
        .bind(sid_core::models::session::SECOND_FACTOR_SCOPE)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0)
    }

    async fn record_login_location(
        &self,
        profile_id: ProfileId,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO profile_locations (profile_id, country, latitude, longitude, login_count, first_seen, last_seen, designated)
             VALUES ($1, $2, $3, $4, 1, now(), now(), 1 >= $5)
             ON CONFLICT (profile_id, country)
             DO UPDATE SET
                login_count = profile_locations.login_count + 1,
                last_seen = now(),
                latitude = $3,
                longitude = $4,
                designated = (profile_locations.login_count + 1) >= $5",
        ).bind(profile_id)
        .bind(country)
        .bind(latitude)
        .bind(longitude)
        .bind(designated_threshold as i32)
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Record login location failed: {}", e)))?;
        Ok(())
    }

    async fn get_designated_countries(&self, profile_id: ProfileId) -> SidResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT country FROM profile_locations WHERE profile_id = $1 AND designated = TRUE",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query designated countries failed: {}", e)))?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }

    async fn export_login_locations(&self) -> SidResult<Vec<(ProfileId, LoginLocation)>> {
        let rows: Vec<(ProfileId, String, f64, f64, i32, Time, Time, bool)> = sqlx::query_as(
            "SELECT profile_id, country, latitude, longitude, login_count, first_seen, last_seen,
                    designated
             FROM profile_locations ORDER BY profile_id, country",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("export login locations: {e}")))?;
        Ok(rows
            .into_iter()
            .map(
                |(owner, country, lat, lon, count, first, last, designated)| {
                    (
                        owner,
                        location_of((country, lat, lon, count, first, last, designated)),
                    )
                },
            )
            .collect())
    }

    async fn import_login_location(
        &self,
        owner: ProfileId,
        location: &LoginLocation,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("import login location: {e}"));
        let count = i32::try_from(location.login_count)
            .map_err(|_| SidError::Validation("login count is out of range".into()))?;
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let held: Option<LocationRow> = sqlx::query_as(
            "SELECT country, latitude, longitude, login_count, first_seen, last_seen, designated
             FROM profile_locations WHERE profile_id = $1 AND country = $2",
        )
        .bind(owner)
        .bind(&location.country)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        if let Some(row) = held {
            return crate::transfer_repeat(&location_of(row), location, "login location");
        }
        sqlx::query(
            "INSERT INTO profile_locations (profile_id, country, latitude, longitude, login_count,
                 first_seen, last_seen, designated)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(owner)
        .bind(&location.country)
        .bind(location.latitude)
        .bind(location.longitude)
        .bind(count)
        .bind(location.first_seen)
        .bind(location.last_seen)
        .bind(location.designated)
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("login location", e))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{owner}"), ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
}

type Time = chrono::DateTime<chrono::Utc>;

/// country, latitude, longitude, login_count, first_seen, last_seen, designated
type LocationRow = (String, f64, f64, i32, Time, Time, bool);

fn location_of(row: LocationRow) -> LoginLocation {
    let (country, latitude, longitude, login_count, first_seen, last_seen, designated) = row;
    LoginLocation {
        country,
        latitude,
        longitude,
        login_count: i64::from(login_count),
        first_seen,
        last_seen,
        designated,
    }
}
