// SPDX-License-Identifier: AGPL-3.0-only
//! The sign-in history the anomaly rules read in CoordiNode: recent
//! addresses and devices from a Profile's sessions, and the countries it
//! signs in from. A sign-in still owing its second factor is no history.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::{ProfileId, Session};
use sid_core::{Error as SidError, Result as SidResult};

use super::{CoordinodeBackend, Decision, Params, Statements, get_int, get_text, key, time};

/// The instant `window` ago.
fn since(window: std::time::Duration) -> SidResult<DateTime<Utc>> {
    let window = chrono::Duration::from_std(window)
        .map_err(|e| SidError::Storage(format!("history window: {e}")))?;
    Utc::now()
        .checked_sub_signed(window)
        .ok_or_else(|| SidError::Validation("history window out of range".into()))
}

/// `profile`'s sessions that count as sign-ins, newest first.
fn sign_ins(tx: &Statements<'_>, profile: ProfileId) -> SidResult<Vec<Session>> {
    Ok(super::session::profile_sessions(tx, profile)?
        .into_iter()
        .filter(|s| !s.awaits_second_factor())
        .collect())
}

fn country_key(profile: ProfileId, country: &str) -> SidResult<Value> {
    key(&[profile.as_bytes(), country.as_bytes()])
}

/// Delete in `tx` the sign-in locations of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    tx.run(
        "MATCH (l:SidLoginLocation) WHERE l.profile_id = $id DETACH DELETE l",
        Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn get_most_recent_session_ip(
        &self,
        profile: ProfileId,
    ) -> SidResult<Option<(IpAddr, DateTime<Utc>)>> {
        self.read(move |tx| {
            Ok(sign_ins(tx, profile)?
                .into_iter()
                .filter_map(|s| s.ip_address.map(|ip| (ip, s.created_at)))
                .max_by_key(|(_, at)| *at))
        })
        .await
    }

    pub(super) async fn has_recent_session_from_ip(
        &self,
        profile: ProfileId,
        ip: IpAddr,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let since = since(window)?;
        self.read(move |tx| {
            Ok(sign_ins(tx, profile)?
                .iter()
                .any(|s| s.ip_address == Some(ip) && s.created_at > since))
        })
        .await
    }

    pub(super) async fn has_recent_session_from_device(
        &self,
        profile: ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let since = since(window)?;
        self.read(move |tx| {
            Ok(sign_ins(tx, profile)?
                .iter()
                .any(|s| s.device_id == Some(device_id) && s.created_at > since))
        })
        .await
    }

    pub(super) async fn record_login_location(
        &self,
        profile: ProfileId,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> SidResult<()> {
        let country = country.to_owned();
        self.transaction(move |tx| {
            let now = time(Utc::now());
            let pair = country_key(profile, &country)?;
            let stored = tx.run(
                "MATCH (l:SidLoginLocation) WHERE l.pair = $pair RETURN l.login_count AS n",
                Params::default().with("pair", pair.clone()),
            )?;
            let logins = match stored.first() {
                Some(row) => get_int(row, "n")?
                    .checked_add(1)
                    .ok_or_else(|| SidError::Storage("login count overflow".into()))?,
                None => 1,
            };
            let params = Params::default()
                .with("pair", pair)
                .with("profile", Value::Binary(profile.as_bytes().to_vec()))
                .with("country", Value::String(country.clone()))
                .with("latitude", Value::Float(latitude))
                .with("longitude", Value::Float(longitude))
                .with("count", Value::Int(logins))
                .with(
                    "designated",
                    Value::Bool(logins >= i64::from(designated_threshold)),
                )
                .with("now", now);
            if stored.is_empty() {
                super::profile::claim_profile(tx, profile)?;
                tx.run(
                    "CREATE (l:SidLoginLocation {pair: $pair, profile_id: $profile,
                        country: $country, latitude: $latitude, longitude: $longitude,
                        login_count: $count, first_seen: $now, last_seen: $now,
                        designated: $designated})",
                    params,
                )?;
            } else {
                tx.run(
                    "MATCH (l:SidLoginLocation) WHERE l.pair = $pair
                     SET l.login_count = $count, l.last_seen = $now, l.latitude = $latitude,
                         l.longitude = $longitude, l.designated = $designated",
                    params,
                )?;
            }
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn get_designated_countries(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<String>> {
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (l:SidLoginLocation) WHERE l.profile_id = $id AND l.designated = true
                 RETURN l.country AS country",
                Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
            )?;
            let mut countries = rows
                .iter()
                .map(|row| get_text(row, "country"))
                .collect::<SidResult<Vec<_>>>()?;
            countries.sort();
            Ok(countries)
        })
        .await
    }
}
