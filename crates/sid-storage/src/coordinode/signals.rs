// SPDX-License-Identifier: AGPL-3.0-only
//! Risk signals and per-Profile settings in CoordiNode: anomaly events, IP
//! reputation, the IP allowlist, notification preferences, and the
//! integrity counts of records whose owner is gone.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::notification::NotificationPreferences;
use sid_core::models::{
    AnomalyEventId, AnomalyEventRecord, IpReputation, MutationContext, ProfileId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bytes, get_int,
    get_opt_bytes, get_text, get_time, get_uuid, time, uuid,
};

const EVENT: &str = "a.id AS id, a.rule_id AS rule_id, a.profile_id AS profile_id,
    a.ip_address AS ip_address, a.description AS description, a.risk_score AS risk_score,
    a.reaction AS reaction, a.occurred_at AS occurred_at";

fn event(row: &Row) -> SidResult<AnomalyEventRecord> {
    let risk_score = get_int(row, "risk_score")?;
    Ok(AnomalyEventRecord {
        id: AnomalyEventId(get_uuid(row, "id")?),
        rule_id: get_text(row, "rule_id")?,
        profile_id: get_text(row, "profile_id")?,
        ip_address: get_opt_bytes(row, "ip_address")?
            .map(|b| super::audit::ip_of(&b))
            .transpose()?,
        description: get_text(row, "description")?,
        risk_score: i32::try_from(risk_score)
            .map_err(|_| SidError::Storage(format!("risk_score: {risk_score}")))?,
        reaction: get_text(row, "reaction")?,
        timestamp: get_time(row, "occurred_at")?,
    })
}

const REPUTATION: &str = "r.ip AS ip, r.failed_count AS failed, r.success_count AS succeeded,
    r.first_seen_at AS first_seen_at, r.last_failed_at AS last_failed_at,
    r.last_success_at AS last_success_at, r.updated_at AS updated_at";

fn reputation(row: &Row) -> SidResult<IpReputation> {
    Ok(IpReputation {
        ip: get_text(row, "ip")?,
        failed_count: get_int(row, "failed")?,
        success_count: get_int(row, "succeeded")?,
        first_seen_at: get_time(row, "first_seen_at")?,
        last_failed_at: super::get_opt_time(row, "last_failed_at")?,
        last_success_at: super::get_opt_time(row, "last_success_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// The reputation of one address: its outcome counts and score.
struct Reputation {
    failed: i64,
    succeeded: i64,
}

impl Reputation {
    /// `failed / (failed + succeeded + 1)`.
    fn score(&self) -> f64 {
        // Counts of logins are far inside f64's exact integers.
        self.failed as f64 / (self.failed + self.succeeded + 1) as f64
    }
}

fn float(row: &Row, name: &str) -> SidResult<f64> {
    match row.get(name) {
        Some(Value::Float(v)) => Ok(*v),
        other => Err(SidError::Storage(format!(
            "{name} is not a float: {other:?}"
        ))),
    }
}

/// The allowlist, oldest entry first.
fn allowlist(tx: &Statements<'_>) -> SidResult<Vec<(String, String, DateTime<Utc>)>> {
    let rows = tx.run(
        "MATCH (w:SidIpAllowlistEntry)
         RETURN w.cidr AS cidr, w.description AS description, w.created_at AS created_at",
        Params::default(),
    )?;
    let entries = rows
        .iter()
        .map(|row| {
            Ok((
                get_text(row, "cidr")?,
                get_text(row, "description")?,
                get_time(row, "created_at")?,
            ))
        })
        .collect::<SidResult<Vec<_>>>()?;
    Ok(super::sorted_page(
        entries,
        |(cidr, _, at)| (*at, cidr.clone()),
        0,
        u64::MAX,
    ))
}

/// Delete in `tx` the notification preferences of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    tx.run(
        "MATCH (n:SidNotificationPreferences) WHERE n.profile_id = $id DETACH DELETE n",
        Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
    )?;
    Ok(())
}

/// How many nodes of `label` name a `property` no Profile holds.
fn orphans_of(tx: &Statements<'_>, label: &str, property: &str) -> SidResult<u64> {
    let rows = tx.run(
        &format!("MATCH (n:{label}) WHERE n.{property} IS NOT NULL RETURN n.{property} AS owner"),
        Params::default(),
    )?;
    let mut orphaned = 0u64;
    for row in &rows {
        let owner = get_bytes(row, "owner")?;
        let found = tx.run(
            "MATCH (p:SidProfile) WHERE p.id = $id RETURN p.id AS id",
            Params::default().with("id", Value::Binary(owner)),
        )?;
        if found.is_empty() {
            orphaned += 1;
        }
    }
    Ok(orphaned)
}

impl CoordinodeBackend {
    // === Anomaly events ===

    pub(super) async fn save_anomaly_event(&self, e: &AnomalyEventRecord) -> SidResult<()> {
        let e = e.clone();
        self.transaction(move |tx| {
            tx.run(
                "CREATE (a:SidAnomalyEvent {id: $id, rule_id: $rule_id, profile_id: $profile_id,
                    ip_address: $ip_address, description: $description, risk_score: $risk_score,
                    reaction: $reaction, occurred_at: $occurred_at})",
                Params::default()
                    .with("id", uuid(&e.id.0))
                    .with("rule_id", Value::String(e.rule_id.clone()))
                    .with("profile_id", Value::String(e.profile_id.clone()))
                    .with(
                        "ip_address",
                        e.ip_address.map_or(Value::Null, super::audit::ip_value),
                    )
                    .with("description", Value::String(e.description.clone()))
                    .with("risk_score", Value::Int(i64::from(e.risk_score)))
                    .with("reaction", Value::String(e.reaction.clone()))
                    .with("occurred_at", time(e.timestamp)),
            )?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn list_anomaly_events(
        &self,
        rule_id: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> SidResult<Vec<AnomalyEventRecord>> {
        let rule_id = rule_id.map(str::to_owned);
        let (limit, offset) = (
            u64::try_from(limit).map_err(|_| SidError::Validation("negative limit".into()))?,
            u64::try_from(offset).map_err(|_| SidError::Validation("negative offset".into()))?,
        );
        self.read(move |tx| {
            let rows = match &rule_id {
                Some(rule) => tx.run(
                    &format!("MATCH (a:SidAnomalyEvent) WHERE a.rule_id = $rule RETURN {EVENT}"),
                    Params::default().with("rule", Value::String(rule.clone())),
                )?,
                None => tx.run(
                    &format!("MATCH (a:SidAnomalyEvent) RETURN {EVENT}"),
                    Params::default(),
                )?,
            };
            let all = rows.iter().map(event).collect::<SidResult<Vec<_>>>()?;
            // Newest first.
            Ok(super::sorted_page(
                all,
                |e| (std::cmp::Reverse(e.timestamp), std::cmp::Reverse(e.id.0)),
                offset,
                limit,
            ))
        })
        .await
    }

    // === IP reputation ===

    pub(super) async fn record_ip_reputation_event(
        &self,
        ip: &str,
        success: bool,
    ) -> SidResult<()> {
        let ip = ip.to_owned();
        self.transaction(move |tx| {
            let now = time(Utc::now());
            let stored = tx.run(
                "MATCH (r:SidIpReputation) WHERE r.ip = $ip
                 RETURN r.failed_count AS failed, r.success_count AS succeeded",
                Params::default().with("ip", Value::String(ip.clone())),
            )?;
            let mut reputation = match stored.first() {
                Some(row) => Reputation {
                    failed: get_int(row, "failed")?,
                    succeeded: get_int(row, "succeeded")?,
                },
                None => Reputation {
                    failed: 0,
                    succeeded: 0,
                },
            };
            if success {
                reputation.succeeded += 1;
            } else {
                reputation.failed += 1;
            }
            let params = Params::default()
                .with("ip", Value::String(ip.clone()))
                .with("failed", Value::Int(reputation.failed))
                .with("succeeded", Value::Int(reputation.succeeded))
                .with("score", Value::Float(reputation.score()))
                .with("now", now);
            if stored.is_empty() {
                // Concurrent first events create one unique address node.
                tx.run(
                    &format!(
                        "CREATE (r:SidIpReputation {{ip: $ip, failed_count: $failed,
                            success_count: $succeeded, score: $score, first_seen_at: $now,
                            {outcome}: $now, updated_at: $now}})",
                        outcome = if success {
                            "last_success_at"
                        } else {
                            "last_failed_at"
                        }
                    ),
                    params,
                )?;
            } else {
                tx.run(
                    &format!(
                        "MATCH (r:SidIpReputation) WHERE r.ip = $ip
                         SET r.failed_count = $failed, r.success_count = $succeeded,
                             r.score = $score, r.{outcome} = $now, r.updated_at = $now",
                        outcome = if success {
                            "last_success_at"
                        } else {
                            "last_failed_at"
                        }
                    ),
                    params,
                )?;
            }
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn get_ip_reputation_score(&self, ip: &str) -> SidResult<Option<f32>> {
        let ip = ip.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (r:SidIpReputation) WHERE r.ip = $ip RETURN r.score AS score",
                Params::default().with("ip", Value::String(ip.clone())),
            )?;
            // A score is a ratio in [0, 1]; f32 holds it without meaningful
            // loss.
            rows.first()
                .map(|row| float(row, "score").map(|s| s as f32))
                .transpose()
        })
        .await
    }

    pub(super) async fn list_suspicious_ips(
        &self,
        min_score: f32,
        limit: i64,
    ) -> SidResult<Vec<(String, f32)>> {
        let limit =
            u64::try_from(limit).map_err(|_| SidError::Validation("negative limit".into()))?;
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (r:SidIpReputation) WHERE r.score >= $min RETURN r.ip AS ip, r.score AS score",
                Params::default().with("min", Value::Float(f64::from(min_score))),
            )?;
            let mut found = rows
                .iter()
                .map(|row| Ok((get_text(row, "ip")?, float(row, "score")?)))
                .collect::<SidResult<Vec<(String, f64)>>>()?;
            // Highest score first, then by address.
            found.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            Ok(found
                .into_iter()
                .take(limit)
                .map(|(ip, s)| (ip, s as f32))
                .collect())
        })
        .await
    }

    pub(super) async fn decay_ip_reputation(
        &self,
        older_than: std::time::Duration,
    ) -> SidResult<u64> {
        let cutoff = crate::decay_cutoff(older_than)?;
        self.transaction(move |tx| {
            let now = time(Utc::now());
            let idle = tx.run(
                "MATCH (r:SidIpReputation) WHERE r.updated_at < $cutoff
                 RETURN r.ip AS ip, r.failed_count AS failed, r.success_count AS succeeded",
                Params::default().with("cutoff", time(cutoff)),
            )?;
            let mut removed = 0u64;
            for row in &idle {
                let halved = Reputation {
                    failed: get_int(row, "failed")? / 2,
                    succeeded: get_int(row, "succeeded")? / 2,
                };
                let ip = Value::String(get_text(row, "ip")?);
                if halved.failed == 0 && halved.succeeded == 0 {
                    tx.run(
                        "MATCH (r:SidIpReputation) WHERE r.ip = $ip DETACH DELETE r",
                        Params::default().with("ip", ip),
                    )?;
                    removed += 1;
                } else {
                    tx.run(
                        "MATCH (r:SidIpReputation) WHERE r.ip = $ip
                         SET r.failed_count = $failed, r.success_count = $succeeded,
                             r.score = $score, r.updated_at = $now",
                        Params::default()
                            .with("ip", ip)
                            .with("failed", Value::Int(halved.failed))
                            .with("succeeded", Value::Int(halved.succeeded))
                            .with("score", Value::Float(halved.score()))
                            .with("now", now.clone()),
                    )?;
                }
            }
            Ok(Decision::Commit(removed))
        })
        .await
    }

    // === IP allowlist ===

    /// Commit an allowlist change under `ctx`, recording for a keyed command
    /// the allowlist the transaction leaves.
    fn allowlist_changed(tx: &Statements<'_>, ctx: &MutationContext) -> SidResult<()> {
        let mut ctx = ctx.clone();
        if ctx.operation.is_some() {
            ctx.record_effect(&allowlist(tx)?)?;
        }
        finalize(tx, "ip_allowlist", ctx)
    }

    pub(super) async fn add_ip_allowlist_entry(
        &self,
        cidr: &str,
        description: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let (cidr, description) = (cidr.to_owned(), description.to_owned());
        self.transaction(move |tx| {
            let updated = tx.run(
                "MATCH (w:SidIpAllowlistEntry) WHERE w.cidr = $cidr
                 SET w.description = $description RETURN w.cidr AS cidr",
                Params::default()
                    .with("cidr", Value::String(cidr.clone()))
                    .with("description", Value::String(description.clone())),
            )?;
            if updated.is_empty() {
                tx.run(
                    "CREATE (w:SidIpAllowlistEntry {cidr: $cidr, description: $description,
                        created_at: $now})",
                    Params::default()
                        .with("cidr", Value::String(cidr.clone()))
                        .with("description", Value::String(description.clone()))
                        .with("now", time(Utc::now())),
                )?;
            }
            Self::allowlist_changed(tx, &ctx)?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn remove_ip_allowlist_entry(
        &self,
        cidr: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let cidr = cidr.to_owned();
        self.transaction(move |tx| {
            tx.run(
                "MATCH (w:SidIpAllowlistEntry) WHERE w.cidr = $cidr DETACH DELETE w",
                Params::default().with("cidr", Value::String(cidr.clone())),
            )?;
            Self::allowlist_changed(tx, &ctx)?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn list_ip_allowlist_entries(
        &self,
    ) -> SidResult<Vec<(String, String, DateTime<Utc>)>> {
        self.read(allowlist).await
    }

    pub(super) async fn import_ip_allowlist_entry(
        &self,
        cidr: &str,
        description: &str,
        created_at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let wanted = (cidr.to_owned(), description.to_owned(), created_at);
        self.transaction(move |tx| {
            let (cidr, description, created_at) = &wanted;
            if let Some(held) = allowlist(tx)?.into_iter().find(|(c, _, _)| c == cidr) {
                return crate::transfer_repeat(&held, &wanted, "IP allowlist entry")
                    .map(Decision::Abandon);
            }
            // Concurrent importers meet on the unique CIDR.
            tx.run(
                "CREATE (w:SidIpAllowlistEntry {cidr: $cidr, description: $description,
                    created_at: $created_at})",
                Params::default()
                    .with("cidr", Value::String(cidr.clone()))
                    .with("description", Value::String(description.clone()))
                    .with("created_at", time(*created_at)),
            )?;
            Self::allowlist_changed(tx, &ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn import_anomaly_event(
        &self,
        e: &AnomalyEventRecord,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let e = e.clone();
        self.transaction(move |tx| {
            let held = tx.run(
                &format!("MATCH (a:SidAnomalyEvent) WHERE a.id = $id RETURN {EVENT}"),
                Params::default().with("id", uuid(&e.id.0)),
            )?;
            if let Some(row) = held.first() {
                return crate::transfer_repeat(&event(row)?, &e, "anomaly event")
                    .map(Decision::Abandon);
            }
            tx.run(
                "CREATE (a:SidAnomalyEvent {id: $id, rule_id: $rule_id, profile_id: $profile_id,
                    ip_address: $ip_address, description: $description, risk_score: $risk_score,
                    reaction: $reaction, occurred_at: $occurred_at})",
                Params::default()
                    .with("id", uuid(&e.id.0))
                    .with("rule_id", Value::String(e.rule_id.clone()))
                    .with("profile_id", Value::String(e.profile_id.clone()))
                    .with(
                        "ip_address",
                        e.ip_address.map_or(Value::Null, super::audit::ip_value),
                    )
                    .with("description", Value::String(e.description.clone()))
                    .with("risk_score", Value::Int(i64::from(e.risk_score)))
                    .with("reaction", Value::String(e.reaction.clone()))
                    .with("occurred_at", time(e.timestamp)),
            )?;
            finalize(tx, &format!("anomaly_event:{}", e.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn export_ip_reputation(&self) -> SidResult<Vec<IpReputation>> {
        self.read(|tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidIpReputation) RETURN {REPUTATION}"),
                Params::default(),
            )?;
            let mut all = rows.iter().map(reputation).collect::<SidResult<Vec<_>>>()?;
            all.sort_by(|a, b| a.ip.cmp(&b.ip));
            Ok(all)
        })
        .await
    }

    pub(super) async fn import_ip_reputation(
        &self,
        r: &IpReputation,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let r = r.clone();
        self.transaction(move |tx| {
            let held = tx.run(
                &format!("MATCH (r:SidIpReputation) WHERE r.ip = $ip RETURN {REPUTATION}"),
                Params::default().with("ip", Value::String(r.ip.clone())),
            )?;
            if let Some(row) = held.first() {
                return crate::transfer_repeat(&reputation(row)?, &r, "IP reputation")
                    .map(Decision::Abandon);
            }
            let score = Reputation {
                failed: r.failed_count,
                succeeded: r.success_count,
            }
            .score();
            let at = |t: Option<DateTime<Utc>>| t.map_or(Value::Null, time);
            // Concurrent importers meet on the unique address.
            tx.run(
                "CREATE (r:SidIpReputation {ip: $ip, failed_count: $failed,
                    success_count: $succeeded, score: $score, first_seen_at: $first,
                    last_failed_at: $last_failed, last_success_at: $last_success,
                    updated_at: $updated})",
                Params::default()
                    .with("ip", Value::String(r.ip.clone()))
                    .with("failed", Value::Int(r.failed_count))
                    .with("succeeded", Value::Int(r.success_count))
                    .with("score", Value::Float(score))
                    .with("first", time(r.first_seen_at))
                    .with("last_failed", at(r.last_failed_at))
                    .with("last_success", at(r.last_success_at))
                    .with("updated", time(r.updated_at)),
            )?;
            finalize(tx, "ip_reputation", ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === Notification preferences ===

    pub(super) async fn get_notification_preferences(
        &self,
        profile: ProfileId,
    ) -> SidResult<Option<NotificationPreferences>> {
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (n:SidNotificationPreferences) WHERE n.profile_id = $id
                 RETURN n.categories AS categories, n.updated_at AS updated_at",
                Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
            )?;
            let Some(row) = rows.first() else {
                return Ok(None);
            };
            Ok(Some(NotificationPreferences {
                profile_id: profile,
                categories: super::get_document(row, "categories")?,
                updated_at: get_time(row, "updated_at")?,
            }))
        })
        .await
    }

    pub(super) async fn save_notification_preferences(
        &self,
        p: &NotificationPreferences,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let document = super::document(&p.categories, "notification preferences")?;
        let (profile, updated_at) = (p.profile_id, p.updated_at);
        self.mutate(format!("profile:{profile}"), ctx, move |tx| {
            let held = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
            )?;
            if !super::claim_first(tx, &held)? {
                return Err(SidError::NotFound(format!("profile {profile}")));
            }
            let params = Params::default()
                .with("id", Value::Binary(profile.as_bytes().to_vec()))
                .with("categories", document.clone())
                .with("updated_at", time(updated_at));
            let updated = tx.run(
                "MATCH (n:SidNotificationPreferences) WHERE n.profile_id = $id
                 SET n.categories = $categories, n.updated_at = $updated_at
                 RETURN n.profile_id AS id",
                params.clone(),
            )?;
            if updated.is_empty() {
                tx.run(
                    "CREATE (n:SidNotificationPreferences {profile_id: $id,
                        categories: $categories, updated_at: $updated_at})",
                    params,
                )?;
            }
            Ok(())
        })
        .await
    }

    // === Integrity ===

    pub(super) async fn count_orphaned_sessions(&self) -> SidResult<u64> {
        self.read(|tx| orphans_of(tx, "SidSession", "profile_id"))
            .await
    }

    pub(super) async fn count_orphaned_credentials(&self) -> SidResult<u64> {
        self.read(|tx| orphans_of(tx, "SidCredential", "profile_id"))
            .await
    }

    pub(super) async fn count_orphaned_role_assignments(&self) -> SidResult<u64> {
        self.read(|tx| {
            // Of a Profile that is gone, or of a role that is gone; a group's
            // assignment counts only by its role.
            let rows = tx.run(
                "MATCH (a:SidRoleAssignment) RETURN a.profile_id AS profile, a.role_id AS role",
                Params::default(),
            )?;
            let mut orphaned = 0u64;
            for row in &rows {
                let missing = |label: &str, value: Vec<u8>| -> SidResult<bool> {
                    Ok(tx
                        .run(
                            &format!("MATCH (n:{label}) WHERE n.id = $id RETURN n.id AS id"),
                            Params::default().with("id", Value::Binary(value)),
                        )?
                        .is_empty())
                };
                let profile_gone = match get_opt_bytes(row, "profile")? {
                    Some(profile) => missing("SidProfile", profile)?,
                    None => false,
                };
                if profile_gone || missing("SidRole", get_bytes(row, "role")?)? {
                    orphaned += 1;
                }
            }
            Ok(orphaned)
        })
        .await
    }
}
