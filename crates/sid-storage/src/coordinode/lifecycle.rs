// SPDX-License-Identifier: AGPL-3.0-only
//! An account's end and its sign-in links in CoordiNode: closure requests
//! with their legal holds, data export jobs and magic link sessions.
//!
//! A closure moves the profile's status and stores the request in one
//! write over the profile revision. An administrator's closure holds the
//! administrator role and every other administrator, so the last usable
//! one is never lost to concurrent closures or revocations.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::magic_link::MagicLinkSession;
use sid_core::models::profile::{ClosureRequest, ExportJob, LegalHold};
use sid_core::models::{MutationContext, Profile, ProfileId};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bool, get_bytes, get_id,
    get_int, get_opt_int, get_opt_text, get_opt_time, get_parsed, get_text, get_time, get_uuid,
    opt_text, opt_time, time, uuid,
};

const CLOSURE: &str = "c.profile_id AS profile_id, c.mode AS mode,
    c.closure_reason AS closure_reason, c.requested_by AS requested_by,
    c.requested_at AS requested_at, c.grace_period_end AS grace_period_end,
    c.export_status AS export_status, c.cancel_count AS cancel_count,
    c.hold_court_reference AS hold_court_reference, c.hold_reason AS hold_reason,
    c.hold_placed_at AS hold_placed_at, c.hold_expected_end AS hold_expected_end,
    c.hold_placed_by AS hold_placed_by, c.hold_counsel AS hold_counsel,
    c.hold_previous_status AS hold_previous_status";

const EXPORT: &str = "e.id AS id, e.profile_id AS profile_id, e.format AS format,
    e.status AS status, e.archive_path AS archive_path, e.size_bytes AS size_bytes,
    e.checksum_sha256 AS checksum_sha256, e.created_at AS created_at, e.ready_at AS ready_at,
    e.expires_at AS expires_at";

const LINK: &str = "l.id AS id, l.email AS email, l.destination AS destination,
    l.token_hash AS token_hash, l.sealed_token AS sealed_token, l.consumed AS consumed,
    l.created_at AS created_at, l.expires_at AS expires_at";

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

// === Closure requests ===

fn closure(row: &Row) -> SidResult<ClosureRequest> {
    let legal_hold = match get_opt_text(row, "hold_court_reference")? {
        Some(court_reference) => Some(LegalHold {
            court_reference,
            reason: get_opt_text(row, "hold_reason")?,
            placed_at: get_time(row, "hold_placed_at")?,
            expected_end: get_opt_time(row, "hold_expected_end")?,
            placed_by: get_id(row, "hold_placed_by")?,
            reviewing_counsel: get_opt_text(row, "hold_counsel")?,
            previous_status: get_parsed(row, "hold_previous_status")?,
        }),
        None => None,
    };
    let cancel_count = get_int(row, "cancel_count")?;
    Ok(ClosureRequest {
        profile_id: get_id(row, "profile_id")?,
        mode: get_parsed(row, "mode")?,
        closure_reason: get_opt_text(row, "closure_reason")?,
        requested_by: get_id(row, "requested_by")?,
        requested_at: get_time(row, "requested_at")?,
        grace_period_end: get_opt_time(row, "grace_period_end")?,
        export_status: get_parsed(row, "export_status")?,
        legal_hold,
        cancel_count: u32::try_from(cancel_count)
            .map_err(|_| SidError::Storage(format!("cancel_count: {cancel_count}")))?,
    })
}

fn get_closure(tx: &Statements<'_>, profile: ProfileId) -> SidResult<Option<ClosureRequest>> {
    let rows = tx.run(
        &format!("MATCH (c:SidClosureRequest) WHERE c.profile_id = $id RETURN {CLOSURE}"),
        Params::default().with("id", bin(profile.as_bytes())),
    )?;
    rows.first().map(closure).transpose()
}

fn hold_params(params: Params, hold: Option<&LegalHold>) -> Params {
    params
        .with(
            "hold_court_reference",
            opt_text(hold.map(|h| h.court_reference.as_str())),
        )
        .with(
            "hold_reason",
            opt_text(hold.and_then(|h| h.reason.as_deref())),
        )
        .with("hold_placed_at", opt_time(hold.map(|h| h.placed_at)))
        .with(
            "hold_expected_end",
            opt_time(hold.and_then(|h| h.expected_end)),
        )
        .with(
            "hold_placed_by",
            hold.map_or(Value::Null, |h| bin(h.placed_by.as_bytes())),
        )
        .with(
            "hold_counsel",
            opt_text(hold.and_then(|h| h.reviewing_counsel.as_deref())),
        )
        .with(
            "hold_previous_status",
            opt_text(hold.map(|h| h.previous_status.as_str())),
        )
}

/// Store `req` in `tx`. With `replace`, it takes the place of the profile's
/// stored request but keeps that one's cancel count and legal hold, which
/// outlive a request; without, an existing request is `Conflict`.
fn insert_closure(tx: &Statements<'_>, req: &ClosureRequest, replace: bool) -> SidResult<()> {
    let stored = get_closure(tx, req.profile_id)?;
    if stored.is_some() && !replace {
        return Err(SidError::Conflict("closure request already exists".into()));
    }
    let (cancel_count, hold) = match &stored {
        Some(kept) => (kept.cancel_count, kept.legal_hold.as_ref()),
        None => (req.cancel_count, req.legal_hold.as_ref()),
    };
    tx.run(
        "MATCH (c:SidClosureRequest) WHERE c.profile_id = $profile_id DETACH DELETE c",
        Params::default().with("profile_id", bin(req.profile_id.as_bytes())),
    )?;
    let params = Params::default()
        .with("profile_id", bin(req.profile_id.as_bytes()))
        .with("mode", Value::String(req.mode.as_str().into()))
        .with("closure_reason", opt_text(req.closure_reason.as_deref()))
        .with("requested_by", bin(req.requested_by.as_bytes()))
        .with("requested_at", time(req.requested_at))
        .with("grace_period_end", opt_time(req.grace_period_end))
        .with(
            "export_status",
            Value::String(req.export_status.as_str().into()),
        )
        .with("cancel_count", Value::Int(i64::from(cancel_count)));
    tx.run(
        "CREATE (c:SidClosureRequest {profile_id: $profile_id, mode: $mode,
            closure_reason: $closure_reason, requested_by: $requested_by,
            requested_at: $requested_at, grace_period_end: $grace_period_end,
            export_status: $export_status, cancel_count: $cancel_count,
            hold_court_reference: $hold_court_reference, hold_reason: $hold_reason,
            hold_placed_at: $hold_placed_at, hold_expected_end: $hold_expected_end,
            hold_placed_by: $hold_placed_by, hold_counsel: $hold_counsel,
            hold_previous_status: $hold_previous_status})",
        hold_params(params, hold),
    )?;
    Ok(())
}

// === Export jobs ===

fn export(row: &Row) -> SidResult<ExportJob> {
    Ok(ExportJob {
        id: get_uuid(row, "id")?,
        profile_id: get_id(row, "profile_id")?,
        format: get_parsed(row, "format")?,
        status: get_parsed(row, "status")?,
        archive_path: get_opt_text(row, "archive_path")?,
        size_bytes: get_opt_int(row, "size_bytes")?,
        checksum_sha256: get_opt_text(row, "checksum_sha256")?,
        created_at: get_time(row, "created_at")?,
        ready_at: get_opt_time(row, "ready_at")?,
        expires_at: get_opt_time(row, "expires_at")?,
    })
}

fn exports_where(tx: &Statements<'_>, filter: &str, value: Value) -> SidResult<Vec<ExportJob>> {
    let rows = tx.run(
        &format!("MATCH (e:SidExportJob) WHERE {filter} RETURN {EXPORT}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(export).collect()
}

// === Magic links ===

fn link(row: &Row) -> SidResult<MagicLinkSession> {
    Ok(MagicLinkSession {
        id: get_uuid(row, "id")?,
        email: get_text(row, "email")?,
        destination: get_text(row, "destination")?,
        token_hash: get_text(row, "token_hash")?,
        sealed_token: get_bytes(row, "sealed_token")?,
        consumed: get_bool(row, "consumed")?,
        created_at: get_time(row, "created_at")?,
        expires_at: get_time(row, "expires_at")?,
    })
}

fn get_link(tx: &Statements<'_>, id: Uuid) -> SidResult<Option<MagicLinkSession>> {
    let rows = tx.run(
        &format!("MATCH (l:SidMagicLink) WHERE l.id = $id RETURN {LINK}"),
        Params::default().with("id", uuid(&id)),
    )?;
    rows.first().map(link).transpose()
}

/// Mark link `id` consumed and drop its sealed token, in `tx`.
fn consume(tx: &Statements<'_>, id: Uuid) -> SidResult<()> {
    tx.run(
        "MATCH (l:SidMagicLink) WHERE l.id = $id SET l.consumed = true, l.sealed_token = $empty",
        Params::default()
            .with("id", uuid(&id))
            .with("empty", Value::Binary(Vec::new())),
    )?;
    Ok(())
}

/// Delete in `tx` the closure request and export jobs of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for query in [
        "MATCH (c:SidClosureRequest) WHERE c.profile_id = $id DETACH DELETE c",
        "MATCH (e:SidExportJob) WHERE e.profile_id = $id DETACH DELETE e",
    ] {
        tx.run(query, Params::default().with("id", bin(profile.as_bytes())))?;
    }
    Ok(())
}

impl CoordinodeBackend {
    // === Closure requests ===

    pub(super) async fn create_closure_request(
        &self,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let req = req.clone();
        self.mutate(format!("closure:{}", req.profile_id), ctx, move |tx| {
            let held = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", bin(req.profile_id.as_bytes())),
            )?;
            if !super::claim_first(tx, &held)? {
                return Err(SidError::NotFound(format!("profile {}", req.profile_id)));
            }
            insert_closure(tx, &req, false)
        })
        .await
    }

    pub(super) async fn request_profile_closure(
        &self,
        profile: &Profile,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (profile, req) = (profile.clone(), req.clone());
        self.transaction(move |tx| {
            if super::rbac::administrator_exists(tx, Some(profile.id))? {
                let admins = super::rbac::held_administrators(tx)?;
                crate::check_other_administrator(profile.id, &admins)?;
            }
            if !super::profile::update(tx, &profile)? {
                return Ok(Decision::Abandon(false));
            }
            insert_closure(tx, &req, true)?;
            finalize(tx, &format!("closure:{}", req.profile_id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn cancel_profile_closure(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let profile = profile.clone();
        self.transaction(move |tx| {
            if !super::profile::update(tx, &profile)? {
                return Ok(Decision::Abandon(false));
            }
            let counted = tx.run(
                "MATCH (c:SidClosureRequest) WHERE c.profile_id = $id
                 SET c.cancel_count = c.cancel_count + 1 RETURN c.profile_id AS id",
                Params::default().with("id", bin(profile.id.as_bytes())),
            )?;
            if counted.is_empty() {
                return Err(SidError::NotFound("no closure request".into()));
            }
            finalize(tx, &format!("closure:{}", profile.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn get_closure_request(
        &self,
        profile: ProfileId,
    ) -> SidResult<Option<ClosureRequest>> {
        self.read(move |tx| get_closure(tx, profile)).await
    }

    // === Export jobs ===

    pub(super) async fn create_export_job(
        &self,
        job: &ExportJob,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let job = job.clone();
        self.mutate(format!("export_job:{}", job.id), ctx, move |tx| {
            let held = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", bin(job.profile_id.as_bytes())),
            )?;
            if !super::claim_first(tx, &held)? {
                return Err(SidError::NotFound(format!("profile {}", job.profile_id)));
            }
            if !exports_where(tx, "e.id = $value", uuid(&job.id))?.is_empty() {
                return Err(SidError::Conflict("export job already exists".into()));
            }
            tx.run(
                "CREATE (e:SidExportJob {id: $id, profile_id: $profile_id, format: $format,
                    status: $status, archive_path: $archive_path, size_bytes: $size_bytes,
                    checksum_sha256: $checksum, created_at: $created_at, ready_at: $ready_at,
                    expires_at: $expires_at})",
                Params::default()
                    .with("id", uuid(&job.id))
                    .with("profile_id", bin(job.profile_id.as_bytes()))
                    .with("format", Value::String(job.format.as_str().into()))
                    .with("status", Value::String(job.status.as_str().into()))
                    .with("archive_path", opt_text(job.archive_path.as_deref()))
                    .with("size_bytes", job.size_bytes.map_or(Value::Null, Value::Int))
                    .with("checksum", opt_text(job.checksum_sha256.as_deref()))
                    .with("created_at", time(job.created_at))
                    .with("ready_at", opt_time(job.ready_at))
                    .with("expires_at", opt_time(job.expires_at)),
            )?;
            Ok(())
        })
        .await
    }

    /// Move a ready job to `to` while its expiry is after `at` (`live`) or
    /// not; `true` when it applied.
    async fn finish_export_job(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        live: bool,
        to: &'static str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let due = exports_where(tx, "e.id = $value", uuid(&id))?
                .pop()
                .is_some_and(|job| {
                    job.status.as_str() == "ready"
                        && job.expires_at.is_some_and(|end| (end > at) == live)
                });
            if !due {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (e:SidExportJob) WHERE e.id = $id AND e.status = 'ready'
                 SET e.status = $to",
                Params::default()
                    .with("id", uuid(&id))
                    .with("to", Value::String(to.into())),
            )?;
            finalize(tx, &format!("export_job:{id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn acknowledge_export_job(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.finish_export_job(id, at, true, "downloaded", ctx)
            .await
    }

    pub(super) async fn expire_export_job(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.finish_export_job(id, at, false, "expired", ctx).await
    }

    pub(super) async fn get_export_job(&self, profile: ProfileId) -> SidResult<Option<ExportJob>> {
        self.read(move |tx| {
            // The newest.
            Ok(
                exports_where(tx, "e.profile_id = $value", bin(profile.as_bytes()))?
                    .into_iter()
                    .max_by_key(|job| (job.created_at, job.id)),
            )
        })
        .await
    }

    pub(super) async fn get_export_job_by_id(&self, id: Uuid) -> SidResult<Option<ExportJob>> {
        self.read(move |tx| Ok(exports_where(tx, "e.id = $value", uuid(&id))?.pop()))
            .await
    }

    // === Magic links ===

    pub(super) async fn create_magic_link_session(
        &self,
        l: &MagicLinkSession,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let l = l.clone();
        self.mutate(format!("magic_link:{}", l.id), ctx, move |tx| {
            if get_link(tx, l.id)?.is_some() {
                return Err(SidError::Conflict("magic link already exists".into()));
            }
            tx.run(
                "CREATE (l:SidMagicLink {id: $id, email: $email, destination: $destination,
                    token_hash: $token_hash, sealed_token: $sealed_token, consumed: $consumed,
                    created_at: $created_at, expires_at: $expires_at})",
                Params::default()
                    .with("id", uuid(&l.id))
                    .with("email", Value::String(l.email.clone()))
                    .with("destination", Value::String(l.destination.clone()))
                    .with("token_hash", Value::String(l.token_hash.clone()))
                    .with("sealed_token", Value::Binary(l.sealed_token.clone()))
                    .with("consumed", Value::Bool(l.consumed))
                    .with("created_at", time(l.created_at))
                    .with("expires_at", time(l.expires_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_magic_link_session(
        &self,
        id: Uuid,
    ) -> SidResult<Option<MagicLinkSession>> {
        self.read(move |tx| get_link(tx, id)).await
    }

    pub(super) async fn export_magic_link_sessions(&self) -> SidResult<Vec<MagicLinkSession>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (l:SidMagicLink) RETURN {LINK}"),
                Params::default(),
            )?;
            let mut links = rows.iter().map(link).collect::<SidResult<Vec<_>>>()?;
            links.sort_by_key(|l| l.id);
            Ok(links)
        })
        .await
    }

    pub(super) async fn consume_magic_link_session(
        &self,
        id: Uuid,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("magic_link:{id}"), ctx, move |tx| consume(tx, id))
            .await
    }

    pub(super) async fn try_consume_magic_link_session(
        &self,
        id: Uuid,
        ctx: MutationContext,
    ) -> SidResult<Option<MagicLinkSession>> {
        self.transaction(move |tx| {
            // The consumption writes the link: of concurrent consumers one
            // commits, the others run again and find it consumed.
            let Some(open) = get_link(tx, id)?.filter(|l| !l.consumed && l.expires_at > Utc::now())
            else {
                return Ok(Decision::Abandon(None));
            };
            consume(tx, id)?;
            let consumed = MagicLinkSession {
                consumed: true,
                sealed_token: Vec::new(),
                ..open
            };
            finalize(tx, &format!("magic_link:{id}"), ctx.clone())?;
            Ok(Decision::Commit(Some(consumed)))
        })
        .await
    }

    pub(super) async fn delete_expired_magic_link_sessions(
        &self,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (l:SidMagicLink) WHERE l.expires_at < $now DETACH DELETE l
                 RETURN count(*) AS n",
                Params::default().with("now", time(Utc::now())),
            )?;
            let removed = super::get_count(&rows)?;
            if removed == 0 && ctx.work.is_empty() && ctx.operation.is_none() {
                return Ok(Decision::Abandon(0));
            }
            finalize(tx, "magic_link:cleanup", ctx.clone())?;
            Ok(Decision::Commit(removed))
        })
        .await
    }

    pub(super) async fn count_active_magic_links_for_email(&self, email: &str) -> SidResult<u32> {
        let email = email.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (l:SidMagicLink) WHERE l.email = $email AND l.consumed = false
                   AND l.expires_at > $now
                 RETURN count(l) AS n",
                Params::default()
                    .with("email", Value::String(email.clone()))
                    .with("now", time(Utc::now())),
            )?;
            u32::try_from(super::get_count(&rows)?)
                .map_err(|_| SidError::Storage("magic link count".into()))
        })
        .await
    }
}
