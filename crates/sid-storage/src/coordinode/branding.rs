// SPDX-License-Identifier: AGPL-3.0-only
//! Branding configurations in CoordiNode: content as a document; status,
//! revision and last change as properties, which are the stored ones.
//!
//! A publish takes its project's `branding_turn`, so two publishes of one
//! project apply one after the other and the later archives the earlier: a
//! project never has two published configs.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::{
    BrandingConfig, BrandingConfigId, BrandingStatus, MutationContext, ProjectId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, document, finalize,
    get_document, get_int, get_parsed, get_time, project::project_value, sorted_page, time, uuid,
};

const CONFIG: &str = "b.content AS content, b.status AS status, b.revision AS revision,
    b.updated_at AS updated_at";

fn config(row: &Row) -> SidResult<BrandingConfig> {
    let mut config: BrandingConfig = get_document(row, "content")?;
    config.status = get_parsed(row, "status")?;
    let revision = get_int(row, "revision")?;
    config.revision = u64::try_from(revision)
        .map_err(|_| SidError::Storage(format!("branding revision: {revision}")))?;
    config.updated_at = get_time(row, "updated_at")?;
    Ok(config)
}

fn get(tx: &Statements<'_>, id: BrandingConfigId) -> SidResult<Option<BrandingConfig>> {
    let rows = tx.run(
        &format!("MATCH (b:SidBranding) WHERE b.id = $id RETURN {CONFIG}"),
        Params::default().with("id", uuid(id.as_uuid())),
    )?;
    rows.first().map(config).transpose()
}

/// Take `project`'s turn at publishing; `false` when the project is gone.
fn branding_turn(tx: &Statements<'_>, project: ProjectId) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (j:SidProject) WHERE j.id = $id
         SET j.branding_turn = coalesce(j.branding_turn, 0) + 1
         RETURN j.id AS id",
        Params::default().with("id", project_value(project)),
    )?;
    Ok(!rows.is_empty())
}

/// Delete in `tx` the branding configurations of `project`.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    tx.run(
        "MATCH (b:SidBranding) WHERE b.project_id = $id DETACH DELETE b",
        Params::default().with("id", project_value(project)),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn create_branding_config(
        &self,
        c: &BrandingConfig,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let params = Params::default()
            .with("id", uuid(c.id.as_uuid()))
            .with("project_id", project_value(c.project_id))
            .with("status", Value::String(c.status.as_str().into()))
            .with("content", document(c, "branding")?)
            .with("created_at", time(c.created_at))
            .with("updated_at", time(c.updated_at));
        let (id, project) = (c.id, c.project_id);
        self.mutate(format!("branding:{}", id), ctx, move |tx| {
            let held = tx.run(
                "MATCH (j:SidProject) WHERE j.id = $project_id RETURN id(j) AS node",
                params.clone(),
            )?;
            if !claim_first(tx, &held)? {
                return Err(SidError::NotFound(format!("project {project}")));
            }
            if get(tx, id)?.is_some() {
                return Err(SidError::Conflict("branding config already exists".into()));
            }
            tx.run(
                "CREATE (b:SidBranding {id: $id, project_id: $project_id, status: $status,
                    content: $content, revision: 0, created_at: $created_at,
                    updated_at: $updated_at})",
                params.clone(),
            )?;
            Ok(())
        })
        .await
    }

    /// Applies only to a draft still at the revision `c` was read at.
    pub(super) async fn update_branding_draft(
        &self,
        c: &BrandingConfig,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let revision = i64::try_from(c.revision)
            .map_err(|_| SidError::Validation("branding revision out of range".into()))?;
        let params = Params::default()
            .with("id", uuid(c.id.as_uuid()))
            .with("revision", Value::Int(revision))
            .with(
                "draft",
                Value::String(BrandingStatus::Draft.as_str().into()),
            )
            .with("content", document(c, "branding")?)
            .with("updated_at", time(c.updated_at));
        let chain = format!("branding:{}", c.id);
        self.transaction(move |tx| {
            let updated = tx.run(
                "MATCH (b:SidBranding)
                 WHERE b.id = $id AND b.status = $draft AND b.revision = $revision
                 SET b.content = $content, b.updated_at = $updated_at,
                     b.revision = b.revision + 1
                 RETURN b.id AS id",
                params.clone(),
            )?;
            if updated.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    /// Publishes a draft of `project` and archives the previous publication
    /// in the same commit.
    pub(super) async fn publish_branding_config(
        &self,
        id: BrandingConfigId,
        project: ProjectId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let chain = format!("branding:{}", id);
        let params = Params::default()
            .with("id", uuid(id.as_uuid()))
            .with("project_id", project_value(project))
            .with("at", time(at))
            .with(
                "draft",
                Value::String(BrandingStatus::Draft.as_str().into()),
            )
            .with(
                "published",
                Value::String(BrandingStatus::Published.as_str().into()),
            )
            .with(
                "archived",
                Value::String(BrandingStatus::Archived.as_str().into()),
            );
        self.transaction(move |tx| {
            if !branding_turn(tx, project)? {
                return Ok(Decision::Abandon(false));
            }
            let draft = tx.run(
                "MATCH (b:SidBranding)
                 WHERE b.id = $id AND b.project_id = $project_id AND b.status = $draft
                 RETURN b.id AS id",
                params.clone(),
            )?;
            if draft.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (b:SidBranding) WHERE b.project_id = $project_id AND b.status = $published
                 SET b.status = $archived, b.updated_at = $at, b.revision = b.revision + 1",
                params.clone(),
            )?;
            tx.run(
                "MATCH (b:SidBranding) WHERE b.id = $id
                 SET b.status = $published, b.updated_at = $at, b.revision = b.revision + 1",
                params.clone(),
            )?;
            let published = get(tx, id)?
                .ok_or_else(|| SidError::Storage("published branding vanished".into()))?;
            let mut ctx = ctx.clone();
            ctx.record_effect(&published)?;
            finalize(tx, &chain, ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn get_published_branding(
        &self,
        project: ProjectId,
    ) -> SidResult<Option<BrandingConfig>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (b:SidBranding) WHERE b.project_id = $id AND b.status = $published
                     RETURN {CONFIG}"
                ),
                Params::default().with("id", project_value(project)).with(
                    "published",
                    Value::String(BrandingStatus::Published.as_str().into()),
                ),
            )?;
            rows.first().map(config).transpose()
        })
        .await
    }

    pub(super) async fn get_branding_config(
        &self,
        id: BrandingConfigId,
    ) -> SidResult<Option<BrandingConfig>> {
        self.read(move |tx| get(tx, id)).await
    }

    pub(super) async fn list_branding_configs(
        &self,
        project: ProjectId,
    ) -> SidResult<Vec<BrandingConfig>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (b:SidBranding) WHERE b.project_id = $id RETURN {CONFIG}"),
                Params::default().with("id", project_value(project)),
            )?;
            let all = rows.iter().map(config).collect::<SidResult<Vec<_>>>()?;
            // Last changed first, then by id.
            Ok(sorted_page(
                all,
                |c| (std::cmp::Reverse(c.updated_at), c.id),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    /// A published config is never deleted, even one published meanwhile.
    pub(super) async fn delete_branding_config(
        &self,
        id: BrandingConfigId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let chain = format!("branding:{}", id);
        self.transaction(move |tx| {
            match get(tx, id)? {
                Some(c) if c.status != BrandingStatus::Published => {}
                _ => return Ok(Decision::Abandon(false)),
            }
            // A publish committed meanwhile changed this node: the delete
            // conflicts and runs again on the published config.
            tx.run(
                "MATCH (b:SidBranding) WHERE b.id = $id DETACH DELETE b",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}
