// SPDX-License-Identifier: AGPL-3.0-only
//! Projects in CoordiNode: one `SidProject` node each. The system project
//! is never changed or deleted.

use coordinode_core::graph::types::Value;
use sid_core::models::{MutationContext, ProfileId, Project, ProjectChange, ProjectId};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bool, get_count,
    get_opt_uuid, get_text, get_time, get_uuid, opt_uuid, sorted_page, time, uuid,
};

const PROJECT: &str = "j.id AS id, j.name AS name, j.description AS description,
    j.owner_id AS owner_id, j.is_system AS is_system, j.created_at AS created_at,
    j.updated_at AS updated_at";

pub(super) fn project_value(id: ProjectId) -> Value {
    uuid(id.as_uuid())
}

fn project(row: &Row) -> SidResult<Project> {
    Ok(Project {
        id: ProjectId::from_uuid(get_uuid(row, "id")?)
            .map_err(|e| SidError::Storage(format!("project id: {e}")))?,
        name: get_text(row, "name")?,
        description: get_text(row, "description")?,
        owner_id: get_opt_uuid(row, "owner_id")?
            .map(ProfileId::from_uuid)
            .transpose()
            .map_err(|e| SidError::Storage(format!("project owner: {e}")))?,
        is_system: get_bool(row, "is_system")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// The project `id`, read in `tx`.
pub(super) fn get(tx: &Statements<'_>, id: ProjectId) -> SidResult<Option<Project>> {
    let rows = tx.run(
        &format!("MATCH (j:SidProject) WHERE j.id = $id RETURN {PROJECT}"),
        Params::default().with("id", project_value(id)),
    )?;
    rows.first().map(project).transpose()
}

/// Store `project` in `tx`; an existing id is `Conflict`.
fn insert(tx: &Statements<'_>, project: &Project) -> SidResult<()> {
    if get(tx, project.id)?.is_some() {
        return Err(SidError::Conflict("project already exists".into()));
    }
    tx.run(
        "CREATE (j:SidProject {id: $id, name: $name, description: $description,
            owner_id: $owner_id, is_system: $is_system, created_at: $created_at,
            updated_at: $updated_at})",
        Params::default()
            .with("id", project_value(project.id))
            .with("name", Value::String(project.name.clone()))
            .with("description", Value::String(project.description.clone()))
            .with(
                "owner_id",
                opt_uuid(project.owner_id.as_ref().map(|o| o.as_uuid())),
            )
            .with("is_system", Value::Bool(project.is_system))
            .with("created_at", time(project.created_at))
            .with("updated_at", time(project.updated_at)),
    )?;
    Ok(())
}

/// Create the system project of an empty store: every installation has it
/// from the start.
pub(super) fn init_system_project(tx: &Statements<'_>) -> SidResult<Decision<()>> {
    if get(tx, ProjectId::SYSTEM)?.is_some() {
        return Ok(Decision::Abandon(()));
    }
    insert(tx, &Project::system())?;
    Ok(Decision::Commit(()))
}

/// Clear `owner` from the projects it owns, in `tx`: the projects outlive
/// the profile that created them.
pub(super) fn disown(tx: &Statements<'_>, owner: ProfileId) -> SidResult<()> {
    tx.run(
        "MATCH (j:SidProject) WHERE j.owner_id = $owner SET j.owner_id = null",
        Params::default().with("owner", uuid(owner.as_uuid())),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn get_project(&self, id: ProjectId) -> SidResult<Option<Project>> {
        self.transaction(move |tx| get(tx, id).map(Decision::Abandon))
            .await
    }

    pub(super) async fn create_project(
        &self,
        project: &Project,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = project.clone();
        self.mutate(format!("project:{}", project.id), ctx, move |tx| {
            insert(tx, &stored)
        })
        .await
    }

    pub(super) async fn update_project(
        &self,
        id: ProjectId,
        change: &ProjectChange,
        ctx: MutationContext,
    ) -> SidResult<Option<Project>> {
        let change = change.clone();
        self.transaction(move |tx| {
            let Some(mut stored) = get(tx, id)? else {
                return Ok(Decision::Abandon(None));
            };
            if stored.is_system {
                return Ok(Decision::Abandon(None));
            }
            if let Some(name) = &change.name {
                stored.name = name.clone();
            }
            if let Some(description) = &change.description {
                stored.description = description.clone();
            }
            stored.updated_at = change.updated_at;
            tx.run(
                "MATCH (j:SidProject) WHERE j.id = $id
                 SET j.name = $name, j.description = $description, j.updated_at = $updated_at",
                Params::default()
                    .with("id", project_value(id))
                    .with("name", Value::String(stored.name.clone()))
                    .with("description", Value::String(stored.description.clone()))
                    .with("updated_at", time(stored.updated_at)),
            )?;
            let mut ctx = ctx.clone();
            ctx.record_effect(&stored)?;
            finalize(tx, &format!("project:{id}"), ctx)?;
            Ok(Decision::Commit(Some(stored)))
        })
        .await
    }

    pub(super) async fn delete_project(
        &self,
        id: ProjectId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if id.is_system() {
            return Err(SidError::Validation(
                "Cannot delete the system project".to_string(),
            ));
        }
        self.mutate(format!("project:{id}"), ctx, move |tx| {
            match get(tx, id)? {
                Some(stored) if !stored.is_system => {
                    // An application or SCIM target keeps its project: no live
                    // client or outbound target outlives it. Creating either
                    // holds the project, so one racing this deletion conflicts.
                    for holder in ["SidApplication", "SidScimTarget"] {
                        let held = tx.run(
                            &format!(
                                "MATCH (n:{holder}) WHERE n.project_id = $id
                                 RETURN n.project_id AS p LIMIT 1"
                            ),
                            Params::default().with("id", project_value(id)),
                        )?;
                        if !held.is_empty() {
                            return Err(SidError::InvalidState(format!("project {id} is in use")));
                        }
                    }
                    super::rbac::delete_project_records(tx, id)?;
                    super::machine::delete_project_records(tx, id)?;
                    super::device::delete_project_records(tx, id)?;
                    super::consent::delete_project_records(tx, id)?;
                    super::flow::delete_project_records(tx, id)?;
                    super::branding::delete_project_records(tx, id)?;
                }
                _ => return Ok(()),
            }
            // A system project is never deleted, whatever its id.
            tx.run(
                "MATCH (j:SidProject) WHERE j.id = $id AND j.is_system = false DETACH DELETE j",
                Params::default().with("id", project_value(id)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn list_projects(&self, offset: u64, limit: u64) -> SidResult<Vec<Project>> {
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (j:SidProject) RETURN {PROJECT}"),
                Params::default(),
            )?;
            let all = rows.iter().map(project).collect::<SidResult<Vec<_>>>()?;
            // Newest first, then by id.
            Ok(Decision::Abandon(sorted_page(
                all,
                |p| (std::cmp::Reverse(p.created_at), *p.id.as_uuid()),
                offset,
                limit,
            )))
        })
        .await
    }

    pub(super) async fn count_projects(&self) -> SidResult<u64> {
        self.transaction(|tx| {
            get_count(&tx.run(
                "MATCH (j:SidProject) RETURN count(j) AS n",
                Params::default(),
            )?)
            .map(Decision::Abandon)
        })
        .await
    }

    pub(super) async fn ensure_system_project(&self, ctx: MutationContext) -> SidResult<()> {
        self.mutate("project:system".to_owned(), ctx, |tx| {
            // Concurrent first starts create one: the id is unique.
            if get(tx, ProjectId::SYSTEM)?.is_none() {
                insert(tx, &Project::system())?;
            }
            Ok(())
        })
        .await
    }
}
