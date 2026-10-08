// SPDX-License-Identifier: AGPL-3.0-only
//! RBAC operations: Role, Group, GroupMember, RoleAssignment, SoD, CedarPolicy.

use super::{SqliteBackend, col, dt_col, fmt_dt, fmt_dt_opt, uuid_col};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        CedarPolicy, CedarPolicyId, Group, GroupId, GroupMember, MutationContext, ProfileId,
        ProjectId, Role, RoleAssignment, RoleAssignmentId, RoleAssignmentPrincipal, RoleId,
        SodConflictRule,
    },
};

fn row_to_role(row: &sqlx::sqlite::SqliteRow) -> SidResult<Role> {
    let permissions: String = col(row, "permissions")?;
    let revision: i64 = col(row, "revision")?;
    Ok(Role {
        id: RoleId(uuid_col(row, "id")?),
        project_id: ProjectId(uuid_col(row, "project_id")?),
        key: col(row, "key")?,
        name: col(row, "name")?,
        description: col(row, "description")?,
        group: col(row, "group_label")?,
        permissions: Role::parse_permissions(&permissions),
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_group(row: &sqlx::sqlite::SqliteRow) -> SidResult<Group> {
    let parent: Option<String> = col(row, "parent_group_id")?;
    Ok(Group {
        id: GroupId(uuid_col(row, "id")?),
        project_id: ProjectId(uuid_col(row, "project_id")?),
        name: col(row, "name")?,
        description: col(row, "description")?,
        parent_group_id: parent
            .map(|s| {
                uuid::Uuid::parse_str(&s)
                    .map(GroupId)
                    .map_err(|e| SidError::Storage(format!("column parent_group_id: {e}")))
            })
            .transpose()?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_group_member(row: &sqlx::sqlite::SqliteRow) -> SidResult<GroupMember> {
    Ok(GroupMember {
        group_id: GroupId(uuid_col(row, "group_id")?),
        profile_id: col(row, "profile_id")?,
        added_at: dt_col(row, "added_at")?,
    })
}

/// Exactly one principal column is set (`chk_principal` in the schema);
/// a row breaking that is reported, not patched over.
fn row_to_role_assignment(row: &sqlx::sqlite::SqliteRow) -> SidResult<RoleAssignment> {
    use sid_core::models::{MachineUserId, ProfileId};
    let id = uuid_col(row, "id")?;
    let group_id: Option<String> = col(row, "group_id")?;

    let principal = if let Some(pid) = col::<Option<ProfileId>>(row, "profile_id")? {
        RoleAssignmentPrincipal::Profile(pid)
    } else if let Some(gid) = group_id {
        RoleAssignmentPrincipal::Group(GroupId(
            uuid::Uuid::parse_str(&gid)
                .map_err(|e| SidError::Storage(format!("column group_id: {e}")))?,
        ))
    } else if let Some(mid) = col::<Option<MachineUserId>>(row, "machine_user_id")? {
        RoleAssignmentPrincipal::MachineUser(mid)
    } else if let Some(client_id) = col::<Option<String>>(row, "oauth_client_id")? {
        RoleAssignmentPrincipal::OAuthClient(client_id)
    } else if let Some(connector) =
        col::<Option<sid_core::models::ProvisioningConnectorId>>(row, "provisioning_connector_id")?
    {
        RoleAssignmentPrincipal::ProvisioningConnector(connector)
    } else {
        return Err(SidError::Storage(format!(
            "role_assignment {id} has no principal"
        )));
    };

    Ok(RoleAssignment {
        id: RoleAssignmentId(id),
        principal,
        role_id: RoleId(uuid_col(row, "role_id")?),
        scope: col(row, "scope")?,
        expires_at: super::dt_col_opt(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
        // The envelope lives in its own tables; `with_admin_envelopes` attaches it.
        admin: None,
        provenance: col::<Option<String>>(row, "granted_by")?
            .map(|granted_by| {
                let reference = |column: &str| -> SidResult<Option<RoleAssignmentId>> {
                    col::<Option<String>>(row, column)?
                        .map(|id| {
                            uuid::Uuid::parse_str(&id)
                                .map(RoleAssignmentId)
                                .map_err(|e| SidError::Storage(format!("column {column}: {e}")))
                        })
                        .transpose()
                };
                Ok::<_, SidError>(sid_core::models::AssignmentProvenance {
                    granted_by,
                    basis: reference("basis_assignment_id")?,
                    depends_on: reference("depends_on_assignment_id")?,
                    // Its own table; `with_admin_envelopes` attaches it.
                    ceiling: None,
                })
            })
            .transpose()?,
        revision: u64::try_from(col::<i64>(row, "revision")?)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
    })
}

/// Insert `assignment` in `tx`; an existing id is a `Conflict`, a missing role
/// or principal an error.
pub(crate) async fn insert_role_assignment(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    assignment: &RoleAssignment,
) -> SidResult<()> {
    let (mut profile_id, mut group_id, mut machine_user_id, mut oauth_client_id) =
        (None, None, None, None);
    let mut connector_id = None;
    match &assignment.principal {
        RoleAssignmentPrincipal::Profile(pid) => profile_id = Some(*pid),
        RoleAssignmentPrincipal::Group(gid) => group_id = Some(gid.0.to_string()),
        RoleAssignmentPrincipal::MachineUser(mid) => machine_user_id = Some(*mid),
        RoleAssignmentPrincipal::OAuthClient(client) => oauth_client_id = Some(client),
        RoleAssignmentPrincipal::ProvisioningConnector(id) => connector_id = Some(*id),
    }
    let provenance = assignment.provenance.as_ref();
    sqlx::query(
        "INSERT INTO role_assignments (id, profile_id, group_id, machine_user_id, oauth_client_id,
            provisioning_connector_id, role_id, scope, expires_at, created_at,
            granted_by, basis_assignment_id, depends_on_assignment_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(assignment.id.0.to_string())
    .bind(profile_id)
    .bind(&group_id)
    .bind(machine_user_id)
    .bind(oauth_client_id)
    .bind(connector_id)
    .bind(assignment.role_id.0.to_string())
    .bind(&assignment.scope)
    .bind(fmt_dt_opt(assignment.expires_at))
    .bind(fmt_dt(&assignment.created_at))
    .bind(provenance.map(|p| p.granted_by.as_str()))
    .bind(provenance.and_then(|p| p.basis).map(|id| id.0.to_string()))
    .bind(
        provenance
            .and_then(|p| p.depends_on)
            .map(|id| id.0.to_string()),
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("role assignment", e))?;
    if let Some(envelope) = &assignment.admin {
        insert_admin_envelope(tx, assignment.id, envelope).await?;
    }
    if let Some(ceiling) = provenance.and_then(|p| p.ceiling.as_ref()) {
        // An empty ceiling would read back as no ceiling at all.
        if ceiling.is_empty() {
            return Err(SidError::Validation(
                "an approved ceiling names no permission".into(),
            ));
        }
        for permission in ceiling {
            sqlx::query(
                "INSERT INTO role_assignment_ceilings (assignment_id, permission) VALUES (?, ?)",
            )
            .bind(assignment.id.0.to_string())
            .bind(permission)
            .execute(&mut **tx)
            .await
            .map_err(|e| super::insert_error("approved ceiling", e))?;
        }
    }
    if let Some(connector) = connector_id {
        super::provisioning_connector::bump_connector_revision(tx, connector).await?;
    }
    Ok(())
}

/// Store `role`'s editable fields in `tx` while the stored role is still at
/// `role.revision`, moving the revision on; false when it is not.
async fn update_role_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    role: &Role,
) -> SidResult<bool> {
    let revision = i64::try_from(role.revision)
        .map_err(|e| SidError::Validation(format!("role revision: {e}")))?;
    Ok(sqlx::query(
        "UPDATE roles SET name = ?, description = ?, group_label = ?, permissions = ?,
            updated_at = ?, revision = revision + 1
         WHERE id = ? AND revision = ?",
    )
    .bind(&role.name)
    .bind(&role.description)
    .bind(&role.group)
    .bind(role.permissions_string())
    .bind(fmt_dt(&role.updated_at))
    .bind(role.id.0.to_string())
    .bind(revision)
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("role", e))?
    .rows_affected()
        == 1)
}

/// Store the envelope of the administrative assignment `id` in `tx`; an
/// incomplete envelope is refused.
async fn insert_admin_envelope(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: RoleAssignmentId,
    envelope: &sid_core::models::AdminEnvelope,
) -> SidResult<()> {
    envelope
        .validate()
        .map_err(|e| SidError::Validation(e.to_string()))?;
    let id = id.0.to_string();
    sqlx::query(
        "INSERT INTO role_assignment_admin (assignment_id, recipient_group_id, max_validity_secs)
         VALUES (?, ?, ?)",
    )
    .bind(&id)
    .bind(envelope.recipient_group.map(|g| g.0.to_string()))
    .bind(envelope.max_validity_secs)
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("administrative envelope", e))?;
    let entries = envelope
        .operations
        .iter()
        .map(|op| ("operation", op.as_str()))
        .chain(
            envelope
                .recipient_kinds
                .iter()
                .map(|kind| ("recipient_kind", kind.as_str())),
        )
        .chain(
            envelope
                .permission_ceiling
                .iter()
                .map(|p| ("permission", p.as_str())),
        );
    for (kind, value) in entries {
        sqlx::query(
            "INSERT INTO role_assignment_admin_entries (assignment_id, kind, value) VALUES (?, ?, ?)",
        )
        .bind(&id)
        .bind(kind)
        .bind(value)
        .execute(&mut **tx)
        .await
        .map_err(|e| super::insert_error("administrative envelope entry", e))?;
    }
    for role in &envelope.roles {
        sqlx::query(
            "INSERT INTO role_assignment_admin_roles (assignment_id, role_id) VALUES (?, ?)",
        )
        .bind(&id)
        .bind(role.0.to_string())
        .execute(&mut **tx)
        .await
        .map_err(|e| super::insert_error("administrative envelope role", e))?;
    }
    Ok(())
}

/// Check in `tx` that `fence` still holds. The write transaction is the
/// only writer, so nothing can change what it read before it commits.
async fn check_assignment_fence(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    fence: &sid_core::models::AssignmentFence,
) -> SidResult<()> {
    let revision =
        |r: u64| i64::try_from(r).map_err(|_| SidError::Fenced("revision out of range".into()));
    let read = |e: sqlx::Error| SidError::Storage(format!("check assignment fence: {e}"));
    if let Some((basis, checked)) = fence.basis {
        let held: Option<(i64,)> = sqlx::query_as(
            "SELECT revision FROM role_assignments
             WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(basis.0.to_string())
        .bind(fmt_dt(&chrono::Utc::now()))
        .fetch_optional(&mut **tx)
        .await
        .map_err(read)?;
        if held.map(|(r,)| r) != Some(revision(checked)?) {
            return Err(SidError::Fenced(
                "the authorizing assignment changed since it was checked".into(),
            ));
        }
    }
    let (role, checked) = &fence.role;
    let held: Option<(String,)> = sqlx::query_as("SELECT permissions FROM roles WHERE id = ?")
        .bind(role.0.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(read)?;
    let same = held.is_some_and(|(permissions,)| {
        Role::parse_permissions(&permissions)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            == *checked
    });
    if !same {
        return Err(SidError::Fenced(
            "the role's permissions changed since it was checked".into(),
        ));
    }
    if let Some((group, member)) = fence.recipient_membership {
        let held: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM group_members WHERE group_id = ? AND profile_id = ?")
                .bind(group.0.to_string())
                .bind(member)
                .fetch_optional(&mut **tx)
                .await
                .map_err(read)?;
        if held.is_none() {
            return Err(SidError::Fenced(
                "the recipient left the eligible group since it was checked".into(),
            ));
        }
    }
    if let Some((group, grantor)) = fence.grantor_outside {
        let inside: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM group_members WHERE group_id = ? AND profile_id = ?")
                .bind(group.0.to_string())
                .bind(grantor)
                .fetch_optional(&mut **tx)
                .await
                .map_err(read)?;
        if inside.is_some() {
            return Err(SidError::Fenced(
                "the grantor joined the recipient group since it was checked".into(),
            ));
        }
    }
    Ok(())
}

/// `rows` as assignments, each administrative one with its envelope.
async fn read_assignments(
    pool: &sqlx::SqlitePool,
    rows: &[sqlx::sqlite::SqliteRow],
) -> SidResult<Vec<RoleAssignment>> {
    let assignments = rows
        .iter()
        .map(row_to_role_assignment)
        .collect::<SidResult<Vec<_>>>()?;
    with_admin_envelopes(pool, assignments).await
}

/// Attach to `assignments` the envelopes of the administrative ones.
pub(crate) async fn with_admin_envelopes(
    pool: &sqlx::SqlitePool,
    mut assignments: Vec<RoleAssignment>,
) -> SidResult<Vec<RoleAssignment>> {
    use sid_core::models::{AdminEnvelope, AdminOperation, RecipientKind};
    use sqlx::Row;
    if assignments.is_empty() {
        return Ok(assignments);
    }
    let unreadable =
        |id: &str| SidError::Storage(format!("administrative envelope {id} unreadable"));
    let read_error =
        |e: sqlx::Error| SidError::Storage(format!("read administrative envelopes: {e}"));
    for assignment in &mut assignments {
        let Some(provenance) = assignment.provenance.as_mut() else {
            continue;
        };
        let permissions: Vec<(String,)> = sqlx::query_as(
            "SELECT permission FROM role_assignment_ceilings WHERE assignment_id = ?",
        )
        .bind(assignment.id.0.to_string())
        .fetch_all(pool)
        .await
        .map_err(|e| SidError::Storage(format!("read approved ceilings: {e}")))?;
        if !permissions.is_empty() {
            provenance.ceiling = Some(permissions.into_iter().map(|(p,)| p).collect());
        }
    }
    let mut envelopes = std::collections::HashMap::<String, AdminEnvelope>::new();
    for assignment in &assignments {
        let id = assignment.id.0.to_string();
        let Some(head) = sqlx::query(
            "SELECT recipient_group_id, max_validity_secs FROM role_assignment_admin
             WHERE assignment_id = ?",
        )
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(read_error)?
        else {
            continue;
        };
        let group: Option<String> = head.try_get("recipient_group_id").map_err(read_error)?;
        let mut envelope = AdminEnvelope {
            operations: Default::default(),
            roles: Default::default(),
            permission_ceiling: Default::default(),
            recipient_kinds: Default::default(),
            recipient_group: group
                .map(|g| uuid::Uuid::parse_str(&g).map(GroupId))
                .transpose()
                .map_err(|_| unreadable(&id))?,
            max_validity_secs: head.try_get("max_validity_secs").map_err(read_error)?,
        };
        let entries = sqlx::query(
            "SELECT kind, value FROM role_assignment_admin_entries WHERE assignment_id = ?",
        )
        .bind(&id)
        .fetch_all(pool)
        .await
        .map_err(read_error)?;
        for entry in entries {
            let kind: String = entry.try_get("kind").map_err(read_error)?;
            let value: String = entry.try_get("value").map_err(read_error)?;
            match kind.as_str() {
                "operation" => {
                    envelope
                        .operations
                        .insert(AdminOperation::parse(&value).ok_or_else(|| unreadable(&id))?);
                }
                "recipient_kind" => {
                    envelope
                        .recipient_kinds
                        .insert(RecipientKind::parse(&value).ok_or_else(|| unreadable(&id))?);
                }
                "permission" => {
                    envelope.permission_ceiling.insert(value);
                }
                _ => return Err(unreadable(&id)),
            }
        }
        let roles =
            sqlx::query("SELECT role_id FROM role_assignment_admin_roles WHERE assignment_id = ?")
                .bind(&id)
                .fetch_all(pool)
                .await
                .map_err(read_error)?;
        for role in roles {
            let role: String = role.try_get("role_id").map_err(read_error)?;
            envelope.roles.insert(RoleId(
                uuid::Uuid::parse_str(&role).map_err(|_| unreadable(&id))?,
            ));
        }
        envelopes.insert(id, envelope);
    }
    for assignment in &mut assignments {
        assignment.admin = envelopes.remove(&assignment.id.0.to_string());
    }
    Ok(assignments)
}

/// An unknown effect is an error: read as permit, a forbid policy would grant
/// what it was written to deny.
fn row_to_cedar_policy(row: &sqlx::sqlite::SqliteRow) -> SidResult<CedarPolicy> {
    let revision: i64 = col(row, "revision")?;
    Ok(CedarPolicy {
        id: CedarPolicyId(uuid_col(row, "id")?),
        project_id: ProjectId(uuid_col(row, "project_id")?),
        name: col(row, "name")?,
        description: col(row, "description")?,
        policy_text: col(row, "policy_text")?,
        effect: super::parsed_col(row, "effect")?,
        enabled: col(row, "enabled")?,
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

/// An unknown severity is an error: read as a warning, a blocking rule would
/// stop blocking.
fn row_to_sod_rule(row: &sqlx::sqlite::SqliteRow) -> SidResult<SodConflictRule> {
    let conflicting_roles: String = col(row, "conflicting_roles")?;
    Ok(SodConflictRule {
        name: col(row, "name")?,
        description: col(row, "description")?,
        conflicting_roles: conflicting_roles
            .split_whitespace()
            .map(String::from)
            .collect(),
        severity: super::parsed_col(row, "severity")?,
    })
}

impl SqliteBackend {
    // === Role ===

    pub(crate) async fn get_role_impl(&self, id: RoleId) -> SidResult<Option<Role>> {
        let row = sqlx::query("SELECT * FROM roles WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_role).transpose()
    }

    pub(crate) async fn get_role_by_name_impl(
        &self,
        project_id: ProjectId,
        name: &str,
    ) -> SidResult<Option<Role>> {
        let row = sqlx::query("SELECT * FROM roles WHERE project_id = ? AND name = ?")
            .bind(project_id.0.to_string())
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_role).transpose()
    }

    pub(crate) async fn create_role_impl(
        &self,
        role: &Role,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO roles (id, project_id, key, name, description, group_label, permissions, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(role.id.0.to_string())
        .bind(role.project_id.0.to_string())
        .bind(&role.key)
        .bind(&role.name)
        .bind(&role.description)
        .bind(&role.group)
        .bind(role.permissions_string())
        .bind(fmt_dt(&role.created_at))
        .bind(fmt_dt(&role.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("role", e))?;
        Self::commit_mutation(tx, &format!("role:{}", role.id.0), audit).await
    }

    pub(crate) async fn update_role_impl(
        &self,
        role: &Role,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !update_role_in_tx(&mut tx, role).await? {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("role:{}", role.id.0), audit).await?;
        Ok(true)
    }

    /// The write transaction is the only writer, so no assignment of the
    /// role can commit between this check and the update.
    pub(crate) async fn update_role_fenced_impl(
        &self,
        role: &Role,
        fence: &sid_core::models::RoleEditFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let revision =
            |v: u64| i64::try_from(v).map_err(|e| SidError::Validation(format!("revision: {e}")));
        let read = |e: sqlx::Error| SidError::Storage(format!("check role edit fence: {e}"));
        let mut tx = self.begin_write().await?;
        if let Some((authority, checked)) = fence.authority {
            let held: Option<(i64,)> = sqlx::query_as(
                "SELECT revision FROM role_assignments
                 WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)",
            )
            .bind(authority.0.to_string())
            .bind(fmt_dt(&chrono::Utc::now()))
            .fetch_optional(&mut *tx)
            .await
            .map_err(read)?;
            if held.map(|(v,)| v) != Some(revision(checked)?) {
                return Err(SidError::Fenced(
                    "the editor's authority changed since it was checked".into(),
                ));
            }
        }
        if let Some(bounded) = &fence.bounded {
            let present: Vec<(String,)> = sqlx::query_as(
                "SELECT DISTINCT a.id FROM role_assignments a
                 JOIN role_assignment_ceilings c ON c.assignment_id = a.id
                 WHERE a.role_id = ?",
            )
            .bind(role.id.0.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(read)?;
            for (id,) in present {
                let id = uuid::Uuid::parse_str(&id)
                    .map_err(|e| SidError::Storage(format!("column id: {e}")))?;
                if !bounded.contains(&RoleAssignmentId(id)) {
                    return Err(SidError::Fenced(
                        "an assignment under an approved ceiling appeared since the check".into(),
                    ));
                }
            }
        }
        if !update_role_in_tx(&mut tx, role).await? {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("role:{}", role.id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn delete_role_impl(
        &self,
        id: RoleId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM roles WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("role:{}", id.0), audit).await
    }

    pub(crate) async fn list_roles_impl(&self, project_id: ProjectId) -> SidResult<Vec<Role>> {
        let rows = sqlx::query("SELECT * FROM roles WHERE project_id = ?")
            .bind(project_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_role).collect()
    }

    // === Group ===

    pub(crate) async fn get_group_impl(&self, id: GroupId) -> SidResult<Option<Group>> {
        let row = sqlx::query("SELECT * FROM groups WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_group).transpose()
    }

    pub(crate) async fn create_group_impl(
        &self,
        group: &Group,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::insert_group(&mut tx, group).await?;
        Self::commit_mutation(tx, &format!("group:{}", group.id.0), audit).await
    }

    pub(crate) async fn set_group_description_impl(
        &self,
        id: GroupId,
        description: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query("UPDATE groups SET description = ?, updated_at = ? WHERE id = ?")
            .bind(description)
            .bind(fmt_dt(&chrono::Utc::now()))
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("update group: {e}")))?
            .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("group:{}", id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn delete_group_impl(
        &self,
        id: GroupId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        // An administrative envelope restricting recipients to the group
        // keeps it: deleting it would widen the envelope. Foreign keys are
        // checked only at commit here, so the reference is looked up first.
        let restricting =
            sqlx::query("SELECT 1 FROM role_assignment_admin WHERE recipient_group_id = ? LIMIT 1")
                .bind(id.0.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        if restricting.is_some() {
            return Err(SidError::Conflict(
                "the group restricts the recipients of an administrative assignment".into(),
            ));
        }
        sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("group:{}", id.0), audit).await
    }

    pub(crate) async fn list_groups_impl(&self, project_id: ProjectId) -> SidResult<Vec<Group>> {
        let rows = sqlx::query("SELECT * FROM groups WHERE project_id = ?")
            .bind(project_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_group).collect()
    }

    pub(crate) async fn add_to_group_impl(
        &self,
        member: &GroupMember,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::add_member(&mut tx, member).await?;
        Self::commit_mutation(tx, &format!("group:{}", member.group_id.0), audit).await
    }

    pub(crate) async fn remove_from_group_impl(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::remove_member(&mut tx, group_id, profile_id).await?;
        Self::commit_mutation(tx, &format!("group:{}", group_id.0), audit).await
    }

    pub(crate) async fn list_group_members_impl(
        &self,
        group_id: GroupId,
    ) -> SidResult<Vec<GroupMember>> {
        let rows = sqlx::query("SELECT * FROM group_members WHERE group_id = ?")
            .bind(group_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_group_member).collect()
    }

    pub(crate) async fn list_groups_for_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<Group>> {
        let rows = sqlx::query(
            "SELECT g.* FROM groups g
             INNER JOIN group_members gm ON g.id = gm.group_id
             WHERE gm.profile_id = ?",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_group).collect()
    }

    // === RoleAssignment ===

    pub(crate) async fn create_role_assignment_impl(
        &self,
        assignment: &RoleAssignment,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        insert_role_assignment(&mut tx, assignment).await?;
        Self::commit_mutation(tx, &format!("role_assignment:{}", assignment.id.0), audit).await
    }

    pub(crate) async fn get_role_assignment_impl(
        &self,
        id: RoleAssignmentId,
    ) -> SidResult<Option<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("read role assignment: {e}")))?;
        Ok(read_assignments(&self.pool, &rows).await?.pop())
    }

    pub(crate) async fn create_role_assignment_fenced_impl(
        &self,
        assignment: &RoleAssignment,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        check_assignment_fence(&mut tx, fence).await?;
        insert_role_assignment(&mut tx, assignment).await?;
        Self::commit_mutation(tx, &format!("role_assignment:{}", assignment.id.0), audit).await
    }

    pub(crate) async fn delete_role_assignment_fenced_impl(
        &self,
        id: RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        check_assignment_fence(&mut tx, fence).await?;
        let removed: Option<(Option<sid_core::models::ProvisioningConnectorId>,)> = sqlx::query_as(
            "DELETE FROM role_assignments WHERE id = ? RETURNING provisioning_connector_id",
        )
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some((connector,)) = removed else {
            return Ok(false);
        };
        if let Some(connector) = connector {
            super::provisioning_connector::bump_connector_revision(&mut tx, connector).await?;
        }
        Self::commit_mutation(tx, &format!("role_assignment:{}", id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn delete_role_assignment_impl(
        &self,
        id: RoleAssignmentId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        let removed: Option<(Option<sid_core::models::ProvisioningConnectorId>,)> = sqlx::query_as(
            "DELETE FROM role_assignments WHERE id = ? RETURNING provisioning_connector_id",
        )
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        if let Some((Some(connector),)) = removed {
            super::provisioning_connector::bump_connector_revision(&mut tx, connector).await?;
        }
        Self::commit_mutation(tx, &format!("role_assignment:{}", id.0), audit).await
    }

    pub(crate) async fn list_role_assignments_for_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_role_assignments_for_group_impl(
        &self,
        group_id: GroupId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE group_id = ?")
            .bind(group_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_role_assignments_for_machine_user_impl(
        &self,
        machine_user_id: sid_core::models::MachineUserId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE machine_user_id = ?")
            .bind(machine_user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_role_assignments_for_oauth_client_impl(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE oauth_client_id = ?")
            .bind(client_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_role_assignments_for_provisioning_connector_impl(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows =
            sqlx::query("SELECT * FROM role_assignments WHERE provisioning_connector_id = ?")
                .bind(connector_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("list connector role assignments: {e}")))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_role_assignments_for_role_impl(
        &self,
        role_id: RoleId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE role_id = ?")
            .bind(role_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_expiring_role_assignments_impl(
        &self,
        within_hours: i64,
    ) -> SidResult<Vec<RoleAssignment>> {
        let cutoff = fmt_dt(&(chrono::Utc::now() + chrono::Duration::hours(within_hours)));
        let rows = sqlx::query(
            "SELECT * FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at <= ?",
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    /// Delete the expired assignments and commit the expired event each owes
    /// in the same transaction.
    pub(crate) async fn cleanup_expired_role_assignments_impl(
        &self,
        mut audit: MutationContext,
    ) -> SidResult<Vec<RoleAssignment>> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let expired = sqlx::query(
            "DELETE FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at < ? \
             RETURNING *",
        )
        .bind(&now)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .iter()
        .map(row_to_role_assignment)
        .collect::<SidResult<Vec<RoleAssignment>>>()?;
        audit
            .work
            .extend(expired.iter().map(|a| a.expired_event().relay()));
        let removed = u64::try_from(expired.len()).expect("a row count fits in u64");
        Self::commit_bulk(tx, removed, "role_assignments:cleanup", audit).await?;
        Ok(expired)
    }

    // === SoD ===

    pub(crate) async fn list_sod_rules_impl(&self) -> SidResult<Vec<SodConflictRule>> {
        let rows = sqlx::query("SELECT * FROM sod_conflict_rules")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_sod_rule).collect()
    }

    // === CedarPolicy ===

    pub(crate) async fn get_cedar_policy_impl(
        &self,
        id: CedarPolicyId,
    ) -> SidResult<Option<CedarPolicy>> {
        let row = sqlx::query("SELECT * FROM cedar_policies WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_cedar_policy).transpose()
    }

    pub(crate) async fn update_cedar_policy_impl(
        &self,
        policy: &CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let revision = i64::try_from(policy.revision)
            .map_err(|e| SidError::Validation(format!("policy revision: {e}")))?;
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query(
            "UPDATE cedar_policies SET description = ?, policy_text = ?, effect = ?, enabled = ?,
                updated_at = ?, revision = revision + 1
             WHERE id = ? AND revision = ?",
        )
        .bind(&policy.description)
        .bind(&policy.policy_text)
        .bind(policy.effect.as_str())
        .bind(policy.enabled)
        .bind(fmt_dt(&policy.updated_at))
        .bind(policy.id.0.to_string())
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update policy: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("cedar_policy:{}", policy.id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn create_cedar_policy_impl(
        &self,
        policy: &CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO cedar_policies (id, project_id, name, description, policy_text, effect, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(policy.id.0.to_string())
        .bind(policy.project_id.0.to_string())
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.policy_text)
        .bind(policy.effect.as_str())
        .bind(policy.enabled)
        .bind(fmt_dt(&policy.created_at))
        .bind(fmt_dt(&policy.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("policy", e))?;
        Self::commit_mutation(tx, &format!("cedar_policy:{}", policy.id.0), audit).await
    }

    pub(crate) async fn delete_cedar_policy_impl(
        &self,
        id: CedarPolicyId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM cedar_policies WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("cedar_policy:{}", id.0), audit).await
    }

    pub(crate) async fn list_cedar_policies_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<CedarPolicy>> {
        let rows = sqlx::query("SELECT * FROM cedar_policies WHERE project_id = ?")
            .bind(project_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_cedar_policy).collect()
    }
}
