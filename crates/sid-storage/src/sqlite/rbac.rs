// SPDX-License-Identifier: AGPL-3.0-only
//! RBAC operations: Role, Group, GroupMember, RoleAssignment, CedarPolicy.

use super::{SqliteBackend, col, dt_col, fmt_dt, fmt_dt_opt};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        CedarPolicy, CedarPolicyId, Group, GroupId, GroupMember, MutationContext, ProfileId,
        ProjectId, Role, RoleAssignment, RoleAssignmentId, RoleAssignmentPrincipal, RoleId,
    },
};

fn row_to_role(row: &sqlx::sqlite::SqliteRow) -> SidResult<Role> {
    let permissions: String = col(row, "permissions")?;
    let revision: i64 = col(row, "revision")?;
    Ok(Role {
        id: col(row, "id")?,
        project_id: col(row, "project_id")?,
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
    Ok(Group {
        id: col(row, "id")?,
        project_id: col(row, "project_id")?,
        name: col(row, "name")?,
        description: col(row, "description")?,
        parent_group_id: col(row, "parent_group_id")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_group_member(row: &sqlx::sqlite::SqliteRow) -> SidResult<GroupMember> {
    Ok(GroupMember {
        group_id: col(row, "group_id")?,
        profile_id: col(row, "profile_id")?,
        added_at: dt_col(row, "added_at")?,
    })
}

/// Exactly one principal column is set (`chk_principal` in the schema);
/// a row breaking that is reported, not patched over.
fn row_to_role_assignment(row: &sqlx::sqlite::SqliteRow) -> SidResult<RoleAssignment> {
    use sid_core::models::{MachineUserId, ProfileId};
    let id: RoleAssignmentId = col(row, "id")?;

    let principal = if let Some(pid) = col::<Option<ProfileId>>(row, "profile_id")? {
        RoleAssignmentPrincipal::Profile(pid)
    } else if let Some(gid) = col::<Option<GroupId>>(row, "group_id")? {
        RoleAssignmentPrincipal::Group(gid)
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
        id,
        principal,
        role_id: col(row, "role_id")?,
        scope: col(row, "scope")?,
        expires_at: super::dt_col_opt(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
        // The envelope lives in its own tables; `with_admin_envelopes` attaches it.
        admin: None,
        policy_admin: None,
        provenance: col::<Option<String>>(row, "granted_by")?
            .map(|granted_by| {
                let reference = |column: &str| col::<Option<RoleAssignmentId>>(row, column);
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

/// Insert `assignment` in `tx`, advancing its connector's revision when a
/// provisioning connector holds it; an existing id is a `Conflict`, a missing
/// role or principal an error.
pub(crate) async fn insert_role_assignment(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    assignment: &RoleAssignment,
) -> SidResult<()> {
    insert_role_assignment_row(tx, assignment).await?;
    if let RoleAssignmentPrincipal::ProvisioningConnector(connector) = assignment.principal {
        super::provisioning_connector::bump_connector_revision(tx, connector).await?;
    }
    Ok(())
}

/// Insert `assignment` in `tx` as recorded, leaving its holder unchanged: a
/// restored connector's revision already counts its assignments.
pub(crate) async fn insert_role_assignment_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    assignment: &RoleAssignment,
) -> SidResult<()> {
    let (mut profile_id, mut group_id, mut machine_user_id, mut oauth_client_id) =
        (None, None, None, None);
    let mut connector_id = None;
    match &assignment.principal {
        RoleAssignmentPrincipal::Profile(pid) => profile_id = Some(*pid),
        RoleAssignmentPrincipal::Group(gid) => group_id = Some(*gid),
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
    .bind(assignment.id)
    .bind(profile_id)
    .bind(group_id)
    .bind(machine_user_id)
    .bind(oauth_client_id)
    .bind(connector_id)
    .bind(assignment.role_id)
    .bind(&assignment.scope)
    .bind(fmt_dt_opt(assignment.expires_at))
    .bind(fmt_dt(&assignment.created_at))
    .bind(provenance.map(|p| p.granted_by.as_str()))
    .bind(provenance.and_then(|p| p.basis))
    .bind(provenance.and_then(|p| p.depends_on))
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("role assignment", e))?;
    if let Some(envelope) = &assignment.admin {
        insert_admin_envelope(tx, assignment.id, envelope).await?;
    }
    if let Some(authority) = &assignment.policy_admin {
        insert_policy_authority_in_tx(tx, assignment.id, authority).await?;
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
            .bind(assignment.id)
            .bind(permission)
            .execute(&mut **tx)
            .await
            .map_err(|e| super::insert_error("approved ceiling", e))?;
        }
    }
    Ok(())
}

/// Whether a live installation administrator assignment exists, held by
/// `profile` when one is given.
pub(crate) async fn administrator_exists<'e, E>(
    executor: E,
    profile: Option<ProfileId>,
) -> SidResult<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM role_assignments
             WHERE role_id = ? AND scope = ?
               AND (expires_at IS NULL OR expires_at > ?)
               AND (? IS NULL OR profile_id = ?))",
    )
    .bind(Role::installation_administrator().id)
    .bind(sid_core::models::INSTALLATION_SCOPE)
    .bind(fmt_dt(&chrono::Utc::now()))
    .bind(profile)
    .bind(profile)
    .fetch_one(executor)
    .await
    .map_err(|e| SidError::Storage(format!("administrator exists: {e}")))
}

/// The Profiles holding a live installation administrator assignment, with
/// their status.
pub(crate) async fn administrators(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> SidResult<Vec<(ProfileId, String)>> {
    sqlx::query_as(
        "SELECT id, status FROM profiles WHERE id IN (
             SELECT profile_id FROM role_assignments
             WHERE role_id = ? AND scope = ?
               AND (expires_at IS NULL OR expires_at > ?))",
    )
    .bind(Role::installation_administrator().id)
    .bind(sid_core::models::INSTALLATION_SCOPE)
    .bind(fmt_dt(&chrono::Utc::now()))
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("read administrators: {e}")))
}

impl super::SqliteBackend {
    /// Make `profile` an installation administrator in `tx`, a host's own
    /// write transaction (begun with [`super::SqliteBackend::begin_write_on`])
    /// that commits it with the host's state, as a first-administrator claim
    /// does.
    pub async fn grant_installation_administrator_in_tx(
        tx: &mut super::WriteTx,
        profile: ProfileId,
    ) -> SidResult<()> {
        grant_installation_administrator(tx, profile).await
    }
}

/// Make `profile` an installation administrator in `tx`: the built-in role
/// is stored if it is not, then assigned across the installation.
pub(crate) async fn grant_installation_administrator(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    profile: ProfileId,
) -> SidResult<()> {
    let role = Role::installation_administrator();
    sqlx::query(
        "INSERT INTO roles (id, project_id, key, name, description, group_label, permissions, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(role.id)
    .bind(role.project_id)
    .bind(&role.key)
    .bind(&role.name)
    .bind(&role.description)
    .bind(&role.group)
    .bind(role.permissions_string())
    .bind(fmt_dt(&role.created_at))
    .bind(fmt_dt(&role.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("role", e))?;
    insert_role_assignment(
        tx,
        &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile), role.id).on_installation(),
    )
    .await
}

/// Refuse, in `tx`, removing the assignment `id` when it is the
/// installation's last live administrator assignment held by an active or
/// suspended Profile. The write transaction holds the database lock: the
/// assignments and statuses counted are the ones this write sees.
async fn keep_last_administrator(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: RoleAssignmentId,
) -> SidResult<()> {
    let administrators: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT ra.id, p.status FROM role_assignments ra
         JOIN profiles p ON p.id = ra.profile_id
         WHERE ra.role_id = ? AND ra.scope = ?
           AND (ra.expires_at IS NULL OR ra.expires_at > ?)",
    )
    .bind(Role::installation_administrator().id)
    .bind(sid_core::models::INSTALLATION_SCOPE)
    .bind(fmt_dt(&chrono::Utc::now()))
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("read administrator assignments: {e}")))?;
    crate::check_other_administrator_assignment(id, &administrators)
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
    .bind(role.id)
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
    sqlx::query(
        "INSERT INTO role_assignment_admin (assignment_id, recipient_group_id, max_validity_secs)
         VALUES (?, ?, ?)",
    )
    .bind(id)
    .bind(envelope.recipient_group)
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
        .bind(id)
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
        .bind(id)
        .bind(*role)
        .execute(&mut **tx)
        .await
        .map_err(|e| super::insert_error("administrative envelope role", e))?;
    }
    Ok(())
}

/// Check in `tx` that `basis` still holds. The write transaction is the only
/// writer, so nothing can change what it read before it commits.
pub(crate) async fn check_authority_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    basis: &sid_core::models::AuthorityBasis,
) -> SidResult<()> {
    let read = |e: sqlx::Error| SidError::Storage(format!("check authority: {e}"));
    let checked = i64::try_from(basis.revision)
        .map_err(|e| SidError::Validation(format!("revision: {e}")))?;
    let held: Option<(i64,)> = sqlx::query_as(
        "SELECT revision FROM role_assignments
         WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(basis.assignment)
    .bind(fmt_dt(&chrono::Utc::now()))
    .fetch_optional(&mut **tx)
    .await
    .map_err(read)?;
    if held.map(|(v,)| v) != Some(checked) {
        return Err(SidError::Fenced(
            "the authorizing assignment changed since it was checked".into(),
        ));
    }
    if let Some((group, member)) = basis.member {
        let held: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM group_members WHERE group_id = ? AND profile_id = ?")
                .bind(group)
                .bind(member)
                .fetch_optional(&mut **tx)
                .await
                .map_err(read)?;
        if held.is_none() {
            return Err(SidError::Fenced(
                "the actor left the group holding its authority".into(),
            ));
        }
    }
    Ok(())
}

/// Store what assignment `id` may do with its resource's policies in `tx`.
pub(crate) async fn insert_policy_authority_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: RoleAssignmentId,
    authority: &sid_core::models::PolicyAuthority,
) -> SidResult<()> {
    for operation in &authority.operations {
        sqlx::query(
            "INSERT INTO role_assignment_policy_admin (assignment_id, operation) VALUES (?, ?)",
        )
        .bind(id)
        .bind(operation.as_str())
        .execute(&mut **tx)
        .await
        .map_err(|e| super::insert_error("policy authority", e))?;
    }
    Ok(())
}

/// Check in `tx` that `fence` still holds. The write transaction is the
/// only writer, so nothing can change what it read before it commits.
async fn check_assignment_fence(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    fence: &sid_core::models::AssignmentFence,
) -> SidResult<()> {
    let read = |e: sqlx::Error| SidError::Storage(format!("check assignment fence: {e}"));
    check_authority_in_tx(tx, &fence.basis).await?;
    let (role, checked) = &fence.role;
    let held: Option<(String,)> = sqlx::query_as("SELECT permissions FROM roles WHERE id = ?")
        .bind(*role)
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
                .bind(group)
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
                .bind(group)
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

/// `SELECT {columns} FROM {table} WHERE assignment_id IN (...)` over `ids`,
/// each bound as its 16 bytes.
async fn rows_of_assignments<T>(
    pool: &sqlx::SqlitePool,
    columns: &str,
    table: &str,
    ids: &[RoleAssignmentId],
) -> Result<Vec<T>, sqlx::Error>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow>,
{
    let mut rows = Vec::with_capacity(ids.len());
    for chunk in ids.chunks(IN_LIST_CHUNK) {
        let mut query = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {columns} FROM {table} WHERE assignment_id IN ({})",
            placeholders(chunk.len())
        )));
        for id in chunk {
            query = query.bind(*id);
        }
        rows.extend(query.fetch_all(pool).await?);
    }
    Ok(rows)
}

/// Values one `IN (...)` list binds: far below SQLite's limit of 32766
/// variables per statement, so a longer list is read in several statements.
pub(super) const IN_LIST_CHUNK: usize = 1000;

/// `n` comma-separated `?` placeholders, one per bound value.
pub(super) fn placeholders(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// Attach to `assignments` their approved ceilings, policy authority and the
/// envelopes of the administrative ones: a fixed number of reads, whatever
/// the number of assignments.
pub(crate) async fn with_admin_envelopes(
    pool: &sqlx::SqlitePool,
    mut assignments: Vec<RoleAssignment>,
) -> SidResult<Vec<RoleAssignment>> {
    use sid_core::models::{AdminEnvelope, AdminOperation, RecipientKind};
    if assignments.is_empty() {
        return Ok(assignments);
    }
    let unreadable = |id: &RoleAssignmentId| {
        SidError::Storage(format!("administrative envelope {id} unreadable"))
    };
    let read_error =
        |e: sqlx::Error| SidError::Storage(format!("read administrative envelopes: {e}"));
    let ids: Vec<RoleAssignmentId> = assignments.iter().map(|a| a.id).collect();
    let position: std::collections::HashMap<RoleAssignmentId, usize> = assignments
        .iter()
        .enumerate()
        .map(|(i, a)| (a.id, i))
        .collect();
    let at = |id: &RoleAssignmentId| position.get(id).copied().ok_or_else(|| unreadable(id));

    let ceilings: Vec<(RoleAssignmentId, String)> = rows_of_assignments(
        pool,
        "assignment_id, permission",
        "role_assignment_ceilings",
        &ids,
    )
    .await
    .map_err(|e| SidError::Storage(format!("read approved ceilings: {e}")))?;
    for (id, permission) in ceilings {
        let provenance = assignments[at(&id)?].provenance.as_mut().ok_or_else(|| {
            SidError::Storage(format!("approved ceiling of {id} without provenance"))
        })?;
        provenance
            .ceiling
            .get_or_insert_with(Default::default)
            .insert(permission);
    }

    let held: Vec<(RoleAssignmentId, String)> = rows_of_assignments(
        pool,
        "assignment_id, operation",
        "role_assignment_policy_admin",
        &ids,
    )
    .await
    .map_err(read_error)?;
    for (id, operation) in held {
        let operation =
            sid_core::models::PolicyOperation::parse(&operation).ok_or_else(|| unreadable(&id))?;
        assignments[at(&id)?]
            .policy_admin
            .get_or_insert_with(|| sid_core::models::PolicyAuthority {
                operations: Default::default(),
            })
            .operations
            .insert(operation);
    }

    let heads: Vec<(RoleAssignmentId, Option<GroupId>, i64)> = rows_of_assignments(
        pool,
        "assignment_id, recipient_group_id, max_validity_secs",
        "role_assignment_admin",
        &ids,
    )
    .await
    .map_err(read_error)?;
    if heads.is_empty() {
        return Ok(assignments);
    }
    let mut envelopes = std::collections::HashMap::<RoleAssignmentId, AdminEnvelope>::new();
    for (id, group, max_validity_secs) in heads {
        let envelope = AdminEnvelope {
            operations: Default::default(),
            roles: Default::default(),
            permission_ceiling: Default::default(),
            recipient_kinds: Default::default(),
            recipient_group: group,
            max_validity_secs,
        };
        envelopes.insert(id, envelope);
    }

    let entries: Vec<(RoleAssignmentId, String, String)> = rows_of_assignments(
        pool,
        "assignment_id, kind, value",
        "role_assignment_admin_entries",
        &ids,
    )
    .await
    .map_err(read_error)?;
    for (id, kind, value) in entries {
        let envelope = envelopes.get_mut(&id).ok_or_else(|| unreadable(&id))?;
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

    let roles: Vec<(RoleAssignmentId, RoleId)> = rows_of_assignments(
        pool,
        "assignment_id, role_id",
        "role_assignment_admin_roles",
        &ids,
    )
    .await
    .map_err(read_error)?;
    for (id, role) in roles {
        envelopes
            .get_mut(&id)
            .ok_or_else(|| unreadable(&id))?
            .roles
            .insert(role);
    }

    for (id, envelope) in envelopes {
        assignments[at(&id)?].admin = Some(envelope);
    }
    Ok(assignments)
}

/// An unknown effect is an error: read as permit, a forbid policy would grant
/// what it was written to deny.
fn row_to_cedar_policy(row: &sqlx::sqlite::SqliteRow) -> SidResult<CedarPolicy> {
    let revision: i64 = col(row, "revision")?;
    let project = col::<Option<ProjectId>>(row, "project_id")?;
    // A scope naming both a project and a resource would apply where it was
    // not written: an error, never one of the two.
    let scope = sid_core::models::PolicyScope::from_columns(project, col(row, "resource_id")?)
        .map_err(SidError::Storage)?;
    Ok(CedarPolicy {
        id: col(row, "id")?,
        scope,
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

impl SqliteBackend {
    // === Role ===

    pub(crate) async fn get_role_impl(&self, id: RoleId) -> SidResult<Option<Role>> {
        let row = sqlx::query("SELECT * FROM roles WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_role).transpose()
    }

    pub(crate) async fn get_roles_impl(&self, ids: &[RoleId]) -> SidResult<Vec<Role>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut roles = Vec::new();
        for chunk in ids.chunks(IN_LIST_CHUNK) {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT * FROM roles WHERE id IN ({})",
                placeholders(chunk.len())
            )));
            for id in chunk {
                query = query.bind(*id);
            }
            let rows = query
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("read roles: {e}")))?;
            for row in &rows {
                roles.push(row_to_role(row)?);
            }
        }
        Ok(roles)
    }

    pub(crate) async fn get_role_by_name_impl(
        &self,
        project_id: ProjectId,
        name: &str,
    ) -> SidResult<Option<Role>> {
        let row = sqlx::query("SELECT * FROM roles WHERE project_id = ? AND name = ?")
            .bind(project_id)
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
        .bind(role.id)
        .bind(role.project_id)
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
        Self::commit_mutation(tx, &format!("role:{}", role.id), audit).await
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
        Self::commit_mutation(tx, &format!("role:{}", role.id), audit).await?;
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
        let read = |e: sqlx::Error| SidError::Storage(format!("check role edit fence: {e}"));
        let mut tx = self.begin_write().await?;
        check_authority_in_tx(&mut tx, &fence.authority).await?;
        if let Some(bounded) = &fence.bounded {
            let present: Vec<(RoleAssignmentId,)> = sqlx::query_as(
                "SELECT DISTINCT a.id FROM role_assignments a
                 JOIN role_assignment_ceilings c ON c.assignment_id = a.id
                 WHERE a.role_id = ?",
            )
            .bind(role.id)
            .fetch_all(&mut *tx)
            .await
            .map_err(read)?;
            for (id,) in present {
                if !bounded.contains(&id) {
                    return Err(SidError::Fenced(
                        "an assignment under an approved ceiling appeared since the check".into(),
                    ));
                }
            }
        }
        if !update_role_in_tx(&mut tx, role).await? {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("role:{}", role.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn delete_role_impl(
        &self,
        id: RoleId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        if id == Role::installation_administrator().id
            && administrator_exists(&mut *tx, None).await?
        {
            return Err(crate::administrator_role_assigned());
        }
        sqlx::query("DELETE FROM roles WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("role:{id}"), audit).await
    }

    pub(crate) async fn list_roles_impl(&self, project_id: ProjectId) -> SidResult<Vec<Role>> {
        let rows = sqlx::query("SELECT * FROM roles WHERE project_id = ?")
            .bind(project_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_role).collect()
    }

    // === Group ===

    pub(crate) async fn get_group_impl(&self, id: GroupId) -> SidResult<Option<Group>> {
        let row = sqlx::query("SELECT * FROM groups WHERE id = ?")
            .bind(id)
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
        Self::commit_mutation(tx, &format!("group:{}", group.id), audit).await
    }

    pub(crate) async fn set_group_description_impl(
        &self,
        id: GroupId,
        description: Option<&str>,
        mut audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query("UPDATE groups SET description = ?, updated_at = ? WHERE id = ?")
            .bind(description)
            .bind(fmt_dt(&chrono::Utc::now()))
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("update group: {e}")))?
            .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        // The group as this write leaves it, read in its transaction.
        let group = sqlx::query("SELECT * FROM groups WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("read updated group: {e}")))?;
        audit.record_effect(&row_to_group(&group)?)?;
        Self::commit_mutation(tx, &format!("group:{id}"), audit).await?;
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
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        if restricting.is_some() {
            return Err(SidError::Conflict(
                "the group restricts the recipients of an administrative assignment".into(),
            ));
        }
        sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("group:{id}"), audit).await
    }

    pub(crate) async fn list_groups_impl(&self, project_id: ProjectId) -> SidResult<Vec<Group>> {
        let rows = sqlx::query("SELECT * FROM groups WHERE project_id = ?")
            .bind(project_id)
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
        Self::commit_mutation(tx, &format!("group:{}", member.group_id), audit).await
    }

    pub(crate) async fn remove_from_group_impl(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::remove_member(&mut tx, group_id, profile_id).await?;
        Self::commit_mutation(tx, &format!("group:{group_id}"), audit).await
    }

    pub(crate) async fn list_group_members_impl(
        &self,
        group_id: GroupId,
    ) -> SidResult<Vec<GroupMember>> {
        let rows = sqlx::query("SELECT * FROM group_members WHERE group_id = ?")
            .bind(group_id)
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
        Self::commit_mutation(tx, &format!("role_assignment:{}", assignment.id), audit).await
    }

    pub(crate) async fn import_role_assignment_impl(
        &self,
        assignment: &RoleAssignment,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        match insert_role_assignment_row(&mut tx, assignment).await {
            Ok(()) => {}
            // The id is taken: the same assignment imported before, or another.
            Err(SidError::Conflict(_)) => {
                drop(tx);
                let held = self.get_role_assignment_impl(assignment.id).await?;
                return match held {
                    Some(held) => crate::transfer_repeat(&held, assignment, "role assignment"),
                    None => Err(SidError::Conflict(
                        "the role assignment conflicts with a stored record".into(),
                    )),
                };
            }
            Err(e) => return Err(e),
        }
        Self::commit_mutation(tx, &format!("role_assignment:{}", assignment.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn get_role_assignment_impl(
        &self,
        id: RoleAssignmentId,
    ) -> SidResult<Option<RoleAssignment>> {
        let rows = sqlx::query("SELECT * FROM role_assignments WHERE id = ?")
            .bind(id)
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
        Self::commit_mutation(tx, &format!("role_assignment:{}", assignment.id), audit).await
    }

    pub(crate) async fn delete_role_assignment_fenced_impl(
        &self,
        id: RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        check_assignment_fence(&mut tx, fence).await?;
        keep_last_administrator(&mut tx, id).await?;
        let removed: Option<(Option<sid_core::models::ProvisioningConnectorId>,)> = sqlx::query_as(
            "DELETE FROM role_assignments WHERE id = ? RETURNING provisioning_connector_id",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some((connector,)) = removed else {
            return Ok(false);
        };
        if let Some(connector) = connector {
            super::provisioning_connector::bump_connector_revision(&mut tx, connector).await?;
        }
        Self::commit_mutation(tx, &format!("role_assignment:{id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn delete_role_assignment_impl(
        &self,
        id: RoleAssignmentId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        keep_last_administrator(&mut tx, id).await?;
        let removed: Option<(Option<sid_core::models::ProvisioningConnectorId>,)> = sqlx::query_as(
            "DELETE FROM role_assignments WHERE id = ? RETURNING provisioning_connector_id",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        if let Some((Some(connector),)) = removed {
            super::provisioning_connector::bump_connector_revision(&mut tx, connector).await?;
        }
        Self::commit_mutation(tx, &format!("role_assignment:{id}"), audit).await
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
            .bind(group_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        read_assignments(&self.pool, &rows).await
    }

    pub(crate) async fn list_role_assignments_held_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query(
            "SELECT * FROM role_assignments WHERE profile_id = ?1
             UNION ALL
             SELECT ra.* FROM role_assignments ra
             JOIN group_members gm ON gm.group_id = ra.group_id
             WHERE gm.profile_id = ?1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read held role assignments: {e}")))?;
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
            .bind(role_id)
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

    // === CedarPolicy ===

    pub(crate) async fn get_cedar_policy_impl(
        &self,
        id: CedarPolicyId,
    ) -> SidResult<Option<CedarPolicy>> {
        let row = sqlx::query("SELECT * FROM cedar_policies WHERE id = ?")
            .bind(id)
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
        .bind(policy.id)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update policy: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("cedar_policy:{}", policy.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn create_cedar_policy_impl(
        &self,
        policy: &CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO cedar_policies (id, project_id, resource_id, name, description, policy_text, effect, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(policy.id)
        .bind(policy.scope.project())
        .bind(policy.scope.resource())
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
        Self::commit_mutation(tx, &format!("cedar_policy:{}", policy.id), audit).await
    }

    pub(crate) async fn delete_cedar_policy_impl(
        &self,
        id: CedarPolicyId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM cedar_policies WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("cedar_policy:{id}"), audit).await
    }

    pub(crate) async fn list_cedar_policies_impl(
        &self,
        scope: sid_core::models::PolicyScope,
    ) -> SidResult<Vec<CedarPolicy>> {
        let rows =
            sqlx::query("SELECT * FROM cedar_policies WHERE project_id IS ? AND resource_id IS ?")
                .bind(scope.project())
                .bind(scope.resource())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_cedar_policy).collect()
    }
}
