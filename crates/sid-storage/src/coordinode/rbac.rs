// SPDX-License-Identifier: AGPL-3.0-only
//! Roles, groups and their members, role assignments with their
//! administrative envelopes, Cedar policies and access requests, in
//! CoordiNode.
//!
//! Every assignment created or removed writes its role's node, and every
//! membership change or assignment to a group writes the group's node.
//! What a decision reads about those (the installation's last
//! administrator, the assignments under an approved ceiling a role edit
//! must admit, a grantor's absence from the group it grants) therefore
//! conflicts with a concurrent change of it. What a fence names that still
//! exists (its basis assignment, a membership) is held for the commit.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::{
    AccessRequest, AccessRequestId, AccessRequestStatus, AdminEnvelope, AdminOperation,
    AssignmentFence, AssignmentProvenance, AuthorityBasis, CedarPolicy, CedarPolicyId, Group,
    GroupId, GroupMember, INSTALLATION_SCOPE, MachineUserId, MutationContext, PolicyAuthority,
    PolicyOperation, PolicyScope, ProfileId, ProjectId, ProvisioningConnectorId, RecipientKind,
    ResourceId, Role, RoleAssignment, RoleAssignmentId, RoleAssignmentPrincipal, RoleEditFence,
    RoleId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bool,
    get_bytes, get_int, get_opt_bytes, get_opt_int, get_opt_text, get_opt_time, get_parsed,
    get_text, get_texts, get_time, hold_first, key, opt_text, opt_time, texts, time,
};

const ROLE: &str = "r.id AS id, r.project_id AS project_id, r.role_key AS role_key,
    r.name AS name, r.description AS description, r.group_label AS group_label,
    r.permissions AS permissions, r.revision AS revision, r.created_at AS created_at,
    r.updated_at AS updated_at";

const GROUP: &str = "g.id AS id, g.project_id AS project_id, g.name AS name,
    g.description AS description, g.parent_group_id AS parent_group_id,
    g.created_at AS created_at, g.updated_at AS updated_at";

const MEMBER: &str = "m.group_id AS group_id, m.profile_id AS profile_id, m.added_at AS added_at";

const ASSIGNMENT: &str = "a.id AS id, a.profile_id AS profile_id, a.group_id AS group_id,
    a.machine_user_id AS machine_user_id, a.oauth_client_id AS oauth_client_id,
    a.connector_id AS connector_id, a.role_id AS role_id, a.scope AS scope,
    a.expires_at AS expires_at, a.created_at AS created_at, a.granted_by AS granted_by,
    a.basis_id AS basis_id, a.depends_on_id AS depends_on_id, a.ceiling AS ceiling,
    a.policy_operations AS policy_operations, a.administers AS administers,
    a.admin_operations AS admin_operations, a.admin_ceiling AS admin_ceiling,
    a.admin_recipient_kinds AS admin_recipient_kinds, a.admin_group AS admin_group,
    a.admin_validity AS admin_validity, a.revision AS revision";

const POLICY: &str = "c.id AS id, c.project_id AS project_id, c.resource_id AS resource_id,
    c.name AS name, c.description AS description, c.policy_text AS policy_text,
    c.effect AS effect, c.enabled AS enabled, c.revision AS revision,
    c.created_at AS created_at, c.updated_at AS updated_at";

const REQUEST: &str = "q.id AS id, q.requester_id AS requester_id, q.project_id AS project_id,
    q.role_key AS role_key, q.justification AS justification,
    q.requested_duration_hours AS requested_duration_hours, q.status AS status,
    q.reviewed_by AS reviewed_by, q.review_comment AS review_comment,
    q.created_at AS created_at, q.reviewed_at AS reviewed_at, q.expires_at AS expires_at";

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn opt_bin(bytes: Option<&[u8; 16]>) -> Value {
    bytes.map_or(Value::Null, bin)
}

/// The identifier `name` holds, decoded by `from`; a malformed one is a
/// storage error.
fn id<T>(row: &Row, name: &str, from: fn(&[u8]) -> Result<T, sid_ids::IdError>) -> SidResult<T> {
    from(&get_bytes(row, name)?).map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

fn opt_id<T>(
    row: &Row,
    name: &str,
    from: fn(&[u8]) -> Result<T, sid_ids::IdError>,
) -> SidResult<Option<T>> {
    get_opt_bytes(row, name)?
        .map(|b| from(&b).map_err(|e| SidError::Storage(format!("{name}: {e}"))))
        .transpose()
}

fn revision_of(row: &Row) -> SidResult<u64> {
    let value = get_int(row, "revision")?;
    u64::try_from(value).map_err(|_| SidError::Storage(format!("revision: {value}")))
}

fn revision(value: u64) -> SidResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| SidError::Validation(format!("revision {value} out of range")))
}

/// A set of names as a list, or none for an empty one.
fn name_list<'a>(names: impl Iterator<Item = &'a str>) -> Value {
    let names: Vec<Value> = names.map(|n| Value::String(n.to_owned())).collect();
    if names.is_empty() {
        Value::Null
    } else {
        Value::Array(names)
    }
}

fn opt_texts(row: &Row, name: &str) -> SidResult<Option<Vec<String>>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_texts(row, name).map(Some),
    }
}

/// Write the `turn` of the node of `label` whose `property` is `value`: a
/// concurrent change of it conflicts. False when there is no such node.
fn take_turn(tx: &Statements<'_>, label: &str, property: &str, value: Value) -> SidResult<bool> {
    let rows = tx.run(
        &format!(
            "MATCH (n:{label}) WHERE n.{property} = $value
             SET n.turn = coalesce(n.turn, 0) + 1 RETURN n.{property} AS id"
        ),
        Params::default().with("value", value),
    )?;
    Ok(!rows.is_empty())
}

/// Hold the node of `label` whose `property` is `value` for the commit;
/// false when there is none.
fn hold(tx: &Statements<'_>, label: &str, property: &str, value: Value) -> SidResult<bool> {
    let rows = tx.run(
        &format!("MATCH (n:{label}) WHERE n.{property} = $value RETURN id(n) AS node"),
        Params::default().with("value", value),
    )?;
    hold_first(tx, &rows)
}

/// Claim the node of `label` whose `property` is `value` for a record
/// created under it, which its deletion removes or detaches; false when
/// there is none.
fn claim(tx: &Statements<'_>, label: &str, property: &str, value: Value) -> SidResult<bool> {
    let rows = tx.run(
        &format!("MATCH (n:{label}) WHERE n.{property} = $value RETURN id(n) AS node"),
        Params::default().with("value", value),
    )?;
    claim_first(tx, &rows)
}

// === Roles ===

fn role(row: &Row) -> SidResult<Role> {
    Ok(Role {
        id: id(row, "id", RoleId::from_slice)?,
        project_id: id(row, "project_id", ProjectId::from_slice)?,
        key: get_text(row, "role_key")?,
        name: get_text(row, "name")?,
        description: get_opt_text(row, "description")?,
        group: get_opt_text(row, "group_label")?,
        permissions: get_texts(row, "permissions")?,
        revision: revision_of(row)?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

pub(super) fn get_role(tx: &Statements<'_>, role_id: RoleId) -> SidResult<Option<Role>> {
    let rows = tx.run(
        &format!("MATCH (r:SidRole) WHERE r.id = $id RETURN {ROLE}"),
        Params::default().with("id", bin(role_id.as_bytes())),
    )?;
    rows.first().map(role).transpose()
}

fn name_key(project: ProjectId, name: &str) -> SidResult<Value> {
    key(&[project.as_bytes(), name.as_bytes()])
}

/// Store a new role of a claimed project in `tx`; its id, or its key or name
/// in the project, already stored is `Conflict`.
fn insert_role(tx: &Statements<'_>, r: &Role) -> SidResult<()> {
    if !claim(tx, "SidProject", "id", bin(r.project_id.as_bytes()))? {
        return Err(SidError::NotFound(format!("project {}", r.project_id)));
    }
    if get_role(tx, r.id)?.is_some() {
        return Err(SidError::Conflict("role already exists".into()));
    }
    tx.run(
        "CREATE (r:SidRole {id: $id, project_id: $project_id, role_key: $role_key,
            project_key: $project_key, name: $name, project_name: $project_name,
            description: $description, group_label: $group_label, permissions: $permissions,
            revision: $revision, created_at: $created_at, updated_at: $updated_at})",
        Params::default()
            .with("id", bin(r.id.as_bytes()))
            .with("project_id", bin(r.project_id.as_bytes()))
            .with("role_key", Value::String(r.key.clone()))
            .with("project_key", name_key(r.project_id, &r.key)?)
            .with("name", Value::String(r.name.clone()))
            .with("project_name", name_key(r.project_id, &r.name)?)
            .with("description", opt_text(r.description.as_deref()))
            .with("group_label", opt_text(r.group.as_deref()))
            .with("permissions", texts(&r.permissions))
            .with("revision", revision(r.revision)?)
            .with("created_at", time(r.created_at))
            .with("updated_at", time(r.updated_at)),
    )?;
    Ok(())
}

/// Write `r`'s editable fields while the stored role is still at
/// `r.revision`, moving the revision on; false when it is not.
fn update_role(tx: &Statements<'_>, r: &Role) -> SidResult<bool> {
    let next = r
        .revision
        .checked_add(1)
        .ok_or_else(|| SidError::Validation("role revision exhausted".into()))?;
    let rows = tx.run(
        "MATCH (r:SidRole) WHERE r.id = $id AND r.revision = $revision
         SET r.name = $name, r.project_name = $project_name, r.description = $description,
             r.group_label = $group_label, r.permissions = $permissions,
             r.updated_at = $updated_at, r.revision = $next
         RETURN r.id AS id",
        Params::default()
            .with("id", bin(r.id.as_bytes()))
            .with("revision", revision(r.revision)?)
            .with("name", Value::String(r.name.clone()))
            .with("project_name", name_key(r.project_id, &r.name)?)
            .with("description", opt_text(r.description.as_deref()))
            .with("group_label", opt_text(r.group.as_deref()))
            .with("permissions", texts(&r.permissions))
            .with("updated_at", time(r.updated_at))
            .with("next", revision(next)?),
    )?;
    Ok(!rows.is_empty())
}

/// Delete role `role_id` in `tx` with its assignments; envelopes naming it
/// lose it, which only narrows them.
fn delete_role_records(tx: &Statements<'_>, role_id: RoleId) -> SidResult<()> {
    for assignment in assignments_where(tx, "a.role_id = $value", bin(role_id.as_bytes()))? {
        delete_assignment(tx, assignment.id)?;
    }
    for query in [
        "MATCH (e:SidAdminRole) WHERE e.role_id = $id DETACH DELETE e",
        "MATCH (r:SidRole) WHERE r.id = $id DETACH DELETE r",
    ] {
        tx.run(query, Params::default().with("id", bin(role_id.as_bytes())))?;
    }
    Ok(())
}

// === Groups ===

fn group(row: &Row) -> SidResult<Group> {
    Ok(Group {
        id: id(row, "id", GroupId::from_slice)?,
        project_id: id(row, "project_id", ProjectId::from_slice)?,
        name: get_text(row, "name")?,
        description: get_opt_text(row, "description")?,
        parent_group_id: opt_id(row, "parent_group_id", GroupId::from_slice)?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn get_group(tx: &Statements<'_>, group_id: GroupId) -> SidResult<Option<Group>> {
    let rows = tx.run(
        &format!("MATCH (g:SidGroup) WHERE g.id = $id RETURN {GROUP}"),
        Params::default().with("id", bin(group_id.as_bytes())),
    )?;
    rows.first().map(group).transpose()
}

/// Store a new group of a claimed project in `tx`, under a claimed parent
/// group, whose deletion detaches its subgroups; its id, or its name in the
/// project, already stored is `Conflict`.
pub(super) fn insert_group(tx: &Statements<'_>, g: &Group) -> SidResult<()> {
    if !claim(tx, "SidProject", "id", bin(g.project_id.as_bytes()))? {
        return Err(SidError::NotFound(format!("project {}", g.project_id)));
    }
    if let Some(parent) = g.parent_group_id
        && !claim(tx, "SidGroup", "id", bin(parent.as_bytes()))?
    {
        return Err(SidError::NotFound(format!("group {parent}")));
    }
    if get_group(tx, g.id)?.is_some() {
        return Err(SidError::Conflict("group already exists".into()));
    }
    tx.run(
        "CREATE (g:SidGroup {id: $id, project_id: $project_id, name: $name,
            project_name: $project_name, description: $description,
            parent_group_id: $parent_group_id, turn: 0, created_at: $created_at,
            updated_at: $updated_at})",
        Params::default()
            .with("id", bin(g.id.as_bytes()))
            .with("project_id", bin(g.project_id.as_bytes()))
            .with("name", Value::String(g.name.clone()))
            .with("project_name", name_key(g.project_id, &g.name)?)
            .with("description", opt_text(g.description.as_deref()))
            .with(
                "parent_group_id",
                opt_bin(g.parent_group_id.as_ref().map(|p| p.as_bytes())),
            )
            .with("created_at", time(g.created_at))
            .with("updated_at", time(g.updated_at)),
    )?;
    Ok(())
}

/// Write the name and description of the stored `g` in `tx`; false when it
/// does not exist. Another group of the project holding the name is
/// `Conflict`.
pub(super) fn update_group(tx: &Statements<'_>, g: &Group) -> SidResult<bool> {
    let Some(stored) = get_group(tx, g.id)? else {
        return Ok(false);
    };
    tx.run(
        "MATCH (g:SidGroup) WHERE g.id = $id
         SET g.name = $name, g.project_name = $project_name, g.description = $description,
             g.updated_at = $updated_at",
        Params::default()
            .with("id", bin(g.id.as_bytes()))
            .with("name", Value::String(g.name.clone()))
            .with("project_name", name_key(stored.project_id, &g.name)?)
            .with("description", opt_text(g.description.as_deref()))
            .with("updated_at", time(g.updated_at)),
    )?;
    Ok(true)
}

fn member(row: &Row) -> SidResult<GroupMember> {
    Ok(GroupMember {
        group_id: id(row, "group_id", GroupId::from_slice)?,
        profile_id: id(row, "profile_id", ProfileId::from_slice)?,
        added_at: get_time(row, "added_at")?,
    })
}

fn member_pair(group_id: GroupId, profile: ProfileId) -> SidResult<Value> {
    key(&[group_id.as_bytes(), profile.as_bytes()])
}

/// Add `m` to its group in `tx` (a repeat is no change). A Profile that
/// granted the group a role under an administrative assignment never joins
/// it: the grant would reach its own grantor.
pub(super) fn add_member(tx: &Statements<'_>, m: &GroupMember) -> SidResult<()> {
    let missing = || SidError::Validation("a group member is not an existing account".into());
    if !take_turn(tx, "SidGroup", "id", bin(m.group_id.as_bytes()))? {
        return Err(missing());
    }
    // The member is claimed: its deletion removes its memberships.
    if !claim(tx, "SidProfile", "id", bin(m.profile_id.as_bytes()))? {
        return Err(missing());
    }
    let granted = tx.run(
        "MATCH (a:SidRoleAssignment) WHERE a.group_id = $group AND a.granted_by = $grantor
           AND a.basis_id IS NOT NULL
         RETURN a.id AS id",
        Params::default()
            .with("group", bin(m.group_id.as_bytes()))
            .with("grantor", Value::String(format!("user:{}", m.profile_id))),
    )?;
    if !granted.is_empty() {
        return Err(SidError::PolicyViolation(format!(
            "profile {} granted this group a role; it cannot join the group",
            m.profile_id
        )));
    }
    let pair = member_pair(m.group_id, m.profile_id)?;
    let held = tx.run(
        "MATCH (m:SidGroupMember) WHERE m.pair = $pair RETURN m.pair AS pair",
        Params::default().with("pair", pair.clone()),
    )?;
    if held.is_empty() {
        tx.run(
            "CREATE (m:SidGroupMember {pair: $pair, group_id: $group, profile_id: $profile,
                added_at: $added_at})",
            Params::default()
                .with("pair", pair)
                .with("group", bin(m.group_id.as_bytes()))
                .with("profile", bin(m.profile_id.as_bytes()))
                .with("added_at", time(m.added_at)),
        )?;
    }
    Ok(())
}

/// Remove `profile` from `group_id` in `tx`.
pub(super) fn remove_member(
    tx: &Statements<'_>,
    group_id: GroupId,
    profile: ProfileId,
) -> SidResult<()> {
    take_turn(tx, "SidGroup", "id", bin(group_id.as_bytes()))?;
    tx.run(
        "MATCH (m:SidGroupMember) WHERE m.pair = $pair DETACH DELETE m",
        Params::default().with("pair", member_pair(group_id, profile)?),
    )?;
    Ok(())
}

/// The groups `profile` is a member of.
fn memberships(tx: &Statements<'_>, profile: ProfileId) -> SidResult<Vec<GroupMember>> {
    let rows = tx.run(
        &format!("MATCH (m:SidGroupMember) WHERE m.profile_id = $profile RETURN {MEMBER}"),
        Params::default().with("profile", bin(profile.as_bytes())),
    )?;
    rows.iter().map(member).collect()
}

/// Delete group `group_id` in `tx` with its members and assignments; its
/// subgroups become roots. A group an envelope restricts recipients to
/// stays: deleting it would widen the envelope.
fn delete_group_records(tx: &Statements<'_>, group_id: GroupId) -> SidResult<()> {
    let restricting = tx.run(
        "MATCH (a:SidRoleAssignment) WHERE a.admin_group = $id RETURN a.id AS id",
        Params::default().with("id", bin(group_id.as_bytes())),
    )?;
    if !restricting.is_empty() {
        return Err(SidError::Conflict(
            "the group restricts the recipients of an administrative assignment".into(),
        ));
    }
    for assignment in assignments_where(tx, "a.group_id = $value", bin(group_id.as_bytes()))? {
        delete_assignment(tx, assignment.id)?;
    }
    for query in [
        "MATCH (m:SidGroupMember) WHERE m.group_id = $id DETACH DELETE m",
        "MATCH (g:SidGroup) WHERE g.parent_group_id = $id SET g.parent_group_id = null",
        "MATCH (g:SidGroup) WHERE g.id = $id DETACH DELETE g",
    ] {
        tx.run(
            query,
            Params::default().with("id", bin(group_id.as_bytes())),
        )?;
    }
    Ok(())
}

// === Role assignments ===

fn principal(row: &Row) -> SidResult<RoleAssignmentPrincipal> {
    if let Some(p) = opt_id(row, "profile_id", ProfileId::from_slice)? {
        return Ok(RoleAssignmentPrincipal::Profile(p));
    }
    if let Some(g) = opt_id(row, "group_id", GroupId::from_slice)? {
        return Ok(RoleAssignmentPrincipal::Group(g));
    }
    if let Some(m) = opt_id(row, "machine_user_id", MachineUserId::from_slice)? {
        return Ok(RoleAssignmentPrincipal::MachineUser(m));
    }
    if let Some(client) = get_opt_text(row, "oauth_client_id")? {
        return Ok(RoleAssignmentPrincipal::OAuthClient(client));
    }
    if let Some(c) = opt_id(row, "connector_id", ProvisioningConnectorId::from_slice)? {
        return Ok(RoleAssignmentPrincipal::ProvisioningConnector(c));
    }
    Err(SidError::Storage(
        "role assignment without a principal".into(),
    ))
}

/// Every name of `name`'s list parsed by `parse`; an unknown one is an
/// error, never dropped: a dropped bound would widen what it limits.
fn parsed_set<T: Ord>(
    row: &Row,
    name: &str,
    parse: fn(&str) -> Option<T>,
) -> SidResult<std::collections::BTreeSet<T>> {
    opt_texts(row, name)?
        .unwrap_or_default()
        .iter()
        .map(|s| parse(s).ok_or_else(|| SidError::Storage(format!("{name}: unknown {s}"))))
        .collect()
}

/// The assignment `row` holds, its envelope's roles read in `tx`.
fn assignment(tx: &Statements<'_>, row: &Row) -> SidResult<RoleAssignment> {
    let assignment_id = id(row, "id", RoleAssignmentId::from_slice)?;
    let admin = if get_bool(row, "administers")? {
        let rows = tx.run(
            "MATCH (e:SidAdminRole) WHERE e.assignment_id = $id RETURN e.role_id AS role_id",
            Params::default().with("id", bin(assignment_id.as_bytes())),
        )?;
        Some(AdminEnvelope {
            operations: parsed_set(row, "admin_operations", AdminOperation::parse)?,
            roles: rows
                .iter()
                .map(|r| id(r, "role_id", RoleId::from_slice))
                .collect::<SidResult<_>>()?,
            permission_ceiling: opt_texts(row, "admin_ceiling")?
                .unwrap_or_default()
                .into_iter()
                .collect(),
            recipient_kinds: parsed_set(row, "admin_recipient_kinds", RecipientKind::parse)?,
            recipient_group: opt_id(row, "admin_group", GroupId::from_slice)?,
            max_validity_secs: get_int(row, "admin_validity")?,
        })
    } else {
        None
    };
    let policy_operations = parsed_set(row, "policy_operations", PolicyOperation::parse)?;
    Ok(RoleAssignment {
        id: assignment_id,
        principal: principal(row)?,
        role_id: id(row, "role_id", RoleId::from_slice)?,
        scope: get_opt_text(row, "scope")?,
        expires_at: get_opt_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
        admin,
        policy_admin: (!policy_operations.is_empty()).then_some(PolicyAuthority {
            operations: policy_operations,
        }),
        provenance: get_opt_text(row, "granted_by")?
            .map(|granted_by| {
                Ok::<_, SidError>(AssignmentProvenance {
                    granted_by,
                    basis: opt_id(row, "basis_id", RoleAssignmentId::from_slice)?,
                    depends_on: opt_id(row, "depends_on_id", RoleAssignmentId::from_slice)?,
                    ceiling: opt_texts(row, "ceiling")?.map(|c| c.into_iter().collect()),
                })
            })
            .transpose()?,
        revision: revision_of(row)?,
    })
}

fn get_assignment(
    tx: &Statements<'_>,
    assignment_id: RoleAssignmentId,
) -> SidResult<Option<RoleAssignment>> {
    let rows = tx.run(
        &format!("MATCH (a:SidRoleAssignment) WHERE a.id = $id RETURN {ASSIGNMENT}"),
        Params::default().with("id", bin(assignment_id.as_bytes())),
    )?;
    rows.first().map(|row| assignment(tx, row)).transpose()
}

/// The assignments `filter` (over `a`, with its `$value`) selects.
fn assignments_where(
    tx: &Statements<'_>,
    filter: &str,
    value: Value,
) -> SidResult<Vec<RoleAssignment>> {
    let rows = tx.run(
        &format!("MATCH (a:SidRoleAssignment) WHERE {filter} RETURN {ASSIGNMENT}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(|row| assignment(tx, row)).collect()
}

/// Write what removing or adding an assignment of `principal` to `role_id`
/// changes beside it: its role's turn, its group's, its connector's
/// revision. The role or principal may be gone already in a cascade.
fn touch_references(
    tx: &Statements<'_>,
    role_id: RoleId,
    principal: &RoleAssignmentPrincipal,
) -> SidResult<()> {
    take_turn(tx, "SidRole", "id", bin(role_id.as_bytes()))?;
    match principal {
        RoleAssignmentPrincipal::Group(g) => {
            take_turn(tx, "SidGroup", "id", bin(g.as_bytes()))?;
        }
        RoleAssignmentPrincipal::ProvisioningConnector(c) => {
            bump_connector(tx, *c)?;
        }
        RoleAssignmentPrincipal::Profile(_)
        | RoleAssignmentPrincipal::MachineUser(_)
        | RoleAssignmentPrincipal::OAuthClient(_) => {}
    }
    Ok(())
}

/// Move connector `c`'s revision on: its grants changed. False when there
/// is no such connector.
fn bump_connector(tx: &Statements<'_>, c: ProvisioningConnectorId) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (c:SidProvisioningConnector) WHERE c.id = $id
         SET c.revision = c.revision + 1 RETURN c.id AS id",
        Params::default().with("id", bin(c.as_bytes())),
    )?;
    Ok(!rows.is_empty())
}

/// Store `a` in `tx`. An existing id is `Conflict`; a missing role,
/// principal or referenced assignment is refused. What deletes or refuses
/// its deletion over the assignments it reads is claimed: the principal, the
/// assignment it depends on, the restricting group and the administered
/// roles. `created` names a Profile this transaction created itself, which
/// needs no claim.
pub(super) fn insert_assignment(
    tx: &Statements<'_>,
    a: &RoleAssignment,
    created: Option<ProfileId>,
) -> SidResult<()> {
    if get_assignment(tx, a.id)?.is_some() {
        return Err(SidError::Conflict("role assignment already exists".into()));
    }
    if !take_turn(tx, "SidRole", "id", bin(a.role_id.as_bytes()))? {
        return Err(SidError::NotFound(format!("role {}", a.role_id)));
    }
    let (mut profile, mut group_id, mut machine, mut client, mut connector) =
        (None, None, None, None, None);
    let present = match &a.principal {
        RoleAssignmentPrincipal::Profile(p) => {
            profile = Some(p);
            created == Some(*p) || claim(tx, "SidProfile", "id", bin(p.as_bytes()))?
        }
        RoleAssignmentPrincipal::Group(g) => {
            group_id = Some(g);
            take_turn(tx, "SidGroup", "id", bin(g.as_bytes()))?
        }
        // A machine user is referenced, not owned: its assignments outlive
        // nothing they need.
        RoleAssignmentPrincipal::MachineUser(m) => {
            machine = Some(m);
            true
        }
        RoleAssignmentPrincipal::OAuthClient(c) => {
            client = Some(c.as_str());
            claim(tx, "SidClient", "client_id", Value::String(c.clone()))?
        }
        RoleAssignmentPrincipal::ProvisioningConnector(c) => {
            connector = Some(c);
            bump_connector(tx, *c)?
        }
    };
    if !present {
        return Err(SidError::NotFound("the assignment's principal".into()));
    }
    let provenance = a.provenance.as_ref();
    if let Some(source) = provenance.and_then(|p| p.depends_on)
        && !claim(tx, "SidRoleAssignment", "id", bin(source.as_bytes()))?
    {
        return Err(SidError::NotFound(format!("role assignment {source}")));
    }
    // An empty ceiling would read back as no ceiling at all.
    if provenance
        .and_then(|p| p.ceiling.as_ref())
        .is_some_and(|c| c.is_empty())
    {
        return Err(SidError::Validation(
            "an approved ceiling names no permission".into(),
        ));
    }
    if let Some(envelope) = &a.admin {
        envelope
            .validate()
            .map_err(|e| SidError::Validation(e.to_string()))?;
        if let Some(restricted) = envelope.recipient_group
            && group_id != Some(&restricted)
            && !claim(tx, "SidGroup", "id", bin(restricted.as_bytes()))?
        {
            return Err(SidError::NotFound(format!("group {restricted}")));
        }
        for administered in &envelope.roles {
            if *administered != a.role_id
                && !claim(tx, "SidRole", "id", bin(administered.as_bytes()))?
            {
                return Err(SidError::NotFound(format!("role {administered}")));
            }
            tx.run(
                "CREATE (e:SidAdminRole {pair: $pair, assignment_id: $assignment,
                    role_id: $role})",
                Params::default()
                    .with("pair", key(&[a.id.as_bytes(), administered.as_bytes()])?)
                    .with("assignment", bin(a.id.as_bytes()))
                    .with("role", bin(administered.as_bytes())),
            )?;
        }
    }
    let envelope = a.admin.as_ref();
    tx.run(
        "CREATE (a:SidRoleAssignment {id: $id, profile_id: $profile_id, group_id: $group_id,
            machine_user_id: $machine_user_id, oauth_client_id: $oauth_client_id,
            connector_id: $connector_id, role_id: $role_id, scope: $scope,
            expires_at: $expires_at, created_at: $created_at, granted_by: $granted_by,
            basis_id: $basis_id, depends_on_id: $depends_on_id, ceiling: $ceiling,
            policy_operations: $policy_operations, administers: $administers,
            admin_operations: $admin_operations, admin_ceiling: $admin_ceiling,
            admin_recipient_kinds: $admin_recipient_kinds, admin_group: $admin_group,
            admin_validity: $admin_validity, revision: $revision})",
        Params::default()
            .with("id", bin(a.id.as_bytes()))
            .with("profile_id", opt_bin(profile.map(|p| p.as_bytes())))
            .with("group_id", opt_bin(group_id.map(|g| g.as_bytes())))
            .with("machine_user_id", opt_bin(machine.map(|m| m.as_bytes())))
            .with("oauth_client_id", opt_text(client))
            .with("connector_id", opt_bin(connector.map(|c| c.as_bytes())))
            .with("role_id", bin(a.role_id.as_bytes()))
            .with("scope", opt_text(a.scope.as_deref()))
            .with("expires_at", opt_time(a.expires_at))
            .with("created_at", time(a.created_at))
            .with(
                "granted_by",
                opt_text(provenance.map(|p| p.granted_by.as_str())),
            )
            .with(
                "basis_id",
                opt_bin(
                    provenance
                        .and_then(|p| p.basis.as_ref())
                        .map(|b| b.as_bytes()),
                ),
            )
            .with(
                "depends_on_id",
                opt_bin(
                    provenance
                        .and_then(|p| p.depends_on.as_ref())
                        .map(|d| d.as_bytes()),
                ),
            )
            .with(
                "ceiling",
                provenance
                    .and_then(|p| p.ceiling.as_ref())
                    .map_or(Value::Null, |c| name_list(c.iter().map(String::as_str))),
            )
            .with(
                "policy_operations",
                a.policy_admin.as_ref().map_or(Value::Null, |p| {
                    name_list(p.operations.iter().map(|o| o.as_str()))
                }),
            )
            .with("administers", Value::Bool(envelope.is_some()))
            .with(
                "admin_operations",
                envelope.map_or(Value::Null, |e| {
                    name_list(e.operations.iter().map(|o| o.as_str()))
                }),
            )
            .with(
                "admin_ceiling",
                envelope.map_or(Value::Null, |e| {
                    name_list(e.permission_ceiling.iter().map(String::as_str))
                }),
            )
            .with(
                "admin_recipient_kinds",
                envelope.map_or(Value::Null, |e| {
                    name_list(e.recipient_kinds.iter().map(|k| k.as_str()))
                }),
            )
            .with(
                "admin_group",
                opt_bin(
                    envelope
                        .and_then(|e| e.recipient_group.as_ref())
                        .map(|g| g.as_bytes()),
                ),
            )
            .with(
                "admin_validity",
                envelope.map_or(Value::Null, |e| Value::Int(e.max_validity_secs)),
            )
            .with("revision", revision(a.revision)?),
    )?;
    Ok(())
}

/// Delete assignment `assignment_id` in `tx` with every administrative
/// assignment redelegated from it, at any depth; the removed one when it
/// was stored.
fn delete_assignment(
    tx: &Statements<'_>,
    assignment_id: RoleAssignmentId,
) -> SidResult<Option<RoleAssignment>> {
    let Some(removed) = get_assignment(tx, assignment_id)? else {
        return Ok(None);
    };
    let mut pending = vec![removed.clone()];
    while let Some(next) = pending.pop() {
        pending.extend(assignments_where(
            tx,
            "a.depends_on_id = $value",
            bin(next.id.as_bytes()),
        )?);
        touch_references(tx, next.role_id, &next.principal)?;
        for query in [
            "MATCH (e:SidAdminRole) WHERE e.assignment_id = $id DETACH DELETE e",
            "MATCH (a:SidRoleAssignment) WHERE a.id = $id DETACH DELETE a",
        ] {
            tx.run(query, Params::default().with("id", bin(next.id.as_bytes())))?;
        }
    }
    Ok(Some(removed))
}

/// The live installation administrator assignments, held by `profile` when
/// one is given.
fn administrator_assignments(
    tx: &Statements<'_>,
    profile: Option<ProfileId>,
) -> SidResult<Vec<RoleAssignment>> {
    let now = Utc::now();
    Ok(assignments_where(
        tx,
        "a.role_id = $value",
        bin(Role::installation_administrator().id.as_bytes()),
    )?
    .into_iter()
    .filter(|a| a.scope.as_deref() == Some(INSTALLATION_SCOPE))
    .filter(|a| a.expires_at.is_none_or(|t| t > now))
    .filter(|a| match profile {
        Some(p) => a.principal == RoleAssignmentPrincipal::Profile(p),
        None => true,
    })
    .collect())
}

/// Whether a live installation administrator assignment exists, held by
/// `profile` when one is given.
pub(super) fn administrator_exists(
    tx: &Statements<'_>,
    profile: Option<ProfileId>,
) -> SidResult<bool> {
    Ok(!administrator_assignments(tx, profile)?.is_empty())
}

/// Make `profile` an installation administrator in `tx`: the built-in role
/// is stored if it is not, then assigned across the installation. `created`
/// as for [`insert_assignment`].
pub(super) fn grant_installation_administrator(
    tx: &Statements<'_>,
    profile: ProfileId,
    created: Option<ProfileId>,
) -> SidResult<()> {
    let administrator = Role::installation_administrator();
    if get_role(tx, administrator.id)?.is_none() {
        insert_role(tx, &administrator)?;
    }
    insert_assignment(
        tx,
        &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile), administrator.id)
            .on_installation(),
        created,
    )
}

/// Refuse removing assignment `assignment_id` when it is the installation's
/// last live administrator assignment held by an active or suspended
/// Profile. Removals write the role, and the holders' Profiles are held, so
/// what is counted stays as counted until the commit.
fn keep_last_administrator(tx: &Statements<'_>, assignment_id: RoleAssignmentId) -> SidResult<()> {
    let mut administrators = Vec::new();
    for a in administrator_assignments(tx, None)? {
        let RoleAssignmentPrincipal::Profile(holder) = a.principal else {
            continue;
        };
        let rows = tx.run(
            "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node, p.status AS status",
            Params::default().with("id", bin(holder.as_bytes())),
        )?;
        if hold_first(tx, &rows)? {
            administrators.push((a.id.into_uuid(), get_text(&rows[0], "status")?));
        }
    }
    crate::check_other_administrator_assignment(assignment_id, &administrators)
}

/// The Profiles holding a live installation administrator assignment, with
/// their stored status. The administrator role's turn and each Profile are
/// held by the caller's commit, so an assignment removed or an
/// administrator's status changed meanwhile conflicts with it.
pub(super) fn held_administrators(tx: &Statements<'_>) -> SidResult<Vec<(ProfileId, String)>> {
    take_turn(
        tx,
        "SidRole",
        "id",
        bin(Role::installation_administrator().id.as_bytes()),
    )?;
    let mut held = Vec::new();
    for a in administrator_assignments(tx, None)? {
        let RoleAssignmentPrincipal::Profile(holder) = a.principal else {
            continue;
        };
        let rows = tx.run(
            "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node, p.status AS status",
            Params::default().with("id", bin(holder.as_bytes())),
        )?;
        if hold_first(tx, &rows)? {
            held.push((holder, get_text(&rows[0], "status")?));
        }
    }
    Ok(held)
}

/// Check in `tx` that `basis` still holds: its assignment unexpired at the
/// checked revision and, when it reached the actor through a group, the
/// actor still a member. Both are held for the commit.
pub(super) fn check_authority(tx: &Statements<'_>, basis: &AuthorityBasis) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (a:SidRoleAssignment) WHERE a.id = $id
         RETURN id(a) AS node, a.revision AS revision, a.expires_at AS expires_at",
        Params::default().with("id", bin(basis.assignment.as_bytes())),
    )?;
    let current = match rows.first() {
        Some(row) => {
            let live = get_opt_time(row, "expires_at")?.is_none_or(|t| t > Utc::now());
            live && revision_of(row)? == basis.revision && hold_first(tx, &rows)?
        }
        None => false,
    };
    if !current {
        return Err(SidError::Fenced(
            "the authorizing assignment changed since it was checked".into(),
        ));
    }
    if let Some((group_id, actor)) = basis.member
        && !hold(tx, "SidGroupMember", "pair", member_pair(group_id, actor)?)?
    {
        return Err(SidError::Fenced(
            "the actor left the group holding its authority".into(),
        ));
    }
    Ok(())
}

/// Check in `tx` that `fence` still holds. The role and the recipient group
/// are written by the change the fence guards, so a concurrent change of
/// either conflicts with it.
fn check_assignment_fence(tx: &Statements<'_>, fence: &AssignmentFence) -> SidResult<()> {
    check_authority(tx, &fence.basis)?;
    let (role_id, checked) = &fence.role;
    let same = get_role(tx, *role_id)?.is_some_and(|r| {
        r.permissions
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            == *checked
    });
    if !same {
        return Err(SidError::Fenced(
            "the role's permissions changed since it was checked".into(),
        ));
    }
    if let Some((group_id, recipient)) = fence.recipient_membership
        && !hold(
            tx,
            "SidGroupMember",
            "pair",
            member_pair(group_id, recipient)?,
        )?
    {
        return Err(SidError::Fenced(
            "the recipient left the eligible group since it was checked".into(),
        ));
    }
    if let Some((group_id, grantor)) = fence.grantor_outside {
        // The group's turn: a member joining meanwhile conflicts.
        take_turn(tx, "SidGroup", "id", bin(group_id.as_bytes()))?;
        let inside = tx.run(
            "MATCH (m:SidGroupMember) WHERE m.pair = $pair RETURN m.pair AS pair",
            Params::default().with("pair", member_pair(group_id, grantor)?),
        )?;
        if !inside.is_empty() {
            return Err(SidError::Fenced(
                "the grantor joined the recipient group since it was checked".into(),
            ));
        }
    }
    Ok(())
}

// === Cascades ===

/// Delete in `tx` what `profile` holds here: its memberships, assignments
/// and access requests.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for m in memberships(tx, profile)? {
        remove_member(tx, m.group_id, profile)?;
    }
    for a in assignments_where(tx, "a.profile_id = $value", bin(profile.as_bytes()))? {
        delete_assignment(tx, a.id)?;
    }
    tx.run(
        "MATCH (q:SidAccessRequest) WHERE q.requester_id = $id DETACH DELETE q",
        Params::default().with("id", bin(profile.as_bytes())),
    )?;
    Ok(())
}

/// Delete in `tx` the roles, groups, policies and access requests of
/// `project`.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    let of_project = |label: &str, alias: &str| -> SidResult<Vec<Row>> {
        tx.run(
            &format!(
                "MATCH ({alias}:{label}) WHERE {alias}.project_id = $id RETURN {alias}.id AS id"
            ),
            Params::default().with("id", bin(project.as_bytes())),
        )
    };
    for row in of_project("SidGroup", "g")? {
        delete_group_records(tx, id(&row, "id", GroupId::from_slice)?)?;
    }
    for row in of_project("SidRole", "r")? {
        delete_role_records(tx, id(&row, "id", RoleId::from_slice)?)?;
    }
    for query in [
        "MATCH (c:SidCedarPolicy) WHERE c.project_id = $id DETACH DELETE c",
        "MATCH (q:SidAccessRequest) WHERE q.project_id = $id DETACH DELETE q",
    ] {
        tx.run(query, Params::default().with("id", bin(project.as_bytes())))?;
    }
    Ok(())
}

/// Delete in `tx` the assignments OAuth client `client_id` holds.
pub(super) fn delete_client_records(tx: &Statements<'_>, client_id: &str) -> SidResult<()> {
    for a in assignments_where(
        tx,
        "a.oauth_client_id = $value",
        Value::String(client_id.to_owned()),
    )? {
        delete_assignment(tx, a.id)?;
    }
    Ok(())
}

// === Cedar policies ===

fn policy(row: &Row) -> SidResult<CedarPolicy> {
    let scope = PolicyScope::from_columns(
        opt_id(row, "project_id", ProjectId::from_slice)?,
        opt_id(row, "resource_id", ResourceId::from_slice)?,
    )
    .map_err(SidError::Storage)?;
    Ok(CedarPolicy {
        id: id(row, "id", CedarPolicyId::from_slice)?,
        scope,
        name: get_text(row, "name")?,
        description: get_opt_text(row, "description")?,
        policy_text: get_text(row, "policy_text")?,
        effect: get_parsed(row, "effect")?,
        enabled: get_bool(row, "enabled")?,
        revision: revision_of(row)?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// The scope's kind, the part of a policy's identity beside its name.
fn scope_kind(scope: PolicyScope) -> &'static str {
    match scope {
        PolicyScope::Installation => "installation",
        PolicyScope::Project(_) => "project",
        PolicyScope::Resource(_) => "resource",
    }
}

fn scope_value(scope: PolicyScope) -> Option<[u8; 16]> {
    match scope {
        PolicyScope::Installation => None,
        PolicyScope::Project(p) => Some(*p.as_bytes()),
        PolicyScope::Resource(r) => Some(*r.as_bytes()),
    }
}

fn get_policy(tx: &Statements<'_>, policy_id: CedarPolicyId) -> SidResult<Option<CedarPolicy>> {
    let rows = tx.run(
        &format!("MATCH (c:SidCedarPolicy) WHERE c.id = $id RETURN {POLICY}"),
        Params::default().with("id", bin(policy_id.as_bytes())),
    )?;
    rows.first().map(policy).transpose()
}

// === Access requests ===

fn request(row: &Row) -> SidResult<AccessRequest> {
    let status = get_text(row, "status")?;
    Ok(AccessRequest {
        id: id(row, "id", AccessRequestId::from_slice)?,
        requester_id: id(row, "requester_id", ProfileId::from_slice)?,
        project_id: id(row, "project_id", ProjectId::from_slice)?,
        role_key: get_text(row, "role_key")?,
        justification: get_opt_text(row, "justification")?,
        requested_duration_hours: get_opt_int(row, "requested_duration_hours")?
            .map(u32::try_from)
            .transpose()
            .map_err(|e| SidError::Storage(format!("requested_duration_hours: {e}")))?,
        status: AccessRequestStatus::from_str_loose(&status)
            .ok_or_else(|| SidError::Storage(format!("unknown access request status: {status}")))?,
        reviewed_by: opt_id(row, "reviewed_by", ProfileId::from_slice)?,
        review_comment: get_opt_text(row, "review_comment")?,
        created_at: get_time(row, "created_at")?,
        reviewed_at: get_opt_time(row, "reviewed_at")?,
        expires_at: get_opt_time(row, "expires_at")?,
    })
}

/// Record `request`'s decision on a request still pending; false, writing
/// nothing, when it was already decided.
fn decide(tx: &Statements<'_>, request: &AccessRequest) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (q:SidAccessRequest) WHERE q.id = $id AND q.status = 'pending'
         SET q.status = $status, q.reviewed_by = $reviewed_by,
             q.review_comment = $review_comment, q.reviewed_at = $reviewed_at
         RETURN q.id AS id",
        Params::default()
            .with("id", bin(request.id.as_bytes()))
            .with("status", Value::String(request.status.as_str().into()))
            .with(
                "reviewed_by",
                opt_bin(request.reviewed_by.as_ref().map(|p| p.as_bytes())),
            )
            .with(
                "review_comment",
                opt_text(request.review_comment.as_deref()),
            )
            .with("reviewed_at", opt_time(request.reviewed_at)),
    )?;
    Ok(!rows.is_empty())
}

impl CoordinodeBackend {
    // === Roles ===

    pub(super) async fn get_role(&self, role_id: RoleId) -> SidResult<Option<Role>> {
        self.read(move |tx| get_role(tx, role_id)).await
    }

    pub(super) async fn get_roles(&self, ids: &[RoleId]) -> SidResult<Vec<Role>> {
        let ids = ids.to_vec();
        self.read(move |tx| {
            let mut found = Vec::with_capacity(ids.len());
            for role_id in &ids {
                found.extend(get_role(tx, *role_id)?);
            }
            Ok(found)
        })
        .await
    }

    pub(super) async fn get_role_by_name(
        &self,
        project: ProjectId,
        name: &str,
    ) -> SidResult<Option<Role>> {
        let name = name.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidRole) WHERE r.project_name = $key RETURN {ROLE}"),
                Params::default().with("key", name_key(project, &name)?),
            )?;
            rows.first().map(role).transpose()
        })
        .await
    }

    pub(super) async fn create_role(&self, r: &Role, ctx: MutationContext) -> SidResult<()> {
        let r = r.clone();
        self.mutate(format!("role:{}", r.id), ctx, move |tx| insert_role(tx, &r))
            .await
    }

    pub(super) async fn update_role(&self, r: &Role, ctx: MutationContext) -> SidResult<bool> {
        let r = r.clone();
        self.transaction(move |tx| {
            if !update_role(tx, &r)? {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("role:{}", r.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn update_role_fenced(
        &self,
        r: &Role,
        fence: &RoleEditFence,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (r, fence) = (r.clone(), fence.clone());
        self.transaction(move |tx| {
            check_authority(tx, &fence.authority)?;
            if let Some(bounded) = &fence.bounded {
                // Assignments of the role write it: one created meanwhile
                // conflicts with this edit, which writes it too.
                let under_ceiling =
                    assignments_where(tx, "a.role_id = $value", bin(r.id.as_bytes()))?
                        .into_iter()
                        .filter(|a| a.provenance.as_ref().is_some_and(|p| p.ceiling.is_some()));
                for a in under_ceiling {
                    if !bounded.contains(&a.id) {
                        return Err(SidError::Fenced(
                            "an assignment under an approved ceiling appeared since the check"
                                .into(),
                        ));
                    }
                }
            }
            if !update_role(tx, &r)? {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("role:{}", r.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_role(&self, role_id: RoleId, ctx: MutationContext) -> SidResult<()> {
        self.mutate(format!("role:{role_id}"), ctx, move |tx| {
            if role_id == Role::installation_administrator().id && administrator_exists(tx, None)? {
                return Err(crate::administrator_role_assigned());
            }
            delete_role_records(tx, role_id)
        })
        .await
    }

    pub(super) async fn list_roles(&self, project: ProjectId) -> SidResult<Vec<Role>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidRole) WHERE r.project_id = $id RETURN {ROLE}"),
                Params::default().with("id", bin(project.as_bytes())),
            )?;
            rows.iter().map(role).collect()
        })
        .await
    }

    // === Groups ===

    pub(super) async fn get_group(&self, group_id: GroupId) -> SidResult<Option<Group>> {
        self.read(move |tx| get_group(tx, group_id)).await
    }

    pub(super) async fn create_group(&self, g: &Group, ctx: MutationContext) -> SidResult<()> {
        let g = g.clone();
        self.mutate(format!("group:{}", g.id), ctx, move |tx| {
            insert_group(tx, &g)
        })
        .await
    }

    pub(super) async fn set_group_description(
        &self,
        group_id: GroupId,
        description: Option<&str>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let description = description.map(str::to_owned);
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (g:SidGroup) WHERE g.id = $id
                     SET g.description = $description, g.updated_at = $now
                     RETURN {GROUP}"
                ),
                Params::default()
                    .with("id", bin(group_id.as_bytes()))
                    .with("description", opt_text(description.as_deref()))
                    .with("now", time(Utc::now())),
            )?;
            let Some(row) = rows.first() else {
                return Ok(Decision::Abandon(false));
            };
            let mut ctx = ctx.clone();
            ctx.record_effect(&group(row)?)?;
            finalize(tx, &format!("group:{group_id}"), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_group(
        &self,
        group_id: GroupId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("group:{group_id}"), ctx, move |tx| {
            delete_group_records(tx, group_id)
        })
        .await
    }

    pub(super) async fn list_groups(&self, project: ProjectId) -> SidResult<Vec<Group>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (g:SidGroup) WHERE g.project_id = $id RETURN {GROUP}"),
                Params::default().with("id", bin(project.as_bytes())),
            )?;
            rows.iter().map(group).collect()
        })
        .await
    }

    pub(super) async fn add_to_group(
        &self,
        m: &GroupMember,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let m = m.clone();
        self.mutate(format!("group:{}", m.group_id), ctx, move |tx| {
            add_member(tx, &m)
        })
        .await
    }

    pub(super) async fn remove_from_group(
        &self,
        group_id: GroupId,
        profile: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("group:{group_id}"), ctx, move |tx| {
            remove_member(tx, group_id, profile)
        })
        .await
    }

    pub(super) async fn list_group_members(
        &self,
        group_id: GroupId,
    ) -> SidResult<Vec<GroupMember>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (m:SidGroupMember) WHERE m.group_id = $id RETURN {MEMBER}"),
                Params::default().with("id", bin(group_id.as_bytes())),
            )?;
            rows.iter().map(member).collect()
        })
        .await
    }

    pub(super) async fn list_groups_for_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<Group>> {
        self.read(move |tx| {
            let mut groups = Vec::new();
            for m in memberships(tx, profile)? {
                groups.extend(get_group(tx, m.group_id)?);
            }
            Ok(groups)
        })
        .await
    }

    // === Role assignments ===

    pub(super) async fn create_role_assignment(
        &self,
        a: &RoleAssignment,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let a = a.clone();
        self.mutate(format!("role_assignment:{}", a.id), ctx, move |tx| {
            insert_assignment(tx, &a, None)
        })
        .await
    }

    pub(super) async fn create_role_assignment_fenced(
        &self,
        a: &RoleAssignment,
        fence: &AssignmentFence,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let (a, fence) = (a.clone(), fence.clone());
        self.mutate(format!("role_assignment:{}", a.id), ctx, move |tx| {
            check_assignment_fence(tx, &fence)?;
            insert_assignment(tx, &a, None)
        })
        .await
    }

    pub(super) async fn get_role_assignment(
        &self,
        assignment_id: RoleAssignmentId,
    ) -> SidResult<Option<RoleAssignment>> {
        self.read(move |tx| get_assignment(tx, assignment_id)).await
    }

    pub(super) async fn delete_role_assignment(
        &self,
        assignment_id: RoleAssignmentId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("role_assignment:{assignment_id}"), ctx, move |tx| {
            keep_last_administrator(tx, assignment_id)?;
            delete_assignment(tx, assignment_id).map(|_| ())
        })
        .await
    }

    pub(super) async fn delete_role_assignment_fenced(
        &self,
        assignment_id: RoleAssignmentId,
        fence: &AssignmentFence,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let fence = fence.clone();
        self.transaction(move |tx| {
            check_assignment_fence(tx, &fence)?;
            keep_last_administrator(tx, assignment_id)?;
            if delete_assignment(tx, assignment_id)?.is_none() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("role_assignment:{assignment_id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    /// The assignments `filter` selects with `value`.
    async fn list_assignments(
        &self,
        filter: &'static str,
        value: Value,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.read(move |tx| assignments_where(tx, filter, value.clone()))
            .await
    }

    pub(super) async fn list_role_assignments_for_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.list_assignments("a.profile_id = $value", bin(profile.as_bytes()))
            .await
    }

    pub(super) async fn list_role_assignments_for_group(
        &self,
        group_id: GroupId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.list_assignments("a.group_id = $value", bin(group_id.as_bytes()))
            .await
    }

    pub(super) async fn list_role_assignments_held_by_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.read(move |tx| {
            let mut held = assignments_where(tx, "a.profile_id = $value", bin(profile.as_bytes()))?;
            for m in memberships(tx, profile)? {
                held.extend(assignments_where(
                    tx,
                    "a.group_id = $value",
                    bin(m.group_id.as_bytes()),
                )?);
            }
            Ok(held)
        })
        .await
    }

    pub(super) async fn list_role_assignments_for_machine_user(
        &self,
        machine: MachineUserId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.list_assignments("a.machine_user_id = $value", bin(machine.as_bytes()))
            .await
    }

    pub(super) async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.list_assignments(
            "a.oauth_client_id = $value",
            Value::String(client_id.to_owned()),
        )
        .await
    }

    pub(super) async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector: ProvisioningConnectorId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.list_assignments("a.connector_id = $value", bin(connector.as_bytes()))
            .await
    }

    pub(super) async fn list_role_assignments_for_role(
        &self,
        role_id: RoleId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.list_assignments("a.role_id = $value", bin(role_id.as_bytes()))
            .await
    }

    pub(super) async fn list_expiring_role_assignments(
        &self,
        within_hours: i64,
    ) -> SidResult<Vec<RoleAssignment>> {
        let cutoff = Utc::now()
            .checked_add_signed(chrono::Duration::hours(within_hours))
            .ok_or_else(|| SidError::Validation(format!("window {within_hours}h out of range")))?;
        self.list_assignments(
            "a.expires_at IS NOT NULL AND a.expires_at <= $value",
            time(cutoff),
        )
        .await
    }

    pub(super) async fn cleanup_expired_role_assignments(
        &self,
        ctx: MutationContext,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.transaction(move |tx| {
            let expired = assignments_where(
                tx,
                "a.expires_at IS NOT NULL AND a.expires_at < $value",
                time(Utc::now()),
            )?;
            for a in &expired {
                delete_assignment(tx, a.id)?;
            }
            let mut ctx = ctx.clone();
            ctx.work
                .extend(expired.iter().map(|a| a.expired_event().relay()));
            if expired.is_empty() && ctx.work.is_empty() && ctx.operation.is_none() {
                return Ok(Decision::Abandon(expired));
            }
            finalize(tx, "role_assignments:cleanup", ctx)?;
            Ok(Decision::Commit(expired))
        })
        .await
    }

    pub(super) async fn admin_exists(&self) -> SidResult<bool> {
        self.read(|tx| administrator_exists(tx, None)).await
    }

    // === Cedar policies ===

    pub(super) async fn get_cedar_policy(
        &self,
        policy_id: CedarPolicyId,
    ) -> SidResult<Option<CedarPolicy>> {
        self.read(move |tx| get_policy(tx, policy_id)).await
    }

    pub(super) async fn create_cedar_policy(
        &self,
        p: &CedarPolicy,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let p = p.clone();
        self.mutate(format!("cedar_policy:{}", p.id), ctx, move |tx| {
            // A project deletes its policies, so it is claimed; a resource is
            // retired with its policies kept, so it is only held.
            let held = match p.scope {
                PolicyScope::Installation => true,
                PolicyScope::Project(project) => {
                    claim(tx, "SidProject", "id", bin(project.as_bytes()))?
                }
                PolicyScope::Resource(resource) => {
                    hold(tx, "SidResource", "id", bin(resource.as_bytes()))?
                }
            };
            if !held {
                return Err(SidError::NotFound(format!("policy scope {:?}", p.scope)));
            }
            if get_policy(tx, p.id)?.is_some() {
                return Err(SidError::Conflict("policy already exists".into()));
            }
            let scope = scope_value(p.scope);
            tx.run(
                "CREATE (c:SidCedarPolicy {id: $id, scope_kind: $scope_kind,
                    project_id: $project_id, resource_id: $resource_id, scope_name: $scope_name,
                    name: $name, description: $description, policy_text: $policy_text,
                    effect: $effect, enabled: $enabled, revision: $revision,
                    created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", bin(p.id.as_bytes()))
                    .with("scope_kind", Value::String(scope_kind(p.scope).into()))
                    .with(
                        "project_id",
                        opt_bin(p.scope.project().as_ref().map(|j| j.as_bytes())),
                    )
                    .with(
                        "resource_id",
                        opt_bin(p.scope.resource().as_ref().map(|r| r.as_bytes())),
                    )
                    .with(
                        "scope_name",
                        key(&[
                            scope_kind(p.scope).as_bytes(),
                            scope.as_ref().map_or(&[][..], |s| &s[..]),
                            p.name.as_bytes(),
                        ])?,
                    )
                    .with("name", Value::String(p.name.clone()))
                    .with("description", opt_text(p.description.as_deref()))
                    .with("policy_text", Value::String(p.policy_text.clone()))
                    .with("effect", Value::String(p.effect.as_str().into()))
                    .with("enabled", Value::Bool(p.enabled))
                    .with("revision", revision(p.revision)?)
                    .with("created_at", time(p.created_at))
                    .with("updated_at", time(p.updated_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn update_cedar_policy(
        &self,
        p: &CedarPolicy,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let p = p.clone();
        self.transaction(move |tx| {
            let next = p
                .revision
                .checked_add(1)
                .ok_or_else(|| SidError::Validation("policy revision exhausted".into()))?;
            let rows = tx.run(
                "MATCH (c:SidCedarPolicy) WHERE c.id = $id AND c.revision = $revision
                 SET c.description = $description, c.policy_text = $policy_text,
                     c.effect = $effect, c.enabled = $enabled, c.updated_at = $updated_at,
                     c.revision = $next
                 RETURN c.id AS id",
                Params::default()
                    .with("id", bin(p.id.as_bytes()))
                    .with("revision", revision(p.revision)?)
                    .with("description", opt_text(p.description.as_deref()))
                    .with("policy_text", Value::String(p.policy_text.clone()))
                    .with("effect", Value::String(p.effect.as_str().into()))
                    .with("enabled", Value::Bool(p.enabled))
                    .with("updated_at", time(p.updated_at))
                    .with("next", revision(next)?),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("cedar_policy:{}", p.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_cedar_policy(
        &self,
        policy_id: CedarPolicyId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("cedar_policy:{policy_id}"), ctx, move |tx| {
            tx.run(
                "MATCH (c:SidCedarPolicy) WHERE c.id = $id DETACH DELETE c",
                Params::default().with("id", bin(policy_id.as_bytes())),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn list_cedar_policies(
        &self,
        scope: PolicyScope,
    ) -> SidResult<Vec<CedarPolicy>> {
        self.read(move |tx| {
            let rows = match scope {
                PolicyScope::Installation => tx.run(
                    &format!(
                        "MATCH (c:SidCedarPolicy) WHERE c.scope_kind = 'installation' RETURN {POLICY}"
                    ),
                    Params::default(),
                )?,
                PolicyScope::Project(project) => tx.run(
                    &format!("MATCH (c:SidCedarPolicy) WHERE c.project_id = $id RETURN {POLICY}"),
                    Params::default().with("id", bin(project.as_bytes())),
                )?,
                PolicyScope::Resource(resource) => tx.run(
                    &format!("MATCH (c:SidCedarPolicy) WHERE c.resource_id = $id RETURN {POLICY}"),
                    Params::default().with("id", bin(resource.as_bytes())),
                )?,
            };
            rows.iter().map(policy).collect()
        })
        .await
    }

    // === Access requests ===

    pub(super) async fn create_access_request(
        &self,
        q: &AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let q = q.clone();
        self.mutate(format!("access_request:{}", q.id), ctx, move |tx| {
            // Both delete the requests they read.
            if !claim(tx, "SidProfile", "id", bin(q.requester_id.as_bytes()))? {
                return Err(SidError::NotFound(format!("profile {}", q.requester_id)));
            }
            if !claim(tx, "SidProject", "id", bin(q.project_id.as_bytes()))? {
                return Err(SidError::NotFound(format!("project {}", q.project_id)));
            }
            let found = tx.run(
                "MATCH (q:SidAccessRequest) WHERE q.id = $id RETURN q.id AS id",
                Params::default().with("id", bin(q.id.as_bytes())),
            )?;
            if !found.is_empty() {
                return Err(SidError::Conflict("access request already exists".into()));
            }
            tx.run(
                "CREATE (q:SidAccessRequest {id: $id, requester_id: $requester_id,
                    project_id: $project_id, role_key: $role_key, justification: $justification,
                    requested_duration_hours: $hours, status: $status, reviewed_by: $reviewed_by,
                    review_comment: $review_comment, created_at: $created_at,
                    reviewed_at: $reviewed_at, expires_at: $expires_at})",
                Params::default()
                    .with("id", bin(q.id.as_bytes()))
                    .with("requester_id", bin(q.requester_id.as_bytes()))
                    .with("project_id", bin(q.project_id.as_bytes()))
                    .with("role_key", Value::String(q.role_key.clone()))
                    .with("justification", opt_text(q.justification.as_deref()))
                    .with(
                        "hours",
                        q.requested_duration_hours
                            .map_or(Value::Null, |h| Value::Int(i64::from(h))),
                    )
                    .with("status", Value::String(q.status.as_str().into()))
                    .with(
                        "reviewed_by",
                        opt_bin(q.reviewed_by.as_ref().map(|p| p.as_bytes())),
                    )
                    .with("review_comment", opt_text(q.review_comment.as_deref()))
                    .with("created_at", time(q.created_at))
                    .with("reviewed_at", opt_time(q.reviewed_at))
                    .with("expires_at", opt_time(q.expires_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_access_request(
        &self,
        request_id: AccessRequestId,
    ) -> SidResult<Option<AccessRequest>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (q:SidAccessRequest) WHERE q.id = $id RETURN {REQUEST}"),
                Params::default().with("id", bin(request_id.as_bytes())),
            )?;
            rows.first().map(request).transpose()
        })
        .await
    }

    pub(super) async fn list_pending_access_requests(&self) -> SidResult<Vec<AccessRequest>> {
        self.read(|tx| {
            let rows = tx.run(
                &format!("MATCH (q:SidAccessRequest) WHERE q.status = 'pending' RETURN {REQUEST}"),
                Params::default(),
            )?;
            // The expiry is applied here: CoordiNode drops a row whose OR
            // branch compares a missing property (coordinode#83).
            let now = Utc::now();
            let pending = rows
                .iter()
                .map(request)
                .collect::<SidResult<Vec<_>>>()?
                .into_iter()
                .filter(|q| q.expires_at.is_none_or(|t| t > now))
                .collect();
            // Oldest first.
            Ok(super::sorted_page(
                pending,
                |q| (q.created_at, q.id),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    pub(super) async fn decide_access_request(
        &self,
        q: &AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        q.check_plain_decision()?;
        let q = q.clone();
        self.transaction(move |tx| {
            // Already decided: nothing written, nothing audited.
            if !decide(tx, &q)? {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("access_request:{}", q.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn approve_access_request(
        &self,
        q: &AccessRequest,
        grant: &RoleAssignment,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        q.check_approval(grant)?;
        let (q, grant) = (q.clone(), grant.clone());
        self.transaction(move |tx| {
            if !decide(tx, &q)? {
                return Ok(Decision::Abandon(false));
            }
            // A grant that cannot be stored drops the approval with it.
            insert_assignment(tx, &grant, None)?;
            finalize(tx, &format!("access_request:{}", q.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}
