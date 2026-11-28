// SPDX-License-Identifier: AGPL-3.0-only
//! Account, contact, principal and group writes inside a caller's write
//! transaction, and the directory (SCIM) writes built from them: one
//! request's changes commit together with its audit entry and owed work.

use sid_core::models::{
    DirectoryGroupWrite, DirectoryResource, DirectorySource, DirectoryUserId, DirectoryUserWrite,
    DirectoryWriteMode, Group, GroupId, GroupMember, MutationContext, Principal, PrincipalId,
    PrincipalType, Profile, ProfileEmail, ProfileEmailId, ProfileId, ProfileMetadata, ProfilePhone,
    ProfilePhoneId, ProvisioningConnectorId, Session, SessionEnd, SourceWrite,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::session::row_to_session;
use super::{SqliteBackend, WriteTx, fmt_dt, fmt_dt_opt, insert_error};

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

macro_rules! profile_insert {
    ($tail:literal) => {
        concat!(
            "INSERT INTO profiles (id, username, given_name, family_name, middle_name, honorific_prefix, honorific_suffix, profile_type, status, visibility, roles, max_assurance, manager_id, migration_pending, migration_started_at, migration_completed_at, created_at, updated_at, revision)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            $tail
        )
    };
}

async fn write_profile(
    tx: &mut WriteTx,
    profile: &Profile,
    revision: i64,
    sql: &'static str,
) -> Result<(), sqlx::Error> {
    sqlx::query(sql)
        .bind(profile.id)
        .bind(&profile.username)
        .bind(&profile.given_name)
        .bind(&profile.family_name)
        .bind(&profile.middle_name)
        .bind(&profile.honorific_prefix)
        .bind(&profile.honorific_suffix)
        .bind(profile.profile_type.as_str())
        .bind(profile.status.as_str())
        .bind(profile.visibility.as_str())
        .bind(profile.roles.join(" "))
        .bind(profile.max_assurance.as_str())
        .bind(profile.manager_id)
        .bind(profile.migration_pending)
        .bind(fmt_dt_opt(profile.migration_started_at))
        .bind(fmt_dt_opt(profile.migration_completed_at))
        .bind(fmt_dt(&profile.created_at))
        .bind(fmt_dt(&profile.updated_at))
        // As given: a restored profile keeps the revision stale copies of it
        // are checked against.
        .bind(revision)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Insert `profile`; an existing id or user name is `Conflict`.
pub(super) async fn insert_profile(tx: &mut WriteTx, profile: &Profile) -> SidResult<()> {
    profile.check_reference()?;
    let revision = i64::try_from(profile.revision)
        .map_err(|e| SidError::Validation(format!("profile revision: {e}")))?;
    write_profile(tx, profile, revision, profile_insert!(""))
        .await
        .map_err(|e| insert_error("profile", e))?;
    // Every account is a user of the directory: its resource is assigned
    // with it, under an identifier of its own.
    sqlx::query("INSERT INTO directory_users (id, profile_id) VALUES (?, ?)")
        .bind(uuid::Uuid::now_v7())
        .bind(profile.id)
        .execute(&mut **tx)
        .await
        .map_err(storage("directory resource"))?;
    Ok(())
}

pub(super) const RESOURCE: &str = "id, profile_id, revision, deleted_at, active";

pub(super) fn resource(row: &sqlx::sqlite::SqliteRow) -> SidResult<DirectoryResource> {
    use sqlx::Row;
    let read = |e: sqlx::Error| SidError::Storage(format!("directory resource row: {e}"));
    let revision: i64 = row.try_get("revision").map_err(read)?;
    let deleted_at: Option<String> = row.try_get("deleted_at").map_err(read)?;
    Ok(DirectoryResource {
        id: DirectoryUserId(row.try_get("id").map_err(read)?),
        profile_id: row.try_get("profile_id").map_err(read)?,
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("directory resource revision: {e}")))?,
        deleted_at: super::parse_dt_opt(deleted_at),
        active: row.try_get("active").map_err(read)?,
    })
}

/// Require the live resource `id` of `profile_id`, deleting it when
/// `delete` and setting the relationship's activity when `active` is given;
/// anything else (unknown, deleted, another account's) is `NotFound`. The
/// write transaction is the only writer.
async fn hold_resource(
    tx: &mut WriteTx,
    id: DirectoryUserId,
    profile_id: ProfileId,
    delete: bool,
    active: Option<bool>,
) -> SidResult<()> {
    let held = if delete {
        sqlx::query(
            "UPDATE directory_users SET deleted_at = ?, revision = revision + 1
             WHERE id = ? AND profile_id = ? AND deleted_at IS NULL",
        )
        .bind(fmt_dt(&jiff::Timestamp::now()))
        .bind(id.0)
        .bind(profile_id)
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected() == 1)
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM directory_users
             WHERE id = ? AND profile_id = ? AND deleted_at IS NULL",
        )
        .bind(id.0)
        .bind(profile_id)
        .fetch_optional(&mut **tx)
        .await
        .map(|found| found.is_some())
    }
    .map_err(storage("directory resource"))?;
    if !held {
        return Err(SidError::NotFound(format!("directory user {id}")));
    }
    if delete {
        // Its sources keep their provenance and give their identifiers up.
        sqlx::query("UPDATE directory_user_sources SET retired = 1 WHERE resource_id = ?")
            .bind(id.0)
            .execute(&mut **tx)
            .await
            .map_err(storage("directory sources"))?;
    } else if let Some(active) = active {
        // A change of the relationship's state is a change of the resource.
        sqlx::query(
            "UPDATE directory_users SET active = ?, revision = revision + 1
             WHERE id = ? AND active <> ?",
        )
        .bind(active)
        .bind(id.0)
        .bind(active)
        .execute(&mut **tx)
        .await
        .map_err(storage("directory resource activity"))?;
    }
    if delete || active.is_some() {
        // The memberships resting on this resource stand or fall with it.
        settle_resource_members(tx, id).await?;
    }
    Ok(())
}

pub(super) const SOURCE: &str = "resource_id, connector_id, external_id, retired, created, managed";

/// A stored set of rights; bits that are no right are a broken record.
pub(super) fn rights(bits: i32) -> SidResult<sid_core::models::DirectoryRights> {
    sid_core::models::DirectoryRights::from_bits(bits)
        .ok_or_else(|| SidError::Storage(format!("directory rights: unknown bits in {bits}")))
}

pub(super) fn source(row: &sqlx::sqlite::SqliteRow) -> SidResult<DirectorySource> {
    use sqlx::Row;
    let read = |e: sqlx::Error| SidError::Storage(format!("directory source row: {e}"));
    Ok(DirectorySource {
        resource: DirectoryUserId(row.try_get("resource_id").map_err(read)?),
        connector: row.try_get("connector_id").map_err(read)?,
        external_id: row.try_get("external_id").map_err(read)?,
        retired: row.try_get("retired").map_err(read)?,
        created: row.try_get("created").map_err(read)?,
        managed: rights(row.try_get("managed").map_err(read)?)?,
    })
}

/// A source identifier the connector already gives to another live resource
/// is `Conflict`.
fn source_error(e: sqlx::Error) -> SidError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => SidError::Conflict(
            "the source already names another resource by this identifier".into(),
        ),
        _ => SidError::Storage(format!("directory source: {e}")),
    }
}

/// Record what the write's source knows of the resource it has just created.
async fn record_source(
    tx: &mut WriteTx,
    profile_id: ProfileId,
    source: &SourceWrite,
) -> SidResult<()> {
    sqlx::query(
        // The creator is recorded as such and assigned nothing by creating.
        "INSERT INTO directory_user_sources (resource_id, connector_id, external_id, created)
         SELECT id, ?, ?, 1 FROM directory_users WHERE profile_id = ? AND deleted_at IS NULL",
    )
    .bind(source.connector)
    .bind(source.external_id.as_deref())
    .bind(profile_id)
    .execute(&mut **tx)
    .await
    .map_err(source_error)?;
    Ok(())
}

/// Give the correlation the write's source already has with `resource` the
/// identifier the write carries. A source without one is not given one: no
/// source takes a resource over by writing to it.
async fn update_source(
    tx: &mut WriteTx,
    resource: DirectoryUserId,
    source: &SourceWrite,
) -> SidResult<()> {
    sqlx::query(
        "UPDATE directory_user_sources SET external_id = ?
         WHERE resource_id = ? AND connector_id = ? AND retired = 0",
    )
    .bind(source.external_id.as_deref())
    .bind(resource.0)
    .bind(source.connector)
    .execute(&mut **tx)
    .await
    .map_err(source_error)?;
    Ok(())
}

/// Write `profile` over the stored row while it is still at
/// `profile.revision`, moving the revision on; its id and creation time never
/// change. False when the row is gone or changed since it was read. A write
/// that would make a federated reference local, or the reverse, is refused:
/// the statement itself leaves such a row untouched.
pub(super) async fn update_profile(tx: &mut WriteTx, profile: &Profile) -> SidResult<bool> {
    profile.check_reference()?;
    let revision = i64::try_from(profile.revision)
        .map_err(|e| SidError::Validation(format!("profile revision: {e}")))?;
    let reference = !profile.profile_type.is_local();
    let written = sqlx::query(
        "UPDATE profiles SET
            profile_type = ?, username = ?,
            given_name = ?, family_name = ?, middle_name = ?,
            honorific_prefix = ?, honorific_suffix = ?,
            roles = ?, status = ?, visibility = ?, max_assurance = ?,
            manager_id = ?, migration_pending = ?,
            migration_started_at = ?, migration_completed_at = ?,
            updated_at = ?, revision = revision + 1
         WHERE id = ? AND revision = ? AND (profile_type = 'federated') = ?",
    )
    .bind(profile.profile_type.as_str())
    .bind(&profile.username)
    .bind(&profile.given_name)
    .bind(&profile.family_name)
    .bind(&profile.middle_name)
    .bind(&profile.honorific_prefix)
    .bind(&profile.honorific_suffix)
    .bind(profile.roles.join(" "))
    .bind(profile.status.as_str())
    .bind(profile.visibility.as_str())
    .bind(profile.max_assurance.as_str())
    .bind(profile.manager_id)
    .bind(profile.migration_pending)
    .bind(fmt_dt_opt(profile.migration_started_at))
    .bind(fmt_dt_opt(profile.migration_completed_at))
    .bind(fmt_dt(&profile.updated_at))
    .bind(profile.id)
    .bind(revision)
    .bind(reference)
    .execute(&mut **tx)
    .await
    .map(|r| r.rows_affected() == 1)
    .map_err(|e| insert_error("profile", e))?;
    if written {
        return Ok(true);
    }
    // Not written: gone, changed since it was read, or of the other kind.
    let stored: Option<bool> = sqlx::query_scalar(
        "SELECT profile_type = 'federated' FROM profiles WHERE id = ? AND revision = ?",
    )
    .bind(profile.id)
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("profile kind: {e}")))?;
    if let Some(stored) = stored {
        profile.check_reference_kept(kind(stored))?;
    }
    Ok(false)
}

/// A Profile type of the stored kind: a federated reference or a local one.
fn kind(reference: bool) -> sid_core::models::ProfileType {
    if reference {
        sid_core::models::ProfileType::Federated
    } else {
        sid_core::models::ProfileType::Corporate
    }
}

/// Upsert the binding of `p` to entity `entity_id`.
async fn upsert_binding(tx: &mut WriteTx, entity_id: uuid::Uuid, p: &Principal) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary, source_field, source_email_id, source_phone_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(principal_id, profile_id) DO UPDATE SET
            is_primary=excluded.is_primary, source_field=excluded.source_field,
            source_email_id=excluded.source_email_id, source_phone_id=excluded.source_phone_id",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(entity_id)
    .bind(p.profile_id)
    .bind(p.is_primary)
    .bind(&p.source_field)
    .bind(p.source_email_id.map(|id| id.0))
    .bind(p.source_phone_id.map(|id| id.0))
    .bind(fmt_dt(&p.created_at))
    .execute(&mut **tx)
    .await
    .map_err(storage("principal binding"))?;
    Ok(())
}

/// Create the entity of `p` when its value is new: first use assigns it to
/// `p`'s claimant with the proof `p` carries. An existing entity is left as
/// it is; only a proven transfer changes its assignment and proof.
async fn insert_new_principal(tx: &mut WriteTx, p: &Principal) -> SidResult<()> {
    let assigned = Some(p.profile_id);
    sqlx::query(
        "INSERT INTO principals (id, principal_type, value, verified, verified_at, verification_expires, assigned_profile_id, assignment_revision, email_policy_revision, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(principal_type, value) DO NOTHING",
    )
    .bind(p.id.0)
    .bind(p.principal_type.as_str())
    .bind(&p.value)
    .bind(p.verified)
    .bind(fmt_dt_opt(p.verified_at))
    .bind(fmt_dt_opt(p.verification_expires))
    .bind(assigned)
    .bind(i64::from(assigned.is_some()))
    .bind(p.email_policy_revision)
    .bind(fmt_dt(&p.created_at))
    .bind(fmt_dt(&p.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| super::principal_write_error("principal", e))?;
    Ok(())
}

async fn entity_id(tx: &mut WriteTx, p: &Principal) -> SidResult<uuid::Uuid> {
    sqlx::query_scalar("SELECT id FROM principals WHERE principal_type = ? AND value = ?")
        .bind(p.principal_type.as_str())
        .bind(&p.value)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage("principal"))
}

impl SqliteBackend {
    /// Record `p`'s claim in `tx`, a host's own write transaction (begun with
    /// [`SqliteBackend::begin_write_on`]) that commits it with the host's
    /// state, as [`sid_plugin::IdentityStore::save_principal`] records one.
    pub async fn bind_principal_in_tx(tx: &mut WriteTx, p: &Principal) -> SidResult<()> {
        bind_principal(tx, p).await
    }
}

/// Record `p`'s claim; other holders keep theirs and the assignment stays.
/// A login handle is never shared (`Conflict` when another Profile holds it).
pub(super) async fn bind_principal(tx: &mut WriteTx, p: &Principal) -> SidResult<()> {
    // A federated reference is reached only by the subject its trusted
    // issuer names: it claims no email, phone or user name here.
    if p.principal_type != PrincipalType::FederatedSubject {
        let reference: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM profiles WHERE id = ? AND profile_type = 'federated')",
        )
        .bind(p.profile_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("principal claimant: {e}")))?;
        if reference {
            return Err(SidError::InvalidState(
                crate::FEDERATED_HOLDS_NO_LOGIN_NAME.into(),
            ));
        }
    }
    if !p.principal_type.is_contestable() {
        return bind_login_principal(tx, p).await;
    }
    insert_new_principal(tx, p).await?;
    let id = entity_id(tx, p).await?;
    upsert_binding(tx, id, p).await
}

/// Bind a login handle, which is never shared: held by another Profile it
/// is `Conflict`, and nothing about the existing entity is changed.
async fn bind_login_principal(tx: &mut WriteTx, p: &Principal) -> SidResult<()> {
    insert_new_principal(tx, p).await?;
    let id = entity_id(tx, p).await?;
    let other_holder: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM principal_bindings WHERE principal_id = ? AND profile_id <> ?)",
    )
    .bind(id)
    .bind(p.profile_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("login principal"))?;
    if other_holder {
        return Err(SidError::Conflict("login handle already exists".into()));
    }
    upsert_binding(tx, id, p).await
}

/// Remove `profile_id`'s claim; the entity goes with its last claim. The
/// assigned Profile releasing its claim clears the assignment and its proof
/// without electing another claimant. `false` when there was no such claim.
pub(super) async fn unbind_principal(
    tx: &mut WriteTx,
    principal_id: PrincipalId,
    profile_id: ProfileId,
) -> SidResult<bool> {
    let removed =
        sqlx::query("DELETE FROM principal_bindings WHERE principal_id = ? AND profile_id = ?")
            .bind(principal_id.0)
            .bind(profile_id)
            .execute(&mut **tx)
            .await
            .map_err(storage("delete binding"))?
            .rows_affected();
    if removed == 0 {
        return Ok(false);
    }
    sqlx::query(
        "DELETE FROM principals WHERE id = ?1 \
         AND NOT EXISTS (SELECT 1 FROM principal_bindings WHERE principal_id = ?1)",
    )
    .bind(principal_id.0)
    .execute(&mut **tx)
    .await
    .map_err(storage("delete principal"))?;
    sqlx::query(
        "UPDATE principals SET assigned_profile_id = NULL,
             assignment_revision = assignment_revision + 1,
             verified = 0, verified_at = NULL, verification_expires = NULL,
             updated_at = ?3
         WHERE id = ?1 AND assigned_profile_id = ?2",
    )
    .bind(principal_id.0)
    .bind(profile_id)
    .bind(fmt_dt(&jiff::Timestamp::now()))
    .execute(&mut **tx)
    .await
    .map_err(storage("release principal"))?;
    Ok(true)
}

/// Insert `email` or update the row with its id.
pub(super) async fn upsert_email(tx: &mut WriteTx, email: &ProfileEmail) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_emails (id, profile_id, email, label, custom_label, is_primary, verified, verified_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            email=excluded.email, label=excluded.label, custom_label=excluded.custom_label,
            is_primary=excluded.is_primary, verified=excluded.verified,
            verified_at=excluded.verified_at, updated_at=excluded.updated_at",
    )
    .bind(email.id.0)
    .bind(email.profile_id)
    .bind(&email.email)
    .bind(email.label.as_str())
    .bind(&email.custom_label)
    .bind(email.is_primary)
    .bind(email.verified)
    .bind(fmt_dt_opt(email.verified_at))
    .bind(fmt_dt(&email.created_at))
    .bind(fmt_dt(&email.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("profile email", e))?;
    Ok(())
}

/// Delete email `id`; only `owner`'s when given.
pub(super) async fn delete_email(
    tx: &mut WriteTx,
    id: ProfileEmailId,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    sqlx::query("DELETE FROM profile_emails WHERE id = ? AND (? IS NULL OR profile_id = ?)")
        .bind(id.0)
        .bind(owner)
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(storage("delete profile email"))?;
    Ok(())
}

/// Insert `phone` or update the row with its id.
pub(super) async fn upsert_phone(tx: &mut WriteTx, phone: &ProfilePhone) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_phones (id, profile_id, e164, extension, label, custom_label, is_primary, can_receive_sms, can_receive_fax, can_receive_voice, verified, verified_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            e164=excluded.e164, extension=excluded.extension, label=excluded.label,
            custom_label=excluded.custom_label, is_primary=excluded.is_primary,
            can_receive_sms=excluded.can_receive_sms, can_receive_fax=excluded.can_receive_fax,
            can_receive_voice=excluded.can_receive_voice,
            verified=excluded.verified, verified_at=excluded.verified_at,
            updated_at=excluded.updated_at",
    )
    .bind(phone.id.0)
    .bind(phone.profile_id)
    .bind(phone.e164 as i64)
    .bind(phone.extension.map(|e| e as i32))
    .bind(phone.label.as_str())
    .bind(&phone.custom_label)
    .bind(phone.is_primary)
    .bind(phone.can_receive_sms)
    .bind(phone.can_receive_fax)
    .bind(phone.can_receive_voice)
    .bind(phone.verified)
    .bind(fmt_dt_opt(phone.verified_at))
    .bind(fmt_dt(&phone.created_at))
    .bind(fmt_dt(&phone.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("profile phone", e))?;
    Ok(())
}

/// Delete phone `id`; only `owner`'s when given.
pub(super) async fn delete_phone(
    tx: &mut WriteTx,
    id: ProfilePhoneId,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    sqlx::query("DELETE FROM profile_phones WHERE id = ? AND (? IS NULL OR profile_id = ?)")
        .bind(id.0)
        .bind(owner)
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(storage("delete profile phone"))?;
    Ok(())
}

/// Set one metadata key of a profile.
pub(super) async fn set_metadata(tx: &mut WriteTx, metadata: &ProfileMetadata) -> SidResult<()> {
    let value = serde_json::to_string(&metadata.value)
        .map_err(|e| SidError::Internal(format!("metadata value: {e}")))?;
    sqlx::query(
        "INSERT INTO profile_metadata (profile_id, key, value, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(profile_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
    )
    .bind(metadata.profile_id)
    .bind(&metadata.key)
    .bind(&value)
    .bind(fmt_dt(&metadata.created_at))
    .bind(fmt_dt(&metadata.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| match &e {
        // Metadata of an account that does not exist.
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
            SidError::NotFound(format!("profile {}", metadata.profile_id))
        }
        _ => storage("set profile metadata")(e),
    })?;
    Ok(())
}

/// Remove one metadata key of a profile.
pub(super) async fn delete_metadata(
    tx: &mut WriteTx,
    profile_id: ProfileId,
    key: &str,
) -> SidResult<()> {
    sqlx::query("DELETE FROM profile_metadata WHERE profile_id = ? AND key = ?")
        .bind(profile_id)
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(storage("delete profile metadata"))?;
    Ok(())
}

/// End every session of `profile_id`; each ended session's owed work is
/// added to `ctx`.
pub(super) async fn end_sessions(
    tx: &mut WriteTx,
    profile_id: ProfileId,
    end: &SessionEnd,
    ctx: &mut MutationContext,
) -> SidResult<Vec<Session>> {
    let sessions = sqlx::query("DELETE FROM sessions WHERE profile_id = ? RETURNING *")
        .bind(profile_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(storage("end sessions"))?
        .iter()
        .map(row_to_session)
        .collect::<SidResult<Vec<Session>>>()?;
    for ended in &sessions {
        ctx.work.extend(end.owed_by(ended));
    }
    Ok(sessions)
}

/// Revoke every active PAT of `profile_id`; returns how many.
pub(super) async fn revoke_pats(
    tx: &mut WriteTx,
    profile_id: ProfileId,
    revoked_by: &str,
) -> SidResult<u64> {
    sqlx::query(
        "UPDATE personal_access_tokens SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE profile_id = ? AND status = 'active'",
    )
    .bind(fmt_dt(&jiff::Timestamp::now()))
    .bind(revoked_by)
    .bind(profile_id)
    .execute(&mut **tx)
    .await
    .map(|r| r.rows_affected())
    .map_err(storage("revoke PATs"))
}

macro_rules! group_insert {
    ($tail:literal) => {
        concat!(
            "INSERT INTO groups (id, project_id, name, description, parent_group_id, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            $tail
        )
    };
}

async fn write_group(
    tx: &mut WriteTx,
    group: &Group,
    sql: &'static str,
) -> Result<(), sqlx::Error> {
    sqlx::query(sql)
        .bind(group.id)
        .bind(group.project_id)
        .bind(&group.name)
        .bind(&group.description)
        .bind(group.parent_group_id)
        .bind(fmt_dt(&group.created_at))
        .bind(fmt_dt(&group.updated_at))
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Insert `group`; an existing id or name is a `Conflict`.
pub(super) async fn insert_group(tx: &mut WriteTx, group: &Group) -> SidResult<()> {
    write_group(tx, group, group_insert!(""))
        .await
        .map_err(|e| insert_error("group", e))
}

/// Write the name and description of the stored `group`; false when it does
/// not exist.
async fn update_group(tx: &mut WriteTx, group: &Group) -> SidResult<bool> {
    sqlx::query("UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?")
        .bind(&group.name)
        .bind(&group.description)
        .bind(fmt_dt(&group.updated_at))
        .bind(group.id)
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected() == 1)
        .map_err(|e| insert_error("group", e))
}

/// The stored origin of an assignment made by `source`: the nil UUID stands
/// for one made locally.
fn origin(source: Option<sid_core::models::ProvisioningConnectorId>) -> uuid::Uuid {
    source.map_or(uuid::Uuid::nil(), |connector| connector.into_uuid())
}

/// Make `group_members` agree with the assignments of `profile_id` to
/// `group_id`: a member while any assignment stands. A local one always
/// does; a connector's does while the resource it rests on is live and
/// active.
async fn settle_member(
    tx: &mut WriteTx,
    group_id: GroupId,
    profile_id: ProfileId,
    added_at: &jiff::Timestamp,
) -> SidResult<()> {
    macro_rules! standing {
        () => {
            "(SELECT 1 FROM group_member_origins o
              LEFT JOIN directory_users d ON d.id = o.resource_id
              WHERE o.group_id = ?1 AND o.profile_id = ?2
                AND (o.resource_id IS NULL OR (d.deleted_at IS NULL AND d.active = 1)))"
        };
    }
    sqlx::query(concat!(
        "INSERT INTO group_members (group_id, profile_id, added_at)
         SELECT ?1, ?2, ?3 WHERE EXISTS ",
        standing!(),
        " ON CONFLICT(group_id, profile_id) DO NOTHING"
    ))
    .bind(group_id)
    .bind(profile_id)
    .bind(fmt_dt(added_at))
    .execute(&mut **tx)
    .await
    .map_err(member_error)?;
    sqlx::query(concat!(
        "DELETE FROM group_members WHERE group_id = ?1 AND profile_id = ?2
         AND NOT EXISTS ",
        standing!()
    ))
    .bind(group_id)
    .bind(profile_id)
    .execute(&mut **tx)
    .await
    .map_err(storage("settle group member"))?;
    Ok(())
}

/// Settle every membership that rests on the directory resource `resource`,
/// after its activity or its deletion changed.
async fn settle_resource_members(tx: &mut WriteTx, resource: DirectoryUserId) -> SidResult<()> {
    let resting: Vec<(GroupId, ProfileId)> = sqlx::query_as(
        "SELECT group_id, profile_id FROM group_member_origins WHERE resource_id = ?",
    )
    .bind(resource.0)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("memberships of a directory resource"))?;
    let now = jiff::Timestamp::now();
    for (group_id, profile_id) in resting {
        settle_member(tx, group_id, profile_id, &now).await?;
    }
    Ok(())
}

/// Record the assignment `member` made by `source` (a repeat is no change)
/// and settle the membership. A connector's assignment rests on the
/// member's live directory resource. A grant the new member made to the
/// group stays withheld from it (`RoleAssignment::withheld_from`), so joining
/// needs no check against the group's grants.
pub(super) async fn add_member(
    tx: &mut WriteTx,
    member: &GroupMember,
    source: Option<sid_core::models::ProvisioningConnectorId>,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO group_member_origins (group_id, profile_id, connector_id, resource_id, added_at)
         VALUES (?1, ?2, ?3,
            CASE WHEN ?4 THEN (SELECT d.id FROM directory_users d
                               WHERE d.profile_id = ?2 AND d.deleted_at IS NULL) END,
            ?5)
         ON CONFLICT(group_id, profile_id, connector_id) DO NOTHING",
    )
    .bind(member.group_id)
    .bind(member.profile_id)
    .bind(origin(source))
    .bind(source.is_some())
    .bind(fmt_dt(&member.added_at))
    .execute(&mut **tx)
    .await
    .map_err(member_error)?;
    settle_member(tx, member.group_id, member.profile_id, &member.added_at).await
}

/// A member that is no account is the caller's mistake, not a fault.
fn member_error(e: sqlx::Error) -> SidError {
    match &e {
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
            SidError::Validation("a group member is not an existing account".into())
        }
        _ => insert_error("group member", e),
    }
}

/// Withdraw the assignment of `profile_id` to `group_id` made by `source`
/// and settle the membership: another origin's assignment keeps it.
pub(super) async fn remove_member(
    tx: &mut WriteTx,
    group_id: GroupId,
    profile_id: ProfileId,
    source: Option<sid_core::models::ProvisioningConnectorId>,
) -> SidResult<()> {
    sqlx::query(
        "DELETE FROM group_member_origins
         WHERE group_id = ? AND profile_id = ? AND connector_id = ?",
    )
    .bind(group_id)
    .bind(profile_id)
    .bind(origin(source))
    .execute(&mut **tx)
    .await
    .map_err(storage("remove group member"))?;
    settle_member(tx, group_id, profile_id, &jiff::Timestamp::now()).await
}

impl SqliteBackend {
    pub(super) async fn write_directory_user_impl(
        &self,
        write: &DirectoryUserWrite,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let profile_id = write.profile_id();
        if write.delete_resource && write.resource.is_none() {
            return Err(SidError::Validation(
                "a directory deletion names its resource".into(),
            ));
        }
        let mut tx = self.begin_write().await?;
        match write.mode {
            DirectoryWriteMode::Create => {
                if write.resource.is_some() {
                    return Err(SidError::Validation(
                        "a directory create is given no resource".into(),
                    ));
                }
                insert_profile(&mut tx, &write.profile).await?;
                if let Some(source) = &write.source {
                    record_source(&mut tx, profile_id, source).await?;
                }
            }
            DirectoryWriteMode::Update => {
                // The resource first: a deletion that committed since the
                // caller read it refuses the write as not found.
                if let Some(resource) = write.resource {
                    hold_resource(
                        &mut tx,
                        resource,
                        profile_id,
                        write.delete_resource,
                        write.resource_active,
                    )
                    .await?;
                    if let Some(source) = write.source.as_ref().filter(|_| !write.delete_resource) {
                        update_source(&mut tx, resource, source).await?;
                    }
                }
                // A missing account or one changed since it was read refuses
                // the whole write.
                if !update_profile(&mut tx, &write.profile).await? {
                    let exists: Option<ProfileId> =
                        sqlx::query_scalar("SELECT id FROM profiles WHERE id = ?")
                            .bind(profile_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(storage("find profile"))?;
                    return Err(match exists {
                        None => SidError::NotFound(format!("profile {profile_id}")),
                        Some(_) => SidError::InvalidState(format!(
                            "profile {profile_id} changed since it was read"
                        )),
                    });
                }
            }
        }
        for id in &write.unbind {
            unbind_principal(&mut tx, *id, profile_id).await?;
        }
        // Contacts before bindings: an email binding names the contact that
        // holds its mailbox.
        for id in &write.remove_emails {
            delete_email(&mut tx, *id, Some(profile_id)).await?;
        }
        for email in &write.add_emails {
            upsert_email(&mut tx, email).await?;
        }
        for p in &write.bind {
            if p.profile_id != profile_id {
                return Err(SidError::Validation(
                    "a directory write binds principals to its own account only".into(),
                ));
            }
            bind_principal(&mut tx, p).await?;
        }
        for id in &write.remove_phones {
            delete_phone(&mut tx, *id, Some(profile_id)).await?;
        }
        for phone in &write.add_phones {
            upsert_phone(&mut tx, phone).await?;
        }
        for key in &write.remove_metadata {
            delete_metadata(&mut tx, profile_id, key).await?;
        }
        for metadata in &write.set_metadata {
            set_metadata(&mut tx, metadata).await?;
        }
        let ended = match &write.end_access {
            Some(end) => {
                let ended = end_sessions(&mut tx, profile_id, end, &mut ctx).await?;
                revoke_pats(&mut tx, profile_id, &end.by).await?;
                ended
            }
            None => Vec::new(),
        };
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), ctx).await?;
        Ok(ended)
    }

    pub(super) async fn find_directory_user_impl(
        &self,
        id: DirectoryUserId,
    ) -> SidResult<Option<DirectoryResource>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {RESOURCE} FROM directory_users WHERE id = ?"
        )))
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("directory resource"))?
        .as_ref()
        .map(resource)
        .transpose()
    }

    pub(super) async fn directory_users_of_impl(
        &self,
        profiles: &[ProfileId],
    ) -> SidResult<Vec<DirectoryResource>> {
        let mut found = Vec::new();
        for run in profiles.chunks(super::rbac::IN_LIST_CHUNK) {
            let ids = super::rbac::placeholders(run.len());
            let mut read = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT {RESOURCE} FROM directory_users
                 WHERE deleted_at IS NULL AND profile_id IN ({ids}) ORDER BY profile_id"
            )));
            for profile in run {
                read = read.bind(*profile);
            }
            for row in read
                .fetch_all(&self.pool)
                .await
                .map_err(storage("directory resources"))?
            {
                found.push(resource(&row)?);
            }
        }
        Ok(found)
    }

    pub(super) async fn export_directory_users_impl(&self) -> SidResult<Vec<DirectoryResource>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {RESOURCE} FROM directory_users ORDER BY profile_id, id"
        )))
        .fetch_all(&self.pool)
        .await
        .map_err(storage("directory resources"))?
        .iter()
        .map(resource)
        .collect()
    }

    pub(super) async fn import_directory_users_impl(
        &self,
        profile_id: ProfileId,
        resources: &[DirectoryResource],
        sources: &[DirectorySource],
        ctx: MutationContext,
    ) -> SidResult<()> {
        if resources.iter().any(|r| r.profile_id != profile_id)
            || resources.iter().filter(|r| r.is_live()).count() > 1
        {
            return Err(SidError::Validation(
                "an account's directory resources are its own, one of them live at most".into(),
            ));
        }
        if sources
            .iter()
            .any(|s| !resources.iter().any(|r| r.id == s.resource))
        {
            return Err(SidError::Validation(
                "a directory source names a resource of the account".into(),
            ));
        }
        let mut tx = self.begin_write().await?;
        // The resource assigned when the account was restored gives way to
        // the ones the account had.
        let held: Vec<uuid::Uuid> =
            sqlx::query_scalar("SELECT id FROM directory_users WHERE profile_id = ?")
                .bind(profile_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(storage("directory resources"))?;
        for id in held {
            if !resources.iter().any(|r| r.id.0 == id) {
                sqlx::query("DELETE FROM directory_users WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("replace directory resource"))?;
            }
        }
        for r in resources {
            let revision = i64::try_from(r.revision)
                .map_err(|e| SidError::Validation(format!("directory resource revision: {e}")))?;
            let written = sqlx::query(
                "INSERT INTO directory_users (id, profile_id, revision, deleted_at, active)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (id) DO UPDATE SET revision = excluded.revision,
                    deleted_at = excluded.deleted_at, active = excluded.active
                 WHERE directory_users.profile_id = excluded.profile_id",
            )
            .bind(r.id.0)
            .bind(profile_id)
            .bind(revision)
            .bind(fmt_dt_opt(r.deleted_at))
            .bind(r.active)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("directory resource", e))?
            .rows_affected();
            if written != 1 {
                return Err(SidError::Conflict(format!(
                    "directory user {} stands for another account",
                    r.id
                )));
            }
        }
        // The resources' sources are exactly the ones given.
        for r in resources {
            sqlx::query("DELETE FROM directory_user_sources WHERE resource_id = ?")
                .bind(r.id.0)
                .execute(&mut *tx)
                .await
                .map_err(storage("replace directory sources"))?;
        }
        for s in sources {
            sqlx::query(
                "INSERT INTO directory_user_sources
                     (resource_id, connector_id, external_id, retired, created, managed)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(s.resource.0)
            .bind(s.connector)
            .bind(s.external_id.as_deref())
            .bind(s.retired)
            .bind(s.created)
            .bind(s.managed.bits())
            .execute(&mut *tx)
            .await
            .map_err(source_error)?;
        }
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), ctx).await
    }

    pub(super) async fn directory_sources_impl(
        &self,
        connector: Option<ProvisioningConnectorId>,
        resources: &[DirectoryUserId],
    ) -> SidResult<Vec<DirectorySource>> {
        let mut found = Vec::new();
        for run in resources.chunks(super::rbac::IN_LIST_CHUNK) {
            let ids = super::rbac::placeholders(run.len());
            let of_connector = if connector.is_some() {
                " AND connector_id = ?"
            } else {
                ""
            };
            let mut read = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT {SOURCE} FROM directory_user_sources
                 WHERE retired = 0 AND resource_id IN ({ids}){of_connector}
                 ORDER BY resource_id, connector_id"
            )));
            for resource in run {
                read = read.bind(resource.0);
            }
            if let Some(connector) = connector {
                read = read.bind(connector);
            }
            for row in read
                .fetch_all(&self.pool)
                .await
                .map_err(storage("directory sources"))?
            {
                found.push(source(&row)?);
            }
        }
        Ok(found)
    }

    pub(super) async fn find_directory_source_impl(
        &self,
        connector: ProvisioningConnectorId,
        external_id: &str,
    ) -> SidResult<Option<DirectorySource>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SOURCE} FROM directory_user_sources
             WHERE connector_id = ? AND external_id = ? AND retired = 0"
        )))
        .bind(connector)
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("directory source"))?
        .as_ref()
        .map(source)
        .transpose()
    }

    pub(super) async fn export_directory_sources_impl(&self) -> SidResult<Vec<DirectorySource>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SOURCE} FROM directory_user_sources ORDER BY resource_id, connector_id"
        )))
        .fetch_all(&self.pool)
        .await
        .map_err(storage("directory sources"))?
        .iter()
        .map(source)
        .collect()
    }

    pub(super) async fn write_directory_group_impl(
        &self,
        write: &DirectoryGroupWrite,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let group_id = write.group.id;
        let mut tx = self.begin_write().await?;
        match write.mode {
            DirectoryWriteMode::Create => insert_group(&mut tx, &write.group).await?,
            DirectoryWriteMode::Update => {
                if !update_group(&mut tx, &write.group).await? {
                    return Err(SidError::NotFound(format!("group {group_id}")));
                }
            }
        }
        for profile_id in &write.remove_members {
            remove_member(&mut tx, group_id, *profile_id, write.source).await?;
        }
        for member in &write.add_members {
            if member.group_id != group_id {
                return Err(SidError::Validation(
                    "a group write adds members to its own group only".into(),
                ));
            }
            add_member(&mut tx, member, write.source).await?;
        }
        Self::commit_mutation(tx, &format!("group:{group_id}"), ctx).await
    }
}
