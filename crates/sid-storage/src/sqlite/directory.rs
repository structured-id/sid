// SPDX-License-Identifier: AGPL-3.0-only
//! Account, contact, principal and group writes inside a caller's write
//! transaction, and the directory (SCIM) writes built from them: one
//! request's changes commit together with its audit entry and owed work.

use sid_core::models::{
    DirectoryGroupWrite, DirectoryUserWrite, DirectoryWriteMode, Group, GroupId, GroupMember,
    MutationContext, Principal, PrincipalId, PrincipalType, Profile, ProfileEmail, ProfileEmailId,
    ProfileId, ProfileMetadata, ProfilePhone, ProfilePhoneId, Session, SessionEnd,
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
            "INSERT INTO profiles (id, username, given_name, family_name, middle_name, honorific_prefix, honorific_suffix, profile_type, status, visibility, roles, max_assurance, manager_id, migration_pending, migration_started_at, migration_completed_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            $tail
        )
    };
}

async fn write_profile(
    tx: &mut WriteTx,
    profile: &Profile,
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
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Insert `profile`; an existing id or user name is `Conflict`.
pub(super) async fn insert_profile(tx: &mut WriteTx, profile: &Profile) -> SidResult<()> {
    write_profile(tx, profile, profile_insert!(""))
        .await
        .map_err(|e| insert_error("profile", e))
}

/// Write `profile` over the stored row while it is still at
/// `profile.revision`, moving the revision on; its id and creation time never
/// change. False when the row is gone or changed since it was read.
pub(super) async fn update_profile(tx: &mut WriteTx, profile: &Profile) -> SidResult<bool> {
    let revision = i64::try_from(profile.revision)
        .map_err(|e| SidError::Validation(format!("profile revision: {e}")))?;
    sqlx::query(
        "UPDATE profiles SET
            profile_type = ?, username = ?,
            given_name = ?, family_name = ?, middle_name = ?,
            honorific_prefix = ?, honorific_suffix = ?,
            roles = ?, status = ?, visibility = ?, max_assurance = ?,
            manager_id = ?, migration_pending = ?,
            migration_started_at = ?, migration_completed_at = ?,
            updated_at = ?, revision = revision + 1
         WHERE id = ? AND revision = ?",
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
    .execute(&mut **tx)
    .await
    .map(|r| r.rows_affected() == 1)
    .map_err(|e| insert_error("profile", e))
}

/// Upsert the binding of `p` to entity `entity_id`.
async fn upsert_binding(tx: &mut WriteTx, entity_id: &str, p: &Principal) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary, source_field, source_email_id, source_phone_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(principal_id, profile_id) DO UPDATE SET
            is_primary=excluded.is_primary, source_field=excluded.source_field,
            source_email_id=excluded.source_email_id, source_phone_id=excluded.source_phone_id",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(entity_id)
    .bind(p.profile_id.to_string())
    .bind(p.is_primary)
    .bind(&p.source_field)
    .bind(p.source_email_id.map(|id| id.0.to_string()))
    .bind(p.source_phone_id.map(|id| id.0.to_string()))
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
    .bind(p.id.0.to_string())
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

async fn entity_id(tx: &mut WriteTx, p: &Principal) -> SidResult<String> {
    sqlx::query_scalar("SELECT id FROM principals WHERE principal_type = ? AND value = ?")
        .bind(p.principal_type.as_str())
        .bind(&p.value)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage("principal"))
}

/// Record `p`'s claim; other holders keep theirs and the assignment stays.
/// A login handle is never shared (`Conflict` when another Profile holds it).
pub(super) async fn bind_principal(tx: &mut WriteTx, p: &Principal) -> SidResult<()> {
    if !p.principal_type.is_contestable() {
        return bind_login_principal(tx, p).await;
    }
    insert_new_principal(tx, p).await?;
    let id = entity_id(tx, p).await?;
    upsert_binding(tx, &id, p).await
}

/// Bind a login handle, which is never shared: held by another Profile it
/// is `Conflict`, and nothing about the existing entity is changed.
async fn bind_login_principal(tx: &mut WriteTx, p: &Principal) -> SidResult<()> {
    insert_new_principal(tx, p).await?;
    let id = entity_id(tx, p).await?;
    let other_holder: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM principal_bindings WHERE principal_id = ? AND profile_id <> ?)",
    )
    .bind(&id)
    .bind(p.profile_id.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("login principal"))?;
    if other_holder {
        return Err(SidError::Conflict("login handle already exists".into()));
    }
    upsert_binding(tx, &id, p).await
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
            .bind(principal_id.0.to_string())
            .bind(profile_id.to_string())
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
    .bind(principal_id.0.to_string())
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
    .bind(principal_id.0.to_string())
    .bind(profile_id.to_string())
    .bind(fmt_dt(&chrono::Utc::now()))
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
    .bind(email.id.0.to_string())
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
        .bind(id.0.to_string())
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
    .bind(phone.id.0.to_string())
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
        .bind(id.0.to_string())
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
    .bind(fmt_dt(&chrono::Utc::now()))
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
        .bind(group.id.0.to_string())
        .bind(group.project_id.0.to_string())
        .bind(&group.name)
        .bind(&group.description)
        .bind(group.parent_group_id.map(|g| g.0.to_string()))
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
        .bind(group.id.0.to_string())
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected() == 1)
        .map_err(|e| insert_error("group", e))
}

/// Add a member (a repeat is no change). A Profile that granted the group a
/// role under an administrative assignment never joins it: the grant would
/// reach its own grantor. The write transaction is the only writer, so no
/// such grant can commit in between.
pub(super) async fn add_member(tx: &mut WriteTx, member: &GroupMember) -> SidResult<()> {
    let granted: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM role_assignments
         WHERE group_id = ? AND basis_assignment_id IS NOT NULL AND granted_by = ?
         LIMIT 1",
    )
    .bind(member.group_id.0.to_string())
    .bind(format!("user:{}", member.profile_id))
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("check group grants: {e}")))?;
    if granted.is_some() {
        return Err(SidError::PolicyViolation(format!(
            "profile {} granted this group a role; it cannot join the group",
            member.profile_id
        )));
    }
    sqlx::query(
        "INSERT INTO group_members (group_id, profile_id, added_at) VALUES (?, ?, ?)
         ON CONFLICT(group_id, profile_id) DO NOTHING",
    )
    .bind(member.group_id.0.to_string())
    .bind(member.profile_id)
    .bind(fmt_dt(&member.added_at))
    .execute(&mut **tx)
    .await
    .map_err(member_error)?;
    Ok(())
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

/// Remove a member.
pub(super) async fn remove_member(
    tx: &mut WriteTx,
    group_id: GroupId,
    profile_id: ProfileId,
) -> SidResult<()> {
    sqlx::query("DELETE FROM group_members WHERE group_id = ? AND profile_id = ?")
        .bind(group_id.0.to_string())
        .bind(profile_id)
        .execute(&mut **tx)
        .await
        .map_err(storage("remove group member"))?;
    Ok(())
}

impl SqliteBackend {
    pub(super) async fn write_directory_user_impl(
        &self,
        write: &DirectoryUserWrite,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let profile_id = write.profile_id();
        let mut tx = self.begin_write().await?;
        match write.mode {
            DirectoryWriteMode::Create => insert_profile(&mut tx, &write.profile).await?,
            DirectoryWriteMode::Update => {
                // A missing account or one changed since it was read refuses
                // the whole write.
                if !update_profile(&mut tx, &write.profile).await? {
                    let exists: Option<String> =
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
        for p in &write.bind {
            if p.profile_id != profile_id {
                return Err(SidError::Validation(
                    "a directory write binds principals to its own account only".into(),
                ));
            }
            if p.principal_type == PrincipalType::Username {
                bind_login_principal(&mut tx, p).await?;
            } else {
                bind_principal(&mut tx, p).await?;
            }
        }
        for id in &write.remove_emails {
            delete_email(&mut tx, *id, Some(profile_id)).await?;
        }
        for email in &write.add_emails {
            upsert_email(&mut tx, email).await?;
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
                    return Err(SidError::NotFound(format!("group {}", group_id.0)));
                }
            }
        }
        for profile_id in &write.remove_members {
            remove_member(&mut tx, group_id, *profile_id).await?;
        }
        for member in &write.add_members {
            if member.group_id != group_id {
                return Err(SidError::Validation(
                    "a group write adds members to its own group only".into(),
                ));
            }
            add_member(&mut tx, member).await?;
        }
        Self::commit_mutation(tx, &format!("group:{}", group_id.0), ctx).await
    }
}
