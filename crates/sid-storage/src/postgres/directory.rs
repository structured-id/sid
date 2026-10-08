// SPDX-License-Identifier: AGPL-3.0-only
//! Account, contact, principal and group writes inside a caller's
//! transaction, and the directory (SCIM) writes built from them: one
//! request's changes commit together with its audit entry and owed work.

use sid_core::models::{
    DirectoryGroupWrite, DirectoryUserWrite, DirectoryWriteMode, Group, GroupId, GroupMember,
    MutationContext, Principal, PrincipalId, PrincipalType, Profile, ProfileEmail, ProfileEmailId,
    ProfileId, ProfileMetadata, ProfilePhone, ProfilePhoneId, Session, SessionEnd,
};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::{PostgresBackend, insert_error};

type Tx<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

macro_rules! profile_insert {
    ($tail:literal) => {
        concat!(
            "INSERT INTO profiles (
                id, profile_type, username,
                given_name, family_name, middle_name, honorific_prefix, honorific_suffix,
                roles, status, visibility, max_assurance, manager_id,
                migration_pending, migration_started_at, migration_completed_at,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
            $tail
        )
    };
}

async fn write_profile(
    tx: &mut Tx<'_>,
    profile: &Profile,
    sql: &'static str,
) -> Result<(), sqlx::Error> {
    sqlx::query(sql)
        .bind(profile.id)
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
        .bind(profile.migration_started_at)
        .bind(profile.migration_completed_at)
        .bind(profile.created_at)
        .bind(profile.updated_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Insert `profile`; an existing id or user name is `Conflict`.
pub(super) async fn insert_profile(tx: &mut Tx<'_>, profile: &Profile) -> SidResult<()> {
    write_profile(tx, profile, profile_insert!(""))
        .await
        .map_err(|e| insert_error("profile", e))
}

/// Write `profile` over the stored row while it is still at
/// `profile.revision`, moving the revision on; its id and creation time never
/// change. False when the row is gone or changed since it was read.
pub(super) async fn update_profile(tx: &mut Tx<'_>, profile: &Profile) -> SidResult<bool> {
    let revision = i64::try_from(profile.revision)
        .map_err(|e| SidError::Validation(format!("profile revision: {e}")))?;
    sqlx::query(
        "UPDATE profiles SET
            profile_type = $3, username = $4,
            given_name = $5, family_name = $6, middle_name = $7,
            honorific_prefix = $8, honorific_suffix = $9,
            roles = $10, status = $11, visibility = $12, max_assurance = $13,
            manager_id = $14, migration_pending = $15,
            migration_started_at = $16, migration_completed_at = $17,
            updated_at = $18, revision = revision + 1
         WHERE id = $1 AND revision = $2",
    )
    .bind(profile.id)
    .bind(revision)
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
    .bind(profile.migration_started_at)
    .bind(profile.migration_completed_at)
    .bind(profile.updated_at)
    .execute(&mut **tx)
    .await
    .map(|r| r.rows_affected() == 1)
    .map_err(|e| insert_error("profile", e))
}

/// Upsert the binding of `p` to entity `entity_id`.
async fn upsert_binding(tx: &mut Tx<'_>, entity_id: Uuid, p: &Principal) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO principal_bindings (
            id, principal_id, profile_id,
            is_primary, source_field, source_email_id, source_phone_id, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (principal_id, profile_id) DO UPDATE SET
            is_primary = EXCLUDED.is_primary,
            source_field = EXCLUDED.source_field,
            source_email_id = EXCLUDED.source_email_id,
            source_phone_id = EXCLUDED.source_phone_id",
    )
    .bind(Uuid::now_v7())
    .bind(entity_id)
    .bind(p.profile_id)
    .bind(p.is_primary)
    .bind(&p.source_field)
    .bind(p.source_email_id.map(|id| id.0))
    .bind(p.source_phone_id.map(|id| id.0))
    .bind(p.created_at)
    .execute(&mut **tx)
    .await
    .map_err(storage("principal binding"))?;
    Ok(())
}

/// Record `p`'s claim. A new principal is first used here and assigned to its
/// claimant with the proof `p` carries; an existing one gains the claim and
/// keeps its assignment and proof, which only a proven transfer changes.
/// A login handle is never shared (`Conflict` when another Profile holds it).
pub(super) async fn bind_principal(tx: &mut Tx<'_>, p: &Principal) -> SidResult<()> {
    if !p.principal_type.is_contestable() {
        return bind_login_principal(tx, p).await;
    }
    let assigned = Some(p.profile_id);
    // The no-op update locks the row and returns its id.
    let entity_id: Uuid = sqlx::query_scalar(
        "INSERT INTO principals (
            id, principal_type, value, verified, verified_at, verification_expires,
            assigned_profile_id, assignment_revision, email_policy_revision,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (principal_type, value) DO UPDATE SET id = principals.id
        RETURNING id",
    )
    .bind(p.id.0)
    .bind(p.principal_type.as_str())
    .bind(&p.value)
    .bind(p.verified)
    .bind(p.verified_at)
    .bind(p.verification_expires)
    .bind(assigned)
    .bind(i64::from(assigned.is_some()))
    .bind(p.email_policy_revision)
    .bind(p.created_at)
    .bind(p.updated_at)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| super::principal_write_error("principal", e))?;
    upsert_binding(tx, entity_id, p).await
}

/// Bind a login handle, which is never shared: held by another Profile it
/// is `Conflict`, and nothing about the existing entity is changed.
async fn bind_login_principal(tx: &mut Tx<'_>, p: &Principal) -> SidResult<()> {
    let assigned = Some(p.profile_id);
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO principals (
            id, principal_type, value, verified, verified_at, verification_expires,
            assigned_profile_id, assignment_revision, email_policy_revision,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (principal_type, value) DO NOTHING
        RETURNING id",
    )
    .bind(p.id.0)
    .bind(p.principal_type.as_str())
    .bind(&p.value)
    .bind(p.verified)
    .bind(p.verified_at)
    .bind(p.verification_expires)
    .bind(assigned)
    .bind(i64::from(assigned.is_some()))
    .bind(p.email_policy_revision)
    .bind(p.created_at)
    .bind(p.updated_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| super::principal_write_error("login principal", e))?;
    let entity_id = match inserted {
        Some(id) => id,
        None => {
            let existing: Uuid = sqlx::query_scalar(
                "SELECT id FROM principals WHERE principal_type = $1 AND value = $2 FOR UPDATE",
            )
            .bind(p.principal_type.as_str())
            .bind(&p.value)
            .fetch_one(&mut **tx)
            .await
            .map_err(storage("login principal"))?;
            let other_holder: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM principal_bindings
                                WHERE principal_id = $1 AND profile_id <> $2)",
            )
            .bind(existing)
            .bind(p.profile_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(storage("login principal"))?;
            if other_holder {
                return Err(SidError::Conflict("login handle already exists".into()));
            }
            existing
        }
    };
    upsert_binding(tx, entity_id, p).await
}

/// Remove `profile_id`'s claim; the entity goes with its last claim. The
/// assigned Profile releasing its claim clears the assignment and its proof
/// without electing another claimant. `false` when there was no such claim.
pub(super) async fn unbind_principal(
    tx: &mut Tx<'_>,
    principal_id: PrincipalId,
    profile_id: ProfileId,
) -> SidResult<bool> {
    // The principal row lock orders this against a concurrent binding of the
    // same value (its upsert takes the same row), so the entity is never
    // removed under a binding committed meanwhile.
    sqlx::query("SELECT id FROM principals WHERE id = $1 FOR UPDATE")
        .bind(principal_id.0)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("lock principal"))?;
    let removed =
        sqlx::query("DELETE FROM principal_bindings WHERE principal_id = $1 AND profile_id = $2")
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
        "DELETE FROM principals p WHERE p.id = $1 \
         AND NOT EXISTS (SELECT 1 FROM principal_bindings pb WHERE pb.principal_id = p.id)",
    )
    .bind(principal_id.0)
    .execute(&mut **tx)
    .await
    .map_err(storage("delete principal"))?;
    sqlx::query(
        "UPDATE principals SET assigned_profile_id = NULL,
             assignment_revision = assignment_revision + 1,
             verified = false, verified_at = NULL, verification_expires = NULL,
             updated_at = NOW()
         WHERE id = $1 AND assigned_profile_id = $2",
    )
    .bind(principal_id.0)
    .bind(profile_id)
    .execute(&mut **tx)
    .await
    .map_err(storage("release principal"))?;
    Ok(true)
}

/// Insert `email` or update the row with its id.
pub(super) async fn upsert_email(tx: &mut Tx<'_>, email: &ProfileEmail) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_emails (
            id, profile_id, email, label, custom_label,
            is_primary, verified, verified_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            label = EXCLUDED.label,
            custom_label = EXCLUDED.custom_label,
            is_primary = EXCLUDED.is_primary,
            verified = EXCLUDED.verified,
            verified_at = EXCLUDED.verified_at,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(email.id.0)
    .bind(email.profile_id)
    .bind(&email.email)
    .bind(email.label.as_str())
    .bind(&email.custom_label)
    .bind(email.is_primary)
    .bind(email.verified)
    .bind(email.verified_at)
    .bind(email.created_at)
    .bind(email.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("profile email", e))?;
    Ok(())
}

/// Delete email `id`; only `owner`'s when given.
pub(super) async fn delete_email(
    tx: &mut Tx<'_>,
    id: ProfileEmailId,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    sqlx::query(
        "DELETE FROM profile_emails WHERE id = $1 AND ($2::uuid IS NULL OR profile_id = $2)",
    )
    .bind(id.0)
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("delete profile email"))?;
    Ok(())
}

/// Insert `phone` or update the row with its id.
pub(super) async fn upsert_phone(tx: &mut Tx<'_>, phone: &ProfilePhone) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_phones (
            id, profile_id, e164, extension, label, custom_label,
            is_primary, can_receive_sms, can_receive_fax, can_receive_voice,
            verified, verified_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (id) DO UPDATE SET
            e164 = EXCLUDED.e164,
            extension = EXCLUDED.extension,
            label = EXCLUDED.label,
            custom_label = EXCLUDED.custom_label,
            is_primary = EXCLUDED.is_primary,
            can_receive_sms = EXCLUDED.can_receive_sms,
            can_receive_fax = EXCLUDED.can_receive_fax,
            can_receive_voice = EXCLUDED.can_receive_voice,
            verified = EXCLUDED.verified,
            verified_at = EXCLUDED.verified_at,
            updated_at = EXCLUDED.updated_at",
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
    .bind(phone.verified_at)
    .bind(phone.created_at)
    .bind(phone.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("profile phone", e))?;
    Ok(())
}

/// Delete phone `id`; only `owner`'s when given.
pub(super) async fn delete_phone(
    tx: &mut Tx<'_>,
    id: ProfilePhoneId,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    sqlx::query(
        "DELETE FROM profile_phones WHERE id = $1 AND ($2::uuid IS NULL OR profile_id = $2)",
    )
    .bind(id.0)
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("delete profile phone"))?;
    Ok(())
}

/// Set one metadata key of a profile.
pub(super) async fn set_metadata(tx: &mut Tx<'_>, metadata: &ProfileMetadata) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO profile_metadata (profile_id, key, value, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (profile_id, key) DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(metadata.profile_id)
    .bind(&metadata.key)
    .bind(&metadata.value)
    .bind(metadata.created_at)
    .bind(metadata.updated_at)
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
    tx: &mut Tx<'_>,
    profile_id: ProfileId,
    key: &str,
) -> SidResult<()> {
    sqlx::query("DELETE FROM profile_metadata WHERE profile_id = $1 AND key = $2")
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
    tx: &mut Tx<'_>,
    profile_id: ProfileId,
    end: &SessionEnd,
    ctx: &mut MutationContext,
) -> SidResult<Vec<Session>> {
    let sessions: Vec<Session> = sqlx::query_as::<_, crate::pg_row::SessionRow>(
        "DELETE FROM sessions WHERE profile_id = $1 RETURNING *",
    )
    .bind(profile_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("end sessions"))?
    .into_iter()
    .map(|row| row.into_domain())
    .collect::<SidResult<_>>()?;
    for ended in &sessions {
        ctx.work
            .extend(end.owed(ended.id, ended.profile_id, ended.client_id.as_deref()));
    }
    Ok(sessions)
}

/// Revoke every active PAT of `profile_id`; returns how many.
pub(super) async fn revoke_pats(
    tx: &mut Tx<'_>,
    profile_id: ProfileId,
    revoked_by: &str,
) -> SidResult<u64> {
    sqlx::query(
        "UPDATE personal_access_tokens SET status = 'revoked', revoked_at = NOW(), revoked_by = $1
        WHERE profile_id = $2 AND status = 'active'",
    )
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
            "INSERT INTO groups (id, project_id, parent_group_id, name, description, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            $tail
        )
    };
}

async fn write_group(tx: &mut Tx<'_>, g: &Group, sql: &'static str) -> Result<u64, sqlx::Error> {
    sqlx::query(sql)
        .bind(g.id.0)
        .bind(g.project_id.0)
        .bind(g.parent_group_id.map(|gid| gid.0))
        .bind(&g.name)
        .bind(&g.description)
        .bind(g.created_at)
        .bind(g.updated_at)
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected())
}

/// Insert `g`; an existing id or name is a `Conflict`.
pub(super) async fn insert_group(tx: &mut Tx<'_>, g: &Group) -> SidResult<()> {
    write_group(tx, g, group_insert!(""))
        .await
        .map_err(|e| insert_error("group", e))?;
    Ok(())
}

/// Write the name and description of the stored group `g`; false when it
/// does not exist.
async fn update_group(tx: &mut Tx<'_>, g: &Group) -> SidResult<bool> {
    sqlx::query("UPDATE groups SET name = $2, description = $3, updated_at = $4 WHERE id = $1")
        .bind(g.id.0)
        .bind(&g.name)
        .bind(&g.description)
        .bind(g.updated_at)
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected() == 1)
        .map_err(|e| insert_error("group", e))
}

/// Add a member (a repeat is no change). A Profile that granted the group a
/// role under an administrative assignment never joins it: the grant would
/// reach its own grantor.
pub(super) async fn add_member(tx: &mut Tx<'_>, member: &GroupMember) -> SidResult<()> {
    // Exclusive lock on the group: a fenced grant to it takes it FOR SHARE,
    // so neither commits unseen by the other.
    sqlx::query("SELECT 1 FROM groups WHERE id = $1 FOR UPDATE")
        .bind(member.group_id.0)
        .execute(&mut **tx)
        .await
        .map_err(storage("lock group"))?;
    let granted: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM role_assignments
         WHERE group_id = $1 AND basis_assignment_id IS NOT NULL AND granted_by = $2
         LIMIT 1",
    )
    .bind(member.group_id.0)
    .bind(format!("user:{}", member.profile_id))
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("check group grants"))?;
    if granted.is_some() {
        return Err(SidError::PolicyViolation(format!(
            "profile {} granted this group a role; it cannot join the group",
            member.profile_id
        )));
    }
    sqlx::query(
        "INSERT INTO group_members (group_id, profile_id, added_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (group_id, profile_id) DO NOTHING",
    )
    .bind(member.group_id.0)
    .bind(member.profile_id)
    .bind(member.added_at)
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
    tx: &mut Tx<'_>,
    group_id: GroupId,
    profile_id: ProfileId,
) -> SidResult<()> {
    sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND profile_id = $2")
        .bind(group_id.0)
        .bind(profile_id)
        .execute(&mut **tx)
        .await
        .map_err(storage("remove group member"))?;
    Ok(())
}

impl PostgresBackend {
    pub(super) async fn write_directory_user_impl(
        &self,
        write: &DirectoryUserWrite,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let profile_id = write.profile_id();
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        match write.mode {
            DirectoryWriteMode::Create => insert_profile(&mut tx, &write.profile).await?,
            DirectoryWriteMode::Update => {
                // The update locks the row for the rest of the write; a missing
                // account or one changed since it was read refuses the whole write.
                if !update_profile(&mut tx, &write.profile).await? {
                    let exists: Option<ProfileId> =
                        sqlx::query_scalar("SELECT id FROM profiles WHERE id = $1")
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
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ended)
    }

    pub(super) async fn write_directory_group_impl(
        &self,
        write: &DirectoryGroupWrite,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let group_id = write.group.id;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
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
        Self::audit_in_tx(&mut tx, &format!("group:{}", group_id.0), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }
}
