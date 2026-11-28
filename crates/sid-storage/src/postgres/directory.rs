// SPDX-License-Identifier: AGPL-3.0-only
//! Account, contact, principal and group writes inside a caller's
//! transaction, and the directory (SCIM) writes built from them: one
//! request's changes commit together with its audit entry and owed work.

use sid_core::models::{
    DirectoryGroupWrite, DirectoryResource, DirectoryRights, DirectorySource, DirectoryUserId,
    DirectoryUserWrite, DirectoryWriteMode, Group, GroupId, GroupMember, ManagementOutcome,
    MutationContext, Principal, PrincipalId, PrincipalType, Profile, ProfileEmail, ProfileEmailId,
    ProfileId, ProfileMetadata, ProfilePhone, ProfilePhoneId, ProvisioningConnectorId, Session,
    SessionEnd, SourceWrite,
};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::{PostgresBackend, insert_error};
use crate::pg_time::ToPg;

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
                created_at, updated_at, revision
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
            $tail
        )
    };
}

async fn write_profile(
    tx: &mut Tx<'_>,
    profile: &Profile,
    revision: i64,
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
        .bind(profile.migration_started_at.pg())
        .bind(profile.migration_completed_at.pg())
        .bind(profile.created_at.pg())
        .bind(profile.updated_at.pg())
        // As given: a restored profile keeps the revision stale copies of it
        // are checked against.
        .bind(revision)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Insert `profile`; an existing id or user name is `Conflict`.
pub(super) async fn insert_profile(tx: &mut Tx<'_>, profile: &Profile) -> SidResult<()> {
    profile.check_reference()?;
    let revision = i64::try_from(profile.revision)
        .map_err(|e| SidError::Validation(format!("profile revision: {e}")))?;
    write_profile(tx, profile, revision, profile_insert!(""))
        .await
        .map_err(|e| insert_error("profile", e))?;
    // Every account is a user of the directory: its resource is assigned
    // with it, under an identifier of its own.
    sqlx::query("INSERT INTO directory_users (id, profile_id) VALUES ($1, $2)")
        .bind(Uuid::now_v7())
        .bind(profile.id)
        .execute(&mut **tx)
        .await
        .map_err(storage("directory resource"))?;
    Ok(())
}

pub(super) fn resource(row: &sqlx::postgres::PgRow) -> SidResult<DirectoryResource> {
    use sqlx::Row;
    let read = |e: sqlx::Error| SidError::Storage(format!("directory resource row: {e}"));
    let revision: i64 = row.try_get("revision").map_err(read)?;
    let deleted_at: Option<crate::pg_time::PgTime> = row.try_get("deleted_at").map_err(read)?;
    Ok(DirectoryResource {
        id: DirectoryUserId(row.try_get("id").map_err(read)?),
        profile_id: row.try_get("profile_id").map_err(read)?,
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("directory resource revision: {e}")))?,
        deleted_at: deleted_at.map(Into::into),
        active: row.try_get("active").map_err(read)?,
    })
}

/// Hold the live resource `id` of `profile_id` for the rest of the write,
/// deleting it when `delete` and setting the relationship's activity when
/// `active` is given; anything else (unknown, deleted, another account's) is
/// `NotFound`.
async fn hold_resource(
    tx: &mut Tx<'_>,
    id: DirectoryUserId,
    profile_id: ProfileId,
    delete: bool,
    active: Option<bool>,
) -> SidResult<()> {
    let held = if delete {
        sqlx::query(
            "UPDATE directory_users SET deleted_at = now(), revision = revision + 1
             WHERE id = $1 AND profile_id = $2 AND deleted_at IS NULL",
        )
        .bind(id.0)
        .bind(profile_id)
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected() == 1)
    } else {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM directory_users
             WHERE id = $1 AND profile_id = $2 AND deleted_at IS NULL FOR SHARE",
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
        sqlx::query("UPDATE directory_user_sources SET retired = TRUE WHERE resource_id = $1")
            .bind(id.0)
            .execute(&mut **tx)
            .await
            .map_err(storage("directory sources"))?;
    } else if let Some(active) = active {
        // A change of the relationship's state is a change of the resource.
        sqlx::query(
            "UPDATE directory_users SET active = $2, revision = revision + 1
             WHERE id = $1 AND active <> $2",
        )
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
pub(super) fn rights(bits: i32) -> SidResult<DirectoryRights> {
    DirectoryRights::from_bits(bits)
        .ok_or_else(|| SidError::Storage(format!("directory rights: unknown bits in {bits}")))
}

pub(super) fn source(row: &sqlx::postgres::PgRow) -> SidResult<DirectorySource> {
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
    tx: &mut Tx<'_>,
    profile_id: ProfileId,
    source: &SourceWrite,
) -> SidResult<()> {
    sqlx::query(
        // The creator is recorded as such and assigned nothing by creating.
        "INSERT INTO directory_user_sources (resource_id, connector_id, external_id, created)
         SELECT id, $2, $3, TRUE FROM directory_users
         WHERE profile_id = $1 AND deleted_at IS NULL",
    )
    .bind(profile_id)
    .bind(source.connector)
    .bind(source.external_id.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(source_error)?;
    Ok(())
}

/// Give the correlation the write's source already has with `resource` the
/// identifier the write carries. A source without one is not given one: no
/// source takes a resource over by writing to it.
async fn update_source(
    tx: &mut Tx<'_>,
    resource: DirectoryUserId,
    source: &SourceWrite,
) -> SidResult<()> {
    sqlx::query(
        "UPDATE directory_user_sources SET external_id = $3
         WHERE resource_id = $1 AND connector_id = $2 AND NOT retired",
    )
    .bind(resource.0)
    .bind(source.connector)
    .bind(source.external_id.as_deref())
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
pub(super) async fn update_profile(tx: &mut Tx<'_>, profile: &Profile) -> SidResult<bool> {
    profile.check_reference()?;
    let revision = i64::try_from(profile.revision)
        .map_err(|e| SidError::Validation(format!("profile revision: {e}")))?;
    let reference = !profile.profile_type.is_local();
    let written = sqlx::query(
        "UPDATE profiles SET
            profile_type = $3, username = $4,
            given_name = $5, family_name = $6, middle_name = $7,
            honorific_prefix = $8, honorific_suffix = $9,
            roles = $10, status = $11, visibility = $12, max_assurance = $13,
            manager_id = $14, migration_pending = $15,
            migration_started_at = $16, migration_completed_at = $17,
            updated_at = $18, revision = revision + 1
         WHERE id = $1 AND revision = $2 AND (profile_type = 'federated') = $19",
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
    .bind(profile.migration_started_at.pg())
    .bind(profile.migration_completed_at.pg())
    .bind(profile.updated_at.pg())
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
        "SELECT profile_type = 'federated' FROM profiles WHERE id = $1 AND revision = $2",
    )
    .bind(profile.id)
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("profile kind"))?;
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
    .bind(p.created_at.pg())
    .execute(&mut **tx)
    .await
    .map_err(storage("principal binding"))?;
    Ok(())
}

impl PostgresBackend {
    /// Record `p`'s claim in `tx`, a host's own transaction that commits it
    /// with the host's state (a confirmed federation association), as
    /// [`sid_plugin::IdentityStore::save_principal`] records one.
    pub async fn bind_principal_in_tx(tx: &mut Tx<'_>, p: &Principal) -> SidResult<()> {
        bind_principal(tx, p).await
    }
}

/// Record `p`'s claim. A new principal is first used here and assigned to its
/// claimant with the proof `p` carries; an existing one gains the claim and
/// keeps its assignment and proof, which only a proven transfer changes.
/// A login handle is never shared (`Conflict` when another Profile holds it).
pub(super) async fn bind_principal(tx: &mut Tx<'_>, p: &Principal) -> SidResult<()> {
    // A federated reference is reached only by the subject its trusted
    // issuer names: it claims no email, phone or user name here.
    if p.principal_type != PrincipalType::FederatedSubject {
        let reference: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM profiles WHERE id = $1 AND profile_type = 'federated'
             )",
        )
        .bind(p.profile_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage("principal claimant"))?;
        if reference {
            return Err(SidError::InvalidState(
                crate::FEDERATED_HOLDS_NO_LOGIN_NAME.into(),
            ));
        }
    }
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
    .bind(p.verified_at.pg())
    .bind(p.verification_expires.pg())
    .bind(assigned)
    .bind(i64::from(assigned.is_some()))
    .bind(p.email_policy_revision)
    .bind(p.created_at.pg())
    .bind(p.updated_at.pg())
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
    .bind(p.verified_at.pg())
    .bind(p.verification_expires.pg())
    .bind(assigned)
    .bind(i64::from(assigned.is_some()))
    .bind(p.email_policy_revision)
    .bind(p.created_at.pg())
    .bind(p.updated_at.pg())
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

/// Lock the profile row before writing a primary contact, as every primary
/// move does, so a reader share-locking the profile to hold its primary
/// contacts as read waits for this write.
async fn lock_profile_for_primary(tx: &mut Tx<'_>, profile: ProfileId) -> SidResult<()> {
    sqlx::query("SELECT 1 FROM profiles WHERE id = $1 FOR NO KEY UPDATE")
        .bind(profile)
        .execute(&mut **tx)
        .await
        .map_err(storage("lock profile"))?;
    Ok(())
}

/// Insert `email` or update the row with its id.
pub(super) async fn upsert_email(tx: &mut Tx<'_>, email: &ProfileEmail) -> SidResult<()> {
    if email.is_primary {
        lock_profile_for_primary(tx, email.profile_id).await?;
    }
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
    .bind(email.verified_at.pg())
    .bind(email.created_at.pg())
    .bind(email.updated_at.pg())
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
    if phone.is_primary {
        lock_profile_for_primary(tx, phone.profile_id).await?;
    }
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
    .bind(phone.verified_at.pg())
    .bind(phone.created_at.pg())
    .bind(phone.updated_at.pg())
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
    .bind(metadata.created_at.pg())
    .bind(metadata.updated_at.pg())
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
        .bind(g.id)
        .bind(g.project_id)
        .bind(g.parent_group_id)
        .bind(&g.name)
        .bind(&g.description)
        .bind(g.created_at.pg())
        .bind(g.updated_at.pg())
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
        .bind(g.id)
        .bind(&g.name)
        .bind(&g.description)
        .bind(g.updated_at.pg())
        .execute(&mut **tx)
        .await
        .map(|r| r.rows_affected() == 1)
        .map_err(|e| insert_error("group", e))
}

/// The stored origin of an assignment made by `source`: the nil UUID stands
/// for one made locally.
fn origin(source: Option<sid_core::models::ProvisioningConnectorId>) -> Uuid {
    source.map_or(Uuid::nil(), |connector| connector.into_uuid())
}

/// Make `group_members` agree with the assignments of `profile_id` to
/// `group_id`: a member while any assignment stands. A local one always
/// does; a connector's does while the resource it rests on is live and
/// active.
async fn settle_member(
    tx: &mut Tx<'_>,
    group_id: GroupId,
    profile_id: ProfileId,
    added_at: jiff::Timestamp,
) -> SidResult<()> {
    macro_rules! standing {
        () => {
            "(SELECT 1 FROM group_member_origins o
              LEFT JOIN directory_users d ON d.id = o.resource_id
              WHERE o.group_id = $1 AND o.profile_id = $2
                AND (o.resource_id IS NULL OR (d.deleted_at IS NULL AND d.active)))"
        };
    }
    sqlx::query(concat!(
        "INSERT INTO group_members (group_id, profile_id, added_at)
         SELECT $1, $2, $3 WHERE EXISTS ",
        standing!(),
        " ON CONFLICT (group_id, profile_id) DO NOTHING"
    ))
    .bind(group_id)
    .bind(profile_id)
    .bind(added_at.pg())
    .execute(&mut **tx)
    .await
    .map_err(member_error)?;
    sqlx::query(concat!(
        "DELETE FROM group_members WHERE group_id = $1 AND profile_id = $2
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
async fn settle_resource_members(tx: &mut Tx<'_>, resource: DirectoryUserId) -> SidResult<()> {
    let resting: Vec<(GroupId, ProfileId)> = sqlx::query_as(
        "SELECT group_id, profile_id FROM group_member_origins WHERE resource_id = $1",
    )
    .bind(resource.0)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("memberships of a directory resource"))?;
    for (group_id, profile_id) in resting {
        settle_member(tx, group_id, profile_id, jiff::Timestamp::now()).await?;
    }
    Ok(())
}

/// Record the assignment `member` made by `source` (a repeat is no change)
/// and settle the membership. A connector's assignment rests on the
/// member's live directory resource. A grant the new member made to the
/// group stays withheld from it (`RoleAssignment::withheld_from`), so joining
/// needs no check against the group's grants.
pub(super) async fn add_member(
    tx: &mut Tx<'_>,
    member: &GroupMember,
    source: Option<sid_core::models::ProvisioningConnectorId>,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO group_member_origins (group_id, profile_id, connector_id, resource_id, added_at)
         VALUES ($1, $2, $3,
            CASE WHEN $4 THEN (SELECT d.id FROM directory_users d
                               WHERE d.profile_id = $2 AND d.deleted_at IS NULL) END,
            $5)
         ON CONFLICT (group_id, profile_id, connector_id) DO NOTHING",
    )
    .bind(member.group_id)
    .bind(member.profile_id)
    .bind(origin(source))
    .bind(source.is_some())
    .bind(member.added_at.pg())
    .execute(&mut **tx)
    .await
    .map_err(member_error)?;
    settle_member(tx, member.group_id, member.profile_id, member.added_at).await
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
    tx: &mut Tx<'_>,
    group_id: GroupId,
    profile_id: ProfileId,
    source: Option<sid_core::models::ProvisioningConnectorId>,
) -> SidResult<()> {
    sqlx::query(
        "DELETE FROM group_member_origins
         WHERE group_id = $1 AND profile_id = $2 AND connector_id = $3",
    )
    .bind(group_id)
    .bind(profile_id)
    .bind(origin(source))
    .execute(&mut **tx)
    .await
    .map_err(storage("remove group member"))?;
    settle_member(tx, group_id, profile_id, jiff::Timestamp::now()).await
}

impl PostgresBackend {
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
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
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
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ended)
    }

    pub(super) async fn find_directory_user_impl(
        &self,
        id: DirectoryUserId,
    ) -> SidResult<Option<DirectoryResource>> {
        sqlx::query(
            "SELECT id, profile_id, revision, deleted_at, active FROM directory_users WHERE id = $1",
        )
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
        let ids: Vec<Uuid> = profiles.iter().map(|p| Uuid::from(*p)).collect();
        sqlx::query(
            "SELECT id, profile_id, revision, deleted_at, active FROM directory_users
             WHERE profile_id = ANY($1) AND deleted_at IS NULL ORDER BY profile_id",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(storage("directory resources"))?
        .iter()
        .map(resource)
        .collect()
    }

    pub(super) async fn directory_sources_impl(
        &self,
        connector: Option<ProvisioningConnectorId>,
        resources: &[DirectoryUserId],
    ) -> SidResult<Vec<DirectorySource>> {
        let ids: Vec<Uuid> = resources.iter().map(|r| r.0).collect();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SOURCE} FROM directory_user_sources
             WHERE resource_id = ANY($1) AND NOT retired
               AND ($2::uuid IS NULL OR connector_id = $2)
             ORDER BY resource_id, connector_id"
        )))
        .bind(ids)
        .bind(connector)
        .fetch_all(&self.pool)
        .await
        .map_err(storage("directory sources"))?
        .iter()
        .map(source)
        .collect()
    }

    pub(super) async fn find_directory_source_impl(
        &self,
        connector: ProvisioningConnectorId,
        external_id: &str,
    ) -> SidResult<Option<DirectorySource>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SOURCE} FROM directory_user_sources
             WHERE connector_id = $1 AND external_id = $2 AND NOT retired"
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

    pub(super) async fn export_directory_users_impl(&self) -> SidResult<Vec<DirectoryResource>> {
        sqlx::query(
            "SELECT id, profile_id, revision, deleted_at, active FROM directory_users ORDER BY profile_id, id",
        )
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
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // The resource assigned when the account was restored gives way to
        // the ones the account had.
        let ids: Vec<Uuid> = resources.iter().map(|r| r.id.0).collect();
        sqlx::query("DELETE FROM directory_users WHERE profile_id = $1 AND NOT (id = ANY($2))")
            .bind(profile_id)
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(storage("replace directory resources"))?;
        for r in resources {
            let revision = i64::try_from(r.revision)
                .map_err(|e| SidError::Validation(format!("directory resource revision: {e}")))?;
            let written = sqlx::query(
                "INSERT INTO directory_users (id, profile_id, revision, deleted_at, active)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (id) DO UPDATE SET revision = EXCLUDED.revision,
                    deleted_at = EXCLUDED.deleted_at, active = EXCLUDED.active
                 WHERE directory_users.profile_id = EXCLUDED.profile_id",
            )
            .bind(r.id.0)
            .bind(profile_id)
            .bind(revision)
            .bind(r.deleted_at.pg())
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
        sqlx::query("DELETE FROM directory_user_sources WHERE resource_id = ANY($1)")
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(storage("replace directory sources"))?;
        for s in sources {
            sqlx::query(
                "INSERT INTO directory_user_sources
                     (resource_id, connector_id, external_id, retired, created, managed)
                 VALUES ($1, $2, $3, $4, $5, $6)",
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
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    pub(super) async fn set_directory_rights_impl(
        &self,
        connector: ProvisioningConnectorId,
        revision: i64,
        rights: DirectoryRights,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // The revision moves with the selection: a write the connector was
        // authorized for before it no longer commits.
        let moved = sqlx::query(
            "UPDATE provisioning_connectors
             SET directory_rights = $3, revision = revision + 1, updated_at = NOW()
             WHERE id = $1 AND revision = $2",
        )
        .bind(connector)
        .bind(revision)
        .bind(rights.bits())
        .execute(&mut *tx)
        .await
        .map_err(storage("set directory rights"))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("provisioning_connector:{connector}"), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(true)
    }

    pub(super) async fn manage_directory_user_impl(
        &self,
        connector: ProvisioningConnectorId,
        revision: i64,
        resource: DirectoryUserId,
        rights: DirectoryRights,
        ctx: MutationContext,
    ) -> SidResult<ManagementOutcome> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // The connector's row is held at the revision the command names: a
        // command based on an older one changes nothing.
        let current = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM provisioning_connectors WHERE id = $1 AND revision = $2 FOR UPDATE",
        )
        .bind(connector)
        .bind(revision)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("hold connector"))?
        .is_some();
        if !current {
            return Ok(ManagementOutcome::Stale);
        }
        let live = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM directory_users WHERE id = $1 AND deleted_at IS NULL FOR SHARE",
        )
        .bind(resource.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("directory resource"))?
        .is_some();
        if !live {
            return Err(SidError::NotFound(format!("directory user {resource}")));
        }
        if rights.is_empty() {
            let withdrawn = sqlx::query(
                "UPDATE directory_user_sources SET managed = 0
                 WHERE resource_id = $1 AND connector_id = $2 AND NOT retired AND managed <> 0",
            )
            .bind(resource.0)
            .bind(connector)
            .execute(&mut *tx)
            .await
            .map_err(storage("withdraw directory user"))?
            .rows_affected();
            if withdrawn == 0 {
                return Ok(ManagementOutcome::NothingToWithdraw);
            }
        } else {
            // A connector that already knows the user keeps its identifier.
            sqlx::query(
                "INSERT INTO directory_user_sources (resource_id, connector_id, managed)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (resource_id, connector_id)
                 DO UPDATE SET managed = excluded.managed",
            )
            .bind(resource.0)
            .bind(connector)
            .bind(rights.bits())
            .execute(&mut *tx)
            .await
            .map_err(storage("assign directory user"))?;
        }
        Self::bump_connector_revision(&mut tx, connector).await?;
        Self::audit_in_tx(&mut tx, &format!("provisioning_connector:{connector}"), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ManagementOutcome::Applied)
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
        Self::audit_in_tx(&mut tx, &format!("group:{group_id}"), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }
}
