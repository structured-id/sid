// SPDX-License-Identifier: AGPL-3.0-only
//! Profile, Principal, Credential, and ProfileMetadata operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        Credential, CredentialData, CredentialId, CredentialType, EmailLabel, HistoryCommit,
        MutationContext, NewRegistration, PhoneLabel, Principal, PrincipalId, PrincipalType,
        Profile, ProfileEmail, ProfileEmailId, ProfileId, ProfileMetadata, ProfilePhone,
        ProfilePhoneId,
    },
};
use sqlx::Row;

use crate::ADMIN_EXISTS_SQL;

use super::{
    SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, parse_dt,
    parse_dt_opt, parsed_col,
};

/// Insert a new credential; an existing id is a `Conflict`, never an update.
pub(super) async fn insert_credential<'e, E>(exec: E, credential: &Credential) -> SidResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let (verified, policy_version, artifact) =
        crate::policy_evidence::columns(&credential.policy_evidence)?;
    sqlx::query(
        "INSERT INTO credentials (id, profile_id, credential_type, status, data, label, policy_version, zkpp_verified, opaque_curve, legacy_algorithm, opaque_credential_identifier, zkpp_artifact, created_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(credential.id.0.to_string())
    .bind(credential.profile_id)
    .bind(credential.credential_type.as_str())
    .bind(credential.status.as_str())
    .bind(credential.data.expose())
    .bind(&credential.label)
    .bind(policy_version)
    .bind(verified)
    .bind(credential.opaque_curve.map(|c| c as i32))
    .bind(&credential.legacy_algorithm)
    .bind(credential.opaque_credential_identifier.map(|id| id.to_vec()))
    .bind(artifact)
    .bind(fmt_dt(&credential.created_at))
    .bind(fmt_dt_opt(credential.last_used_at))
    .execute(exec)
    .await
    .map_err(|e| insert_error("credential", e))?;
    Ok(())
}

/// Replace the profile's credentials of the types `credential` replaces (its
/// one password, its recovery-code set) with it, inside `tx`.
async fn replace_credential_in_tx(
    tx: &mut super::WriteTx,
    credential: &Credential,
) -> SidResult<()> {
    let replaced = credential.credential_type.replaces();
    if replaced.is_empty() {
        return Err(SidError::Validation(format!(
            "a {} credential is added, not replaced",
            credential.credential_type.as_str()
        )));
    }
    for kind in replaced {
        sqlx::query("DELETE FROM credentials WHERE profile_id = ? AND credential_type = ?")
            .bind(credential.profile_id)
            .bind(kind.as_str())
            .execute(&mut **tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
    }
    insert_credential(&mut **tx, credential).await
}

// ─── Row → Model converters ───

/// An unknown type, status, assurance or visibility is an error: reading an
/// unknown status as active would reopen a closed or suspended account.
fn row_to_profile(row: &sqlx::sqlite::SqliteRow) -> SidResult<Profile> {
    let roles: String = col(row, "roles")?;
    let revision: i64 = col(row, "revision")?;
    Ok(Profile {
        id: col(row, "id")?,
        profile_type: parsed_col(row, "profile_type")?,
        username: col(row, "username")?,
        given_name: col(row, "given_name")?,
        family_name: col(row, "family_name")?,
        middle_name: col(row, "middle_name")?,
        honorific_prefix: col(row, "honorific_prefix")?,
        honorific_suffix: col(row, "honorific_suffix")?,
        roles: roles.split_whitespace().map(String::from).collect(),
        status: parsed_col(row, "status")?,
        max_assurance: parsed_col(row, "max_assurance")?,
        visibility: parsed_col(row, "visibility")?,
        manager_id: col(row, "manager_id")?,
        migration_pending: col(row, "migration_pending")?,
        migration_started_at: dt_col_opt(row, "migration_started_at")?,
        migration_completed_at: dt_col_opt(row, "migration_completed_at")?,
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

/// Convert a JOINed row (principals + principal_bindings) to Principal domain model.
/// Expected aliases: pr.* for principal columns, pb.* for binding columns.
/// Query must SELECT pr.*, pb.profile_id AS pb_profile_id,
/// pb.is_primary AS pb_is_primary, pb.source_field AS pb_source_field, etc.
/// The principal is returned as its claiming Profile sees it (proof only for
/// the holder).
fn row_to_principal(row: &sqlx::sqlite::SqliteRow) -> SidResult<Principal> {
    let principal = Principal {
        id: principal_id(row)?,
        profile_id: col(row, "pb_profile_id")?,
        principal_type: principal_type(row)?,
        value: row.get("value"),
        verified: row.get::<bool, _>("verified"),
        verified_at: parse_dt_opt(
            row.try_get::<Option<String>, _>("verified_at")
                .ok()
                .flatten(),
        ),
        verification_expires: parse_dt_opt(
            row.try_get::<Option<String>, _>("verification_expires")
                .ok()
                .flatten(),
        ),
        assigned_profile_id: col(row, "assigned_profile_id")?,
        assignment_revision: col(row, "assignment_revision")?,
        email_policy_revision: col(row, "email_policy_revision")?,
        is_primary: row.try_get::<bool, _>("pb_is_primary").unwrap_or(false),
        source_field: row
            .try_get::<Option<String>, _>("pb_source_field")
            .unwrap_or(None),
        source_email_id: row
            .try_get::<Option<String>, _>("pb_source_email_id")
            .ok()
            .flatten()
            .and_then(|s| uuid::Uuid::parse_str(&s).ok())
            .map(ProfileEmailId),
        source_phone_id: row
            .try_get::<Option<String>, _>("pb_source_phone_id")
            .ok()
            .flatten()
            .and_then(|s| uuid::Uuid::parse_str(&s).ok())
            .map(ProfilePhoneId),
        created_at: parse_dt(&row.get::<String, _>("created_at")),
        updated_at: parse_dt(&row.get::<String, _>("updated_at")),
    };
    Ok(principal.as_seen_by_subject())
}

fn principal_id(row: &sqlx::sqlite::SqliteRow) -> SidResult<PrincipalId> {
    let id: String = col(row, "id")?;
    uuid::Uuid::parse_str(&id)
        .map(PrincipalId)
        .map_err(|e| SidError::Storage(format!("principal id: {e}")))
}

fn principal_type(row: &sqlx::sqlite::SqliteRow) -> SidResult<PrincipalType> {
    col::<String>(row, "principal_type")?
        .parse()
        .map_err(|e| SidError::Storage(format!("principal: {e}")))
}

fn row_to_credential(row: &sqlx::sqlite::SqliteRow) -> SidResult<Credential> {
    use sid_core::models::credential::CredentialStatus;

    // A type, status or id this build cannot read is refused: read as a
    // default it would sign in as a password or stay active after revocation.
    let credential_type: CredentialType = row
        .get::<String, _>("credential_type")
        .parse()
        .map_err(SidError::Storage)?;
    let status: CredentialStatus = row
        .get::<String, _>("status")
        .parse()
        .map_err(SidError::Storage)?;

    let id_str: String = row.get("id");
    let id = uuid::Uuid::parse_str(&id_str)
        .map_err(|e| SidError::Storage(format!("credential id {id_str}: {e}")))?;
    let data: Vec<u8> = row.get("data");

    Ok(Credential {
        id: CredentialId(id),
        profile_id: col(row, "profile_id")?,
        credential_type,
        status,
        data: CredentialData::from(data),
        label: row.get("label"),
        created_at: parse_dt(&row.get::<String, _>("created_at")),
        last_used_at: parse_dt_opt(row.get("last_used_at")),
        policy_evidence: crate::policy_evidence::from_columns(
            row.get::<bool, _>("zkpp_verified"),
            row.get::<Option<i32>, _>("policy_version"),
            row.get::<Option<Vec<u8>>, _>("zkpp_artifact"),
        )?,
        opaque_curve: row.get::<Option<i32>, _>("opaque_curve").map(|v| v as u8),
        opaque_credential_identifier: row
            .get::<Option<Vec<u8>>, _>("opaque_credential_identifier")
            .map(|bytes| {
                <[u8; 16]>::try_from(bytes).map_err(|_| {
                    SidError::Storage("column opaque_credential_identifier: not 16 bytes".into())
                })
            })
            .transpose()?,
        legacy_algorithm: row.get("legacy_algorithm"),
    })
}

fn row_to_profile_metadata(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProfileMetadata> {
    let value_str: String = row.get("value");
    let value: serde_json::Value =
        serde_json::from_str(&value_str).unwrap_or(serde_json::Value::Null);

    Ok(ProfileMetadata {
        profile_id: col(row, "profile_id")?,
        key: row.get("key"),
        value,
        created_at: parse_dt(&row.get::<String, _>("created_at")),
        updated_at: parse_dt(&row.get::<String, _>("updated_at")),
    })
}

fn row_to_profile_phone(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProfilePhone> {
    let id_str: String = row.get("id");
    Ok(ProfilePhone {
        id: ProfilePhoneId(uuid::Uuid::parse_str(&id_str).unwrap_or_default()),
        profile_id: col(row, "profile_id")?,
        e164: row.get::<i64, _>("e164") as u64,
        extension: row.get::<Option<i32>, _>("extension").map(|e| e as u32),
        label: PhoneLabel::from_str_lossy(&row.get::<String, _>("label")),
        custom_label: row.get("custom_label"),
        is_primary: row.get::<bool, _>("is_primary"),
        can_receive_sms: row.get::<bool, _>("can_receive_sms"),
        can_receive_fax: row.get::<bool, _>("can_receive_fax"),
        can_receive_voice: row.get::<bool, _>("can_receive_voice"),
        verified: row.get::<bool, _>("verified"),
        verified_at: parse_dt_opt(
            row.try_get::<Option<String>, _>("verified_at")
                .ok()
                .flatten(),
        ),
        created_at: parse_dt(&row.get::<String, _>("created_at")),
        updated_at: parse_dt(&row.get::<String, _>("updated_at")),
    })
}

fn row_to_profile_email(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProfileEmail> {
    let id_str: String = row.get("id");
    Ok(ProfileEmail {
        id: ProfileEmailId(uuid::Uuid::parse_str(&id_str).unwrap_or_default()),
        profile_id: col(row, "profile_id")?,
        email: row.get("email"),
        label: EmailLabel::from_str_lossy(&row.get::<String, _>("label")),
        custom_label: row.get("custom_label"),
        is_primary: row.get::<bool, _>("is_primary"),
        verified: row.get::<bool, _>("verified"),
        verified_at: parse_dt_opt(
            row.try_get::<Option<String>, _>("verified_at")
                .ok()
                .flatten(),
        ),
        created_at: parse_dt(&row.get::<String, _>("created_at")),
        updated_at: parse_dt(&row.get::<String, _>("updated_at")),
    })
}

// ─── SqliteBackend impl methods ───

impl SqliteBackend {
    // === Profile ===

    pub(crate) async fn get_profile_impl(&self, id: ProfileId) -> SidResult<Option<Profile>> {
        let row = sqlx::query("SELECT * FROM profiles WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile).transpose()
    }

    pub(crate) async fn get_profile_by_username_impl(
        &self,
        username: &str,
    ) -> SidResult<Option<Profile>> {
        let row = sqlx::query("SELECT * FROM profiles WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile).transpose()
    }

    pub(crate) async fn get_profile_by_email_impl(
        &self,
        email: &str,
    ) -> SidResult<Option<Profile>> {
        let row = sqlx::query(
            "SELECT p.* FROM profiles p
             INNER JOIN profile_emails pe ON pe.profile_id = p.id
             WHERE pe.email = ?",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile).transpose()
    }

    pub(crate) async fn create_profile_impl(
        &self,
        profile: &Profile,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::insert_profile(&mut tx, profile).await?;
        Self::commit_mutation(tx, &format!("profile:{}", profile.id), audit).await
    }

    pub(crate) async fn update_profile_impl(
        &self,
        profile: &Profile,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !super::directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("profile:{}", profile.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn delete_profile_impl(
        &self,
        id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM profiles WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("profile:{id}"), audit).await
    }

    pub(crate) async fn register_profile_impl(
        &self,
        registration: &NewRegistration,
        audit: MutationContext,
    ) -> SidResult<()> {
        let NewRegistration {
            profile,
            principal,
            email,
            phone,
            credential,
            source,
            instance_claim,
            history,
        } = registration;
        let mut tx = self.begin_write().await?;

        // The first administrator's registration consumes the claim first; a
        // refusal drops the transaction with nothing written.
        if let Some(claim) = instance_claim {
            let consumed =
                sqlx::query("DELETE FROM instance_secrets WHERE name = ? AND sealed = ?")
                    .bind(sid_core::models::InstanceSecret::AdminClaim.as_str())
                    .bind(claim)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| SidError::Storage(format!("consume admin claim: {e}")))?
                    .rows_affected()
                    == 1;
            let admin_exists: bool = sqlx::query_scalar(ADMIN_EXISTS_SQL)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("admin exists: {e}")))?;
            if !consumed || admin_exists {
                return Err(SidError::InvalidState(
                    "the installation has no open administrator claim".into(),
                ));
            }
        }

        // Principal first: the (principal_type, value) key decides a registration race,
        // and a taken identifier drops the transaction with nothing written.
        // A new identifier is first used here: it is assigned to the registrant.
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO principals (id, principal_type, value, verified, verified_at, verification_expires, assigned_profile_id, assignment_revision, email_policy_revision, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
             ON CONFLICT(principal_type, value) DO NOTHING
             RETURNING id",
        )
        .bind(principal.id.0.to_string())
        .bind(principal.principal_type.as_str())
        .bind(&principal.value)
        .bind(principal.verified)
        .bind(fmt_dt_opt(principal.verified_at))
        .bind(fmt_dt_opt(principal.verification_expires))
        .bind(profile.id)
        .bind(principal.email_policy_revision)
        .bind(fmt_dt(&principal.created_at))
        .bind(fmt_dt(&principal.updated_at))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| super::principal_write_error("insert principal", e))?;
        if inserted.is_none() {
            return Err(SidError::Conflict("principal already registered".into()));
        }

        super::directory::insert_profile(&mut tx, profile).await?;

        if let Some(email) = email {
            sqlx::query(
                "INSERT INTO profile_emails (id, profile_id, email, label, custom_label, is_primary, verified, verified_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("profile email", e))?;
        }

        if let Some(phone) = phone {
            sqlx::query(
                "INSERT INTO profile_phones (id, profile_id, e164, extension, label, custom_label, is_primary, can_receive_sms, can_receive_fax, can_receive_voice, verified, verified_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("profile phone", e))?;
        }

        sqlx::query(
            "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary, source_field, source_email_id, source_phone_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(principal.id.0.to_string())
        .bind(principal.profile_id.to_string())
        .bind(principal.is_primary)
        .bind(&principal.source_field)
        .bind(principal.source_email_id.map(|id| id.0.to_string()))
        .bind(principal.source_phone_id.map(|id| id.0.to_string()))
        .bind(fmt_dt(&principal.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("principal binding", e))?;

        if let Some(credential) = credential {
            insert_credential(&mut *tx, credential).await?;
        }
        // A new owner has no history row: nothing can have moved it, so a
        // refusal here is a caller error, not a lost race.
        if let Some(history) = history
            && !super::password_history::apply_in_tx(&mut tx, history).await?
        {
            return Err(SidError::Conflict(
                "the new profile already has password history".into(),
            ));
        }
        if let Some(source) = source {
            super::enrollment::insert_registration_source(&mut tx, profile.id, source).await?;
        }
        Self::commit_mutation(tx, &format!("profile:{}", profile.id), audit).await
    }

    // === Profile Phone ===

    pub(crate) async fn get_profile_phone_impl(
        &self,
        id: ProfilePhoneId,
    ) -> SidResult<Option<ProfilePhone>> {
        let row = sqlx::query("SELECT * FROM profile_phones WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile_phone).transpose()
    }

    pub(crate) async fn list_profile_phones_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ProfilePhone>> {
        let rows = sqlx::query(
            "SELECT * FROM profile_phones WHERE profile_id = ? ORDER BY is_primary DESC, created_at",
        ).bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile_phone).collect()
    }

    pub(crate) async fn get_primary_profile_phone_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ProfilePhone>> {
        let row =
            sqlx::query("SELECT * FROM profile_phones WHERE profile_id = ? AND is_primary = 1")
                .bind(profile_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile_phone).transpose()
    }

    pub(crate) async fn delete_profile_phone_impl(
        &self,
        id: ProfilePhoneId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::delete_phone(&mut tx, id, None).await?;
        Self::commit_mutation(tx, &format!("profile_phone:{}", id.0), audit).await
    }

    // === Profile Email ===

    pub(crate) async fn get_profile_email_impl(
        &self,
        id: ProfileEmailId,
    ) -> SidResult<Option<ProfileEmail>> {
        let row = sqlx::query("SELECT * FROM profile_emails WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile_email).transpose()
    }

    pub(crate) async fn list_profile_emails_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileEmail>> {
        let rows = sqlx::query(
            "SELECT * FROM profile_emails WHERE profile_id = ? ORDER BY is_primary DESC, created_at",
        ).bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile_email).collect()
    }

    pub(crate) async fn get_primary_profile_email_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ProfileEmail>> {
        let row =
            sqlx::query("SELECT * FROM profile_emails WHERE profile_id = ? AND is_primary = 1")
                .bind(profile_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile_email).transpose()
    }

    pub(crate) async fn delete_profile_email_impl(
        &self,
        id: ProfileEmailId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::delete_email(&mut tx, id, None).await?;
        Self::commit_mutation(tx, &format!("profile_email:{}", id.0), audit).await
    }

    // === Principal ===

    pub(crate) async fn get_principal_impl(&self, id: PrincipalId) -> SidResult<Option<Principal>> {
        let row = sqlx::query(
            "SELECT pr.*,
                    pb.profile_id AS pb_profile_id,
                    pb.is_primary AS pb_is_primary, pb.source_field AS pb_source_field,
                    pb.source_email_id AS pb_source_email_id, pb.source_phone_id AS pb_source_phone_id
             FROM principals pr
             LEFT JOIN principal_bindings pb ON pr.id = pb.principal_id
             WHERE pr.id = ?"
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_principal).transpose()
    }

    pub(crate) async fn get_principals_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<Principal>> {
        let rows = sqlx::query(
            "SELECT pr.*,
                    pb.profile_id AS pb_profile_id,
                    pb.is_primary AS pb_is_primary, pb.source_field AS pb_source_field,
                    pb.source_email_id AS pb_source_email_id, pb.source_phone_id AS pb_source_phone_id
             FROM principals pr
             INNER JOIN principal_bindings pb ON pr.id = pb.principal_id
             WHERE pb.profile_id = ?"
        ).bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_principal).collect()
    }

    pub(crate) async fn get_profile_by_principal_impl(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<Profile>> {
        // The assigned profile, while it still holds its claim; a claim alone
        // resolves nobody.
        let row = sqlx::query(
            "SELECT p.* FROM principals pr
             INNER JOIN profiles p ON p.id = pr.assigned_profile_id
             INNER JOIN principal_bindings pb ON pb.principal_id = pr.id AND pb.profile_id = p.id
             WHERE pr.principal_type = ? AND pr.value = ?",
        )
        .bind(principal_type.as_str())
        .bind(value)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile).transpose()
    }

    pub(crate) async fn save_principal_impl(
        &self,
        p: &Principal,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::bind_principal(&mut tx, p).await?;
        Self::commit_mutation(tx, &format!("principal:{}", p.id.0), audit).await
    }

    /// The identifier entity of `principal_type` and `value`, without binding.
    pub(crate) async fn get_principal_by_value_impl(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<sid_core::models::PrincipalEntity>> {
        let row = sqlx::query(
            "SELECT id, value, verified, verified_at, verification_expires,
                    assigned_profile_id, assignment_revision, email_policy_revision,
                    created_at, updated_at
             FROM principals WHERE principal_type = ? AND value = ?",
        )
        .bind(principal_type.as_str())
        .bind(value)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.map(|row| {
            Ok(sid_core::models::PrincipalEntity {
                id: principal_id(&row)?,
                principal_type,
                value: row.get("value"),
                verified: row.get::<bool, _>("verified"),
                verified_at: parse_dt_opt(row.get("verified_at")),
                verification_expires: parse_dt_opt(row.get("verification_expires")),
                assigned_profile_id: col(&row, "assigned_profile_id")?,
                assignment_revision: col(&row, "assignment_revision")?,
                email_policy_revision: col(&row, "email_policy_revision")?,
                created_at: parse_dt(&row.get::<String, _>("created_at")),
                updated_at: parse_dt(&row.get::<String, _>("updated_at")),
            })
        })
        .transpose()
    }

    /// Bindings of the identifier held by active profiles.
    pub(crate) async fn count_active_principal_bindings_impl(
        &self,
        principal_id: PrincipalId,
    ) -> SidResult<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM principal_bindings pb
             JOIN profiles prof ON pb.profile_id = prof.id
             WHERE pb.principal_id = ? AND prof.status = 'active'",
        )
        .bind(principal_id.0.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(crate) async fn get_principal_bindings_impl(
        &self,
        principal_id: PrincipalId,
    ) -> SidResult<Vec<sid_core::models::PrincipalBinding>> {
        let rows = sqlx::query(
            "SELECT id, principal_id, profile_id, is_primary, source_field, source_email_id, source_phone_id, created_at
             FROM principal_bindings WHERE principal_id = ?"
        )
        .bind(principal_id.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;

        let mut bindings = Vec::with_capacity(rows.len());
        for row in rows {
            let id_str: String = row.get("id");
            let pid_str: String = row.get("principal_id");
            bindings.push(sid_core::models::PrincipalBinding {
                id: sid_core::models::PrincipalBindingId(
                    uuid::Uuid::parse_str(&id_str)
                        .map_err(|e| SidError::Storage(format!("Invalid UUID: {e}")))?,
                ),
                principal_id: sid_core::models::PrincipalId(
                    uuid::Uuid::parse_str(&pid_str)
                        .map_err(|e| SidError::Storage(format!("Invalid UUID: {e}")))?,
                ),
                profile_id: col(&row, "profile_id")?,
                is_primary: row.get::<bool, _>("is_primary"),
                source_field: row.get("source_field"),
                source_email_id: row
                    .get::<Option<String>, _>("source_email_id")
                    .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                    .map(ProfileEmailId),
                source_phone_id: row
                    .get::<Option<String>, _>("source_phone_id")
                    .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                    .map(ProfilePhoneId),
                created_at: parse_dt(&row.get::<String, _>("created_at")),
            });
        }
        Ok(bindings)
    }

    pub(crate) async fn reconcile_email_key_impl(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        contact: &ProfileEmail,
        reason: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        if contact.profile_id != profile_id {
            return Err(SidError::Validation(
                "the evidence is a contact of another profile".into(),
            ));
        }
        let mut tx = self.begin_write().await?;
        // The key leaves quarantine only while it still is quarantined and
        // assigned to this profile; the write lock orders concurrent repairs.
        let moved = sqlx::query(
            "UPDATE principals SET email_policy_revision =
                 (SELECT revision FROM email_policy_activations WHERE scope = 'installation'),
                 updated_at = ?3
             WHERE id = ?1 AND principal_type = 'email'
               AND email_policy_revision = 0 AND assigned_profile_id = ?2",
        )
        .bind(principal_id.0.to_string())
        .bind(profile_id.to_string())
        .bind(fmt_dt(&chrono::Utc::now()))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::principal_write_error("reconcile email key", e))?
        .rows_affected();
        if moved == 0 {
            return Ok(false);
        }
        super::directory::upsert_email(&mut tx, contact).await?;
        sqlx::query(
            "UPDATE principal_bindings SET source_field = 'email', source_email_id = ?3
             WHERE principal_id = ?1 AND profile_id = ?2",
        )
        .bind(principal_id.0.to_string())
        .bind(profile_id.to_string())
        .bind(contact.id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("link reconciled key: {e}")))?;
        sqlx::query(
            "INSERT INTO email_policy_dispositions
                 (principal_id, from_revision, to_revision, disposition, reason)
             SELECT ?1, 0, revision, 'migrated', ?2
             FROM email_policy_activations WHERE scope = 'installation'
             ON CONFLICT (principal_id) DO UPDATE SET
                 to_revision = excluded.to_revision, disposition = 'migrated',
                 reason = excluded.reason,
                 recorded_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(principal_id.0.to_string())
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record reconciliation: {e}")))?;
        Self::commit_mutation(tx, &format!("principal:{}", principal_id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn unbind_principal_impl(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !super::directory::unbind_principal(&mut tx, principal_id, profile_id).await? {
            return Ok(false);
        }
        Self::commit_mutation(
            tx,
            &format!("principal_binding:{}:{}", principal_id.0, profile_id),
            audit,
        )
        .await?;
        Ok(true)
    }

    // === Credential ===

    pub(crate) async fn get_credential_impl(
        &self,
        id: CredentialId,
    ) -> SidResult<Option<Credential>> {
        let row = sqlx::query("SELECT * FROM credentials WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_credential).transpose()
    }

    pub(crate) async fn get_credentials_by_profile_impl(
        &self,
        profile_id: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> SidResult<Vec<Credential>> {
        let rows = if let Some(ct) = credential_type {
            sqlx::query("SELECT * FROM credentials WHERE profile_id = ? AND credential_type = ?")
                .bind(profile_id)
                .bind(ct.as_str())
                .fetch_all(&self.pool)
                .await
        } else {
            sqlx::query("SELECT * FROM credentials WHERE profile_id = ?")
                .bind(profile_id)
                .fetch_all(&self.pool)
                .await
        }
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_credential).collect()
    }

    pub(crate) async fn list_credentials_by_type_impl(
        &self,
        credential_type: CredentialType,
        after: Option<sid_core::models::CredentialId>,
        limit: u32,
    ) -> SidResult<Vec<Credential>> {
        let rows = sqlx::query(
            "SELECT * FROM credentials
             WHERE credential_type = ? AND (? IS NULL OR id > ?)
             ORDER BY id LIMIT ?",
        )
        .bind(credential_type.as_str())
        .bind(after.map(|id| id.0.to_string()))
        .bind(after.map(|id| id.0.to_string()))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_credential).collect()
    }

    pub(crate) async fn list_key_versions_impl(
        &self,
    ) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
        let rows = sqlx::query(
            "SELECT version, salt, algorithm, context FROM key_versions ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter()
            .map(|row| {
                let version = u32::try_from(row.get::<i64, _>("version"))
                    .map_err(|_| SidError::Storage("negative key version".into()))?;
                crate::key_versions::key_version_params(
                    version,
                    row.get("salt"),
                    &row.get::<String, _>("algorithm"),
                    row.get("context"),
                )
            })
            .collect()
    }

    pub(crate) async fn insert_key_version_impl(
        &self,
        params: &sid_keys::KeyVersionParams,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(
            "INSERT INTO key_versions (version, salt, algorithm, context)
             VALUES (?, ?, ?, ?) ON CONFLICT (version) DO NOTHING",
        )
        .bind(i64::from(params.version))
        .bind(&params.salt)
        .bind(crate::key_versions::key_derivation_name(params.algorithm))
        .bind(&params.context)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if inserted {
            Self::commit_mutation(tx, &format!("key_version:{}", params.version), audit).await?;
        }
        Ok(inserted)
    }

    pub(crate) async fn get_instance_secret_impl(
        &self,
        secret: sid_core::models::InstanceSecret,
    ) -> SidResult<Option<Vec<u8>>> {
        sqlx::query_scalar("SELECT sealed FROM instance_secrets WHERE name = ?")
            .bind(secret.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(crate) async fn insert_instance_secret_impl(
        &self,
        secret: sid_core::models::InstanceSecret,
        sealed: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(
            "INSERT INTO instance_secrets (name, sealed) VALUES (?, ?)
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(secret.as_str())
        .bind(sealed)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if inserted {
            Self::commit_mutation(tx, &format!("instance_secret:{secret}"), audit).await?;
        }
        Ok(inserted)
    }

    pub(crate) async fn instance_organization_impl(
        &self,
    ) -> SidResult<Option<sid_core::models::Organization>> {
        let row = sqlx::query(
            "SELECT id, org_type, status, canonical_domain, created_at
             FROM organizations WHERE is_instance",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.map(|row| {
            Ok(sid_core::models::Organization {
                id: col(&row, "id")?,
                org_type: parsed_col(&row, "org_type")?,
                status: parsed_col(&row, "status")?,
                canonical_domain: col(&row, "canonical_domain")?,
                created_at: dt_col(&row, "created_at")?,
            })
        })
        .transpose()
    }

    pub(crate) async fn insert_instance_organization_impl(
        &self,
        org: &sid_core::models::Organization,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(
            "INSERT INTO organizations (id, org_type, status, canonical_domain, is_instance, created_at)
             VALUES (?, ?, ?, ?, 1, ?)
             ON CONFLICT (is_instance) WHERE is_instance DO NOTHING",
        )
        .bind(org.id)
        .bind(org.org_type.as_str())
        .bind(org.status.as_str())
        .bind(&org.canonical_domain)
        .bind(fmt_dt(&org.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if inserted {
            Self::commit_mutation(tx, &format!("organization:{}", org.id), audit).await?;
        }
        Ok(inserted)
    }

    pub(crate) async fn assign_unowned_clients_impl(
        &self,
        org_id: sid_core::models::OrgId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let assigned = sqlx::query(
            "UPDATE oauth2_clients SET org_id = ?, revision = revision + 1
             WHERE org_id IS NULL",
        )
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected();
        if assigned > 0 {
            Self::commit_mutation(tx, &format!("organization:{org_id}"), audit).await?;
        }
        Ok(assigned)
    }

    pub(crate) async fn admin_exists_impl(&self) -> SidResult<bool> {
        sqlx::query_scalar(ADMIN_EXISTS_SQL)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(crate) async fn claim_first_admin_impl(
        &self,
        claim_sealed: &[u8],
        profile: &Profile,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let consumed = sqlx::query("DELETE FROM instance_secrets WHERE name = ? AND sealed = ?")
            .bind(sid_core::models::InstanceSecret::AdminClaim.as_str())
            .bind(claim_sealed)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?
            .rows_affected()
            == 1;
        if !consumed {
            return Ok(false);
        }
        let admin_exists: bool = sqlx::query_scalar(ADMIN_EXISTS_SQL)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if admin_exists {
            // A claim left beside an administrator grants nothing: drop it.
            tx.commit()
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
            return Ok(false);
        }
        if !super::directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("profile:{}", profile.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn create_credential_impl(
        &self,
        credential: &Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        insert_credential(&mut *tx, credential).await?;
        Self::commit_mutation(tx, &format!("credential:{}", credential.id.0), audit).await
    }

    pub(crate) async fn set_credential_label_impl(
        &self,
        id: CredentialId,
        label: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let profile_id: Option<String> = sqlx::query_scalar(
            "UPDATE credentials SET label = ?
             WHERE id = ? AND status = 'active' RETURNING profile_id",
        )
        .bind(label)
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn change_password_impl(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let (verified, policy_version, artifact) =
            crate::policy_evidence::columns(&new.policy_evidence)?;
        let mut tx = self.begin_write().await?;
        let profile_id: Option<String> = sqlx::query_scalar(
            "UPDATE credentials SET data = ?,
                policy_version = ?, zkpp_verified = ?,
                opaque_credential_identifier = ?, zkpp_artifact = ?, last_used_at = ?
             WHERE id = ? AND status = 'active' AND data = ? RETURNING profile_id",
        )
        .bind(new.data.expose())
        .bind(policy_version)
        .bind(verified)
        .bind(new.opaque_credential_identifier.map(|id| id.to_vec()))
        .bind(artifact)
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id.0.to_string())
        .bind(expected)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        if let Some(history) = history {
            if history.owner.to_string() != profile_id {
                return Err(SidError::Validation(
                    "password history belongs to the credential's profile".into(),
                ));
            }
            if !super::password_history::apply_in_tx(&mut tx, history).await? {
                return Ok(false);
            }
        }
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn reseal_credential_data_impl(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let profile_id: Option<String> = sqlx::query_scalar(
            "UPDATE credentials SET data = ?
             WHERE id = ? AND data = ? RETURNING profile_id",
        )
        .bind(data)
        .bind(id.0.to_string())
        .bind(expected)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn mark_credential_used_impl(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let profile_id: Option<String> = sqlx::query_scalar(
            "UPDATE credentials SET last_used_at = ?
             WHERE id = ? AND status = 'active' RETURNING profile_id",
        )
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn replace_credential_data_impl(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let profile_id: Option<String> = sqlx::query_scalar(
            "UPDATE credentials SET data = ?, last_used_at = ?
             WHERE id = ? AND status = 'active' AND data = ? RETURNING profile_id",
        )
        .bind(data)
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id.0.to_string())
        .bind(expected)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn replace_credential_impl(
        &self,
        credential: &Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        replace_credential_in_tx(&mut tx, credential).await?;
        Self::commit_mutation(tx, &format!("profile:{}", credential.profile_id), audit).await
    }

    pub(crate) async fn enroll_credential_impl(
        &self,
        credential: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if let Some(set) = recovery
            && set.credential_type != CredentialType::Recovery
        {
            return Err(SidError::Validation(
                "only recovery codes are issued with an enrolled factor".into(),
            ));
        }
        let mut tx = self.begin_write().await?;
        insert_credential(&mut *tx, credential).await?;
        if let Some(set) = recovery {
            replace_credential_in_tx(&mut tx, set).await?;
        }
        Self::commit_mutation(tx, &format!("profile:{}", credential.profile_id), ctx).await
    }

    pub(crate) async fn delete_credential_impl(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM credentials WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("credential:{}", id.0), audit).await
    }

    /// Revoke the credential unless it is its profile's last active primary
    /// one; `BEGIN IMMEDIATE` makes the count and the update one step.
    pub(crate) async fn revoke_credential_impl(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::CredentialRevocation> {
        use sid_core::models::CredentialRevocation;
        let storage = |e: sqlx::Error| SidError::Storage(e.to_string());
        let mut tx = self.begin_write().await?;
        let target: Option<(String, String)> =
            sqlx::query_as("SELECT credential_type, status FROM credentials WHERE id = ?")
                .bind(id.0.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let Some((credential_type, status)) = target else {
            return Ok(CredentialRevocation::AlreadyGone);
        };
        if status != "active" {
            return Ok(CredentialRevocation::AlreadyGone);
        }
        let primary_types = CredentialType::PRIMARY.map(|t| t.as_str());
        if primary_types.contains(&credential_type.as_str()) {
            let others: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM credentials
                 WHERE profile_id = (SELECT profile_id FROM credentials WHERE id = ?1)
                   AND id <> ?1 AND status = 'active'
                   AND credential_type IN (SELECT value FROM json_each(?2))",
            )
            .bind(id.0.to_string())
            .bind(serde_json::to_string(&primary_types).expect("names serialize"))
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            if others == 0 {
                return Ok(CredentialRevocation::LastPrimary);
            }
        }
        sqlx::query("UPDATE credentials SET status = 'revoked' WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::commit_mutation(tx, &format!("credential:{}", id.0), audit).await?;
        Ok(CredentialRevocation::Revoked)
    }

    pub(crate) async fn delete_credentials_by_profile_impl(
        &self,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let result = sqlx::query("DELETE FROM credentials WHERE profile_id = ?")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        Ok(result.rows_affected())
    }

    // === Profile Metadata ===

    pub(crate) async fn get_profile_metadata_impl(
        &self,
        profile_id: ProfileId,
        key: &str,
    ) -> SidResult<Option<ProfileMetadata>> {
        let row = sqlx::query("SELECT * FROM profile_metadata WHERE profile_id = ? AND key = ?")
            .bind(profile_id)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile_metadata).transpose()
    }

    pub(crate) async fn set_profile_metadata_impl(
        &self,
        metadata: &ProfileMetadata,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::set_metadata(&mut tx, metadata).await?;
        Self::commit_mutation(
            tx,
            &format!("profile:{}:metadata:{}", metadata.profile_id, metadata.key),
            audit,
        )
        .await
    }

    pub(crate) async fn delete_profile_metadata_impl(
        &self,
        profile_id: ProfileId,
        key: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        super::directory::delete_metadata(&mut tx, profile_id, key).await?;
        Self::commit_mutation(tx, &format!("profile:{profile_id}:metadata:{key}"), audit).await
    }

    pub(crate) async fn list_profile_metadata_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileMetadata>> {
        let rows = sqlx::query("SELECT * FROM profile_metadata WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile_metadata).collect()
    }

    // === Admin queries (profile-related) ===

    pub(crate) async fn list_profiles_impl(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Profile>> {
        let rows = sqlx::query("SELECT * FROM profiles ORDER BY created_at, id LIMIT ? OFFSET ?")
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile).collect()
    }

    pub(crate) async fn count_profiles_impl(&self) -> SidResult<u64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM profiles")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(row.get::<i64, _>("cnt") as u64)
    }

    pub(crate) async fn list_profiles_with_status_impl(
        &self,
        status: sid_core::models::ProfileStatus,
    ) -> SidResult<Vec<Profile>> {
        let rows = sqlx::query("SELECT * FROM profiles WHERE status = ? ORDER BY id")
            .bind(status.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile).collect()
    }

    pub(crate) async fn list_profiles_with_pending_migration_impl(
        &self,
    ) -> SidResult<Vec<Profile>> {
        let rows = sqlx::query("SELECT * FROM profiles WHERE migration_pending = 1")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile).collect()
    }

    pub(crate) async fn end_legacy_migration_impl(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !super::directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        sqlx::query("DELETE FROM credentials WHERE profile_id = ? AND credential_type = ?")
            .bind(profile.id)
            .bind(CredentialType::LegacyHash.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("profile:{}", profile.id), ctx).await?;
        Ok(true)
    }
}
