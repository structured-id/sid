// SPDX-License-Identifier: AGPL-3.0-only
//! SQLite storage backend for embedded/dev mode.
//!
//! Provides `SqliteBackend` implementing `StorageBackend` trait for:
//! - Local development without PostgreSQL
//! - Single-node CE deployments
//! - Embedded IoT hubs (resource-constrained, no external DB)
//!
//! **Not the default CE backend** — full CE uses PostgreSQL+AGE.
//! Enable via `storage-sqlite` feature flag.

mod migrations;
mod schema;

// Domain implementation modules
mod application;
mod attestation;
mod audit;
mod audit_retention;
mod auth;
mod binding;
mod branding;
mod consent;
mod contact;
mod device;
mod directory;
mod enrollment;
mod flow_action;
mod governance;
mod grants;
mod job_lock;
mod lifecycle;
mod login_history;
mod machine;
mod oidc_issuer;
mod operation;
mod password_history;
mod profile;
mod project;
mod provisioning_connector;
mod rbac;
mod reset;
mod scim_outbound;
mod session;
mod signals;
mod webauthn;
mod work;

pub use audit::SqliteAuditLog;

use async_trait::async_trait;
use sid_core::models::MutationContext;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::storage::StorageBackend;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::str::FromStr;
use std::time::Duration;

/// A mutation's write transaction.
type WriteTx = sqlx::Transaction<'static, sqlx::Sqlite>;

/// The message the email policy fence aborts with (schema migration 2).
const EMAIL_POLICY_FENCE: &str = "email policy fence";

/// A failed principal write: `Fenced` when its email key was derived under a
/// policy revision that is not the installation's active one.
fn principal_write_error(what: &str, e: sqlx::Error) -> SidError {
    match &e {
        sqlx::Error::Database(db) if db.message() == EMAIL_POLICY_FENCE => SidError::Fenced(
            format!("{what}: email key not under the active policy revision"),
        ),
        _ => SidError::Storage(format!("{what}: {e}")),
    }
}

/// SQLite storage backend (sqlx-based).
///
/// Uses WAL mode for concurrent read access. All writes are serialized
/// by SQLite's write lock, which is fine for embedded/dev deployments (<10K users).
/// Every mutation commits with its audit entry (in this database's audit
/// chains) and the work it owes, in one transaction.
#[derive(Clone)]
pub struct SqliteBackend {
    pool: SqlitePool,
}

impl SqliteBackend {
    /// Create a new SQLite backend with a file-based database.
    ///
    /// Creates the database file if it doesn't exist and brings its schema
    /// to the version this build serves; a file it cannot serve is refused
    /// unchanged.
    pub async fn new(path: &str) -> SidResult<Self> {
        let backend = Self::open(path).await?;
        backend.init_schema().await?;
        Ok(backend)
    }

    /// [`Self::new`] stopping at schema version `version`: a staged upgrade,
    /// leaving later migrations for the next open. A file already past
    /// `version`, or a version this build does not have, is refused.
    pub async fn new_through(path: &str, version: i64) -> SidResult<Self> {
        let last = migrations::MIGRATIONS
            .iter()
            .position(|m| m.version == version)
            .map(|i| i + 1)
            .or((version == migrations::BASELINE_VERSION).then_some(0))
            .ok_or_else(|| SidError::Validation(format!("no SQLite schema version {version}")))?;
        let backend = Self::open(path).await?;
        migrations::upgrade(
            &backend.pool,
            schema::BASELINE,
            &migrations::MIGRATIONS[..last],
        )
        .await?;
        Ok(backend)
    }

    async fn open(path: &str) -> SidResult<Self> {
        let options = SqliteConnectOptions::from_str(path)
            .map_err(|e| SidError::Storage(format!("Invalid SQLite path: {e}")))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|e| SidError::Storage(format!("SQLite connection failed: {e}")))?;
        Ok(Self { pool })
    }

    /// Create a new in-memory SQLite backend (for tests).
    ///
    /// Each call creates an isolated database. Data is lost when the pool is dropped.
    pub async fn new_in_memory() -> SidResult<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| SidError::Storage(format!("SQLite memory init failed: {e}")))?
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);

        // For in-memory SQLite, we need exactly 1 connection to keep the database alive.
        // Multiple connections would create separate databases.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| SidError::Storage(format!("SQLite memory pool failed: {e}")))?;

        let backend = Self { pool };
        backend.init_schema().await?;
        Ok(backend)
    }

    /// Get the connection pool (for advanced queries / audit log).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Create the schema of an empty file, or upgrade an existing one to the
    /// version this build serves.
    async fn init_schema(&self) -> SidResult<()> {
        migrations::upgrade(&self.pool, schema::BASELINE, migrations::MIGRATIONS).await?;
        let quarantined: i64 = sqlx::query_scalar(crate::QUARANTINED_EMAIL_KEYS_SQL)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("count quarantined email keys: {e}")))?;
        crate::warn_quarantined_email_keys(quarantined);
        Ok(())
    }

    /// Start a mutation's transaction. `BEGIN IMMEDIATE` takes the database
    /// write lock first, so reads inside it (an audit chain head, a count
    /// checked against a limit) cannot be overtaken by another writer.
    async fn begin_write(&self) -> SidResult<WriteTx> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| SidError::Storage(format!("begin transaction: {e}")))
    }

    /// Commit a mutation's transaction together with its audit entry, on
    /// `chain_id`, and the work it owes: all of it or none.
    async fn commit_mutation(
        mut tx: WriteTx,
        chain_id: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        // The authority first: a write whose actor changed commits nothing.
        if let Some(fence) = &ctx.fence {
            provisioning_connector::check_fence(&mut tx, fence).await?;
        }
        // Then the completion: a keyed command another commit already
        // completed commits nothing, not even its audit or work.
        if let Some(operation) = &ctx.operation {
            operation::record_in_tx(&mut tx, operation).await?;
        }
        SqliteAuditLog::log_in_conn(&mut tx, chain_id, ctx.audit)
            .await
            .map_err(|e| SidError::Storage(format!("Audit log failed: {e}")))?;
        for owed in &ctx.work {
            work::insert_work_in_tx(&mut tx, owed, crate::OWED_WORK_CAPACITY).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))
    }

    /// Commit a bulk mutation that changed `rows` rows. One that changed
    /// nothing and owes nothing records nothing (its transaction is dropped).
    async fn commit_bulk(
        tx: WriteTx,
        rows: u64,
        chain_id: &str,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        if rows > 0 || !ctx.work.is_empty() || ctx.operation.is_some() {
            Self::commit_mutation(tx, chain_id, ctx).await?;
        }
        Ok(rows)
    }

    /// The single `COUNT(*)` a query selects.
    async fn count_rows(&self, sql: &'static str) -> SidResult<u64> {
        let count: i64 = sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        u64::try_from(count).map_err(|e| SidError::Storage(e.to_string()))
    }
}

// ─── Helper: parse DateTime from SQLite TEXT ───

pub(crate) fn parse_dt(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

pub(crate) fn parse_dt_opt(s: Option<String>) -> Option<chrono::DateTime<chrono::Utc>> {
    s.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    })
}

/// A failed insert: an existing key is a `Conflict`, never an update.
pub(crate) fn insert_error(what: &str, e: sqlx::Error) -> SidError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            SidError::Conflict(format!("{what} already exists"))
        }
        _ => SidError::Storage(format!("Insert {what} failed: {e}")),
    }
}

pub(crate) fn fmt_dt(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(crate) fn fmt_dt_opt(dt: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    dt.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// Decode one column, naming it in the error so a malformed stored value
/// (a bad id, say) points at its source.
pub(crate) fn col<'r, T>(row: &'r sqlx::sqlite::SqliteRow, name: &str) -> SidResult<T>
where
    T: sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    use sqlx::Row;
    row.try_get(name)
        .map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

/// Decode a UUID stored as text; a malformed value is an error, never nil.
pub(crate) fn uuid_col(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<uuid::Uuid> {
    let raw: String = col(row, name)?;
    uuid::Uuid::parse_str(&raw).map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

/// Decode an RFC 3339 timestamp column; a malformed value is an error, never
/// a substitute time.
pub(crate) fn dt_col(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> SidResult<chrono::DateTime<chrono::Utc>> {
    let raw: String = col(row, name)?;
    chrono::DateTime::parse_from_rfc3339(&raw)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| SidError::Storage(format!("column {name}: bad timestamp {raw}: {e}")))
}

/// [`dt_col`] for a nullable column.
pub(crate) fn dt_col_opt(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
    let raw: Option<String> = col(row, name)?;
    raw.map(|raw| {
        chrono::DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| SidError::Storage(format!("column {name}: bad timestamp {raw}: {e}")))
    })
    .transpose()
}

/// Decode a text column through the type's `FromStr`; an unknown value is an
/// error, never a default.
pub(crate) fn parsed_col<T>(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<T>
where
    T: std::str::FromStr<Err = String>,
{
    let raw: String = col(row, name)?;
    raw.parse()
        .map_err(|e: String| SidError::Storage(format!("column {name}: {e}")))
}

// ─── StorageBackend trait impl — delegates to domain modules ───

#[async_trait]
impl StorageBackend for SqliteBackend {
    fn name(&self) -> &'static str {
        "sqlite_sqlx"
    }

    // Profile operations — see profile.rs
    async fn get_profile(
        &self,
        id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::Profile>> {
        self.get_profile_impl(id).await
    }

    async fn get_profile_by_username(
        &self,
        username: &str,
    ) -> SidResult<Option<sid_core::models::Profile>> {
        self.get_profile_by_username_impl(username).await
    }

    async fn get_profile_by_email(
        &self,
        email: &str,
    ) -> SidResult<Option<sid_core::models::Profile>> {
        self.get_profile_by_email_impl(email).await
    }

    async fn create_profile(
        &self,
        profile: &sid_core::models::Profile,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_profile_impl(profile, audit).await
    }

    async fn update_profile(
        &self,
        profile: &sid_core::models::Profile,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_profile_impl(profile, audit).await
    }

    async fn delete_profile(
        &self,
        id: sid_core::models::ProfileId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_profile_impl(id, audit).await
    }

    async fn register_profile(
        &self,
        registration: &sid_core::models::NewRegistration,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.register_profile_impl(registration, audit).await
    }

    // Profile Phone operations — see profile.rs
    async fn get_profile_phone(
        &self,
        id: sid_core::models::ProfilePhoneId,
    ) -> SidResult<Option<sid_core::models::ProfilePhone>> {
        self.get_profile_phone_impl(id).await
    }

    async fn list_profile_phones(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::ProfilePhone>> {
        self.list_profile_phones_impl(profile_id).await
    }

    async fn get_primary_profile_phone(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::ProfilePhone>> {
        self.get_primary_profile_phone_impl(profile_id).await
    }

    async fn create_profile_phone(
        &self,
        phone: &sid_core::models::ProfilePhone,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_profile_phone_impl(phone, audit).await
    }

    async fn update_profile_phone_settings(
        &self,
        profile_id: sid_core::models::ProfileId,
        id: sid_core::models::ProfilePhoneId,
        settings: &sid_core::models::PhoneSettings,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_profile_phone_settings_impl(profile_id, id, settings, at, audit)
            .await
    }

    async fn set_primary_profile_phone(
        &self,
        profile_id: sid_core::models::ProfileId,
        id: sid_core::models::ProfilePhoneId,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.set_primary_profile_phone_impl(profile_id, id, at, audit)
            .await
    }

    async fn delete_profile_phone(
        &self,
        id: sid_core::models::ProfilePhoneId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_profile_phone_impl(id, audit).await
    }

    // Profile Email operations — see profile.rs
    async fn get_profile_email(
        &self,
        id: sid_core::models::ProfileEmailId,
    ) -> SidResult<Option<sid_core::models::ProfileEmail>> {
        self.get_profile_email_impl(id).await
    }

    async fn list_profile_emails(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::ProfileEmail>> {
        self.list_profile_emails_impl(profile_id).await
    }

    async fn get_primary_profile_email(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::ProfileEmail>> {
        self.get_primary_profile_email_impl(profile_id).await
    }

    async fn create_profile_email(
        &self,
        email: &sid_core::models::ProfileEmail,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_profile_email_impl(email, audit).await
    }

    async fn update_profile_email_settings(
        &self,
        profile_id: sid_core::models::ProfileId,
        id: sid_core::models::ProfileEmailId,
        settings: &sid_core::models::EmailSettings,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_profile_email_settings_impl(profile_id, id, settings, at, audit)
            .await
    }

    async fn set_primary_profile_email(
        &self,
        profile_id: sid_core::models::ProfileId,
        id: sid_core::models::ProfileEmailId,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.set_primary_profile_email_impl(profile_id, id, at, audit)
            .await
    }

    async fn delete_profile_email(
        &self,
        id: sid_core::models::ProfileEmailId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_profile_email_impl(id, audit).await
    }

    // Principal operations — see profile.rs
    async fn get_principal(
        &self,
        id: sid_core::models::PrincipalId,
    ) -> SidResult<Option<sid_core::models::Principal>> {
        self.get_principal_impl(id).await
    }

    async fn get_principals_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::Principal>> {
        self.get_principals_by_profile_impl(profile_id).await
    }

    async fn get_profile_by_principal(
        &self,
        principal_type: sid_core::models::PrincipalType,
        value: &str,
    ) -> SidResult<Option<sid_core::models::Profile>> {
        self.get_profile_by_principal_impl(principal_type, value)
            .await
    }

    async fn save_principal(
        &self,
        principal: &sid_core::models::Principal,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.save_principal_impl(principal, audit).await
    }

    async fn get_principal_bindings(
        &self,
        principal_id: sid_core::models::PrincipalId,
    ) -> SidResult<Vec<sid_core::models::PrincipalBinding>> {
        self.get_principal_bindings_impl(principal_id).await
    }

    async fn get_principal_by_value(
        &self,
        principal_type: sid_core::models::PrincipalType,
        value: &str,
    ) -> SidResult<Option<sid_core::models::PrincipalEntity>> {
        self.get_principal_by_value_impl(principal_type, value)
            .await
    }

    async fn count_active_principal_bindings(
        &self,
        principal_id: sid_core::models::PrincipalId,
    ) -> SidResult<i64> {
        self.count_active_principal_bindings_impl(principal_id)
            .await
    }

    async fn unbind_principal(
        &self,
        principal_id: sid_core::models::PrincipalId,
        profile_id: sid_core::models::ProfileId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.unbind_principal_impl(principal_id, profile_id, audit)
            .await
    }

    // Credential operations — see profile.rs
    async fn get_credential(
        &self,
        id: sid_core::models::CredentialId,
    ) -> SidResult<Option<sid_core::models::Credential>> {
        self.get_credential_impl(id).await
    }

    async fn get_credentials_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
        credential_type: Option<sid_core::models::CredentialType>,
    ) -> SidResult<Vec<sid_core::models::Credential>> {
        self.get_credentials_by_profile_impl(profile_id, credential_type)
            .await
    }

    async fn create_credential(
        &self,
        credential: &sid_core::models::Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_credential_impl(credential, audit).await
    }

    async fn set_credential_label(
        &self,
        id: sid_core::models::CredentialId,
        label: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.set_credential_label_impl(id, label, audit).await
    }

    async fn change_password(
        &self,
        id: sid_core::models::CredentialId,
        expected: &[u8],
        new: &sid_core::models::Credential,
        history: Option<&sid_core::models::HistoryCommit>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.change_password_impl(id, expected, new, history, audit)
            .await
    }

    async fn get_password_history(
        &self,
        owner: sid_core::models::ProfileId,
    ) -> SidResult<sid_core::models::PasswordHistory> {
        self.get_password_history_impl(owner).await
    }

    async fn get_history_epochs(
        &self,
        owner: sid_core::models::ProfileId,
    ) -> SidResult<sid_core::models::HistoryEpochs> {
        self.get_history_epochs_impl(owner).await
    }

    async fn export_password_history(
        &self,
        owner: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::HistoryArchive>> {
        self.export_password_history_impl(owner).await
    }

    async fn import_password_history(
        &self,
        archive: &sid_core::models::HistoryArchive,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.import_password_history_impl(archive, ctx).await
    }

    async fn ensure_history_epoch(
        &self,
        new: &sid_core::models::NewHistoryEpoch,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::HistoryEpoch> {
        self.ensure_history_epoch_impl(new, audit).await
    }

    async fn rotate_history_epoch(
        &self,
        new: &sid_core::models::NewHistoryEpoch,
        replaces: sid_core::models::HistoryEpochId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::HistoryEpoch> {
        self.rotate_history_epoch_impl(new, replaces, audit).await
    }

    async fn get_history_epoch_key(
        &self,
        epoch: sid_core::models::HistoryEpochId,
    ) -> SidResult<Option<sid_core::models::WrappedHistoryKey>> {
        self.get_history_epoch_key_impl(epoch).await
    }

    async fn reseal_credential_data(
        &self,
        id: sid_core::models::CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.reseal_credential_data_impl(id, expected, data, audit)
            .await
    }

    async fn mark_credential_used(
        &self,
        id: sid_core::models::CredentialId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.mark_credential_used_impl(id, audit).await
    }

    async fn replace_credential_data(
        &self,
        id: sid_core::models::CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.replace_credential_data_impl(id, expected, data, audit)
            .await
    }

    async fn replace_credential(
        &self,
        credential: &sid_core::models::Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.replace_credential_impl(credential, audit).await
    }

    async fn enroll_credential(
        &self,
        credential: &sid_core::models::Credential,
        recovery: Option<&sid_core::models::Credential>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.enroll_credential_impl(credential, recovery, ctx).await
    }

    async fn write_directory_user(
        &self,
        write: &sid_core::models::DirectoryUserWrite,
        ctx: MutationContext,
    ) -> SidResult<Vec<sid_core::models::Session>> {
        self.write_directory_user_impl(write, ctx).await
    }

    async fn write_directory_group(
        &self,
        write: &sid_core::models::DirectoryGroupWrite,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.write_directory_group_impl(write, ctx).await
    }

    async fn delete_credential(
        &self,
        id: sid_core::models::CredentialId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_credential_impl(id, audit).await
    }

    async fn revoke_credential(
        &self,
        id: sid_core::models::CredentialId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::CredentialRevocation> {
        self.revoke_credential_impl(id, audit).await
    }

    async fn delete_credentials_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.delete_credentials_by_profile_impl(profile_id, audit)
            .await
    }

    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: sid_core::models::ProfileId,
        rp_id: &str,
        candidate: sid_core::models::WebAuthnUserHandle,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::WebAuthnUserHandle> {
        self.ensure_webauthn_user_handle_impl(profile_id, rp_id, candidate, audit)
            .await
    }

    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: sid_core::models::WebAuthnUserHandle,
    ) -> SidResult<Option<sid_core::models::ProfileId>> {
        self.get_profile_by_webauthn_user_handle_impl(rp_id, handle)
            .await
    }

    async fn revoke_consents_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.revoke_consents_by_profile_impl(profile_id, audit)
            .await
    }

    async fn create_consent(
        &self,
        consent: &sid_core::models::consent::ConsentRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_consent_impl(consent, audit).await
    }

    async fn change_claim_grant(
        &self,
        id: sid_core::models::consent::ConsentId,
        claim_name: &str,
        decision: sid_core::models::consent::ClaimDecision,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::consent::ClaimGrantChange> {
        self.change_claim_grant_impl(id, claim_name, decision, audit)
            .await
    }

    async fn get_consent(
        &self,
        id: sid_core::models::consent::ConsentId,
    ) -> SidResult<Option<sid_core::models::consent::ConsentRecord>> {
        self.get_consent_impl(id).await
    }

    async fn get_consent_by_client(
        &self,
        profile_id: sid_core::models::ProfileId,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::consent::ConsentRecord>> {
        self.get_consent_by_client_impl(profile_id, client_id).await
    }

    async fn list_consents_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::consent::ConsentRecord>> {
        self.list_consents_by_profile_impl(profile_id).await
    }

    async fn delete_consent(
        &self,
        id: sid_core::models::consent::ConsentId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.delete_consent_impl(id, audit).await
    }

    async fn save_anomaly_event(
        &self,
        event: &sid_core::models::AnomalyEventRecord,
    ) -> SidResult<()> {
        self.save_anomaly_event_impl(event).await
    }

    async fn list_anomaly_events(
        &self,
        rule_id: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> SidResult<Vec<sid_core::models::AnomalyEventRecord>> {
        self.list_anomaly_events_impl(rule_id, limit, offset).await
    }

    async fn record_ip_reputation_event(&self, ip: &str, success: bool) -> SidResult<()> {
        self.record_ip_reputation_event_impl(ip, success).await
    }

    async fn get_ip_reputation_score(&self, ip: &str) -> SidResult<Option<f32>> {
        self.get_ip_reputation_score_impl(ip).await
    }

    async fn list_suspicious_ips(
        &self,
        min_score: f32,
        limit: i64,
    ) -> SidResult<Vec<(String, f32)>> {
        self.list_suspicious_ips_impl(min_score, limit).await
    }

    async fn decay_ip_reputation(&self, older_than: std::time::Duration) -> SidResult<u64> {
        self.decay_ip_reputation_impl(older_than).await
    }

    async fn add_ip_allowlist_entry(&self, cidr: &str, description: &str) -> SidResult<()> {
        self.add_ip_allowlist_entry_impl(cidr, description).await
    }
    async fn remove_ip_allowlist_entry(&self, cidr: &str) -> SidResult<()> {
        self.remove_ip_allowlist_entry_impl(cidr).await
    }
    async fn list_ip_allowlist_entries(
        &self,
    ) -> SidResult<Vec<(String, String, chrono::DateTime<chrono::Utc>)>> {
        self.list_ip_allowlist_entries_impl().await
    }

    // Session operations — see session.rs
    async fn create_session(
        &self,
        session: &sid_core::models::Session,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_session_impl(session, ctx).await
    }

    async fn record_session_authentication(
        &self,
        id: sid_core::models::SessionId,
        expected: &sid_core::models::SessionAuthentication,
        new: &sid_core::models::SessionAuthentication,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.record_session_authentication_impl(id, expected, new, ctx)
            .await
    }

    async fn create_session_atomic(
        &self,
        session: &sid_core::models::Session,
        max_sessions: u32,
        ctx: MutationContext,
    ) -> SidResult<Vec<sid_core::models::SessionId>> {
        self.create_session_atomic_impl(session, max_sessions, ctx)
            .await
    }

    async fn get_session(
        &self,
        id: sid_core::models::SessionId,
    ) -> SidResult<Option<sid_core::models::Session>> {
        self.get_session_impl(id).await
    }

    async fn get_session_by_browser_secret(
        &self,
        hash: &sid_core::models::BrowserSecretHash,
    ) -> SidResult<Option<sid_core::models::Session>> {
        self.get_session_by_browser_secret_impl(hash).await
    }

    async fn touch_session(
        &self,
        id: sid_core::models::SessionId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<()> {
        self.touch_session_impl(id, at).await
    }

    async fn delete_session(
        &self,
        id: sid_core::models::SessionId,
        end: &sid_core::models::SessionEnd,
        ctx: MutationContext,
    ) -> SidResult<Vec<sid_core::models::SessionId>> {
        // Commits owed work in its own transaction: no refusal needed.
        self.delete_session_impl(id, end, ctx).await
    }

    // Commits owed work in its own transaction: no refusal needed.
    async fn delete_sessions_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
        end: &sid_core::models::SessionEnd,
        ctx: MutationContext,
    ) -> SidResult<Vec<sid_core::models::Session>> {
        self.delete_sessions_by_profile_impl(profile_id, end, ctx)
            .await
    }

    // Project operations — see project.rs
    async fn get_project(
        &self,
        id: sid_core::models::ProjectId,
    ) -> SidResult<Option<sid_core::models::Project>> {
        self.get_project_impl(id).await
    }

    async fn create_project(
        &self,
        project: &sid_core::models::Project,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_project_impl(project, audit).await
    }

    async fn update_project(
        &self,
        id: sid_core::models::ProjectId,
        change: &sid_core::models::ProjectChange,
        audit: MutationContext,
    ) -> SidResult<Option<sid_core::models::Project>> {
        self.update_project_impl(id, change, audit).await
    }

    async fn delete_project(
        &self,
        id: sid_core::models::ProjectId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_project_impl(id, audit).await
    }

    async fn list_projects(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::Project>> {
        self.list_projects_impl(offset, limit).await
    }

    async fn count_projects(&self) -> SidResult<u64> {
        self.count_projects_impl().await
    }

    async fn list_oauth2_clients_by_project(
        &self,
        project_id: sid_core::models::ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::OAuth2Client>> {
        self.list_oauth2_clients_by_project_impl(project_id, offset, limit)
            .await
    }

    async fn ensure_system_project(&self, audit: MutationContext) -> SidResult<()> {
        self.ensure_system_project_impl(audit).await
    }

    // OAuth2 client operations — see project.rs
    async fn get_oauth2_client(
        &self,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::OAuth2Client>> {
        self.get_oauth2_client_impl(client_id).await
    }

    async fn update_oauth2_client(
        &self,
        client: &sid_core::models::OAuth2Client,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_oauth2_client_impl(client, audit).await
    }

    async fn create_oauth2_client(
        &self,
        client: &sid_core::models::OAuth2Client,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_oauth2_client_impl(client, audit).await
    }

    async fn delete_oauth2_client(&self, client_id: &str, audit: MutationContext) -> SidResult<()> {
        self.delete_oauth2_client_impl(client_id, audit).await
    }

    async fn list_oauth2_clients(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::OAuth2Client>> {
        self.list_oauth2_clients_impl(offset, limit).await
    }

    async fn oauth2_client_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> SidResult<Option<sid_core::models::OAuth2Client>> {
        self.oauth2_client_of_application_impl(id).await
    }

    // Applications, protected resources, resource access — see application.rs
    async fn create_application(
        &self,
        app: &sid_core::models::Application,
        client: Option<&sid_core::models::OAuth2Client>,
        resource: Option<&sid_core::models::ProtectedResource>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_application_impl(app, client, resource, ctx)
            .await
    }

    async fn get_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> SidResult<Option<sid_core::models::Application>> {
        self.get_application_impl(id).await
    }

    async fn system_application(
        &self,
        kind: sid_core::models::SystemIntegration,
    ) -> SidResult<Option<sid_core::models::Application>> {
        self.system_application_impl(kind).await
    }

    async fn list_applications_by_project(
        &self,
        project_id: sid_core::models::ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::Application>> {
        self.list_applications_by_project_impl(project_id, offset, limit)
            .await
    }

    async fn update_application(
        &self,
        app: &sid_core::models::Application,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_application_impl(app, ctx).await
    }

    async fn delete_application(
        &self,
        id: sid_core::models::ApplicationId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.delete_application_impl(id, ctx).await
    }

    async fn create_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_protected_resource_impl(resource, ctx).await
    }

    async fn get_protected_resource(
        &self,
        id: sid_core::models::ResourceId,
    ) -> SidResult<Option<sid_core::models::ProtectedResource>> {
        self.get_protected_resource_impl(id).await
    }

    async fn protected_resource_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> SidResult<Option<sid_core::models::ProtectedResource>> {
        self.protected_resource_of_application_impl(id).await
    }

    async fn list_protected_resources(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::ProtectedResource>> {
        self.list_protected_resources_impl(offset, limit).await
    }

    async fn import_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.import_protected_resource_impl(resource, ctx).await
    }

    async fn protected_resource_by_indicator(
        &self,
        issuer: sid_core::models::IssuerId,
        indicator: &sid_core::models::ResourceIndicator,
    ) -> SidResult<Option<sid_core::models::ProtectedResource>> {
        self.protected_resource_by_indicator_impl(issuer, indicator)
            .await
    }

    async fn update_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_protected_resource_impl(resource, ctx).await
    }

    async fn set_resource_access(
        &self,
        access: &sid_core::models::ResourceAccess,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.set_resource_access_impl(access, ctx).await
    }

    async fn remove_resource_access(
        &self,
        client_id: &str,
        resource: sid_core::models::ResourceId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.remove_resource_access_impl(client_id, resource, ctx)
            .await
    }

    async fn resource_access(
        &self,
        client_id: &str,
        resource: sid_core::models::ResourceId,
    ) -> SidResult<Option<sid_core::models::ResourceAccess>> {
        self.resource_access_impl(client_id, resource).await
    }

    async fn list_resource_access_by_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<sid_core::models::ResourceAccess>> {
        self.list_resource_access_by_client_impl(client_id).await
    }

    async fn list_resource_access_by_resource(
        &self,
        resource: sid_core::models::ResourceId,
    ) -> SidResult<Vec<sid_core::models::ResourceAccess>> {
        self.list_resource_access_by_resource_impl(resource).await
    }

    // Admin query operations — see session.rs
    async fn list_profiles(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::Profile>> {
        self.list_profiles_impl(offset, limit).await
    }

    async fn count_profiles(&self) -> SidResult<u64> {
        self.count_profiles_impl().await
    }

    async fn list_profiles_with_status(
        &self,
        status: sid_core::models::ProfileStatus,
    ) -> SidResult<Vec<sid_core::models::Profile>> {
        self.list_profiles_with_status_impl(status).await
    }

    async fn list_profiles_with_pending_migration(
        &self,
    ) -> SidResult<Vec<sid_core::models::Profile>> {
        self.list_profiles_with_pending_migration_impl().await
    }

    async fn end_legacy_migration(
        &self,
        profile: &sid_core::models::Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.end_legacy_migration_impl(profile, ctx).await
    }

    async fn list_sessions_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::Session>> {
        self.list_sessions_by_profile_impl(profile_id).await
    }

    async fn get_most_recent_session_ip(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<(String, chrono::DateTime<chrono::Utc>)>> {
        self.get_most_recent_session_ip_impl(profile_id).await
    }

    async fn has_recent_session_from_ip(
        &self,
        profile_id: sid_core::models::ProfileId,
        ip: &str,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        self.has_recent_session_from_ip_impl(profile_id, ip, window)
            .await
    }

    async fn has_recent_session_from_device(
        &self,
        profile_id: sid_core::models::ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        self.has_recent_session_from_device_impl(profile_id, device_id, window)
            .await
    }

    async fn record_login_location(
        &self,
        profile_id: sid_core::models::ProfileId,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> SidResult<()> {
        self.record_login_location_impl(
            profile_id,
            country,
            latitude,
            longitude,
            designated_threshold,
        )
        .await
    }

    async fn get_designated_countries(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<String>> {
        self.get_designated_countries_impl(profile_id).await
    }

    // Refresh token operations — see auth.rs
    async fn create_refresh_token(
        &self,
        token: &sid_core::models::RefreshToken,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_refresh_token_impl(token, audit).await
    }

    async fn get_refresh_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<sid_core::models::RefreshToken>> {
        self.get_refresh_token_by_hash_impl(token_hash).await
    }

    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: sid_core::models::SessionId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.revoke_refresh_tokens_by_session_impl(session_id, audit)
            .await
    }

    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.revoke_refresh_tokens_by_family_impl(family_id, audit)
            .await
    }

    async fn rotate_refresh_token(
        &self,
        old_id: uuid::Uuid,
        new: &sid_core::models::RefreshToken,
        grace_expires_at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.rotate_refresh_token_impl(old_id, new, grace_expires_at, audit)
            .await
    }

    // Authorization code operations — see auth.rs
    async fn create_auth_code(
        &self,
        code: &sid_core::models::AuthorizationCode,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_auth_code_impl(code, audit).await
    }

    async fn get_auth_code_by_hash(
        &self,
        code_hash: &[u8],
    ) -> SidResult<Option<sid_core::models::AuthorizationCode>> {
        self.get_auth_code_by_hash_impl(code_hash).await
    }

    async fn redeem_auth_code(
        &self,
        code_hash: &[u8],
        session: &sid_core::models::Session,
        refresh_token: &sid_core::models::RefreshToken,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::AuthCodeRedemption> {
        self.redeem_auth_code_impl(code_hash, session, refresh_token, audit)
            .await
    }

    // Initial access token operations — see auth.rs
    async fn create_initial_access_token(
        &self,
        token: &sid_core::models::InitialAccessToken,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_initial_access_token_impl(token, audit).await
    }

    async fn list_key_versions(&self) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
        self.list_key_versions_impl().await
    }

    async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.insert_key_version_impl(params, audit).await
    }

    async fn get_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
    ) -> SidResult<Option<Vec<u8>>> {
        self.get_instance_secret_impl(secret).await
    }

    async fn insert_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
        sealed: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.insert_instance_secret_impl(secret, sealed, audit)
            .await
    }

    async fn instance_organization(&self) -> SidResult<Option<sid_core::models::Organization>> {
        self.instance_organization_impl().await
    }

    async fn insert_instance_organization(
        &self,
        org: &sid_core::models::Organization,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.insert_instance_organization_impl(org, audit).await
    }

    async fn assign_unowned_clients(
        &self,
        org_id: sid_core::models::OrgId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.assign_unowned_clients_impl(org_id, audit).await
    }

    async fn oidc_issuer_for(
        &self,
        authority: sid_core::models::IssuerAuthority,
        recipient_org: sid_core::models::OrgId,
    ) -> SidResult<Option<sid_core::models::OidcIssuer>> {
        self.oidc_issuer_for_impl(authority, recipient_org).await
    }

    async fn oidc_issuer_by_handle(
        &self,
        handle: &sid_core::models::IssuerHandle,
    ) -> SidResult<Option<sid_core::models::OidcIssuer>> {
        self.oidc_issuer_by_handle_impl(handle).await
    }

    async fn insert_oidc_issuer(
        &self,
        issuer: &sid_core::models::OidcIssuer,
        first_key: &sid_core::models::IssuerSigningKey,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.insert_oidc_issuer_impl(issuer, first_key, audit).await
    }

    async fn oidc_issuer_signing_keys(
        &self,
        issuer: sid_core::models::IssuerId,
    ) -> SidResult<Vec<sid_core::models::IssuerSigningKey>> {
        self.oidc_issuer_signing_keys_impl(issuer).await
    }

    async fn admin_exists(&self) -> SidResult<bool> {
        self.admin_exists_impl().await
    }

    async fn claim_first_admin(
        &self,
        claim_sealed: &[u8],
        profile: &sid_core::models::Profile,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.claim_first_admin_impl(claim_sealed, profile, audit)
            .await
    }

    async fn service_binding(
        &self,
        profile_id: sid_core::models::ProfileId,
        scope: &sid_core::models::BindingScope,
        ctx: MutationContext,
    ) -> SidResult<sid_core::models::ServiceBinding> {
        self.service_binding_impl(profile_id, scope, ctx).await
    }

    async fn find_service_binding(
        &self,
        profile_id: sid_core::models::ProfileId,
        scope: &sid_core::models::BindingScope,
    ) -> SidResult<Option<sid_core::models::ServiceBinding>> {
        self.find_service_binding_impl(profile_id, scope).await
    }

    async fn list_service_bindings(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::ServiceBinding>> {
        self.list_service_bindings_impl(profile_id).await
    }

    async fn import_service_binding(
        &self,
        imported: &sid_core::models::ServiceBinding,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.import_service_binding_impl(imported, ctx).await
    }

    async fn list_credentials_by_type(
        &self,
        credential_type: sid_core::models::CredentialType,
        after: Option<sid_core::models::CredentialId>,
        limit: u32,
    ) -> SidResult<Vec<sid_core::models::Credential>> {
        self.list_credentials_by_type_impl(credential_type, after, limit)
            .await
    }

    async fn register_dynamic_client(
        &self,
        app: &sid_core::models::Application,
        client: &sid_core::models::OAuth2Client,
        iat: sid_core::models::InitialAccessTokenId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.register_dynamic_client_impl(app, client, iat, audit)
            .await
    }

    async fn get_initial_access_token(
        &self,
        id: sid_core::models::InitialAccessTokenId,
    ) -> SidResult<Option<sid_core::models::InitialAccessToken>> {
        self.get_initial_access_token_impl(id).await
    }

    async fn get_initial_access_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<sid_core::models::InitialAccessToken>> {
        self.get_initial_access_token_by_hash_impl(token_hash).await
    }

    async fn list_initial_access_tokens_by_project(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::InitialAccessToken>> {
        self.list_initial_access_tokens_by_project_impl(project_id)
            .await
    }

    async fn revoke_initial_access_token(
        &self,
        id: sid_core::models::InitialAccessTokenId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.revoke_initial_access_token_impl(id, audit).await
    }

    // RBAC operations — see rbac.rs
    async fn get_role(
        &self,
        id: sid_core::models::RoleId,
    ) -> SidResult<Option<sid_core::models::Role>> {
        self.get_role_impl(id).await
    }

    async fn get_role_by_name(
        &self,
        project_id: sid_core::models::ProjectId,
        name: &str,
    ) -> SidResult<Option<sid_core::models::Role>> {
        self.get_role_by_name_impl(project_id, name).await
    }

    async fn create_role(
        &self,
        role: &sid_core::models::Role,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_role_impl(role, audit).await
    }

    async fn update_role(
        &self,
        role: &sid_core::models::Role,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_role_impl(role, audit).await
    }

    async fn update_role_fenced(
        &self,
        role: &sid_core::models::Role,
        fence: &sid_core::models::RoleEditFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_role_fenced_impl(role, fence, audit).await
    }

    async fn delete_role(
        &self,
        id: sid_core::models::RoleId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_role_impl(id, audit).await
    }

    async fn list_roles(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::Role>> {
        self.list_roles_impl(project_id).await
    }

    async fn get_group(
        &self,
        id: sid_core::models::GroupId,
    ) -> SidResult<Option<sid_core::models::Group>> {
        self.get_group_impl(id).await
    }

    async fn create_group(
        &self,
        group: &sid_core::models::Group,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_group_impl(group, audit).await
    }

    async fn set_group_description(
        &self,
        id: sid_core::models::GroupId,
        description: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.set_group_description_impl(id, description, audit)
            .await
    }

    async fn delete_group(
        &self,
        id: sid_core::models::GroupId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_group_impl(id, audit).await
    }

    async fn list_groups(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::Group>> {
        self.list_groups_impl(project_id).await
    }

    async fn add_to_group(
        &self,
        member: &sid_core::models::GroupMember,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.add_to_group_impl(member, audit).await
    }

    async fn remove_from_group(
        &self,
        group_id: sid_core::models::GroupId,
        profile_id: sid_core::models::ProfileId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.remove_from_group_impl(group_id, profile_id, audit)
            .await
    }

    async fn list_group_members(
        &self,
        group_id: sid_core::models::GroupId,
    ) -> SidResult<Vec<sid_core::models::GroupMember>> {
        self.list_group_members_impl(group_id).await
    }

    async fn list_groups_for_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::Group>> {
        self.list_groups_for_profile_impl(profile_id).await
    }

    async fn create_role_assignment(
        &self,
        assignment: &sid_core::models::RoleAssignment,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_role_assignment_impl(assignment, audit).await
    }

    async fn delete_role_assignment(
        &self,
        id: sid_core::models::RoleAssignmentId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_role_assignment_impl(id, audit).await
    }

    async fn get_role_assignment(
        &self,
        id: sid_core::models::RoleAssignmentId,
    ) -> SidResult<Option<sid_core::models::RoleAssignment>> {
        self.get_role_assignment_impl(id).await
    }

    async fn create_role_assignment_fenced(
        &self,
        assignment: &sid_core::models::RoleAssignment,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_role_assignment_fenced_impl(assignment, fence, audit)
            .await
    }

    async fn delete_role_assignment_fenced(
        &self,
        id: sid_core::models::RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.delete_role_assignment_fenced_impl(id, fence, audit)
            .await
    }

    async fn list_role_assignments_for_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_role_assignments_for_profile_impl(profile_id)
            .await
    }

    async fn list_role_assignments_for_group(
        &self,
        group_id: sid_core::models::GroupId,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_role_assignments_for_group_impl(group_id).await
    }

    async fn list_role_assignments_for_machine_user(
        &self,
        machine_user_id: sid_core::models::MachineUserId,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_role_assignments_for_machine_user_impl(machine_user_id)
            .await
    }

    async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_role_assignments_for_oauth_client_impl(client_id)
            .await
    }

    async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_role_assignments_for_provisioning_connector_impl(connector_id)
            .await
    }

    async fn list_role_assignments_for_role(
        &self,
        role_id: sid_core::models::RoleId,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_role_assignments_for_role_impl(role_id).await
    }

    async fn list_expiring_role_assignments(
        &self,
        within_hours: i64,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.list_expiring_role_assignments_impl(within_hours).await
    }

    async fn cleanup_expired_role_assignments(
        &self,
        audit: MutationContext,
    ) -> SidResult<Vec<sid_core::models::RoleAssignment>> {
        self.cleanup_expired_role_assignments_impl(audit).await
    }

    async fn list_sod_rules(&self) -> SidResult<Vec<sid_core::models::SodConflictRule>> {
        self.list_sod_rules_impl().await
    }

    // Cedar policy operations — see rbac.rs
    async fn get_cedar_policy(
        &self,
        id: sid_core::models::CedarPolicyId,
    ) -> SidResult<Option<sid_core::models::CedarPolicy>> {
        self.get_cedar_policy_impl(id).await
    }

    async fn create_cedar_policy(
        &self,
        policy: &sid_core::models::CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_cedar_policy_impl(policy, audit).await
    }

    async fn update_cedar_policy(
        &self,
        policy: &sid_core::models::CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_cedar_policy_impl(policy, audit).await
    }

    async fn delete_cedar_policy(
        &self,
        id: sid_core::models::CedarPolicyId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_cedar_policy_impl(id, audit).await
    }

    async fn list_cedar_policies(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::CedarPolicy>> {
        self.list_cedar_policies_impl(project_id).await
    }

    // Profile metadata operations — see profile.rs
    async fn get_profile_metadata(
        &self,
        profile_id: sid_core::models::ProfileId,
        key: &str,
    ) -> SidResult<Option<sid_core::models::ProfileMetadata>> {
        self.get_profile_metadata_impl(profile_id, key).await
    }

    async fn set_profile_metadata(
        &self,
        metadata: &sid_core::models::ProfileMetadata,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.set_profile_metadata_impl(metadata, audit).await
    }

    async fn delete_profile_metadata(
        &self,
        profile_id: sid_core::models::ProfileId,
        key: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_profile_metadata_impl(profile_id, key, audit)
            .await
    }

    async fn list_profile_metadata(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::ProfileMetadata>> {
        self.list_profile_metadata_impl(profile_id).await
    }

    // Device operations — see device.rs
    async fn create_device(
        &self,
        device: &sid_core::models::Device,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_device_impl(device, audit).await
    }

    async fn rename_device(
        &self,
        id: sid_core::models::DeviceId,
        display_name: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.rename_device_impl(id, display_name, audit).await
    }

    async fn set_device_trust(
        &self,
        id: sid_core::models::DeviceId,
        trusted: bool,
        max_trusted: usize,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DeviceTrustChange> {
        self.set_device_trust_impl(id, trusted, max_trusted, audit)
            .await
    }

    async fn get_device(
        &self,
        id: sid_core::models::DeviceId,
    ) -> SidResult<Option<sid_core::models::Device>> {
        self.get_device_impl(id).await
    }

    async fn list_devices_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::Device>> {
        self.list_devices_by_profile_impl(profile_id).await
    }

    async fn delete_device(
        &self,
        id: sid_core::models::DeviceId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_device_impl(id, audit).await
    }

    async fn get_device_by_fingerprint(
        &self,
        profile_id: sid_core::models::ProfileId,
        fingerprint_hash: &str,
    ) -> SidResult<Option<sid_core::models::Device>> {
        self.get_device_by_fingerprint_impl(profile_id, fingerprint_hash)
            .await
    }

    async fn create_device_attestation(
        &self,
        attestation: &sid_core::models::DeviceAttestation,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_device_attestation_impl(attestation, audit)
            .await
    }

    async fn rotate_device_attestation(
        &self,
        device_id: sid_core::models::DeviceId,
        device_public_key: &[u8],
        attestation_object: Option<&[u8]>,
        attestation_certificate: Option<&[u8]>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.rotate_device_attestation_impl(
            device_id,
            device_public_key,
            attestation_object,
            attestation_certificate,
            audit,
        )
        .await
    }

    async fn revoke_device_attestation(
        &self,
        device_id: sid_core::models::DeviceId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.revoke_device_attestation_impl(device_id, audit).await
    }

    async fn get_device_attestation(
        &self,
        id: sid_core::models::DeviceAttestationId,
    ) -> SidResult<Option<sid_core::models::DeviceAttestation>> {
        self.get_device_attestation_impl(id).await
    }

    async fn get_device_attestation_by_device_id(
        &self,
        device_id: sid_core::models::DeviceId,
    ) -> SidResult<Option<sid_core::models::DeviceAttestation>> {
        self.get_device_attestation_by_device_id_impl(device_id)
            .await
    }

    async fn list_device_attestations_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::DeviceAttestation>> {
        self.list_device_attestations_by_profile_impl(profile_id)
            .await
    }

    async fn delete_device_attestation(
        &self,
        device_id: sid_core::models::DeviceId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_device_attestation_impl(device_id, audit).await
    }

    // Device authorization operations — see device.rs
    async fn create_device_auth_code(
        &self,
        code: &sid_core::models::DeviceAuthorizationCode,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_device_auth_code_impl(code, audit).await
    }

    async fn get_device_auth_by_device_code_hash(
        &self,
        device_code_hash: &[u8],
    ) -> SidResult<Option<sid_core::models::DeviceAuthorizationCode>> {
        self.get_device_auth_by_device_code_hash_impl(device_code_hash)
            .await
    }

    async fn get_device_auth_by_user_code(
        &self,
        user_code: &str,
    ) -> SidResult<Option<sid_core::models::DeviceAuthorizationCode>> {
        self.get_device_auth_by_user_code_impl(user_code).await
    }

    async fn decide_device_auth(
        &self,
        id: sid_core::models::DeviceAuthCodeId,
        decision: sid_core::models::DeviceAuthDecision,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.decide_device_auth_impl(id, decision, audit).await
    }

    async fn record_device_poll(
        &self,
        id: sid_core::models::DeviceAuthCodeId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DevicePoll> {
        self.record_device_poll_impl(id, audit).await
    }

    async fn redeem_device_code(
        &self,
        device_code_hash: &[u8],
        session: &sid_core::models::Session,
        refresh_token: &sid_core::models::RefreshToken,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DeviceCodeRedemption> {
        self.redeem_device_code_impl(device_code_hash, session, refresh_token, audit)
            .await
    }

    async fn cleanup_expired_device_auth_codes(&self, audit: MutationContext) -> SidResult<u64> {
        self.cleanup_expired_device_auth_codes_impl(audit).await
    }

    // Profile grant operations — see grants.rs
    async fn get_profile_grant(
        &self,
        id: sid_core::models::ProfileGrantId,
    ) -> SidResult<Option<sid_core::models::ProfileGrant>> {
        self.get_profile_grant_impl(id).await
    }

    async fn create_profile_grant(
        &self,
        grant: &sid_core::models::ProfileGrant,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_profile_grant_impl(grant, audit).await
    }

    async fn delete_profile_grant(
        &self,
        id: sid_core::models::ProfileGrantId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_profile_grant_impl(id, audit).await
    }

    async fn list_profile_grants_for_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::ProfileGrant>> {
        self.list_profile_grants_for_profile_impl(profile_id).await
    }

    async fn list_profile_grants_for_project(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::ProfileGrant>> {
        self.list_profile_grants_for_project_impl(project_id).await
    }

    // Upstream provider operations — see grants.rs
    async fn get_upstream_provider(
        &self,
        id: sid_core::models::UpstreamProviderId,
    ) -> SidResult<Option<sid_core::models::UpstreamProvider>> {
        self.get_upstream_provider_impl(id).await
    }

    async fn create_upstream_provider(
        &self,
        provider: &sid_core::models::UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_upstream_provider_impl(provider, audit).await
    }

    async fn update_upstream_provider(
        &self,
        provider: &sid_core::models::UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_upstream_provider_impl(provider, audit).await
    }

    async fn delete_upstream_provider(
        &self,
        id: sid_core::models::UpstreamProviderId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_upstream_provider_impl(id, audit).await
    }

    async fn list_enabled_upstream_providers(
        &self,
    ) -> SidResult<Vec<sid_core::models::UpstreamProvider>> {
        self.list_enabled_upstream_providers_impl().await
    }

    // Upstream identity operations — see grants.rs
    async fn get_upstream_identity_by_provider_subject(
        &self,
        provider_id: sid_core::models::UpstreamProviderId,
        upstream_subject: &str,
    ) -> SidResult<Option<sid_core::models::UpstreamIdentity>> {
        self.get_upstream_identity_by_provider_subject_impl(provider_id, upstream_subject)
            .await
    }

    async fn create_upstream_identity(
        &self,
        identity: &sid_core::models::UpstreamIdentity,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_upstream_identity_impl(identity, audit).await
    }

    async fn record_upstream_login(
        &self,
        id: sid_core::models::UpstreamIdentityId,
        login: &sid_core::models::UpstreamLogin,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.record_upstream_login_impl(id, login, audit).await
    }

    async fn list_upstream_identities_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::UpstreamIdentity>> {
        self.list_upstream_identities_by_profile_impl(profile_id)
            .await
    }

    async fn delete_upstream_identity(
        &self,
        id: sid_core::models::UpstreamIdentityId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_upstream_identity_impl(id, audit).await
    }

    // PAT operations — see lifecycle.rs
    async fn get_pat(
        &self,
        id: sid_core::models::PatId,
    ) -> SidResult<Option<sid_core::models::PersonalAccessToken>> {
        self.get_pat_impl(id).await
    }

    async fn get_pat_by_token_hash(
        &self,
        token_hash: &str,
    ) -> SidResult<Option<sid_core::models::PersonalAccessToken>> {
        self.get_pat_by_token_hash_impl(token_hash).await
    }

    async fn create_pat(
        &self,
        pat: &sid_core::models::PersonalAccessToken,
        active_limit: Option<u64>,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_pat_impl(pat, active_limit, audit).await
    }

    async fn record_pat_use(
        &self,
        id: sid_core::models::PatId,
        ip: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.record_pat_use_impl(id, ip, audit).await
    }

    async fn revoke_pat(
        &self,
        id: sid_core::models::PatId,
        revoked_by: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.revoke_pat_impl(id, revoked_by, audit).await
    }

    async fn list_pats_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Vec<sid_core::models::PersonalAccessToken>> {
        self.list_pats_by_profile_impl(profile_id).await
    }

    async fn list_all_pats(&self) -> SidResult<Vec<sid_core::models::PersonalAccessToken>> {
        self.list_all_pats_impl().await
    }

    async fn count_active_pats_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<u64> {
        self.count_active_pats_by_profile_impl(profile_id).await
    }

    async fn revoke_active_pats_by_profile(
        &self,
        profile_id: sid_core::models::ProfileId,
        revoked_by: &str,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.revoke_active_pats_by_profile_impl(profile_id, revoked_by, audit)
            .await
    }

    async fn revoke_unused_pats(&self, days: u32, audit: MutationContext) -> SidResult<u64> {
        self.revoke_unused_pats_impl(days, audit).await
    }

    // Machine user operations — see machine.rs
    async fn get_machine_user(
        &self,
        id: sid_core::models::MachineUserId,
    ) -> SidResult<Option<sid_core::models::MachineUser>> {
        self.get_machine_user_impl(id).await
    }

    async fn get_machine_user_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::MachineUser>> {
        self.get_machine_user_by_client_id_impl(client_id).await
    }

    async fn create_machine_user(
        &self,
        mu: &sid_core::models::MachineUser,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_machine_user_impl(mu, audit).await
    }

    async fn update_machine_user(
        &self,
        mu: &sid_core::models::MachineUser,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.update_machine_user_impl(mu, audit).await
    }

    async fn transition_machine_user(
        &self,
        id: sid_core::models::MachineUserId,
        from: sid_core::models::machine_user::MachineUserStatus,
        to: sid_core::models::machine_user::MachineUserStatus,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.transition_machine_user_impl(id, from, to, audit).await
    }

    async fn delete_machine_user(
        &self,
        id: sid_core::models::MachineUserId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_machine_user_impl(id, audit).await
    }

    async fn list_machine_users_by_project(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::MachineUser>> {
        self.list_machine_users_by_project_impl(project_id).await
    }

    // Machine user credential operations — see machine.rs
    async fn get_machine_credential_by_kid(
        &self,
        kid: &str,
    ) -> SidResult<Option<sid_core::models::MachineUserCredential>> {
        self.get_machine_credential_by_kid_impl(kid).await
    }

    async fn add_machine_credential(
        &self,
        cred: &sid_core::models::MachineUserCredential,
        active_limit: Option<u64>,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.add_machine_credential_impl(cred, active_limit, audit)
            .await
    }

    async fn rotate_machine_credential(
        &self,
        machine_user_id: sid_core::models::MachineUserId,
        old_kid: &str,
        new: &sid_core::models::MachineUserCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.rotate_machine_credential_impl(machine_user_id, old_kid, new, grace_until, audit)
            .await
    }

    async fn revoke_machine_credential(
        &self,
        machine_user_id: sid_core::models::MachineUserId,
        kid: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.revoke_machine_credential_impl(machine_user_id, kid, audit)
            .await
    }

    async fn revoke_active_machine_credentials_by_user(
        &self,
        id: sid_core::models::MachineUserId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        self.revoke_active_machine_credentials_by_user_impl(id, audit)
            .await
    }

    async fn list_machine_credentials_by_user(
        &self,
        id: sid_core::models::MachineUserId,
    ) -> SidResult<Vec<sid_core::models::MachineUserCredential>> {
        self.list_machine_credentials_by_user_impl(id).await
    }

    async fn get_provisioning_connector(
        &self,
        id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Option<sid_core::models::ProvisioningConnector>> {
        self.connector_get(id).await
    }

    async fn get_provisioning_connector_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::ProvisioningConnector>> {
        self.connector_by_client_id(client_id).await
    }

    async fn list_provisioning_connectors(
        &self,
        org_id: sid_core::models::OrgId,
    ) -> SidResult<Vec<sid_core::models::ProvisioningConnector>> {
        self.connector_list(org_id).await
    }

    async fn create_provisioning_connector(
        &self,
        connector: &sid_core::models::ProvisioningConnector,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.connector_create(connector, ctx).await
    }

    async fn rename_provisioning_connector(
        &self,
        id: sid_core::models::ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_rename(id, revision, display_name, ctx).await
    }

    async fn transition_provisioning_connector(
        &self,
        id: sid_core::models::ProvisioningConnectorId,
        from: sid_core::models::ConnectorState,
        to: sid_core::models::ConnectorState,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_transition(id, from, to, ctx).await
    }

    async fn add_provisioning_credential(
        &self,
        credential: &sid_core::models::ProvisioningCredential,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_add_credential(credential, ctx).await
    }

    async fn rotate_provisioning_credential(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
        old: sid_core::models::ProvisioningCredentialId,
        new: &sid_core::models::ProvisioningCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_rotate_credential(connector_id, old, new, grace_until, ctx)
            .await
    }

    async fn revoke_provisioning_credential(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
        id: sid_core::models::ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_revoke_credential(connector_id, id, ctx)
            .await
    }

    async fn list_provisioning_credentials(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Vec<sid_core::models::ProvisioningCredential>> {
        self.connector_list_credentials(connector_id).await
    }

    async fn find_provisioning_credential(
        &self,
        verifier: &str,
    ) -> SidResult<
        Option<(
            sid_core::models::ProvisioningCredential,
            sid_core::models::ProvisioningConnector,
        )>,
    > {
        self.connector_find_credential(verifier).await
    }

    async fn list_expiring_machine_credentials(
        &self,
        within_days: u32,
    ) -> SidResult<Vec<sid_core::models::MachineUserCredential>> {
        self.list_expiring_machine_credentials_impl(within_days)
            .await
    }

    // Impersonation grant operations — see machine.rs
    async fn save_impersonation_grant(
        &self,
        grant: &sid_core::models::ImpersonationGrant,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.save_impersonation_grant_impl(grant, audit).await
    }

    async fn delete_impersonation_grant(
        &self,
        machine_user_id: sid_core::models::MachineUserId,
        target_type: &str,
        target: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.delete_impersonation_grant_impl(machine_user_id, target_type, target, audit)
            .await
    }

    async fn list_impersonation_grants(
        &self,
        machine_user_id: sid_core::models::MachineUserId,
    ) -> SidResult<Vec<sid_core::models::ImpersonationGrant>> {
        self.list_impersonation_grants_impl(machine_user_id).await
    }

    // Quarantine operations — see lifecycle.rs
    async fn quarantine_principal(
        &self,
        principal_hash: &str,
        principal_type: &str,
        quarantine_until: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.quarantine_principal_impl(principal_hash, principal_type, quarantine_until, audit)
            .await
    }

    async fn is_principal_quarantined(&self, principal_hash: &str) -> SidResult<bool> {
        self.is_principal_quarantined_impl(principal_hash).await
    }

    async fn cleanup_expired_quarantine(&self, audit: MutationContext) -> SidResult<u64> {
        self.cleanup_expired_quarantine_impl(audit).await
    }

    // Closure request operations — see lifecycle.rs
    async fn create_closure_request(
        &self,
        req: &sid_core::models::ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_closure_request_impl(req, ctx).await
    }

    async fn request_profile_closure(
        &self,
        profile: &sid_core::models::Profile,
        req: &sid_core::models::ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.request_profile_closure_impl(profile, req, ctx).await
    }

    async fn cancel_profile_closure(
        &self,
        profile: &sid_core::models::Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.cancel_profile_closure_impl(profile, ctx).await
    }

    async fn get_closure_request(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::ClosureRequest>> {
        self.get_closure_request_impl(profile_id).await
    }

    // Export job operations — see lifecycle.rs
    async fn create_export_job(
        &self,
        job: &sid_core::models::ExportJob,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_export_job_impl(job, audit).await
    }

    async fn acknowledge_export_job(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.acknowledge_export_job_impl(id, at, audit).await
    }

    async fn expire_export_job(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.expire_export_job_impl(id, at, audit).await
    }

    async fn get_export_job(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::ExportJob>> {
        self.get_export_job_impl(profile_id).await
    }

    async fn get_export_job_by_id(
        &self,
        job_id: uuid::Uuid,
    ) -> SidResult<Option<sid_core::models::ExportJob>> {
        self.get_export_job_by_id_impl(job_id).await
    }

    // Magic link operations — see lifecycle.rs
    async fn create_magic_link_session(
        &self,
        session: &sid_core::models::MagicLinkSession,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_magic_link_session_impl(session, audit).await
    }

    async fn get_magic_link_session(
        &self,
        id: uuid::Uuid,
    ) -> SidResult<Option<sid_core::models::MagicLinkSession>> {
        self.get_magic_link_session_impl(id).await
    }

    async fn consume_magic_link_session(
        &self,
        id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.consume_magic_link_session_impl(id, audit).await
    }

    async fn try_consume_magic_link_session(
        &self,
        id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<Option<sid_core::models::MagicLinkSession>> {
        self.try_consume_magic_link_session_impl(id, audit).await
    }

    async fn delete_expired_magic_link_sessions(&self, audit: MutationContext) -> SidResult<u64> {
        self.delete_expired_magic_link_sessions_impl(audit).await
    }

    async fn count_active_magic_links_for_email(&self, email: &str) -> SidResult<u32> {
        self.count_active_magic_links_for_email_impl(email).await
    }

    // === SCIM OUTBOUND ===

    async fn create_scim_outbound_target(
        &self,
        target: &sid_core::models::ScimOutboundTarget,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_scim_outbound_target_impl(target, ctx).await
    }
    async fn get_scim_outbound_target(
        &self,
        id: sid_core::models::ScimOutboundTargetId,
    ) -> SidResult<Option<sid_core::models::ScimOutboundTarget>> {
        self.get_scim_outbound_target_impl(id).await
    }
    async fn list_scim_outbound_targets(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::ScimOutboundTarget>> {
        self.list_scim_outbound_targets_impl(project_id).await
    }
    async fn delete_scim_outbound_target(
        &self,
        id: sid_core::models::ScimOutboundTargetId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.delete_scim_outbound_target_impl(id, ctx).await
    }
    async fn create_scim_outbound_record(
        &self,
        record: &sid_core::models::ScimOutboundRecord,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_scim_outbound_record_impl(record, ctx).await
    }
    async fn record_scim_outbound_sync(
        &self,
        record: &sid_core::models::ScimOutboundRecord,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.record_scim_outbound_sync_impl(record, ctx).await
    }
    async fn record_scim_outbound_failure(
        &self,
        target_id: sid_core::models::ScimOutboundTargetId,
        sid_entity_id: uuid::Uuid,
        entity_type: sid_core::models::OutboundEntityType,
        error: &str,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.record_scim_outbound_failure_impl(
            target_id,
            sid_entity_id,
            entity_type,
            error,
            at,
            ctx,
        )
        .await
    }
    async fn get_scim_outbound_record(
        &self,
        target_id: sid_core::models::ScimOutboundTargetId,
        sid_entity_id: uuid::Uuid,
        entity_type: sid_core::models::OutboundEntityType,
    ) -> SidResult<Option<sid_core::models::ScimOutboundRecord>> {
        self.get_scim_outbound_record_impl(target_id, sid_entity_id, entity_type)
            .await
    }
    async fn create_outbound_dlq_entry(
        &self,
        entry: &sid_core::models::OutboundDlqEntry,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_outbound_dlq_entry_impl(entry, ctx).await
    }
    async fn list_outbound_dlq_entries(
        &self,
        target_id: sid_core::models::ScimOutboundTargetId,
    ) -> SidResult<Vec<sid_core::models::OutboundDlqEntry>> {
        self.list_outbound_dlq_entries_impl(target_id).await
    }
    async fn delete_outbound_dlq_entry(
        &self,
        id: uuid::Uuid,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.delete_outbound_dlq_entry_impl(id, ctx).await
    }
    // === AUTH FLOW CONFIGURATION ===
    async fn get_flow_config(
        &self,
        project_id: sid_core::models::ProjectId,
        flow_type: sid_core::models::FlowType,
    ) -> SidResult<Option<sid_core::models::FlowConfig>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT data FROM flow_configs WHERE project_id = ?1 AND flow_type = ?2",
        )
        .bind(project_id.0.to_string())
        .bind(flow_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query: {e}")))?;
        match row {
            Some((data,)) => {
                Ok(Some(serde_json::from_str(&data).map_err(|e| {
                    SidError::Storage(format!("Deserialize: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }
    async fn save_flow_config(
        &self,
        config: &sid_core::models::FlowConfig,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let data = serde_json::to_string(config)
            .map_err(|e| SidError::Storage(format!("Serialize: {e}")))?;
        let mut tx = self.begin_write().await?;
        sqlx::query("INSERT INTO flow_configs (project_id, flow_type, data, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(project_id, flow_type) DO UPDATE SET data = ?3, updated_at = ?4")
        .bind(config.project_id.0.to_string()).bind(config.flow_type.as_str()).bind(&data)
        .bind(config.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .execute(&mut *tx).await.map_err(|e| SidError::Storage(format!("Insert: {e}")))?;
        Self::commit_mutation(
            tx,
            &format!(
                "flow_config:{}:{}",
                config.project_id.0,
                config.flow_type.as_str()
            ),
            ctx,
        )
        .await
    }
    async fn list_flow_configs(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::FlowConfig>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM flow_configs WHERE project_id = ?1 ORDER BY flow_type",
        )
        .bind(project_id.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query: {e}")))?;
        rows.into_iter()
            .map(|(data,)| {
                serde_json::from_str(&data)
                    .map_err(|e| SidError::Storage(format!("Deserialize: {e}")))
            })
            .collect()
    }
    // === AUTH FLOW ACTIONS ===
    async fn create_flow_action(
        &self,
        action: &sid_core::models::FlowAction,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_flow_action_impl(action, ctx).await
    }
    async fn update_flow_action(
        &self,
        action: &sid_core::models::FlowAction,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_flow_action_impl(action, ctx).await
    }
    async fn get_flow_action(
        &self,
        id: sid_core::models::ActionId,
    ) -> SidResult<Option<sid_core::models::FlowAction>> {
        self.get_flow_action_impl(id).await
    }
    async fn list_flow_actions(
        &self,
        project_id: sid_core::models::ProjectId,
        flow_type: sid_core::models::FlowType,
        action_point: Option<sid_core::models::ActionPoint>,
    ) -> SidResult<Vec<sid_core::models::FlowAction>> {
        self.list_flow_actions_impl(project_id, flow_type, action_point)
            .await
    }
    async fn delete_flow_action(
        &self,
        id: sid_core::models::ActionId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM flow_actions WHERE id = ?1")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete: {e}")))?;
        Self::commit_mutation(tx, &format!("flow_action:{id}"), ctx).await
    }
    // === BRANDING ===
    async fn create_branding_config(
        &self,
        config: &sid_core::models::BrandingConfig,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_branding_config_impl(config, ctx).await
    }
    async fn update_branding_draft(
        &self,
        config: &sid_core::models::BrandingConfig,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_branding_draft_impl(config, ctx).await
    }
    async fn publish_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
        project_id: sid_core::models::ProjectId,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.publish_branding_config_impl(id, project_id, at, ctx)
            .await
    }
    async fn get_published_branding(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Option<sid_core::models::BrandingConfig>> {
        self.get_published_branding_impl(project_id).await
    }
    async fn get_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
    ) -> SidResult<Option<sid_core::models::BrandingConfig>> {
        self.get_branding_config_impl(id).await
    }
    async fn list_branding_configs(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::BrandingConfig>> {
        self.list_branding_configs_impl(project_id).await
    }
    async fn delete_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.delete_branding_config_impl(id, ctx).await
    }
    // === INVITE OPERATIONS ===
    async fn create_invite(
        &self,
        invite: &sid_core::models::Invite,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_invite_impl(invite, audit).await
    }
    async fn get_invite(
        &self,
        id: sid_core::models::InviteId,
    ) -> SidResult<Option<sid_core::models::Invite>> {
        self.get_invite_impl(id).await
    }
    async fn get_invite_by_code(&self, code: &str) -> SidResult<Option<sid_core::models::Invite>> {
        self.get_invite_by_code_impl(code).await
    }
    async fn list_invites(
        &self,
        filter: &sid_core::models::InviteFilter,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::Invite>> {
        self.list_invites_impl(filter, offset, limit).await
    }
    async fn count_invites(&self, filter: &sid_core::models::InviteFilter) -> SidResult<u64> {
        self.count_invites_impl(filter).await
    }
    async fn try_use_invite(
        &self,
        id: sid_core::models::InviteId,
        audit: MutationContext,
    ) -> SidResult<Option<sid_core::models::Invite>> {
        self.try_use_invite_impl(id, audit).await
    }
    async fn revoke_invite(
        &self,
        id: sid_core::models::InviteId,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.revoke_invite_impl(id, audit).await
    }
    // === REGISTRATION SOURCE OPERATIONS ===
    async fn get_registration_source(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::RegistrationSource>> {
        self.get_registration_source_impl(profile_id).await
    }
    async fn count_registrations_by_source(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<Vec<(sid_core::models::RegistrationSourceType, u64)>> {
        self.count_registrations_by_source_impl(since).await
    }
    async fn top_referrers(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        limit: u64,
    ) -> SidResult<Vec<(sid_core::models::ProfileId, u64)>> {
        self.top_referrers_impl(since, limit).await
    }
    async fn try_job_lock(&self, job: i64) -> SidResult<Option<sid_plugin::storage::JobLock>> {
        self.try_job_lock_impl(job).await
    }
    async fn ensure_audit_partition(&self, month_start: chrono::NaiveDate) -> SidResult<bool> {
        // One audit table holds every month: nothing to prepare.
        use chrono::Datelike;
        if month_start.day() != 1 {
            return Err(SidError::Validation(format!(
                "{month_start} is not the first day of a month"
            )));
        }
        Ok(false)
    }
    async fn drop_expired_audit_records(
        &self,
        cut_before: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.drop_expired_audit_records_impl(cut_before, ctx).await
    }
    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &sid_core::models::OperationKey,
    ) -> SidResult<Option<sid_core::models::OperationRecord>> {
        operation::get(&self.pool, namespace, key).await
    }

    async fn export_operation_results(&self) -> SidResult<Vec<sid_core::models::OperationRecord>> {
        operation::export(&self.pool).await
    }

    async fn import_operation_result(
        &self,
        record: &sid_core::models::OperationRecord,
    ) -> SidResult<bool> {
        operation::import(&self.pool, record).await
    }
    async fn get_notification_preferences(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::notification::NotificationPreferences>> {
        self.get_notification_preferences_impl(profile_id).await
    }
    async fn save_notification_preferences(
        &self,
        preferences: &sid_core::models::notification::NotificationPreferences,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.save_notification_preferences_impl(preferences, ctx)
            .await
    }
    async fn count_orphaned_sessions(&self) -> SidResult<u64> {
        self.count_rows(
            "SELECT COUNT(*) FROM sessions s \
             WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = s.profile_id)",
        )
        .await
    }
    async fn count_orphaned_credentials(&self) -> SidResult<u64> {
        self.count_rows(
            "SELECT COUNT(*) FROM credentials c \
             WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = c.profile_id)",
        )
        .await
    }
    async fn count_orphaned_role_assignments(&self) -> SidResult<u64> {
        self.count_rows(
            "SELECT COUNT(*) FROM role_assignments ra \
             WHERE (ra.profile_id IS NOT NULL \
                    AND NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = ra.profile_id)) \
                OR NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = ra.role_id)",
        )
        .await
    }
    // === ACCESS REQUEST OPERATIONS ===
    async fn create_access_request(
        &self,
        request: &sid_core::models::AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_access_request_impl(request, ctx).await
    }
    async fn get_access_request(
        &self,
        id: sid_core::models::AccessRequestId,
    ) -> SidResult<Option<sid_core::models::AccessRequest>> {
        self.get_access_request_impl(id).await
    }
    async fn list_pending_access_requests(
        &self,
    ) -> SidResult<Vec<sid_core::models::AccessRequest>> {
        self.list_pending_access_requests_impl().await
    }
    async fn decide_access_request(
        &self,
        request: &sid_core::models::AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.decide_access_request_impl(request, ctx).await
    }
    async fn approve_access_request(
        &self,
        request: &sid_core::models::AccessRequest,
        grant: &sid_core::models::RoleAssignment,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.approve_access_request_impl(request, grant, ctx).await
    }
    // === PASSWORD RESET SESSIONS ===
    async fn create_reset_session(
        &self,
        session: &sid_core::models::PasswordResetSession,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_reset_session_impl(session, ctx).await
    }
    async fn get_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
    ) -> SidResult<Option<sid_core::models::PasswordResetSession>> {
        self.get_reset_session_impl(id).await
    }
    async fn verify_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.verify_reset_session_impl(id, ctx).await
    }
    async fn complete_password_reset(
        &self,
        id: sid_core::models::ResetSessionId,
        credential: &sid_core::models::Credential,
        history: Option<&sid_core::models::HistoryCommit>,
        end: &sid_core::models::SessionEnd,
        ctx: MutationContext,
    ) -> SidResult<Option<Vec<sid_core::models::Session>>> {
        self.complete_password_reset_impl(id, credential, history, end, ctx)
            .await
    }
    async fn count_active_reset_sessions(
        &self,
        profile_id: sid_core::models::ProfileId,
    ) -> SidResult<u32> {
        self.count_active_reset_sessions_impl(profile_id).await
    }
    async fn delete_expired_reset_sessions(&self, ctx: MutationContext) -> SidResult<u64> {
        self.delete_expired_reset_sessions_impl(ctx).await
    }
    async fn expire_principal_verifications(&self) -> SidResult<i64> {
        self.expire_principal_verifications_impl().await
    }

    async fn reconcile_email_key(
        &self,
        principal_id: sid_core::models::PrincipalId,
        profile_id: sid_core::models::ProfileId,
        contact: &sid_core::models::ProfileEmail,
        reason: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.reconcile_email_key_impl(principal_id, profile_id, contact, reason, audit)
            .await
    }
    // === EMAIL PROVIDER CONFIGURATION ===
    // Refused rather than kept: provider credentials must not be stored in
    // clear, and this backend has no sealed storage for them.
    async fn get_email_provider_config(
        &self,
    ) -> SidResult<Option<sid_core::models::EmailProviderConfig>> {
        Ok(None)
    }
    async fn upsert_email_provider_config(
        &self,
        _config: &sid_core::models::EmailProviderConfig,
        _ctx: MutationContext,
    ) -> SidResult<()> {
        Err(SidError::Validation(
            "the embedded SQLite backend does not store an email provider; configure it through the notification service settings".into(),
        ))
    }
}
