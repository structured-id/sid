// SPDX-License-Identifier: AGPL-3.0-only
//! Pairwise service bindings: one per (profile, scope), allocated on first use.

use chrono::{DateTime, Utc};
use sid_core::models::{BindingId, BindingScope, MutationContext, ProfileId, ServiceBinding};
use sid_core::{Error as SidError, Result as SidResult};

use super::{SqliteBackend, fmt_dt};

macro_rules! columns {
    () => {
        "binding_id, profile_id, scope, binding_index, created_at, last_used_at"
    };
}

const FIND: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM service_bindings WHERE profile_id = ? AND scope = ?"
);

const TOUCH: &str = concat!(
    "UPDATE service_bindings SET last_used_at = ?
     WHERE profile_id = ? AND scope = ? RETURNING ",
    columns!()
);

const ALLOCATE: &str = concat!(
    "INSERT INTO service_bindings
         (binding_id, profile_id, scope, binding_index, created_at, last_used_at)
     VALUES (?, ?, ?,
             (SELECT COALESCE(MAX(binding_index) + 1, 0) FROM service_bindings
              WHERE profile_id = ?),
             ?, ?)
     RETURNING ",
    columns!()
);

const LIST: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM service_bindings WHERE profile_id = ? ORDER BY binding_index"
);

const BY_ID: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM service_bindings WHERE binding_id = ?"
);

// Any unique key already held (id, profile+scope, profile+index) inserts nothing.
const IMPORT: &str = "INSERT INTO service_bindings
     (binding_id, profile_id, scope, binding_index, created_at, last_used_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT DO NOTHING";

type Row = (BindingId, ProfileId, String, i64, String, String);

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn timestamp(text: &str) -> SidResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| SidError::Storage(format!("stored binding timestamp {text:?}: {e}")))
}

fn binding(
    (binding_id, profile_id, scope, index, created_at, last_used_at): Row,
) -> SidResult<ServiceBinding> {
    Ok(ServiceBinding {
        binding_id,
        profile_id,
        scope: BindingScope::try_from(scope)
            .map_err(|e| SidError::Storage(format!("stored binding scope: {e}")))?,
        binding_index: u32::try_from(index)
            .map_err(|_| SidError::Storage(format!("stored binding index {index}")))?,
        created_at: timestamp(&created_at)?,
        last_used_at: timestamp(&last_used_at)?,
    })
}

impl SqliteBackend {
    pub(crate) async fn find_service_binding_impl(
        &self,
        profile_id: ProfileId,
        scope: &BindingScope,
    ) -> SidResult<Option<ServiceBinding>> {
        let row: Option<Row> = sqlx::query_as(FIND)
            .bind(profile_id)
            .bind(scope.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("find service binding"))?;
        row.map(binding).transpose()
    }

    pub(crate) async fn list_service_bindings_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ServiceBinding>> {
        let rows: Vec<Row> = sqlx::query_as(LIST)
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage("list service bindings"))?;
        rows.into_iter().map(binding).collect()
    }

    pub(crate) async fn import_service_binding_impl(
        &self,
        imported: &ServiceBinding,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(IMPORT)
            .bind(imported.binding_id)
            .bind(imported.profile_id)
            .bind(imported.scope.as_str())
            .bind(i64::from(imported.binding_index))
            .bind(fmt_dt(&imported.created_at))
            .bind(fmt_dt(&imported.last_used_at))
            .execute(&mut *tx)
            .await
            .map_err(storage("import service binding"))?
            .rows_affected()
            == 1;
        if inserted {
            Self::commit_mutation(tx, &format!("service_binding:{}", imported.binding_id), ctx)
                .await?;
            return Ok(true);
        }
        let stored: Option<Row> = sqlx::query_as(BY_ID)
            .bind(imported.binding_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("import service binding"))?;
        match stored.map(binding).transpose()? {
            Some(same)
                if same.profile_id == imported.profile_id
                    && same.scope == imported.scope
                    && same.binding_index == imported.binding_index =>
            {
                Ok(false)
            }
            _ => Err(SidError::Conflict(format!(
                "binding {} collides with a stored binding",
                imported.binding_id
            ))),
        }
    }

    /// Touch the existing binding, or allocate one with the profile's next
    /// index. The write lock (`BEGIN IMMEDIATE`) serializes first uses.
    pub(crate) async fn service_binding_impl(
        &self,
        profile_id: ProfileId,
        scope: &BindingScope,
        ctx: MutationContext,
    ) -> SidResult<ServiceBinding> {
        let now = fmt_dt(&Utc::now());
        let mut tx = self.begin_write().await?;
        let existing: Option<Row> = sqlx::query_as(TOUCH)
            .bind(&now)
            .bind(profile_id)
            .bind(scope.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("touch service binding"))?;
        if let Some(row) = existing {
            tx.commit()
                .await
                .map_err(storage("touch service binding"))?;
            return binding(row);
        }
        let profile: Option<String> = sqlx::query_scalar("SELECT id FROM profiles WHERE id = ?")
            .bind(profile_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("find profile for binding"))?;
        if profile.is_none() {
            return Err(SidError::NotFound(format!("profile {profile_id}")));
        }
        let row: Row = sqlx::query_as(ALLOCATE)
            .bind(BindingId::generate())
            .bind(profile_id)
            .bind(scope.as_str())
            .bind(profile_id)
            .bind(&now)
            .bind(&now)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage("allocate service binding"))?;
        let allocated = binding(row)?;
        Self::commit_mutation(
            tx,
            &format!("service_binding:{}", allocated.binding_id),
            ctx,
        )
        .await?;
        Ok(allocated)
    }
}
