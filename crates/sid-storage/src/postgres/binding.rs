// SPDX-License-Identifier: AGPL-3.0-only
//! Pairwise service bindings: one per (profile, scope), allocated on first use.

use chrono::{DateTime, Utc};
use sid_core::models::{BindingId, BindingScope, MutationContext, ProfileId, ServiceBinding};
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::PgPool;

use super::PostgresBackend;

macro_rules! columns {
    () => {
        "binding_id, profile_id, scope, binding_index, created_at, last_used_at"
    };
}

const FIND: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM service_bindings WHERE profile_id = $1 AND scope = $2"
);

const TOUCH: &str = concat!(
    "UPDATE service_bindings SET last_used_at = NOW()
     WHERE profile_id = $1 AND scope = $2 RETURNING ",
    columns!()
);

const ALLOCATE: &str = concat!(
    "INSERT INTO service_bindings (binding_id, profile_id, scope, binding_index)
     VALUES ($1, $2, $3,
             (SELECT COALESCE(MAX(binding_index) + 1, 0) FROM service_bindings
              WHERE profile_id = $2))
     RETURNING ",
    columns!()
);

const LIST: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM service_bindings WHERE profile_id = $1 ORDER BY binding_index"
);

const BY_ID: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM service_bindings WHERE binding_id = $1"
);

// Any unique key already held (id, profile+scope, profile+index) inserts nothing.
const IMPORT: &str = "INSERT INTO service_bindings
     (binding_id, profile_id, scope, binding_index, created_at, last_used_at)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT DO NOTHING";

type Row = (
    BindingId,
    ProfileId,
    String,
    i32,
    DateTime<Utc>,
    DateTime<Utc>,
);

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
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
        created_at,
        last_used_at,
    })
}

pub(super) async fn find(
    pool: &PgPool,
    profile_id: ProfileId,
    scope: &BindingScope,
) -> SidResult<Option<ServiceBinding>> {
    let row: Option<Row> = sqlx::query_as(FIND)
        .bind(profile_id)
        .bind(scope.as_str())
        .fetch_optional(pool)
        .await
        .map_err(storage("find service binding"))?;
    row.map(binding).transpose()
}

pub(super) async fn list(pool: &PgPool, profile_id: ProfileId) -> SidResult<Vec<ServiceBinding>> {
    let rows: Vec<Row> = sqlx::query_as(LIST)
        .bind(profile_id)
        .fetch_all(pool)
        .await
        .map_err(storage("list service bindings"))?;
    rows.into_iter().map(binding).collect()
}

pub(super) async fn import(
    pool: &PgPool,
    imported: &ServiceBinding,
    ctx: MutationContext,
) -> SidResult<bool> {
    let index = i32::try_from(imported.binding_index)
        .map_err(|_| SidError::Validation(format!("binding index {}", imported.binding_index)))?;
    let mut tx = pool
        .begin()
        .await
        .map_err(storage("import service binding"))?;
    let inserted = sqlx::query(IMPORT)
        .bind(imported.binding_id)
        .bind(imported.profile_id)
        .bind(imported.scope.as_str())
        .bind(index)
        .bind(imported.created_at)
        .bind(imported.last_used_at)
        .execute(&mut *tx)
        .await
        .map_err(storage("import service binding"))?
        .rows_affected()
        == 1;
    if inserted {
        PostgresBackend::audit_in_tx(
            &mut tx,
            &format!("service_binding:{}", imported.binding_id),
            ctx,
        )
        .await?;
        tx.commit()
            .await
            .map_err(storage("import service binding"))?;
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

/// Touch the existing binding, or allocate one with the profile's next index.
/// Allocation locks the profile row, so concurrent first uses of any scope of
/// one profile serialize: one allocates, the others then find its row.
pub(super) async fn get_or_allocate(
    pool: &PgPool,
    profile_id: ProfileId,
    scope: &BindingScope,
    ctx: MutationContext,
) -> SidResult<ServiceBinding> {
    let existing: Option<Row> = sqlx::query_as(TOUCH)
        .bind(profile_id)
        .bind(scope.as_str())
        .fetch_optional(pool)
        .await
        .map_err(storage("touch service binding"))?;
    if let Some(row) = existing {
        return binding(row);
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(storage("allocate service binding"))?;
    let profile: Option<(ProfileId,)> =
        sqlx::query_as("SELECT id FROM profiles WHERE id = $1 FOR UPDATE")
            .bind(profile_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("lock profile for binding"))?;
    if profile.is_none() {
        return Err(SidError::NotFound(format!("profile {profile_id}")));
    }
    // Another first use may have allocated while this one waited for the lock.
    let raced: Option<Row> = sqlx::query_as(TOUCH)
        .bind(profile_id)
        .bind(scope.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("touch service binding"))?;
    if let Some(row) = raced {
        tx.commit()
            .await
            .map_err(storage("allocate service binding"))?;
        return binding(row);
    }
    let row: Row = sqlx::query_as(ALLOCATE)
        .bind(BindingId::generate())
        .bind(profile_id)
        .bind(scope.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("allocate service binding"))?;
    let allocated = binding(row)?;
    PostgresBackend::audit_in_tx(
        &mut tx,
        &format!("service_binding:{}", allocated.binding_id),
        ctx,
    )
    .await?;
    tx.commit()
        .await
        .map_err(storage("allocate service binding"))?;
    Ok(allocated)
}
