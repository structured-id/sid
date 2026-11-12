// SPDX-License-Identifier: AGPL-3.0-only
//! One holder's assignments in one exact scope, read with their revision and
//! replaced conditionally on it. The write transaction is the only writer,
//! so the set read in it stays as read until it commits.

use sid_core::models::{
    AssignmentSet, AssignmentSetChange, MutationContext, RoleAssignment, RoleAssignmentId,
    RoleAssignmentPrincipal,
};
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::Sqlite;
use sqlx::query::{Query, QueryScalar};
use sqlx::sqlite::SqliteArguments;

use super::{SqliteBackend, rbac};

/// The holder column a set's assignments name it in: the only text the
/// queries here interpolate, every value bound.
fn holder_column(principal: &RoleAssignmentPrincipal) -> &'static str {
    match principal {
        RoleAssignmentPrincipal::Profile(_) => "profile_id",
        RoleAssignmentPrincipal::Group(_) => "group_id",
        RoleAssignmentPrincipal::MachineUser(_) => "machine_user_id",
        RoleAssignmentPrincipal::OAuthClient(_) => "oauth_client_id",
        RoleAssignmentPrincipal::ProvisioningConnector(_) => "provisioning_connector_id",
    }
}

/// The holder's id, as the holder column binds it.
macro_rules! bind_holder {
    ($query:expr, $principal:expr) => {
        match $principal {
            RoleAssignmentPrincipal::Profile(id) => $query.bind(*id),
            RoleAssignmentPrincipal::Group(id) => $query.bind(*id),
            RoleAssignmentPrincipal::MachineUser(id) => $query.bind(*id),
            RoleAssignmentPrincipal::OAuthClient(id) => $query.bind(id.as_str()),
            RoleAssignmentPrincipal::ProvisioningConnector(id) => $query.bind(*id),
        }
    };
}

fn revision_of(stored: i64) -> SidResult<u64> {
    u64::try_from(stored).map_err(|e| SidError::Storage(format!("assignment set revision: {e}")))
}

fn read_failed(e: sqlx::Error) -> SidError {
    SidError::Storage(format!("read role assignment set: {e}"))
}

/// The set's revision read in `conn`, 0 for a set never changed; `IS`
/// matches the absent scope.
async fn set_revision(conn: &mut sqlx::SqliteConnection, set: &AssignmentSet) -> SidResult<u64> {
    let sql = format!(
        "SELECT revision FROM role_assignment_sets WHERE {} = ? AND scope IS ?",
        holder_column(&set.principal)
    );
    let query: QueryScalar<'_, Sqlite, i64, SqliteArguments> =
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()));
    bind_holder!(query, &set.principal)
        .bind(set.scope.as_deref())
        .fetch_optional(&mut *conn)
        .await
        .map_err(read_failed)?
        .map_or(Ok(0), revision_of)
}

impl SqliteBackend {
    pub(crate) async fn read_role_assignment_set(
        &self,
        set: &AssignmentSet,
    ) -> SidResult<(u64, Vec<RoleAssignment>)> {
        // One read transaction: one snapshot for the revision and the rows.
        let mut tx = self.pool.begin().await.map_err(read_failed)?;
        let revision = set_revision(&mut tx, set).await?;
        let sql = format!(
            "SELECT * FROM role_assignments WHERE {} = ? AND scope IS ?",
            holder_column(&set.principal)
        );
        let query: Query<'_, Sqlite, SqliteArguments> =
            sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        let rows = bind_holder!(query, &set.principal)
            .bind(set.scope.as_deref())
            .fetch_all(&mut *tx)
            .await
            .map_err(read_failed)?;
        let assignments = rbac::read_assignments_in(&mut tx, &rows).await?;
        tx.commit().await.map_err(read_failed)?;
        Ok((revision, assignments))
    }

    pub(crate) async fn replace_role_assignment_set(
        &self,
        change: &AssignmentSetChange,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        let set = &change.set;
        if let Some((outside, _)) = change.create.iter().find(|(a, _)| !set.holds(a)) {
            return Err(SidError::Validation(format!(
                "assignment {} is outside the set it replaces",
                outside.id
            )));
        }
        let failed = |e: sqlx::Error| SidError::Storage(format!("replace role assignments: {e}"));
        let mut tx = self.begin_write().await?;
        let current = set_revision(&mut tx, set).await?;
        if current != change.expected_revision {
            return Err(SidError::AssignmentSetChanged { current });
        }
        let fences = change
            .create
            .iter()
            .map(|(_, f)| f)
            .chain(change.delete.iter().map(|(_, f)| f))
            .chain(&change.hold);
        for fence in fences {
            rbac::check_assignment_fence(&mut tx, fence).await?;
        }
        let removed: Vec<RoleAssignmentId> = change.delete.iter().map(|(id, _)| *id).collect();
        let administrators = if removed.is_empty() {
            Vec::new()
        } else {
            rbac::administrator_assignments(&mut tx).await?
        };
        let sql = format!(
            "DELETE FROM role_assignments WHERE id = ? AND {} = ? AND scope IS ? RETURNING id",
            holder_column(&set.principal)
        );
        for id in &removed {
            let query: QueryScalar<'_, Sqlite, RoleAssignmentId, SqliteArguments> =
                sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str())).bind(*id);
            let gone = bind_holder!(query, &set.principal)
                .bind(set.scope.as_deref())
                .fetch_optional(&mut *tx)
                .await
                .map_err(failed)?;
            // One already gone was removed by a change the caller did not see.
            if gone.is_none() {
                return Err(SidError::AssignmentSetChanged { current });
            }
        }
        if let RoleAssignmentPrincipal::ProvisioningConnector(connector) = set.principal
            && !removed.is_empty()
        {
            super::provisioning_connector::bump_connector_revision(&mut tx, connector).await?;
        }
        for (assignment, _) in &change.create {
            rbac::insert_role_assignment(&mut tx, assignment).await?;
        }
        let removes_administrator = removed
            .iter()
            .any(|r| administrators.iter().any(|(id, _)| *id == r.into_uuid()));
        if removes_administrator {
            let remaining = rbac::administrator_assignments(&mut tx).await?;
            crate::check_administrator_kept(&removed, &administrators, &remaining)?;
        }
        // The row exists unless the set never held an assignment.
        let insert: Query<'_, Sqlite, SqliteArguments> = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT OR IGNORE INTO role_assignment_sets ({}, scope, revision) VALUES (?, ?, 0)",
            holder_column(&set.principal)
        )));
        bind_holder!(insert, &set.principal)
            .bind(set.scope.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(|e| super::insert_error("role assignment set", e))?;
        // The only writer: the one revision others see after `expected` is
        // the next.
        let next = change
            .expected_revision
            .checked_add(1)
            .and_then(|next| Some((next, i64::try_from(next).ok()?)))
            .ok_or_else(|| SidError::InvalidState("assignment set revision exhausted".into()))?;
        let sql = format!(
            "UPDATE role_assignment_sets SET revision = ? WHERE {} = ? AND scope IS ?",
            holder_column(&set.principal)
        );
        let query: Query<'_, Sqlite, SqliteArguments> =
            sqlx::query(sqlx::AssertSqlSafe(sql.as_str())).bind(next.1);
        bind_holder!(query, &set.principal)
            .bind(set.scope.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(failed)?;
        Self::commit_mutation(tx, &format!("role_assignments:{set}"), ctx).await?;
        Ok(next.0)
    }
}
