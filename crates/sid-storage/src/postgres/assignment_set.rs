// SPDX-License-Identifier: AGPL-3.0-only
//! One holder's assignments in one exact scope, read with their revision and
//! replaced conditionally on it.

use sid_core::models::{
    AssignmentSet, AssignmentSetChange, MutationContext, RoleAssignment, RoleAssignmentId,
    RoleAssignmentPrincipal,
};
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::Postgres;
use sqlx::postgres::PgArguments;
use sqlx::query::{Query, QueryAs, QueryScalar};

use super::{PostgresBackend, insert_error};

type Tx<'a> = sqlx::Transaction<'a, Postgres>;

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

/// The set's six key columns in schema order, as `$first..` bind them.
macro_rules! bind_key {
    ($query:expr, $set:expr) => {{
        let (mut profile, mut group, mut machine, mut client, mut connector) =
            (None, None, None, None, None);
        match &$set.principal {
            RoleAssignmentPrincipal::Profile(id) => profile = Some(*id),
            RoleAssignmentPrincipal::Group(id) => group = Some(*id),
            RoleAssignmentPrincipal::MachineUser(id) => machine = Some(*id),
            RoleAssignmentPrincipal::OAuthClient(id) => client = Some(id.as_str()),
            RoleAssignmentPrincipal::ProvisioningConnector(id) => connector = Some(*id),
        }
        $query
            .bind(profile)
            .bind(group)
            .bind(machine)
            .bind(client)
            .bind(connector)
            .bind($set.scope.as_deref())
    }};
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

const SET_KEY: &str = "role_assignment_set_key($1, $2, $3, $4, $5, $6)";

fn revision_of(stored: i64) -> SidResult<u64> {
    u64::try_from(stored).map_err(|e| SidError::Storage(format!("assignment set revision: {e}")))
}

/// The revision a replacement at `expected` commits, as answered and as
/// stored.
fn next_revision(expected: u64) -> SidResult<(u64, i64)> {
    expected
        .checked_add(1)
        .and_then(|next| Some((next, i64::try_from(next).ok()?)))
        .ok_or_else(|| SidError::InvalidState("assignment set revision exhausted".into()))
}

fn read_failed(e: sqlx::Error) -> SidError {
    SidError::Storage(format!("read role assignment set: {e}"))
}

impl PostgresBackend {
    pub(super) async fn read_role_assignment_set(
        &self,
        set: &AssignmentSet,
    ) -> SidResult<(u64, Vec<RoleAssignment>)> {
        let mut tx = self.pool.begin().await.map_err(read_failed)?;
        // One snapshot: the revision is the one of exactly these assignments.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(read_failed)?;
        let sql = format!("SELECT revision FROM role_assignment_sets WHERE set_key = {SET_KEY}");
        let query: QueryScalar<'_, Postgres, i64, PgArguments> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()));
        let revision = bind_key!(query, set)
            .fetch_optional(&mut *tx)
            .await
            .map_err(read_failed)?
            .map_or(Ok(0), revision_of)?;
        let rows = Self::set_rows_in(&mut tx, set).await?;
        let assignments = Self::role_assignments_in(&mut tx, rows).await?;
        tx.commit().await.map_err(read_failed)?;
        Ok((revision, assignments))
    }

    /// The stored rows of `set`'s assignments, read in `tx`.
    async fn set_rows_in(
        tx: &mut Tx<'_>,
        set: &AssignmentSet,
    ) -> SidResult<Vec<crate::pg_row::RoleAssignmentRow>> {
        let sql = format!(
            "SELECT * FROM role_assignments WHERE {} = $1 AND scope IS NOT DISTINCT FROM $2",
            holder_column(&set.principal)
        );
        let query: QueryAs<'_, Postgres, crate::pg_row::RoleAssignmentRow, PgArguments> =
            sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()));
        bind_holder!(query, &set.principal)
            .bind(set.scope.as_deref())
            .fetch_all(&mut **tx)
            .await
            .map_err(read_failed)
    }

    pub(super) async fn replace_role_assignment_set(
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
        let mut tx = self.pool.begin().await.map_err(failed)?;
        // The locks in the order every assignment write takes them: the
        // administrators, the fenced authority, then the set's revision.
        let removed: Vec<RoleAssignmentId> = change.delete.iter().map(|(id, _)| *id).collect();
        let administrators = if removed.is_empty() {
            Vec::new()
        } else {
            Self::administrator_assignments_in_tx(&mut tx).await?
        };
        let fences = change
            .create
            .iter()
            .map(|(_, f)| f)
            .chain(change.delete.iter().map(|(_, f)| f))
            .chain(&change.hold);
        for fence in fences {
            Self::check_assignment_fence_in_tx(&mut tx, fence).await?;
        }
        let current = Self::lock_set_in_tx(&mut tx, set).await?;
        if current != change.expected_revision {
            return Err(SidError::AssignmentSetChanged { current });
        }
        let sql = format!(
            "DELETE FROM role_assignments WHERE id = $1 AND {} = $2
               AND scope IS NOT DISTINCT FROM $3 RETURNING id",
            holder_column(&set.principal)
        );
        for id in &removed {
            let query: QueryScalar<'_, Postgres, RoleAssignmentId, PgArguments> =
                sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str())).bind(*id);
            let gone = bind_holder!(query, &set.principal)
                .bind(set.scope.as_deref())
                .fetch_optional(&mut *tx)
                .await
                .map_err(failed)?;
            // Under the set's lock its assignments are as read: one already
            // gone was removed by a change the caller did not see.
            if gone.is_none() {
                return Err(SidError::AssignmentSetChanged { current });
            }
        }
        if let RoleAssignmentPrincipal::ProvisioningConnector(connector) = set.principal
            && !removed.is_empty()
        {
            Self::bump_connector_revision(&mut tx, connector).await?;
        }
        for (assignment, _) in &change.create {
            Self::insert_role_assignment_in_tx(&mut tx, assignment).await?;
        }
        let removes_administrator = removed
            .iter()
            .any(|r| administrators.iter().any(|(id, _)| *id == r.into_uuid()));
        if removes_administrator {
            let remaining = Self::administrator_assignments_in_tx(&mut tx).await?;
            crate::check_administrator_kept(&removed, &administrators, &remaining)?;
        }
        // Every write of the set waited for this transaction, so the one
        // revision others see after `expected` is the next.
        let next = next_revision(change.expected_revision)?;
        let sql =
            format!("UPDATE role_assignment_sets SET revision = $7 WHERE set_key = {SET_KEY}");
        let query: Query<'_, Postgres, PgArguments> =
            sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        bind_key!(query, set)
            .bind(next.1)
            .execute(&mut *tx)
            .await
            .map_err(failed)?;
        Self::audit_in_tx(&mut tx, &format!("role_assignments:{set}"), ctx).await?;
        tx.commit().await.map_err(failed)?;
        Ok(next.0)
    }

    /// Create `set`'s revision row when absent and lock it, answering its
    /// revision: every write of the set waits for this transaction.
    async fn lock_set_in_tx(tx: &mut Tx<'_>, set: &AssignmentSet) -> SidResult<u64> {
        let insert: Query<'_, Postgres, PgArguments> = sqlx::query(
            "INSERT INTO role_assignment_sets (profile_id, group_id, machine_user_id,
                 oauth_client_id, provisioning_connector_id, scope, revision)
             VALUES ($1, $2, $3, $4, $5, $6, 0)
             ON CONFLICT (set_key) DO NOTHING",
        );
        bind_key!(insert, set)
            .execute(&mut **tx)
            .await
            .map_err(|e| insert_error("role assignment set", e))?;
        let sql = format!(
            "SELECT revision FROM role_assignment_sets WHERE set_key = {SET_KEY} FOR UPDATE"
        );
        let query: QueryScalar<'_, Postgres, i64, PgArguments> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()));
        revision_of(
            bind_key!(query, set)
                .fetch_one(&mut **tx)
                .await
                .map_err(read_failed)?,
        )
    }
}
