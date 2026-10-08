// SPDX-License-Identifier: AGPL-3.0-only
//! Monthly audit partitions: created ahead of their month, and removed whole
//! once their month is past retention, with a chain checkpoint left behind.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use sid_core::{Error as SidError, Result as SidResult};

type Tx<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// The month after `(year, month)`.
fn next_month(year: i32, month: u32) -> SidResult<NaiveDate> {
    let (y, m) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(y, m, 1)
        .ok_or_else(|| SidError::Validation(format!("no month after {year}-{month:02}")))
}

/// `(year, month)` of a monthly partition name (`audit_records_YYYY_MM`);
/// `None` for any other partition, the default one included.
fn partition_month(name: &str) -> Option<(i32, u32)> {
    let rest = name.strip_prefix("audit_records_")?;
    let (year, month) = rest.split_once('_')?;
    if year.len() != 4 || month.len() != 2 {
        return None;
    }
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    (1..=12).contains(&month).then_some((year, month))
}

/// The first instant of the month `at` falls in.
pub(super) fn month_start(at: DateTime<Utc>) -> SidResult<DateTime<Utc>> {
    NaiveDate::from_ymd_opt(at.year(), at.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| t.and_utc())
        .ok_or_else(|| SidError::Validation(format!("no month start for {at}")))
}

/// Create the partition of the month starting at `month_start`; `true` when
/// it did not exist yet.
pub(super) async fn ensure_partition(
    pool: &sqlx::PgPool,
    month_start: NaiveDate,
) -> SidResult<bool> {
    if month_start.day() != 1 {
        return Err(SidError::Validation(format!(
            "{month_start} is not the first day of a month"
        )));
    }
    let outcome: String = sqlx::query_scalar("SELECT create_audit_partition($1, $2)")
        .bind(month_start.year())
        .bind(i32::try_from(month_start.month()).map_err(|e| SidError::Validation(e.to_string()))?)
        .fetch_one(pool)
        .await
        .map_err(|e| SidError::Storage(format!("create audit partition: {e}")))?;
    Ok(outcome.ends_with("(created)"))
}

/// Drop, inside `tx`, every monthly partition whose month ended at or before
/// `boundary` (a month start), oldest first, recording each chain's last
/// dropped record as its checkpoint. Returns the partitions and the records
/// dropped.
pub(super) async fn drop_expired(
    tx: &mut Tx<'_>,
    boundary: DateTime<Utc>,
) -> SidResult<(usize, u64)> {
    // The parent resolves through this connection's search path: another
    // installation's schema in the same database has its own audit_records.
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = 'audit_records'::regclass",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("list audit partitions: {e}")))?;

    let mut expired = Vec::new();
    for (year, month) in names.iter().filter_map(|n| partition_month(n)) {
        let end = next_month(year, month)?
            .and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc())
            .ok_or_else(|| SidError::Validation("month end".into()))?;
        if end <= boundary {
            expired.push((year, month));
        }
    }
    expired.sort_unstable();

    let partitions = expired.len();
    let mut removed = 0u64;
    for (year, month) in expired {
        // The name is rebuilt from the two integers, never taken from input.
        let table = format!("audit_records_{year:04}_{month:02}");
        let count: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| SidError::Storage(format!("count {table}: {e}")))?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO audit_chain_checkpoints (chain_id, sequence, hash, cut_before)
             SELECT DISTINCT ON (chain_id) chain_id, sequence, hash, $1 FROM {table}
             ORDER BY chain_id, sequence DESC
             ON CONFLICT (chain_id) DO UPDATE SET
                sequence = EXCLUDED.sequence, hash = EXCLUDED.hash,
                cut_before = EXCLUDED.cut_before
             WHERE EXCLUDED.sequence > audit_chain_checkpoints.sequence"
        )))
        .bind(boundary)
        .execute(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("checkpoint {table}: {e}")))?;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {table}")))
            .execute(&mut **tx)
            .await
            .map_err(|e| SidError::Storage(format!("drop {table}: {e}")))?;
        removed += u64::try_from(count).map_err(|e| SidError::Storage(e.to_string()))?;
    }
    Ok((partitions, removed))
}

#[cfg(test)]
mod tests;
