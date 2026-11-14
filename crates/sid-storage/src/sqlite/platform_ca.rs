// SPDX-License-Identifier: AGPL-3.0-only
//! The admitted platform CA set in SQLite. Every write runs in the single
//! writer's transaction, so a set and its generations are one committed
//! revision and two applies are decided one after the other.

use async_trait::async_trait;
use sid_core::Error as SidError;
use sid_core::models::MutationContext;
use sid_plugin::platform_ca::{
    AnchorStatus, Applied, GenerationStatus, HeldAnchors, HeldGeneration, HeldSet, IssuerStatus,
    PlatformCaArchive, PlatformCaError, PlatformCaSet, PlatformCaState, PlatformCaStore,
};

use super::SqliteBackend;

/// The audit chain the store's writes are recorded on.
const CHAIN: &str = "installation:platform_ca";

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> PlatformCaError {
    move |e| PlatformCaError::Storage(SidError::Storage(format!("{what}: {e}")))
}

fn stored(value: u64, field: &str) -> Result<i64, PlatformCaError> {
    i64::try_from(value).map_err(|_| {
        PlatformCaError::Storage(SidError::Validation(format!(
            "{field} {value} out of range"
        )))
    })
}

/// A stored non-negative number as the unsigned value it holds.
fn unsigned<T: TryFrom<i64>>(value: i64, field: &str) -> Result<T, PlatformCaError> {
    T::try_from(value).map_err(|_| {
        PlatformCaError::Storage(SidError::Storage(format!(
            "stored {field} {value} out of range"
        )))
    })
}

/// Everything the store holds, as one committed state of `conn`'s
/// transaction.
async fn archive(conn: &mut sqlx::SqliteConnection) -> Result<PlatformCaArchive, PlatformCaError> {
    let set: Option<(i64, i64, i64)> =
        sqlx::query_as("SELECT revision, issued_at, next_update FROM platform_ca_set")
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage("read the held set"))?;
    let set = set
        .map(|(revision, issued_at, next_update)| {
            Ok::<_, PlatformCaError>(HeldSet {
                revision: unsigned(revision, "revision")?,
                issued_at,
                next_update,
            })
        })
        .transpose()?;
    let rows: Vec<(i64, Vec<u8>, i64, Option<i64>, i64)> = sqlx::query_as(
        "SELECT generation, certificate, state, overlap_end, listed_in
         FROM platform_ca_generations ORDER BY generation",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("read the generations"))?;
    let mut generations = Vec::with_capacity(rows.len());
    for (generation, certificate, state, overlap_end, listed_in) in rows {
        generations.push(HeldGeneration {
            generation: unsigned(generation, "generation")?,
            certificate,
            state: PlatformCaState::from_rank(state).ok_or_else(|| {
                PlatformCaError::Storage(SidError::Storage(format!(
                    "stored platform CA state {state}"
                )))
            })?,
            overlap_end,
            listed_in: unsigned(listed_in, "revision")?,
        });
    }
    let rows: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT generation, number, next_update FROM platform_ca_status ORDER BY generation",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("read the status"))?;
    let mut status = Vec::with_capacity(rows.len());
    for (generation, number, next_update) in rows {
        let revoked = sqlx::query_scalar(
            "SELECT serial FROM platform_ca_revoked WHERE generation = ? ORDER BY serial",
        )
        .bind(generation)
        .fetch_all(&mut *conn)
        .await
        .map_err(storage("read the revocations"))?;
        status.push(GenerationStatus {
            generation: unsigned(generation, "generation")?,
            number: unsigned(number, "CRL number")?,
            next_update,
            revoked,
        });
    }
    let rows: Vec<(Vec<u8>, i64, i64)> =
        sqlx::query_as("SELECT issuer, number, next_update FROM ca_issuer_status ORDER BY issuer")
            .fetch_all(&mut *conn)
            .await
            .map_err(storage("read the issuer status"))?;
    let mut issuers = Vec::with_capacity(rows.len());
    for (issuer, number, next_update) in rows {
        let revoked = sqlx::query_scalar(
            "SELECT serial FROM ca_issuer_revoked WHERE issuer = ? ORDER BY serial",
        )
        .bind(issuer.as_slice())
        .fetch_all(&mut *conn)
        .await
        .map_err(storage("read the issuer revocations"))?;
        issuers.push(IssuerStatus {
            issuer: issuer.try_into().map_err(|_| {
                PlatformCaError::Storage(SidError::Storage("a stored issuer name".into()))
            })?,
            number: unsigned(number, "CRL number")?,
            next_update,
            revoked,
        });
    }
    Ok(PlatformCaArchive {
        set,
        generations,
        status,
        issuers,
    })
}

/// Hold one issuer's CRL in `tx`: its number and time when not older than
/// the held one, and every serial it revokes whatever the number.
async fn hold_issuer_status(
    tx: &mut sqlx::SqliteConnection,
    crl: &IssuerStatus,
) -> Result<(), PlatformCaError> {
    sqlx::query(
        "INSERT INTO ca_issuer_status (issuer, number, next_update) VALUES (?, ?, ?)
         ON CONFLICT (issuer) DO UPDATE SET number = excluded.number,
             next_update = excluded.next_update
         WHERE ca_issuer_status.number <= excluded.number",
    )
    .bind(crl.issuer.as_slice())
    .bind(stored(crl.number, "CRL number")?)
    .bind(crl.next_update)
    .execute(&mut *tx)
    .await
    .map_err(storage("hold an issuer's CRL"))?;
    for serial in &crl.revoked {
        sqlx::query(
            "INSERT INTO ca_issuer_revoked (issuer, serial) VALUES (?, ?)
             ON CONFLICT (issuer, serial) DO NOTHING",
        )
        .bind(crl.issuer.as_slice())
        .bind(serial.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(storage("hold an issuer's revocation"))?;
    }
    Ok(())
}

#[async_trait]
impl PlatformCaStore for SqliteBackend {
    async fn record_issuer_status(
        &self,
        status: &IssuerStatus,
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError> {
        let mut tx = self.begin_write().await?;
        hold_issuer_status(&mut tx, status).await?;
        Self::commit_mutation(tx, CHAIN, ctx).await?;
        Ok(())
    }

    async fn held_issuer_status(&self, issuer: &[u8; 32]) -> Result<AnchorStatus, PlatformCaError> {
        // One read transaction: the evidence's end and the revocations are
        // one committed state.
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let until = sqlx::query_scalar("SELECT next_update FROM ca_issuer_status WHERE issuer = ?")
            .bind(issuer.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read an issuer's status"))?;
        let revoked = sqlx::query_scalar(
            "SELECT serial FROM ca_issuer_revoked WHERE issuer = ? ORDER BY serial",
        )
        .bind(issuer.as_slice())
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("read an issuer's revocations"))?;
        Ok(AnchorStatus { until, revoked })
    }

    async fn export_platform_cas(&self) -> Result<PlatformCaArchive, PlatformCaError> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        archive(&mut tx).await
    }

    async fn import_platform_cas(
        &self,
        moved: &PlatformCaArchive,
        ctx: MutationContext,
    ) -> Result<bool, PlatformCaError> {
        let mut tx = self.begin_write().await?;
        let held = archive(&mut tx).await?;
        if held == *moved {
            return Ok(false);
        }
        if !held.is_empty() {
            return Err(PlatformCaError::Occupied);
        }
        if let Some(set) = &moved.set {
            sqlx::query(
                "INSERT INTO platform_ca_set (id, revision, issued_at, next_update)
                 VALUES (1, ?, ?, ?)",
            )
            .bind(stored(set.revision, "revision")?)
            .bind(set.issued_at)
            .bind(set.next_update)
            .execute(&mut *tx)
            .await
            .map_err(storage("move the set"))?;
        }
        for generation in &moved.generations {
            sqlx::query(
                "INSERT INTO platform_ca_generations
                     (generation, certificate, state, overlap_end, listed_in)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(i64::from(generation.generation))
            .bind(generation.certificate.as_slice())
            .bind(generation.state.rank())
            .bind(generation.overlap_end)
            .bind(stored(generation.listed_in, "revision")?)
            .execute(&mut *tx)
            .await
            .map_err(storage("move a generation"))?;
        }
        for crl in &moved.status {
            let generation = i64::from(crl.generation);
            sqlx::query(
                "INSERT INTO platform_ca_status (generation, number, next_update)
                 VALUES (?, ?, ?)",
            )
            .bind(generation)
            .bind(stored(crl.number, "CRL number")?)
            .bind(crl.next_update)
            .execute(&mut *tx)
            .await
            .map_err(storage("move a CRL"))?;
            for serial in &crl.revoked {
                sqlx::query("INSERT INTO platform_ca_revoked (generation, serial) VALUES (?, ?)")
                    .bind(generation)
                    .bind(serial.as_slice())
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("move a revocation"))?;
            }
        }
        // The target held none: the same writes that record one hold it.
        for crl in &moved.issuers {
            hold_issuer_status(&mut tx, crl).await?;
        }
        Self::commit_mutation(tx, CHAIN, ctx).await?;
        Ok(true)
    }

    async fn apply_platform_cas(
        &self,
        set: &PlatformCaSet,
        ctx: MutationContext,
    ) -> Result<Applied, PlatformCaError> {
        let revision = stored(set.revision, "revision")?;
        let mut tx = self.begin_write().await?;
        let held: Option<i64> = sqlx::query_scalar("SELECT revision FROM platform_ca_set")
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read the held revision"))?;
        if held.is_some_and(|held| held > revision) {
            return Ok(Applied::Stale);
        }
        // Every generation is checked before anything is written: a set
        // naming a held generation with another certificate holds nothing.
        for generation in &set.generations {
            let certificate: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT certificate FROM platform_ca_generations WHERE generation = ?",
            )
            .bind(i64::from(generation.generation))
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read a generation"))?;
            if certificate.is_some_and(|held| held != generation.certificate) {
                return Err(PlatformCaError::Conflict(generation.generation));
            }
        }
        sqlx::query(
            "INSERT INTO platform_ca_set (id, revision, issued_at, next_update)
             VALUES (1, ?, ?, ?)
             ON CONFLICT (id) DO UPDATE SET revision = excluded.revision,
                 issued_at = excluded.issued_at, next_update = excluded.next_update",
        )
        .bind(revision)
        .bind(set.issued_at)
        .bind(set.next_update)
        .execute(&mut *tx)
        .await
        .map_err(storage("hold the set"))?;
        for generation in &set.generations {
            // Listed now in any case; the state moves only to a narrower
            // one, and a wider state keeps the narrower one already held.
            sqlx::query(
                "INSERT INTO platform_ca_generations
                     (generation, certificate, state, overlap_end, listed_in)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (generation) DO UPDATE SET listed_in = excluded.listed_in,
                     overlap_end = CASE WHEN platform_ca_generations.state <= excluded.state
                         THEN excluded.overlap_end ELSE platform_ca_generations.overlap_end END,
                     state = max(platform_ca_generations.state, excluded.state)",
            )
            .bind(i64::from(generation.generation))
            .bind(generation.certificate.as_slice())
            .bind(generation.state.rank())
            .bind(generation.overlap_end)
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(storage("hold a generation"))?;
        }
        Self::commit_mutation(tx, CHAIN, ctx).await?;
        Ok(Applied::Current)
    }

    async fn record_platform_ca_status(
        &self,
        status: &[GenerationStatus],
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError> {
        let mut tx = self.begin_write().await?;
        for crl in status {
            let generation = i64::from(crl.generation);
            sqlx::query(
                "INSERT INTO platform_ca_status (generation, number, next_update)
                 VALUES (?, ?, ?)
                 ON CONFLICT (generation) DO UPDATE SET number = excluded.number,
                     next_update = excluded.next_update
                 WHERE platform_ca_status.number <= excluded.number",
            )
            .bind(generation)
            .bind(stored(crl.number, "CRL number")?)
            .bind(crl.next_update)
            .execute(&mut *tx)
            .await
            .map_err(storage("hold a CRL"))?;
            // Kept whatever the number: an authenticated revocation stands.
            for serial in &crl.revoked {
                sqlx::query(
                    "INSERT INTO platform_ca_revoked (generation, serial) VALUES (?, ?)
                     ON CONFLICT (generation, serial) DO NOTHING",
                )
                .bind(generation)
                .bind(serial.as_slice())
                .execute(&mut *tx)
                .await
                .map_err(storage("hold a revocation"))?;
            }
        }
        Self::commit_mutation(tx, CHAIN, ctx).await?;
        Ok(())
    }

    async fn held_platform_cas(&self, now: i64) -> Result<HeldAnchors, PlatformCaError> {
        // One read transaction: the set, its generations and their status
        // are one committed state.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(storage("read the held set"))?;
        let set: Option<(i64, i64, i64)> =
            sqlx::query_as("SELECT revision, issued_at, next_update FROM platform_ca_set")
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage("read the held set"))?;
        let (revision, issued_at, next_update) = set.ok_or(PlatformCaError::NotProvisioned)?;
        if now > next_update {
            return Err(PlatformCaError::Stale);
        }
        let generations: Vec<(i64, Vec<u8>, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT g.generation, g.certificate, g.overlap_end, c.next_update
             FROM platform_ca_generations g
             LEFT JOIN platform_ca_status c ON c.generation = g.generation
             WHERE g.listed_in = ?
               AND (g.state = 0 OR (g.state = 1 AND g.overlap_end > ?))
             ORDER BY g.generation DESC",
        )
        .bind(revision)
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("read the held generations"))?;
        let mut until = next_update;
        let mut anchors = Vec::with_capacity(generations.len());
        let mut status = Vec::with_capacity(generations.len());
        for (generation, certificate, overlap_end, crl_until) in generations {
            if let Some(overlap_end) = overlap_end {
                until = until.min(overlap_end);
            }
            let revoked: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT serial FROM platform_ca_revoked WHERE generation = ? ORDER BY serial",
            )
            .bind(generation)
            .fetch_all(&mut *tx)
            .await
            .map_err(storage("read the revocations"))?;
            anchors.push(certificate);
            status.push(AnchorStatus {
                until: crl_until,
                revoked,
            });
        }
        Ok(HeldAnchors {
            revision: u64::try_from(revision).map_err(|_| {
                PlatformCaError::Storage(SidError::Storage("negative held revision".into()))
            })?,
            anchors,
            status,
            until,
            // Both are seconds since the epoch, so the halfway point cannot
            // overflow; a set issued after its own refresh time renews at
            // once.
            renew_at: issued_at + (next_update - issued_at).max(0) / 2,
        })
    }
}
