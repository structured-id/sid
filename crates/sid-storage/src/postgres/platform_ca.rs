// SPDX-License-Identifier: AGPL-3.0-only
//! The admitted platform CA set in PostgreSQL. An apply writes the set's
//! single row first and only when its revision is not older: that
//! conditional write holds the row until commit, so concurrent applies
//! serialize on it and an older set changes nothing.

use async_trait::async_trait;
use sid_core::Error as SidError;
use sid_core::models::MutationContext;
use sid_plugin::platform_ca::{
    AnchorStatus, Applied, GenerationStatus, HeldAnchors, HeldGeneration, HeldSet, IssuerStatus,
    PlatformCaArchive, PlatformCaError, PlatformCaSet, PlatformCaState, PlatformCaStore,
};

use super::PostgresBackend;

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

/// Everything the store holds, as `conn`'s transaction sees it.
async fn archive(conn: &mut sqlx::PgConnection) -> Result<PlatformCaArchive, PlatformCaError> {
    let set: Option<(i64, i64, i64)> =
        sqlx::query_as("SELECT revision, issued_at, next_update FROM platform_ca_set WHERE id = 1")
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
    let rows: Vec<(i64, Vec<u8>, i16, Option<i64>, i64)> = sqlx::query_as(
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
            state: PlatformCaState::from_rank(i64::from(state)).ok_or_else(|| {
                PlatformCaError::Storage(SidError::Storage(format!(
                    "stored platform CA state {state}"
                )))
            })?,
            overlap_end,
            listed_in: unsigned(listed_in, "revision")?,
        });
    }
    let rows: Vec<(i64, i64, i64, Vec<Vec<u8>>)> = sqlx::query_as(
        "SELECT c.generation, c.number, c.next_update,
                COALESCE((SELECT array_agg(r.serial ORDER BY r.serial)
                          FROM platform_ca_revoked r
                          WHERE r.generation = c.generation), '{}')
         FROM platform_ca_status c ORDER BY c.generation",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("read the status"))?;
    let mut status = Vec::with_capacity(rows.len());
    for (generation, number, next_update, revoked) in rows {
        status.push(GenerationStatus {
            generation: unsigned(generation, "generation")?,
            number: unsigned(number, "CRL number")?,
            next_update,
            revoked,
        });
    }
    let rows: Vec<(Vec<u8>, i64, i64, Vec<Vec<u8>>)> = sqlx::query_as(
        "SELECT c.issuer, c.number, c.next_update,
                COALESCE((SELECT array_agg(r.serial ORDER BY r.serial)
                          FROM ca_issuer_revoked r WHERE r.issuer = c.issuer), '{}')
         FROM ca_issuer_status c ORDER BY c.issuer",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("read the issuer status"))?;
    let mut issuers = Vec::with_capacity(rows.len());
    for (issuer, number, next_update, revoked) in rows {
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
/// the held one (concurrent recorders serialize on the issuer's row, so the
/// highest number stands), and every serial it revokes whatever the number.
async fn hold_issuer_status(
    tx: &mut sqlx::PgConnection,
    crl: &IssuerStatus,
) -> Result<(), PlatformCaError> {
    sqlx::query(
        "INSERT INTO ca_issuer_status (issuer, number, next_update) VALUES ($1, $2, $3)
         ON CONFLICT (issuer) DO UPDATE SET number = EXCLUDED.number,
             next_update = EXCLUDED.next_update
         WHERE ca_issuer_status.number <= EXCLUDED.number",
    )
    .bind(crl.issuer.as_slice())
    .bind(stored(crl.number, "CRL number")?)
    .bind(crl.next_update)
    .execute(&mut *tx)
    .await
    .map_err(storage("hold an issuer's CRL"))?;
    if !crl.revoked.is_empty() {
        sqlx::query(
            "INSERT INTO ca_issuer_revoked (issuer, serial)
             SELECT $1, serial FROM UNNEST($2::bytea[]) AS revoked(serial)
             ON CONFLICT (issuer, serial) DO NOTHING",
        )
        .bind(crl.issuer.as_slice())
        .bind(&crl.revoked)
        .execute(&mut *tx)
        .await
        .map_err(storage("hold an issuer's revocations"))?;
    }
    Ok(())
}

#[async_trait]
impl PlatformCaStore for PostgresBackend {
    async fn record_issuer_status(
        &self,
        status: &IssuerStatus,
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        hold_issuer_status(&mut tx, status).await?;
        Self::audit_in_tx(&mut tx, CHAIN, ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    async fn held_issuer_status(&self, issuer: &[u8; 32]) -> Result<AnchorStatus, PlatformCaError> {
        // One statement: the evidence's end and the revocations are one
        // committed state. An issuer with revocations always has its row.
        let held: Option<(i64, Vec<Vec<u8>>)> = sqlx::query_as(
            "SELECT c.next_update,
                    COALESCE((SELECT array_agg(r.serial ORDER BY r.serial)
                              FROM ca_issuer_revoked r WHERE r.issuer = c.issuer), '{}')
             FROM ca_issuer_status c WHERE c.issuer = $1",
        )
        .bind(issuer.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("read an issuer's status"))?;
        Ok(
            held.map_or_else(AnchorStatus::default, |(until, revoked)| AnchorStatus {
                until: Some(until),
                revoked,
            }),
        )
    }

    async fn export_platform_cas(&self) -> Result<PlatformCaArchive, PlatformCaError> {
        // One snapshot for every table: the archive is one committed state.
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(storage("begin"))?;
        archive(&mut tx).await
    }

    async fn import_platform_cas(
        &self,
        moved: &PlatformCaArchive,
        ctx: MutationContext,
    ) -> Result<bool, PlatformCaError> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // Imports of one installation are decided one after the other: the
        // second reads what the first committed.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('sid.platform_ca.import'))")
            .execute(&mut *tx)
            .await
            .map_err(storage("serialize the move"))?;
        let held = archive(&mut tx).await?;
        if held == *moved {
            return Ok(false);
        }
        if !held.is_empty() {
            return Err(PlatformCaError::Occupied);
        }
        // A plain insert: state another writer committed meanwhile collides
        // on its key and the move is refused whole.
        if let Some(set) = &moved.set {
            sqlx::query(
                "INSERT INTO platform_ca_set (id, revision, issued_at, next_update)
                 VALUES (1, $1, $2, $3)",
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
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(i64::from(generation.generation))
            .bind(generation.certificate.as_slice())
            // A rank is 0, 1 or 2.
            .bind(generation.state.rank() as i16)
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
                 VALUES ($1, $2, $3)",
            )
            .bind(generation)
            .bind(stored(crl.number, "CRL number")?)
            .bind(crl.next_update)
            .execute(&mut *tx)
            .await
            .map_err(storage("move a CRL"))?;
            if !crl.revoked.is_empty() {
                sqlx::query(
                    "INSERT INTO platform_ca_revoked (generation, serial)
                     SELECT $1, serial FROM UNNEST($2::bytea[]) AS revoked(serial)",
                )
                .bind(generation)
                .bind(&crl.revoked)
                .execute(&mut *tx)
                .await
                .map_err(storage("move the revocations"))?;
            }
        }
        // The target held none: the same writes that record one hold it.
        for crl in &moved.issuers {
            hold_issuer_status(&mut tx, crl).await?;
        }
        Self::audit_in_tx(&mut tx, CHAIN, ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(true)
    }

    async fn apply_platform_cas(
        &self,
        set: &PlatformCaSet,
        ctx: MutationContext,
    ) -> Result<Applied, PlatformCaError> {
        let revision = stored(set.revision, "revision")?;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let held = sqlx::query(
            "INSERT INTO platform_ca_set (id, revision, issued_at, next_update)
             VALUES (1, $1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET revision = EXCLUDED.revision,
                 issued_at = EXCLUDED.issued_at, next_update = EXCLUDED.next_update
             WHERE platform_ca_set.revision <= EXCLUDED.revision",
        )
        .bind(revision)
        .bind(set.issued_at)
        .bind(set.next_update)
        .execute(&mut *tx)
        .await
        .map_err(storage("hold the set"))?;
        if held.rows_affected() == 0 {
            return Ok(Applied::Stale);
        }
        for generation in &set.generations {
            let number = i64::from(generation.generation);
            let certificate: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT certificate FROM platform_ca_generations WHERE generation = $1",
            )
            .bind(number)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read a generation"))?;
            // Dropping the transaction rolls the set's row back with it.
            if certificate.is_some_and(|held| held != generation.certificate) {
                return Err(PlatformCaError::Conflict(generation.generation));
            }
            // Listed now in any case; the state moves only to a narrower
            // one, and a wider state keeps the narrower one already held.
            sqlx::query(
                "INSERT INTO platform_ca_generations
                     (generation, certificate, state, overlap_end, listed_in)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (generation) DO UPDATE SET listed_in = EXCLUDED.listed_in,
                     overlap_end = CASE WHEN platform_ca_generations.state <= EXCLUDED.state
                         THEN EXCLUDED.overlap_end ELSE platform_ca_generations.overlap_end END,
                     state = GREATEST(platform_ca_generations.state, EXCLUDED.state)",
            )
            .bind(number)
            .bind(generation.certificate.as_slice())
            // A rank is 0, 1 or 2.
            .bind(generation.state.rank() as i16)
            .bind(generation.overlap_end)
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(storage("hold a generation"))?;
        }
        Self::audit_in_tx(&mut tx, CHAIN, ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(Applied::Current)
    }

    async fn record_platform_ca_status(
        &self,
        status: &[GenerationStatus],
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        for crl in status {
            let generation = i64::from(crl.generation);
            sqlx::query(
                "INSERT INTO platform_ca_status (generation, number, next_update)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (generation) DO UPDATE SET number = EXCLUDED.number,
                     next_update = EXCLUDED.next_update
                 WHERE platform_ca_status.number <= EXCLUDED.number",
            )
            .bind(generation)
            .bind(stored(crl.number, "CRL number")?)
            .bind(crl.next_update)
            .execute(&mut *tx)
            .await
            .map_err(storage("hold a CRL"))?;
            // Kept whatever the number: an authenticated revocation stands.
            if !crl.revoked.is_empty() {
                sqlx::query(
                    "INSERT INTO platform_ca_revoked (generation, serial)
                     SELECT $1, serial FROM UNNEST($2::bytea[]) AS revoked(serial)
                     ON CONFLICT (generation, serial) DO NOTHING",
                )
                .bind(generation)
                .bind(&crl.revoked)
                .execute(&mut *tx)
                .await
                .map_err(storage("hold the revocations"))?;
            }
        }
        Self::audit_in_tx(&mut tx, CHAIN, ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    async fn held_platform_cas(&self, now: i64) -> Result<HeldAnchors, PlatformCaError> {
        // One statement reads the set, its generations and their status, so
        // the answer is one committed revision. A revocation committed after
        // it is one more refusal on the next read, never one fewer.
        type Row = (
            i64,
            i64,
            i64,
            Option<i64>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
            Vec<Vec<u8>>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT s.revision, s.issued_at, s.next_update, g.generation, g.certificate,
                    g.overlap_end, c.next_update,
                    COALESCE((SELECT array_agg(r.serial ORDER BY r.serial)
                              FROM platform_ca_revoked r
                              WHERE r.generation = g.generation), '{}')
             FROM platform_ca_set s
             LEFT JOIN platform_ca_generations g ON g.listed_in = s.revision
                 AND (g.state = 0 OR (g.state = 1 AND g.overlap_end > $1))
             LEFT JOIN platform_ca_status c ON c.generation = g.generation
             WHERE s.id = 1 ORDER BY g.generation DESC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(storage("read the held set"))?;
        let &(revision, issued_at, next_update, ..) =
            rows.first().ok_or(PlatformCaError::NotProvisioned)?;
        if now > next_update {
            return Err(PlatformCaError::Stale);
        }
        let mut until = next_update;
        let mut anchors = Vec::with_capacity(rows.len());
        let mut status = Vec::with_capacity(rows.len());
        for (.., certificate, overlap_end, crl_until, revoked) in rows {
            // A set that lists no anchoring generation is one row without
            // a certificate.
            let Some(certificate) = certificate else {
                continue;
            };
            if let Some(overlap_end) = overlap_end {
                until = until.min(overlap_end);
            }
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
