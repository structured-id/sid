// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's site enrollment for the PostgreSQL backend: one
//! record, replaced only in place of the one its writer read.

use sid_core::models::SiteEnrollment;
use sid_core::{Error as SidError, Result as SidResult};

use super::PostgresBackend;

/// The held enrollment read on `executor`; none before one was held.
async fn held<'e, E>(executor: E) -> SidResult<Option<SiteEnrollment>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT certificate, chain FROM site_enrollment WHERE scope = 'installation'",
    )
    .fetch_optional(executor)
    .await
    .map_err(|e| SidError::Storage(format!("read site enrollment: {e}")))?;
    row.map(|(certificate, chain)| {
        Ok(SiteEnrollment {
            certificate,
            chain: SiteEnrollment::chain_from_bytes(&chain)
                .ok_or_else(|| SidError::Storage("stored site enrollment: its chain".into()))?,
        })
    })
    .transpose()
}

impl PostgresBackend {
    pub(super) async fn site_enrollment_impl(&self) -> SidResult<Option<SiteEnrollment>> {
        held(&self.pool).await
    }

    pub(super) async fn set_site_enrollment_impl(
        &self,
        enrollment: &SiteEnrollment,
        expected: Option<&SiteEnrollment>,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        enrollment.check()?;
        let storage = |e: sqlx::Error| SidError::Storage(format!("write site enrollment: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // One writer at a time, also while no row exists yet; readers are
        // not held. What is read below is what this write replaces.
        sqlx::query("LOCK TABLE site_enrollment IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        if held(&mut *tx).await?.as_ref() != expected {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO site_enrollment (scope, certificate, chain, updated_at)
             VALUES ('installation', $1, $2, NOW())
             ON CONFLICT (scope) DO UPDATE SET
                 certificate = EXCLUDED.certificate,
                 chain = EXCLUDED.chain,
                 updated_at = NOW()",
        )
        .bind(enrollment.certificate.as_slice())
        .bind(enrollment.chain_bytes())
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::audit_in_tx(&mut tx, "installation:site_enrollment", ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
}
