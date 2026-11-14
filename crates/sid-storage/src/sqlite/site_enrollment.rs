// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's site enrollment for the SQLite backend: one record,
//! replaced only in place of the one its writer read.

use sid_core::models::SiteEnrollment;
use sid_core::{Error as SidError, Result as SidResult};

use super::SqliteBackend;

/// The held enrollment read on `executor`; none before one was held.
async fn held<'e, E>(executor: E) -> SidResult<Option<SiteEnrollment>>
where
    E: sqlx::SqliteExecutor<'e>,
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

impl SqliteBackend {
    pub(crate) async fn site_enrollment_impl(&self) -> SidResult<Option<SiteEnrollment>> {
        held(&self.pool).await
    }

    pub(crate) async fn set_site_enrollment_impl(
        &self,
        enrollment: &SiteEnrollment,
        expected: Option<&SiteEnrollment>,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        enrollment.check()?;
        // The write lock is held from here: what is read below is what this
        // write replaces.
        let mut tx = self.begin_write().await?;
        if held(&mut *tx).await?.as_ref() != expected {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO site_enrollment (scope, certificate, chain, updated_at)
             VALUES ('installation', ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT (scope) DO UPDATE SET
                 certificate = excluded.certificate,
                 chain = excluded.chain,
                 updated_at = excluded.updated_at",
        )
        .bind(enrollment.certificate.as_slice())
        .bind(enrollment.chain_bytes())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("write site enrollment: {e}")))?;
        Self::commit_mutation(tx, "installation:site_enrollment", ctx).await?;
        Ok(true)
    }
}
