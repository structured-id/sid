// SPDX-License-Identifier: AGPL-3.0-only
//! The authoritative store of an application composed with SID, such as a
//! browser adapter's sessions: the ceremony state capability over the
//! database the deployment names for that application.

use std::sync::Arc;

use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::CeremonyStateStore;

/// The ceremony state store in the database at `url`: PostgreSQL
/// (`postgres://`, `postgresql://`) for replicas sharing it, SQLite
/// (`sqlite:`) for a single instance. A database without the schema gets it;
/// one of another schema is refused unchanged.
pub async fn ceremony_store(url: &str) -> SidResult<Arc<dyn CeremonyStateStore>> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        #[cfg(feature = "storage-pg")]
        {
            let backend = crate::PostgresBackend::new(url, None).await?;
            crate::migrator::run_migrations(backend.pool(), None).await?;
            return Ok(Arc::new(backend));
        }
        #[cfg(not(feature = "storage-pg"))]
        return Err(SidError::Validation(
            "this build has no PostgreSQL storage".into(),
        ));
    }
    if url.starts_with("sqlite:") {
        #[cfg(feature = "storage-sqlite")]
        return Ok(Arc::new(crate::sqlite::SqliteBackend::new(url).await?));
        #[cfg(not(feature = "storage-sqlite"))]
        return Err(SidError::Validation(
            "this build has no SQLite storage".into(),
        ));
    }
    Err(SidError::Validation(
        "the application database URL names neither postgres:// nor sqlite:".into(),
    ))
}

#[cfg(test)]
mod tests;
