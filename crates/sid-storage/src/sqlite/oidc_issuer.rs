// SPDX-License-Identifier: AGPL-3.0-only
//! OIDC issuers: one per authority and recipient organization, with their
//! token-signing keys.

use sid_core::models::{
    IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, MutationContext, OidcIssuer, OrgId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{SqliteBackend, col, dt_col, fmt_dt, insert_error, parsed_col};

const ISSUER_COLUMNS: &str = "id, handle, canonical_url, authority, recipient_org, created_at";

fn issuer_from_row(row: &sqlx::sqlite::SqliteRow) -> SidResult<OidcIssuer> {
    let id: IssuerId = col(row, "id")?;
    let handle: String = col(row, "handle")?;
    Ok(OidcIssuer {
        id,
        handle: IssuerHandle::parse(&handle)
            .map_err(|e| SidError::Storage(format!("oidc issuer {id}: {e}")))?,
        canonical_url: col(row, "canonical_url")?,
        authority: parsed_col(row, "authority")?,
        recipient_org: col(row, "recipient_org")?,
        created_at: dt_col(row, "created_at")?,
    })
}

impl SqliteBackend {
    pub(crate) async fn oidc_issuer_for_impl(
        &self,
        authority: IssuerAuthority,
        recipient_org: OrgId,
    ) -> SidResult<Option<OidcIssuer>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ISSUER_COLUMNS} FROM oidc_issuers WHERE authority = ? AND recipient_org = ?"
        )))
        .bind(authority.as_str())
        .bind(recipient_org)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("oidc issuer: {e}")))?
        .as_ref()
        .map(issuer_from_row)
        .transpose()
    }

    pub(crate) async fn oidc_issuer_by_handle_impl(
        &self,
        handle: &IssuerHandle,
    ) -> SidResult<Option<OidcIssuer>> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ISSUER_COLUMNS} FROM oidc_issuers WHERE handle = ?"
        )))
        .bind(handle.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("oidc issuer by handle: {e}")))?
        .as_ref()
        .map(issuer_from_row)
        .transpose()
    }

    pub(crate) async fn insert_oidc_issuer_impl(
        &self,
        issuer: &OidcIssuer,
        first_key: &IssuerSigningKey,
        audit: MutationContext,
    ) -> SidResult<bool> {
        issuer.check_first_key(first_key)?;
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(
            "INSERT INTO oidc_issuers (id, handle, canonical_url, authority, recipient_org, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (authority, recipient_org) DO NOTHING",
        )
        .bind(issuer.id)
        .bind(issuer.handle.as_str())
        .bind(&issuer.canonical_url)
        .bind(issuer.authority.as_str())
        .bind(issuer.recipient_org)
        .bind(fmt_dt(&issuer.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("oidc issuer", e))?
        .rows_affected()
            == 1;
        if !inserted {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO oidc_issuer_signing_keys
                 (issuer_id, generation, key_id, public_key, sealed_private_key, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(first_key.issuer_id)
        .bind(i64::from(first_key.generation))
        .bind(&first_key.key_id)
        .bind(first_key.public_key.as_slice())
        .bind(&first_key.sealed_private_key)
        .bind(fmt_dt(&first_key.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("oidc issuer signing key", e))?;
        Self::commit_mutation(tx, &format!("oidc_issuer:{}", issuer.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn oidc_issuer_signing_keys_impl(
        &self,
        issuer: IssuerId,
    ) -> SidResult<Vec<IssuerSigningKey>> {
        let rows = sqlx::query(
            "SELECT issuer_id, generation, key_id, public_key, sealed_private_key, created_at
             FROM oidc_issuer_signing_keys WHERE issuer_id = ? ORDER BY generation",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("oidc issuer signing keys: {e}")))?;
        rows.iter()
            .map(|row| {
                let issuer_id: IssuerId = col(row, "issuer_id")?;
                let stored = |what: &str| {
                    SidError::Storage(format!("signing key of issuer {issuer_id}: {what}"))
                };
                let generation: i64 = col(row, "generation")?;
                let public_key: Vec<u8> = col(row, "public_key")?;
                Ok(IssuerSigningKey {
                    issuer_id,
                    generation: u32::try_from(generation)
                        .map_err(|_| stored("generation out of range"))?,
                    key_id: col(row, "key_id")?,
                    public_key: public_key
                        .try_into()
                        .map_err(|_| stored("public key is not 32 bytes"))?,
                    sealed_private_key: col(row, "sealed_private_key")?,
                    created_at: dt_col(row, "created_at")?,
                })
            })
            .collect()
    }
}
