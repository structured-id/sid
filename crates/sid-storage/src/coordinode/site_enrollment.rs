// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's site enrollment in CoordiNode: one node, replaced only
//! in place of the one its writer read.

use coordinode_core::graph::types::Value;
use sid_core::models::SiteEnrollment;
use sid_core::{Error as SidError, Result as SidResult};

use super::{CoordinodeBackend, Params, get_bytes, hold_first};

/// The one scope an enrollment is held for.
fn scope() -> Value {
    Value::String("installation".into())
}

/// The held enrollment of `row`.
fn held(row: &super::Row) -> SidResult<SiteEnrollment> {
    Ok(SiteEnrollment {
        certificate: get_bytes(row, "certificate")?,
        chain: SiteEnrollment::chain_from_bytes(&get_bytes(row, "chain")?)
            .ok_or_else(|| SidError::Storage("stored site enrollment: its chain".into()))?,
    })
}

/// The values of `enrollment` as a write binds them.
fn values(enrollment: &SiteEnrollment) -> Params {
    Params::default()
        .with("scope", scope())
        .with("certificate", Value::Binary(enrollment.certificate.clone()))
        // Each certificate behind its four-byte length, in order.
        .with("chain", Value::Binary(enrollment.chain_bytes()))
        .with("now", super::time(chrono::Utc::now()))
}

impl CoordinodeBackend {
    pub(super) async fn site_enrollment(&self) -> SidResult<Option<SiteEnrollment>> {
        self.read(|tx| {
            let rows = tx.run(
                "MATCH (s:SidSiteEnrollment) WHERE s.scope = $scope
                 RETURN s.certificate AS certificate, s.chain AS chain",
                Params::default().with("scope", scope()),
            )?;
            rows.first().map(held).transpose()
        })
        .await
    }

    pub(super) async fn set_site_enrollment(
        &self,
        enrollment: &SiteEnrollment,
        expected: Option<&SiteEnrollment>,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        enrollment.check()?;
        let enrollment = enrollment.clone();
        let expected = expected.cloned();
        self.transaction(move |tx| {
            // The held enrollment, held for the commit: a write committed
            // meanwhile conflicts with this one.
            let rows = tx.run(
                "MATCH (s:SidSiteEnrollment) WHERE s.scope = $scope
                 RETURN id(s) AS node, s.certificate AS certificate, s.chain AS chain",
                Params::default().with("scope", scope()),
            )?;
            let current = rows.first().map(held).transpose()?;
            if current != expected || (current.is_some() && !hold_first(tx, &rows)?) {
                return Ok(super::Decision::Abandon(false));
            }
            let updated = tx.run(
                "MATCH (s:SidSiteEnrollment) WHERE s.scope = $scope
                 SET s.certificate = $certificate, s.chain = $chain, s.updated_at = $now
                 RETURN s.scope AS scope",
                values(&enrollment),
            )?;
            if updated.is_empty() {
                // Another first write may have created the node since this
                // transaction looked: it then runs again, finds an
                // enrollment it did not expect and writes nothing.
                tx.create_absent(
                    "CREATE (s:SidSiteEnrollment {scope: $scope, certificate: $certificate,
                         chain: $chain, updated_at: $now})",
                    values(&enrollment),
                )?;
            }
            super::finalize(tx, "installation:site_enrollment", ctx.clone())?;
            Ok(super::Decision::Commit(true))
        })
        .await
    }
}
