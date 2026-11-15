// SPDX-License-Identifier: AGPL-3.0-only
//! Handing the platform a site's signed admission statement
//! (`sid.v1.federation.SiteAdmissionService.PublishSiteAdmission`): the
//! host's transport to the platform its build names.
//!
//! The statement authenticates itself; the transport carries it and reports
//! how the platform answered, nothing else.

use async_trait::async_trait;

/// How the platform took a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// It holds this statement's conditions now (or already did).
    Held,
    /// It holds a newer revision for the entry: this one has nothing left
    /// to deliver.
    Superseded,
}

/// Why a statement was not taken.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The platform did not answer or cannot decide now: the same statement
    /// may be published again later.
    #[error("the platform is unavailable: {0}")]
    Unavailable(String),
    /// The platform refused the statement itself: publishing it again
    /// cannot succeed.
    #[error("the platform refused the statement: {0}")]
    Refused(String),
}

/// The transport of a site's statements to its build's platform.
#[async_trait]
pub trait AdmissionPublisher: Send + Sync {
    /// Publish `statement` (a `sid-login-admission+jws`, as signed).
    async fn publish(&self, statement: &[u8]) -> Result<Published, PublishError>;
}
