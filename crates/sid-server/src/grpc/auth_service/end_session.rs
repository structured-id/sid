// SPDX-License-Identifier: AGPL-3.0-only
//! RP-Initiated Logout at an issuer's end-session endpoint: the engine's
//! ([`sid::oauth::end_session`]) with the browser's IdP session read from
//! its cookie only.

use sid::oauth::end_session::EndSessionError;
use sid_core::models::Session;
use tonic::metadata::MetadataMap;

pub(crate) use sid::oauth::end_session::{EndSession, LogoutRequest};

use super::*;

/// The answer to a failed logout.
fn end_session_refusal(e: EndSessionError) -> Status {
    match e {
        EndSessionError::Ceremony(e) => e.into_status(),
        EndSessionError::RandomUnavailable => {
            Status::internal("operating system random source unavailable")
        }
        EndSessionError::Store(e) => storage_failure(e),
    }
}

impl AuthServiceImpl {
    /// RP-Initiated Logout `request` at `issuer`, the browser's cookie in
    /// `metadata`.
    pub(crate) async fn end_session(
        &self,
        metadata: &MetadataMap,
        issuer: &OidcIssuer,
        request: LogoutRequest<'_>,
    ) -> Result<EndSession, Status> {
        let browser = self.browser_session(metadata).await?;
        self.end_sessions
            .end(&self.oauth, browser, issuer, request)
            .await
            .map_err(end_session_refusal)
    }

    /// The session this authority's IdP session cookie in `metadata` names,
    /// if it still exists.
    pub(super) async fn browser_session(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Option<Session>, Status> {
        let cookies = metadata
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok());
        self.sign_ins
            .browser_session(cookies)
            .await
            .map_err(sign_in_refusal)
    }
}
