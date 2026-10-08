// SPDX-License-Identifier: AGPL-3.0-only
//! The account API's side of the account integration
//! (auth/session-management.md, API authority and identity boundary): the
//! access tokens it accepts besides the installation's own session tokens,
//! and whom they stand for.
//!
//! A token is accepted only when the installation's local issuer signed it
//! (`at+jwt`, RFC 9068 §4) for the account API resource, naming the client
//! it was issued to and no source `pid`. Such a token was issued to a client
//! of the installation organization under its local issuer, where the
//! subject rule is the managed Profile (`subject::SubjectRule::for_hop`), so
//! its `sub` is the local ProfileId: the typed caller is resolved from that
//! verified context, never from the shape of `sub`.

use std::sync::Arc;

use sid_core::models::{OidcIssuer, ProfileId, ResourceIndicator};
use sid_core::{Error as SidError, Result as SidResult};

use crate::issuer::IssuerRegistry;
use crate::jwt::AccessTokenClaims;
use crate::resource_token::ResourceTokenVerifier;

/// Verifies access tokens for the account API.
#[derive(Debug)]
pub struct AccountApiVerifier {
    tokens: ResourceTokenVerifier,
}

/// A verified account API token and the Profile it acts for.
#[derive(Debug)]
pub struct AccountApiToken {
    pub claims: AccessTokenClaims,
    pub profile_id: ProfileId,
}

impl AccountApiVerifier {
    /// A verifier of `issuer`'s tokens for the account API `indicator`, with
    /// its current keys.
    pub async fn new(
        issuers: Arc<IssuerRegistry>,
        issuer: OidcIssuer,
        indicator: ResourceIndicator,
    ) -> SidResult<Self> {
        Ok(Self {
            tokens: ResourceTokenVerifier::new(issuers, issuer, indicator).await?,
        })
    }

    /// The exact issuer identifier whose tokens this verifier accepts.
    pub fn issuer(&self) -> &str {
        self.tokens.issuer()
    }

    /// Verify `token` as an account API token: see the module documentation.
    pub async fn verify(&self, token: &str) -> SidResult<AccountApiToken> {
        let refused = |why: &str| SidError::AuthenticationFailed(format!("Invalid token: {why}"));
        let claims = self.tokens.verify(token).await?;
        // A source ProfileId never travels in an application token; one that
        // carries it was not issued by this issuer's application path.
        if claims.pid.is_some() {
            return Err(refused("carries a source profile id"));
        }
        let profile_id = ProfileId::parse(&claims.sub).map_err(|_| refused("subject"))?;
        Ok(AccountApiToken { claims, profile_id })
    }
}
