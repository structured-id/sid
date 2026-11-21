// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's own APIs that its system integrations call
//! (auth/session-management.md, API authority and identity boundary): the
//! account API, for the account pages, and the administrative API, for the
//! administration console. Their access tokens are accepted besides the
//! installation's own session tokens, and stand for the user they were issued
//! for.
//!
//! A token is accepted only when the installation's local issuer signed it
//! (`at+jwt`, RFC 9068 §4) for exactly that API's resource, naming the client
//! it was issued to, stating that API's credential kind and carrying no
//! source `pid`. Such a token was issued to a client of the installation
//! organization under its local issuer, where the subject rule is the
//! managed Profile (`subject::SubjectRule::for_hop`), so its `sub` is the
//! local ProfileId: the typed caller is resolved from that verified context,
//! never from the shape of `sub`.
//!
//! An account API token never carries administrator authority. A console
//! token carries none of its own either: whether its user administers the
//! installation is read from the current assignments on every call, so a
//! revoked assignment ends the console's authority at once.

use std::sync::Arc;

use sid_core::models::{OidcIssuer, ProfileId, ResourceIndicator};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::StorageBackend;

use crate::issuer::IssuerRegistry;
use crate::jwt::{AccessTokenClaims, IssuedCredential};
use crate::resource_token::ResourceTokenVerifier;

/// Which of the installation's APIs a verifier accepts tokens for.
#[derive(Clone)]
enum Api {
    /// The account API: the user's own account, no administrator authority.
    Account,
    /// The administrative API: what the user's current assignments allow.
    Administration(Arc<dyn StorageBackend>),
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Account => "Account",
            Self::Administration(_) => "Administration",
        })
    }
}

/// Verifies access tokens for one of the installation's APIs.
#[derive(Debug)]
pub struct InstallationApiVerifier {
    tokens: ResourceTokenVerifier,
    indicator: ResourceIndicator,
    api: Api,
}

/// A verified token of one of the installation's APIs and the Profile it
/// acts for.
#[derive(Debug)]
pub struct InstallationApiToken {
    pub claims: AccessTokenClaims,
    pub profile_id: ProfileId,
    /// Whether the Profile administers the installation now; always false
    /// for the account API.
    pub administers: bool,
}

impl InstallationApiVerifier {
    /// A verifier of `issuer`'s tokens for the account API `indicator`.
    pub async fn account(
        issuers: Arc<IssuerRegistry>,
        issuer: OidcIssuer,
        indicator: ResourceIndicator,
    ) -> SidResult<Self> {
        Self::new(issuers, issuer, indicator, Api::Account).await
    }

    /// A verifier of `issuer`'s tokens for the administrative API
    /// `indicator`, reading the user's current authority from `storage`.
    pub async fn administration(
        issuers: Arc<IssuerRegistry>,
        issuer: OidcIssuer,
        indicator: ResourceIndicator,
        storage: Arc<dyn StorageBackend>,
    ) -> SidResult<Self> {
        Self::new(issuers, issuer, indicator, Api::Administration(storage)).await
    }

    async fn new(
        issuers: Arc<IssuerRegistry>,
        issuer: OidcIssuer,
        indicator: ResourceIndicator,
        api: Api,
    ) -> SidResult<Self> {
        Ok(Self {
            tokens: ResourceTokenVerifier::new(issuers, issuer, indicator.clone()).await?,
            indicator,
            api,
        })
    }

    /// The exact issuer identifier whose tokens this verifier accepts.
    pub fn issuer(&self) -> &str {
        self.tokens.issuer()
    }

    /// The resource indicator its tokens name as their audience.
    pub fn indicator(&self) -> &ResourceIndicator {
        &self.indicator
    }

    /// Whether this verifier is the administrative API's.
    pub fn is_administration(&self) -> bool {
        matches!(self.api, Api::Administration(_))
    }

    /// Verify `token` for this API: see the module documentation.
    pub async fn verify(&self, token: &str) -> SidResult<InstallationApiToken> {
        let refused = |why: &str| SidError::AuthenticationFailed(format!("Invalid token: {why}"));
        let claims = self.tokens.verify(token).await?;
        // A source ProfileId never travels in an application token; one that
        // carries it was not issued by this issuer's application path.
        if claims.pid.is_some() {
            return Err(refused("carries a source profile id"));
        }
        // Only what the issuer stated to be this API's kind of access is
        // accepted: another issuance path's token for this resource, or one
        // stating no kind, is no such credential.
        let expected = match self.api {
            Api::Account => IssuedCredential::AccountApi,
            Api::Administration(_) => IssuedCredential::Delegated,
        };
        if claims.credential_kind != Some(expected) {
            return Err(refused("not this API's credential kind"));
        }
        let profile_id = ProfileId::parse(&claims.sub).map_err(|_| refused("subject"))?;
        let administers = match &self.api {
            Api::Account => false,
            Api::Administration(storage) => {
                crate::account_roles::administers_installation(storage.as_ref(), profile_id).await?
            }
        };
        Ok(InstallationApiToken {
            claims,
            profile_id,
            administers,
        })
    }
}

#[cfg(test)]
mod tests;
