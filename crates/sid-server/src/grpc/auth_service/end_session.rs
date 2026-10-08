// SPDX-License-Identifier: AGPL-3.0-only
//! RP-Initiated Logout at an issuer's end-session endpoint (OIDC
//! RP-Initiated Logout 1.0 §2). A validated `id_token_hint` ends the
//! application session it names, and single sign-on with it when that
//! session reuses the browser's IdP session; ending the browser's IdP
//! session otherwise takes the user's confirmation, by a one-time value the
//! confirmation page's form posts back. The browser's IdP session is read
//! from its cookie only. The browser returns to a post-logout redirect URI
//! only when a validated hint names the client that registered it (§3).

use base64::Engine;
use sid_authn::browser_session::BrowserSecret;
use sid_authn::jwt::IdTokenClaims;
use sid_core::models::Session;
use tonic::metadata::MetadataMap;

use super::*;

/// How long a confirmation page's form stays valid.
pub(super) const CONFIRMATION_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// What a logout confirmation form's value stands for.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct LogoutConfirmation {
    /// The browser's IdP session the confirmation ends.
    session: SessionId,
    /// Where the browser returns afterwards: a validated post-logout
    /// redirect, `state` included.
    return_to: Option<url::Url>,
}

/// The parameters of a logout request (OIDC RP-Initiated Logout 1.0 §2).
#[derive(Default)]
pub(crate) struct LogoutRequest<'a> {
    pub(crate) id_token_hint: Option<&'a str>,
    pub(crate) client_id: Option<&'a str>,
    pub(crate) post_logout_redirect_uri: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    /// The value of this endpoint's own confirmation form.
    pub(crate) confirmation: Option<&'a str>,
}

/// What the end-session endpoint did and answers with. `return_to` is where
/// the browser goes instead of a page.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EndSession {
    /// The browser's IdP session ended (single sign-on with it): the answer
    /// clears the cookie.
    SignedOut { return_to: Option<url::Url> },
    /// The relying party's own session ended; the browser keeps its IdP
    /// session, and may confirm ending it with `confirmation`.
    ApplicationSignedOut {
        confirmation: Option<String>,
        return_to: Option<url::Url>,
    },
    /// Nothing ended: the user confirms ending the browser's IdP session with
    /// `confirmation`.
    Confirm { confirmation: String },
    /// There is no session to end.
    NothingToEnd { return_to: Option<url::Url> },
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

        // The confirmation form ends the IdP session it was issued for, and
        // only while this browser still holds it.
        if let Some(confirmation) = request.confirmation {
            let confirmed = self
                .logout_confirmations
                .take(confirmation)
                .await?
                .filter(|confirmed| browser.as_ref().is_some_and(|b| b.id == confirmed.session));
            if let (Some(confirmed), Some(browser)) = (confirmed, &browser) {
                self.end_browser_session(browser).await?;
                return Ok(EndSession::SignedOut {
                    return_to: confirmed.return_to,
                });
            }
        }

        let hint = self
            .validated_hint(issuer, request.id_token_hint, request.client_id)
            .await?;
        let return_to = match (&hint, request.post_logout_redirect_uri) {
            (Some(hint), Some(uri)) => self.post_logout_target(hint, uri, request.state).await?,
            _ => None,
        };
        let application = match &hint {
            Some(hint) => self.hinted_session(hint).await?,
            None => None,
        };

        match application {
            Some(application) => {
                // The application's session reuses this browser's IdP session:
                // ending that ends both (the cascade ends its dependents).
                if let Some(browser) = browser.as_ref().filter(|b| {
                    application.authenticated_by == Some(b.id) || application.id == b.id
                }) {
                    self.end_browser_session(browser).await?;
                    return Ok(EndSession::SignedOut { return_to });
                }
                self.cascade
                    .revoke_session(
                        application.id,
                        RevocationReason::UserRequested,
                        &application.profile_id.to_string(),
                        "session.end_session",
                    )
                    .await
                    .map_err(storage_failure)?;
                let confirmation = match &browser {
                    Some(browser) => Some(self.confirmation_for(browser, return_to.clone()).await?),
                    None => None,
                };
                Ok(EndSession::ApplicationSignedOut {
                    confirmation,
                    return_to,
                })
            }
            None => match (&browser, &hint) {
                // A valid hint whose session already ended: the relying party
                // is signed out; ending the IdP session is still offered.
                (Some(browser), Some(_)) => Ok(EndSession::ApplicationSignedOut {
                    confirmation: Some(self.confirmation_for(browser, return_to.clone()).await?),
                    return_to,
                }),
                (Some(browser), None) => Ok(EndSession::Confirm {
                    confirmation: self.confirmation_for(browser, None).await?,
                }),
                (None, _) => Ok(EndSession::NothingToEnd { return_to }),
            },
        }
    }

    /// The session the browser's IdP session cookie in `metadata` names, if
    /// it still exists.
    async fn browser_session(&self, metadata: &MetadataMap) -> Result<Option<Session>, Status> {
        let cookies = metadata
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok());
        let Some(secret) = BrowserSecret::from_cookie_headers(cookies) else {
            return Ok(None);
        };
        self.storage
            .get_session_by_browser_secret(&secret.hash())
            .await
            .map_err(storage_failure)
    }

    /// The claims of a valid `id_token_hint` of `issuer`: an ID token of this
    /// issuer whose audience is `client_id` when given. Anything else is no
    /// hint.
    async fn validated_hint(
        &self,
        issuer: &OidcIssuer,
        id_token_hint: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<Option<IdTokenClaims>, Status> {
        let Some(hint) = id_token_hint.filter(|hint| !hint.is_empty()) else {
            return Ok(None);
        };
        let verifier = self
            .issuers
            .verifier(issuer)
            .await
            .map_err(storage_failure)?;
        let Ok(claims) = verifier.validate_id_token_hint(hint) else {
            return Ok(None);
        };
        if client_id.is_some_and(|client| client != claims.aud) {
            return Ok(None);
        }
        Ok(Some(claims))
    }

    /// The application session `hint` names, when it is a session of the
    /// hint's client that still exists.
    async fn hinted_session(&self, hint: &IdTokenClaims) -> Result<Option<Session>, Status> {
        let Some(session_id) = hint
            .sid
            .as_deref()
            .and_then(|sid| SessionId::parse(sid).ok())
        else {
            return Ok(None);
        };
        Ok(self
            .storage
            .get_session(session_id)
            .await
            .map_err(storage_failure)?
            .filter(|session| session.client_id.as_deref() == Some(hint.aud.as_str())))
    }

    /// `uri` with `state` added, when the active client `hint` names
    /// registered exactly `uri` as a post-logout redirect URI (§3); none
    /// otherwise.
    async fn post_logout_target(
        &self,
        hint: &IdTokenClaims,
        uri: &str,
        state: Option<&str>,
    ) -> Result<Option<url::Url>, Status> {
        let registered = self
            .storage
            .get_oauth2_client(&hint.aud)
            .await
            .map_err(storage_failure)?
            .is_some_and(|client| client.active && client.is_post_logout_redirect_uri_allowed(uri));
        if !registered {
            return Ok(None);
        }
        let Ok(mut target) = url::Url::parse(uri) else {
            return Ok(None);
        };
        if let Some(state) = state.filter(|state| !state.is_empty()) {
            target.query_pairs_mut().append_pair("state", state);
        }
        Ok(Some(target))
    }

    /// End `browser`, the browser's IdP session, and the sessions it
    /// authenticated.
    async fn end_browser_session(&self, browser: &Session) -> Result<(), Status> {
        self.cascade
            .revoke_session(
                browser.id,
                RevocationReason::UserRequested,
                &browser.profile_id.to_string(),
                "session.end_session",
            )
            .await
            .map_err(storage_failure)?;
        Ok(())
    }

    /// A one-time confirmation value for ending `browser`, returning to
    /// `return_to` afterwards.
    async fn confirmation_for(
        &self,
        browser: &Session,
        return_to: Option<url::Url>,
    ) -> Result<String, Status> {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let confirmation = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.logout_confirmations
            .insert(
                &confirmation,
                &LogoutConfirmation {
                    session: browser.id,
                    return_to,
                },
            )
            .await?;
        Ok(confirmation)
    }
}
