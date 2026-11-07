// SPDX-License-Identifier: AGPL-3.0-only
//! RP-Initiated Logout at an issuer's end-session endpoint (OIDC
//! RP-Initiated Logout 1.0 §2). A validated `id_token_hint` ends the
//! application session it names, and single sign-on with it when that
//! session reuses the browser's IdP session; ending the browser's IdP
//! session otherwise takes the user's confirmation, by a one-time value the
//! confirmation page's form posts back. The browser returns to a post-logout
//! redirect URI only when a validated hint names the client that registered
//! it (§3).

use std::sync::Arc;

use base64::Engine;
use sid_authn::challenge_store::{ChallengeStore, ChallengeStoreError};
use sid_authn::jwt::IdTokenClaims;
use sid_core::Error as SidError;
use sid_core::models::{OidcIssuer, RevocationReason, Session, SessionId};

use super::OAuth;

/// Why a logout is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EndSessionError {
    /// The confirmation could not be kept or read.
    #[error(transparent)]
    Ceremony(#[from] ChallengeStoreError),
    /// No random confirmation value could be drawn.
    #[error("operating system random source unavailable")]
    RandomUnavailable,
    #[error("store: {0}")]
    Store(#[from] SidError),
}

/// How long a confirmation page's form stays valid.
const CONFIRMATION_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// What a logout confirmation form's value stands for.
#[derive(serde::Serialize, serde::Deserialize)]
struct LogoutConfirmation {
    /// The browser's IdP session the confirmation ends.
    session: SessionId,
    /// Where the browser returns afterwards: a validated post-logout
    /// redirect, `state` included.
    return_to: Option<url::Url>,
}

/// The parameters of a logout request (OIDC RP-Initiated Logout 1.0 §2).
#[derive(Default)]
pub struct LogoutRequest<'a> {
    pub id_token_hint: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub post_logout_redirect_uri: Option<&'a str>,
    pub state: Option<&'a str>,
    /// The value of this endpoint's own confirmation form.
    pub confirmation: Option<&'a str>,
}

/// What the end-session endpoint did and answers with. `return_to` is where
/// the browser goes instead of a page.
#[derive(Debug, PartialEq, Eq)]
pub enum EndSession {
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

/// The end-session endpoint of one installation, with the confirmations it
/// offered and not yet received.
pub struct EndSessions {
    confirmations: ChallengeStore<LogoutConfirmation>,
}

impl EndSessions {
    pub fn new(
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            confirmations: ChallengeStore::new(
                ceremonies,
                keys,
                "logout-confirmation",
                CONFIRMATION_TTL,
            ),
        }
    }

    /// RP-Initiated Logout `request` at `issuer`, with `browser`, the
    /// browser's IdP session by its cookie.
    pub async fn end(
        &self,
        oauth: &OAuth,
        browser: Option<Session>,
        issuer: &OidcIssuer,
        request: LogoutRequest<'_>,
    ) -> Result<EndSession, EndSessionError> {
        // The confirmation form ends the IdP session it was issued for, and
        // only while this browser still holds it.
        if let Some(confirmation) = request.confirmation {
            let confirmed = self
                .confirmations
                .take(confirmation)
                .await?
                .filter(|confirmed| browser.as_ref().is_some_and(|b| b.id == confirmed.session));
            if let (Some(confirmed), Some(browser)) = (confirmed, &browser) {
                end_browser_session(oauth, browser).await?;
                return Ok(EndSession::SignedOut {
                    return_to: confirmed.return_to,
                });
            }
        }

        let hint = validated_hint(oauth, issuer, request.id_token_hint, request.client_id).await?;
        let return_to = match (&hint, request.post_logout_redirect_uri) {
            (Some(hint), Some(uri)) => post_logout_target(oauth, hint, uri, request.state).await?,
            _ => None,
        };
        let application = match &hint {
            Some(hint) => hinted_session(oauth, hint).await?,
            None => None,
        };

        match application {
            Some(application) => {
                // The application's session reuses this browser's IdP
                // session: ending that ends both (the cascade ends its
                // dependents).
                if let Some(browser) = browser.as_ref().filter(|b| {
                    application.authenticated_by == Some(b.id) || application.id == b.id
                }) {
                    end_browser_session(oauth, browser).await?;
                    return Ok(EndSession::SignedOut { return_to });
                }
                oauth
                    .cascade
                    .revoke_session(
                        application.id,
                        RevocationReason::UserRequested,
                        &application.profile_id.to_string(),
                        "session.end_session",
                    )
                    .await?;
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
                // A valid hint whose session already ended: the relying
                // party is signed out; ending the IdP session is still
                // offered.
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

    /// A one-time confirmation value for ending `browser`, returning to
    /// `return_to` afterwards.
    async fn confirmation_for(
        &self,
        browser: &Session,
        return_to: Option<url::Url>,
    ) -> Result<String, EndSessionError> {
        let mut bytes = [0u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut bytes)
            .map_err(|_| EndSessionError::RandomUnavailable)?;
        let confirmation = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.confirmations
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

/// The claims of a valid `id_token_hint` of `issuer`: an ID token of this
/// issuer whose audience is `client_id` when given. Anything else is no
/// hint.
async fn validated_hint(
    oauth: &OAuth,
    issuer: &OidcIssuer,
    id_token_hint: Option<&str>,
    client_id: Option<&str>,
) -> Result<Option<IdTokenClaims>, EndSessionError> {
    let Some(hint) = id_token_hint.filter(|hint| !hint.is_empty()) else {
        return Ok(None);
    };
    let verifier = oauth.issuers.verifier(issuer).await?;
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
async fn hinted_session(
    oauth: &OAuth,
    hint: &IdTokenClaims,
) -> Result<Option<Session>, EndSessionError> {
    let Some(session_id) = hint
        .sid
        .as_deref()
        .and_then(|sid| SessionId::parse(sid).ok())
    else {
        return Ok(None);
    };
    Ok(oauth
        .storage
        .get_session(session_id)
        .await?
        .filter(|session| session.client_id.as_deref() == Some(hint.aud.as_str())))
}

/// `uri` with `state` added, when the active client `hint` names registered
/// exactly `uri` as a post-logout redirect URI (§3); none otherwise.
async fn post_logout_target(
    oauth: &OAuth,
    hint: &IdTokenClaims,
    uri: &str,
    state: Option<&str>,
) -> Result<Option<url::Url>, EndSessionError> {
    let registered = oauth
        .storage
        .get_oauth2_client(&hint.aud)
        .await?
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
async fn end_browser_session(oauth: &OAuth, browser: &Session) -> Result<(), EndSessionError> {
    oauth
        .cascade
        .revoke_session(
            browser.id,
            RevocationReason::UserRequested,
            &browser.profile_id.to_string(),
            "session.end_session",
        )
        .await?;
    Ok(())
}
