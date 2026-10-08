// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization endpoint's core, shared by the typed RPC, where a bearer
//! token names the session, and the browser endpoint, where the IdP session
//! cookie does. A browser request the user must first sign in for is kept
//! server-side and continued by an opaque reference, never rebuilt from the
//! URL the sign-in page returns to.

use base64::Engine;
use chrono::{DateTime, Utc};
use sid_authn::browser_session::BrowserSecret;
use sid_authn::oauth2::prompt::Prompt;
use sid_core::models::{OAuth2Client, Session};
use tonic::metadata::MetadataMap;

use super::*;

/// Whether `status` asks the user to authenticate further (STEP_UP_REQUIRED),
/// as opposed to any other refusal of the request.
fn asks_step_up(status: &Status) -> bool {
    sid_core::grpc_error::extract_error_info(status)
        .is_some_and(|(reason, _, _)| reason == ErrorReason::StepUpRequired.as_str())
}

/// How long a kept authorization request waits for the user to sign in.
pub(super) const CONTINUATION_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// An authorization request the browser endpoint keeps while the user signs
/// in, or while a cross-site POST continues on the issuer host.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingAuthorization {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    acr_values: Option<String>,
    issuer_handle: String,
    resource: Vec<String>,
    prompt: Option<String>,
    max_age: Option<u32>,
    /// When the request arrived: `prompt=login` and `max_age` count from it.
    arrived_at: DateTime<Utc>,
    /// The interaction `prompt` asked for (account selection, consent) has
    /// been offered on the sign-in page.
    interacted: bool,
}

impl PendingAuthorization {
    /// `request` as it arrives now.
    pub(crate) fn arrived(request: OAuth2AuthorizeRequest) -> Self {
        Self {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            response_type: request.response_type,
            scope: request.scope,
            state: request.state,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            nonce: request.nonce,
            acr_values: request.acr_values,
            issuer_handle: request.issuer_handle,
            resource: request.resource,
            prompt: request.prompt,
            max_age: request.max_age,
            arrived_at: Utc::now(),
            interacted: false,
        }
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn issuer_handle(&self) -> &str {
        &self.issuer_handle
    }

    pub(crate) fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub(crate) fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// The request as the typed RPC carries it.
    pub(crate) fn request(&self) -> OAuth2AuthorizeRequest {
        OAuth2AuthorizeRequest {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            response_type: self.response_type.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            nonce: self.nonce.clone(),
            acr_values: self.acr_values.clone(),
            issuer_handle: self.issuer_handle.clone(),
            resource: self.resource.clone(),
            prompt: self.prompt.clone(),
            max_age: self.max_age,
            request_uri: None,
        }
    }
}

/// What the browser endpoint answers an authorization request with.
pub(crate) enum BrowserAuthorization {
    /// The authorization response for the client.
    Answer(OAuth2AuthorizeResponse),
    /// The user signs in (or interacts) first; the request is kept under
    /// `reference` for the sign-in page to return to.
    SignIn { reference: String },
    /// `prompt=none` asked for no interaction and one is needed: the OIDC
    /// error for the client (OpenID Connect Core §3.1.2.6).
    NoInteraction(&'static str),
}

impl AuthServiceImpl {
    /// The active client `request` names and the issuer serving it, and its
    /// exact redirect URI. Established before anything else, the caller
    /// included: every later error is reported by redirecting there, which
    /// RFC 6749 §4.1.2.1 forbids for an unknown client or an unregistered URI.
    /// Those two errors are marked so the front channel shows them instead of
    /// redirecting. A client of another issuer than the one whose endpoint
    /// this is counts as unknown.
    pub(crate) async fn authorize_client(
        &self,
        request: &OAuth2AuthorizeRequest,
    ) -> Result<(OAuth2Client, OidcIssuer), Status> {
        let unknown_client = || {
            Status::from(
                ApiError::new(ErrorReason::ApplicationNotFound, "unknown client")
                    .with_metadata("field", "client_id"),
            )
        };
        let client = self
            .storage
            .get_oauth2_client(&request.client_id)
            .await
            .map_err(storage_failure)?
            .filter(|client| client.active)
            .ok_or_else(unknown_client)?;
        let issuer = self
            .issuer_serving(&request.issuer_handle, client.org_id)
            .await?
            .ok_or_else(unknown_client)?;
        if !client.is_redirect_uri_allowed(&request.redirect_uri) {
            return Err(authorize_refusal(
                sid_authn::oauth2::AuthorizeError::UnregisteredRedirectUri,
            ));
        }
        Ok((client, issuer))
    }

    /// Whether `session` may authorize at `now`: not expired, not
    /// provisional, and used within the installation's idle limit.
    pub(crate) fn authorizes(&self, session: &Session, now: DateTime<Utc>) -> bool {
        if session.expires_at <= now || session.is_provisional {
            return false;
        }
        match self.security_policy.session.idle_timeout_hours {
            0 => true,
            hours => {
                let last = session.last_activity_at.unwrap_or(session.created_at);
                now - last <= Duration::hours(i64::from(hours))
            }
        }
    }

    /// The authorization code `session` grants for `request` to `client` at
    /// `issuer`: the client's and the request's assurance judged against the
    /// session, the request validated, the code bound to its resource and
    /// carrying the session's authentication.
    pub(crate) async fn authorize_with(
        &self,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        session: &Session,
        req: OAuth2AuthorizeRequest,
    ) -> Result<OAuth2AuthorizeResponse, Status> {
        let profile_id = session.profile_id;

        // ── Per-app policy enforcement ──
        // The org policy, the client's override and the level the relying
        // party asks for (OpenID Connect Core 1.0 §3.1.2.1 `acr_values`) are
        // merged and judged by the one enforcement engine, which honours the
        // client's enforcement mode. The engine judges the level; the
        // client's required methods are checked after it.
        let requested_acr = req.acr_values.as_deref().and_then(parse_acr_values);
        let policy =
            sid_authz::conditional_access::ConditionalAccessEngine::resolve_effective_policy(
                &self.security_policy,
                Some(client),
                requested_acr,
            );
        // Every session meets the lowest level, so only a higher level or a
        // method requirement is judged.
        if policy.min_acr > sid_core::models::session::AuthLevel::Basic
            || !client.required_amr.is_empty()
        {
            use sid_core::models::enforcement::EnforcementAction;
            let decision =
                sid_authz::conditional_access::ConditionalAccessEngine::evaluate(&policy, session);
            match decision.action {
                EnforcementAction::Allow | EnforcementAction::Grace => {
                    if decision.has_violations() {
                        info!(
                            client = %req.client_id,
                            violations = ?decision.violations,
                            "Policy not met, allowed by enforcement mode"
                        );
                    }
                }
                EnforcementAction::StepUp => {
                    info!(
                        client = %req.client_id,
                        session_acr = ?session.assurance_at(Utc::now()),
                        required = ?policy.min_acr,
                        "Authorize: step-up required"
                    );
                    return Err(super::step_up_to_acr(policy.min_acr.acr_value()).into());
                }
                EnforcementAction::Block => {
                    warn!(
                        client = %req.client_id,
                        violations = ?decision.violations,
                        "Authorize: denied by policy"
                    );
                    return Err(super::sign_in_refused());
                }
            }

            // Every method the client requires must be among the session's.
            let missing: Vec<&str> = client
                .required_amr
                .iter()
                .filter(|r| !session.amr.contains(r))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                info!(
                    client = %req.client_id,
                    session_amr = ?session.amr,
                    ?missing,
                    "Authorize: required methods missing"
                );
                return Err(super::step_up_to_amr(missing).into());
            }
        }

        let auth_req = sid_authn::oauth2::AuthorizeRequest {
            client_id: req.client_id,
            redirect_uri: req.redirect_uri,
            response_type: req.response_type,
            scope: req.scope,
            state: req.state,
            code_challenge: req.code_challenge,
            code_challenge_method: req.code_challenge_method,
            nonce: req.nonce,
        };
        let validated = self
            .oauth2
            .validate_authorize_request(client, &auth_req)
            .map_err(authorize_refusal)?;
        // The code is bound to the resource its tokens will be for.
        let target = self.select_target(issuer, client, &req.resource).await?;

        let (raw_code, auth_code) = self
            .oauth2
            .generate_auth_code(
                profile_id,
                &validated,
                target.resource_id(),
                session.grant_authentication(),
            )
            .map_err(|e| internal("generate authorization code", e))?;

        self.storage
            .create_auth_code(
                &auth_code,
                AuditEntry::user(
                    profile_id.to_string(),
                    "auth_code.create",
                    auth_code.client_id.clone(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(
            "Issued auth code for profile {} → client {}",
            profile_id, auth_code.client_id
        );

        Ok(OAuth2AuthorizeResponse {
            state: validated.state,
            result: Some(o_auth2_authorize_response::Result::AuthorizationCode(
                raw_code,
            )),
        })
    }

    /// The browser endpoint's answer to `pending`, the browser's IdP session
    /// read from the `cookie` headers of `metadata`. The client is
    /// established first; then the session must authorize, be fresh enough
    /// for `prompt=login` / `max_age`, and have had any interaction `prompt`
    /// asks for. Otherwise the user signs in and the request is kept, unless
    /// `prompt=none` forbids it.
    pub(crate) async fn browser_authorize(
        &self,
        metadata: &MetadataMap,
        pending: PendingAuthorization,
    ) -> Result<BrowserAuthorization, Status> {
        self.check_maintenance().await?;
        let request = pending.request();
        let (client, issuer) = self.authorize_client(&request).await?;
        let prompt = Prompt::parse(pending.prompt.as_deref()).map_err(authorize_refusal)?;
        let now = Utc::now();

        let cookies = metadata
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok());
        let session = match BrowserSecret::from_cookie_headers(cookies) {
            Some(secret) => self
                .storage
                .get_session_by_browser_secret(&secret.hash())
                .await
                .map_err(storage_failure)?,
            None => None,
        };
        let after = prompt.authenticated_after(pending.max_age, pending.arrived_at);
        let session = session.filter(|session| {
            self.authorizes(session, now)
                && after.is_none_or(|after| session.authenticated_at >= after)
        });
        let interaction_owed = prompt.asks_interaction() && !pending.interacted;

        match session {
            Some(session) if !interaction_owed => {
                match self
                    .authorize_with(&client, &issuer, &session, request)
                    .await
                {
                    Ok(answer) => {
                        // Only an accepted use counts as activity.
                        self.storage
                            .touch_session(session.id, now)
                            .await
                            .map_err(storage_failure)?;
                        Ok(BrowserAuthorization::Answer(answer))
                    }
                    // Below the level or methods the client requires: the
                    // user authenticates further (OIDC Core 1.0 §3.1.2.3).
                    Err(status) if asks_step_up(&status) => {
                        self.sign_in_first(prompt, pending).await
                    }
                    Err(status) => Err(status),
                }
            }
            _ => self.sign_in_first(prompt, pending).await,
        }
    }

    /// Keep `pending` for the sign-in page to return to, or, under
    /// `prompt=none`, the error that says an interaction is needed.
    async fn sign_in_first(
        &self,
        prompt: Prompt,
        mut pending: PendingAuthorization,
    ) -> Result<BrowserAuthorization, Status> {
        if prompt.none() {
            return Ok(BrowserAuthorization::NoInteraction("login_required"));
        }
        // The sign-in page offers account selection and consent; the
        // continued request does not ask for them again.
        pending.interacted |= prompt.asks_interaction();
        Ok(BrowserAuthorization::SignIn {
            reference: self.keep_authorization(&pending).await?,
        })
    }

    /// Keep `pending` under a fresh random reference.
    pub(crate) async fn keep_authorization(
        &self,
        pending: &PendingAuthorization,
    ) -> Result<String, Status> {
        let mut bytes = [0u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut bytes)
            .map_err(|_| Status::internal("operating system random source unavailable"))?;
        let reference = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.continuations.insert(&reference, pending).await?;
        Ok(reference)
    }

    /// The request kept under `reference`, taken: a reference continues once.
    pub(crate) async fn continue_authorization(
        &self,
        reference: &str,
    ) -> Result<Option<PendingAuthorization>, Status> {
        Ok(self.continuations.take(reference).await?)
    }
}
