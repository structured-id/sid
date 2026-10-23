// SPDX-License-Identifier: AGPL-3.0-only
//! The browser adapter of an application hosted here: it signs the
//! application's users in at its issuer as the confidential web client the
//! installation registered (code flow, S256 PKCE, `private_key_jwt`), keeps
//! the issuer's tokens server-side and gives the browser only an HttpOnly
//! session cookie and a CSRF token (`sid.v1.authn.ApplicationSessionService`).
//!
//! Sign-in start and completion are browser navigations: their answers are
//! HTTP (`x-http-code`, `location`, `set-cookie` in the response metadata)
//! that the embedded transcoder turns into the HTTP response. The session
//! read and the sign-out are typed calls the page makes over gRPC-Web.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use sid_authn::bff_session::{BffSession, BffSessionStore, SessionClaims};
use sid_authn::issuer_directory::IssuerDirectory;
use sid_authn::relying_party::Connection;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::{ApiError, ErrorReason, refuse};
use sid_infra::issuer_client::{RpClient, RpClientError};
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::authn::application_session_service_server::ApplicationSessionService;
use sid_proto::sid::v1::authn::{
    ApplicationSession, CompleteSignInRequest, EndApplicationSessionRequest,
    EndApplicationSessionResponse, GetApplicationSessionRequest, GrantOutcome, StartSignInRequest,
};
use subtle::ConstantTimeEq;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Code, Request, Response, Status};

/// The request headers the RPCs read, which the transcoder must hand over
/// as metadata.
pub const FORWARDED_HEADERS: [&str; 2] = ["cookie", CSRF_HEADER];

/// The header a page echoes its session's CSRF token in.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";

/// An access token this close to expiry is refreshed before use, so it does
/// not expire between this host and the API.
const REFRESH_MARGIN_SECS: i64 = 30;
/// How long one replica holds a session's refresh: longer than a token
/// endpoint call.
const REFRESH_HOLD: std::time::Duration = std::time::Duration::from_secs(15);
/// How often a replica that did not win the refresh looks for its result.
const REFRESH_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// The adapter of one application: its client at the issuer, the issuer
/// directory that verifies what the issuer returns, the shared session store
/// and the revocations every SID process records.
pub struct ApplicationSessions {
    client: Arc<RpClient>,
    issuers: Arc<IssuerDirectory>,
    sessions: Arc<BffSessionStore>,
    revocation: Arc<RevocationCache>,
    /// The session cookie's name: a `__Host-` name of its own, so applications
    /// sharing a host never read or replace each other's sessions.
    cookie: String,
}

impl ApplicationSessions {
    pub fn new(
        client: Arc<RpClient>,
        issuers: Arc<IssuerDirectory>,
        sessions: Arc<BffSessionStore>,
        revocation: Arc<RevocationCache>,
        cookie: String,
    ) -> Self {
        Self {
            client,
            issuers,
            sessions,
            revocation,
            cookie,
        }
    }

    /// The application's connection, or the answer when the installation has
    /// not provisioned its client yet.
    async fn connection(&self) -> Result<&Connection, RpClientError> {
        self.client.connection().await
    }

    /// The session the request's cookie names, when it is live, was made
    /// under this application's connection and its issuer session was not
    /// ended elsewhere.
    async fn signed_in(&self, metadata: &MetadataMap) -> Result<(String, BffSession), Status> {
        // No cookie, or one naming no session, is a determinable refusal: the
        // connection is asked for only when there is a session to check.
        let id = cookie_value(metadata, &self.cookie).ok_or_else(unauthenticated)?;
        let session = self
            .sessions
            .get_session(&id)
            .await
            .map_err(|e| refuse::dependency_unavailable("session store", e))?
            .ok_or_else(unauthenticated)?;
        let connection = self
            .connection()
            .await
            .map_err(|e| refuse::dependency_unavailable("application connection", e))?;
        // A session of another connection (a bundle replaced since) is left
        // in place: during a rollout a replica of that connection shares the
        // store and still serves it.
        if session.connection != connection.binding() {
            return Err(unauthenticated());
        }
        // An issuer session ended elsewhere (sign-out on another device, an
        // administrator's kill) ends this one with it.
        match self
            .revocation
            .is_revoked(&session.claims.jti, &session.claims.sid)
            .await
        {
            Ok(false) => Ok((id, session)),
            Ok(true) => {
                if let Err(e) = self.sessions.destroy_session(&id).await {
                    tracing::error!(error = %e, "cannot destroy a revoked application session");
                }
                Err(unauthenticated())
            }
            Err(e) => Err(refuse::dependency_unavailable("revocation state", e)),
        }
    }

    /// Revoke the grant behind a destroyed session (RFC 7009 §2.1), so its
    /// refresh token dies with it.
    async fn revoke_grant(&self, session: BffSession) -> GrantOutcome {
        let Some(refresh_token) = session.refresh_token else {
            return GrantOutcome::None;
        };
        let connection = match self.connection().await {
            // A grant of another connection is not this client's to revoke.
            Ok(connection) if session.connection != connection.binding() => {
                return GrantOutcome::NotRevoked;
            }
            Ok(connection) => connection,
            Err(e) => {
                tracing::warn!(error = %e, "no connection; the grant was not revoked");
                return GrantOutcome::NotRevoked;
            }
        };
        match self
            .client
            .revoke(connection, refresh_token.expose_secret().to_owned())
            .await
        {
            Ok(()) => GrantOutcome::Revoked,
            Err(e) => {
                let outcome = revocation_failure(&e);
                tracing::warn!(error = %e, ?outcome, "revocation failed");
                outcome
            }
        }
    }

    /// The access token a call to the application's API carries for the
    /// signed-in user (RFC 6750 §2.1), refreshed first when it is about to
    /// expire. Every such call reads or changes data on the user's behalf, so
    /// it must echo the session's CSRF token: a request another site makes the
    /// browser send carries the cookie but not the token.
    pub async fn bearer(&self, metadata: &MetadataMap) -> Result<SecretString, Status> {
        let (id, session) = self.signed_in(metadata).await?;
        if !csrf_matches(metadata, &session.csrf_token) {
            return Err(ApiError::new(
                ErrorReason::CsrfTokenInvalid,
                "the request does not carry this session's CSRF token",
            )
            .into());
        }
        self.current_token(&id, session).await
    }

    /// The session's access token, refreshed when it is about to expire.
    ///
    /// One replica refreshes; the others wait for its result in the shared
    /// store. A refused refresh (the grant was revoked or expired) ends the
    /// session; a refresh that cannot be done now leaves it for the next call.
    ///
    /// A refresh whose answer was lost may still have rotated the token, so
    /// the next call presents the replaced one. The issuer accepts a replaced
    /// token for a grace window after its rotation and rotates again; after
    /// that window it reads the replay as theft, revokes the family and the
    /// refusal ends this session: the user signs in again, nothing is left
    /// holding a token the issuer no longer honours.
    async fn current_token(&self, id: &str, session: BffSession) -> Result<SecretString, Status> {
        let now = chrono::Utc::now().timestamp();
        if session.claims.exp - now > REFRESH_MARGIN_SECS {
            return Ok(session.access_token);
        }
        let Some(refresh_token) = session.refresh_token else {
            return Err(self.end(id).await);
        };
        let claimed = self
            .sessions
            .claim_refresh(id, REFRESH_HOLD)
            .await
            .map_err(|e| refuse::dependency_unavailable("session store", e))?;
        if !claimed {
            return self
                .refreshed_elsewhere(id, session.access_token.expose_secret())
                .await;
        }
        let connection = self
            .connection()
            .await
            .map_err(|e| refuse::dependency_unavailable("application connection", e))?;
        let tokens = match self
            .client
            .refresh(connection, refresh_token.expose_secret().to_owned())
            .await
        {
            Ok(tokens) => tokens,
            Err(RpClientError::Rpc(status)) if !transient(&status) => {
                tracing::info!(error = %status, "refresh refused, session ended");
                return Err(self.end(id).await);
            }
            Err(e) => return Err(refuse::dependency_unavailable("issuer", e)),
        };
        let claims = self
            .issuers
            .issued_access_token(
                &connection.issuer,
                &connection.resource,
                &tokens.access_token,
            )
            .await
            .map_err(|e| refuse::dependency_unavailable("issuer", e))?;
        let claims = SessionClaims::from(claims).refreshed(&session.claims);
        let access_token = SecretString::from(tokens.access_token);
        match self
            .sessions
            .replace_tokens(
                id,
                access_token.clone(),
                tokens.refresh_token.map(SecretString::from),
                claims,
            )
            .await
        {
            Ok(true) => Ok(access_token),
            Ok(false) => Err(unauthenticated()),
            Err(e) => Err(refuse::dependency_unavailable("session store", e)),
        }
    }

    /// The token another replica's refresh stored, once it is there.
    async fn refreshed_elsewhere(&self, id: &str, stale: &str) -> Result<SecretString, Status> {
        let deadline = tokio::time::Instant::now() + REFRESH_HOLD;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(REFRESH_POLL).await;
            match self.sessions.get_session(id).await {
                Ok(Some(session)) if session.bearer() != stale => return Ok(session.access_token),
                Ok(Some(_)) => {}
                Ok(None) => return Err(unauthenticated()),
                Err(e) => return Err(refuse::dependency_unavailable("session store", e)),
            }
        }
        Err(refuse::dependency_unavailable(
            "session store",
            "another replica's refresh did not finish",
        ))
    }

    /// Destroy an ended session; the user signs in again.
    async fn end(&self, id: &str) -> Status {
        match self.sessions.destroy_session(id).await {
            Ok(()) => unauthenticated(),
            Err(e) => refuse::dependency_unavailable("session store", e),
        }
    }

    /// The name of the cookie binding a pending sign-in to its browser,
    /// beside the session cookie under the same `__Host-` prefix.
    fn sign_in_cookie(&self) -> String {
        format!("{}-signin", self.cookie)
    }

    /// The `set-cookie` value carrying session `id`: host-only (`__Host-`),
    /// TLS only, out of reach of scripts, sent on top-level navigations from
    /// other sites but not on their subrequests (RFC 6265bis §4.1.3.2,
    /// §5.6.7.1).
    fn session_cookie(&self, id: &str) -> String {
        format!(
            "{}={id}; Path=/; Secure; HttpOnly; SameSite=Lax",
            self.cookie
        )
    }

    /// The `set-cookie` value that removes the session cookie; its attributes
    /// match the ones that set it (RFC 6265bis §5.7).
    fn cleared_cookie(&self) -> String {
        format!(
            "{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
            self.cookie
        )
    }
}

#[tonic::async_trait]
impl ApplicationSessionService for ApplicationSessions {
    async fn start_sign_in(
        &self,
        request: Request<StartSignInRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let connection = match self.connection().await {
            Ok(connection) => connection,
            Err(e) => {
                tracing::error!(error = %e, "no connection to the application's client");
                return Ok(page(503, "The sign-in is not available yet."));
            }
        };
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        // Same shape and strength as the verifier: 256 random bits.
        let nonce = random_token();
        let return_to = local_path(&request.get_ref().rd);
        // The browser this sign-in belongs to. Another tab of the same browser
        // keeps the binding it already has, so its own sign-in stays valid.
        let browser = cookie_value(request.metadata(), &self.sign_in_cookie())
            .filter(|value| is_random_token(value))
            .unwrap_or_else(random_token);
        // Without a store there is no sign-in to start: sending the browser on
        // with a state nobody can verify would make the callback unverifiable.
        let state = match self
            .sessions
            .store_pending(
                SecretString::from(verifier),
                nonce.clone(),
                return_to,
                &browser_binding(connection, &browser),
            )
            .await
        {
            Ok(state) => state,
            Err(e) => {
                tracing::error!(error = %e, "cannot record the sign-in");
                return Ok(page(503, "The sign-in is not available right now."));
            }
        };
        let mut response = redirect(
            connection
                .authorize_url(&challenge, &state, &nonce)
                .as_str(),
        );
        insert(
            response.metadata_mut(),
            "set-cookie",
            &format!(
                "{}={browser}; Path=/; Secure; HttpOnly; SameSite=Lax",
                self.sign_in_cookie()
            ),
        );
        Ok(response)
    }

    async fn complete_sign_in(
        &self,
        request: Request<CompleteSignInRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        // A callback completes only the sign-in of the browser that started it
        // (RFC 6749 §10.12, RFC 9700 §4.7.1): otherwise an attacker's own
        // unused code, sent to a victim's browser, would sign the victim in
        // to the attacker's account.
        let Some(browser) = cookie_value(request.metadata(), &self.sign_in_cookie()) else {
            return Ok(page(400, "This sign-in was started in another browser."));
        };
        let params = request.into_inner();
        let connection = match self.connection().await {
            Ok(connection) => connection,
            Err(e) => {
                tracing::error!(error = %e, "no connection to the application's client");
                return Ok(page(503, "The sign-in is not available yet."));
            }
        };
        // A sign-in started in another browser, or under another connection or
        // callback, is not found under this binding and stays where it is: for
        // its own browser, or a replica that still holds that connection.
        let pending = match self
            .sessions
            .take_pending(&params.state, &browser_binding(connection, &browser))
            .await
        {
            Ok(Some(pending)) => pending,
            Ok(None) => return Ok(page(400, "This sign-in has expired or was already used.")),
            Err(e) => {
                // A store that cannot tell whether this state was already
                // consumed cannot rule out a replay.
                tracing::error!(error = %e, "cannot claim the sign-in");
                return Ok(page(503, "The sign-in is not available right now."));
            }
        };
        // The answer must come from the application's issuer (RFC 9207 §2.4).
        if params.iss.as_deref() != Some(connection.issuer.as_str()) {
            tracing::warn!("authorization response from another issuer");
            return Ok(page(
                400,
                "The sign-in answer did not come from the issuer.",
            ));
        }
        if let Some(error) = &params.error {
            tracing::warn!(%error, "authorization error");
            return Ok(page(403, "The sign-in was refused."));
        }
        let Some(code) = params.code else {
            return Ok(page(400, "The sign-in answer carries no code."));
        };
        let tokens = match self
            .client
            .redeem(
                connection,
                code,
                pending.code_verifier.expose_secret().to_owned(),
            )
            .await
        {
            Ok(tokens) => tokens,
            Err(e) => {
                tracing::error!(error = %e, "code redemption failed");
                return Ok(page(502, "The issuer did not complete the sign-in."));
            }
        };
        let mut claims = match self
            .issuers
            .issued_access_token(
                &connection.issuer,
                &connection.resource,
                &tokens.access_token,
            )
            .await
        {
            Ok(claims) => SessionClaims::from(claims),
            Err(e) => {
                tracing::error!(error = %e, "issued token is not for the application's API");
                return Ok(page(502, "The issuer did not complete the sign-in."));
            }
        };
        // The ID token is this sign-in's (its nonce) and the user's profile
        // claims come from it; an access token carries none (RFC 9068 §2.2).
        let Some(id_token) = tokens.id_token.as_deref() else {
            tracing::error!("no ID token for an openid sign-in");
            return Ok(page(502, "The issuer did not complete the sign-in."));
        };
        let identity = match self
            .issuers
            .issued_id_token(
                &connection.issuer,
                &connection.client_id,
                &pending.nonce,
                id_token,
            )
            .await
        {
            Ok(identity) => identity,
            Err(e) => {
                tracing::error!(error = %e, "the ID token is not this sign-in's");
                return Ok(page(502, "The issuer did not complete the sign-in."));
            }
        };
        if identity.sub != claims.sub {
            tracing::error!("ID and access tokens name different users");
            return Ok(page(502, "The issuer did not complete the sign-in."));
        }
        claims.email = identity.email;
        claims.name = identity.name;
        claims.preferred_username = identity.preferred_username;

        let (session_id, _csrf) = match self
            .sessions
            .create_session(
                SecretString::from(tokens.access_token),
                tokens.refresh_token.map(SecretString::from),
                claims,
                &connection.binding(),
            )
            .await
        {
            Ok(created) => created,
            Err(e) => {
                tracing::error!(error = %e, "cannot store the session");
                return Ok(page(503, "The sign-in is not available right now."));
            }
        };
        let mut response = redirect(&pending.redirect_url);
        insert(
            response.metadata_mut(),
            "set-cookie",
            &self.session_cookie(&session_id),
        );
        Ok(response)
    }

    async fn get_application_session(
        &self,
        request: Request<GetApplicationSessionRequest>,
    ) -> Result<Response<ApplicationSession>, Status> {
        let (_, session) = self.signed_in(request.metadata()).await?;
        let claims = session.claims;
        let mut response = Response::new(ApplicationSession {
            sub: claims.sub,
            email: claims.email,
            name: claims.name,
            preferred_username: claims.preferred_username,
            acr: claims.acr,
            csrf_token: session.csrf_token,
        });
        insert(response.metadata_mut(), "cache-control", "no-store");
        Ok(response)
    }

    async fn end_application_session(
        &self,
        request: Request<EndApplicationSessionRequest>,
    ) -> Result<Response<EndApplicationSessionResponse>, Status> {
        let metadata = request.metadata();
        // Without a cookie there is nothing to end.
        let id = cookie_value(metadata, &self.cookie).ok_or_else(unauthenticated)?;
        let grant = match self.sessions.get_session(&id).await {
            Ok(Some(session)) => {
                if !csrf_matches(metadata, &session.csrf_token) {
                    return Err(ApiError::new(
                        ErrorReason::CsrfTokenInvalid,
                        "the request does not carry this session's CSRF token",
                    )
                    .into());
                }
                // The cookie must not be cleared while the session stays usable
                // by anyone holding its id.
                self.sessions
                    .destroy_session(&id)
                    .await
                    .map_err(|e| refuse::dependency_unavailable("session store", e))?;
                self.revoke_grant(session).await
            }
            // Already gone, perhaps expired with its grant still alive: the
            // cookie is cleared anyway and nothing is known of the grant.
            Ok(None) => GrantOutcome::Unknown,
            Err(e) => return Err(refuse::dependency_unavailable("session store", e)),
        };
        let mut response = Response::new(EndApplicationSessionResponse {
            grant: grant as i32,
        });
        insert(
            response.metadata_mut(),
            "set-cookie",
            &self.cleared_cookie(),
        );
        Ok(response)
    }
}

/// The outcome of a revocation call that failed. A refusal the issuer
/// answered leaves the grant alive; a call whose answer was lost or broken
/// may have taken effect (gRPC status codes, `Unavailable` to `DataLoss`).
fn revocation_failure(failure: &RpClientError) -> GrantOutcome {
    match failure {
        RpClientError::Rpc(status) => match status.code() {
            Code::Unavailable
            | Code::Cancelled
            | Code::DeadlineExceeded
            | Code::Unknown
            | Code::Internal
            | Code::Aborted
            | Code::DataLoss => GrantOutcome::Unknown,
            _ => GrantOutcome::NotRevoked,
        },
        // Nothing was sent.
        RpClientError::Invalid(_) | RpClientError::Connection(_) | RpClientError::Key(_) => {
            GrantOutcome::NotRevoked
        }
    }
}

/// Whether a failed refresh may succeed if repeated: the issuer or the path
/// to it failed, not the grant.
fn transient(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::Unavailable
            | Code::DeadlineExceeded
            | Code::Internal
            | Code::Unknown
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Cancelled
    )
}

fn unauthenticated() -> Status {
    ApiError::new(ErrorReason::TokenInvalid, "no application session").into()
}

/// The value of the cookie `name` in the request's `cookie` metadata, when
/// it is present exactly once: a `__Host-` cookie has one host and one path,
/// so a browser never sends two, and two would be ambiguous.
fn cookie_value(metadata: &MetadataMap, name: &str) -> Option<String> {
    let mut found = None;
    for header in metadata.get_all("cookie") {
        let Ok(header) = header.to_str() else {
            continue;
        };
        // RFC 6265bis §4.2.1: cookie-pair *( ";" SP cookie-pair ).
        for pair in header.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

/// Whether the request echoes `expected` in exactly one `x-csrf-token`,
/// compared in constant time: a mismatch says nothing about how much of a
/// guess was right.
fn csrf_matches(metadata: &MetadataMap, expected: &str) -> bool {
    let mut sent = metadata.get_all(CSRF_HEADER).iter();
    let (Some(value), None) = (sent.next(), sent.next()) else {
        return false;
    };
    bool::from(value.as_bytes().ct_eq(expected.as_bytes()))
}

/// A path on this origin to return to after sign-in; anything else, which
/// would make the adapter an open redirector (RFC 9700 §4.11), is the root.
/// `//host` and `/\host` are other origins to a browser.
fn local_path(requested: &str) -> String {
    if requested.starts_with('/')
        && !requested.starts_with("//")
        && !requested.starts_with("/\\")
        && !requested.chars().any(char::is_control)
    {
        requested.to_owned()
    } else {
        "/".to_owned()
    }
}

/// What a pending sign-in is bound to: the connection's sign-in binding and
/// the browser that started it.
fn browser_binding(connection: &Connection, browser: &str) -> String {
    format!("{}\n{browser}", connection.sign_in_binding())
}

/// Whether `value` has the shape [`random_token`] produces: a browser cookie
/// of any other shape is not one this adapter set.
fn is_random_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// 256 random bits, base64url: a PKCE verifier (RFC 7636 §4.1) or a nonce.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// An HTTP answer with `status` and an empty body, never stored by caches.
fn http(status: u16) -> Response<HttpBody> {
    let mut response = Response::new(HttpBody {
        content_type: String::new(),
        data: Vec::new(),
        extensions: Vec::new(),
    });
    insert(response.metadata_mut(), "x-http-code", &status.to_string());
    insert(response.metadata_mut(), "cache-control", "no-store");
    response
}

/// A `302 Found` to `location`.
fn redirect(location: &str) -> Response<HttpBody> {
    let mut response = http(302);
    insert(response.metadata_mut(), "location", location);
    response
}

/// A page with `status` and plain `text`, shown instead of a redirect.
fn page(status: u16, text: &str) -> Response<HttpBody> {
    let mut response = http(status);
    let body = response.get_mut();
    body.content_type = "text/plain; charset=utf-8".into();
    body.data = text.as_bytes().to_vec();
    response
}

/// Insert `value` under `name`; every value here is built from header-safe
/// text (a URL, a cookie of hex and fixed attributes, a status code).
fn insert(metadata: &mut MetadataMap, name: &'static str, value: &str) {
    match MetadataValue::try_from(value) {
        Ok(value) => {
            metadata.insert(name, value);
        }
        Err(e) => tracing::error!(error = %e, name, "not a header value"),
    }
}

#[cfg(test)]
mod tests;
