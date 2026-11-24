// SPDX-License-Identifier: AGPL-3.0-only
//! The browser adapter of an application hosted here, over its RPCs
//! (`sid.v1.authn.ApplicationSessionService`): the request metadata becomes a
//! [`BrowserRequest`] for the shared [`BrowserSessions`], and its outcomes
//! become the RPC answers.
//!
//! Sign-in start and completion are browser navigations: their answers are
//! HTTP (`x-http-code`, `location`, `set-cookie` in the response metadata)
//! that the embedded transcoder turns into the HTTP response. The session
//! read and the sign-out are typed calls the page makes over gRPC-Web.

use std::sync::Arc;

use sid_authn::application_session::{
    ApplicationClient, AuthorizationAnswer, Bearer, BrowserRequest, BrowserSessions,
    GrantOutcome as Outcome, LogoutReceipt, SessionFailure, SignInFailure, cookie_value,
};
use sid_authn::bff_session::BffSessionStore;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_authn::relying_party::SignInChoice;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::grpc_error::{ApiError, ErrorReason, refuse};
use sid_infra::issuer_client::RpClient;
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::authn::application_session_service_server::ApplicationSessionService;
use sid_proto::sid::v1::authn::{
    ApplicationSession, BackChannelLogoutRequest, CompleteSignInRequest,
    EndApplicationSessionRequest, EndApplicationSessionResponse, GetApplicationSessionRequest,
    GrantOutcome, SignInEntry, StartSignInRequest,
};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Response, Status};

/// The request headers the RPCs read, which the transcoder must hand over
/// as metadata.
pub const FORWARDED_HEADERS: [&str; 3] = ["cookie", CSRF_HEADER, "origin"];

/// The header a page echoes its session's CSRF token in.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";

/// The adapter of one application: its browser sessions as the confidential
/// web client the installation registered. `C` is how that client reaches
/// the issuer: over a channel by default.
pub struct ApplicationSessions<C: ApplicationClient = RpClient> {
    sessions: BrowserSessions<C>,
}

impl<C: ApplicationClient> ApplicationSessions<C> {
    /// The sessions of the application `client` is the client of. The
    /// session cookie's name is a `__Host-` name of its own, so applications
    /// sharing a host never read or replace each other's sessions.
    pub fn new(
        client: Arc<C>,
        issuers: Arc<IssuerDirectory>,
        sessions: Arc<BffSessionStore>,
        revocation: Arc<RevocationCache>,
        cookie: String,
    ) -> Self {
        Self {
            sessions: BrowserSessions::new(client, issuers, sessions, revocation, cookie),
        }
    }

    /// The access token a call to the application's API carries for the
    /// signed-in user (RFC 6750 §2.1), refreshed first when it is due. Every
    /// such call reads or changes data on the user's behalf over a POST, so
    /// it must come from the page and echo the session's CSRF token.
    pub async fn bearer(&self, metadata: &MetadataMap) -> Result<Bearer, Status> {
        self.sessions
            .bearer(&self.request(metadata))
            .await
            .map_err(refusal)
    }

    /// Mark that the API refused the call `bearer` was presented with for
    /// want of a usable credential. A store that cannot take the mark is an
    /// outage of the call, not a refusal the page would read against a
    /// session still answered as live.
    pub async fn refused(&self, bearer: &Bearer) -> Result<(), Status> {
        self.sessions.refused(bearer).await.map_err(refusal)
    }

    /// What `metadata` carries for a session check. Every RPC is a POST, so
    /// none is a safe request.
    fn request<'a>(&self, metadata: &'a MetadataMap) -> BrowserRequest<'a> {
        BrowserRequest {
            session: cookie_value(
                metadata
                    .get_all("cookie")
                    .iter()
                    .filter_map(|value| value.to_str().ok()),
                self.sessions.cookie(),
            ),
            origins: metadata
                .get_all("origin")
                .iter()
                .map(|value| value.as_bytes())
                .collect(),
            csrf: metadata
                .get_all(CSRF_HEADER)
                .iter()
                .map(|value| value.as_bytes())
                .collect(),
            safe: false,
        }
    }

    /// The `set-cookie` value carrying session `id`: host-only (`__Host-`),
    /// TLS only, out of reach of scripts, sent on top-level navigations from
    /// other sites but not on their subrequests (RFC 6265bis §4.1.3.2,
    /// §5.6.7.1).
    fn session_cookie(&self, id: &str) -> String {
        format!(
            "{}={id}; Path=/; Secure; HttpOnly; SameSite=Lax",
            self.sessions.cookie()
        )
    }

    /// The `set-cookie` value that removes the session cookie; its attributes
    /// match the ones that set it (RFC 6265bis §5.7).
    fn cleared_cookie(&self) -> String {
        format!(
            "{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
            self.sessions.cookie()
        )
    }
}

#[tonic::async_trait]
impl<C: ApplicationClient + 'static> ApplicationSessionService for ApplicationSessions<C> {
    async fn start_sign_in(
        &self,
        request: Request<StartSignInRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let asked = request.get_ref();
        // A value this adapter does not know states no choice.
        let sign_in = match asked.sign_in.map(SignInEntry::try_from) {
            Some(Ok(SignInEntry::Local)) => SignInChoice::Local,
            _ => SignInChoice::Ordinary,
        };
        let start = match self.sessions.start_sign_in_at(&asked.rd, sign_in).await {
            Ok(start) => start,
            Err(failure) => return Ok(sign_in_page(&failure)),
        };
        let mut response = redirect(start.authorize_url.as_str());
        insert(
            response.metadata_mut(),
            "set-cookie",
            &format!(
                "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
                self.sessions.sign_in_cookie(&start.state),
                start.browser_secret,
                self.sessions.pending_ttl().as_secs()
            ),
        );
        Ok(response)
    }

    async fn complete_sign_in(
        &self,
        request: Request<CompleteSignInRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let correlation = self.sessions.sign_in_cookie(&request.get_ref().state);
        let secret = cookie_value(
            request
                .metadata()
                .get_all("cookie")
                .iter()
                .filter_map(|value| value.to_str().ok()),
            &correlation,
        );
        let params = request.into_inner();
        let answer = AuthorizationAnswer {
            state: params.state,
            code: params.code,
            error: params.error,
            iss: params.iss,
        };
        let (mut response, taken) = match self
            .sessions
            .complete_sign_in(secret.as_deref(), answer)
            .await
        {
            Ok(signed_in) => {
                let mut response = redirect(&signed_in.return_to);
                insert(
                    response.metadata_mut(),
                    "set-cookie",
                    &self.session_cookie(&signed_in.session_id),
                );
                (response, true)
            }
            Err(failure) => (sign_in_page(&failure), failure.took_the_sign_in()),
        };
        // A taken sign-in clears its correlation cookie, whatever came of it,
        // and only its own.
        if taken {
            append(
                response.metadata_mut(),
                "set-cookie",
                &format!("{correlation}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
            );
        }
        Ok(response)
    }

    async fn get_application_session(
        &self,
        request: Request<GetApplicationSessionRequest>,
    ) -> Result<Response<ApplicationSession>, Status> {
        let session = self
            .sessions
            .read(&self.request(request.metadata()))
            .await
            .map_err(refusal)?;
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
        let outcome = self
            .sessions
            .end(&self.request(request.metadata()))
            .await
            .map_err(refusal)?;
        let grant = match outcome {
            Outcome::Revoked => GrantOutcome::Revoked,
            Outcome::NotRevoked => GrantOutcome::NotRevoked,
            Outcome::None => GrantOutcome::None,
            Outcome::Unknown => GrantOutcome::Unknown,
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

    async fn receive_back_channel_logout(
        &self,
        request: Request<BackChannelLogoutRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let body = request.into_inner().body.unwrap_or_default();
        Ok(
            match self
                .sessions
                .receive_logout(&body.content_type, &body.data)
                .await
            {
                LogoutReceipt::Recorded => http(200),
                LogoutReceipt::Refused(description) => logout_refused(description),
                LogoutReceipt::Unavailable => http(503),
            },
        )
    }
}

/// The RPC refusal of a session request.
fn refusal(failure: SessionFailure) -> Status {
    match failure {
        SessionFailure::NotSignedIn => {
            ApiError::new(ErrorReason::TokenInvalid, "no application session").into()
        }
        SessionFailure::NotThePage => ApiError::new(
            ErrorReason::CsrfTokenInvalid,
            "the request does not come from the application's page",
        )
        .into(),
        SessionFailure::CsrfMismatch => ApiError::new(
            ErrorReason::CsrfTokenInvalid,
            "the request does not carry this session's CSRF token",
        )
        .into(),
        SessionFailure::Unavailable { dependency, detail } => {
            refuse::dependency_unavailable(dependency, detail)
        }
    }
}

/// The page a sign-in that did not start or complete shows the user.
fn sign_in_page(failure: &SignInFailure) -> Response<HttpBody> {
    tracing::warn!(error = %failure, "sign-in did not complete");
    match failure {
        SignInFailure::NotProvisioned(_) => page(503, "The sign-in is not available yet."),
        SignInFailure::EndedAtIssuer => page(403, "The sign-in was ended at the issuer."),
        SignInFailure::OtherBrowser => page(400, "This sign-in was started in another browser."),
        SignInFailure::ExpiredOrUsed => page(400, "This sign-in has expired or was already used."),
        SignInFailure::WrongIssuer => page(400, "The sign-in answer did not come from the issuer."),
        SignInFailure::Refused { error, return_to } => sid_infra::oauth_http::link_page(
            403,
            if error == "access_denied" {
                "You did not sign in."
            } else {
                "The sign-in was refused."
            },
            "Sign in again",
            return_to,
        ),
        SignInFailure::NoCode => page(400, "The sign-in answer carries no code."),
        SignInFailure::IssuerFailed(_) => page(502, "The issuer did not complete the sign-in."),
        SignInFailure::Unavailable(_) | SignInFailure::NotStored(_) => {
            page(503, "The sign-in is not available right now.")
        }
    }
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

/// 400 with the JSON error `invalid_request` (Back-Channel Logout 1.0 §2.8).
fn logout_refused(description: &str) -> Response<HttpBody> {
    let mut response = http(400);
    let body = response.get_mut();
    body.content_type = "application/json".into();
    body.data = serde_json::to_vec(&serde_json::json!({
        "error": "invalid_request",
        "error_description": description,
    }))
    .expect("a JSON object encodes");
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

/// [`insert`], keeping the values already under `name`: a response sets
/// several cookies, one `set-cookie` each (RFC 6265bis §3).
fn append(metadata: &mut MetadataMap, name: &'static str, value: &str) {
    match MetadataValue::try_from(value) {
        Ok(value) => {
            metadata.append(name, value);
        }
        Err(e) => tracing::error!(error = %e, name, "not a header value"),
    }
}

#[cfg(test)]
pub(crate) mod tests;
