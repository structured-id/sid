// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC FederatedEntryService: one sign-in through a registered entry
//! connection.
//!
//! In plain words: the sign-in page sends a browser without a session to
//! the entry's start, naming a connection; the connection's issuer
//! authenticates the holder and returns a code to the installation issuer's
//! one callback; the return
//! is exchanged, the identity it signs in is resolved and admitted
//! ([`sid::federated_admission`]) under this installation's sign-in policy,
//! and the browser continues the authorization it came from with this
//! installation's session cookie.
//!
//! The browser names an installation issuer and a registered connection. It
//! supplies no issuer to trust, no endpoint and no credential: those are the
//! connection's, read from the store on every step, so a connection disabled
//! or removed meanwhile starts and completes nothing.

use std::sync::Arc;

use sid::entry_connections::EntryConnections;
use sid::federated_admission::resolve;
use sid_authn::federated_entry::{EntryError, EntryRequest, FederatedEntry, TrustedIssuer};
use sid_core::models::{EntryConnection, EntryHandle, IssuerHandle, OidcIssuer};
use sid_fed::recipient::PresentedIdentities;
use sid_infra::authn::ceremony::Deliver as _;
use sid_infra::oauth_http;
use sid_plugin::StorageBackend;
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::federated_entry_service_server::FederatedEntryService;
use sid_proto::sid::v1::{CompleteFederatedEntryRequest, StartFederatedEntryRequest};
use tonic::{Request, Response, Status};
use tracing::warn;

use super::auth_service::{AdmittedCompletion, AuthServiceImpl};

/// Builds the federated entry through a connection's issuer, with the
/// installation's HTTP client, pending-entry store and browser-session
/// cookie.
pub type Entries = Arc<dyn Fn(TrustedIssuer) -> FederatedEntry + Send + Sync>;

/// The federated entry of this installation's issuers.
pub struct FederatedEntryServiceImpl {
    entries: Entries,
    connections: Arc<EntryConnections>,
    storage: Arc<dyn StorageBackend>,
    auth: Arc<AuthServiceImpl>,
    /// Accepts the presentation of an identity the organization did not
    /// issue.
    identities: Arc<dyn PresentedIdentities>,
}

/// One step of an entry: the installation issuer and the connection the
/// browser named, with the entry through the connection's issuer.
struct Step {
    issuer: OidcIssuer,
    connection: EntryConnection,
    entry: FederatedEntry,
}

/// Why a step names nothing to run.
enum NoStep {
    /// The path names no issuer of this installation.
    UnknownIssuer,
    /// The path names no enabled connection of that issuer.
    NoConnection,
    /// The store or the key manager could not answer.
    Unavailable,
}

impl FederatedEntryServiceImpl {
    /// The entry built from `entries`, through the connections in
    /// `connections`, resolving who a return signs in over `storage` and
    /// `identities`, signed in by `auth`.
    pub fn new(
        entries: Entries,
        connections: Arc<EntryConnections>,
        storage: Arc<dyn StorageBackend>,
        auth: Arc<AuthServiceImpl>,
        identities: Arc<dyn PresentedIdentities>,
    ) -> Self {
        Self {
            entries,
            connections,
            storage,
            auth,
            identities,
        }
    }

    /// The step at the installation issuer `issuer_handle` names, through
    /// the connection `connection` names. No name is the authority the
    /// installation's provisioning set for that issuer, never the first
    /// connection of some list.
    async fn step(&self, issuer_handle: &str, connection: &str) -> Result<Step, NoStep> {
        let unavailable = |e: &dyn std::fmt::Display, what: &'static str| {
            warn!(error = %e, "{what}");
            NoStep::Unavailable
        };
        let handle = IssuerHandle::parse(issuer_handle).map_err(|_| NoStep::UnknownIssuer)?;
        let issuer = self
            .storage
            .oidc_issuer_by_handle(&handle)
            .await
            .map_err(|e| unavailable(&e, "installation issuer lookup"))?
            .ok_or(NoStep::UnknownIssuer)?;
        let handle = if connection.is_empty() {
            self.connections
                .provisioned(&issuer)
                .await
                .map_err(|e| unavailable(&e, "provisioned authority"))?
                .ok_or(NoStep::NoConnection)?
                .handle
        } else {
            EntryHandle::parse(connection).map_err(|_| NoStep::NoConnection)?
        };
        let (connection, trusted) = self
            .connections
            .for_entry(&issuer, handle)
            .await
            .map_err(|e| unavailable(&e, "entry connection"))?
            .ok_or(NoStep::NoConnection)?;
        Ok(Step {
            issuer,
            // Every connection of the issuer returns to one callback: the
            // state of an entry names the connection it was started through.
            entry: (self.entries)(trusted).routed_by(connection.handle.to_string()),
            connection,
        })
    }

    /// The admitted return: the Profile the connection's issuer signed in,
    /// signed in here on the evidence it returned. A repeat of the return in
    /// the same browser resumes the entry and gets the same session (the
    /// recoverable federation callback completion contract). A refusal is
    /// logged and answered with a page; nothing is created for it.
    async fn admit(
        &self,
        step: &Step,
        request: &Request<CompleteFederatedEntryRequest>,
    ) -> Result<Response<HttpBody>, Refusal> {
        let message = request.get_ref();
        let cookies = request
            .metadata()
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok());
        let returned = match step
            .entry
            .complete(
                &message.state,
                cookies,
                &message.code,
                &step.connection.callback,
            )
            .await
        {
            Ok(returned) => returned,
            // The code may be spent without a kept answer: never redeemed
            // again, sign-in starts anew where the entry would have gone,
            // reusing the issuer's sign-in when it is still sufficient.
            Err(EntryError::Ambiguous { continuation }) => {
                return match url::Url::parse(&continuation) {
                    Ok(continuation) => Ok(self
                        .begin(step, &continuation, &EntryRequest::default())
                        .await
                        .unwrap_or_else(unavailable)),
                    Err(_) => Err(Refusal::over("Sign-in was not completed")),
                };
            }
            // Another return of the same entry is exchanging its code now:
            // this one keeps the entry and is retried, completing the same
            // sign-in without another exchange.
            Err(e @ (EntryError::Issuer(_) | EntryError::Store(_) | EntryError::InProgress)) => {
                warn!(error = %e, "federated entry not completed, retryable");
                return Err(Refusal::retry());
            }
            Err(e) => {
                warn!(error = %e, "federated entry not completed");
                return Err(Refusal::over("Sign-in was not completed"));
            }
        };
        let (profile, assignment) = resolve(
            self.storage.as_ref(),
            self.identities.as_ref(),
            &step.issuer,
            &step.connection,
            &returned,
            std::time::SystemTime::now(),
        )
        .await
        .map_err(|refused| {
            if refused.retryable() {
                warn!(error = %refused, "returned identity not decided");
                Refusal::retry()
            } else {
                warn!(error = %refused, "returned identity not admitted");
                Refusal::over("This account has no access here")
            }
        })?;
        // A resumed admission keeps the original authentication time and
        // evidence bounds: the evidence is the one kept with the entry.
        let Some(authentication) = returned.evidence.authentication(chrono::Utc::now()) else {
            warn!("federated entry evidence is no longer current");
            return Err(Refusal::over("Sign-in was not completed"));
        };
        // The application whose authorization the entry continues: its
        // login policy decides the sign-in.
        let Ok(continuation) = url::Url::parse(&returned.continuation) else {
            return Err(Refusal::over("Sign-in was not completed"));
        };
        let Some(client_id) = client_of(&continuation) else {
            return Err(Refusal::over("Sign-in was not completed"));
        };
        let completion = AdmittedCompletion {
            operation: &returned.operation,
            deadline: returned.deadline,
        };
        let signed_in = match self
            .auth
            .complete_admitted_sign_in(
                request,
                &profile,
                assignment,
                &authentication,
                &client_id,
                Some(completion),
            )
            .await
        {
            Ok(signed_in) => signed_in,
            Err(status) => {
                // A level or freshness the issuer can be asked for starts one
                // further entry asking for it; anything else, or a return to
                // an entry that already asked, is refused. A further entry
                // that cannot start now keeps this one, so the same return
                // can be retried.
                if let Some(further) = further_request(&status, &returned.requested) {
                    return self
                        .begin(step, &continuation, &further)
                        .await
                        .ok_or_else(Refusal::retry);
                }
                warn!(error = %status, profile = %profile.id, "federated sign-in refused");
                return Err(match status.code() {
                    tonic::Code::Unavailable | tonic::Code::Internal => Refusal::retry(),
                    _ => Refusal::over("Sign-in was refused"),
                });
            }
        };
        let mut response = oauth_http::redirect(&continuation);
        signed_in
            .delivery
            .deliver(response.metadata_mut())
            .map_err(|status| {
                warn!(error = %status, "deliver the session cookie");
                Refusal::retry()
            })?;
        Ok(response)
    }

    /// The answer to an error return: the holder declined at the issuer, or
    /// it refused. The entry ends and the application whose authorization it
    /// continued is told `access_denied` (RFC 6749 §4.1.2.1); a return this
    /// installation is not waiting on reaches no application. Its
    /// correlation cookie is cleared unless the entry could not be read.
    async fn declined(
        &self,
        step: &Step,
        request: &Request<CompleteFederatedEntryRequest>,
    ) -> Response<HttpBody> {
        let message = request.get_ref();
        warn!(error = %message.error, "federated entry returned an error");
        let cookies = request
            .metadata()
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok());
        let mut response = match step
            .entry
            .decline(&message.state, cookies, &step.connection.callback)
            .await
        {
            Ok(continuation) => match self.auth.declined_sign_in(&continuation).await {
                Ok(answer) => oauth_http::redirect(&answer),
                Err(status) => {
                    warn!(error = %status, "declined authorization not answered");
                    match status.code() {
                        tonic::Code::Unavailable | tonic::Code::Internal => {
                            oauth_http::page(503, Refusal::retry().text)
                        }
                        _ => oauth_http::page(403, "Sign-in was not completed"),
                    }
                }
            },
            Err(EntryError::Store(e)) => {
                warn!(error = %e, "declined entry not read");
                return oauth_http::page(503, Refusal::retry().text);
            }
            Err(e) => {
                warn!(error = %e, "declined entry not ended");
                oauth_http::page(403, "Sign-in was not completed")
            }
        };
        if !with_cookie(&mut response, &step.entry.clear_cookie(&message.state)) {
            return oauth_http::page(502, "Sign-in is temporarily unavailable");
        }
        response
    }

    /// Send the browser to the connection's issuer for an entry continuing
    /// at `continuation` that asks for `request`; `None` when the entry
    /// could not be started, which the caller answers as its own failure.
    async fn begin(
        &self,
        step: &Step,
        continuation: &url::Url,
        request: &EntryRequest,
    ) -> Option<Response<HttpBody>> {
        let started = match step
            .entry
            .start(&step.connection.callback, continuation.as_str(), request)
            .await
        {
            Ok(started) => started,
            Err(e) => {
                warn!(error = %e, "federated entry not started");
                return None;
            }
        };
        let url = url::Url::parse(&started.authorization_url).ok()?;
        let mut response = oauth_http::redirect(&url);
        with_cookie(&mut response, &started.set_cookie).then_some(response)
    }
}

/// Why a return is answered with a page, and whether its entry stays for a
/// retry of the same return in the same browser.
struct Refusal {
    text: &'static str,
    /// The entry is resumable (a dependency failed, nothing was refused):
    /// its correlation cookie stays.
    keep_entry: bool,
}

impl Refusal {
    /// A refusal that ends the entry.
    fn over(text: &'static str) -> Self {
        Self {
            text,
            keep_entry: false,
        }
    }

    /// A failure the same return may be retried after.
    fn retry() -> Self {
        Self {
            text: "Sign-in is temporarily unavailable",
            keep_entry: true,
        }
    }
}

/// The page of an entry the issuer could not be reached for.
fn unavailable() -> Response<HttpBody> {
    oauth_http::page(502, "Sign-in is temporarily unavailable")
}

/// Add the `Set-Cookie` value `cookie` to `response`, beside any it carries;
/// false when the value cannot be a header, which the caller answers as a
/// failure rather than a response that silently lacks the cookie.
fn with_cookie(response: &mut Response<HttpBody>, cookie: &str) -> bool {
    match cookie.parse() {
        Ok(value) => {
            response.metadata_mut().append("set-cookie", value);
            true
        }
        Err(_) => false,
    }
}

/// The further entry that meets the step-up `refusal` names, given what the
/// returned entry already `asked` the issuer for: a higher level
/// (`acr_values`) or a fresher authentication (`max_age`, OpenID Connect
/// Core 1.0 §3.1.2.1), a second factor being asked as the level that attests
/// one. None when the refusal is no step-up, names a particular method (an
/// issuer is asked for no `amr`), or asks for what the entry already asked: a
/// second insufficient return completes nothing, so no entry loops.
fn further_request(refusal: &Status, asked: &EntryRequest) -> Option<EntryRequest> {
    use tonic_types::StatusExt;
    let info = refusal.get_details_error_info()?;
    if info.reason != "STEP_UP_REQUIRED" {
        return None;
    }
    let violations = refusal.get_details_precondition_failure()?.violations;
    if violations.is_empty() {
        return None;
    }
    let mut further = asked.clone();
    for violation in violations {
        match violation.r#type.as_str() {
            "acr" => {
                let level = sid_core::models::AuthLevel::from_acr_value(&violation.subject)?;
                if asked.acr.is_some_and(|a| a >= level) {
                    return None;
                }
                further.acr = Some(level);
            }
            "max_age" => {
                let max_age = std::time::Duration::from_secs(violation.subject.parse().ok()?);
                if asked.max_age.is_some_and(|a| a <= max_age) {
                    return None;
                }
                further.max_age = Some(max_age);
            }
            // A second factor of any kind is what the multi-factor level
            // attests, and the level is what an issuer can be asked for.
            "amr" if violation.subject == "mfa" => {
                let level = sid_core::models::AuthLevel::Standard;
                if asked.acr.is_some_and(|a| a >= level) {
                    return None;
                }
                further.acr = Some(further.acr.map_or(level, |a| a.max(level)));
            }
            _ => return None,
        }
    }
    Some(further)
}

/// `rd` when it continues an authorization at `issuer_url`'s own
/// authorization endpoint (the continuation its sign-in step names), else
/// `None`: the entry never returns the browser anywhere else.
fn continuation_of(issuer_url: &str, rd: &str) -> Option<url::Url> {
    let endpoint = url::Url::parse(&format!("{issuer_url}/oauth2/authorize")).ok()?;
    let rd = url::Url::parse(rd).ok()?;
    let here = rd.origin() == endpoint.origin()
        && rd.path() == endpoint.path()
        && rd.fragment().is_none()
        && rd.username().is_empty()
        && rd.password().is_none();
    (here && client_of(&rd).is_some()).then_some(rd)
}

/// The one `client_id` an authorization request names (RFC 6749 §4.1.1;
/// §3.1: a parameter is not repeated), else `None`.
fn client_of(authorization: &url::Url) -> Option<String> {
    let mut ids = authorization
        .query_pairs()
        .filter(|(name, _)| name == "client_id")
        .map(|(_, value)| value.into_owned());
    match (ids.next(), ids.next()) {
        (Some(id), None) if !id.is_empty() => Some(id),
        _ => None,
    }
}

#[tonic::async_trait]
impl FederatedEntryService for FederatedEntryServiceImpl {
    async fn start_federated_entry(
        &self,
        request: Request<StartFederatedEntryRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let message = request.into_inner();
        let step = match self.step(&message.issuer_handle, &message.connection).await {
            Ok(step) => step,
            Err(NoStep::UnknownIssuer) => return Ok(oauth_http::page(404, "Unknown issuer")),
            // Not registered, another issuer's, or disabled: nothing starts.
            Err(NoStep::NoConnection) => {
                return Ok(oauth_http::page(404, "This sign-in is not available"));
            }
            Err(NoStep::Unavailable) => return Ok(oauth_http::page(503, Refusal::retry().text)),
        };
        let Some(continuation) = continuation_of(&step.issuer.canonical_url, &message.rd) else {
            return Ok(oauth_http::page(400, "Sign-in request refused"));
        };
        // This installation's policy weighs whatever the issuer returns; the
        // first request asks for nothing beyond the subject.
        Ok(self
            .begin(&step, &continuation, &EntryRequest::default())
            .await
            .unwrap_or_else(unavailable))
    }

    async fn complete_federated_entry(
        &self,
        request: Request<CompleteFederatedEntryRequest>,
    ) -> Result<Response<HttpBody>, Status> {
        let message = request.get_ref();
        // The state names the connection the entry was started through. It
        // only selects: the entry is found by that connection's issuer and
        // client alone, so a state naming another connection completes
        // nothing. A state naming none started no entry here.
        let Some(connection) = sid_authn::federated_entry::route_of(&message.state) else {
            return Ok(oauth_http::page(400, "Sign-in was not completed"));
        };
        let step = match self.step(&message.issuer_handle, connection).await {
            Ok(step) => step,
            Err(NoStep::UnknownIssuer) => return Ok(oauth_http::page(404, "Unknown issuer")),
            // The connection is gone or disabled since the entry started:
            // the return completes nothing.
            Err(NoStep::NoConnection) => {
                return Ok(oauth_http::page(400, "Sign-in was not completed"));
            }
            Err(NoStep::Unavailable) => return Ok(oauth_http::page(503, Refusal::retry().text)),
        };
        // Several issuers return to this one callback, so a return must say
        // which issuer it comes from, and that is the connection's exactly
        // (RFC 9207 §2.4; RFC 9700 §4.4.2.1): an error return too. Refused
        // before anything is exchanged.
        if message.iss != step.entry.issuer() {
            warn!("federated entry returned without its issuer, or by another");
            return Ok(oauth_http::page(400, "Sign-in was not completed"));
        }
        // OpenID Connect Core 1.0 §3.1.2.6: an error return completes nothing.
        if !message.error.is_empty() {
            return Ok(self.declined(&step, &request).await);
        }
        let (mut response, over) = match self.admit(&step, &request).await {
            Ok(response) => (response, true),
            Err(refusal) if refusal.keep_entry => (oauth_http::page(503, refusal.text), false),
            Err(refusal) => (oauth_http::page(403, refusal.text), true),
        };
        // A return that completed or was refused ends its entry: its
        // correlation cookie, and only its own, is cleared. One that failed
        // on a dependency keeps it, so the same browser can retry. The
        // response delivering the session clears it in the same breath: a
        // browser that never received it still holds both for its retry.
        if over && !with_cookie(&mut response, &step.entry.clear_cookie(&message.state)) {
            return Ok(oauth_http::page(502, "Sign-in is temporarily unavailable"));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
