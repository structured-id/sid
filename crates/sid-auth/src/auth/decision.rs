// SPDX-License-Identifier: AGPL-3.0-only
//! The forward-auth decision, independent of how it is asked.
//!
//! A reverse proxy asks through `ForwardAuthService.Verify` (HTTP via the
//! transcoder) and Envoy through ext_authz `Check`; both hand the original
//! request here and turn the verdict into their own answer, so the two
//! transports enforce one contract.
//!
//! Pipeline:
//! 1. Resolve the protected application the proxy names
//! 2. Match its route policy for the original path and method
//! 3. auth: none → allow, no identity
//! 4. Resolve the registered target, then validate the token for it
//! 5. Revocation and sender constraint
//! 6. Required roles and, when configured, sid-authz
//! 7. Identity headers

use std::sync::Arc;

use http::header::{LOCATION, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use super::headers::build_auth_headers;
use super::jwt::{
    ForwardAuthClaims, TargetAccess, TokenRefusal, presented_token, validate_for_target,
};
use super::policy::{AuthRequirement, PolicyEngine};
use super::sender::check_sender;
use crate::issuers::IssuerDirectory;

/// What forward auth needs to decide.
pub struct Pdp {
    /// The installation's issuers and registered resources.
    pub issuers: Arc<IssuerDirectory>,
    /// The protected applications and their routes.
    pub applications: Arc<PolicyEngine>,
    /// Revoked tokens and sessions, as every SID process records them.
    pub revocation: Arc<sid_authn::revocation_cache::RevocationCache>,
    /// DPoP proof checks; proof `jti`s are recorded in the shared cache.
    pub dpop: Arc<sid_authn::dpop::DPopValidator>,
    /// Channel to sid-authz for routes that ask it.
    pub authz: tonic::transport::Channel,
    /// This service's own credential for the authorization API; routes that
    /// ask sid-authz have no verdict without it.
    pub checker: Option<Arc<sid_authn::client_credential::ClientCredential>>,
    /// Where a 401 sends a browser to sign in; empty for none.
    pub login_url: String,
}

impl std::fmt::Debug for Pdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pdp")
            .field("applications", &self.applications)
            .finish_non_exhaustive()
    }
}

/// The original request the proxy asks about.
#[derive(Debug, Clone, Copy)]
pub struct OriginalRequest<'a> {
    pub method: &'a Method,
    /// Path with query, as the client sent it.
    pub path: &'a str,
    /// The original request's headers (`authorization`, `dpop`).
    pub headers: &'a HeaderMap,
}

/// The HTTP answer the proxy acts on.
#[derive(Debug)]
pub struct Verdict {
    pub status: StatusCode,
    /// Identity headers on allow; `www-authenticate` / `location` on 401.
    pub headers: HeaderMap,
}

impl Verdict {
    fn bare(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
        }
    }

    pub fn allowed(&self) -> bool {
        self.status == StatusCode::OK
    }
}

/// Why no verdict could be given; the proxy denies on each.
#[derive(Debug, thiserror::Error)]
pub enum DecisionError {
    /// The proxy names an application the route configuration lacks.
    #[error("no protected application named {0}")]
    UnknownApplication(String),
    /// A registry, revocation or authorization check could not be answered.
    #[error("{0} unavailable")]
    Unavailable(&'static str),
}

impl Pdp {
    /// Decide whether `request` may reach `application`.
    pub async fn decide(
        &self,
        application: &str,
        request: OriginalRequest<'_>,
    ) -> Result<Verdict, DecisionError> {
        let app = self
            .applications
            .application(application)
            .ok_or_else(|| DecisionError::UnknownApplication(application.to_owned()))?;
        let policy = app.match_route(request.path, request.method);

        // A public route admits anyone and discloses nobody.
        if policy.auth == AuthRequirement::None {
            return Ok(Verdict::bare(StatusCode::OK));
        }
        let optional = policy.auth == AuthRequirement::Optional;
        let anonymous_or = |refusal: Verdict| {
            if optional {
                Verdict::bare(StatusCode::OK)
            } else {
                refusal
            }
        };

        let Some(presented) = presented_token(request.headers) else {
            return Ok(anonymous_or(self.unauthorized(request.path)));
        };

        let TargetAccess { claims, resource } = match validate_for_target(
            &self.issuers,
            &app.target,
            presented.token(),
        )
        .await
        {
            Ok(access) => access,
            Err(TokenRefusal::Unavailable(e)) => {
                tracing::error!(error = %e, "issuer registry unavailable");
                return Err(DecisionError::Unavailable("issuer registry"));
            }
            Err(TokenRefusal::NoTarget(why)) => {
                tracing::warn!(application, resource = %app.target.resource, why, "route target refused");
                return Ok(Verdict::bare(StatusCode::FORBIDDEN));
            }
            Err(e @ TokenRefusal::Invalid(_)) => {
                tracing::debug!(error = %e, "access token refused");
                return Ok(anonymous_or(self.unauthorized(request.path)));
            }
        };

        // A revoked token or session opens nothing; an unanswerable check
        // refuses rather than admits.
        match self.revocation.is_revoked(&claims.jti, &claims.sid).await {
            Ok(false) => {}
            Ok(true) => {
                tracing::debug!(sid = %claims.sid, "token or session revoked");
                return Ok(anonymous_or(self.unauthorized(request.path)));
            }
            Err(e) => {
                tracing::error!(error = %e, "revocation check unavailable");
                return Err(DecisionError::Unavailable("revocation check"));
            }
        }

        // A key-bound token needs its proof for this request (RFC 9449 §7.1),
        // checked against the configured origin of the application, not
        // against a forwarded host the client could have set.
        let uri = format!("{}{}", app.origin, request.path);
        if let Err(e) = check_sender(
            &self.dpop,
            presented,
            &claims,
            request.headers,
            request.method.as_str(),
            Some(&uri),
        )
        .await
        {
            tracing::debug!(error = %e, "sender constraint not met");
            let mut refusal = Verdict::bare(StatusCode::UNAUTHORIZED);
            // No login redirect: signing in again does not supply a proof.
            refusal
                .headers
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static(e.challenge()));
            return Ok(anonymous_or(refusal));
        }

        if !policy.required_roles.is_empty() && !has_any_role(&claims, &policy.required_roles) {
            tracing::debug!(
                sub = %claims.sub,
                required = ?policy.required_roles,
                actual = %claims.roles,
                "insufficient roles"
            );
            return Ok(Verdict::bare(StatusCode::FORBIDDEN));
        }

        if let Some(action) = &policy.authz_action {
            let question = super::permission::Question {
                asking: application,
                issuer: &app.target.issuer,
                resource,
                action,
                object: "",
                token: presented.token(),
                claims: &claims,
                method: request.method.as_str(),
                uri: &uri,
            };
            use super::permission::Permission;
            match super::permission::ask(self.checker.as_deref(), &self.authz, question)
                .await
                .map_err(|_| DecisionError::Unavailable("authorization check"))?
            {
                Permission::Allowed => {}
                Permission::Denied => return Ok(Verdict::bare(StatusCode::FORBIDDEN)),
                // Revoked or ended where this service's revocation view has
                // not seen it yet: the same as a revoked token above.
                Permission::TokenRefused => {
                    return Ok(anonymous_or(self.unauthorized(request.path)));
                }
            }
        }

        Ok(Verdict {
            status: StatusCode::OK,
            headers: build_auth_headers(&claims, &policy.inject_headers, Some(presented.token())),
        })
    }

    /// 401 with the bearer challenge (RFC 6750 §3) and, when configured, the
    /// login page to return from.
    fn unauthorized(&self, original_path: &str) -> Verdict {
        let mut verdict = Verdict::bare(StatusCode::UNAUTHORIZED);
        verdict
            .headers
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        if !self.login_url.is_empty()
            && let Ok(location) = HeaderValue::from_str(&format!(
                "{}?rd={}",
                self.login_url,
                urlencoded(original_path)
            ))
        {
            verdict.headers.insert(LOCATION, location);
        }
        verdict
    }
}

/// Whether the token carries any of `required`.
fn has_any_role(claims: &ForwardAuthClaims, required: &[String]) -> bool {
    claims
        .roles
        .split_whitespace()
        .any(|role| required.iter().any(|r| r == role))
}

/// Percent-encode the characters that would end the `rd` parameter.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace('&', "%26")
        .replace('?', "%3F")
        .replace('=', "%3D")
        .replace(' ', "%20")
        .replace('#', "%23")
}

#[cfg(test)]
pub(crate) mod tests;
