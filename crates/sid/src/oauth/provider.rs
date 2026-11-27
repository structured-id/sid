// SPDX-License-Identifier: AGPL-3.0-only
//! An issuer's public endpoints for its relying parties: OIDC Discovery 1.0
//! and RFC 8414 metadata, the JWK Set (RFC 7517) of the keys that sign its
//! tokens, and UserInfo (OIDC Core 1.0 §5.3). Every answer belongs to the
//! issuer the handle names; there is no issuer-less endpoint and no fallback
//! to another issuer.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sid_authn::resource::{self, Scheme, SenderError};
use sid_core::Error as SidError;
use sid_core::models::{OidcIssuer, SessionId};
use sid_proto::sid::v1::{JsonWebKey, JsonWebKeySet, ProviderMetadata, UserInfo};

use super::OAuth;

/// Why an issuer endpoint is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// No OIDC issuer has the handle.
    #[error("no OIDC issuer has this handle")]
    IssuerNotFound(String),
    /// No access token was presented (RFC 6750 §3).
    #[error("an access token is required")]
    NoToken,
    /// The token presented under the scheme is not valid here (RFC 6750
    /// §3.1): another issuer's or resource's, revoked, or of an ended
    /// session.
    #[error("the access token is not valid")]
    InvalidToken(Scheme),
    /// The proof of possession does not hold (RFC 9449 §7.1); `challenge`
    /// says what the client must send.
    #[error("the proof of possession is not valid")]
    Proof { challenge: String },
    /// The token was not issued for UserInfo: it lacks `openid` (RFC 6750
    /// §3.1 `insufficient_scope`).
    #[error("the access token lacks the openid scope")]
    InsufficientScope(Scheme),
    /// A dependency the decision needs cannot answer now; the client retries.
    #[error("{what} unavailable: {cause}")]
    Unavailable { what: &'static str, cause: String },
    #[error("store: {0}")]
    Store(#[from] SidError),
}

/// What a UserInfo request presented: the token under its scheme, its
/// sender proofs, and the request they must name as it was received.
pub struct Presented<'a> {
    pub scheme: Scheme,
    pub token: &'a str,
    pub proofs: &'a [&'a str],
    pub method: &'a str,
    pub uri: &'a str,
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

/// The asymmetric algorithms a registered client key verifies, wherever a
/// client authenticates with `private_key_jwt`.
const CLIENT_ASSERTION_ALGORITHMS: &[&str] = &[
    "EdDSA", "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];

/// The metadata of the issuer at `issuer`: every endpoint under its URL,
/// and the token exchange grant only where `impersonation` is offered.
pub fn metadata(issuer: &str, impersonation: bool) -> ProviderMetadata {
    let mut grant_types = strings(&[
        "authorization_code",
        "refresh_token",
        "client_credentials",
        super::DEVICE_CODE_GRANT,
    ]);
    if impersonation {
        grant_types.push(super::TOKEN_EXCHANGE_GRANT.to_string());
    }
    ProviderMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        userinfo_endpoint: Some(sid_authn::issuer::userinfo_endpoint(issuer)),
        jwks_uri: format!("{issuer}/jwks"),
        end_session_endpoint: Some(format!("{issuer}/oauth2/end-session")),
        introspection_endpoint: Some(format!("{issuer}/oauth2/introspect")),
        revocation_endpoint: Some(format!("{issuer}/oauth2/revoke")),
        device_authorization_endpoint: Some(format!("{issuer}/oauth2/device")),
        response_types_supported: strings(&["code"]),
        grant_types_supported: grant_types,
        // OIDC Core §8: `public` is issuer-relative. Within this issuer every
        // client of the organization gets the same permitted subject for a
        // user; other organizations and contours are other issuers.
        subject_types_supported: strings(&["public"]),
        // Signed with the issuer's own Ed25519 key.
        id_token_signing_alg_values_supported: strings(&["EdDSA"]),
        scopes_supported: strings(&["openid", "profile", "email", "offline_access"]),
        token_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ]),
        token_endpoint_auth_signing_alg_values_supported: strings(CLIENT_ASSERTION_ALGORITHMS),
        // Revocation authenticates a client as the token endpoint does
        // (RFC 7009 §2.1), a public one by naming itself.
        revocation_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ]),
        revocation_endpoint_auth_signing_alg_values_supported: strings(CLIENT_ASSERTION_ALGORITHMS),
        // Only an authenticated caller introspects (RFC 7662 §2.1, §4).
        introspection_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ]),
        introspection_endpoint_auth_signing_alg_values_supported: strings(
            CLIENT_ASSERTION_ALGORITHMS,
        ),
        code_challenge_methods_supported: strings(&["S256"]),
        dpop_signing_alg_values_supported: strings(
            sid_core::models::dpop::DPopProof::SIGNING_ALGORITHMS,
        ),
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        // RFC 9207 §3: every authorization response names its issuer.
        authorization_response_iss_parameter_supported: true,
        registration_endpoint: Some(format!("{issuer}/oauth2/register")),
    }
}

/// The UserInfo of subject `sub`: the values `held`, the holder's consent to
/// the token's client, discloses for the claims the token's `scopes` ask
/// for (OIDC Core 1.0 §5.4) or the client registered (`registered`). Only
/// an approved value is delivered, never the current Profile; a claim the
/// holder did not share is left out (consent-flow.md, OIDC scope requests).
pub fn disclosed_claims(
    sub: String,
    scopes: &str,
    registered: &[sid_core::models::ClaimRequest],
    held: Option<&sid_core::models::ConsentRecord>,
) -> UserInfo {
    let scopes: Vec<String> = scopes.split_whitespace().map(str::to_owned).collect();
    let asked = sid_core::models::consent::scope_claims(&scopes);
    let mut info = UserInfo {
        sub,
        ..Default::default()
    };
    let Some(held) = held.filter(|c| c.status.is_active()) else {
        return info;
    };
    for grant in held.grants.iter().filter(|g| g.is_active()) {
        let requested = asked.contains(&grant.claim_name.as_str())
            || registered.iter().any(|r| r.claim_name == grant.claim_name);
        let Some(disclosed) = grant.disclosed.as_ref().filter(|_| requested) else {
            continue;
        };
        // An attestation discloses only that the value was verified.
        let value = (grant.claim_type == sid_core::models::ClaimType::Data)
            .then(|| disclosed.value.clone());
        match grant.claim_name.as_str() {
            "name" => info.name = value,
            "given_name" => info.given_name = value,
            "family_name" => info.family_name = value,
            "middle_name" => info.middle_name = value,
            "preferred_username" => info.preferred_username = value,
            "email" => {
                info.email = value;
                info.email_verified = disclosed.verified;
            }
            "phone_number" => {
                info.phone_number = value;
                info.phone_number_verified = disclosed.verified;
            }
            _ => {}
        }
    }
    info
}

impl OAuth {
    /// The issuer `handle` names.
    pub async fn issuer_by_handle(&self, handle: &str) -> Result<OidcIssuer, ProviderError> {
        self.issuers
            .by_handle(handle)
            .await?
            .ok_or_else(|| ProviderError::IssuerNotFound(handle.to_string()))
    }

    /// The discovery metadata of the issuer `handle` names.
    pub async fn provider_metadata(&self, handle: &str) -> Result<ProviderMetadata, ProviderError> {
        Ok(metadata(
            &self.issuer_by_handle(handle).await?.canonical_url,
            self.impersonation,
        ))
    }

    /// The public keys of the issuer `handle` names, newest generation
    /// first, as the contract lists them.
    pub async fn jwks(&self, handle: &str) -> Result<JsonWebKeySet, ProviderError> {
        let issuer = self.issuer_by_handle(handle).await?;
        let mut keys = self.issuers.public_keys(&issuer).await?;
        keys.reverse();
        Ok(JsonWebKeySet {
            keys: keys
                .into_iter()
                .map(|(kid, public_key)| JsonWebKey {
                    kty: "OKP".into(),
                    r#use: "sig".into(),
                    alg: "EdDSA".into(),
                    kid,
                    crv: "Ed25519".into(),
                    x: URL_SAFE_NO_PAD.encode(public_key),
                })
                .collect(),
        })
    }

    /// UserInfo at the issuer `handle` names: the token must be one this
    /// issuer signed for its UserInfo resource, unrevoked, for the `openid`
    /// scope, sent under its key binding (its proof naming the request as
    /// received), and of a session that still exists.
    pub async fn user_info(
        &self,
        handle: &str,
        presented: Option<Presented<'_>>,
    ) -> Result<UserInfo, ProviderError> {
        let issuer = self.issuer_by_handle(handle).await?;
        let presented = presented.ok_or(ProviderError::NoToken)?;
        let scheme = presented.scheme;
        let verifier = self.issuers.verifier(&issuer).await?;
        // Only this issuer's tokens for its UserInfo resource: a sibling
        // issuer's or a sign-in token names another `iss` or key, and a token
        // for another resource another `aud` (RFC 9068 §4).
        let endpoint = sid_authn::issuer::userinfo_endpoint(&issuer.canonical_url);
        let claims = verifier
            .validate_access_token_for(presented.token, &endpoint)
            .map_err(|_| ProviderError::InvalidToken(scheme))?;
        match self.revocation.is_revoked(&claims.jti, &claims.sid).await {
            Ok(false) => {}
            Ok(true) => return Err(ProviderError::InvalidToken(scheme)),
            Err(e) => {
                return Err(ProviderError::Unavailable {
                    what: "token revocation state",
                    cause: e.to_string(),
                });
            }
        }
        // A key-bound token needs its proof for this request (RFC 9449 §7.1),
        // naming it as it was received.
        resource::check_sender(
            &self.dpop,
            scheme,
            presented.token,
            claims.cnf.as_ref().map(|cnf| cnf.jkt.as_str()),
            presented.proofs,
            presented.method,
            Some(presented.uri),
        )
        .await
        .map_err(|e| match e {
            // An unreachable replay record cannot rule out a replay; the
            // client retries the same request with a new proof.
            SenderError::Proof(sid_authn::dpop::DPopError::ReplayStoreUnavailable) => {
                ProviderError::Unavailable {
                    what: "DPoP replay record",
                    cause: "replay store unreachable".to_string(),
                }
            }
            other => {
                tracing::debug!(error = %other, "UserInfo: sender constraint not met");
                ProviderError::Proof {
                    challenge: other.challenge().to_string(),
                }
            }
        })?;
        // RFC 6750 §3.1: a token without `openid` was not issued for UserInfo.
        if !claims.scope.split_whitespace().any(|s| s == "openid") {
            return Err(ProviderError::InsufficientScope(scheme));
        }
        let session_id =
            SessionId::parse(&claims.sid).map_err(|_| ProviderError::InvalidToken(scheme))?;
        let session = self
            .storage
            .get_session(session_id)
            .await?
            .filter(|session| !session.is_expired())
            .ok_or(ProviderError::InvalidToken(scheme))?;
        let profile = self
            .storage
            .get_profile(session.profile_id)
            .await?
            .ok_or(ProviderError::InvalidToken(scheme))?;
        // What the holder disclosed to the token's client: its approved
        // values, never the current Profile (identity-model.md, recipient
        // disclosure).
        let client_id = claims.client_id.as_deref().unwrap_or_default();
        let registered = self
            .storage
            .get_oauth2_client(client_id)
            .await?
            .map(|c| c.claim_requests)
            .unwrap_or_default();
        let held = self.held_disclosure(profile.id, client_id).await?;
        // `sub` as the token carries it: the ID token of this client under
        // the same hop carried the same value (OIDC Core 1.0 §5.3.2).
        Ok(disclosed_claims(
            claims.sub.clone(),
            &claims.scope,
            &registered,
            held.as_ref(),
        ))
    }
}

#[cfg(test)]
mod tests;
