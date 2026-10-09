// SPDX-License-Identifier: AGPL-3.0-only
//! This service's own credential at its issuer: a client credentials token
//! (RFC 6749 §4.4) for one protected resource, requested from the issuer and
//! reused until shortly before it expires, so a call never waits for a token
//! request of its own. The resource is the authorization API (`{issuer}/authz`)
//! for a service that asks permission questions, or the service it calls.

use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tonic::metadata::{AsciiMetadataValue, MetadataValue};

/// How long a client assertion is valid (RFC 7523 §3 item 4): long enough to
/// reach the token endpoint, far below the server's accepted lifetime.
const ASSERTION_LIFETIME_SECS: i64 = 60;

/// A registered client (a confidential OAuth client or a machine user) this
/// service authenticates as at its issuer: to ask sid-authz, holding the
/// permission-checker role on the resources it asks about, or to call
/// another service, holding that service's actions.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredentialConfig {
    /// The exact issuer the client is registered under; its tokens are for
    /// that issuer's resources only.
    pub issuer: String,
    /// The client identifier (RFC 6749 §2.2).
    pub client_id: String,
    /// How the client authenticates at the token endpoint (RFC 6749 §2.3).
    pub authentication: ClientAuthentication,
}

/// A client authentication method with the file holding its credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientAuthentication {
    /// The client secret in HTTP Basic (RFC 6749 §2.3.1).
    ClientSecretBasic {
        /// File holding the client secret.
        secret_file: String,
    },
    /// The client secret in the request body (RFC 6749 §2.3.1).
    ClientSecretPost {
        /// File holding the client secret.
        secret_file: String,
    },
    /// A JWT signed with the client's registered key (RFC 7523 §2.2).
    PrivateKeyJwt {
        /// File holding the PKCS#8 PEM private key.
        key_file: String,
        /// The JWS algorithm of the key: `EdDSA`, `ES256` or `RS256`.
        algorithm: String,
        /// The registered key's identifier, sent as the JWS `kid`; absent
        /// when the client registered a single key.
        #[serde(default)]
        key_id: Option<String>,
    },
}

impl ClientCredentialConfig {
    /// From `{prefix}_CLIENT_ID`, `_ISSUER`, `_METHOD` and the method's
    /// `_SECRET_FILE` or `_KEY_FILE`/`_ALGORITHM`/`_KEY_ID` in the process
    /// environment; `None` when no client is named.
    pub fn from_env(prefix: &str) -> Result<Option<Self>, CredentialError> {
        Self::from_vars(prefix, |name| {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        })
    }

    /// As [`Self::from_env`], reading variables through `var`.
    pub fn from_vars(
        prefix: &str,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, CredentialError> {
        let name = |suffix: &str| format!("{prefix}_{suffix}");
        let Some(client_id) = var(&name("CLIENT_ID")) else {
            return Ok(None);
        };
        let required = |suffix: &str| {
            let key = name(suffix);
            var(&key).ok_or_else(|| {
                CredentialError::Config(format!("{key} is required with {prefix}_CLIENT_ID"))
            })
        };
        let authentication = match required("METHOD")?.as_str() {
            "client_secret_basic" => ClientAuthentication::ClientSecretBasic {
                secret_file: required("SECRET_FILE")?,
            },
            "client_secret_post" => ClientAuthentication::ClientSecretPost {
                secret_file: required("SECRET_FILE")?,
            },
            "private_key_jwt" => ClientAuthentication::PrivateKeyJwt {
                key_file: required("KEY_FILE")?,
                algorithm: required("ALGORITHM")?,
                key_id: var(&name("KEY_ID")),
            },
            other => {
                return Err(CredentialError::Config(format!(
                    "{prefix}_METHOD {other} is not a supported method"
                )));
            }
        };
        Ok(Some(Self {
            issuer: required("ISSUER")?,
            client_id,
            authentication,
        }))
    }
}

/// Why no token is available.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The configuration cannot authenticate (unreadable or malformed file,
    /// an issuer outside this installation).
    #[error("client credential: {0}")]
    Config(String),
    /// The token endpoint refused or could not be reached.
    #[error("token request: {0}")]
    Token(String),
}

/// How the client proves itself at the token endpoint.
enum Credential {
    Basic(SecretString),
    Post(SecretString),
    Assertion {
        key: jsonwebtoken::EncodingKey,
        algorithm: jsonwebtoken::Algorithm,
        key_id: Option<String>,
    },
}

/// A token in hand. The header value is the form every call sends, so it is
/// kept once in that form rather than rebuilt per call.
struct Held {
    authorization: AsciiMetadataValue,
    refresh_at: Instant,
}

/// A client, the resource its tokens are for and the token it holds.
pub struct ClientCredential {
    /// The exact issuer the client and the resource belong to.
    issuer: String,
    /// The issuer's handle: the token endpoint the request is for.
    handle: String,
    client_id: String,
    credential: Credential,
    /// The protected resource the tokens are for (RFC 8707).
    resource: String,
    /// The scope every token must carry, when one is required.
    scope: Option<&'static str>,
    channel: tonic::transport::Channel,
    held: RwLock<Option<std::sync::Arc<Held>>>,
    /// One token request at a time: concurrent calls wait for it rather
    /// than each requesting a token.
    requesting: Mutex<()>,
}

impl std::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredential")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

impl ClientCredential {
    /// The credential `config` names for the issuer's authorization API with
    /// the `authz.check` scope: what a service asking permission questions
    /// holds.
    pub fn checker(
        config: &ClientCredentialConfig,
        base: &str,
        channel: tonic::transport::Channel,
    ) -> Result<Self, CredentialError> {
        let api = crate::issuer::authorization_api_endpoint(&config.issuer);
        Self::load(
            config,
            base,
            channel,
            api,
            Some(sid_core::models::AUTHZ_CHECK),
        )
    }

    /// The credential `config` names for the protected resource `resource`:
    /// what a service presents to the service it calls.
    pub fn for_resource(
        config: &ClientCredentialConfig,
        base: &str,
        channel: tonic::transport::Channel,
        resource: &str,
    ) -> Result<Self, CredentialError> {
        Self::load(config, base, channel, resource.to_owned(), None)
    }

    /// The credential `config` names, for an issuer under `base` (the
    /// installation's public URL), asking the issuer over `channel`. The
    /// credential file is read now: a deployment that cannot authenticate
    /// fails at start-up, not at its first call.
    fn load(
        config: &ClientCredentialConfig,
        base: &str,
        channel: tonic::transport::Channel,
        resource: String,
        scope: Option<&'static str>,
    ) -> Result<Self, CredentialError> {
        let invalid = |why: String| CredentialError::Config(why);
        let prefix = format!("{}/i/", base.trim_end_matches('/'));
        let handle = config
            .issuer
            .strip_prefix(&prefix)
            .filter(|handle| sid_core::models::IssuerHandle::parse(handle).is_ok())
            .ok_or_else(|| invalid("the issuer is not one of this installation".into()))?
            .to_owned();
        if config.client_id.is_empty() {
            return Err(invalid("the client_id is empty".into()));
        }
        let read = |path: &str| {
            std::fs::read_to_string(path).map_err(|e| invalid(format!("reading {path}: {e}")))
        };
        let secret = |path: &str| {
            let secret = read(path)?.trim().to_owned();
            if secret.is_empty() {
                return Err(invalid(format!("{path} holds no secret")));
            }
            Ok(SecretString::from(secret))
        };
        let credential = match &config.authentication {
            ClientAuthentication::ClientSecretBasic { secret_file } => {
                Credential::Basic(secret(secret_file)?)
            }
            ClientAuthentication::ClientSecretPost { secret_file } => {
                Credential::Post(secret(secret_file)?)
            }
            ClientAuthentication::PrivateKeyJwt {
                key_file,
                algorithm,
                key_id,
            } => {
                let pem = SecretString::from(read(key_file)?);
                let pem = pem.expose_secret().as_bytes();
                let unusable = |e: jsonwebtoken::errors::Error| {
                    invalid(format!("{key_file} is not a {algorithm} private key: {e}"))
                };
                let (key, algorithm) = match algorithm.as_str() {
                    "EdDSA" => (
                        jsonwebtoken::EncodingKey::from_ed_pem(pem).map_err(unusable)?,
                        jsonwebtoken::Algorithm::EdDSA,
                    ),
                    "ES256" => (
                        jsonwebtoken::EncodingKey::from_ec_pem(pem).map_err(unusable)?,
                        jsonwebtoken::Algorithm::ES256,
                    ),
                    "RS256" => (
                        jsonwebtoken::EncodingKey::from_rsa_pem(pem).map_err(unusable)?,
                        jsonwebtoken::Algorithm::RS256,
                    ),
                    other => return Err(invalid(format!("unsupported algorithm {other}"))),
                };
                Credential::Assertion {
                    key,
                    algorithm,
                    key_id: key_id.clone(),
                }
            }
        };
        Ok(Self {
            issuer: config.issuer.clone(),
            handle,
            client_id: config.client_id.clone(),
            credential,
            resource,
            scope,
            channel,
            held: RwLock::new(None),
            requesting: Mutex::new(()),
        })
    }

    /// The exact issuer this credential's tokens come from.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The `authorization` value of a call to the resource: the held token
    /// while it is fresh, otherwise a new one.
    pub async fn authorization(&self) -> Result<AsciiMetadataValue, CredentialError> {
        if let Some(held) = self.fresh().await {
            return Ok(held.authorization.clone());
        }
        let _requesting = self.requesting.lock().await;
        // Another question may have fetched it while this one waited.
        if let Some(held) = self.fresh().await {
            return Ok(held.authorization.clone());
        }
        let held = std::sync::Arc::new(self.request().await?);
        *self.held.write().await = Some(held.clone());
        Ok(held.authorization.clone())
    }

    /// Drop the held token when it is `refused`: the resource no longer
    /// accepts it (revoked, its client disabled), so the next call requests
    /// another instead of repeating it.
    pub async fn refused(&self, refused: &AsciiMetadataValue) {
        let mut held = self.held.write().await;
        if held
            .as_ref()
            .is_some_and(|held| held.authorization == *refused)
        {
            *held = None;
        }
    }

    async fn fresh(&self) -> Option<std::sync::Arc<Held>> {
        self.held
            .read()
            .await
            .as_ref()
            .filter(|held| Instant::now() < held.refresh_at)
            .cloned()
    }

    /// A new token from the issuer's token endpoint (RFC 6749 §4.4.2) for the
    /// resource, with the required scope when there is one.
    async fn request(&self) -> Result<Held, CredentialError> {
        use sid_proto::sid::v1::OAuth2TokenRequest;
        let token_endpoint = crate::issuer::token_endpoint(&self.issuer);
        let mut body = OAuth2TokenRequest {
            grant_type: "client_credentials".into(),
            scope: self.scope.map(str::to_owned),
            issuer_handle: self.handle.clone(),
            resource: vec![self.resource.clone()],
            ..Default::default()
        };
        let mut basic = None;
        match &self.credential {
            Credential::Basic(secret) => {
                basic = Some(basic_authorization(&self.client_id, secret)?)
            }
            Credential::Post(secret) => {
                body.client_id = Some(self.client_id.clone());
                body.client_secret = Some(secret.expose_secret().to_owned());
            }
            Credential::Assertion {
                key,
                algorithm,
                key_id,
            } => {
                body.client_id = Some(self.client_id.clone());
                body.client_assertion =
                    Some(self.assertion(&token_endpoint, key, *algorithm, key_id.as_deref())?);
                body.client_assertion_type =
                    Some(crate::client_assertion::JWT_BEARER_ASSERTION_TYPE.into());
            }
        }
        let mut request = tonic::Request::new(body);
        if let Some(basic) = basic {
            request.metadata_mut().insert("authorization", basic);
        }
        let asked = Instant::now();
        let mut client =
            sid_proto::sid::v1::auth_service_client::AuthServiceClient::new(self.channel.clone());
        let answer = client
            .o_auth2_token(request)
            .await
            .map_err(|status| {
                CredentialError::Token(format!("{:?}: {}", status.code(), status.message()))
            })?
            .into_inner();
        // A bearer token only: a bound one would need a proof per call that
        // this credential does not make (RFC 9449 §7.1).
        if !answer.token_type.eq_ignore_ascii_case("bearer") {
            return Err(CredentialError::Token(format!(
                "the issuer answered a {} token",
                answer.token_type
            )));
        }
        // A token without the required scope is refused by the resource on
        // every call; better known now (RFC 6749 §5.1 `scope`).
        if let Some(required) = self.scope
            && answer
                .scope
                .as_deref()
                .is_some_and(|scope| !scope.split_whitespace().any(|granted| granted == required))
        {
            return Err(CredentialError::Token(format!(
                "the issuer did not grant {required}"
            )));
        }
        let lifetime = u64::try_from(answer.expires_in)
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| CredentialError::Token("the token has no lifetime".into()))?;
        let mut authorization: AsciiMetadataValue =
            MetadataValue::try_from(format!("Bearer {}", answer.access_token))
                .map_err(|_| CredentialError::Token("the token is not a header value".into()))?;
        authorization.set_sensitive(true);
        // Renewed after nine tenths of its lifetime, counted from when it was
        // asked for, so it never reaches the API expired.
        let refresh_at = asked + Duration::from_secs(lifetime) * 9 / 10;
        Ok(Held {
            authorization,
            refresh_at,
        })
    }

    /// A client assertion (RFC 7523 §3) for `audience`, the token endpoint.
    fn assertion(
        &self,
        audience: &str,
        key: &jsonwebtoken::EncodingKey,
        algorithm: jsonwebtoken::Algorithm,
        key_id: Option<&str>,
    ) -> Result<String, CredentialError> {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": audience,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
            "jti": uuid::Uuid::now_v7().to_string(),
        });
        let mut header = jsonwebtoken::Header::new(algorithm);
        header.kid = key_id.map(str::to_owned);
        jsonwebtoken::encode(&header, &claims, key)
            .map_err(|e| CredentialError::Config(format!("signing the client assertion: {e}")))
    }
}

/// A gRPC channel whose every call carries this service's own token for the
/// resource it calls. A call the resource refuses as unauthenticated drops
/// that token, so the next call presents a new one; the refused call itself
/// is answered as it was, never repeated here.
#[derive(Clone)]
pub struct WithCredential<S> {
    inner: S,
    credential: std::sync::Arc<ClientCredential>,
}

impl<S> WithCredential<S> {
    pub fn new(inner: S, credential: std::sync::Arc<ClientCredential>) -> Self {
        Self { inner, credential }
    }
}

impl<S> tonic::codegen::Service<http::Request<tonic::body::Body>> for WithCredential<S>
where
    S: tonic::codegen::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<tonic::body::Body>,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<tonic::codegen::StdError>,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = tonic::codegen::StdError;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: http::Request<tonic::body::Body>) -> Self::Future {
        // The ready service answers this call; its clone waits for the next.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let credential = self.credential.clone();
        Box::pin(async move {
            let authorization = credential.authorization().await?;
            let mut header = http::HeaderValue::from_bytes(authorization.as_encoded_bytes())?;
            header.set_sensitive(true);
            request
                .headers_mut()
                .insert(http::header::AUTHORIZATION, header);
            let response = inner.call(request).await.map_err(Into::into)?;
            // A refusal before any message is a trailers-only response: its
            // status is in the headers (gRPC over HTTP/2, "Trailers-Only").
            let unauthenticated = response
                .headers()
                .get("grpc-status")
                .is_some_and(|status| status.as_bytes() == b"16");
            if unauthenticated {
                credential.refused(&authorization).await;
            }
            Ok(response)
        })
    }
}

/// `Basic` credentials (RFC 7617 §2) of `client_id` and `secret`, each
/// form-urlencoded first (RFC 6749 §2.3.1).
fn basic_authorization(
    client_id: &str,
    secret: &SecretString,
) -> Result<AsciiMetadataValue, CredentialError> {
    use base64::Engine;
    let joined = SecretString::from(format!(
        "{}:{}",
        form_encode(client_id),
        form_encode(secret.expose_secret())
    ));
    let encoded = base64::engine::general_purpose::STANDARD.encode(joined.expose_secret());
    let mut value: AsciiMetadataValue = MetadataValue::try_from(format!("Basic {encoded}"))
        .map_err(|_| {
            CredentialError::Config("the client credentials are not a header value".into())
        })?;
    value.set_sensitive(true);
    Ok(value)
}

/// `application/x-www-form-urlencoded` encoding of one value (WHATWG URL
/// §5.2): unreserved bytes as they are, space as `+`, the rest `%XX`.
fn form_encode(value: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => write!(out, "%{byte:02X}").expect("writing to a String cannot fail"),
        }
    }
    out
}

#[cfg(test)]
mod tests;
