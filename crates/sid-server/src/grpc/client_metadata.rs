// SPDX-License-Identifier: AGPL-3.0-only
//! Client metadata in its RFC 7591 JSON form: a registration or RFC 7592
//! update body read into the typed request, and a registered client written
//! as the client information response.

use serde_json::{Map, Value};
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::{
    ApplicationType, OAuthClient, RegisterClientRequest, SubjectType, TokenEndpointAuthMethod,
    UpdateRegisteredClientRequest,
};

/// Why a body is not client metadata the endpoint can read: the field it
/// concerns, when one, and a description (RFC 7591 §3.2.2
/// `invalid_client_metadata`).
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid {
    pub field: Option<&'static str>,
    pub description: &'static str,
}

impl Invalid {
    fn field(field: &'static str, description: &'static str) -> Self {
        Self {
            field: Some(field),
            description,
        }
    }
}

/// Client metadata as RFC 7591 §2 and OIDC Registration 1.0 §2 name it. A
/// field sent as `null` counts as left out; a field this server does not know
/// is ignored (RFC 7591 §2).
#[derive(Debug, Default, PartialEq)]
pub struct Metadata {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    pub application_type: ApplicationType,
    pub subject_type: SubjectType,
    pub sector_identifier_uri: Option<String>,
    pub contacts: Vec<String>,
    pub scope: Vec<String>,
    /// The `jwks` object as JSON text; its keys are checked by the
    /// registration.
    pub jwks: Option<String>,
    /// OIDC RP-Initiated Logout 1.0 §3.1 `post_logout_redirect_uris`.
    pub post_logout_redirect_uris: Vec<String>,
}

impl Metadata {
    /// Read `body`, which must be an `application/json` object.
    pub fn parse(body: Option<&HttpBody>) -> Result<Self, Invalid> {
        const NOT_JSON: Invalid = Invalid {
            field: None,
            description: "the request body must be a JSON object of client metadata",
        };
        let body = body.ok_or(NOT_JSON)?;
        let media_type = body.content_type.split(';').next().unwrap_or("").trim();
        if !media_type.eq_ignore_ascii_case("application/json") {
            return Err(NOT_JSON);
        }
        let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&body.data) else {
            return Err(NOT_JSON);
        };
        Ok(Self {
            client_id: string(&object, "client_id")?,
            client_secret: string(&object, "client_secret")?,
            client_name: string(&object, "client_name")?,
            redirect_uris: strings(&object, "redirect_uris")?,
            grant_types: strings(&object, "grant_types")?,
            response_types: strings(&object, "response_types")?,
            token_endpoint_auth_method: string(&object, "token_endpoint_auth_method")?
                .map(|method| auth_method(&method))
                .transpose()?,
            application_type: string(&object, "application_type")?
                .map_or(Ok(ApplicationType::Web), |kind| application_type(&kind))?,
            subject_type: string(&object, "subject_type")?
                .map_or(Ok(SubjectType::Unspecified), |kind| subject_type(&kind))?,
            sector_identifier_uri: string(&object, "sector_identifier_uri")?,
            contacts: strings(&object, "contacts")?,
            // RFC 7591 §2: `scope` is one space-separated string.
            scope: string(&object, "scope")?
                .map(|scope| scope.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            // RFC 7591 §2: `jwks` is a JWK Set document, a JSON object.
            jwks: match object.get("jwks") {
                None | Some(Value::Null) => None,
                Some(set @ Value::Object(_)) => Some(set.to_string()),
                Some(_) => return Err(Invalid::field("jwks", "jwks must be a JWK Set object")),
            },
            post_logout_redirect_uris: strings(&object, "post_logout_redirect_uris")?,
        })
    }

    /// The registration this metadata asks for under the issuer `issuer_handle`.
    /// Credentials are not metadata a registration sets: a `client_id` or
    /// `client_secret` in the body is ignored.
    pub fn into_registration(self, issuer_handle: String) -> RegisterClientRequest {
        RegisterClientRequest {
            client_name: self.client_name.unwrap_or_default(),
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types,
            response_types: self.response_types,
            token_endpoint_auth_method: self
                .token_endpoint_auth_method
                .unwrap_or(TokenEndpointAuthMethod::Unspecified)
                .into(),
            application_type: self.application_type.into(),
            subject_type: self.subject_type.into(),
            sector_identifier_uri: self.sector_identifier_uri,
            contacts: self.contacts,
            scope: self.scope,
            issuer_handle,
            jwks: self.jwks,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
        }
    }

    /// The update of `client_id` this metadata asks for (RFC 7592 §2.2): the
    /// body must name that client in `client_id`.
    pub fn into_update(
        self,
        client_id: String,
        issuer_handle: String,
    ) -> Result<UpdateRegisteredClientRequest, Invalid> {
        if self.client_id.as_deref() != Some(client_id.as_str()) {
            return Err(Invalid::field(
                "client_id",
                "the body must name the client being updated in client_id",
            ));
        }
        Ok(UpdateRegisteredClientRequest {
            client_id,
            client_name: self.client_name,
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types,
            response_types: self.response_types,
            token_endpoint_auth_method: self.token_endpoint_auth_method.map(Into::into),
            subject_type: match self.subject_type {
                SubjectType::Unspecified => None,
                other => Some(other.into()),
            },
            sector_identifier_uri: self.sector_identifier_uri,
            contacts: self.contacts,
            scope: self.scope,
            issuer_handle,
            client_secret: self.client_secret,
            jwks: self.jwks,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
        })
    }
}

/// The value of `name` when it is a string; `null` or absent is `None`.
fn string(object: &Map<String, Value>, name: &'static str) -> Result<Option<String>, Invalid> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Invalid::field(name, "the value must be a string")),
    }
}

/// The value of `name` when it is an array of strings; `null` or absent is
/// empty.
fn strings(object: &Map<String, Value>, name: &'static str) -> Result<Vec<String>, Invalid> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or(Invalid::field(
                    name,
                    "the value must be an array of strings",
                ))
            })
            .collect(),
        Some(_) => Err(Invalid::field(
            name,
            "the value must be an array of strings",
        )),
    }
}

/// A `token_endpoint_auth_method` value (RFC 7591 §2); a value this issuer
/// does not know is refused, never read as the default.
fn auth_method(value: &str) -> Result<TokenEndpointAuthMethod, Invalid> {
    match value {
        "client_secret_basic" => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
        "client_secret_post" => Ok(TokenEndpointAuthMethod::ClientSecretPost),
        "none" => Ok(TokenEndpointAuthMethod::None),
        "private_key_jwt" => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        _ => Err(Invalid::field(
            "token_endpoint_auth_method",
            "token_endpoint_auth_method is not a supported value",
        )),
    }
}

/// An `application_type` value (OIDC Registration 1.0 §2): `web` or `native`.
fn application_type(value: &str) -> Result<ApplicationType, Invalid> {
    match value {
        "web" => Ok(ApplicationType::Web),
        "native" => Ok(ApplicationType::Native),
        _ => Err(Invalid::field(
            "application_type",
            "application_type must be 'web' or 'native'",
        )),
    }
}

/// A `subject_type` value (OIDC Registration 1.0 §2). `pairwise` is read so
/// the registration refuses it with its own explanation.
fn subject_type(value: &str) -> Result<SubjectType, Invalid> {
    match value {
        "public" => Ok(SubjectType::Public),
        "pairwise" => Ok(SubjectType::Pairwise),
        _ => Err(Invalid::field(
            "subject_type",
            "subject_type is not a known value. Supported value: 'public'.",
        )),
    }
}

/// The name of `method` in client metadata (RFC 7591 §2).
fn auth_method_name(method: TokenEndpointAuthMethod) -> &'static str {
    match method {
        TokenEndpointAuthMethod::ClientSecretPost => "client_secret_post",
        TokenEndpointAuthMethod::None => "none",
        TokenEndpointAuthMethod::PrivateKeyJwt => "private_key_jwt",
        TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::Unspecified => {
            "client_secret_basic"
        }
    }
}

/// Credentials a response hands out once: at registration only.
pub struct Credentials<'a> {
    pub client_secret: Option<&'a str>,
    pub registration_access_token: &'a str,
}

/// The client information response for `application`, a registered client
/// (RFC 7591 §3.2.1, RFC 7592 §3): every registered metadata value, the time
/// the identifier was issued, and where the client manages itself.
/// `credentials` are present only in the answer to the registration that
/// created them; the secret is never stored in a readable form, so a read or
/// update answer has none.
pub fn client_information(
    application: &OAuthClient,
    credentials: Option<Credentials<'_>>,
) -> Value {
    let mut body = Map::new();
    body.insert("client_id".into(), application.client_id.clone().into());
    if let Some(issued) = &application.client_id_issued_at {
        // RFC 7591 §3.2.1: seconds since the epoch as a JSON number.
        body.insert("client_id_issued_at".into(), issued.seconds.into());
    }
    if let Some(credentials) = credentials {
        if let Some(secret) = credentials.client_secret {
            body.insert("client_secret".into(), secret.into());
            // RFC 7591 §3.2.1: REQUIRED with a secret; 0 means it does not
            // expire.
            let expires = application
                .client_secret_expires_at
                .as_ref()
                .map_or(0, |at| at.seconds);
            body.insert("client_secret_expires_at".into(), expires.into());
        }
        body.insert(
            "registration_access_token".into(),
            credentials.registration_access_token.into(),
        );
    }
    body.insert(
        "registration_client_uri".into(),
        format!(
            "{}/oauth2/register/{}",
            application.issuer, application.client_id
        )
        .into(),
    );
    body.insert("client_name".into(), application.name.clone().into());
    body.insert(
        "redirect_uris".into(),
        application.redirect_uris.clone().into(),
    );
    body.insert("grant_types".into(), application.grant_types.clone().into());
    body.insert(
        "response_types".into(),
        application.response_types.clone().into(),
    );
    body.insert(
        "token_endpoint_auth_method".into(),
        auth_method_name(application.token_endpoint_auth_method()).into(),
    );
    let kind = match application.r#type() {
        ApplicationType::Native => "native",
        _ => "web",
    };
    body.insert("application_type".into(), kind.into());
    // Scoped issuers register only the issuer-relative public subject type.
    body.insert("subject_type".into(), "public".into());
    if !application.contacts.is_empty() {
        body.insert("contacts".into(), application.contacts.clone().into());
    }
    if !application.allowed_scopes.is_empty() {
        body.insert("scope".into(), application.allowed_scopes.join(" ").into());
    }
    if !application.post_logout_redirect_uris.is_empty() {
        body.insert(
            "post_logout_redirect_uris".into(),
            application.post_logout_redirect_uris.clone().into(),
        );
    }
    // Stored only in validated form, so it parses back to the registered set.
    if let Some(jwks) = application
        .jwks
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
    {
        body.insert("jwks".into(), jwks);
    }
    Value::Object(body)
}

#[cfg(test)]
mod tests;
