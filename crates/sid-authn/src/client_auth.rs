// SPDX-License-Identifier: AGPL-3.0-only
//! How a token request authenticates its client (RFC 6749 §2.3): which method
//! it used and the credential it presented, before any lookup.

use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::SecretBox;
use sid_core::models::TokenEndpointAuthMethod;

use crate::client_assertion::JWT_BEARER_ASSERTION_TYPE;
use crate::oauth2::TokenError;

/// The client identity and credential a token request presents.
pub enum ClientAuthentication {
    /// A public client names itself and presents no credential (RFC 6749 §2.1).
    None { client_id: String },
    /// `client_secret_basic`: the `Authorization: Basic` header
    /// (RFC 6749 §2.3.1).
    Basic {
        client_id: String,
        secret: SecretBox<String>,
    },
    /// `client_secret_post`: the secret in the request body (RFC 6749 §2.3.1).
    Post {
        client_id: String,
        secret: SecretBox<String>,
    },
    /// `private_key_jwt`: a signed assertion (RFC 7523 §2.2).
    Assertion {
        client_id: String,
        assertion: String,
    },
}

impl ClientAuthentication {
    /// Read the client authentication of a token request from its
    /// `Authorization` header value and body parameters.
    ///
    /// A parameter sent with an empty value counts as omitted (RFC 6749 §3.2).
    /// An `Authorization` header with a scheme other than `Basic` is not a
    /// client credential and is ignored.
    pub fn from_request(
        authorization: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        client_assertion: Option<&str>,
        client_assertion_type: Option<&str>,
    ) -> Result<Self, TokenError> {
        let basic = authorization.and_then(basic_credentials);
        let client_id = present(client_id);
        let client_secret = present(client_secret);
        let client_assertion = present(client_assertion);

        // RFC 6749 §5.2 `invalid_request`: more than one mechanism for
        // authenticating the client.
        let methods = usize::from(basic.is_some())
            + usize::from(client_secret.is_some())
            + usize::from(client_assertion.is_some());
        if methods > 1 {
            return Err(TokenError::InvalidRequest);
        }

        if let Some(basic) = basic {
            let (id, secret) = basic?;
            // The body may repeat the client_id, never contradict it.
            if client_id.is_some_and(|body| body != id) {
                return Err(TokenError::InvalidRequest);
            }
            return Ok(Self::Basic {
                client_id: id,
                secret: SecretBox::new(Box::new(secret)),
            });
        }

        let client_id = client_id.ok_or(TokenError::InvalidRequest)?.to_owned();
        if let Some(assertion) = client_assertion {
            // RFC 7521 §4.2.1: an assertion that cannot authenticate the
            // client is `invalid_client`.
            if present(client_assertion_type) != Some(JWT_BEARER_ASSERTION_TYPE) {
                return Err(TokenError::InvalidClient);
            }
            return Ok(Self::Assertion {
                client_id,
                assertion: assertion.to_owned(),
            });
        }
        Ok(match client_secret {
            Some(secret) => Self::Post {
                client_id,
                secret: SecretBox::new(Box::new(secret.to_owned())),
            },
            None => Self::None { client_id },
        })
    }

    /// The client the request names.
    pub fn client_id(&self) -> &str {
        match self {
            Self::None { client_id }
            | Self::Basic { client_id, .. }
            | Self::Post { client_id, .. }
            | Self::Assertion { client_id, .. } => client_id,
        }
    }

    /// The method used, as a client registers it (RFC 7591 §2).
    pub fn method(&self) -> TokenEndpointAuthMethod {
        match self {
            Self::None { .. } => TokenEndpointAuthMethod::None,
            Self::Basic { .. } => TokenEndpointAuthMethod::ClientSecretBasic,
            Self::Post { .. } => TokenEndpointAuthMethod::ClientSecretPost,
            Self::Assertion { .. } => TokenEndpointAuthMethod::PrivateKeyJwt,
        }
    }

    /// The client secret, when the request presented one.
    pub fn secret(&self) -> Option<&SecretBox<String>> {
        match self {
            Self::Basic { secret, .. } | Self::Post { secret, .. } => Some(secret),
            Self::None { .. } | Self::Assertion { .. } => None,
        }
    }
}

/// A parameter value, `None` when omitted or empty.
fn present(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// The `(client_id, secret)` of a `Basic` authorization value, `None` for
/// another scheme, `Some(Err)` for a malformed one.
fn basic_credentials(authorization: &str) -> Option<Result<(String, String), TokenError>> {
    let (scheme, credentials) = authorization.split_once(' ')?;
    // RFC 9110 §11.1: the scheme name is case-insensitive.
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    Some(decode_basic(credentials.trim()).ok_or(TokenError::InvalidClient))
}

fn decode_basic(credentials: &str) -> Option<(String, String)> {
    let decoded = String::from_utf8(STANDARD.decode(credentials).ok()?).ok()?;
    // RFC 7617 §2: the user-id cannot contain a colon, the password can.
    let (id, secret) = decoded.split_once(':')?;
    // RFC 6749 §2.3.1: both are form-urlencoded before being joined.
    let id = form_decode(id)?;
    if id.is_empty() {
        return None;
    }
    Some((id, form_decode(secret)?))
}

/// Decode one `application/x-www-form-urlencoded` value: `+` is a space,
/// `%XX` a byte; a `%` not followed by two hex digits stays as it is
/// (WHATWG URL §5.1). `None` when the bytes are not UTF-8.
fn form_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => match (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            ) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
