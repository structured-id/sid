// SPDX-License-Identifier: AGPL-3.0-only
//! A sign-in or ceremony operation over gRPC: which client a request is,
//! from its `Origin` metadata; the context and the session credential put
//! into response metadata, marked sensitive; and a later step's context read
//! back from the request. The decisions are the cores'
//! ([`sid_authn::sign_in_delivery`], [`sid_authn::ceremony_context`]).

use chrono::{DateTime, Utc};
use sid_authn::browser_session::{BrowserCookie, BrowserSecret, CSRF_HEADER};
use sid_authn::ceremony_context::{CeremonyBinding, CeremonyContext, CeremonyRefusal};
use sid_authn::sign_in_delivery::{self, CeremonyClient, Delivery, NotSignInPage, SignedIn};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Response, Status};

use crate::grpc_error::refuse::internal;
use crate::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};

impl IntoStatus for NotSignInPage {
    fn into_status(self) -> Status {
        ApiError::new(ErrorReason::SignInRefused, self.to_string()).into()
    }
}

impl IntoStatus for CeremonyRefusal {
    fn into_status(self) -> Status {
        let reason = match self {
            CeremonyRefusal::NotHeld => ErrorReason::TokenInvalid,
            CeremonyRefusal::Csrf => ErrorReason::InsufficientPermissions,
        };
        ApiError::new(reason, self.to_string()).into()
    }
}

/// Who completes a sign-in ceremony sent with `metadata` (see
/// [`sign_in_delivery::ceremony_client`]).
#[allow(clippy::result_large_err)]
pub fn ceremony_client(
    metadata: &MetadataMap,
    sign_in_origin: Option<&url::Origin>,
) -> Result<CeremonyClient, Status> {
    let origins = metadata.get_all("origin").iter().map(|v| v.to_str().ok());
    sign_in_delivery::ceremony_client(origins, sign_in_origin).or_status()
}

/// Put `context` into the start's response `metadata` (see
/// [`CeremonyContext::headers`]).
#[allow(clippy::result_large_err)]
pub fn deliver_context(
    context: CeremonyContext,
    cookie: &BrowserCookie,
    expires_at: DateTime<Utc>,
    metadata: &mut MetadataMap,
) -> Result<(), Status> {
    for (name, value) in context.headers(cookie, expires_at) {
        insert(metadata, name, value, "encode ceremony context")?;
    }
    Ok(())
}

/// Whether the request with `metadata` continues the operation `binding`
/// names: its client by the sign-in page's Origin, then its context by the
/// transaction `cookie` and CSRF token, or by the bearer secret.
#[allow(clippy::result_large_err)]
pub fn admit(
    binding: &CeremonyBinding,
    metadata: &MetadataMap,
    cookie: &BrowserCookie,
    sign_in_origin: Option<&url::Origin>,
) -> Result<(), Status> {
    let client = ceremony_client(metadata, sign_in_origin)?;
    let values = |name| {
        metadata
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
    };
    let secret = match client {
        CeremonyClient::Browser => cookie.secret(values("cookie")),
        CeremonyClient::Native => bearer(metadata),
    };
    binding
        .admit(client, secret, values(CSRF_HEADER))
        .or_status()
}

/// The secret of the single `authorization: Bearer` value in `metadata`.
/// Two values are ambiguous and present none (RFC 9110 §11.6.2 allows one).
fn bearer(metadata: &MetadataMap) -> Option<BrowserSecret> {
    let mut values = metadata.get_all("authorization").iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let (scheme, secret) = value.to_str().ok()?.split_once(' ')?;
    // RFC 9110 §11.1: the auth-scheme is case-insensitive.
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    BrowserSecret::decode(secret.trim())
}

/// A session's credential put into gRPC response metadata.
pub trait Deliver {
    /// Put the credential into `metadata` (see [`Delivery::header`]).
    #[allow(clippy::result_large_err)]
    fn deliver(self, metadata: &mut MetadataMap) -> Result<(), Status>;
}

impl Deliver for Delivery {
    fn deliver(self, metadata: &mut MetadataMap) -> Result<(), Status> {
        let (name, value, refresh) = self.header();
        insert(metadata, name, value, "encode session credential")?;
        if let Some(refresh) = refresh {
            let mut value = MetadataValue::from_bytes(&refresh);
            value.set_sensitive(true);
            metadata.insert_bin(sid_authn::native_session::CREDENTIALS_METADATA, value);
        }
        Ok(())
    }
}

/// A sign-in ceremony's answer over gRPC.
pub trait Respond {
    /// The ceremony's answer `message` builds from the session id and the
    /// credential's lifetime, its credential in the response metadata.
    #[allow(clippy::result_large_err)]
    fn respond<T>(
        self,
        message: impl FnOnce(sid_ids::SessionId, i64) -> T,
    ) -> Result<Response<T>, Status>;
}

impl Respond for SignedIn {
    fn respond<T>(
        self,
        message: impl FnOnce(sid_ids::SessionId, i64) -> T,
    ) -> Result<Response<T>, Status> {
        let mut response = Response::new(message(self.session_id, self.expires_in));
        self.delivery.deliver(response.metadata_mut())?;
        Ok(response)
    }
}

#[allow(clippy::result_large_err)]
fn insert(
    metadata: &mut MetadataMap,
    name: &'static str,
    value: String,
    what: &'static str,
) -> Result<(), Status> {
    let mut value: MetadataValue<_> = value.parse().map_err(|e| internal(what, e))?;
    // A live secret or its CSRF token: kept out of debug output and HPACK
    // indexing.
    value.set_sensitive(true);
    metadata.insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests;
