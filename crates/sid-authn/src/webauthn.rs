// SPDX-License-Identifier: AGPL-3.0-only
//! WebAuthn / passkeys: the relying party side of registration and assertion
//! ceremonies, on `structured-webauthn`.
//!
//! A ceremony's state lives in the shared [`ChallengeStore`] under the
//! challenge the authenticator signs back, so a finish finds it from the
//! response alone, on any replica, once. Stored passkeys are versioned binary
//! records (see `record`), decoded strictly on every read.

mod record;
#[cfg(any(test, feature = "soft-authenticator"))]
pub mod soft_authenticator;

use crate::challenge_store::ChallengeStore;
use base64::Engine;
use core::borrow::Borrow;
use serde::{Deserialize, Serialize};
use sid_core::models::{Credential, CredentialId as SidCredentialId, WebAuthnUserHandle};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::KeyManager;
use sid_plugin::cache::CacheBackend;
use std::sync::Arc;
use std::time::Duration;
use structured_webauthn::bin::{Decode, Encode};
use structured_webauthn::request::auth::{AllowedCredentials, AuthenticationVerificationOptions};
use structured_webauthn::request::register::{
    CoseAlgorithmIdentifier, CoseAlgorithmIdentifiers, PublicKeyCredentialUserEntity16,
    RegistrationVerificationOptions, UserHandle16,
};
use structured_webauthn::request::{
    AsciiDomain, Credentials as _, PublicKeyCredentialDescriptor, RpId, UserVerificationRequirement,
};
use structured_webauthn::response::register::{Attestation, CompressedPubKeyOwned};
use structured_webauthn::response::{
    AuthenticatorAttachment, AuthenticatorTransport, Backup, CredentialId, SentChallenge,
};
use structured_webauthn::{
    AuthenticatedCredential16, CredentialCreationOptions16, DiscoverableAuthentication16,
    DiscoverableAuthenticationServerState, DiscoverableCredentialRequestOptions,
    NonDiscoverableAuthentication16, NonDiscoverableAuthenticationServerState,
    NonDiscoverableCredentialRequestOptions, Registration, RegistrationServerState16,
};
use url::Url;

/// Length of SID's user handles ([`WebAuthnUserHandle`]).
const USER_HANDLE_LEN: usize = 16;

/// Lifetime of a ceremony's server state.
const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// The signature algorithms SID accepts: ES256 and RS256. Another one, a
/// post-quantum one included, is enabled here by policy, never by what the
/// library can verify.
const ALGORITHMS: CoseAlgorithmIdentifiers = CoseAlgorithmIdentifiers::ALL
    .remove(CoseAlgorithmIdentifier::Mldsa87)
    .remove(CoseAlgorithmIdentifier::Mldsa65)
    .remove(CoseAlgorithmIdentifier::Mldsa44)
    .remove(CoseAlgorithmIdentifier::Eddsa)
    .remove(CoseAlgorithmIdentifier::Es384);

/// What a stored ceremony is for: a finish of another kind finds no state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Purpose {
    Registration,
    SignIn,
    StepUp,
    Discoverable,
}

/// What an assertion ceremony that names its account is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionPurpose {
    /// An identifier-first sign-in.
    SignIn,
    /// Step-up of an existing session.
    StepUp,
}

impl From<AssertionPurpose> for Purpose {
    fn from(p: AssertionPurpose) -> Self {
        match p {
            AssertionPurpose::SignIn => Self::SignIn,
            AssertionPurpose::StepUp => Self::StepUp,
        }
    }
}

/// A ceremony's server state as the shared store keeps it.
#[derive(Serialize, Deserialize)]
struct Pending {
    purpose: Purpose,
    state: Vec<u8>,
}

/// A started ceremony: the options for the browser and the key its state is
/// stored under.
pub struct CeremonyStart {
    /// `CredentialCreationOptions` / `CredentialRequestOptions` as JSON,
    /// `publicKey` inside (WebAuthn Level 3 §5.4, §5.5).
    pub options: Vec<u8>,
    /// The challenge, base64url: what the response's client data answers.
    pub state_key: String,
}

/// A newly registered passkey.
pub struct RegisteredPasskey {
    /// The record to store as the credential's data.
    pub data: Vec<u8>,
    /// The account handle the passkey was created for.
    pub user_handle: WebAuthnUserHandle,
}

/// A verified assertion and what it changes on the stored passkey.
#[derive(Debug)]
pub struct VerifiedAssertion {
    /// The stored passkey that made the assertion.
    pub credential: SidCredentialId,
    /// Its record with the new counter and backup state, when they changed.
    pub updated_data: Option<Vec<u8>>,
    /// Whether the authenticator verified the user in this ceremony.
    pub user_verified: bool,
    /// The RFC 8176 §2 method of the key: `hwk` or `swk`.
    pub key_amr: &'static str,
}

fn challenge_key(challenge: SentChallenge) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.0.to_le_bytes())
}

fn no_challenge() -> SidError {
    SidError::AuthenticationFailed("the response answers no challenge".into())
}

/// A registration response, `RegistrationResponseJSON` (WebAuthn Level 3
/// §5.1.4), parsed strictly.
pub struct RegistrationResponse(Registration);

impl RegistrationResponse {
    pub fn parse(json: &[u8]) -> SidResult<Self> {
        serde_json::from_slice(json)
            .map(Self)
            .map_err(|e| SidError::Validation(format!("not a WebAuthn registration response: {e}")))
    }

    /// The key of the ceremony this response answers.
    pub fn state_key(&self) -> SidResult<String> {
        self.0
            .challenge()
            .map(challenge_key)
            .map_err(|_| no_challenge())
    }
}

/// An assertion for a ceremony that named its account,
/// `AuthenticationResponseJSON` (WebAuthn Level 3 §5.1.4), parsed strictly.
pub struct AssertionResponse(NonDiscoverableAuthentication16);

impl AssertionResponse {
    pub fn parse(json: &[u8]) -> SidResult<Self> {
        serde_json::from_slice(json)
            .map(Self)
            .map_err(|e| SidError::Validation(format!("not a WebAuthn assertion: {e}")))
    }

    /// The key of the ceremony this response answers.
    pub fn state_key(&self) -> SidResult<String> {
        self.0
            .challenge()
            .map(challenge_key)
            .map_err(|_| no_challenge())
    }
}

/// An assertion of a discoverable credential: its user handle is required.
pub struct DiscoverableAssertionResponse(DiscoverableAuthentication16);

impl DiscoverableAssertionResponse {
    pub fn parse(json: &[u8]) -> SidResult<Self> {
        serde_json::from_slice(json)
            .map(Self)
            .map_err(|e| SidError::Validation(format!("not a WebAuthn assertion: {e}")))
    }

    /// The key of the ceremony this response answers.
    pub fn state_key(&self) -> SidResult<String> {
        self.0
            .challenge()
            .map(challenge_key)
            .map_err(|_| no_challenge())
    }

    /// The user handle the authenticator returned. It names an account only
    /// through the stored association, and authenticates nobody by itself.
    pub fn user_handle(&self) -> WebAuthnUserHandle {
        WebAuthnUserHandle(self.0.response().user_handle().into_array())
    }
}

/// WebAuthn relying party for passkey registration and assertion.
pub struct WebAuthnServer {
    rp_id: RpId,
    /// The one origin responses may come from, as its ASCII serialization.
    origin: String,
    ceremonies: ChallengeStore<Pending>,
}

impl WebAuthnServer {
    /// A relying party `rp_id` serving `rp_origin`, whose host must be the RP
    /// ID or a subdomain of it (WebAuthn Level 3 §5.1.4.1). `cache` and `keys`
    /// hold ceremony state shared between replicas and seal it there.
    pub fn new(
        rp_id: &str,
        rp_origin: &Url,
        cache: Arc<dyn CacheBackend>,
        keys: Arc<dyn KeyManager>,
    ) -> SidResult<Self> {
        let host = rp_origin
            .host_str()
            .ok_or_else(|| SidError::Validation(format!("RP origin {rp_origin} has no host")))?;
        if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
            return Err(SidError::Validation(format!(
                "RP origin {rp_origin} is not on RP ID {rp_id}"
            )));
        }
        let domain = AsciiDomain::try_from(rp_id.to_owned())
            .map_err(|e| SidError::Validation(format!("RP ID {rp_id}: {e}")))?;
        Ok(Self {
            rp_id: RpId::Domain(domain),
            origin: rp_origin.origin().ascii_serialization(),
            ceremonies: ChallengeStore::new(cache, keys, "webauthn", CEREMONY_TTL),
        })
    }

    /// The relying party ID: the scope of every user handle and credential.
    pub fn rp_id(&self) -> &str {
        self.rp_id.as_ref()
    }

    async fn store(&self, key: &str, purpose: Purpose, state: Vec<u8>) -> SidResult<()> {
        self.ceremonies
            .insert(key, &Pending { purpose, state })
            .await?;
        Ok(())
    }

    /// Take the state stored under `key` for `purpose`. Missing, expired,
    /// already taken or of another purpose: the ceremony fails.
    async fn take(&self, key: &str, purpose: Purpose) -> SidResult<Vec<u8>> {
        match self.ceremonies.take(key).await? {
            Some(pending) if pending.purpose == purpose => Ok(pending.state),
            _ => Err(SidError::AuthenticationFailed(
                "WebAuthn ceremony expired or not found".into(),
            )),
        }
    }

    /// Start registering a passkey for the account whose handle at this RP is
    /// `user_handle`. `existing` are its passkeys, excluded so an
    /// authenticator does not register twice.
    pub async fn registration_start(
        &self,
        user_handle: WebAuthnUserHandle,
        username: &str,
        existing: &[Credential],
    ) -> SidResult<CeremonyStart> {
        let handle = UserHandle16::decode(user_handle.0).unwrap_or_else(|never| match never {});
        let exclude = existing
            .iter()
            .map(|c| descriptor(c.data.expose()))
            .collect::<SidResult<Vec<_>>>()?;
        // A discoverable credential with user verification required
        // (WebAuthn Level 3 §5.4.4), so a sign-in that names no account
        // finds it.
        let mut options = CredentialCreationOptions16::passkey(
            &self.rp_id,
            PublicKeyCredentialUserEntity16 {
                name: username,
                id: &handle,
                display_name: username,
            },
            exclude,
        );
        options.public_key.pub_key_cred_params = ALGORITHMS;
        let (server, client) = options
            .start_ceremony()
            .map_err(|e| SidError::Internal(format!("WebAuthn registration options: {e}")))?;
        let options = serde_json::to_vec(&client)
            .map_err(|e| SidError::Internal(format!("WebAuthn registration options: {e}")))?;
        let state_key = challenge_key(*Borrow::<SentChallenge>::borrow(&server));
        let state = server
            .encode()
            .map_err(|e| SidError::Internal(format!("WebAuthn registration state: {e}")))?;
        self.store(&state_key, Purpose::Registration, state).await?;
        Ok(CeremonyStart { options, state_key })
    }

    /// Verify a registration response against the ceremony it answers
    /// (WebAuthn Level 3 §7.1) and return the record to store.
    pub async fn registration_finish(
        &self,
        response: &RegistrationResponse,
    ) -> SidResult<RegisteredPasskey> {
        let state = self
            .take(&response.state_key()?, Purpose::Registration)
            .await?;
        let server = RegistrationServerState16::decode(&state)
            .map_err(|e| SidError::Internal(format!("WebAuthn registration state: {e}")))?;
        let origins = [self.origin.as_str()];
        let options: RegistrationVerificationOptions<'_, '_, &str, &str> =
            RegistrationVerificationOptions {
                allowed_origins: &origins,
                ..RegistrationVerificationOptions::new()
            };
        let credential = server
            .verify(&self.rp_id, &response.0, &options)
            .map_err(|e| SidError::AuthenticationFailed(format!("passkey registration: {e}")))?;
        Ok(RegisteredPasskey {
            data: record::encode(&credential)?,
            user_handle: WebAuthnUserHandle(credential.user_id().into_array()),
        })
    }

    /// Start an assertion ceremony for an account whose `passkeys` are known.
    pub async fn authentication_start<'p>(
        &self,
        purpose: AssertionPurpose,
        passkeys: impl IntoIterator<Item = &'p Credential>,
    ) -> SidResult<CeremonyStart> {
        let allowed: AllowedCredentials = passkeys
            .into_iter()
            .map(|passkey| descriptor(passkey.data.expose()))
            .collect::<SidResult<Vec<_>>>()?
            .into();
        if allowed.len() == 0 {
            return Err(SidError::AuthenticationFailed(
                "no passkeys registered".into(),
            ));
        }
        let mut options =
            NonDiscoverableCredentialRequestOptions::second_factor(&self.rp_id, allowed);
        // A passkey signs in on its own, so the user is verified as at
        // registration (WebAuthn Level 3 §7.2 step 17).
        options.options.user_verification = UserVerificationRequirement::Required;
        let (server, client) = options
            .start_ceremony()
            .map_err(|e| SidError::Internal(format!("WebAuthn request options: {e}")))?;
        let options = serde_json::to_vec(&client)
            .map_err(|e| SidError::Internal(format!("WebAuthn request options: {e}")))?;
        let state_key = challenge_key(*Borrow::<SentChallenge>::borrow(&server));
        let state = server
            .encode()
            .map_err(|e| SidError::Internal(format!("WebAuthn assertion state: {e}")))?;
        self.store(&state_key, purpose.into(), state).await?;
        Ok(CeremonyStart { options, state_key })
    }

    /// Start a ceremony that names no account: the browser offers the
    /// discoverable credentials it holds for this RP.
    pub async fn discoverable_authentication_start(&self) -> SidResult<CeremonyStart> {
        let (server, client) = DiscoverableCredentialRequestOptions::passkey(&self.rp_id)
            .start_ceremony()
            .map_err(|e| SidError::Internal(format!("WebAuthn request options: {e}")))?;
        let options = serde_json::to_vec(&client)
            .map_err(|e| SidError::Internal(format!("WebAuthn request options: {e}")))?;
        let state_key = challenge_key(*Borrow::<SentChallenge>::borrow(&server));
        let state = server
            .encode()
            .map_err(|e| SidError::Internal(format!("WebAuthn assertion state: {e}")))?;
        self.store(&state_key, Purpose::Discoverable, state).await?;
        Ok(CeremonyStart { options, state_key })
    }

    /// Verify an assertion for a ceremony of `purpose` against the account's
    /// `passkeys` (WebAuthn Level 3 §7.2).
    pub async fn authentication_finish(
        &self,
        purpose: AssertionPurpose,
        response: &AssertionResponse,
        passkeys: &[Credential],
    ) -> SidResult<VerifiedAssertion> {
        let state = self.take(&response.state_key()?, purpose.into()).await?;
        let server = NonDiscoverableAuthenticationServerState::decode(&state)
            .map_err(|e| SidError::Internal(format!("WebAuthn assertion state: {e}")))?;
        let origins = [self.origin.as_str()];
        let options = assertion_options(&origins);
        verify_with(passkeys, response.0.raw_id(), None, |credential| {
            server.verify(&self.rp_id, &response.0, credential, &options)
        })
    }

    /// Verify a discoverable assertion. `user_handle` is the stored handle of
    /// the account the response's handle resolved to: the asserting passkey
    /// must belong to that account and carry that handle.
    pub async fn discoverable_authentication_finish(
        &self,
        response: &DiscoverableAssertionResponse,
        user_handle: WebAuthnUserHandle,
        passkeys: &[Credential],
    ) -> SidResult<VerifiedAssertion> {
        let state = self
            .take(&response.state_key()?, Purpose::Discoverable)
            .await?;
        let server = DiscoverableAuthenticationServerState::decode(&state)
            .map_err(|e| SidError::Internal(format!("WebAuthn assertion state: {e}")))?;
        let origins = [self.origin.as_str()];
        let options = assertion_options(&origins);
        verify_with(
            passkeys,
            response.0.raw_id(),
            Some(user_handle),
            |credential| server.verify(&self.rp_id, &response.0, credential, &options),
        )
    }
}

/// Assertion checks beyond the ceremony's own: responses from `origins`
/// only, the signature counter refused when it does not advance past a
/// positive stored value (WebAuthn Level 3 §7.2 step 22), backup state
/// recorded as reported.
fn assertion_options<'o>(
    origins: &'o [&'o str],
) -> AuthenticationVerificationOptions<'o, 'o, &'o str, &'o str> {
    AuthenticationVerificationOptions {
        allowed_origins: origins,
        ..AuthenticationVerificationOptions::new()
    }
}

/// The exclusion/allow-list descriptor of a stored passkey.
fn descriptor(data: &[u8]) -> SidResult<PublicKeyCredentialDescriptor<Box<[u8]>>> {
    let record = record::decode(data)?;
    Ok(PublicKeyCredentialDescriptor {
        id: owned_id(record.id)?,
        transports: record.transports,
    })
}

fn owned_id(id: CredentialId<&[u8]>) -> SidResult<CredentialId<Box<[u8]>>> {
    CredentialId::<Box<[u8]>>::decode(Box::from(id.as_ref()))
        .map_err(|e| SidError::Internal(format!("stored passkey id: {e}")))
}

/// Find the stored passkey `raw_id` names, check it carries `user_handle`
/// when one is required, and run `verify` on it.
fn verify_with(
    passkeys: &[Credential],
    raw_id: CredentialId<&[u8]>,
    user_handle: Option<WebAuthnUserHandle>,
    verify: impl FnOnce(
        &mut AuthenticatedCredential16<'_, '_, CompressedPubKeyOwned>,
    )
        -> Result<bool, structured_webauthn::response::auth::error::AuthCeremonyErr>,
) -> SidResult<VerifiedAssertion> {
    let mut found = None;
    for passkey in passkeys {
        let record = record::decode(passkey.data.expose())?;
        if record.id.as_ref() == raw_id.as_ref() {
            found = Some((passkey, record));
            break;
        }
    }
    let unknown = || SidError::AuthenticationFailed("the passkey is not the account's".into());
    let (passkey, record) = found.ok_or_else(unknown)?;
    if user_handle.is_some_and(|h| h.0 != record.user_handle) {
        return Err(unknown());
    }
    let handle = UserHandle16::decode(record.user_handle).unwrap_or_else(|never| match never {});
    let transports = record.transports;
    let dynamic_at = record.dynamic_at;
    let mut credential = AuthenticatedCredential16::new(
        record.id,
        &handle,
        record.static_state,
        record.dynamic_state,
    )
    .map_err(|e| SidError::Internal(format!("stored passkey: {e}")))?;
    let changed = verify(&mut credential)
        .map_err(|e| SidError::AuthenticationFailed(format!("passkey assertion: {e}")))?;
    let dynamic = credential.dynamic_state();
    Ok(VerifiedAssertion {
        credential: passkey.id,
        updated_data: if changed {
            Some(record::with_dynamic_state(
                passkey.data.expose(),
                dynamic_at,
                dynamic,
            ))
        } else {
            None
        },
        // Every SID ceremony requires user verification, and the library
        // refuses an assertion without the UV flag then (WebAuthn Level 3
        // §7.2 step 17).
        user_verified: true,
        key_amr: method_of(transports, dynamic.backup),
    })
}

/// The RFC 8176 §2 method a sign-in with a passkey records: `hwk` only with
/// evidence the key is hardware-bound (not backup eligible, so it never
/// leaves the authenticator, and reached as a roaming authenticator over
/// USB, NFC or BLE); `swk` otherwise, including a synced passkey and one
/// whose authenticator reported no transports.
fn method_of(
    transports: structured_webauthn::response::AuthTransports,
    backup: Backup,
) -> &'static str {
    let roaming = [
        AuthenticatorTransport::Usb,
        AuthenticatorTransport::Nfc,
        AuthenticatorTransport::Ble,
    ]
    .into_iter()
    .filter(|t| transports.contains(*t))
    .count();
    let only_roaming = !transports.is_empty() && u32::try_from(roaming) == Ok(transports.count());
    if matches!(backup, Backup::NotEligible) && only_roaming {
        "hwk"
    } else {
        "swk"
    }
}

/// How a passkey reaches its authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyTransport {
    Usb,
    Nfc,
    Ble,
    SmartCard,
    Hybrid,
    Internal,
}

/// Where the authenticator sits relative to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyAttachment {
    Unknown,
    Platform,
    CrossPlatform,
}

/// Display-safe facts about a stored passkey; no key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub transports: Vec<PasskeyTransport>,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub attachment: PasskeyAttachment,
    /// The attestation statement format: `none` or `packed` (self). CE
    /// stores it and verifies no attestation chain.
    pub attestation_format: &'static str,
    /// Whether the user was verified when the passkey was registered.
    pub user_verified: bool,
    /// The RFC 8176 §2 method a sign-in with it records.
    pub key_amr: &'static str,
}

/// What a stored passkey shows about itself.
pub fn passkey_info(data: &[u8]) -> SidResult<PasskeyInfo> {
    let record = record::decode(data)?;
    let dynamic = record.dynamic_state;
    let transports = [
        (AuthenticatorTransport::Usb, PasskeyTransport::Usb),
        (AuthenticatorTransport::Nfc, PasskeyTransport::Nfc),
        (AuthenticatorTransport::Ble, PasskeyTransport::Ble),
        (
            AuthenticatorTransport::SmartCard,
            PasskeyTransport::SmartCard,
        ),
        (AuthenticatorTransport::Hybrid, PasskeyTransport::Hybrid),
        (AuthenticatorTransport::Internal, PasskeyTransport::Internal),
    ]
    .into_iter()
    .filter(|(t, _)| record.transports.contains(*t))
    .map(|(_, t)| t)
    .collect();
    Ok(PasskeyInfo {
        transports,
        backup_eligible: !matches!(dynamic.backup, Backup::NotEligible),
        backed_up: matches!(dynamic.backup, Backup::Exists),
        attachment: match dynamic.authenticator_attachment {
            AuthenticatorAttachment::None => PasskeyAttachment::Unknown,
            AuthenticatorAttachment::Platform => PasskeyAttachment::Platform,
            AuthenticatorAttachment::CrossPlatform => PasskeyAttachment::CrossPlatform,
        },
        attestation_format: match record.metadata.attestation {
            Attestation::None => "none",
            Attestation::Surrogate => "packed",
        },
        // With `update_uv` off the library never changes this after
        // registration, so it is the registration's UV.
        user_verified: dynamic.user_verified,
        key_amr: method_of(record.transports, dynamic.backup),
    })
}

/// The id a stored passkey is known by to authenticators.
pub fn passkey_credential_id(data: &[u8]) -> SidResult<Vec<u8>> {
    Ok(record::decode(data)?.id.as_ref().to_vec())
}

#[cfg(test)]
mod tests;
