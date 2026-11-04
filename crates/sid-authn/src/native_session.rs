// SPDX-License-Identifier: AGPL-3.0-only
//! Native sessions renewed with refresh credentials bound to the application
//! instance's key (native_session.proto). A ceremony completion that proved
//! the key gets the session's first generation; a refresh presents one
//! credential of the current generation with a fresh proof and gets the next.
//! A retry of the same exchange inside the redelivery window gets that same
//! generation again; nothing branches. A copied credential without the key
//! rotates, discloses and ends nothing.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use prost::Message;
use sid_core::models::{
    AuditEntry, MutationContext, NATIVE_GENERATION_SIZE_MAX, NativeExchange, NativeGeneration,
    NativeRotation, NativeRotationOutcome, RevocationReason, Session, SessionEnd, SessionId,
    security_policy::SessionPolicy,
};
use sid_keys::KeyManager;
use sid_plugin::GrantStore;
use sid_proto::sid::v1::authn::NativeCredentialSet;
use zeroize::Zeroizing;

use crate::dpop::{DPopError, DPopValidator, NativeProofBinding};
use crate::oauth2::OAuth2Server;

/// Response metadata carrying a generation's [`NativeCredentialSet`].
pub const CREDENTIALS_METADATA: &str = "sid-native-credentials-bin";
/// Request metadata carrying a SID native proof.
pub const PROOF_METADATA: &str = "sid-native-proof";
/// Request metadata carrying the presented refresh credential.
pub const REFRESH_METADATA: &str = "sid-native-refresh";

/// Random bytes of one refresh credential.
const CREDENTIAL_BYTES: usize = 32;

/// How an issuer's session policy shapes native generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePolicy {
    generation_size: u32,
    redelivery_window: Duration,
}

/// A session policy whose native settings are out of bounds.
#[derive(Debug, thiserror::Error)]
#[error("native generation size {0} is outside 1..={NATIVE_GENERATION_SIZE_MAX}")]
pub struct NativePolicyError(u32);

impl NativePolicy {
    pub fn from_session_policy(policy: &SessionPolicy) -> Result<Self, NativePolicyError> {
        let size = policy.native_refresh_generation_size;
        if !(1..=NATIVE_GENERATION_SIZE_MAX).contains(&size) {
            return Err(NativePolicyError(size));
        }
        Ok(Self {
            generation_size: size,
            redelivery_window: Duration::from_secs(u64::from(
                policy.native_redelivery_window_seconds,
            )),
        })
    }
}

/// A generation as stored and as delivered: the store keeps only hashes.
struct NewGeneration {
    generation: NativeGeneration,
    set: NativeCredentialSet,
}

fn new_generation(
    session: &Session<impl Sized>,
    key_jkt: &str,
    policy: NativePolicy,
) -> NewGeneration {
    let now = chrono::Utc::now();
    let credentials: Vec<String> = (0..policy.generation_size)
        .map(|_| {
            let mut bytes = Zeroizing::new([0u8; CREDENTIAL_BYTES]);
            rand::Rng::fill_bytes(&mut rand::rng(), bytes.as_mut_slice());
            URL_SAFE_NO_PAD.encode(bytes.as_slice())
        })
        .collect();
    let generation = NativeGeneration {
        id: uuid::Uuid::now_v7(),
        session_id: session.id,
        key_jkt: key_jkt.to_owned(),
        credential_hashes: credentials
            .iter()
            .map(|c| OAuth2Server::hash_token(c))
            .collect(),
        // A credential never outlives its session.
        expires_at: session.expires_at,
        created_at: now,
    };
    let set = NativeCredentialSet {
        refresh_credentials: credentials,
        expires_in: (session.expires_at - now).num_seconds().max(0),
        redelivery_window: i64::try_from(policy.redelivery_window.as_secs())
            .expect("a policy window in seconds fits i64"),
    };
    NewGeneration { generation, set }
}

/// Why a native step was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    /// The proof does not verify, or binds something else.
    #[error("native proof refused: {0}")]
    Proof(#[from] DPopError),
    /// No generation holds the presented credential.
    #[error("unknown refresh credential")]
    UnknownCredential,
    /// The proof is by another key than the session's.
    #[error("the proof is not by the session's key")]
    KeyMismatch,
    /// The presented generation expired.
    #[error("refresh credential expired")]
    Expired,
    /// A retired credential presented with the session's key: the session
    /// ended under the reuse rule.
    #[error("refresh credential already used")]
    Reused,
    /// The session ended or expired.
    #[error("session ended")]
    Ended,
    /// The sealed result could not be sealed or opened.
    #[error("sealed result: {0}")]
    Sealing(String),
    #[error(transparent)]
    Storage(#[from] sid_core::Error),
}

/// The context a generation's sealed result is bound to: the generation it
/// rotated, so a result moved to another generation does not open.
fn sealing_context(presented: uuid::Uuid) -> String {
    format!("native-refresh:{}", presented.hyphenated())
}

/// Bind the session a ceremony just committed to the application key `jkt`
/// a verified ceremony proof named, and give it its first generation.
pub async fn issue<S>(
    store: &S,
    session: &Session<S::Owner>,
    key_jkt: &str,
    policy: NativePolicy,
) -> Result<NativeCredentialSet, NativeError>
where
    S: GrantStore + ?Sized,
{
    let first = new_generation(session, key_jkt, policy);
    store
        .issue_native_generation(
            &first.generation,
            AuditEntry::user(
                session.id.to_string(),
                "native_session.issue",
                first.generation.id.to_string(),
            )
            .into(),
        )
        .await?;
    Ok(first.set)
}

/// One verified refresh request: the proof as sent, the endpoint the client
/// called and what it presents.
pub struct RefreshRequest<'a> {
    pub proof: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub credential: &'a str,
    pub exchange: NativeExchange,
}

/// A refreshed (or redelivered) session and the generation to deliver.
pub struct Refreshed {
    pub session_id: SessionId,
    pub set: NativeCredentialSet,
}

/// Refresh a native session, or deliver again the generation this exchange
/// committed. The proof is verified and its key matched before any effect:
/// a credential presented without the session's key rotates nothing,
/// discloses nothing and ends nothing.
pub async fn refresh<S>(
    store: &S,
    keys: &dyn KeyManager,
    proofs: &DPopValidator,
    request: RefreshRequest<'_>,
    policy: NativePolicy,
) -> Result<Refreshed, NativeError>
where
    S: GrantStore + ?Sized,
{
    let presented = store
        .native_generation_by_credential(&OAuth2Server::hash_token(request.credential))
        .await?
        .ok_or(NativeError::UnknownCredential)?;
    let proved = proofs
        .validate_native(
            request.proof,
            request.method,
            request.url,
            NativeProofBinding::Refresh {
                credential: request.credential,
                exchange: &request.exchange,
            },
        )
        .await?;
    // A key thumbprint is public: an ordinary comparison discloses nothing.
    if proved.jkt != presented.key_jkt {
        return Err(NativeError::KeyMismatch);
    }
    if presented.expires_at <= chrono::Utc::now() {
        return Err(NativeError::Expired);
    }
    let session = store
        .get_session(presented.session_id)
        .await?
        .filter(|s| !s.is_expired())
        .ok_or(NativeError::Ended)?;

    let successor = new_generation(&session, &presented.key_jkt, policy);
    let context = sealing_context(presented.generation);
    let sealed = crate::sealed_secret::seal(keys, &context, &successor.set.encode_to_vec())
        .await
        .map_err(|e| NativeError::Sealing(e.to_string()))?;
    let window = chrono::Duration::from_std(policy.redelivery_window)
        .map_err(|e| NativeError::Sealing(format!("redelivery window: {e}")))?;
    let outcome = store
        .rotate_native_generation(
            NativeRotation {
                presented: presented.generation,
                exchange: request.exchange,
                successor: &successor.generation,
                sealed: &sealed,
                redeliver_until: chrono::Utc::now() + window,
            },
            AuditEntry::user(
                session.id.to_string(),
                "native_session.refresh",
                successor.generation.id.to_string(),
            )
            .into(),
        )
        .await?;
    match outcome {
        NativeRotationOutcome::Rotated => Ok(Refreshed {
            session_id: session.id,
            set: successor.set,
        }),
        NativeRotationOutcome::Redeliver(sealed) => {
            let opened = crate::sealed_secret::open(keys, &context, &sealed)
                .await
                .map_err(|e| NativeError::Sealing(e.to_string()))?;
            let set = NativeCredentialSet::decode(opened.secret.as_slice())
                .map_err(|e| NativeError::Sealing(format!("sealed generation: {e}")))?;
            Ok(Refreshed {
                session_id: session.id,
                set,
            })
        }
        NativeRotationOutcome::Retired => {
            // A retired credential with the session's own key: whoever holds
            // it is not the client alone. The session and what it
            // authenticated end; a failure to end it fails the request.
            store
                .delete_session(
                    session.id,
                    &SessionEnd::new(RevocationReason::AnomalyDetected, "system"),
                    MutationContext::from(AuditEntry::system(
                        "native_session.reuse",
                        session.id.to_string(),
                    )),
                )
                .await?;
            Err(NativeError::Reused)
        }
        NativeRotationOutcome::Ended => Err(NativeError::Ended),
    }
}

#[cfg(test)]
mod tests;
