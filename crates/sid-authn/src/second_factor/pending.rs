// SPDX-License-Identifier: AGPL-3.0-only
//! A sign-in's pending second-factor context, for any authenticated account
//! type: the credential its first factor proved, its completion into a full
//! session once a second factor verified, and the redelivery of a committed
//! completion to the same context after a lost response. The host commits
//! and delivers the session as every one of its sign-ins does; this module
//! decides what a completion may commit and what may be delivered again.

use async_trait::async_trait;
use chrono::Utc;
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    ActorFence, BrowserSecretHash, Credential, CredentialFence, OperationKey, RevocationReason,
    Session, SessionEnd, SessionId,
};
use sid_keys::KeyManager;
use sid_plugin::{CredentialStore, GrantStore, OperationResultStore};

use super::{FactorOwner, FactorSpend};
use crate::browser_session::{BrowserCookie, BrowserCsrf};
use crate::challenge_store::{ChallengeStore, ChallengeStoreError};
use crate::login_policy::{LoginDecision, LoginRequirements, Unmet};
use crate::sealed_secret::SealedSecretError;
use crate::sign_in_delivery::{CeremonyClient, RetainedDelivery, SignedIn};

/// The namespace of second-factor completions, whose results are their
/// deliveries sealed for a lost response.
pub const SECOND_FACTOR_NAMESPACE: &str = "second-factor-sign-in";

/// The method a second-factor completion records.
pub const SECOND_FACTOR_METHOD: &str = "complete_second_factor";

/// Why a pending context's step gave no result.
#[derive(Debug, thiserror::Error)]
pub enum PendingError {
    /// The pending context, or the session a completion delivered, has
    /// ended.
    #[error("the sign-in has ended")]
    SessionEnded,
    /// The credential the first factor proved changed, or the context ended
    /// under a concurrent completion: nothing commits, the sign-in starts
    /// again.
    #[error("the sign-in's proof or context changed")]
    Fenced,
    /// The completed authentication does not meet the requirements in force.
    #[error("a step-up is required: {0:?}")]
    StepUp(Unmet),
    /// The account no longer signs in, or a completion of this context was
    /// presented by another client; one answer whatever the reason.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// A retained delivery could not be sealed or opened.
    #[error("retained delivery: {0}")]
    Sealed(#[from] SealedSecretError),
    /// A name this module builds was refused.
    #[error("{0}")]
    Internal(String),
    #[error(transparent)]
    State(#[from] ChallengeStoreError),
    #[error("store: {0}")]
    Store(#[from] sid_core::Error),
}

/// The credential a pending context's first factor proved: its id and the
/// SHA-256 of the data it held then.
#[derive(serde::Serialize, serde::Deserialize)]
struct FirstFactorProof {
    credential: uuid::Uuid,
    digest: [u8; 32],
}

impl FirstFactorProof {
    fn of(fence: &CredentialFence) -> Self {
        use sha2::Digest;
        Self {
            credential: fence.id.0,
            digest: sha2::Sha256::digest(fence.data.expose()).into(),
        }
    }

    /// Whether `credential` is the one proved, holding the same data.
    fn proves<O>(&self, credential: &Credential<O>) -> bool {
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(credential.data.expose()).into();
        credential.id.0 == self.credential && digest == self.digest
    }
}

/// The credential each pending context's first factor proved, keyed by the
/// context: its completion commits only while that credential is unchanged.
pub struct FirstFactorProofs(ChallengeStore<Option<FirstFactorProof>>);

impl FirstFactorProofs {
    pub fn new(
        ceremonies: std::sync::Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: std::sync::Arc<dyn KeyManager>,
        ttl: std::time::Duration,
    ) -> Self {
        Self(ChallengeStore::new(
            ceremonies,
            keys,
            "first-factor-proof",
            ttl,
        ))
    }

    /// Keep what `pending`'s first factor proved for as long as the context
    /// lives; `false` when it could not be kept, and the context must not be
    /// delivered (a completion that finds none completes nothing).
    pub async fn keep<O>(
        &self,
        pending: &Session<O>,
        proved_by: Option<&CredentialFence>,
    ) -> Result<bool, PendingError> {
        Ok(self
            .0
            .insert_until(
                &pending.id.to_string(),
                &proved_by.map(FirstFactorProof::of),
                pending.expires_at,
            )
            .await?)
    }

    /// The credential `pending`'s first factor proved, while it still holds
    /// in `credentials`: it commits with what the context completes, as in a
    /// sign-in that needs no second factor. One replaced or revoked since
    /// completes nothing (`Fenced`), and a context whose proof is gone has
    /// ended.
    pub async fn fence<O: Copy + Send + Sync>(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        pending: &Session<O>,
    ) -> Result<Option<CredentialFence>, PendingError> {
        let proof = self
            .0
            .read(&pending.id.to_string())
            .await?
            .ok_or(PendingError::SessionEnded)?;
        let Some(proof) = proof else {
            return Ok(None);
        };
        let credential = credentials
            .get_credentials_by_profile(pending.profile_id, None)
            .await?
            .into_iter()
            .find(|c| c.status.is_active() && proof.proves(c))
            .ok_or(PendingError::Fenced)?;
        Ok(Some(CredentialFence {
            id: credential.id,
            data: credential.data,
        }))
    }
}

/// A pending second-factor context as its client proves it, whether or not
/// it has completed: the context names the completion whose result a retry
/// after a lost response receives, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompletedContext {
    /// The sign-in page's context: the hash of its cookie's secret and the
    /// CSRF token it was given (both checked by the browser adapter).
    Browser {
        secret: BrowserSecretHash,
        csrf: String,
    },
    /// A native client's context and the application key a fresh proof of
    /// this request bound to it, when the client proves one.
    Native {
        pending: SessionId,
        key: Option<String>,
    },
}

impl CompletedContext {
    /// The context `client` completes `pending` from, with the key
    /// `native_key` a native client proved; `None` for a browser context
    /// that holds no cookie binding.
    pub fn of<O>(
        pending: &Session<O>,
        client: CeremonyClient,
        native_key: Option<&str>,
    ) -> Option<Self> {
        match client {
            CeremonyClient::Browser => Some(Self::Browser {
                secret: pending.browser_secret_hash?,
                csrf: pending.browser_csrf.as_ref().map(BrowserCsrf::encode)?,
            }),
            CeremonyClient::Native => Some(Self::Native {
                pending: pending.id,
                key: native_key.map(str::to_owned),
            }),
        }
    }

    /// The key of the completion this context names.
    fn key(&self) -> Result<OperationKey, PendingError> {
        let key = match self {
            Self::Browser { secret, .. } => format!("browser:{}", hex::encode(secret.as_bytes())),
            Self::Native { pending, .. } => format!("native:{pending}"),
        };
        OperationKey::parse(&key)
            .map_err(|e| PendingError::Internal(format!("name a second-factor completion: {e}")))
    }

    /// What a retry must present again: the CSRF token a browser context
    /// was given, the application key a native client proved.
    fn inputs(&self) -> Vec<u8> {
        match self {
            Self::Browser { csrf, .. } => csrf.as_bytes().to_vec(),
            Self::Native { key, .. } => key.as_deref().unwrap_or_default().as_bytes().to_vec(),
        }
    }
}

/// The keyed completion a session commits with: its delivery sealed for a
/// lost response, redelivered to the same context and to no other.
pub struct RetainedCompletion {
    pub namespace: &'static str,
    pub method: &'static str,
    pub completion_key: OperationKey,
    /// The sealing context: this completion at this issuer.
    pub context: String,
    /// The end of the completion's redelivery.
    pub deadline: chrono::DateTime<Utc>,
    /// What a retry must present again.
    pub inputs: Vec<u8>,
}

/// What the host commits: `session` completing `pending`, which ends with
/// `end` in the same commit, spending `spend`, while `proved_by` and
/// `policy` still hold, with `retained`'s completion when given.
pub struct Completion<'a, O> {
    pub pending: &'a Session<O>,
    pub end: SessionEnd,
    pub session: Session<O>,
    pub client: CeremonyClient,
    pub native_key: Option<&'a str>,
    pub proved_by: Option<CredentialFence>,
    pub policy: Option<ActorFence>,
    pub spend: Option<FactorSpend>,
    pub retained: Option<RetainedCompletion>,
}

/// Why the host's commit of a completion gave no session.
pub enum CommitError<E> {
    /// The pending context ended, under a concurrent completion among
    /// others, or the proof or policy it commits under changed.
    Fenced,
    /// Any other refusal or failure, returned as is.
    Other(E),
}

impl<E> From<E> for CommitError<E> {
    fn from(e: E) -> Self {
        Self::Other(e)
    }
}

/// What a pending-context host supplies. One value serves one request.
#[async_trait]
pub trait PendingSignInHost: Send + Sync {
    /// The account a sign-in authenticates.
    type Owner: FactorOwner;
    /// A refusal or failure of the host, returned as is.
    type Error: Send + From<PendingError>;

    fn credentials(&self) -> &dyn CredentialStore<Owner = Self::Owner>;
    fn grants(&self) -> &dyn GrantStore<Owner = Self::Owner>;
    fn operations(&self) -> &dyn OperationResultStore;
    fn keys(&self) -> &dyn KeyManager;
    fn cookie(&self) -> &BrowserCookie;
    fn proofs(&self) -> &FirstFactorProofs;
    /// The issuer completions are sealed to.
    fn issuer(&self) -> &str;

    /// The login requirements in force for `owner` now, with the protection
    /// its credentials establish.
    async fn requirements(&self, owner: Self::Owner) -> Result<LoginRequirements, Self::Error>;

    /// Whether `owner` may still sign in.
    async fn can_sign_in(&self, owner: Self::Owner) -> Result<bool, Self::Error>;

    /// A full session of `owner` from `ip_address`, of this authority's
    /// lifetime and scopes; its authentication is the caller's to set.
    fn new_session(
        &self,
        owner: Self::Owner,
        ip_address: Option<std::net::IpAddr>,
    ) -> Session<Self::Owner>;

    /// Commit `completion` and deliver its session's credential to its
    /// client, as every sign-in of this authority is committed and
    /// delivered.
    async fn commit(
        &self,
        completion: Completion<'_, Self::Owner>,
    ) -> Result<SignedIn, CommitError<Self::Error>>;

    /// Whether the bearer credential `delivery` retained for `session` may
    /// be handed out again: its access token not replaced and stopped, its
    /// first refresh generation still the session's current one.
    async fn bearer_deliverable(
        &self,
        delivery: &RetainedDelivery,
        session: &Session<Self::Owner>,
    ) -> Result<bool, Self::Error>;

    /// Record `owner`'s completed sign-in from `ip_address` as evidence for
    /// later sign-ins.
    async fn record_completed(&self, owner: Self::Owner, ip_address: Option<std::net::IpAddr>);
}

/// The requirements in force now for `pending`'s account when `pending`
/// completed by the second factor `method` would meet them; the step-up they
/// ask otherwise. A factor spent on the completion is checked here before it
/// is spent.
pub async fn second_factor_requirements<H: PendingSignInHost>(
    host: &H,
    pending: &Session<H::Owner>,
    method: &str,
) -> Result<LoginRequirements, H::Error> {
    let now = Utc::now();
    let requirements = host.requirements(pending.profile_id).await?;
    if !requirements.met_with(pending, AuthLevel::Standard, method, now) {
        let mut completed = pending.clone();
        completed.assurance_level = completed.assurance_level.max(AuthLevel::Standard);
        completed.amr.push(method.to_string());
        return Err(PendingError::StepUp(requirements.unmet(&completed, now)).into());
    }
    Ok(requirements)
}

/// The credential `pending`'s first factor proved, while it still holds.
pub async fn first_factor_fence<H: PendingSignInHost>(
    host: &H,
    pending: &Session<H::Owner>,
) -> Result<Option<CredentialFence>, H::Error> {
    Ok(host.proofs().fence(host.credentials(), pending).await?)
}

/// `pending` as it stands now when it is still a live context of its
/// account; otherwise the context `client` proves, which may only receive
/// again the sign-in its completion committed.
pub async fn live_pending<O: PartialEq + Send + Sync>(
    grants: &dyn GrantStore<Owner = O>,
    pending: Session<O>,
    client: CeremonyClient,
    native_key: Option<&str>,
) -> Result<Result<Session<O>, CompletedContext>, PendingError> {
    let live = grants.get_session(pending.id).await?.filter(|s| {
        s.profile_id == pending.profile_id && s.awaits_second_factor() && !s.is_expired()
    });
    match live {
        Some(live) => Ok(Ok(live)),
        None => CompletedContext::of(&pending, client, native_key)
            .map(Err)
            .ok_or(PendingError::SessionEnded),
    }
}

/// The sealing context of a completion's delivery: the completion
/// `completed` names at `issuer`.
fn sealing_context(issuer: &str, completed: &CompletedContext) -> Result<String, PendingError> {
    Ok(format!(
        "second-factor-sign-in:{}:{}",
        issuer,
        completed.key()?.as_str()
    ))
}

/// Complete `pending` with the verified second factor `method` (RFC 8176):
/// the requirements in force now are met by the completed authentication,
/// the first factor's credential still holds, the pending context ends
/// exactly once and the account gets its session with a new credential,
/// delivered to `client` (with the refresh generation bound to `native_key`
/// when it proved one); the factor's `spend` commits with that session or
/// not at all. A completion that loses to a concurrent one of the same
/// context is answered with the one that committed.
pub async fn complete_second_factor<H: PendingSignInHost>(
    host: &H,
    pending: Session<H::Owner>,
    method: &str,
    client: CeremonyClient,
    native_key: Option<&str>,
    spend: Option<FactorSpend>,
) -> Result<SignedIn, H::Error> {
    let owner = pending.profile_id;
    if !host.can_sign_in(owner).await? {
        return Err(PendingError::AuthenticationFailed.into());
    }
    // The delivery commits with the session, sealed to the context the
    // client completed from, and is kept while either may still be used: a
    // retry of that context after a lost response receives it again.
    let completed = CompletedContext::of(&pending, client, native_key);
    let mut spend = spend;
    let mut decided_again = false;
    loop {
        let requirements = second_factor_requirements(host, &pending, method).await?;
        // The last attempt spends the factor itself; an earlier one a copy.
        let attempt_spend = if decided_again {
            spend.take()
        } else {
            spend.clone()
        };
        match commit_completion(
            host,
            &pending,
            method,
            client,
            native_key,
            &requirements,
            attempt_spend,
            completed.as_ref(),
        )
        .await?
        {
            Some(signed_in) => {
                // Recorded from the address the rules judged at the first factor.
                host.record_completed(owner, pending.ip_address).await;
                return Ok(signed_in);
            }
            None => {
                // A concurrent completion of this context committed first.
                if let Some(completed) = &completed
                    && let Some(signed_in) = redeliver_second_factor(host, completed).await?
                {
                    return Ok(signed_in);
                }
                // A policy written after the decision fenced the commit: the
                // completion is decided once more under the policy in force
                // now, which refuses it with its own reason or fences it again.
                if decided_again || host.requirements(owner).await?.fence == requirements.fence {
                    return Err(PendingError::Fenced.into());
                }
                decided_again = true;
            }
        }
    }
}

/// Commit `pending` completed by `method` under `requirements` with `spend`;
/// `None` when a fence stopped the commit.
#[allow(clippy::too_many_arguments)]
async fn commit_completion<H: PendingSignInHost>(
    host: &H,
    pending: &Session<H::Owner>,
    method: &str,
    client: CeremonyClient,
    native_key: Option<&str>,
    requirements: &LoginRequirements,
    spend: Option<FactorSpend>,
    completed: Option<&CompletedContext>,
) -> Result<Option<SignedIn>, H::Error> {
    let owner = pending.profile_id;
    let proved_by = first_factor_fence(host, pending).await?;

    let mut session = host.new_session(owner, pending.ip_address);
    session.device_id = pending.device_id;
    session.user_agent = pending.user_agent.clone();
    session.assurance_level = pending.assurance_level.max(AuthLevel::Standard);
    session.amr = pending.amr.clone();
    if !session.amr.iter().any(|m| m == method) {
        session.amr.push(method.to_string());
    }
    // The authentication began with the first factor.
    session.authenticated_at = pending.authenticated_at;
    let retained = match completed {
        Some(completed) => Some(RetainedCompletion {
            namespace: SECOND_FACTOR_NAMESPACE,
            method: SECOND_FACTOR_METHOD,
            completion_key: completed.key()?,
            context: sealing_context(host.issuer(), completed)?,
            deadline: pending.expires_at.min(session.expires_at),
            inputs: completed.inputs(),
        }),
        None => None,
    };
    // The pending context ends in the session's own commit: of concurrent
    // completions one signs in, and one ended meanwhile completes nothing
    // more; it is answered with the completion that committed.
    match host
        .commit(Completion {
            pending,
            end: SessionEnd::new(RevocationReason::SignInCompleted, owner.to_string()),
            session,
            client,
            native_key,
            proved_by,
            policy: requirements.fence,
            spend,
            retained,
        })
        .await
    {
        Ok(signed_in) => Ok(Some(signed_in)),
        Err(CommitError::Other(e)) => Err(e),
        Err(CommitError::Fenced) => Ok(None),
    }
}

/// The sign-in the second factor of `completed` already completed,
/// delivered again to that context after a lost response: the same session
/// and credential, with no further effect. `None` when no completion of
/// that context committed, or it is no longer kept. A completion of another
/// context, an ended or expired session, an account that can no longer sign
/// in, requirements the session no longer meets, or a bearer credential the
/// host no longer hands out deliver nothing.
pub async fn redeliver_second_factor<H: PendingSignInHost>(
    host: &H,
    completed: &CompletedContext,
) -> Result<Option<SignedIn>, H::Error> {
    let Some(record) = host
        .operations()
        .get_operation_result(SECOND_FACTOR_NAMESPACE, &completed.key()?)
        .await
        .map_err(PendingError::from)?
    else {
        return Ok(None);
    };
    // A completion of this context presented with another CSRF token or
    // proved by another key is not this client's.
    if !record.matches(SECOND_FACTOR_METHOD, &completed.inputs(), None) {
        return Err(PendingError::AuthenticationFailed.into());
    }
    let delivery = RetainedDelivery::open(
        host.keys(),
        &sealing_context(host.issuer(), completed)?,
        &record.completion.result,
    )
    .await
    .map_err(PendingError::from)?;
    if delivery.deadline <= Utc::now() {
        return Ok(None);
    }
    let ended = || -> H::Error { PendingError::SessionEnded.into() };
    let session = host
        .grants()
        .get_session(delivery.session_id)
        .await
        .map_err(PendingError::from)?
        .filter(|session| !session.is_expired())
        .ok_or_else(ended)?;
    if !host.can_sign_in(session.profile_id).await? {
        return Err(ended());
    }
    let requirements = host.requirements(session.profile_id).await?;
    if let LoginDecision::StepUp(unmet) = requirements.decide(&session, Utc::now()) {
        return Err(PendingError::StepUp(unmet).into());
    }
    if delivery.bearer_token().is_some() && !host.bearer_deliverable(&delivery, &session).await? {
        return Err(ended());
    }
    delivery
        .signed_in(host.cookie(), &session)
        .map(Some)
        .ok_or_else(ended)
}

#[cfg(test)]
mod tests;
