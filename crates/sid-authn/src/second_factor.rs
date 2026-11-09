// SPDX-License-Identifier: AGPL-3.0-only
//! Second factors of any authenticated account type: enrolling a TOTP
//! authenticator with its recovery codes, accepting a TOTP code once,
//! spending a recovery code with the effect it pays for, and the factors a
//! sign-in owing one offers. The host keeps its accounts, sessions and the
//! authority to bind a factor; this module keeps the ceremonies and the
//! credential transitions, the same for every authority.

use std::fmt::Display;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sid_core::models::event::{Event, event_types};
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialId, CredentialRevocation, CredentialSpend,
    CredentialType, MutationContext, NewWork, OperationCompletion, Session,
};
use sid_keys::KeyManager;
use sid_plugin::{CredentialStore, OperationResultStore};
use sid_proto::sid::v1::{
    DeleteMfaCredentialResponse, StepUpMethod, TotpAlgorithm, TotpEnrollmentChallenge,
};

use crate::challenge_store::{ChallengeStore, ChallengeStoreError};
use crate::login_policy::LoginRequirements;
use crate::operation::{KeyedCommand, OperationError};
use crate::sealed_secret::{Opened, SealedSecretError};

pub mod pending;

/// The method a recovery code records: RFC 8176 `mca`, a multiple-channel
/// authenticator.
pub const RECOVERY_CODE_AMR: &str = "mca";

/// The method a TOTP code records (RFC 8176 `otp`).
pub const TOTP_AMR: &str = "otp";

/// How long a started enrollment may be finished.
const CEREMONY_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The account a second factor belongs to.
pub trait FactorOwner:
    Copy + Eq + Display + Into<uuid::Uuid> + Serialize + DeserializeOwned + Send + Sync + 'static
{
}

impl<T> FactorOwner for T where
    T: Copy
        + Eq
        + Display
        + Into<uuid::Uuid>
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static
{
}

/// Why a second-factor step gave no result.
#[derive(Debug, thiserror::Error)]
pub enum FactorError {
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// A TOTP authenticator is already enrolled.
    #[error("a TOTP authenticator is already enrolled")]
    AlreadyEnrolled,
    /// The account has no active `0`.
    #[error("no {0} is enrolled")]
    NotEnrolled(&'static str),
    /// The `0` ceremony is unknown, expired or another account's.
    #[error("the {0} expired")]
    Expired(&'static str),
    /// The factor does not verify; one answer whatever the reason.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The account has no active credential of this id: another account's,
    /// a removed one or none, answered alike.
    #[error("credential not found")]
    CredentialNotFound(CredentialId),
    /// The credential is the account's last way to sign in and stays.
    #[error("the account's last way to sign in stays")]
    LastSignInMethod(CredentialId),
    /// A dependency cannot answer now; the client retries.
    #[error("{what} unavailable: {cause}")]
    Unavailable { what: &'static str, cause: String },
    /// A retried recovery code generation whose set was issued: the set's
    /// credential id, recorded with the completion.
    #[error("these recovery codes were already issued")]
    RecoveryCodesIssued(Vec<u8>),
    /// The keyed operation's record refused or failed.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// A sealed secret could not be produced or opened.
    #[error("sealed secret: {0}")]
    Sealed(#[from] SealedSecretError),
    /// A stored value this module wrote cannot be read back.
    #[error("{0}")]
    Corrupt(String),
    #[error(transparent)]
    State(#[from] ChallengeStoreError),
    #[error("store: {0}")]
    Store(#[from] sid_core::Error),
}

/// A TOTP code is exactly six ASCII digits (RFC 6238 §5.3 with the default
/// `Digit` of 6); anything else is a malformed request, not a wrong code.
pub fn require_totp_code_format(code: &str) -> Result<(), FactorError> {
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(FactorError::InvalidField {
            field: "code",
            reason: "six digits".to_string(),
        })
    }
}

/// A single-use secret a second factor spends (a recovery code): spent in
/// the commit of the effect it pays for, with the work its spend owes, or
/// not at all.
pub struct FactorSpend {
    pub spend: CredentialSpend,
    pub owes: NewWork,
}

impl FactorSpend {
    /// `ctx`, also spending this.
    pub fn into_context(self, ctx: MutationContext) -> MutationContext {
        ctx.spending(self.spend).with_work(self.owes)
    }
}

/// A TOTP authenticator just enrolled: its credential and, when it is the
/// account's first second factor, the recovery codes issued with it.
pub struct TotpEnrolled {
    pub credential_id: CredentialId,
    pub recovery_codes: Vec<String>,
}

/// The second-factor ceremonies of one authority, with the enrollments
/// started and not yet finished.
pub struct FactorCeremonies<O> {
    /// The issuer whose events announce enrolled factors and spent codes.
    issuer: String,
    /// What the authority's accounts are called in events and keyed
    /// commands (`profile` for a local Profile).
    account_kind: &'static str,
    /// The account's own pending TOTP enrollment: the account and its seed.
    totp_enrollments: ChallengeStore<(O, Vec<u8>)>,
    /// The TOTP steps already accepted, on any path.
    totp_replay: crate::TotpReplayGuard,
}

impl<O: FactorOwner> FactorCeremonies<O> {
    pub fn new(
        issuer: String,
        account_kind: &'static str,
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn KeyManager>,
    ) -> Self {
        Self {
            issuer,
            account_kind,
            totp_enrollments: ChallengeStore::new(
                ceremonies.clone(),
                keys,
                "totp-enrollment",
                CEREMONY_TTL,
            ),
            totp_replay: crate::TotpReplayGuard::new(ceremonies),
        }
    }

    /// The subject events about `owner` name.
    fn subject(&self, owner: O) -> String {
        format!("{}/{}", self.account_kind, owner)
    }

    /// The keyed command of method `M` by `owner`: one key namespace per
    /// authenticated account, whatever service it calls.
    pub fn command<M: sid_proto::KeyedMethod>(
        &self,
        owner: O,
        context: sid_core::models::OperationContext,
        request: &M::Request,
    ) -> KeyedCommand {
        KeyedCommand::of::<M>(format!("{}:{}", self.account_kind, owner), context, request)
    }

    /// Accept `code` for `secret` once: a wrong code and a code already
    /// accepted on any path answer alike (RFC 6238 §5.2).
    pub async fn accept_totp(
        &self,
        owner: O,
        secret: &[u8],
        code: &str,
    ) -> Result<(), FactorError> {
        let step = crate::totp_step(secret, code).ok_or(FactorError::AuthenticationFailed)?;
        let first = self.totp_replay.first_use(owner, step).await.map_err(|e| {
            FactorError::Unavailable {
                what: "TOTP replay record",
                cause: e.to_string(),
            }
        })?;
        if first {
            Ok(())
        } else {
            Err(FactorError::AuthenticationFailed)
        }
    }

    /// Start enrolling a TOTP authenticator for `owner`, named `account_name`
    /// in the authenticator: a new seed and the parameters its codes are
    /// checked with. A new start replaces the account's earlier pending one.
    /// The host has checked that `owner`'s caller may bind it.
    pub async fn totp_enrollment_start(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        owner: O,
        account_name: String,
    ) -> Result<TotpEnrollmentChallenge, FactorError> {
        if credentials
            .get_credentials_by_profile(owner, Some(CredentialType::Totp))
            .await?
            .iter()
            .any(|c| c.status.is_active())
        {
            return Err(FactorError::AlreadyEnrolled);
        }
        let secret = crate::generate_secret();
        self.totp_enrollments
            .insert(&totp_key(owner), &(owner, secret.clone()))
            .await?;
        Ok(TotpEnrollmentChallenge {
            issuer: "StructuredID".to_string(),
            account_name,
            shared_secret: secret,
            algorithm: TotpAlgorithm::Sha1.into(),
            digits: crate::TOTP_DIGITS,
            period_seconds: u32::try_from(crate::TOTP_PERIOD)
                .expect("the TOTP period is a few seconds"),
        })
    }

    /// Take `owner`'s pending TOTP enrollment: its seed. Another account's
    /// pending enrollment never matches, and reads as expired.
    pub async fn take_totp_enrollment(&self, owner: O) -> Result<Vec<u8>, FactorError> {
        self.totp_enrollments
            .take(&totp_key(owner))
            .await?
            .filter(|(enrolled, _)| *enrolled == owner)
            .map(|(_, secret)| secret)
            .ok_or(FactorError::Expired("TOTP enrollment"))
    }

    /// Finish `owner`'s enrollment of `secret` with a code from the new
    /// authenticator, spent like any accepted one: the seed is stored sealed
    /// and, when it is the account's first second factor, with recovery codes
    /// in one write. The host has checked again that the caller may bind it.
    pub async fn enroll_totp(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        keys: &dyn KeyManager,
        owner: O,
        secret: &[u8],
        code: &str,
    ) -> Result<TotpEnrolled, FactorError> {
        self.accept_totp(owner, secret, code).await?;
        // The seed is stored only sealed, bound to this account.
        let sealed =
            crate::sealed_secret::seal(keys, &crate::sealed_secret::totp_context(owner), secret)
                .await?;
        let credential = Credential::new(
            owner,
            CredentialType::Totp,
            CredentialData::new(sealed),
            Some("TOTP Authenticator".to_string()),
        );
        let credential_id = credential.id;
        let first_mfa = !credentials
            .get_credentials_by_profile(owner, None)
            .await?
            .into_iter()
            .any(|c| {
                matches!(
                    c.credential_type,
                    CredentialType::Totp | CredentialType::WebAuthn
                ) && c.status.is_active()
                    && c.id != credential_id
            });
        let enrolled = Event::new(&self.issuer, event_types::MFA_ENROLLED)
            .with_subject(self.subject(owner))
            .with_data(serde_json::json!({
                "method": "totp",
                "credential_id": credential_id.0.to_string(),
                "first_mfa": first_mfa,
            }));
        // The first factor comes with recovery codes, stored with it: a
        // factor without its codes could not be enrolled again to get them.
        let (recovery_codes, recovery_set) = if first_mfa {
            let (plaintext, set) = recovery_set(owner)?;
            (plaintext, Some(set))
        } else {
            (vec![], None)
        };
        let ctx = MutationContext::from(AuditEntry::user(
            owner.to_string(),
            "credential.totp_enrolled",
            credential_id.0.to_string(),
        ))
        .with_work(enrolled.relay());
        credentials
            .enroll_credential(&credential, recovery_set.as_ref(), ctx)
            .await?;
        tracing::info!("TOTP enrolled for {} {}", self.account_kind, owner);
        Ok(TotpEnrolled {
            credential_id,
            recovery_codes,
        })
    }

    /// `owner`'s active TOTP credential and its seed. A seed stored under an
    /// older key version is written back re-sealed under the current one.
    pub async fn active_totp_seed(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        keys: &dyn KeyManager,
        owner: O,
    ) -> Result<Option<(Credential<O>, Opened)>, FactorError> {
        let credential = credentials
            .get_credentials_by_profile(owner, Some(CredentialType::Totp))
            .await?
            .into_iter()
            .find(|c| c.status.is_active());
        let Some(mut credential) = credential else {
            return Ok(None);
        };
        let mut opened = crate::sealed_secret::open(
            keys,
            &crate::sealed_secret::totp_context(owner),
            credential.data.expose(),
        )
        .await?;
        if let Some(resealed) = opened.resealed.take() {
            // Not applied when another reader resealed it first or it was
            // revoked meanwhile; the use that follows is conditional on the
            // credential still being active.
            let applied = credentials
                .reseal_credential_data(
                    credential.id,
                    credential.data.expose(),
                    &resealed,
                    AuditEntry::system("credential.secret_resealed", credential.id.0.to_string())
                        .into(),
                )
                .await?;
            if applied {
                credential.data = CredentialData::new(resealed);
            }
        }
        Ok(Some((credential, opened)))
    }

    /// Verify `code` against `owner`'s active TOTP authenticator and record
    /// its use: a revoked one never verifies, and one revoked since it was
    /// read neither verifies nor comes back.
    pub async fn verify_totp(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        keys: &dyn KeyManager,
        owner: O,
        code: &str,
    ) -> Result<(), FactorError> {
        let (totp, secret) = self
            .active_totp_seed(credentials, keys, owner)
            .await?
            .ok_or(FactorError::NotEnrolled("TOTP authenticator"))?;
        self.accept_totp(owner, &secret.secret, code).await?;
        let used = credentials
            .mark_credential_used(
                totp.id,
                AuditEntry::user(
                    owner.to_string(),
                    "credential.mfa_verified",
                    totp.id.0.to_string(),
                )
                .into(),
            )
            .await?;
        if used {
            Ok(())
        } else {
            Err(FactorError::AuthenticationFailed)
        }
    }

    /// The spend of one recovery code of `owner`'s active set and how many
    /// remain after it. Nothing is spent here: the spend commits with the
    /// effect it pays for, as a compare-and-swap on the set as read, so
    /// concurrent uses spend a code once and only by an effect that
    /// committed; every stored hash is compared, in constant time.
    pub async fn recovery_spend(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        owner: O,
        code: &str,
    ) -> Result<(FactorSpend, i32), FactorError> {
        use subtle::ConstantTimeEq;
        let input_hash = crate::hash_code(&crate::normalize_code(code));
        let set = credentials
            .get_credentials_by_profile(owner, Some(CredentialType::Recovery))
            .await?
            .into_iter()
            .find(|c| c.status.is_active())
            .ok_or(FactorError::NotEnrolled("recovery code set"))?;
        let mut hashes = recovery_hashes(&set)?;
        let mut matched = None;
        for (i, stored) in hashes.iter().enumerate() {
            if bool::from(input_hash.as_bytes().ct_eq(stored.as_bytes())) {
                matched = Some(i);
            }
        }
        let Some(index) = matched else {
            return Err(FactorError::AuthenticationFailed);
        };
        hashes.remove(index);
        let left = serde_json::to_vec(&hashes)
            .map_err(|e| FactorError::Corrupt(format!("write recovery code set: {e}")))?;
        // A spent code is security-relevant (it may mean the account is
        // compromised); the spend owes the event, a spend that did not
        // commit owes nothing.
        let used = Event::new(&self.issuer, event_types::MFA_RECOVERY_CODE_USED)
            .with_subject(self.subject(owner))
            .with_data(serde_json::json!({
                "remaining": hashes.len(),
                "needs_regeneration": hashes.len() <= 3,
            }));
        Ok((
            FactorSpend {
                spend: CredentialSpend {
                    credential: set.id,
                    read: set.data.expose().to_vec(),
                    left,
                },
                owes: used.relay(),
            },
            count(hashes.len())?,
        ))
    }

    /// Issue `owner` a new set of recovery codes in place of the old one, as
    /// the keyed `command`: the new set takes the old one's place in one
    /// transaction, so old codes never stay valid beside the new ones and a
    /// failure leaves the old set usable rather than none. Only the hashes
    /// are kept: a retry of a completed generation names the set it issued
    /// and issues no other. The host has checked that the caller may bind it.
    pub async fn regenerate_recovery_codes(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        operations: &dyn OperationResultStore,
        owner: O,
        command: KeyedCommand,
    ) -> Result<Vec<String>, FactorError> {
        if let Some(recorded) = command.completed(operations).await? {
            return Err(FactorError::RecoveryCodesIssued(recorded));
        }
        let (plaintext, credential) = recovery_set(owner)?;
        let generated = Event::new(&self.issuer, event_types::MFA_ENROLLED)
            .with_subject(self.subject(owner))
            .with_data(serde_json::json!({
                "method": "recovery",
                "credential_id": credential.id.0.to_string(),
                "regenerated": true,
            }));
        let ctx = MutationContext::from(AuditEntry::user(
            owner.to_string(),
            "credential.recovery_codes_generated",
            credential.id.0.to_string(),
        ))
        .with_work(generated.relay())
        .with_operation(command.completion(credential.id.0.as_bytes().to_vec()));
        match credentials.replace_credential(&credential, ctx).await {
            Ok(()) => {}
            // Another attempt of this command committed first: its set is
            // the issued one.
            Err(sid_core::Error::OperationCompleted(_)) => {
                return Err(FactorError::RecoveryCodesIssued(
                    command.committed_elsewhere(operations).await?,
                ));
            }
            Err(e) => return Err(e.into()),
        }
        tracing::info!(
            "Recovery codes generated for {} {} ({} codes)",
            self.account_kind,
            owner,
            plaintext.len()
        );
        Ok(plaintext)
    }

    /// Remove `owner`'s second factor `credential` of `kind` (from
    /// [`removable_factor`]): revoked, its record kept for the audit, in one
    /// commit with the event announcing it and `completion`, the keyed
    /// command's record of the response it is given. One removed meanwhile
    /// reads as not found; the account's last way to sign in stays. The host
    /// has checked that the caller may remove a factor of `kind` and runs
    /// this inside its keyed command, so a retry gets the recorded response.
    pub async fn remove_factor(
        &self,
        credentials: &dyn CredentialStore<Owner = O>,
        owner: O,
        credential: CredentialId,
        kind: CredentialType,
        completion: impl FnOnce(&DeleteMfaCredentialResponse) -> OperationCompletion,
    ) -> Result<DeleteMfaCredentialResponse, FactorError> {
        let name = factor_name(kind).ok_or_else(not_a_factor)?;
        let response = DeleteMfaCredentialResponse {
            deleted: true,
            credential_type: name.to_string(),
        };
        let disabled = Event::new(&self.issuer, event_types::MFA_DISABLED)
            .with_subject(self.subject(owner))
            .with_data(serde_json::json!({
                "credential_type": name,
                "credential_id": credential.0.to_string(),
            }));
        let ctx = MutationContext::from(AuditEntry::user(
            owner.to_string(),
            "credential.mfa_deleted",
            credential.0.to_string(),
        ))
        .with_work(disabled.relay())
        .with_operation(completion(&response));
        // The event commits only with a revocation that happened.
        match credentials.revoke_credential(credential, ctx).await? {
            CredentialRevocation::Revoked => {}
            CredentialRevocation::AlreadyGone => {
                return Err(FactorError::CredentialNotFound(credential));
            }
            CredentialRevocation::LastPrimary => {
                return Err(FactorError::LastSignInMethod(credential));
            }
        }
        tracing::info!(
            "{} removed for {} {} ({})",
            name,
            self.account_kind,
            owner,
            credential.0
        );
        Ok(response)
    }
}

/// What a second factor of `kind` is called in its removal's response and
/// event; none for a credential that is not a second factor.
fn factor_name(kind: CredentialType) -> Option<&'static str> {
    match kind {
        CredentialType::Totp => Some("totp"),
        CredentialType::WebAuthn => Some("webauthn"),
        CredentialType::Recovery => Some("recovery"),
        _ => None,
    }
}

fn not_a_factor() -> FactorError {
    FactorError::InvalidField {
        field: "credential_id",
        reason: "not a second factor (TOTP, passkey or recovery codes)".to_string(),
    }
}

/// The kind of `owner`'s active second factor `credential`, which the host
/// checks its caller may remove before [`FactorCeremonies::remove_factor`].
/// Another account's credential and a removed one read as not found, so a
/// foreign id reveals nothing; a password is not a second factor.
pub async fn removable_factor<O: Send + Sync>(
    credentials: &dyn CredentialStore<Owner = O>,
    owner: O,
    credential: CredentialId,
) -> Result<CredentialType, FactorError> {
    let kind = credentials
        .get_credentials_by_profile(owner, None)
        .await?
        .into_iter()
        .find(|c| c.id == credential && c.status.is_active())
        .map(|c| c.credential_type)
        .ok_or(FactorError::CredentialNotFound(credential))?;
    factor_name(kind).ok_or_else(not_a_factor)?;
    Ok(kind)
}

/// The kept pending TOTP enrollment of `owner`.
fn totp_key(owner: impl Display) -> String {
    format!("totp:{owner}")
}

/// A new recovery-code set of `owner`: the codes, shown once, and the
/// credential keeping only their hashes.
fn recovery_set<O>(owner: O) -> Result<(Vec<String>, Credential<O>), FactorError> {
    let (plaintext, hashes) = crate::generate_recovery_codes();
    let data = serde_json::to_vec(&hashes)
        .map_err(|e| FactorError::Corrupt(format!("encode recovery codes: {e}")))?;
    Ok((
        plaintext,
        Credential::new(
            owner,
            CredentialType::Recovery,
            CredentialData::new(data),
            Some("Recovery Codes".to_string()),
        ),
    ))
}

/// The code hashes a recovery-code set keeps.
fn recovery_hashes<O>(set: &Credential<O>) -> Result<Vec<String>, FactorError> {
    serde_json::from_slice(set.data.expose())
        .map_err(|e| FactorError::Corrupt(format!("read recovery code set: {e}")))
}

/// A number of codes as the wire counts them; a set holds a few.
fn count(codes: usize) -> Result<i32, FactorError> {
    i32::try_from(codes).map_err(|e| FactorError::Corrupt(format!("count recovery codes: {e}")))
}

/// How many recovery codes `owner` has left.
pub async fn codes_left<O: Send + Sync>(
    credentials: &dyn CredentialStore<Owner = O>,
    owner: O,
) -> Result<i32, FactorError> {
    match credentials
        .get_credentials_by_profile(owner, Some(CredentialType::Recovery))
        .await?
        .into_iter()
        .find(|c| c.status.is_active())
    {
        Some(set) => count(recovery_hashes(&set)?.len()),
        None => Ok(0),
    }
}

/// The second factors `owner` has enrolled that complete `first`, its
/// first-factor authentication, under `requirements` (with the account's
/// protection) at `now`.
pub async fn offered_factors<O: Copy + Send + Sync>(
    credentials: &dyn CredentialStore<Owner = O>,
    owner: O,
    requirements: &LoginRequirements,
    first: &Session<O>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<StepUpMethod>, FactorError> {
    let mut factors = Vec::new();
    if requirements.met_with(first, AuthLevel::Standard, TOTP_AMR, now)
        && credentials
            .get_credentials_by_profile(owner, Some(CredentialType::Totp))
            .await?
            .iter()
            .any(|c| c.status.is_active())
    {
        factors.push(StepUpMethod::Totp);
    }
    // Recovery codes complete the sign-in of an account whose enabled factor
    // is unavailable: they are its fallback, never the account's only
    // protection, and only where the requirements accept them.
    if requirements.account_protection > AuthLevel::Basic
        && requirements.met_with(first, AuthLevel::Standard, RECOVERY_CODE_AMR, now)
        && credentials
            .get_credentials_by_profile(owner, Some(CredentialType::Recovery))
            .await?
            .iter()
            .any(|c| c.status.is_active())
    {
        factors.push(StepUpMethod::RecoveryCode);
    }
    Ok(factors)
}

/// The factors `owner` may enroll first to complete `first` under
/// `requirements`: none on an account with established protection, whose
/// lost factor goes through recovery.
pub async fn enrollable_factors<O: Clone + Send + Sync>(
    credentials: &dyn CredentialStore<Owner = O>,
    owner: O,
    requirements: &LoginRequirements,
    first: &Session<O>,
    passkey_satisfies_mfa: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<StepUpMethod>, FactorError> {
    if !requirements.met_with(first, AuthLevel::Standard, TOTP_AMR, now) {
        return Ok(Vec::new());
    }
    let active: Vec<_> = credentials
        .get_credentials_by_profile(owner, None)
        .await?
        .into_iter()
        .filter(|c| c.status.is_active())
        .collect();
    let established =
        crate::credential_enrollment::established_assurance(&active, passkey_satisfies_mfa);
    Ok(if established == AuthLevel::Basic {
        vec![StepUpMethod::Totp]
    } else {
        Vec::new()
    })
}

#[cfg(test)]
mod tests;
