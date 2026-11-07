// SPDX-License-Identifier: AGPL-3.0-only
//! Profile management: Profiles, their login handles and contacts, their
//! credentials, sessions and devices, the passkey prompt, revocation, account
//! closure and data export. The same operations for the service and an
//! embedding application.
//!
//! Each operation takes the verified [`Caller`] and decides its authority
//! itself: a Profile acts on its own account, an administrator on any. A
//! keyed operation takes the caller's operation context, commits its state,
//! audit and completion together and answers a retry with what the first
//! attempt recorded. An operation that authorizes its target before it
//! needs the context takes it as an option and refuses its absence
//! ([`IdentityError::ContextRequired`]) only then, so a refused caller learns
//! nothing more than without one.

use std::sync::Arc;

use prost::Message;
use sid_authn::account_closure::AccountClosureService;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::credential_enrollment::EnrollmentError;
use sid_authn::data_export::DataExportService;
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_authn::passkey_prompt;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::Error as SidError;
use sid_core::models::registration::parse_e164;
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{
    AuditEntry, ClosureMode as CoreClosureMode, ContestCheck, CredentialId,
    CredentialType as CoreCredType, DeviceId, MutationContext, NewRegistration, OperationContext,
    PrincipalId, PrincipalType, Profile, ProfileEmail, ProfileId, ProfileMetadata, ProfilePhone,
    RegistrationSource, RevocationReason, SessionId, SignupIdentifier,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::identity::identity_service as keyed;
use sid_proto::sid::v1::*;
use tracing::info;

use crate::wire::{FieldError, to_timestamp, wire_id};

mod view;

use view::{
    credential_to_proto, device_to_proto, export_status_to_proto, principal_to_proto,
    profile_to_proto, profile_to_proto_with_contacts,
};

/// Profiles per ListProfiles page when the request names no size.
const DEFAULT_PROFILE_PAGE: u64 = 50;

/// The largest ListProfiles page; a bigger request gets this many.
const MAX_PROFILE_PAGE: i32 = 500;

/// Which account record a closure or export refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRecord {
    /// The account's closure request.
    Closure,
    /// The account's data export.
    Export,
}

impl AccountRecord {
    /// The precondition type of the record's wrong state.
    pub fn state(self) -> &'static str {
        match self {
            Self::Closure => "CLOSURE_STATE",
            Self::Export => "EXPORT_STATE",
        }
    }
}

/// Why a Profile management operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// Removing a credential takes the authority adding it would.
    #[error(transparent)]
    Enrollment(#[from] EnrollmentError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation (a broken invariant); its cause is in
    /// the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// The operation reached the point where it needs the caller's operation
    /// context, and the caller gave none it could use.
    #[error("an operation context is required")]
    ContextRequired,
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// A new account names none of its possible login handles.
    #[error("a username, email or phone is required")]
    SignupHandleRequired,
    /// No Profile is named so (an id, or the kind of handle an administrator
    /// looked the account up by).
    #[error("profile {0} not found")]
    ProfileNotFound(String),
    /// Unknown, or not the caller's to see.
    #[error("credential {} not found", .0.0)]
    CredentialNotFound(CredentialId),
    /// Unknown, or another profile's.
    #[error("device {0} not found")]
    DeviceNotFound(DeviceId),
    /// Unknown, or held only by others.
    #[error("principal {} not found", .0.0)]
    PrincipalNotFound(PrincipalId),
    /// A handle or contact of this type is held by another account.
    #[error("the {} is registered to another account", .0.as_str())]
    Taken(PrincipalType),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
    /// An email key of an earlier policy revision must be confirmed by its
    /// owner before it signs in again.
    #[error("this address must be confirmed before it signs in again")]
    AddressUnconfirmed,
    /// The principal has several holders; the request names none.
    #[error("principal {} has several holders", .0.0)]
    SeveralHolders(PrincipalId),
    /// The credential is the profile's last way to sign in.
    #[error("credential {} is the profile's last way to sign in", .0.0)]
    LastPrimary(CredentialId),
    /// The profile already trusts as many devices as it may.
    #[error("the limit of trusted devices is reached")]
    TrustedDeviceLimit,
    /// Only the profile's own devices are listed.
    #[error("only the profile's own devices are listed")]
    OtherProfileDevices,
    /// The account's closure or export is not in a state that allows this.
    #[error("the account is not in a state that allows this: {why}")]
    AccountState {
        record: AccountRecord,
        owner: ProfileId,
        why: String,
    },
    /// The account has no such closure or export.
    #[error("no {record:?} for {owner}")]
    AccountRecordNotFound {
        record: AccountRecord,
        owner: ProfileId,
    },
    /// The yearly limit of cancelled closures is reached.
    #[error("the yearly limit of cancelled closures is reached")]
    CancelLimit,
    /// The request needs what this build does not include.
    #[error("{0} is not in this build")]
    NotInThisBuild(&'static str),
}

impl From<IdentityError> for Effect<IdentityError> {
    fn from(e: IdentityError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<IdentityError>> for IdentityError {
    fn from(e: CommandError<IdentityError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for IdentityError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

impl From<FieldError> for Effect<IdentityError> {
    fn from(e: FieldError) -> Self {
        Self::Refused(e.into())
    }
}

fn invalid_field(field: &'static str, reason: impl Into<String>) -> IdentityError {
    IdentityError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> IdentityError {
    tracing::error!(operation, error = %cause, "internal failure");
    IdentityError::Internal
}

/// The context a deferring operation needs now.
fn required(operation: Option<OperationContext>) -> Result<OperationContext, IdentityError> {
    operation.ok_or(IdentityError::ContextRequired)
}

/// The Profile a self-service request acts on: the caller's own when the
/// request names none; naming another takes administrator authority.
fn target_profile(
    caller: &Caller,
    named: Option<&sid_ids_proto::ProfileId>,
) -> Result<ProfileId, IdentityError> {
    let Some(named) = named else {
        return Ok(caller.profile_id);
    };
    let pid = wire_id(Some(named), "profile_id")?;
    caller.require_self_or_admin(pid)?;
    Ok(pid)
}

fn credential_id(id: Option<&sid_ids_proto::CredentialId>) -> Result<CredentialId, IdentityError> {
    Ok(CredentialId(wire_id(id, "credential_id")?.into_uuid()))
}

fn device_id(id: Option<&sid_ids_proto::DeviceId>) -> Result<DeviceId, IdentityError> {
    Ok(wire_id(id, "device_id")?)
}

/// `input` of the request field `field` as the login handle of `expected`
/// kind it must be; anything else names the field.
fn login_handle(
    field: &'static str,
    input: &str,
    expected: PrincipalType,
) -> Result<sid_authn::normalize::NormalizedPrincipal, IdentityError> {
    let handle = sid_authn::normalize::normalize_principal(input)
        .map_err(|e| invalid_field(field, e.to_string()))?;
    if handle.principal_type.to_principal_type() != expected {
        return Err(invalid_field(field, format!("not a {field}")));
    }
    Ok(handle)
}

/// The identifier a new account starts from: an email (its key, delivery
/// address and key revision), a phone or a username.
pub fn signup_identifier<'a>(
    principal_type: PrincipalType,
    value: &'a str,
    email: Option<&'a sid_authn::email::EmailHandle>,
) -> Result<SignupIdentifier<'a>, IdentityError> {
    match principal_type {
        PrincipalType::Email => {
            let email = email.ok_or_else(|| internal("sign up", "an email without its address"))?;
            Ok(SignupIdentifier::Email {
                key: value,
                address: &email.delivery,
                revision: email.revision,
            })
        }
        PrincipalType::Phone => Ok(SignupIdentifier::Phone(value)),
        PrincipalType::Username => Ok(SignupIdentifier::Username(value)),
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag | PrincipalType::FederatedSubject => {
            Err(invalid_field(
                "identifier",
                "a new account starts from an email, phone or username",
            ))
        }
    }
}

/// The form a principal of `principal_type` is stored in: text handles in
/// the normalized form login looks them up by, and of the requested type;
/// device identifiers as given. An email also yields its validated handle:
/// the address in the spelling given and the policy revision of its key.
pub fn stored_principal_value(
    principal_type: PrincipalType,
    value: &str,
) -> Result<(String, Option<sid_authn::email::EmailHandle>), IdentityError> {
    match principal_type {
        PrincipalType::Email | PrincipalType::Phone | PrincipalType::Username => {
            let normalized = sid_authn::normalize::normalize_principal(value)
                .map_err(|e| invalid_field("value", e.to_string()))?;
            if normalized.principal_type.to_principal_type() != principal_type {
                return Err(invalid_field("value", format!("not a {principal_type}")));
            }
            Ok((normalized.normalized, normalized.email))
        }
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag => {
            if value.is_empty() {
                return Err(IdentityError::MissingField("value"));
            }
            Ok((value.to_owned(), None))
        }
        // Only a confirmed federation association records one, never a caller.
        PrincipalType::FederatedSubject => Err(invalid_field(
            "type",
            "a federated subject is recorded by its association, not added",
        )),
    }
}

/// A revocation refused because the credential is the profile's last way to
/// sign in is the caller's to fix (add another method first); a credential
/// already gone is revoked as asked.
pub fn last_primary(
    outcome: sid_core::models::CredentialRevocation,
    credential: CredentialId,
) -> Result<(), IdentityError> {
    use sid_core::models::CredentialRevocation;
    match outcome {
        CredentialRevocation::LastPrimary => Err(IdentityError::LastPrimary(credential)),
        CredentialRevocation::Revoked | CredentialRevocation::AlreadyGone => Ok(()),
    }
}

/// The closure and export services' refusals of `owner`'s own account, by
/// cause. A missing record the operation needs (`needed`) is not found; a
/// missing record anywhere else (the caller's own profile) is internal, as is
/// any other failure.
fn account_refusal(
    operation: &'static str,
    record: AccountRecord,
    needed: bool,
    owner: ProfileId,
    e: SidError,
) -> IdentityError {
    match e {
        SidError::NotFound(_) if needed => IdentityError::AccountRecordNotFound { record, owner },
        SidError::InvalidState(why) => IdentityError::AccountState { record, owner, why },
        SidError::RateLimited(_) => IdentityError::CancelLimit,
        e => internal(operation, e),
    }
}

/// A keyed closure or export command's failure: a commit another attempt of
/// it completed answers with that attempt's result, and one its period no
/// longer admits is answered as such; anything else is refused as
/// [`account_refusal`].
fn account_effect(
    operation: &'static str,
    record: AccountRecord,
    needed: bool,
    owner: ProfileId,
    e: SidError,
) -> Effect<IdentityError> {
    match e {
        SidError::OperationCompleted(_) | SidError::OperationPeriodRefused(_) => Effect::Store(e),
        e => Effect::Refused(account_refusal(operation, record, needed, owner, e)),
    }
}

/// A handle `command`'s commit found taken: by another attempt of this very
/// command that committed first, which answers with that attempt's result, or
/// by someone else.
async fn taken_unless_completed(
    command: &KeyedCommand,
    storage: &dyn StorageBackend,
    principal_type: PrincipalType,
) -> Effect<IdentityError> {
    match command.completed(storage).await {
        Ok(Some(_)) => Effect::Store(SidError::OperationCompleted(
            "committed by another attempt".into(),
        )),
        Ok(None) => IdentityError::Taken(principal_type).into(),
        Err(e) => Effect::Operation(e),
    }
}

/// UpdateCredential's answer: `cred` without its secret material.
fn credential_response(
    cred: sid_core::models::Credential,
) -> Result<UpdateCredentialResponse, IdentityError> {
    Ok(UpdateCredentialResponse {
        credential: Some(credential_to_proto(cred)?),
    })
}

/// A data export archive and its job, read for download.
pub struct ExportArchive {
    pub data: Vec<u8>,
    pub job: sid_core::models::ExportJob,
}

/// The Profile management of one installation.
pub struct Identity {
    storage: Arc<dyn StorageBackend>,
    cascade: Arc<RevocationCascadeService>,
    closure: Arc<AccountClosureService>,
    export: Arc<DataExportService>,
}

impl Identity {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        cascade: Arc<RevocationCascadeService>,
        closure: Arc<AccountClosureService>,
        export: Arc<DataExportService>,
    ) -> Self {
        Self {
            storage,
            cascade,
            closure,
            export,
        }
    }

    /// `profile_id`'s email contact spelled exactly `address`, created
    /// (unverified, not primary) when it has none.
    async fn email_contact(
        &self,
        profile_id: ProfileId,
        address: &str,
    ) -> Result<ProfileEmail, IdentityError> {
        let contacts = self.storage.list_profile_emails(profile_id).await?;
        if let Some(contact) = contacts.into_iter().find(|c| c.email == address) {
            return Ok(contact);
        }
        let now = chrono::Utc::now();
        let contact = ProfileEmail {
            id: sid_core::models::ProfileEmailId::new(),
            profile_id,
            email: address.to_string(),
            label: sid_core::models::EmailLabel::Personal,
            custom_label: None,
            is_primary: false,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        };
        self.storage
            .create_profile_email(
                &contact,
                AuditEntry::system("principal.email_contact", contact.id.0.to_string()).into(),
            )
            .await?;
        Ok(contact)
    }

    /// When `key` is a quarantined email key of `profile_id` (written before
    /// email policy revisions, its address unknown), repair it on the address
    /// `email` the caller gives. Only an administrator's assertion, within
    /// the installation's authority over its managed accounts, establishes
    /// the address here; the owner confirms it instead. The repair commits
    /// `command`'s completion and answers with the claim that commit
    /// recorded. `None` when the key is not such a key.
    async fn repair_quarantined_email(
        &self,
        command: &KeyedCommand,
        caller: &Caller,
        profile_id: ProfileId,
        key: &str,
        email: &sid_authn::email::EmailHandle,
    ) -> Result<Option<sid_core::models::Principal>, IdentityError> {
        let Some(existing) = self
            .storage
            .get_principal_by_value(PrincipalType::Email, key)
            .await?
        else {
            return Ok(None);
        };
        if existing.email_policy_revision == Some(email.revision)
            || existing.assigned_profile_id != Some(profile_id)
        {
            return Ok(None);
        }
        if !caller.is_admin() {
            return Err(IdentityError::AddressUnconfirmed);
        }
        let contact = self.email_contact(profile_id, &email.delivery).await?;
        let repaired = self
            .storage
            .reconcile_email_key(
                existing.id,
                profile_id,
                &contact,
                "administrator_asserted",
                MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "principal.email_repaired",
                    existing.id.0.to_string(),
                ))
                .with_operation(command.effect_completion()),
            )
            .await?;
        if !repaired {
            // Another attempt of this command may have made the repair.
            return match command.recorded_effect(&*self.storage).await {
                Ok(held) => Ok(Some(held)),
                Err(OperationError::OutcomeUnknown) => Err(IdentityError::ChangedConcurrently),
                Err(e) => Err(e.into()),
            };
        }
        // The claim as this commit left it, whatever changed since.
        Ok(Some(command.recorded_effect(&*self.storage).await?))
    }

    /// A profile's primary email and phone for a profile read; a failed read
    /// fails the operation rather than answer as if the profile had none.
    async fn primary_contacts(
        &self,
        profile_id: ProfileId,
    ) -> Result<(Option<ProfileEmail>, Option<ProfilePhone>), IdentityError> {
        let email = self.storage.get_primary_profile_email(profile_id).await?;
        let phone = self.storage.get_primary_profile_phone(profile_id).await?;
        Ok((email, phone))
    }

    /// Credential `id` if the caller may see it (their own, or any for an
    /// administrator); another profile's is not found, as an unknown one.
    async fn visible_credential(
        &self,
        caller: &Caller,
        id: CredentialId,
    ) -> Result<sid_core::models::Credential, IdentityError> {
        self.storage
            .get_credential(id)
            .await?
            .filter(|c| caller.require_self_or_admin(c.profile_id).is_ok())
            .ok_or(IdentityError::CredentialNotFound(id))
    }

    /// The caller's device `device_id`; another profile's is not found.
    async fn owned_device(
        &self,
        caller_id: ProfileId,
        device_id: DeviceId,
    ) -> Result<sid_core::models::Device, IdentityError> {
        self.storage
            .get_device(device_id)
            .await?
            .filter(|d| d.profile_id == caller_id)
            .ok_or(IdentityError::DeviceNotFound(device_id))
    }

    /// The profile's stored passkey prompt state.
    async fn stored_passkey_prompt(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<passkey_prompt::PasskeyPromptState>, IdentityError> {
        Ok(self
            .storage
            .get_profile_metadata(profile_id, passkey_prompt::PROFILE_METADATA_KEY)
            .await?
            .and_then(|m| {
                serde_json::from_value::<passkey_prompt::PasskeyPromptState>(m.value).ok()
            }))
    }

    /// The prompt as `stored_state` leaves it for `profile_id`.
    async fn passkey_prompt_state(
        &self,
        profile_id: ProfileId,
        stored_state: Option<passkey_prompt::PasskeyPromptState>,
    ) -> Result<sid_proto::sid::v1::PasskeyPromptState, IdentityError> {
        use sid_core::models::security_policy::PasskeyPromptMode as Mode;
        let policy = SecurityPolicy::ce_default();
        let config = &policy.passkey_prompt;

        // A failed read fails the call: answering "no passkey" would prompt,
        // or under Required demand, a passkey the profile already has.
        let has_passkey = !self
            .storage
            .get_credentials_by_profile(profile_id, Some(CoreCredType::WebAuthn))
            .await?
            .is_empty();
        let decision = passkey_prompt::decide(config, stored_state.as_ref(), has_passkey);
        let mode = match config.mode {
            Mode::Encouraged => sid_proto::sid::v1::PasskeyPromptMode::Encouraged,
            Mode::Required => sid_proto::sid::v1::PasskeyPromptMode::Required,
            Mode::None => sid_proto::sid::v1::PasskeyPromptMode::None,
        };
        Ok(sid_proto::sid::v1::PasskeyPromptState {
            mode: mode.into(),
            decision: decision.as_str().to_string(),
            skip_count: stored_state.as_ref().map_or(0, |s| s.skip_count),
            skip_limit: config.skip_limit,
            has_passkey,
        })
    }

    // ── Profiles ────────────────────────────────────────────────────

    /// Provision an account for someone else: an administrator action;
    /// self-registration goes through the registration ceremonies.
    pub async fn create_profile(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateProfileRequest,
    ) -> Result<CreateProfileResponse, IdentityError> {
        caller.require_admin()?;
        let command =
            KeyedCommand::by_profile::<keyed::CreateProfile>(caller.profile_id, operation, &req);
        // A completed creation answers before the checks below, which its own
        // account would now fail (its handles are taken).
        if let Some(response) = command.replay(&*self.storage).await? {
            return Ok(response);
        }
        // A refusal a concurrent attempt of this command caused (the handles
        // its account took) is that attempt's answer.
        let answer = self.new_profile(caller, &command, &req).await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(CommandError::refusal)
    }

    async fn new_profile(
        &self,
        caller: &Caller,
        command: &KeyedCommand,
        req: &CreateProfileRequest,
    ) -> Result<CreateProfileResponse, IdentityError> {
        // Administrator provisioning is allowed in every enrollment mode: the
        // mode governs self-registration only, and no invite is spent here.
        //
        // D013: one signup principal, the username when given, else the
        // email, else the phone; the other contacts are stored unverified.
        // A username is a valuable identity: never auto-generated. Each given
        // contact as the login handle it would be: the key a principal stores
        // and lookups use, and for an email the validated address its contact
        // stores.
        let given = |value: &Option<String>, field, kind| {
            value
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| login_handle(field, s, kind))
                .transpose()
        };
        let provided_username = given(&req.username, "username", PrincipalType::Username)?;
        let provided_email = given(&req.email, "email", PrincipalType::Email)?;
        let provided_phone = given(&req.phone, "phone", PrincipalType::Phone)?;
        let signup = match (&provided_username, &provided_email, &provided_phone) {
            (Some(username), _, _) => username,
            (None, Some(email), _) => email,
            (None, None, Some(phone)) => phone,
            (None, None, None) => return Err(IdentityError::SignupHandleRequired),
        };

        // Contacts already on another account are refused with the reason the
        // UI shows; the principal's unique key settles a race below. A
        // username is also the profile's own name: held either way.
        if let Some(username) = &provided_username
            && self
                .storage
                .get_profile_by_username(&username.normalized)
                .await?
                .is_some()
        {
            return Err(IdentityError::Taken(PrincipalType::Username));
        }
        for handle in [&provided_username, &provided_email, &provided_phone]
            .into_iter()
            .flatten()
        {
            let principal_type = handle.principal_type.to_principal_type();
            if self
                .storage
                .get_principal_by_value(principal_type, &handle.normalized)
                .await?
                .is_some()
            {
                return Err(IdentityError::Taken(principal_type));
            }
        }

        let mut profile = Profile::new(provided_username.as_ref().map(|u| u.normalized.as_str()));
        profile.given_name = req.given_name.clone();
        profile.family_name = req.family_name.clone();
        profile.middle_name = req.middle_name.clone();
        profile.honorific_prefix = req.honorific_prefix.clone();
        profile.honorific_suffix = req.honorific_suffix.clone();

        let principal_type = signup.principal_type.to_principal_type();
        let principal_field = match principal_type {
            PrincipalType::Username => "username",
            PrincipalType::Email => "email",
            _ => "phone",
        };
        let identifier =
            signup_identifier(principal_type, &signup.normalized, signup.email.as_ref())?;
        let mut registration = NewRegistration::new(profile, identifier, None)
            .map_err(|e| invalid_field(principal_field, e.to_string()))?;
        if let Some(email) = &provided_email
            && principal_type != PrincipalType::Email
        {
            let address = email
                .email
                .as_ref()
                .map(|handle| handle.delivery.as_str())
                .ok_or_else(|| internal("create profile", "an email without its address"))?;
            registration = registration.with_email(address);
        }
        if let Some(phone) = &provided_phone
            && principal_type != PrincipalType::Phone
        {
            registration = registration.with_phone(
                parse_e164(&phone.normalized).map_err(|e| invalid_field("phone", e.to_string()))?,
            );
        }
        // Where the account came from is stored with it while the policy in
        // force when it commits tracks sources: the storage decides in the
        // account's transaction.
        let mut source = RegistrationSource::admin_created(caller.profile_id);
        if let Some(referrer) = &req.referrer_id {
            let rid = wire_id(Some(referrer), "referrer_id")?;
            if self.storage.get_profile(rid).await?.is_none() {
                return Err(invalid_field("referrer_id", "names no profile"));
            }
            source.referrer_id = Some(rid);
        }
        if let Some(utm) = &req.utm {
            source.utm = sid_core::models::UtmParams {
                source: utm.source.clone().unwrap_or_default(),
                medium: utm.medium.clone().unwrap_or_default(),
                campaign: utm.campaign.clone().unwrap_or_default(),
                term: utm.term.clone().unwrap_or_default(),
                content: utm.content.clone().unwrap_or_default(),
            };
        }
        registration = registration
            .with_source(source)
            .recording_source_while_tracked();
        let profile = registration.profile.clone();

        // A retry of a completed creation answers with the account it
        // created, as its commit stored it, and creates no second one. The
        // account's id is new on every attempt, so the key alone says it is
        // the same command.
        let response = CreateProfileResponse {
            profile: Some(profile_to_proto_with_contacts(
                &profile,
                registration.email.as_ref(),
                None,
            )),
        };
        // USER_CREATED is owed by the commit that stores the account.
        let created = sid_core::models::event::Event::new(
            "sid-identity",
            sid_core::models::event::event_types::USER_CREATED,
        )
        .with_subject(format!("profile/{}", profile.id))
        .with_data(serde_json::json!({
            "profile_id": profile.id.to_string(),
            "username": profile.username,
        }));
        command
            .execute(&*self.storage, || async {
                let ctx = MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "profile.create",
                    profile.id.to_string(),
                ))
                .with_work(created.relay())
                .with_operation(command.completion(response.encode_to_vec()));
                match self.storage.register_profile(&registration, ctx).await {
                    Ok(()) => {}
                    Err(SidError::Conflict(_)) => {
                        return Err(taken_unless_completed(
                            command,
                            &*self.storage,
                            principal_type,
                        )
                        .await);
                    }
                    Err(e) => return Err(e.into()),
                }
                info!(
                    "Created profile {} ({})",
                    profile.username.as_deref().unwrap_or("<no username>"),
                    profile.id
                );
                Ok(response.clone())
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// A user reads only their own profile by id; looking an account up by
    /// username or email is an administrator action (it tells whether the
    /// account exists).
    pub async fn get_profile(
        &self,
        caller: &Caller,
        req: GetProfileRequest,
    ) -> Result<GetProfileResponse, IdentityError> {
        let (named, profile) = match req.identifier {
            Some(get_profile_request::Identifier::Id(id)) => {
                let pid = wire_id(Some(&id), "id")?;
                caller.require_self_or_admin(pid)?;
                (pid.to_string(), self.storage.get_profile(pid).await)
            }
            // A handle is personal data: the refusal names its kind, not its
            // value, since error details travel through proxies and logs.
            Some(get_profile_request::Identifier::Username(username)) => {
                caller.require_admin()?;
                let found = self.storage.get_profile_by_username(&username).await;
                ("username".to_string(), found)
            }
            Some(get_profile_request::Identifier::Email(email)) => {
                caller.require_admin()?;
                let found = self.storage.get_profile_by_email(&email).await;
                ("email".to_string(), found)
            }
            None => return Err(IdentityError::MissingField("identifier")),
        };
        let p = profile?.ok_or(IdentityError::ProfileNotFound(named))?;
        self.profile_response(p).await
    }

    /// The caller's own profile.
    pub async fn current_profile(
        &self,
        caller: &Caller,
    ) -> Result<GetProfileResponse, IdentityError> {
        let profile = self
            .storage
            .get_profile(caller.profile_id)
            .await?
            .ok_or_else(|| IdentityError::ProfileNotFound(caller.profile_id.to_string()))?;
        self.profile_response(profile).await
    }

    async fn profile_response(&self, p: Profile) -> Result<GetProfileResponse, IdentityError> {
        let (primary_email, primary_phone) = self.primary_contacts(p.id).await?;
        Ok(GetProfileResponse {
            profile: Some(profile_to_proto_with_contacts(
                &p,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )),
        })
    }

    /// Edit a profile's names; the context is required after the caller is
    /// authorized for the target.
    pub async fn update_profile(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: UpdateProfileRequest,
    ) -> Result<UpdateProfileResponse, IdentityError> {
        let pid = wire_id(req.id.as_ref(), "id")?;
        caller.require_self_or_admin(pid)?;
        let operation = required(operation)?;

        // A retry of a completed edit answers with the profile as that edit
        // left it and never writes its names again over a later edit.
        let command =
            KeyedCommand::by_profile::<keyed::UpdateProfile>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let mut profile = self
                    .storage
                    .get_profile(pid)
                    .await?
                    .ok_or_else(|| IdentityError::ProfileNotFound(pid.to_string()))?;
                let req = req.clone();
                if let Some(v) = req.given_name {
                    profile.given_name = Some(v);
                }
                if let Some(v) = req.family_name {
                    profile.family_name = Some(v);
                }
                if let Some(v) = req.middle_name {
                    profile.middle_name = Some(v);
                }
                if let Some(v) = req.honorific_prefix {
                    profile.honorific_prefix = Some(v);
                }
                if let Some(v) = req.honorific_suffix {
                    profile.honorific_suffix = Some(v);
                }
                profile.updated_at = chrono::Utc::now();

                // The profile as this edit leaves it, with the contacts it
                // has: the edit changes no contact.
                let (primary_email, primary_phone) = self.primary_contacts(pid).await?;
                let mut left = profile.clone();
                left.revision += 1;
                let response = UpdateProfileResponse {
                    profile: Some(profile_to_proto_with_contacts(
                        &left,
                        primary_email.as_ref(),
                        primary_phone.as_ref(),
                    )),
                };
                let changed = sid_core::models::event::Event::new(
                    "sid-identity",
                    sid_core::models::event::event_types::PROFILE_CLAIM_CHANGED,
                )
                .with_subject(format!("profile/{}", profile.id))
                .with_data(serde_json::json!({
                    "profile_id": profile.id.to_string(),
                }));
                let ctx = MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "profile.update",
                    profile.id.to_string(),
                ))
                .with_work(changed.relay())
                .with_operation(command.completion(response.encode_to_vec()));
                // Over the revision read above, so the names written here never
                // carry back a status or role changed meanwhile (a suspension
                // stays).
                if !self.storage.update_profile(&profile, ctx).await? {
                    return Err(IdentityError::ChangedConcurrently.into());
                }
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Hard deletion: an administrator action; a user closes their own
    /// account through the closure flow.
    pub async fn delete_profile(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: DeleteProfileRequest,
    ) -> Result<DeleteProfileResponse, IdentityError> {
        caller.require_admin()?;
        let pid = wire_id(req.id.as_ref(), "id")?;
        // A retry of a completed deletion answers as it did and owes its
        // events and purge only once.
        let command =
            KeyedCommand::by_profile::<keyed::DeleteProfile>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let response = DeleteProfileResponse {};
                let deleted = sid_core::models::event::Event::new(
                    "sid-identity",
                    sid_core::models::event::event_types::USER_DELETED,
                )
                .with_subject(format!("profile/{}", pid))
                .with_data(serde_json::json!({
                    "profile_id": pid.to_string(),
                }));
                let mut ctx = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "profile.delete",
                    pid.to_string(),
                ))
                .with_work(deleted.relay())
                .with_operation(command.completion(response.encode_to_vec()));
                // The owner's history keys go with it, owed in the same
                // transaction.
                if let Some(purge) =
                    crate::maintenance::owner_purge(self.storage.as_ref(), pid).await?
                {
                    ctx = ctx.with_work(purge);
                }
                self.storage.delete_profile(pid, ctx).await?;
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn list_profiles(
        &self,
        caller: &Caller,
        req: ListProfilesRequest,
    ) -> Result<ListProfilesResponse, IdentityError> {
        caller.require_admin()?;
        let limit: u64 = if req.page_size > 0 {
            req.page_size.min(MAX_PROFILE_PAGE) as u64
        } else {
            DEFAULT_PROFILE_PAGE
        };
        // An empty token is the first page; any other token is one this
        // engine issued (an offset), never silently reset to the first page.
        // Bounded to i64: the stores take the offset as a SQL BIGINT.
        let offset: u64 = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse::<i64>()
                .ok()
                .and_then(|o| u64::try_from(o).ok())
                .ok_or_else(|| invalid_field("page_token", "not a token this service issued"))?
        };
        let profiles = self.storage.list_profiles(offset, limit).await?;
        // A full page may have a next one; an offset past BIGINT has none.
        let next_page_token = offset
            .checked_add(limit)
            .filter(|next| profiles.len() as u64 == limit && i64::try_from(*next).is_ok())
            .map(|next| next.to_string())
            .unwrap_or_default();
        Ok(ListProfilesResponse {
            profiles: profiles.iter().map(profile_to_proto).collect(),
            next_page_token,
        })
    }

    // ── Credentials ─────────────────────────────────────────────────

    pub async fn list_credentials(
        &self,
        caller: &Caller,
        req: ListCredentialsRequest,
    ) -> Result<ListCredentialsResponse, IdentityError> {
        let pid = target_profile(caller, req.profile_id.as_ref())?;
        let creds = self.storage.get_credentials_by_profile(pid, None).await?;
        Ok(ListCredentialsResponse {
            credentials: creds
                .into_iter()
                .map(credential_to_proto)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Rename a credential; the identifier is checked before the context.
    pub async fn update_credential(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: UpdateCredentialRequest,
    ) -> Result<UpdateCredentialResponse, IdentityError> {
        caller.require_interactive()?;
        let cred_id = credential_id(req.credential_id.as_ref())?;
        // A retry of a completed rename answers with the credential as that
        // rename left it and never writes its label over a later one.
        let command = KeyedCommand::by_profile::<keyed::UpdateCredential>(
            caller.profile_id,
            required(operation)?,
            &req,
        );
        let audit = || {
            AuditEntry::user(
                caller.profile_id.to_string(),
                "credential.update",
                cred_id.0.to_string(),
            )
        };
        let Some(label) = req.label.clone() else {
            // Nothing to write: the credential as it is, this command's
            // outcome.
            return command
                .unchanged(&*self.storage, audit(), || async {
                    credential_response(self.visible_credential(caller, cred_id).await?)
                })
                .await
                .map_err(CommandError::refusal);
        };
        command
            .execute(&*self.storage, || async {
                let mut cred = self.visible_credential(caller, cred_id).await?;
                cred.label = Some(label.clone());
                let response = credential_response(cred)?;
                let ctx = MutationContext::from(audit())
                    .with_operation(command.completion(response.encode_to_vec()));
                // A revoked credential is gone for its owner: renaming it
                // neither succeeds nor revives it.
                if !self
                    .storage
                    .set_credential_label(cred_id, Some(&label), ctx)
                    .await?
                {
                    return Err(IdentityError::CredentialNotFound(cred_id).into());
                }
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn revoke_credential(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, IdentityError> {
        caller.require_interactive()?;
        let cred_id = credential_id(req.credential_id.as_ref())?;
        // A retry of a completed revocation answers as it did, not as a
        // credential not found.
        let command =
            KeyedCommand::by_profile::<keyed::RevokeCredential>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let credential = self.visible_credential(caller, cred_id).await?;
                // Removing protection takes the authority adding it would:
                // otherwise a weaker session revokes the strong factor, then
                // adds its own.
                if caller.profile_id == credential.profile_id {
                    sid_authn::credential_enrollment::authorize(
                        self.storage.as_ref(),
                        caller,
                        credential.credential_type,
                        SecurityPolicy::ce_default().auth.passkey_satisfies_mfa,
                    )
                    .await
                    .map_err(IdentityError::from)?;
                }
                // Revoked, not deleted; the profile keeps one active primary
                // credential, checked in the same step as the revocation.
                let response = RevokeCredentialResponse {};
                let ctx = MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "credential.revoke",
                    cred_id.0.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                let outcome = self.storage.revoke_credential(cred_id, ctx).await?;
                last_primary(outcome, cred_id)?;
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Principals ──────────────────────────────────────────────────

    /// Claim a login handle or contact; the target is authorized before the
    /// context is required.
    pub async fn add_principal(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: AddPrincipalRequest,
    ) -> Result<AddPrincipalResponse, IdentityError> {
        caller.require_interactive()?;
        let pid = target_profile(caller, req.profile_id.as_ref())?;
        let operation = required(operation)?;

        let principal_type = match req.r#type() {
            sid_proto::sid::v1::PrincipalType::Email => PrincipalType::Email,
            sid_proto::sid::v1::PrincipalType::Phone => PrincipalType::Phone,
            sid_proto::sid::v1::PrincipalType::FaceEmbedding => PrincipalType::FaceEmbedding,
            sid_proto::sid::v1::PrincipalType::NfcTag => PrincipalType::NfcTag,
            sid_proto::sid::v1::PrincipalType::Username => PrincipalType::Username,
            _ => return Err(IdentityError::MissingField("type")),
        };
        let (value, email) = stored_principal_value(principal_type, &req.value)?;

        // One claim per operation key: a retry answers with the claim as its
        // first commit stored it, never as a handle taken by itself, owes no
        // second contestation check and never adds back a claim removed since.
        let command =
            KeyedCommand::by_profile::<keyed::AddPrincipal>(caller.profile_id, operation, &req);
        let stored: sid_core::models::Principal = command
            .execute_recorded(&*self.storage, || async {
                self.storage
                    .get_profile(pid)
                    .await?
                    .ok_or_else(|| IdentityError::ProfileNotFound(pid.to_string()))?;

                let mut principal = sid_core::models::Principal::new(pid, principal_type, &value);
                if let Some(email) = &email {
                    principal.email_policy_revision = Some(email.revision);
                    if let Some(repaired) = self
                        .repair_quarantined_email(&command, caller, pid, &value, email)
                        .await?
                    {
                        // The repair is complete as written: a retry finds
                        // the key on the current revision and claims it as is.
                        return Ok(repaired);
                    }
                    // The handle's delivery address: the profile's contact
                    // with this exact spelling, else a new unverified one.
                    let contact = self.email_contact(pid, &email.delivery).await?;
                    principal.source_field = Some("email".into());
                    principal.source_email_id = Some(contact.id);
                }

                // A shared contact channel owes the contestation check: once
                // the claim commits, every other holder is told. A login handle
                // is never shared, so it owes none. The store records the claim
                // as stored: its id is the principal's, which an earlier holder
                // may have created.
                let mut ctx = MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "principal.create",
                    principal.id.0.to_string(),
                ))
                .with_operation(command.effect_completion());
                if principal_type.is_contestable() {
                    ctx = ctx.with_work(ContestCheck::new(principal_type, &value, pid).work());
                }
                match self.storage.save_principal(&principal, ctx).await {
                    Ok(()) => {}
                    // Only a login handle is unique; a contact channel is shared.
                    Err(SidError::Conflict(_)) => {
                        return Err(taken_unless_completed(
                            &command,
                            &*self.storage,
                            principal_type,
                        )
                        .await);
                    }
                    Err(e) => return Err(e.into()),
                }
                // The claim as this commit stored it, whatever changed since.
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;

        info!("Added {} principal for profile {}", principal_type, pid);
        // Its proof is shown only to the holder.
        Ok(AddPrincipalResponse {
            principal: principal_to_proto(&stored)?,
        })
    }

    pub async fn list_principals(
        &self,
        caller: &Caller,
        req: ListPrincipalsRequest,
    ) -> Result<ListPrincipalsResponse, IdentityError> {
        let pid = target_profile(caller, req.profile_id.as_ref())?;
        let principals = self.storage.get_principals_by_profile(pid).await?;
        Ok(ListPrincipalsResponse {
            principals: principals
                .iter()
                .map(principal_to_proto)
                .filter_map(Result::transpose)
                .collect::<Result<_, _>>()?,
        })
    }

    pub async fn remove_principal(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RemovePrincipalRequest,
    ) -> Result<RemovePrincipalResponse, IdentityError> {
        caller.require_interactive()?;
        let principal_id =
            PrincipalId(wire_id(req.principal_id.as_ref(), "principal_id")?.into_uuid());
        // A retry of a completed removal answers as it did, not as a principal
        // not found, and never removes a binding made again since.
        let command =
            KeyedCommand::by_profile::<keyed::RemovePrincipal>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                // A principal can be held by several accounts (contestation),
                // so the request removes one holder's binding: the caller's
                // own, or for an administrator the only holder's. The request
                // names no account, so an administrator cannot pick among
                // several holders.
                let bindings = self.storage.get_principal_bindings(principal_id).await?;
                let not_found = || IdentityError::PrincipalNotFound(principal_id);
                if bindings.is_empty() {
                    return Err(not_found().into());
                }
                let holder = match bindings.iter().find(|b| b.profile_id == caller.profile_id) {
                    Some(own) => own.profile_id,
                    // Held only by others: not found for a user, as an unknown one.
                    None => {
                        caller.require_admin().map_err(|_| not_found())?;
                        match bindings.as_slice() {
                            [only] => only.profile_id,
                            _ => return Err(IdentityError::SeveralHolders(principal_id).into()),
                        }
                    }
                };
                let response = RemovePrincipalResponse {};
                let ctx = MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "principal.delete",
                    principal_id.0.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                // A binding released meanwhile is no longer there to remove.
                if !self
                    .storage
                    .unbind_principal(principal_id, holder, ctx)
                    .await?
                {
                    return Err(not_found().into());
                }
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Sessions ────────────────────────────────────────────────────

    pub async fn list_sessions(
        &self,
        caller: &Caller,
        req: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, IdentityError> {
        let pid = target_profile(caller, req.profile_id.as_ref())?;
        let sessions = self.storage.list_sessions(&pid).await?;
        Ok(ListSessionsResponse {
            sessions: sessions
                .into_iter()
                .map(|s| Session {
                    id: Some(s.id.into()),
                    client_id: s.client_id.unwrap_or_default(),
                    // The stored value is the User-Agent fingerprint the
                    // new-device rule compares sign-ins by, never a
                    // registered Device; a session carries no managed device
                    // association, so it names none.
                    device_id: None,
                    ip_address: s.ip_address.map(|ip| ip.to_string()).unwrap_or_default(),
                    user_agent: s.user_agent,
                    created_at: Some(to_timestamp(s.created_at)),
                    expires_at: Some(to_timestamp(s.expires_at)),
                    last_activity_at: None,
                    scopes: vec![],
                })
                .collect(),
        })
    }

    /// End a session: only its owner or an administrator may. An ended
    /// session is already revoked: nothing to do, and nothing about it is
    /// disclosed.
    pub async fn revoke_session(
        &self,
        caller: &Caller,
        req: RevokeSessionRequest,
    ) -> Result<RevokeSessionResponse, IdentityError> {
        caller.require_interactive()?;
        let session_id: SessionId = wire_id(req.session_id.as_ref(), "session_id")?;
        let session = self.storage.get_session(session_id).await?;
        let Some(owner) = session.as_ref().map(|s| s.profile_id) else {
            return Ok(RevokeSessionResponse {});
        };
        caller.require_self_or_admin(owner)?;
        // Access tokens stop in every process, refresh tokens are revoked and
        // the session is deleted; its client logout and its revoked event are
        // committed with the deletion and delivered by the durable work runner.
        self.cascade
            .revoke_session(
                session_id,
                RevocationReason::UserRequested,
                &caller.profile_id.to_string(),
                "session.revoke",
            )
            .await
            .map_err(|e| internal("revoke session", e))?;
        info!("Revoked session {}", session_id);
        Ok(RevokeSessionResponse {})
    }

    // ── Passkey prompt ──────────────────────────────────────────────

    pub async fn passkey_prompt(
        &self,
        caller: &Caller,
    ) -> Result<GetPasskeyPromptStateResponse, IdentityError> {
        let stored = self.stored_passkey_prompt(caller.profile_id).await?;
        Ok(GetPasskeyPromptStateResponse {
            state: Some(self.passkey_prompt_state(caller.profile_id, stored).await?),
        })
    }

    pub async fn record_passkey_prompt_dismissal(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RecordPasskeyPromptDismissalRequest,
    ) -> Result<RecordPasskeyPromptDismissalResponse, IdentityError> {
        let profile_id = caller.profile_id;
        let policy = SecurityPolicy::ce_default();
        // One dismissal per operation key: a retry answers with the prompt as
        // the first commit left it and counts no second skip.
        let command = KeyedCommand::by_profile::<keyed::RecordPasskeyPromptDismissal>(
            profile_id, operation, &req,
        );
        command
            .execute(&*self.storage, || async {
                let updated = passkey_prompt::record_dismissal(
                    self.stored_passkey_prompt(profile_id).await?,
                    policy.passkey_prompt.skip_cooldown_days,
                );
                let metadata = ProfileMetadata::new(
                    profile_id,
                    passkey_prompt::PROFILE_METADATA_KEY,
                    serde_json::to_value(&updated)
                        .map_err(|e| internal("serialize passkey prompt state", e))?,
                );
                let response = RecordPasskeyPromptDismissalResponse {
                    state: Some(self.passkey_prompt_state(profile_id, Some(updated)).await?),
                };
                let ctx = MutationContext::from(AuditEntry::user(
                    profile_id.to_string(),
                    "passkey_prompt.dismiss",
                    profile_id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.set_profile_metadata(&metadata, ctx).await?;
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Revocation ──────────────────────────────────────────────────

    /// End everything a Profile holds. Named even by its owner: revocation
    /// ends every session of the Profile, so it is never implied by the
    /// caller's context.
    pub async fn revoke_profile(
        &self,
        caller: &Caller,
        req: RevokeProfileRequest,
    ) -> Result<RevokeProfileResponse, IdentityError> {
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        caller.require_self_or_admin(profile_id)?;
        caller.require_interactive()?;
        // The audit records the reason given; an unknown one is refused, not
        // recorded as another.
        let reason = match req.reason.as_str() {
            "" => return Err(IdentityError::MissingField("reason")),
            "user_requested" => RevocationReason::UserRequested,
            "admin" => RevocationReason::Admin,
            "emergency" => RevocationReason::Emergency,
            "anomaly_detected" => RevocationReason::AnomalyDetected,
            "expired" => RevocationReason::Expired,
            _ => {
                return Err(invalid_field(
                    "reason",
                    "one of user_requested, admin, emergency, anomaly_detected, expired",
                ));
            }
        };
        // An owner revokes their own profile as a user request; every other
        // reason is an administrative decision.
        if reason != RevocationReason::UserRequested {
            caller.require_admin()?;
        }
        let revocation = self
            .cascade
            .revoke_profile(profile_id, reason, &caller.profile_id.to_string())
            .await
            .map_err(|e| internal("revoke profile", e))?;
        info!(
            profile_id = %profile_id,
            entities_revoked = revocation.total_revoked(),
            "Profile revoked",
        );
        Ok(RevokeProfileResponse {
            entities_revoked: revocation.total_revoked() as i32,
        })
    }

    // ── Account closure ─────────────────────────────────────────────

    /// The user closes their own account, voluntarily or as a GDPR Art. 17
    /// request. Admin termination and regulatory-order closure act on another
    /// user's account under an organization's or a court's authority: they
    /// are never requested by the account holder.
    pub async fn request_closure(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: RequestClosureRequest,
    ) -> Result<RequestClosureResponse, IdentityError> {
        let caller_id = caller.profile_id;
        let mode = match req.mode() {
            ClosureMode::Voluntary => CoreClosureMode::Voluntary,
            ClosureMode::GdprErasure => CoreClosureMode::GdprErasure,
            ClosureMode::AdminTermination => {
                return Err(IdentityError::NotInThisBuild("admin_termination"));
            }
            ClosureMode::RegulatoryOrder => {
                return Err(IdentityError::NotInThisBuild("regulatory_order_closure"));
            }
            ClosureMode::Unspecified => return Err(IdentityError::MissingField("mode")),
        };
        let operation = required(operation)?;
        let answer = |closure: &sid_core::models::ClosureRequest| RequestClosureResponse {
            mode: req.mode,
            grace_period_end: closure.grace_period_end.map(to_timestamp),
        };
        // A retry of a completed request answers with the closure it started,
        // its grace period unchanged, and is never refused as a profile
        // already closing.
        let command = KeyedCommand::by_profile::<keyed::RequestClosure>(caller_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let closure = self
                    .closure
                    .request_closure(caller_id, mode, caller_id, |closure| {
                        Some(command.completion(answer(closure).encode_to_vec()))
                    })
                    .await
                    .map_err(|e| {
                        account_effect(
                            "request closure",
                            AccountRecord::Closure,
                            false,
                            caller_id,
                            e,
                        )
                    })?;
                Ok(answer(&closure))
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn cancel_closure(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CancelClosureRequest,
    ) -> Result<CancelClosureResponse, IdentityError> {
        let caller_id = caller.profile_id;
        // A retry of a completed cancellation answers as it did and never
        // cancels a closure requested again since.
        let command = KeyedCommand::by_profile::<keyed::CancelClosure>(caller_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let response = CancelClosureResponse {};
                self.closure
                    .cancel_closure(
                        caller_id,
                        caller_id,
                        Some(command.completion(response.encode_to_vec())),
                    )
                    .await
                    .map_err(|e| {
                        account_effect("cancel closure", AccountRecord::Closure, true, caller_id, e)
                    })?;
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn closure_status(
        &self,
        caller: &Caller,
    ) -> Result<GetClosureStatusResponse, IdentityError> {
        let closure = self
            .closure
            .get_closure_status(caller.profile_id)
            .await
            .map_err(|e| internal("get closure status", e))?;
        Ok(match closure {
            Some(req) => GetClosureStatusResponse {
                has_active_closure: true,
                mode: match req.mode {
                    CoreClosureMode::Voluntary => ClosureMode::Voluntary,
                    CoreClosureMode::GdprErasure => ClosureMode::GdprErasure,
                    CoreClosureMode::AdminTermination => ClosureMode::AdminTermination,
                    CoreClosureMode::RegulatoryOrder => ClosureMode::RegulatoryOrder,
                }
                .into(),
                export_status: export_status_to_proto(&req.export_status).into(),
                grace_period_end: req.grace_period_end.map(to_timestamp),
                requested_at: Some(to_timestamp(req.requested_at)),
                cancel_count: req.cancel_count as i32,
            },
            None => GetClosureStatusResponse {
                has_active_closure: false,
                mode: ClosureMode::Unspecified.into(),
                export_status: sid_proto::sid::v1::ExportStatus::NotStarted.into(),
                grace_period_end: None,
                requested_at: None,
                cancel_count: 0,
            },
        })
    }

    // ── Data export (GDPR Art. 20) ──────────────────────────────────

    pub async fn prepare_export(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: PrepareExportRequest,
    ) -> Result<PrepareExportResponse, IdentityError> {
        let caller_id = caller.profile_id;
        // CE only supports JSON.
        let format = sid_core::models::ExportFormat::Json;
        let answer = |job: &sid_core::models::ExportJob| PrepareExportResponse {
            estimated_ready: Some(to_timestamp(job.created_at)),
        };
        // A retry of a completed preparation answers with the export it
        // created and prepares no other.
        let command = KeyedCommand::by_profile::<keyed::PrepareExport>(caller_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let job = self
                    .export
                    .prepare_export(caller_id, format, &caller_id.to_string(), |job| {
                        Some(command.completion(answer(job).encode_to_vec()))
                    })
                    .await
                    .map_err(|e| {
                        account_effect("prepare export", AccountRecord::Export, false, caller_id, e)
                    })?;
                Ok(answer(&job))
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn export_status(
        &self,
        caller: &Caller,
    ) -> Result<GetExportStatusResponse, IdentityError> {
        let job = self
            .export
            .get_export_status(caller.profile_id)
            .await
            .map_err(|e| internal("get export status", e))?;
        Ok(match job {
            Some(j) => GetExportStatusResponse {
                export_status: export_status_to_proto(&j.status).into(),
                size_bytes: j.size_bytes,
                // Stored hex-encoded; a value that does not decode is corruption.
                checksum_sha256: j
                    .checksum_sha256
                    .as_deref()
                    .map(hex::decode)
                    .transpose()
                    .map_err(|e| internal("stored export checksum", e))?,
                ready_at: j.ready_at.map(to_timestamp),
                expires_at: j.expires_at.map(to_timestamp),
            },
            None => GetExportStatusResponse {
                export_status: sid_proto::sid::v1::ExportStatus::NotStarted.into(),
                size_bytes: None,
                checksum_sha256: None,
                ready_at: None,
                expires_at: None,
            },
        })
    }

    /// The caller's ready export archive, read whole for download.
    pub async fn export_archive(&self, caller: &Caller) -> Result<ExportArchive, IdentityError> {
        let caller_id = caller.profile_id;
        let (data, job) = self
            .export
            .read_export_archive(caller_id)
            .await
            .map_err(|e| {
                account_refusal("download export", AccountRecord::Export, true, caller_id, e)
            })?;
        Ok(ExportArchive { data, job })
    }

    pub async fn acknowledge_export(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AcknowledgeExportRequest,
    ) -> Result<(), IdentityError> {
        let caller_id = caller.profile_id;
        // A retry of a completed acknowledgement answers as it did, not as an
        // export no longer ready.
        let command =
            KeyedCommand::by_profile::<keyed::AcknowledgeExport>(caller_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                self.export
                    .acknowledge_export(
                        caller_id,
                        &caller_id.to_string(),
                        Some(command.completion(().encode_to_vec())),
                    )
                    .await
                    .map_err(|e| {
                        account_effect(
                            "acknowledge export",
                            AccountRecord::Export,
                            true,
                            caller_id,
                            e,
                        )
                    })
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Devices ─────────────────────────────────────────────────────

    /// The caller's own devices only.
    pub async fn list_devices(
        &self,
        caller: &Caller,
        req: ListDevicesRequest,
    ) -> Result<ListDevicesResponse, IdentityError> {
        let profile_id = target_profile(caller, req.profile_id.as_ref())?;
        if profile_id != caller.profile_id {
            return Err(IdentityError::OtherProfileDevices);
        }
        let devices = self.storage.list_devices_by_profile(profile_id).await?;
        Ok(ListDevicesResponse {
            devices: devices.iter().map(device_to_proto).collect(),
        })
    }

    pub async fn get_device(
        &self,
        caller: &Caller,
        req: GetDeviceRequest,
    ) -> Result<sid_proto::sid::v1::Device, IdentityError> {
        let device_id = device_id(req.device_id.as_ref())?;
        Ok(device_to_proto(
            &self.owned_device(caller.profile_id, device_id).await?,
        ))
    }

    /// Rename a device; the identifier is checked before the context.
    pub async fn update_device(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: UpdateDeviceRequest,
    ) -> Result<sid_proto::sid::v1::Device, IdentityError> {
        let caller_id = caller.profile_id;
        let device_id = device_id(req.device_id.as_ref())?;
        let command =
            KeyedCommand::by_profile::<keyed::UpdateDevice>(caller_id, required(operation)?, &req);
        let audit = || {
            AuditEntry::user(
                caller_id.to_string(),
                "device.update",
                device_id.to_string(),
            )
        };
        let Some(name) = req.display_name.clone() else {
            // Nothing to write: the device as it is, recorded as this
            // command's outcome so its retry answers the same.
            let device: sid_core::models::Device = command
                .unchanged_recorded(&*self.storage, audit(), || {
                    self.owned_device(caller_id, device_id)
                })
                .await
                .map_err(CommandError::refusal)?;
            return Ok(device_to_proto(&device));
        };
        // Only the name is written: a trust change or removal made meanwhile
        // is never undone by this copy, nor a later rename by a retry, which
        // answers with the device as the first commit left it.
        let device: sid_core::models::Device = command
            .execute_recorded(&*self.storage, || async {
                self.owned_device(caller_id, device_id).await?;
                let ctx =
                    MutationContext::from(audit()).with_operation(command.effect_completion());
                if !self
                    .storage
                    .rename_device(device_id, Some(&name), ctx)
                    .await?
                {
                    return Err(IdentityError::DeviceNotFound(device_id).into());
                }
                // The device as this commit left it, whatever changed since.
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;
        Ok(device_to_proto(&device))
    }

    /// Remove a device; the identifier is checked before the context.
    pub async fn remove_device(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: RemoveDeviceRequest,
    ) -> Result<(), IdentityError> {
        let caller_id = caller.profile_id;
        let device_id = device_id(req.device_id.as_ref())?;
        // A retry of a completed removal answers as it did, not as a device
        // not found.
        let command =
            KeyedCommand::by_profile::<keyed::RemoveDevice>(caller_id, required(operation)?, &req);
        command
            .execute(&*self.storage, || async {
                self.owned_device(caller_id, device_id).await?;
                // The audit names the user who removed it, not the system.
                let ctx = MutationContext::from(AuditEntry::user(
                    caller_id.to_string(),
                    "device.remove",
                    device_id.to_string(),
                ))
                .with_operation(command.completion(().encode_to_vec()));
                self.storage.delete_device(device_id, ctx).await?;
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)?;
        info!(device_id = %device_id, "Device removed");
        Ok(())
    }

    pub async fn trust_device(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: TrustDeviceRequest,
    ) -> Result<sid_proto::sid::v1::Device, IdentityError> {
        let device_id = device_id(req.device_id.as_ref())?;
        let command = KeyedCommand::by_profile::<keyed::TrustDevice>(
            caller.profile_id,
            required(operation)?,
            &req,
        );
        self.change_device_trust(caller.profile_id, &command, device_id, true)
            .await
    }

    pub async fn revoke_device_trust(
        &self,
        caller: &Caller,
        operation: Option<OperationContext>,
        req: RevokeDeviceTrustRequest,
    ) -> Result<sid_proto::sid::v1::Device, IdentityError> {
        let device_id = device_id(req.device_id.as_ref())?;
        let command = KeyedCommand::by_profile::<keyed::RevokeDeviceTrust>(
            caller.profile_id,
            required(operation)?,
            &req,
        );
        self.change_device_trust(caller.profile_id, &command, device_id, false)
            .await
    }

    /// Trust or distrust one of the caller's devices, once per operation key:
    /// a retry answers with the device as the first commit left it and never
    /// undoes a later change. The trusted-device limit is checked by the store
    /// in the same transaction as the change.
    async fn change_device_trust(
        &self,
        caller_id: ProfileId,
        command: &KeyedCommand,
        device_id: DeviceId,
        trusted: bool,
    ) -> Result<sid_proto::sid::v1::Device, IdentityError> {
        use sid_core::models::{DeviceTrustChange, device::MAX_TRUSTED_DEVICES};
        let action = if trusted {
            "device.trust"
        } else {
            "device.revoke_trust"
        };
        let device: sid_core::models::Device = command
            .execute_recorded(&*self.storage, || async {
                self.owned_device(caller_id, device_id).await?;
                let ctx = MutationContext::from(AuditEntry::user(
                    caller_id.to_string(),
                    action,
                    device_id.to_string(),
                ))
                .with_operation(command.effect_completion());
                match self
                    .storage
                    .set_device_trust(device_id, trusted, MAX_TRUSTED_DEVICES, ctx)
                    .await?
                {
                    DeviceTrustChange::Changed => {
                        info!(device_id = %device_id, trusted, "Device trust changed")
                    }
                    DeviceTrustChange::Unchanged => {}
                    DeviceTrustChange::NotFound => {
                        return Err(IdentityError::DeviceNotFound(device_id).into());
                    }
                    DeviceTrustChange::LimitReached => {
                        return Err(IdentityError::TrustedDeviceLimit.into());
                    }
                }
                // The device as this commit left it, whatever changed since.
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;
        Ok(device_to_proto(&device))
    }
}

#[cfg(test)]
mod tests;
