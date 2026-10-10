// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC IdentityService implementation.
//!
//! Mirrors the REST profile/session/credential handlers using the same
//! storage backend and business logic.

use crate::feature_flags::FeatureFlagService;
use sid_authn::account_closure::AccountClosureService;
use sid_authn::caller::{Caller, authenticate};
use sid_authn::data_export::DataExportService;
use sid_authn::jwt::JwtService;
use sid_authn::passkey_prompt;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::registration::parse_e164;
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{
    AuditEntry, ClosureMode as CoreClosureMode, CredentialId, CredentialType as CoreCredType,
    DeviceId, Profile, ProfileEmail, ProfileId, ProfileMetadata, ProfilePhone, RegistrationSource,
    RevocationReason, SessionId,
};
use sid_core::models::{ContestCheck, MutationContext, NewRegistration};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

use super::convert;
use sid_core::grpc_error::refuse::{
    changed_concurrently, internal, invalid_field, maintenance, missing_field, not_configured,
    not_found, not_in_this_build, storage_failure,
};

/// Profiles per ListProfiles page when the request names no size.
const DEFAULT_PROFILE_PAGE: u64 = 50;
/// The largest ListProfiles page; a bigger request gets this many.
const MAX_PROFILE_PAGE: i32 = 500;

/// PROFILE_NOT_FOUND for `id` (a profile id, or the kind of handle an
/// administrator looked the account up by).
fn profile_not_found(id: impl Into<String>) -> Status {
    not_found(ErrorReason::ProfileNotFound, "Profile", id)
}

/// CREDENTIAL_NOT_FOUND for `id`.
fn credential_not_found(id: CredentialId) -> Status {
    not_found(
        ErrorReason::CredentialNotFound,
        "Credential",
        id.0.to_string(),
    )
}

#[allow(clippy::result_large_err)]
fn parse_credential_id(s: &str) -> Result<CredentialId, Status> {
    uuid::Uuid::parse_str(s)
        .map(CredentialId)
        .map_err(|_| invalid_field("credential_id", "not a credential identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_device_id(s: &str) -> Result<DeviceId, Status> {
    s.parse::<DeviceId>()
        .map_err(|_| invalid_field("device_id", "not a device identifier"))
}

/// DEVICE_NOT_FOUND for `id`: also the answer for another profile's device,
/// so a caller learns nothing about devices that are not theirs.
fn device_not_found(id: DeviceId) -> Status {
    not_found(ErrorReason::DeviceNotFound, "Device", id.to_string())
}

/// A handle or contact of `principal_type` is held by another account.
fn contact_taken(principal_type: sid_core::models::PrincipalType) -> Status {
    use sid_core::models::PrincipalType;
    let reason = match principal_type {
        PrincipalType::Username => ErrorReason::UsernameAlreadyTaken,
        PrincipalType::Email => ErrorReason::EmailAlreadyRegistered,
        PrincipalType::Phone => ErrorReason::PhoneAlreadyRegistered,
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag => ErrorReason::PrincipalAlreadyHeld,
    };
    let field = principal_type.as_str();
    ApiError::new(
        reason,
        format!("the {field} is registered to another account"),
    )
    .with_resource("Principal", field)
    .into()
}

/// `input` of the request field `field` as the login handle of
/// `expected` kind it must be; anything else names the field.
#[allow(clippy::result_large_err)]
fn login_handle(
    field: &'static str,
    input: &str,
    expected: sid_core::models::PrincipalType,
) -> Result<sid_authn::normalize::NormalizedPrincipal, Status> {
    let handle = sid_authn::normalize::normalize_principal(input)
        .map_err(|e| invalid_field(field, e.to_string()))?;
    if handle.principal_type.to_principal_type() != expected {
        return Err(invalid_field(field, format!("not a {field}")));
    }
    Ok(handle)
}

/// What a closure or export operation acts on, for its refusals: the
/// precondition type of a wrong state (`CLOSURE_STATE`, `EXPORT_STATE`) and,
/// where the operation needs an existing record, its NOT_FOUND reason and
/// resource type.
struct AccountRecord {
    state: &'static str,
    missing: Option<(ErrorReason, &'static str)>,
}

const CLOSURE: AccountRecord = AccountRecord {
    state: "CLOSURE_STATE",
    missing: None,
};
const CLOSURE_TO_CANCEL: AccountRecord = AccountRecord {
    state: "CLOSURE_STATE",
    missing: Some((ErrorReason::ClosureRequestNotFound, "ClosureRequest")),
};
const NEW_EXPORT: AccountRecord = AccountRecord {
    state: "EXPORT_STATE",
    missing: None,
};
const EXPORT: AccountRecord = AccountRecord {
    state: "EXPORT_STATE",
    missing: Some((ErrorReason::ExportNotFound, "Export")),
};

/// The closure and export services' refusals of `owner`'s own account, by
/// cause. A missing record the operation needs is NOT_FOUND; a missing record
/// anywhere else (the caller's own profile) is internal, as is any other
/// failure.
fn account_refusal(
    operation: &'static str,
    record: AccountRecord,
    owner: ProfileId,
    e: sid_core::Error,
) -> Status {
    match (e, record.missing) {
        (sid_core::Error::NotFound(_), Some((reason, resource_type))) => {
            not_found(reason, resource_type, owner.to_string())
        }
        (sid_core::Error::InvalidState(why), _) => ApiError::new(
            ErrorReason::InvalidState,
            "the account is not in a state that allows this",
        )
        .with_precondition(record.state, owner.to_string(), why)
        .into(),
        (sid_core::Error::RateLimited(_), _) => ApiError::new(
            ErrorReason::QuotaExceeded,
            "the yearly limit of cancelled closures is reached",
        )
        .with_quota_violation(
            "closure_cancellations",
            format!(
                "at most {} cancelled closures per year",
                sid_core::models::MAX_CANCEL_CYCLES_PER_YEAR
            ),
        )
        .into(),
        (e, _) => internal(operation, e),
    }
}

pub struct IdentityServiceImpl {
    pub(crate) storage: Arc<dyn StorageBackend>,
    pub(crate) jwt: Arc<JwtService>,
    pub(crate) revocation_cache: Arc<RevocationCache>,
    pub(crate) feature_flags: FeatureFlagService,
    pub(crate) cascade_service: Arc<RevocationCascadeService>,
    pub(crate) closure_service: Arc<AccountClosureService>,
    pub(crate) data_export: Arc<DataExportService>,
}

impl IdentityServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation_cache: Arc<RevocationCache>,
        feature_flags: FeatureFlagService,
        cascade_service: Arc<RevocationCascadeService>,
        closure_service: Arc<AccountClosureService>,
        data_export: Arc<DataExportService>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation_cache,
            feature_flags,
            cascade_service,
            closure_service,
            data_export,
        }
    }

    /// The authenticated caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation_cache).await
    }

    /// `profile_id`'s email contact spelled exactly `address`, created
    /// (unverified, not primary) when it has none.
    async fn email_contact(
        &self,
        profile_id: ProfileId,
        address: &str,
    ) -> Result<ProfileEmail, Status> {
        let contacts = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;
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
            .await
            .map_err(storage_failure)?;
        Ok(contact)
    }

    /// When `key` is a quarantined email key of `profile_id` (written before
    /// email policy revisions, its address unknown), repair it on the address
    /// `email` the caller gives. Only an administrator's assertion, within
    /// the installation's authority over its managed accounts, establishes
    /// the address here; the owner confirms it instead, so an owner gets
    /// FAILED_PRECONDITION. `None` when the key is not such a key.
    async fn repair_quarantined_email(
        &self,
        caller: &Caller,
        profile_id: ProfileId,
        key: &str,
        email: &sid_authn::email::EmailHandle,
    ) -> Result<Option<sid_core::models::Principal>, Status> {
        use sid_core::models::PrincipalType;

        let Some(existing) = self
            .storage
            .get_principal_by_value(PrincipalType::Email, key)
            .await
            .map_err(storage_failure)?
        else {
            return Ok(None);
        };
        if existing.email_policy_revision == Some(email.revision)
            || existing.assigned_profile_id != Some(profile_id)
        {
            return Ok(None);
        }
        if !caller.is_admin() {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "this address must be confirmed before it signs in again",
            )
            .with_precondition(
                "EMAIL_ADDRESS_UNCONFIRMED",
                "principal",
                "confirm the address from the account",
            )
            .into());
        }
        let contact = self.email_contact(profile_id, &email.delivery).await?;
        let repaired = self
            .storage
            .reconcile_email_key(
                existing.id,
                profile_id,
                &contact,
                "administrator_asserted",
                AuditEntry::user(
                    caller.profile_id.to_string(),
                    "principal.email_repaired",
                    existing.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !repaired {
            return Err(changed_concurrently());
        }
        self.storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .find(|p| p.principal_type == PrincipalType::Email && p.value == key)
            .map(Some)
            .ok_or_else(|| internal("repair email", "repaired principal missing"))
    }

    /// A profile's primary email and phone for a profile read; a failed read
    /// fails the RPC rather than answer as if the profile had none.
    async fn primary_contacts(
        &self,
        profile_id: ProfileId,
    ) -> Result<(Option<ProfileEmail>, Option<ProfilePhone>), Status> {
        let email = self
            .storage
            .get_primary_profile_email(profile_id)
            .await
            .map_err(storage_failure)?;
        let phone = self
            .storage
            .get_primary_profile_phone(profile_id)
            .await
            .map_err(storage_failure)?;
        Ok((email, phone))
    }

    /// The contacts echoed after a write that has already committed: a failed
    /// read leaves them out of the response (logged) instead of reporting the
    /// committed write as failed, which a retry would then repeat.
    async fn contacts_after_write(
        &self,
        profile_id: ProfileId,
    ) -> (Option<ProfileEmail>, Option<ProfilePhone>) {
        let email = self
            .storage
            .get_primary_profile_email(profile_id)
            .await
            .unwrap_or_else(|e| {
                warn!(profile = %profile_id, error = %e, "primary email left out of the response");
                None
            });
        let phone = self
            .storage
            .get_primary_profile_phone(profile_id)
            .await
            .unwrap_or_else(|e| {
                warn!(profile = %profile_id, error = %e, "primary phone left out of the response");
                None
            });
        (email, phone)
    }

    /// Trust or distrust one of the caller's devices. The trusted-device limit
    /// is checked by the store in the same transaction as the change.
    async fn change_device_trust(
        &self,
        caller_id: ProfileId,
        device_id: sid_core::models::DeviceId,
        trusted: bool,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        use sid_core::models::{DeviceTrustChange, device::MAX_TRUSTED_DEVICES};
        self.owned_device(caller_id, device_id).await?;
        let action = if trusted {
            "device.trust"
        } else {
            "device.revoke_trust"
        };
        match self
            .storage
            .set_device_trust(
                device_id,
                trusted,
                MAX_TRUSTED_DEVICES,
                AuditEntry::user(caller_id.to_string(), action, device_id.to_string()).into(),
            )
            .await
            .map_err(storage_failure)?
        {
            DeviceTrustChange::Changed => {
                info!(device_id = %device_id, trusted, "Device trust changed")
            }
            DeviceTrustChange::Unchanged => {}
            DeviceTrustChange::NotFound => return Err(device_not_found(device_id)),
            DeviceTrustChange::LimitReached => {
                return Err(ApiError::new(
                    ErrorReason::QuotaExceeded,
                    "the limit of trusted devices is reached",
                )
                .with_quota_violation(
                    "trusted_devices",
                    format!("at most {MAX_TRUSTED_DEVICES} trusted devices per profile"),
                )
                .into());
            }
        }
        let device = self.owned_device(caller_id, device_id).await?;
        Ok(Response::new(convert::device_to_proto(&device)))
    }

    /// Credential `id` if the caller may see it (their own, or any for an
    /// administrator); another profile's is not found, as an unknown one.
    async fn visible_credential(
        &self,
        caller: &Caller,
        id: CredentialId,
    ) -> Result<sid_core::models::Credential, Status> {
        self.storage
            .get_credential(id)
            .await
            .map_err(storage_failure)?
            .filter(|c| caller.require_self_or_admin(c.profile_id).is_ok())
            .ok_or_else(|| credential_not_found(id))
    }

    /// The caller's device `device_id`; another profile's is not found.
    async fn owned_device(
        &self,
        caller_id: ProfileId,
        device_id: DeviceId,
    ) -> Result<sid_core::models::Device, Status> {
        self.storage
            .get_device(device_id)
            .await
            .map_err(storage_failure)?
            .filter(|d| d.profile_id == caller_id)
            .ok_or_else(|| device_not_found(device_id))
    }

    /// Build PasskeyPromptState proto from business logic.
    async fn build_passkey_prompt_state(
        &self,
        profile_id: ProfileId,
    ) -> Result<sid_proto::sid::v1::PasskeyPromptState, Status> {
        let policy = SecurityPolicy::ce_default();
        let config = &policy.passkey_prompt;

        // A failed read fails the call: answering "no passkey" would prompt,
        // or under Required demand, a passkey the profile already has.
        let has_passkey = !self
            .storage
            .get_credentials_by_profile(profile_id, Some(CoreCredType::WebAuthn))
            .await
            .map_err(storage_failure)?
            .is_empty();

        // Load prompt state from ProfileMetadata.
        let stored_state = self
            .storage
            .get_profile_metadata(profile_id, passkey_prompt::PROFILE_METADATA_KEY)
            .await
            .map_err(storage_failure)?
            .and_then(|m| {
                serde_json::from_value::<passkey_prompt::PasskeyPromptState>(m.value).ok()
            });

        let decision = passkey_prompt::decide(config, stored_state.as_ref(), has_passkey);

        let mode = match config.mode {
            sid_core::models::security_policy::PasskeyPromptMode::Encouraged => {
                sid_proto::sid::v1::PasskeyPromptMode::Encouraged.into()
            }
            sid_core::models::security_policy::PasskeyPromptMode::Required => {
                sid_proto::sid::v1::PasskeyPromptMode::Required.into()
            }
            sid_core::models::security_policy::PasskeyPromptMode::None => {
                sid_proto::sid::v1::PasskeyPromptMode::None.into()
            }
        };

        Ok(sid_proto::sid::v1::PasskeyPromptState {
            mode,
            decision: decision.as_str().to_string(),
            skip_count: stored_state.as_ref().map_or(0, |s| s.skip_count),
            skip_limit: config.skip_limit,
            has_passkey,
        })
    }
}

#[tonic::async_trait]
impl IdentityService for IdentityServiceImpl {
    #[tracing::instrument(skip_all, fields(rpc = "create_profile"))]
    #[instrument(skip_all, fields(method = "create_profile"))]
    async fn create_profile(
        &self,
        request: Request<CreateProfileRequest>,
    ) -> Result<Response<CreateProfileResponse>, Status> {
        // Provisioning an account for someone else is an administrator action;
        // self-registration goes through the registration ceremonies.
        let caller = self.caller(&request).await?;
        caller.require_admin()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        if !self.feature_flags.is_registration_enabled().await {
            return Err(not_configured("registration"));
        }

        use sid_core::models::PrincipalType;

        let req = request.into_inner();

        // Administrator provisioning is allowed in every enrollment mode: the
        // mode governs self-registration only, and no invite is spent here.
        //
        // D013: one signup principal, the username when given, else the
        // email, else the phone; the other contacts are stored unverified.
        // Username is a VALUABLE identity — never auto-generated.
        // Each given contact as the login handle it would be: the key a
        // principal stores and lookups use, and for an email the validated
        // address its contact stores.
        let provided_username = req
            .username
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| login_handle("username", s, PrincipalType::Username))
            .transpose()?;
        let provided_email = req
            .email
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| login_handle("email", s, PrincipalType::Email))
            .transpose()?;
        let provided_phone = req
            .phone
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| login_handle("phone", s, PrincipalType::Phone))
            .transpose()?;
        let signup = match (&provided_username, &provided_email, &provided_phone) {
            (Some(username), _, _) => username,
            (None, Some(email), _) => email,
            (None, None, Some(phone)) => phone,
            (None, None, None) => {
                return Err(ApiError::new(
                    ErrorReason::RequiredFieldMissing,
                    "a username, email or phone is required",
                )
                .with_field_violation("username", "one of username, email, phone is required")
                .with_field_violation("email", "one of username, email, phone is required")
                .with_field_violation("phone", "one of username, email, phone is required")
                .into());
            }
        };

        // Contacts already on another account are refused with the reason the
        // UI shows; the principal's unique key settles a race below.
        // A username is also the profile's own name: held either way.
        if let Some(username) = &provided_username
            && self
                .storage
                .get_profile_by_username(&username.normalized)
                .await
                .map_err(storage_failure)?
                .is_some()
        {
            return Err(contact_taken(PrincipalType::Username));
        }
        for handle in [&provided_username, &provided_email, &provided_phone]
            .into_iter()
            .flatten()
        {
            let principal_type = handle.principal_type.to_principal_type();
            if self
                .storage
                .get_principal_by_value(principal_type, &handle.normalized)
                .await
                .map_err(storage_failure)?
                .is_some()
            {
                return Err(contact_taken(principal_type));
            }
        }

        let mut profile = Profile::new(provided_username.as_ref().map(|u| u.normalized.as_str()));
        profile.given_name = req.given_name;
        profile.family_name = req.family_name;
        profile.middle_name = req.middle_name;
        profile.honorific_prefix = req.honorific_prefix;
        profile.honorific_suffix = req.honorific_suffix;

        let principal_type = signup.principal_type.to_principal_type();
        let principal_field = match principal_type {
            PrincipalType::Username => "username",
            PrincipalType::Email => "email",
            _ => "phone",
        };
        let identifier = super::auth_service::signup_identifier(
            principal_type,
            &signup.normalized,
            signup.email.as_ref(),
        )?;
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
        // Where the account came from is stored with it.
        if SecurityPolicy::ce_default().enrollment.track_source {
            let mut source = RegistrationSource::admin_created(caller.profile_id);
            if let Some(referrer) = &req.referrer_id {
                let rid = ProfileId::parse(referrer)
                    .map_err(|_| invalid_field("referrer_id", "not a profile identifier"))?;
                if self
                    .storage
                    .get_profile(rid)
                    .await
                    .map_err(storage_failure)?
                    .is_none()
                {
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
            registration = registration.with_source(source);
        }
        let profile = registration.profile.clone();

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
        let ctx = MutationContext::from(AuditEntry::user(
            caller.profile_id.to_string(),
            "profile.create",
            profile.id.to_string(),
        ))
        .with_work(created.relay());
        match self.storage.register_profile(&registration, ctx).await {
            Ok(()) => {}
            Err(sid_core::Error::Conflict(_)) => return Err(contact_taken(principal_type)),
            Err(e) => return Err(storage_failure(e)),
        }

        info!(
            "Created profile {} ({})",
            profile.username.as_deref().unwrap_or("<no username>"),
            profile.id
        );

        let (primary_email, _) = self.contacts_after_write(profile.id).await;
        Ok(Response::new(CreateProfileResponse {
            profile: Some(convert::profile_to_proto_with_contacts(
                &profile,
                primary_email.as_ref(),
                None,
            )),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_profile"))]
    #[instrument(skip_all, fields(method = "get_profile"))]
    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();

        // A user reads only their own profile by id; looking an account up by
        // username or email is an administrator action (it tells whether the
        // account exists).
        let (named, profile) = match req.identifier {
            Some(get_profile_request::Identifier::Id(id)) => {
                let pid = convert::parse_profile_id(&id)?;
                caller.require_self_or_admin(pid)?;
                (id, self.storage.get_profile(pid).await)
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
            None => return Err(missing_field("identifier")),
        };

        let p = profile
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(named))?;
        let (primary_email, primary_phone) = self.primary_contacts(p.id).await?;
        Ok(Response::new(GetProfileResponse {
            profile: Some(convert::profile_to_proto_with_contacts(
                &p,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_profile"))]
    #[instrument(skip_all, fields(method = "update_profile"))]
    async fn update_profile(
        &self,
        request: Request<UpdateProfileRequest>,
    ) -> Result<Response<UpdateProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let pid = convert::parse_profile_id(&req.id)?;
        caller.require_self_or_admin(pid)?;

        let mut profile = self
            .storage
            .get_profile(pid)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(req.id.clone()))?;

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
        .with_work(changed.relay());
        // Over the revision read above, so the names written here never carry
        // back a status or role changed meanwhile (a suspension stays).
        let updated = self
            .storage
            .update_profile(&profile, ctx)
            .await
            .map_err(storage_failure)?;
        if !updated {
            return Err(changed_concurrently());
        }
        profile.revision += 1;

        let (primary_email, primary_phone) = self.contacts_after_write(profile.id).await;
        Ok(Response::new(UpdateProfileResponse {
            profile: Some(convert::profile_to_proto_with_contacts(
                &profile,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "delete_profile"))]
    #[instrument(skip_all, fields(method = "delete_profile"))]
    async fn delete_profile(
        &self,
        request: Request<DeleteProfileRequest>,
    ) -> Result<Response<DeleteProfileResponse>, Status> {
        // Hard deletion is an administrator action; a user closes their own
        // account through the closure flow.
        let caller = self.caller(&request).await?;
        caller.require_admin()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let pid = convert::parse_profile_id(&req.id)?;

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
        .with_work(deleted.relay());
        // The owner's history keys go with it, owed in the same transaction.
        if let Some(purge) = super::password_operation::owner_purge(self.storage.as_ref(), pid)
            .await
            .map_err(storage_failure)?
        {
            ctx = ctx.with_work(purge);
        }
        self.storage
            .delete_profile(pid, ctx)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(DeleteProfileResponse {}))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_profiles"))]
    #[instrument(skip_all, fields(method = "list_profiles"))]
    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesResponse>, Status> {
        self.caller(&request).await?.require_admin()?;
        let req = request.into_inner();
        let limit: u64 = if req.page_size > 0 {
            req.page_size.min(MAX_PROFILE_PAGE) as u64
        } else {
            DEFAULT_PROFILE_PAGE
        };
        // An empty token is the first page; any other token is one this
        // service issued (an offset), never silently reset to the first page.
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

        let profiles = self
            .storage
            .list_profiles(offset, limit)
            .await
            .map_err(storage_failure)?;

        // A full page may have a next one; an offset past BIGINT has none.
        let next_page_token = offset
            .checked_add(limit)
            .filter(|next| profiles.len() as u64 == limit && i64::try_from(*next).is_ok())
            .map(|next| next.to_string())
            .unwrap_or_default();
        Ok(Response::new(ListProfilesResponse {
            profiles: profiles.iter().map(convert::profile_to_proto).collect(),
            next_page_token,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "add_credential"))]
    #[instrument(skip_all, fields(method = "add_credential"))]
    async fn add_credential(
        &self,
        _request: Request<AddCredentialRequest>,
    ) -> Result<Response<AddCredentialResponse>, Status> {
        // Credentials are added only through their registration ceremonies
        // (OPAQUE, WebAuthn, TOTP enrollment), which prove the factor.
        Err(not_in_this_build("add_credential"))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_credentials"))]
    #[instrument(skip_all, fields(method = "list_credentials"))]
    async fn list_credentials(
        &self,
        request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();
        let pid = convert::parse_profile_id(&req.profile_id)?;
        caller.require_self_or_admin(pid)?;

        let creds = self
            .storage
            .get_credentials_by_profile(pid, None)
            .await
            .map_err(storage_failure)?;

        let infos = creds
            .iter()
            .map(convert::credential_info)
            .collect::<Result<Vec<_>, Status>>()?;

        Ok(Response::new(ListCredentialsResponse {
            credentials: creds
                .into_iter()
                .zip(infos)
                .map(|(c, info)| Credential {
                    id: c.id.0.to_string(),
                    profile_id: c.profile_id.to_string(),
                    r#type: match c.credential_type {
                        sid_core::models::CredentialType::Opaque => CredentialType::Opaque.into(),
                        sid_core::models::CredentialType::WebAuthn => {
                            CredentialType::Webauthn.into()
                        }
                        sid_core::models::CredentialType::Totp => CredentialType::Totp.into(),
                        sid_core::models::CredentialType::Recovery => {
                            CredentialType::Recovery.into()
                        }
                        sid_core::models::CredentialType::LegacyHash => {
                            CredentialType::LegacyHash.into()
                        }
                    },
                    data: vec![], // Never expose raw credential data over gRPC
                    label: c.label,
                    created_at: Some(convert::to_timestamp(c.created_at)),
                    last_used_at: c.last_used_at.map(convert::to_timestamp),
                    info,
                })
                .collect(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_credential"))]
    #[instrument(skip_all, fields(method = "update_credential"))]
    async fn update_credential(
        &self,
        request: Request<UpdateCredentialRequest>,
    ) -> Result<Response<UpdateCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let cred_id = parse_credential_id(&req.credential_id)?;
        let mut cred = self.visible_credential(&caller, cred_id).await?;

        if let Some(label) = req.label {
            // A revoked credential is gone for its owner: renaming it neither
            // succeeds nor revives it.
            let renamed = self
                .storage
                .set_credential_label(
                    cred.id,
                    Some(&label),
                    AuditEntry::user(
                        caller.profile_id.to_string(),
                        "credential.update",
                        cred.id.0.to_string(),
                    )
                    .into(),
                )
                .await
                .map_err(storage_failure)?;
            if !renamed {
                return Err(credential_not_found(cred.id));
            }
            cred.label = Some(label);
        }
        let info = convert::credential_info(&cred)?;

        Ok(Response::new(UpdateCredentialResponse {
            credential: Some(Credential {
                id: cred.id.0.to_string(),
                profile_id: cred.profile_id.to_string(),
                r#type: match cred.credential_type {
                    sid_core::models::CredentialType::Opaque => CredentialType::Opaque.into(),
                    sid_core::models::CredentialType::WebAuthn => CredentialType::Webauthn.into(),
                    sid_core::models::CredentialType::Totp => CredentialType::Totp.into(),
                    sid_core::models::CredentialType::Recovery => CredentialType::Recovery.into(),
                    sid_core::models::CredentialType::LegacyHash => {
                        CredentialType::LegacyHash.into()
                    }
                },
                data: vec![],
                label: cred.label,
                created_at: Some(convert::to_timestamp(cred.created_at)),
                last_used_at: cred.last_used_at.map(convert::to_timestamp),
                info,
            }),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_credential"))]
    #[instrument(skip_all, fields(method = "revoke_credential"))]
    async fn revoke_credential(
        &self,
        request: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let cred_id = parse_credential_id(&req.credential_id)?;
        let credential = self.visible_credential(&caller, cred_id).await?;
        // Removing protection takes the authority adding it would: otherwise
        // a weaker session revokes the strong factor, then adds its own.
        if caller.profile_id == credential.profile_id {
            sid_authn::credential_enrollment::authorize(
                self.storage.as_ref(),
                &caller,
                credential.credential_type,
                SecurityPolicy::ce_default().auth.passkey_satisfies_mfa,
            )
            .await?;
        }

        // Revoked, not deleted; the profile keeps one active primary
        // credential, checked in the same step as the revocation.
        let outcome = self
            .storage
            .revoke_credential(
                cred_id,
                AuditEntry::user(
                    caller.profile_id.to_string(),
                    "credential.revoke",
                    cred_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        refuse_last_primary(outcome, cred_id)?;

        Ok(Response::new(RevokeCredentialResponse {}))
    }

    #[tracing::instrument(skip_all, fields(rpc = "add_principal"))]
    #[instrument(skip_all, fields(method = "add_principal"))]
    async fn add_principal(
        &self,
        request: Request<AddPrincipalRequest>,
    ) -> Result<Response<AddPrincipalResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let pid = convert::parse_profile_id(&req.profile_id)?;
        caller.require_self_or_admin(pid)?;

        // Verify profile exists
        self.storage
            .get_profile(pid)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(req.profile_id.clone()))?;

        let principal_type = match req.r#type() {
            sid_proto::sid::v1::PrincipalType::Email => sid_core::models::PrincipalType::Email,
            sid_proto::sid::v1::PrincipalType::Phone => sid_core::models::PrincipalType::Phone,
            sid_proto::sid::v1::PrincipalType::FaceEmbedding => {
                sid_core::models::PrincipalType::FaceEmbedding
            }
            sid_proto::sid::v1::PrincipalType::NfcTag => sid_core::models::PrincipalType::NfcTag,
            sid_proto::sid::v1::PrincipalType::Username => {
                sid_core::models::PrincipalType::Username
            }
            _ => return Err(missing_field("type")),
        };
        let (value, email) = stored_principal_value(principal_type, &req.value)?;

        let mut principal = sid_core::models::Principal::new(pid, principal_type, &value);
        if let Some(email) = &email {
            principal.email_policy_revision = Some(email.revision);
            if let Some(repaired) = self
                .repair_quarantined_email(&caller, pid, &value, email)
                .await?
            {
                return Ok(Response::new(AddPrincipalResponse {
                    principal: Some(convert::principal_to_proto(&repaired)),
                }));
            }
            // The handle's delivery address: the profile's contact with this
            // exact spelling, else a new unverified one.
            let contact = self.email_contact(pid, &email.delivery).await?;
            principal.source_field = Some("email".into());
            principal.source_email_id = Some(contact.id);
        }

        // A shared contact channel owes the contestation check: once the
        // claim commits, every other holder is told. A login handle is never
        // shared, so it owes none.
        let mut ctx = MutationContext::from(AuditEntry::user(
            caller.profile_id.to_string(),
            "principal.create",
            principal.id.0.to_string(),
        ));
        if principal_type.is_contestable() {
            ctx = ctx.with_work(ContestCheck::new(principal_type, &value, pid).work());
        }
        self.storage
            .save_principal(&principal, ctx)
            .await
            .map_err(|e| match e {
                // Only a login handle is unique; a contact channel is shared.
                sid_core::Error::Conflict(_) => contact_taken(principal_type),
                e => storage_failure(e),
            })?;

        // The stored claim: its id is the principal's, which an earlier holder
        // may have created, and its proof is shown only to the holder.
        let stored = self
            .storage
            .get_principals_by_profile(pid)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .find(|p| p.principal_type == principal_type && p.value == value)
            .ok_or_else(|| {
                internal(
                    "add principal",
                    format!("principal {} missing after save", principal.id.0),
                )
            })?;

        info!("Added {} principal for profile {}", principal_type, pid);

        Ok(Response::new(AddPrincipalResponse {
            principal: Some(convert::principal_to_proto(&stored)),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_principals"))]
    #[instrument(skip_all, fields(method = "list_principals"))]
    async fn list_principals(
        &self,
        request: Request<ListPrincipalsRequest>,
    ) -> Result<Response<ListPrincipalsResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();
        let pid = convert::parse_profile_id(&req.profile_id)?;
        caller.require_self_or_admin(pid)?;

        let principals = self
            .storage
            .get_principals_by_profile(pid)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListPrincipalsResponse {
            principals: principals.iter().map(convert::principal_to_proto).collect(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "remove_principal"))]
    #[instrument(skip_all, fields(method = "remove_principal"))]
    async fn remove_principal(
        &self,
        request: Request<RemovePrincipalRequest>,
    ) -> Result<Response<RemovePrincipalResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let principal_id = uuid::Uuid::parse_str(&req.principal_id)
            .map(sid_core::models::PrincipalId)
            .map_err(|_| invalid_field("principal_id", "not a principal identifier"))?;

        // A principal can be held by several accounts (contestation), so the
        // request removes one holder's binding: the caller's own, or for an
        // administrator the only holder's. The request names no account, so
        // an administrator cannot pick among several holders.
        let bindings = self
            .storage
            .get_principal_bindings(principal_id)
            .await
            .map_err(storage_failure)?;
        let principal_not_found = || {
            not_found(
                ErrorReason::PrincipalNotFound,
                "Principal",
                principal_id.0.to_string(),
            )
        };
        if bindings.is_empty() {
            return Err(principal_not_found());
        }
        let holder = match bindings.iter().find(|b| b.profile_id == caller.profile_id) {
            Some(own) => own.profile_id,
            // Held only by others: not found for a user, as an unknown one.
            None => {
                caller.require_admin().map_err(|_| principal_not_found())?;
                match bindings.as_slice() {
                    [only] => only.profile_id,
                    _ => {
                        return Err(ApiError::new(
                            ErrorReason::InvalidState,
                            "the principal has several holders; remove it from a specific account",
                        )
                        .with_precondition(
                            "PRINCIPAL_HOLDERS",
                            principal_id.0.to_string(),
                            "several",
                        )
                        .into());
                    }
                }
            }
        };

        self.storage
            .unbind_principal(
                principal_id,
                holder,
                AuditEntry::user(
                    caller.profile_id.to_string(),
                    "principal.delete",
                    principal_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(RemovePrincipalResponse {}))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_sessions"))]
    #[instrument(skip_all, fields(method = "list_sessions"))]
    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();
        let pid = convert::parse_profile_id(&req.profile_id)?;
        caller.require_self_or_admin(pid)?;

        let sessions = self
            .storage
            .list_sessions_by_profile(pid)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListSessionsResponse {
            sessions: sessions
                .into_iter()
                .map(|s| Session {
                    id: s.id.to_string(),
                    profile_id: s.profile_id.to_string(),
                    client_id: s.client_id.unwrap_or_default(),
                    device_id: s.device_id.map(|d| d.to_string()),
                    ip_address: s.ip_address,
                    user_agent: s.user_agent,
                    created_at: Some(convert::to_timestamp(s.created_at)),
                    expires_at: Some(convert::to_timestamp(s.expires_at)),
                    last_activity_at: None,
                    scopes: vec![],
                })
                .collect(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_session"))]
    #[instrument(skip_all, fields(method = "revoke_session"))]
    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<RevokeSessionResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive()?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }
        let req = request.into_inner();
        let session_id = SessionId::parse(&req.session_id)
            .map_err(|_| invalid_field("session_id", "not a session identifier"))?;

        // Fetch the session first: only its owner or an administrator may end it.
        let session = self
            .storage
            .get_session(session_id)
            .await
            .map_err(storage_failure)?;
        // An ended session is already revoked: nothing to do, and nothing about it
        // is disclosed.
        let Some(owner) = session.as_ref().map(|s| s.profile_id) else {
            return Ok(Response::new(RevokeSessionResponse {}));
        };
        caller.require_self_or_admin(owner)?;

        // Access tokens stop in every process, refresh tokens are revoked and
        // the session is deleted.
        self.cascade_service
            .revoke_session(
                session_id,
                RevocationReason::UserRequested,
                &caller.profile_id.to_string(),
                "session.revoke",
            )
            .await
            .map_err(|e| internal("revoke session", e))?;

        // The session's client logout and its revoked event are committed
        // with the deletion and delivered by the durable work runner.
        info!("Revoked session {}", session_id);

        Ok(Response::new(RevokeSessionResponse {}))
    }

    // ── Passkey Registration Prompts ──

    #[tracing::instrument(skip_all, fields(rpc = "get_passkey_prompt_state"))]
    #[instrument(skip_all, fields(method = "get_passkey_prompt_state"))]
    async fn get_passkey_prompt_state(
        &self,
        request: Request<GetPasskeyPromptStateRequest>,
    ) -> Result<Response<GetPasskeyPromptStateResponse>, Status> {
        let profile_id = self.caller(&request).await?.profile_id;

        let state = self.build_passkey_prompt_state(profile_id).await?;

        Ok(Response::new(GetPasskeyPromptStateResponse {
            state: Some(state),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "record_passkey_prompt_dismissal"))]
    #[instrument(skip_all, fields(method = "record_passkey_prompt_dismissal"))]
    async fn record_passkey_prompt_dismissal(
        &self,
        request: Request<RecordPasskeyPromptDismissalRequest>,
    ) -> Result<Response<RecordPasskeyPromptDismissalResponse>, Status> {
        let profile_id = self.caller(&request).await?.profile_id;

        let policy = SecurityPolicy::ce_default();

        // Load current state.
        let current_state = self
            .storage
            .get_profile_metadata(profile_id, passkey_prompt::PROFILE_METADATA_KEY)
            .await
            .map_err(storage_failure)?
            .and_then(|m| {
                serde_json::from_value::<passkey_prompt::PasskeyPromptState>(m.value).ok()
            });

        // Record dismissal.
        let updated = passkey_prompt::record_dismissal(
            current_state,
            policy.passkey_prompt.skip_cooldown_days,
        );

        // Persist updated state.
        let metadata = ProfileMetadata::new(
            profile_id,
            passkey_prompt::PROFILE_METADATA_KEY,
            serde_json::to_value(&updated)
                .map_err(|e| internal("serialize passkey prompt state", e))?,
        );
        self.storage
            .set_profile_metadata(
                &metadata,
                AuditEntry::user(
                    profile_id.to_string(),
                    "passkey_prompt.dismiss",
                    profile_id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        // Build response with updated state.
        let state = self.build_passkey_prompt_state(profile_id).await?;

        Ok(Response::new(RecordPasskeyPromptDismissalResponse {
            state: Some(state),
        }))
    }

    // ── Revocation Cascade ──

    #[tracing::instrument(skip_all, fields(rpc = "revoke_profile"))]
    #[instrument(skip_all, fields(method = "revoke_profile"))]
    async fn revoke_profile(
        &self,
        request: Request<RevokeProfileRequest>,
    ) -> Result<Response<RevokeProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }

        let req = request.into_inner();
        let profile_id = convert::parse_profile_id(&req.profile_id)?;
        caller.require_self_or_admin(profile_id)?;
        caller.require_interactive()?;

        // The audit records the reason given; an unknown one is refused, not
        // recorded as another.
        let reason = match req.reason.as_str() {
            "" => return Err(missing_field("reason")),
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
            .cascade_service
            .revoke_profile(profile_id, reason, &caller.profile_id.to_string())
            .await
            .map_err(|e| internal("revoke profile", e))?;

        info!(
            profile_id = %profile_id,
            entities_revoked = revocation.total_revoked(),
            "Profile revoked via gRPC",
        );

        Ok(Response::new(RevokeProfileResponse {
            entities_revoked: revocation.total_revoked() as i32,
        }))
    }

    // ── Account Closure ──

    #[tracing::instrument(skip_all, fields(rpc = "request_closure"))]
    #[instrument(skip_all, fields(method = "request_closure"))]
    async fn request_closure(
        &self,
        request: Request<RequestClosureRequest>,
    ) -> Result<Response<RequestClosureResponse>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }

        let req = request.into_inner();

        // The user closes their own account, voluntarily or as a GDPR Art. 17
        // request. Admin termination and regulatory-order closure act on
        // another user's account under an organization's or a court's
        // authority: they are never requested by the account holder (a regulatory order has no grace period and
        // cannot be cancelled).
        let mode = match req.mode() {
            ClosureMode::Voluntary => CoreClosureMode::Voluntary,
            ClosureMode::GdprErasure => CoreClosureMode::GdprErasure,
            ClosureMode::AdminTermination => return Err(not_in_this_build("admin_termination")),
            ClosureMode::RegulatoryOrder => {
                return Err(not_in_this_build("regulatory_order_closure"));
            }
            ClosureMode::Unspecified => return Err(missing_field("mode")),
        };

        let closure_req = self
            .closure_service
            .request_closure(caller_id, mode, caller_id)
            .await
            .map_err(|e| account_refusal("request closure", CLOSURE, caller_id, e))?;

        Ok(Response::new(RequestClosureResponse {
            profile_id: closure_req.profile_id.to_string(),
            mode: req.mode,
            grace_period_end: closure_req.grace_period_end.map(convert::to_timestamp),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "cancel_closure"))]
    #[instrument(skip_all, fields(method = "cancel_closure"))]
    async fn cancel_closure(
        &self,
        request: Request<CancelClosureRequest>,
    ) -> Result<Response<CancelClosureResponse>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        if self.feature_flags.is_maintenance_mode().await {
            return Err(maintenance());
        }

        self.closure_service
            .cancel_closure(caller_id, caller_id)
            .await
            .map_err(|e| account_refusal("cancel closure", CLOSURE_TO_CANCEL, caller_id, e))?;

        Ok(Response::new(CancelClosureResponse {}))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_closure_status"))]
    #[instrument(skip_all, fields(method = "get_closure_status"))]
    async fn get_closure_status(
        &self,
        request: Request<GetClosureStatusRequest>,
    ) -> Result<Response<GetClosureStatusResponse>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;

        let closure = self
            .closure_service
            .get_closure_status(caller_id)
            .await
            .map_err(|e| internal("get closure status", e))?;

        match closure {
            Some(req) => Ok(Response::new(GetClosureStatusResponse {
                has_active_closure: true,
                mode: match req.mode {
                    CoreClosureMode::Voluntary => ClosureMode::Voluntary.into(),
                    CoreClosureMode::GdprErasure => ClosureMode::GdprErasure.into(),
                    CoreClosureMode::AdminTermination => ClosureMode::AdminTermination.into(),
                    CoreClosureMode::RegulatoryOrder => ClosureMode::RegulatoryOrder.into(),
                },
                export_status: convert::export_status_to_proto(&req.export_status).into(),
                grace_period_end: req.grace_period_end.map(convert::to_timestamp),
                requested_at: Some(convert::to_timestamp(req.requested_at)),
                cancel_count: req.cancel_count as i32,
            })),
            None => Ok(Response::new(GetClosureStatusResponse {
                has_active_closure: false,
                mode: ClosureMode::Unspecified.into(),
                export_status: sid_proto::sid::v1::ExportStatus::NotStarted.into(),
                grace_period_end: None,
                requested_at: None,
                cancel_count: 0,
            })),
        }
    }

    // === Data Export (GDPR Art. 20) ===

    #[tracing::instrument(skip_all, fields(rpc = "prepare_export"))]
    #[instrument(skip_all, fields(method = "prepare_export"))]
    async fn prepare_export(
        &self,
        request: Request<PrepareExportRequest>,
    ) -> Result<Response<PrepareExportResponse>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;

        let _format_proto = request.into_inner().format();
        // CE only supports JSON.
        let format = sid_core::models::ExportFormat::Json;

        let job = self
            .data_export
            .prepare_export(caller_id, format, &caller_id.to_string())
            .await
            .map_err(|e| account_refusal("prepare export", NEW_EXPORT, caller_id, e))?;

        Ok(Response::new(PrepareExportResponse {
            export_id: job.id.to_string(),
            estimated_ready: Some(convert::to_timestamp(job.created_at)),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_export_status"))]
    #[instrument(skip_all, fields(method = "get_export_status"))]
    async fn get_export_status(
        &self,
        request: Request<GetExportStatusRequest>,
    ) -> Result<Response<GetExportStatusResponse>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;

        let job = self
            .data_export
            .get_export_status(caller_id)
            .await
            .map_err(|e| internal("get export status", e))?;

        match job {
            Some(j) => Ok(Response::new(GetExportStatusResponse {
                export_status: convert::export_status_to_proto(&j.status).into(),
                size_bytes: j.size_bytes,
                checksum_sha256: j.checksum_sha256,
                ready_at: j.ready_at.map(convert::to_timestamp),
                expires_at: j.expires_at.map(convert::to_timestamp),
            })),
            None => Ok(Response::new(GetExportStatusResponse {
                export_status: sid_proto::sid::v1::ExportStatus::NotStarted.into(),
                size_bytes: None,
                checksum_sha256: None,
                ready_at: None,
                expires_at: None,
            })),
        }
    }

    type DownloadExportStream =
        tokio_stream::wrappers::ReceiverStream<Result<DownloadExportChunk, Status>>;

    #[tracing::instrument(skip_all, fields(rpc = "download_export"))]
    #[instrument(skip_all, fields(method = "download_export"))]
    async fn download_export(
        &self,
        request: Request<DownloadExportRequest>,
    ) -> Result<Response<Self::DownloadExportStream>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;

        let (data, job) = self
            .data_export
            .read_export_archive(caller_id)
            .await
            .map_err(|e| account_refusal("download export", EXPORT, caller_id, e))?;

        let total_size = data.len() as i64;
        let chunk_size = 64 * 1024; // 64 KiB chunks.

        let (tx, rx) = tokio::sync::mpsc::channel(4);

        tokio::spawn(async move {
            let mut offset: i64 = 0;
            for chunk in data.chunks(chunk_size) {
                let msg = DownloadExportChunk {
                    data: chunk.to_vec(),
                    offset,
                    total_size,
                };
                if tx.send(Ok(msg)).await.is_err() {
                    break;
                }
                offset += chunk.len() as i64;
            }
        });

        info!(
            profile_id = %caller_id,
            export_id = %job.id,
            size_bytes = total_size,
            "Export download started",
        );

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    #[tracing::instrument(skip_all, fields(rpc = "acknowledge_export"))]
    #[instrument(skip_all, fields(method = "acknowledge_export"))]
    async fn acknowledge_export(
        &self,
        request: Request<AcknowledgeExportRequest>,
    ) -> Result<Response<()>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;

        self.data_export
            .acknowledge_export(caller_id, &caller_id.to_string())
            .await
            .map_err(|e| account_refusal("acknowledge export", EXPORT, caller_id, e))?;

        Ok(Response::new(()))
    }

    // === Device management ===

    #[tracing::instrument(skip_all, fields(rpc = "list_devices"))]
    #[instrument(skip_all, fields(method = "list_devices"))]
    async fn list_devices(
        &self,
        request: Request<ListDevicesRequest>,
    ) -> Result<Response<ListDevicesResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();

        let profile_id = convert::parse_profile_id(&req.profile_id)?;

        // Only allow listing own devices.
        if profile_id != caller.profile_id {
            return Err(ApiError::new(
                ErrorReason::InsufficientPermissions,
                "only the profile's own devices are listed",
            )
            .into());
        }

        let devices = self
            .storage
            .list_devices_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;

        let proto_devices = devices.iter().map(convert::device_to_proto).collect();

        Ok(Response::new(ListDevicesResponse {
            devices: proto_devices,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_device"))]
    #[instrument(skip_all, fields(method = "get_device"))]
    async fn get_device(
        &self,
        request: Request<GetDeviceRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        let device_id = parse_device_id(&request.into_inner().device_id)?;
        let device = self.owned_device(caller_id, device_id).await?;
        Ok(Response::new(convert::device_to_proto(&device)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_device"))]
    #[instrument(skip_all, fields(method = "update_device"))]
    async fn update_device(
        &self,
        request: Request<UpdateDeviceRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        let req = request.into_inner();
        let device_id = parse_device_id(&req.device_id)?;
        self.owned_device(caller_id, device_id).await?;

        // Only the name is written: a trust change or removal made meanwhile
        // is never undone by this copy.
        if let Some(name) = req.display_name.as_deref()
            && !self
                .storage
                .rename_device(
                    device_id,
                    Some(name),
                    AuditEntry::user(
                        caller_id.to_string(),
                        "device.update",
                        device_id.to_string(),
                    )
                    .into(),
                )
                .await
                .map_err(storage_failure)?
        {
            return Err(device_not_found(device_id));
        }

        let device = self.owned_device(caller_id, device_id).await?;
        Ok(Response::new(convert::device_to_proto(&device)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "remove_device"))]
    #[instrument(skip_all, fields(method = "remove_device"))]
    async fn remove_device(
        &self,
        request: Request<RemoveDeviceRequest>,
    ) -> Result<Response<()>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        let device_id = parse_device_id(&request.into_inner().device_id)?;
        self.owned_device(caller_id, device_id).await?;

        // The audit names the user who removed it, not the system.
        self.storage
            .delete_device(
                device_id,
                AuditEntry::user(
                    caller_id.to_string(),
                    "device.remove",
                    device_id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(device_id = %device_id, "Device removed");
        Ok(Response::new(()))
    }

    #[tracing::instrument(skip_all, fields(rpc = "trust_device"))]
    #[instrument(skip_all, fields(method = "trust_device"))]
    async fn trust_device(
        &self,
        request: Request<TrustDeviceRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        let device_id = parse_device_id(&request.into_inner().device_id)?;
        self.change_device_trust(caller_id, device_id, true).await
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_device_trust"))]
    #[instrument(skip_all, fields(method = "revoke_device_trust"))]
    async fn revoke_device_trust(
        &self,
        request: Request<RevokeDeviceTrustRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;
        let device_id = parse_device_id(&request.into_inner().device_id)?;
        self.change_device_trust(caller_id, device_id, false).await
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_current_profile"))]
    #[instrument(skip_all, fields(method = "get_current_profile"))]
    async fn get_current_profile(
        &self,
        request: Request<GetCurrentProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        let caller_id = self.caller(&request).await?.profile_id;

        let profile = self
            .storage
            .get_profile(caller_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(caller_id.to_string()))?;

        let (primary_email, primary_phone) = self.primary_contacts(profile.id).await?;
        Ok(Response::new(GetProfileResponse {
            profile: Some(convert::profile_to_proto_with_contacts(
                &profile,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )),
        }))
    }
}

/// A revocation refused because the credential is the profile's last way to
/// sign in is the caller's to fix (add another method first); a credential
/// already gone is revoked as asked.
#[allow(clippy::result_large_err)]
pub(crate) fn refuse_last_primary(
    outcome: sid_core::models::CredentialRevocation,
    credential: CredentialId,
) -> Result<(), Status> {
    match outcome {
        sid_core::models::CredentialRevocation::LastPrimary => Err(ApiError::new(
            ErrorReason::InvalidState,
            "the profile's last way to sign in cannot be revoked; add another first",
        )
        .with_precondition(
            "LAST_PRIMARY_CREDENTIAL",
            credential.0.to_string(),
            "the profile has no other active primary credential",
        )
        .into()),
        sid_core::models::CredentialRevocation::Revoked
        | sid_core::models::CredentialRevocation::AlreadyGone => Ok(()),
    }
}

/// The form a principal of `principal_type` is stored in: text handles in
/// the normalized form login looks them up by, and of the requested type;
/// device identifiers as given. An email also yields its validated handle:
/// the address in the spelling given and the policy revision of its key.
#[allow(clippy::result_large_err)]
pub(crate) fn stored_principal_value(
    principal_type: sid_core::models::PrincipalType,
    value: &str,
) -> Result<(String, Option<sid_authn::email::EmailHandle>), Status> {
    use sid_core::models::PrincipalType;

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
                return Err(missing_field("value"));
            }
            Ok((value.to_owned(), None))
        }
    }
}

#[cfg(test)]
mod tests;
