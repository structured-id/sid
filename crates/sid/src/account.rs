// SPDX-License-Identifier: AGPL-3.0-only
//! Self-service account management of the authenticated Profile: the sites it
//! consented to and the claims each receives, and its contact phones and
//! emails. Each operation acts on the caller's own Profile only; another
//! Profile's record is not found, as one that does not exist. A keyed one
//! commits its change, audit and completion together and answers a retry
//! with what the first attempt recorded.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use prost::Message;
use sid_authn::caller::Caller;
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::consent::{ClaimDecision, ClaimGrantChange, ClaimType as DomainClaimType};
use sid_core::models::principal::{Principal, PrincipalType};
use sid_core::models::profile::Profile;
use sid_core::models::profile_email::{EmailLabel, ProfileEmailId};
use sid_core::models::profile_phone::{PhoneLabel, ProfilePhoneId};
use sid_core::models::{
    AuditEntry, EmailSettings, MutationContext, OperationContext, PhoneSettings, ProfileEmail,
    ProfileId, ProfilePhone,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::account::account_service as keyed;
use sid_proto::sid::v1::{self, account as v1a};
use tracing::info;

use crate::wire::{FieldError, stored_id, to_timestamp, wire_id};

/// Why an account operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
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
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// The caller has no consent for this site.
    #[error("no consent for site {0}")]
    ConsentNotFound(String),
    /// The caller's consent for this site is inactive and takes no claim
    /// changes.
    #[error("the consent for site {0} is inactive")]
    ConsentInactive(String),
    /// The caller's Profile has no such phone.
    #[error("phone {} not found", .0.0)]
    PhoneNotFound(ProfilePhoneId),
    /// The caller's Profile has no such email.
    #[error("email {} not found", .0.0)]
    EmailNotFound(ProfileEmailId),
}

impl From<AccountError> for Effect<AccountError> {
    fn from(e: AccountError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<AccountError>> for AccountError {
    fn from(e: CommandError<AccountError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for AccountError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> AccountError {
    tracing::error!(operation, error = %cause, "internal failure");
    AccountError::Internal
}

/// The audit of `profile_id`'s own `action` on `target`.
fn own_ctx(profile_id: ProfileId, action: &str, target: String) -> MutationContext {
    AuditEntry::user(profile_id.to_string(), action, target).into()
}

/// The phone a request names, validated before any lookup.
fn phone_id(id: Option<&sid_ids_proto::ProfilePhoneId>) -> Result<ProfilePhoneId, AccountError> {
    Ok(ProfilePhoneId(wire_id(id, "phone_id")?.into_uuid()))
}

/// The email a request names, validated before any lookup.
fn email_id(id: Option<&sid_ids_proto::ProfileEmailId>) -> Result<ProfileEmailId, AccountError> {
    Ok(ProfileEmailId(wire_id(id, "email_id")?.into_uuid()))
}

/// The self-service account of one installation.
pub struct Account {
    storage: Arc<dyn StorageBackend>,
}

impl Account {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// `profile_id`'s phone `id` as stored; not found for another profile's.
    async fn owned_phone(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
    ) -> Result<ProfilePhone, AccountError> {
        self.storage
            .get_profile_phone(id)
            .await?
            .filter(|p| p.profile_id == profile_id)
            .ok_or(AccountError::PhoneNotFound(id))
    }

    /// `profile_id`'s email `id` as stored; not found for another profile's.
    async fn owned_email(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
    ) -> Result<ProfileEmail, AccountError> {
        self.storage
            .get_profile_email(id)
            .await?
            .filter(|e| e.profile_id == profile_id)
            .ok_or(AccountError::EmailNotFound(id))
    }

    // ── Consents ──

    /// The sites the caller consented to. A deleted client is shown by its
    /// id; a failed read is an error.
    pub async fn list_consents(
        &self,
        caller: &Caller,
    ) -> Result<v1a::ListConsentsResponse, AccountError> {
        let records = self
            .storage
            .list_consents_by_profile(caller.profile_id)
            .await?;
        let client_ids: HashSet<&str> = records.iter().map(|r| r.client_id.as_str()).collect();
        let mut client_info: HashMap<String, (String, Option<String>)> = HashMap::new();
        for cid in client_ids {
            if let Some(client) = self.storage.get_oauth2_client(cid).await? {
                client_info.insert(cid.to_string(), (client.client_name, client.logo_uri));
            }
        }
        let consents = records
            .into_iter()
            .map(|r| {
                let count = |kind: DomainClaimType| {
                    r.grants
                        .iter()
                        .filter(|g| g.claim_type == kind && g.is_active())
                        .count() as i32
                };
                let (site_name, site_favicon) = client_info
                    .get(&r.client_id)
                    .map(|(name, favicon)| (name.clone(), favicon.clone()))
                    .unwrap_or_else(|| (r.client_id.clone(), None));
                v1a::ConsentInfo {
                    site_id: r.client_id.clone(),
                    site_name,
                    site_favicon,
                    status: consent_status(r.status.is_active()),
                    connected_at: Some(prost_types::Timestamp {
                        seconds: r.consented_at.timestamp(),
                        nanos: 0,
                    }),
                    claims_mandatory: count(DomainClaimType::Data),
                    claims_optional: count(DomainClaimType::Attestation),
                    last_sync: None,
                }
            })
            .collect();
        Ok(v1a::ListConsentsResponse { consents })
    }

    /// One consent with each claim's state and a masked preview of the
    /// value it shares.
    pub async fn consent_detail(
        &self,
        caller: &Caller,
        req: v1a::GetConsentDetailRequest,
    ) -> Result<v1a::GetConsentDetailResponse, AccountError> {
        let profile_id = caller.profile_id;
        let site_id = req.site_id;
        if site_id.is_empty() {
            return Err(AccountError::MissingField("site_id"));
        }
        let record = self
            .storage
            .get_consent_by_client(profile_id, &site_id)
            .await?
            .ok_or_else(|| AccountError::ConsentNotFound(site_id.clone()))?;
        let profile = self.storage.get_profile(profile_id).await?;
        let principals = self.storage.get_principals_by_profile(profile_id).await?;
        let claims: Vec<v1a::ClaimConsent> = record
            .grants
            .iter()
            .map(|g| v1a::ClaimConsent {
                claim_name: g.claim_name.clone(),
                claim_type: match g.claim_type {
                    DomainClaimType::Data => v1a::ClaimType::Mandatory.into(),
                    DomainClaimType::Attestation => v1a::ClaimType::Optional.into(),
                },
                current_status: if g.is_active() {
                    v1a::ClaimConsentStatus::Granted.into()
                } else {
                    v1a::ClaimConsentStatus::Denied.into()
                },
                // Attestations have no value to preview.
                value_preview: match g.claim_type {
                    DomainClaimType::Attestation => String::new(),
                    DomainClaimType::Data => {
                        claim_preview(&g.claim_name, profile.as_ref(), &principals)
                    }
                },
                last_propagated: None,
            })
            .collect();
        // A deleted client is shown by its id; a failed read is an error.
        let (site_name, site_favicon) =
            match self.storage.get_oauth2_client(&record.client_id).await? {
                Some(client) => (client.client_name, client.logo_uri),
                None => (record.client_id.clone(), None),
            };
        let of_type = |kind: v1a::ClaimType| {
            claims
                .iter()
                .filter(|c| c.claim_type == i32::from(kind))
                .count() as i32
        };
        let site_info = v1a::ConsentInfo {
            site_id: record.client_id.clone(),
            site_name,
            site_favicon,
            status: consent_status(record.status.is_active()),
            connected_at: Some(prost_types::Timestamp {
                seconds: record.consented_at.timestamp(),
                nanos: 0,
            }),
            claims_mandatory: of_type(v1a::ClaimType::Mandatory),
            claims_optional: of_type(v1a::ClaimType::Optional),
            last_sync: None,
        };
        Ok(v1a::GetConsentDetailResponse {
            site_info: Some(site_info),
            claims,
        })
    }

    /// Grant or revoke one claim of a consent. A retry of a completed
    /// decision answers as it did, and never applies it again over a later
    /// decision on the same claim.
    pub async fn update_claim_consent(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::UpdateClaimConsentRequest,
    ) -> Result<(), AccountError> {
        if req.site_id.is_empty() {
            return Err(AccountError::MissingField("site_id"));
        }
        if req.claim_name.is_empty() {
            return Err(AccountError::MissingField("claim_name"));
        }
        let profile_id = caller.profile_id;
        let command =
            KeyedCommand::by_profile::<keyed::UpdateClaimConsent>(profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                self.decide_claim(profile_id, &command, &req).await
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Apply one claim decision of `profile_id`'s consent under `command`.
    async fn decide_claim(
        &self,
        profile_id: ProfileId,
        command: &KeyedCommand,
        req: &v1a::UpdateClaimConsentRequest,
    ) -> Result<(), Effect<AccountError>> {
        let record = self
            .storage
            .get_consent_by_client(profile_id, &req.site_id)
            .await?
            .ok_or_else(|| AccountError::ConsentNotFound(req.site_id.clone()))?;
        // A claim granted again keeps what it was shared as.
        let decision = if req.grant {
            ClaimDecision::Grant(
                record
                    .grants
                    .iter()
                    .find(|g| g.claim_name == req.claim_name)
                    .map_or(DomainClaimType::Data, |g| g.claim_type),
            )
        } else {
            ClaimDecision::Revoke
        };
        // The event is owed by the same commit that changes the consent; a
        // decision already in effect commits only its completion.
        let event_type = if req.grant {
            sid_core::models::event::event_types::CONSENT_GRANTED
        } else {
            sid_core::models::event::event_types::CONSENT_REVOKED
        };
        let event = sid_core::models::event::Event::new("sid-account", event_type)
            .with_subject(format!("profile/{profile_id}"))
            .with_data(serde_json::json!({
                "profile_id": profile_id.to_string(),
                "site_id": req.site_id,
                "claim_name": req.claim_name,
            }));
        let action = if req.grant {
            "consent.claim_granted"
        } else {
            "consent.claim_revoked"
        };
        let ctx = own_ctx(
            profile_id,
            action,
            format!("{}:{}", req.site_id, req.claim_name),
        )
        .with_work(event.relay())
        .with_operation(command.completion(().encode_to_vec()));
        match self
            .storage
            .change_claim_grant(record.id, &req.claim_name, decision, ctx)
            .await?
        {
            ClaimGrantChange::Changed => {}
            // Already as asked: nothing changed, nothing announced.
            ClaimGrantChange::Unchanged => return Ok(()),
            ClaimGrantChange::ConsentNotActive => {
                return Err(AccountError::ConsentInactive(req.site_id.clone()).into());
            }
        }
        info!(
            "Consent claim {} {} for profile {} site {}",
            req.claim_name,
            if req.grant { "granted" } else { "revoked" },
            profile_id,
            req.site_id
        );
        Ok(())
    }

    /// Remove the caller's consent for a site. A retry of a completed
    /// disconnect answers as it did.
    pub async fn disconnect_site(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::DisconnectSiteRequest,
    ) -> Result<(), AccountError> {
        if req.site_id.is_empty() {
            return Err(AccountError::MissingField("site_id"));
        }
        let profile_id = caller.profile_id;
        let command =
            KeyedCommand::by_profile::<keyed::DisconnectSite>(profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let site_id = &req.site_id;
                let record = self
                    .storage
                    .get_consent_by_client(profile_id, site_id)
                    .await?
                    .ok_or_else(|| AccountError::ConsentNotFound(site_id.clone()))?;
                let event = sid_core::models::event::Event::new(
                    "sid-account",
                    sid_core::models::event::event_types::CONSENT_REVOKED,
                )
                .with_subject(format!("profile/{profile_id}"))
                .with_data(serde_json::json!({
                    "profile_id": profile_id.to_string(),
                    "site_id": site_id,
                    "disconnect": true,
                }));
                let ctx = own_ctx(profile_id, "consent.site_disconnected", site_id.clone())
                    .with_work(event.relay())
                    .with_operation(command.completion(().encode_to_vec()));
                if !self.storage.delete_consent(record.id, ctx).await? {
                    // Disconnected meanwhile: that disconnect announced it.
                    return Err(AccountError::ConsentNotFound(site_id.clone()).into());
                }
                info!("Site {} disconnected for profile {}", site_id, profile_id);
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    // ── Phones ──

    /// Add a phone. A retry of a completed addition answers with the phone it
    /// added and adds no second one.
    pub async fn add_phone(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::AddPhoneRequest,
    ) -> Result<v1::ProfilePhone, AccountError> {
        if req.e164 == 0 {
            return Err(AccountError::MissingField("e164"));
        }
        let profile_id = caller.profile_id;
        let command = KeyedCommand::by_profile::<keyed::AddPhone>(profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let now = chrono::Utc::now();
                let phone = ProfilePhone {
                    id: ProfilePhoneId::new(),
                    profile_id,
                    e164: req.e164,
                    extension: req.extension,
                    label: phone_label(req.label),
                    custom_label: req.custom_label.clone().filter(|s| !s.is_empty()),
                    is_primary: req.is_primary,
                    can_receive_sms: req.can_receive_sms,
                    can_receive_fax: req.can_receive_fax,
                    can_receive_voice: req.can_receive_voice,
                    verified: false,
                    verified_at: None,
                    created_at: now,
                    updated_at: now,
                };
                let view = phone_to_proto(&phone)?;
                // A primary phone takes the flag from the current one in the
                // same write.
                let ctx = own_ctx(profile_id, "phone.added", phone.id.0.to_string())
                    .with_operation(command.completion(view.encode_to_vec()));
                self.storage.create_profile_phone(&phone, ctx).await?;
                info!("Phone {} added for profile {}", phone.id.0, profile_id);
                Ok(view)
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Remove one of the caller's phones. A retry of a completed removal
    /// answers as it did.
    pub async fn remove_phone(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::RemovePhoneRequest,
    ) -> Result<(), AccountError> {
        let phone_id = phone_id(req.phone_id.as_ref())?;
        let profile_id = caller.profile_id;
        let command = KeyedCommand::by_profile::<keyed::RemovePhone>(profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                self.owned_phone(profile_id, phone_id).await?;
                let ctx = own_ctx(profile_id, "phone.removed", phone_id.0.to_string())
                    .with_operation(command.completion(().encode_to_vec()));
                self.storage.delete_profile_phone(phone_id, ctx).await?;
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Change the settings given of one of the caller's phones: the number,
    /// its verification and the primary flag stay as stored. A retry answers
    /// with the phone as that edit's commit left it, and never writes it
    /// again over a later edit.
    pub async fn update_phone(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::UpdatePhoneRequest,
    ) -> Result<v1::ProfilePhone, AccountError> {
        let phone_id = phone_id(req.phone_id.as_ref())?;
        let profile_id = caller.profile_id;
        let settings = PhoneSettings {
            label: req.label.map(phone_label),
            custom_label: req
                .custom_label
                .clone()
                .map(|s| Some(s).filter(|s| !s.is_empty())),
            can_receive_sms: req.can_receive_sms,
            can_receive_fax: req.can_receive_fax,
            can_receive_voice: req.can_receive_voice,
        };
        let command = KeyedCommand::by_profile::<keyed::UpdatePhone>(profile_id, operation, &req);
        let phone: ProfilePhone = command
            .execute_recorded(&*self.storage, || async {
                let ctx = own_ctx(profile_id, "phone.updated", phone_id.0.to_string())
                    .with_operation(command.effect_completion());
                if !self
                    .storage
                    .update_profile_phone_settings(
                        profile_id,
                        phone_id,
                        &settings,
                        chrono::Utc::now(),
                        ctx,
                    )
                    .await?
                {
                    return Err(AccountError::PhoneNotFound(phone_id).into());
                }
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;
        phone_to_proto(&phone)
    }

    /// Make one of the caller's phones the primary one; the flag moves from
    /// the current primary in one write. A retry answers with the phone as
    /// that move's commit left it, and never moves the flag back over a
    /// later move.
    pub async fn set_primary_phone(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::SetPrimaryPhoneRequest,
    ) -> Result<v1::ProfilePhone, AccountError> {
        let phone_id = phone_id(req.phone_id.as_ref())?;
        let profile_id = caller.profile_id;
        let command =
            KeyedCommand::by_profile::<keyed::SetPrimaryPhone>(profile_id, operation, &req);
        let phone: ProfilePhone = command
            .execute_recorded(&*self.storage, || async {
                let ctx = own_ctx(profile_id, "phone.primary_set", phone_id.0.to_string())
                    .with_operation(command.effect_completion());
                if !self
                    .storage
                    .set_primary_profile_phone(profile_id, phone_id, chrono::Utc::now(), ctx)
                    .await?
                {
                    return Err(AccountError::PhoneNotFound(phone_id).into());
                }
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;
        phone_to_proto(&phone)
    }

    pub async fn list_phones(
        &self,
        caller: &Caller,
    ) -> Result<v1a::ListPhonesResponse, AccountError> {
        let phones = self.storage.list_profile_phones(caller.profile_id).await?;
        Ok(v1a::ListPhonesResponse {
            phones: phones
                .iter()
                .map(phone_to_proto)
                .collect::<Result<_, _>>()?,
        })
    }

    // ── Emails ──

    /// Add a contact email. It keeps the spelling given (its delivery
    /// address); only an invalid mailbox is refused, and nothing is folded.
    /// A retry of a completed addition answers with the email it added and
    /// adds no second one.
    pub async fn add_email(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::AddEmailRequest,
    ) -> Result<v1::ProfileEmail, AccountError> {
        if req.email.is_empty() {
            return Err(AccountError::MissingField("email"));
        }
        let address =
            sid_authn::email::parse(req.email.trim(), &sid_authn::email::EmailPolicy::LOCAL)
                .map_err(|e| AccountError::InvalidField {
                    field: "email",
                    reason: e.to_string(),
                })?
                .delivery;
        let profile_id = caller.profile_id;
        let command = KeyedCommand::by_profile::<keyed::AddEmail>(profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let now = chrono::Utc::now();
                let email = ProfileEmail {
                    id: ProfileEmailId::new(),
                    profile_id,
                    email: address.clone(),
                    label: email_label(req.label),
                    custom_label: req.custom_label.clone().filter(|s| !s.is_empty()),
                    is_primary: req.is_primary,
                    verified: false,
                    verified_at: None,
                    created_at: now,
                    updated_at: now,
                };
                let view = email_to_proto(&email)?;
                // A primary email takes the flag from the current one in the
                // same write.
                let ctx = own_ctx(profile_id, "email.added", email.id.0.to_string())
                    .with_operation(command.completion(view.encode_to_vec()));
                self.storage.create_profile_email(&email, ctx).await?;
                info!("Email {} added for profile {}", email.id.0, profile_id);
                Ok(view)
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Remove one of the caller's emails. A retry of a completed removal
    /// answers as it did.
    pub async fn remove_email(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::RemoveEmailRequest,
    ) -> Result<(), AccountError> {
        let email_id = email_id(req.email_id.as_ref())?;
        let profile_id = caller.profile_id;
        let command = KeyedCommand::by_profile::<keyed::RemoveEmail>(profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                self.owned_email(profile_id, email_id).await?;
                let ctx = own_ctx(profile_id, "email.removed", email_id.0.to_string())
                    .with_operation(command.completion(().encode_to_vec()));
                self.storage.delete_profile_email(email_id, ctx).await?;
                Ok(())
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Change the label of one of the caller's emails: the address, its
    /// verification and the primary flag stay as stored. A retry answers
    /// with the email as that edit's commit left it.
    pub async fn update_email(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::UpdateEmailRequest,
    ) -> Result<v1::ProfileEmail, AccountError> {
        let email_id = email_id(req.email_id.as_ref())?;
        let profile_id = caller.profile_id;
        let settings = EmailSettings {
            label: req.label.map(email_label),
            custom_label: req
                .custom_label
                .clone()
                .map(|s| Some(s).filter(|s| !s.is_empty())),
        };
        let command = KeyedCommand::by_profile::<keyed::UpdateEmail>(profile_id, operation, &req);
        let email: ProfileEmail = command
            .execute_recorded(&*self.storage, || async {
                let ctx = own_ctx(profile_id, "email.updated", email_id.0.to_string())
                    .with_operation(command.effect_completion());
                if !self
                    .storage
                    .update_profile_email_settings(
                        profile_id,
                        email_id,
                        &settings,
                        chrono::Utc::now(),
                        ctx,
                    )
                    .await?
                {
                    return Err(AccountError::EmailNotFound(email_id).into());
                }
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;
        email_to_proto(&email)
    }

    /// Make one of the caller's emails the primary one, in one write with
    /// the current primary's flag.
    pub async fn set_primary_email(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1a::SetPrimaryEmailRequest,
    ) -> Result<v1::ProfileEmail, AccountError> {
        let email_id = email_id(req.email_id.as_ref())?;
        let profile_id = caller.profile_id;
        let command =
            KeyedCommand::by_profile::<keyed::SetPrimaryEmail>(profile_id, operation, &req);
        let email: ProfileEmail = command
            .execute_recorded(&*self.storage, || async {
                let ctx = own_ctx(profile_id, "email.primary_set", email_id.0.to_string())
                    .with_operation(command.effect_completion());
                if !self
                    .storage
                    .set_primary_profile_email(profile_id, email_id, chrono::Utc::now(), ctx)
                    .await?
                {
                    return Err(AccountError::EmailNotFound(email_id).into());
                }
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::refusal)?;
        email_to_proto(&email)
    }

    pub async fn list_emails(
        &self,
        caller: &Caller,
    ) -> Result<v1a::ListEmailsResponse, AccountError> {
        let emails = self.storage.list_profile_emails(caller.profile_id).await?;
        Ok(v1a::ListEmailsResponse {
            emails: emails
                .iter()
                .map(email_to_proto)
                .collect::<Result<_, _>>()?,
        })
    }
}

fn consent_status(active: bool) -> i32 {
    if active {
        v1a::ConsentStatus::Active.into()
    } else {
        v1a::ConsentStatus::Inactive.into()
    }
}

// ── Claim value masking ──

/// A claim value masked for preview:
/// - email: first char + "***" + "@" + domain → "j***@example.com"
/// - phone: first 3 chars + "***" + last 4 → "+38***4567"
/// - name-like: first char + "***" → "A***"
/// - other: "***"
fn mask_claim_value(claim_name: &str, value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    match claim_name {
        "email" | "email_verified" => mask_email(value),
        "phone" | "phone_number" | "phone_number_verified" => mask_phone(value),
        "name" | "display_name" | "given_name" | "family_name" | "preferred_username"
        | "nickname" => mask_name(value),
        _ => "***".to_string(),
    }
}

/// "alice@example.com" → "a***@example.com"
fn mask_email(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        if local.is_empty() {
            return format!("***@{domain}");
        }
        let first = &local[..local.chars().next().map_or(0, |c| c.len_utf8())];
        format!("{first}***@{domain}")
    } else {
        // Not an email address: the generic mask.
        mask_name(email)
    }
}

/// "+380501234567" → "+38***4567"
fn mask_phone(phone: &str) -> String {
    let digits_only: String = phone
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();
    let len = digits_only.len();
    if len <= 4 {
        return "***".to_string();
    }
    let prefix_len = 3.min(len - 4);
    let prefix = &digits_only[..prefix_len];
    let suffix = &digits_only[len - 4..];
    format!("{prefix}***{suffix}")
}

/// "Alice" → "A***"
fn mask_name(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let first_char_len = name.chars().next().map_or(0, |c| c.len_utf8());
    format!("{}***", &name[..first_char_len])
}

/// The masked current value of a claim: OIDC claim names map to Profile
/// fields or the primary Principal of their kind.
fn claim_preview(claim_name: &str, profile: Option<&Profile>, principals: &[Principal]) -> String {
    let raw_value = match claim_name {
        "name" | "display_name" => profile.and_then(|p| p.formatted_name()),
        "given_name" => profile.and_then(|p| p.given_name.clone()),
        "family_name" => profile.and_then(|p| p.family_name.clone()),
        "middle_name" => profile.and_then(|p| p.middle_name.clone()),
        "preferred_username" => profile.and_then(|p| p.username.clone()),
        "email" | "email_verified" => principals
            .iter()
            .find(|p| p.principal_type == PrincipalType::Email && p.is_primary)
            .map(|p| p.value.clone()),
        "phone" | "phone_number" | "phone_number_verified" => principals
            .iter()
            .find(|p| p.principal_type == PrincipalType::Phone && p.is_primary)
            .or_else(|| {
                principals
                    .iter()
                    .find(|p| p.principal_type == PrincipalType::Phone)
            })
            .map(|p| p.value.clone()),
        _ => None,
    };
    match raw_value {
        Some(val) if !val.is_empty() => mask_claim_value(claim_name, &val),
        _ => String::new(),
    }
}

// ── Messages ──

/// A request's phone label; an unspecified or unknown one is Mobile.
fn phone_label(v: i32) -> PhoneLabel {
    use v1::PhoneLabel as P;
    match P::try_from(v) {
        Ok(P::Home) => PhoneLabel::Home,
        Ok(P::Work) => PhoneLabel::Work,
        Ok(P::Fax) => PhoneLabel::Fax,
        Ok(P::Pager) => PhoneLabel::Pager,
        Ok(P::Main) => PhoneLabel::Main,
        Ok(P::Other) => PhoneLabel::Other,
        Ok(P::Custom) => PhoneLabel::Custom,
        _ => PhoneLabel::Mobile,
    }
}

/// A request's email label; an unspecified or unknown one is Personal.
fn email_label(v: i32) -> EmailLabel {
    use v1::EmailLabel as P;
    match P::try_from(v) {
        Ok(P::Work) => EmailLabel::Work,
        Ok(P::School) => EmailLabel::School,
        Ok(P::Other) => EmailLabel::Other,
        Ok(P::Custom) => EmailLabel::Custom,
        _ => EmailLabel::Personal,
    }
}

/// `p` as the API returns it; a stored id that is not a valid identifier of
/// its kind is corruption, never sent as it is.
fn phone_to_proto(p: &ProfilePhone) -> Result<v1::ProfilePhone, AccountError> {
    let label = match p.label {
        PhoneLabel::Mobile => v1::PhoneLabel::Mobile,
        PhoneLabel::Home => v1::PhoneLabel::Home,
        PhoneLabel::Work => v1::PhoneLabel::Work,
        PhoneLabel::Fax => v1::PhoneLabel::Fax,
        PhoneLabel::Pager => v1::PhoneLabel::Pager,
        PhoneLabel::Main => v1::PhoneLabel::Main,
        PhoneLabel::Other => v1::PhoneLabel::Other,
        PhoneLabel::Custom => v1::PhoneLabel::Custom,
    };
    Ok(v1::ProfilePhone {
        id: stored_id::<sid_ids::ProfilePhoneId, _>(p.id.0)
            .map_err(|e| internal("stored identifier", e))?,
        e164: p.e164,
        extension: p.extension,
        label: label.into(),
        custom_label: p.custom_label.clone(),
        is_primary: p.is_primary,
        can_receive_sms: p.can_receive_sms,
        can_receive_fax: p.can_receive_fax,
        can_receive_voice: p.can_receive_voice,
        verified: p.verified,
        verified_at: p.verified_at.map(to_timestamp),
    })
}

/// `e` as the API returns it; a corrupt stored id is never sent.
fn email_to_proto(e: &ProfileEmail) -> Result<v1::ProfileEmail, AccountError> {
    let label = match e.label {
        EmailLabel::Personal => v1::EmailLabel::Personal,
        EmailLabel::Work => v1::EmailLabel::Work,
        EmailLabel::School => v1::EmailLabel::School,
        EmailLabel::Other => v1::EmailLabel::Other,
        EmailLabel::Custom => v1::EmailLabel::Custom,
    };
    Ok(v1::ProfileEmail {
        id: stored_id::<sid_ids::ProfileEmailId, _>(e.id.0)
            .map_err(|e| internal("stored identifier", e))?,
        email: e.email.clone(),
        label: label.into(),
        custom_label: e.custom_label.clone(),
        is_primary: e.is_primary,
        verified: e.verified,
        verified_at: e.verified_at.map(to_timestamp),
    })
}

#[cfg(test)]
mod tests;
