// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AccountService implementation (CE).
//!
//! Self-service account management for authenticated users:
//! - Consent management (4 RPCs) — claim-level consent control
//! - Activity history, linked accounts, app launcher, notification prefs, passwordless — TODO

use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{AuditEntry, MutationContext, ProfileId};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::account::account_service_server::AccountService;
use sid_proto::sid::v1::account::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::principal::PrincipalType;

use sid_core::grpc_error::refuse::{
    invalid_field, missing_field, not_found, not_in_this_build, storage_failure,
};

/// CONSENT_NOT_FOUND: the caller has no consent for `site_id`.
fn consent_not_found(site_id: &str) -> Status {
    not_found(ErrorReason::ConsentNotFound, "Consent", site_id)
}

/// PHONE_NOT_FOUND: the caller's profile has no phone `id`.
fn phone_not_found(id: sid_core::models::ProfilePhoneId) -> Status {
    not_found(ErrorReason::PhoneNotFound, "ProfilePhone", id.0.to_string())
}

/// EMAIL_NOT_FOUND: the caller's profile has no email `id`.
fn email_not_found(id: sid_core::models::ProfileEmailId) -> Status {
    not_found(ErrorReason::EmailNotFound, "ProfileEmail", id.0.to_string())
}

// ── Claim value masking ──────────────────────────────────────────

/// Mask a claim value for preview display.
///
/// Rules:
/// - email: first char + "***" + "@" + domain → "j***@example.com"
/// - phone: first 3 chars + "***" + last 4 → "+38***4567"
/// - name/display_name: first char + "***" → "A***"
/// - other/unknown: "***"
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
        // Not a valid email format — generic mask.
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
    // Show first 3 chars + "***" + last 4.
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
    let first = &name[..first_char_len];
    format!("{first}***")
}

/// Resolve the current value of a claim and mask it for preview.
///
/// Maps OIDC claim names to Profile fields or Principal records.
fn resolve_claim_preview(
    claim_name: &str,
    profile: Option<&sid_core::models::profile::Profile>,
    principals: &[sid_core::models::principal::Principal],
) -> String {
    let raw_value = match claim_name {
        // Profile-level fields.
        "name" | "display_name" => profile.and_then(|p| p.formatted_name()),
        "given_name" => profile.and_then(|p| p.given_name.clone()),
        "family_name" => profile.and_then(|p| p.family_name.clone()),
        "middle_name" => profile.and_then(|p| p.middle_name.clone()),
        "preferred_username" => profile.and_then(|p| p.username.clone()),
        // Email — from primary Principal(Email).
        "email" | "email_verified" => principals
            .iter()
            .find(|p| p.principal_type == PrincipalType::Email && p.is_primary)
            .map(|p| p.value.clone()),
        // Phone — from primary Principal(Phone).
        "phone" | "phone_number" | "phone_number_verified" => principals
            .iter()
            .find(|p| p.principal_type == PrincipalType::Phone && p.is_primary)
            .or_else(|| {
                principals
                    .iter()
                    .find(|p| p.principal_type == PrincipalType::Phone)
            })
            .map(|p| p.value.clone()),
        // Unknown claim — no value to preview.
        _ => None,
    };

    match raw_value {
        Some(val) if !val.is_empty() => mask_claim_value(claim_name, &val),
        _ => String::new(),
    }
}

/// Convert proto PhoneLabel i32 to domain PhoneLabel.
fn proto_phone_label(v: i32) -> sid_core::models::profile_phone::PhoneLabel {
    use sid_core::models::profile_phone::PhoneLabel;
    match sid_proto::sid::v1::PhoneLabel::try_from(v) {
        Ok(sid_proto::sid::v1::PhoneLabel::Mobile) => PhoneLabel::Mobile,
        Ok(sid_proto::sid::v1::PhoneLabel::Home) => PhoneLabel::Home,
        Ok(sid_proto::sid::v1::PhoneLabel::Work) => PhoneLabel::Work,
        Ok(sid_proto::sid::v1::PhoneLabel::Fax) => PhoneLabel::Fax,
        Ok(sid_proto::sid::v1::PhoneLabel::Pager) => PhoneLabel::Pager,
        Ok(sid_proto::sid::v1::PhoneLabel::Main) => PhoneLabel::Main,
        Ok(sid_proto::sid::v1::PhoneLabel::Other) => PhoneLabel::Other,
        Ok(sid_proto::sid::v1::PhoneLabel::Custom) => PhoneLabel::Custom,
        _ => PhoneLabel::Mobile, // default
    }
}

/// Convert proto EmailLabel i32 to domain EmailLabel.
fn proto_email_label(v: i32) -> sid_core::models::profile_email::EmailLabel {
    use sid_core::models::profile_email::EmailLabel;
    match sid_proto::sid::v1::EmailLabel::try_from(v) {
        Ok(sid_proto::sid::v1::EmailLabel::Personal) => EmailLabel::Personal,
        Ok(sid_proto::sid::v1::EmailLabel::Work) => EmailLabel::Work,
        Ok(sid_proto::sid::v1::EmailLabel::School) => EmailLabel::School,
        Ok(sid_proto::sid::v1::EmailLabel::Other) => EmailLabel::Other,
        Ok(sid_proto::sid::v1::EmailLabel::Custom) => EmailLabel::Custom,
        _ => EmailLabel::Personal, // default
    }
}

/// Parse a phone ID string into `ProfilePhoneId`.
fn parse_phone_id(id: &str) -> Result<sid_core::models::profile_phone::ProfilePhoneId, Status> {
    uuid::Uuid::parse_str(id)
        .map(sid_core::models::profile_phone::ProfilePhoneId)
        .map_err(|_| invalid_field("phone_id", "not a phone identifier"))
}

/// Parse an email ID string into `ProfileEmailId`.
fn parse_email_id(id: &str) -> Result<sid_core::models::profile_email::ProfileEmailId, Status> {
    uuid::Uuid::parse_str(id)
        .map(sid_core::models::profile_email::ProfileEmailId)
        .map_err(|_| invalid_field("email_id", "not an email identifier"))
}

pub struct AccountServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl AccountServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
        }
    }

    /// The authenticated caller's profile.
    #[allow(clippy::result_large_err)]
    async fn extract_profile_id<T>(&self, req: &Request<T>) -> Result<ProfileId, Status> {
        Ok(authenticate(req, self.jwt.verifier(), &self.revocation)
            .await?
            .profile_id)
    }

    /// `profile_id`'s phone `id` as stored; NotFound for another profile's.
    async fn owned_phone(
        &self,
        profile_id: ProfileId,
        id: sid_core::models::ProfilePhoneId,
    ) -> Result<sid_core::models::ProfilePhone, Status> {
        self.storage
            .get_profile_phone(id)
            .await
            .map_err(storage_failure)?
            .filter(|p| p.profile_id == profile_id)
            .ok_or_else(|| phone_not_found(id))
    }

    /// `profile_id`'s email `id` as stored; NotFound for another profile's.
    async fn owned_email(
        &self,
        profile_id: ProfileId,
        id: sid_core::models::ProfileEmailId,
    ) -> Result<sid_core::models::ProfileEmail, Status> {
        self.storage
            .get_profile_email(id)
            .await
            .map_err(storage_failure)?
            .filter(|e| e.profile_id == profile_id)
            .ok_or_else(|| email_not_found(id))
    }
}

#[tonic::async_trait]
impl AccountService for AccountServiceImpl {
    // ── Consents ──

    async fn list_consents(
        &self,
        request: Request<ListConsentsRequest>,
    ) -> Result<Response<ListConsentsResponse>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;

        let records = self
            .storage
            .list_consents_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;

        // Batch lookup OAuth2Client for site_name + favicon (deduplicate client_ids).
        let client_ids: std::collections::HashSet<&str> =
            records.iter().map(|r| r.client_id.as_str()).collect();
        let mut client_info: std::collections::HashMap<String, (String, Option<String>)> =
            std::collections::HashMap::new();
        // A deleted client falls back to its id; a failed read is an error.
        for cid in client_ids {
            let client = self
                .storage
                .get_oauth2_client(cid)
                .await
                .map_err(storage_failure)?;
            if let Some(client) = client {
                client_info.insert(cid.to_string(), (client.client_name, client.logo_uri));
            }
        }

        let consents = records
            .into_iter()
            .map(|r| {
                let mandatory_count = r
                    .grants
                    .iter()
                    .filter(|g| {
                        g.claim_type == sid_core::models::consent::ClaimType::Data && g.is_active()
                    })
                    .count() as i32;
                let optional_count = r
                    .grants
                    .iter()
                    .filter(|g| {
                        g.claim_type == sid_core::models::consent::ClaimType::Attestation
                            && g.is_active()
                    })
                    .count() as i32;

                let (site_name, site_favicon) = client_info
                    .get(&r.client_id)
                    .map(|(name, favicon)| (name.clone(), favicon.clone()))
                    .unwrap_or_else(|| (r.client_id.clone(), None));

                ConsentInfo {
                    site_id: r.client_id.clone(),
                    site_name,
                    site_favicon,
                    status: if r.status.is_active() {
                        ConsentStatus::Active.into()
                    } else {
                        ConsentStatus::Inactive.into()
                    },
                    connected_at: Some(prost_types::Timestamp {
                        seconds: r.consented_at.timestamp(),
                        nanos: 0,
                    }),
                    claims_mandatory: mandatory_count,
                    claims_optional: optional_count,
                    last_sync: None,
                }
            })
            .collect();

        Ok(Response::new(ListConsentsResponse { consents }))
    }

    async fn get_consent_detail(
        &self,
        request: Request<GetConsentDetailRequest>,
    ) -> Result<Response<GetConsentDetailResponse>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let site_id = request.into_inner().site_id;

        if site_id.is_empty() {
            return Err(missing_field("site_id"));
        }

        let record = self
            .storage
            .get_consent_by_client(profile_id, &site_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| consent_not_found(&site_id))?;

        // Fetch profile + principals for value_preview masking.
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        let principals = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;

        let claims: Vec<ClaimConsent> = record
            .grants
            .iter()
            .map(|g| {
                let preview = if g.claim_type == sid_core::models::consent::ClaimType::Attestation {
                    String::new() // Attestations have no value to preview.
                } else {
                    resolve_claim_preview(&g.claim_name, profile.as_ref(), &principals)
                };

                ClaimConsent {
                    claim_name: g.claim_name.clone(),
                    claim_type: match g.claim_type {
                        sid_core::models::consent::ClaimType::Data => ClaimType::Mandatory.into(),
                        sid_core::models::consent::ClaimType::Attestation => {
                            ClaimType::Optional.into()
                        }
                    },
                    current_status: if g.is_active() {
                        ClaimConsentStatus::Granted.into()
                    } else {
                        ClaimConsentStatus::Denied.into()
                    },
                    value_preview: preview,
                    last_propagated: None,
                }
            })
            .collect();

        // Resolve site name + favicon from OAuth2Client registry.
        // A deleted client falls back to its id; a failed read is an error.
        let client = self
            .storage
            .get_oauth2_client(&record.client_id)
            .await
            .map_err(storage_failure)?;
        let (site_name, site_favicon) = match client {
            Some(client) => (client.client_name, client.logo_uri),
            None => (record.client_id.clone(), None),
        };

        let site_info = ConsentInfo {
            site_id: record.client_id.clone(),
            site_name,
            site_favicon,
            status: if record.status.is_active() {
                ConsentStatus::Active.into()
            } else {
                ConsentStatus::Inactive.into()
            },
            connected_at: Some(prost_types::Timestamp {
                seconds: record.consented_at.timestamp(),
                nanos: 0,
            }),
            claims_mandatory: claims
                .iter()
                .filter(|c| c.claim_type == i32::from(ClaimType::Mandatory))
                .count() as i32,
            claims_optional: claims
                .iter()
                .filter(|c| c.claim_type == i32::from(ClaimType::Optional))
                .count() as i32,
            last_sync: None,
        };

        Ok(Response::new(GetConsentDetailResponse {
            site_info: Some(site_info),
            claims,
        }))
    }

    async fn update_claim_consent(
        &self,
        request: Request<UpdateClaimConsentRequest>,
    ) -> Result<Response<()>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let req = request.into_inner();

        if req.site_id.is_empty() {
            return Err(missing_field("site_id"));
        }
        if req.claim_name.is_empty() {
            return Err(missing_field("claim_name"));
        }

        use sid_core::models::consent::{ClaimDecision, ClaimGrantChange, ClaimType};
        let record = self
            .storage
            .get_consent_by_client(profile_id, &req.site_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| consent_not_found(&req.site_id))?;

        // A claim granted again keeps what it was shared as.
        let decision = if req.grant {
            ClaimDecision::Grant(
                record
                    .grants
                    .iter()
                    .find(|g| g.claim_name == req.claim_name)
                    .map_or(ClaimType::Data, |g| g.claim_type),
            )
        } else {
            ClaimDecision::Revoke
        };

        // The event is owed by the same commit that changes the consent.
        let consent_event_type = if req.grant {
            sid_core::models::event::event_types::CONSENT_GRANTED
        } else {
            sid_core::models::event::event_types::CONSENT_REVOKED
        };
        let event = sid_core::models::event::Event::new("sid-account", consent_event_type)
            .with_subject(format!("profile/{}", profile_id))
            .with_data(serde_json::json!({
                "profile_id": profile_id.to_string(),
                "site_id": req.site_id,
                "claim_name": req.claim_name,
            }));
        let ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            if req.grant {
                "consent.claim_granted"
            } else {
                "consent.claim_revoked"
            },
            format!("{}:{}", req.site_id, req.claim_name),
        ))
        .with_work(event.relay());
        let change = self
            .storage
            .change_claim_grant(record.id, &req.claim_name, decision, ctx)
            .await
            .map_err(storage_failure)?;
        match change {
            ClaimGrantChange::Changed => {}
            // Already as asked: nothing changed, nothing announced.
            ClaimGrantChange::Unchanged => return Ok(Response::new(())),
            ClaimGrantChange::ConsentNotActive => {
                return Err(ApiError::new(
                    ErrorReason::InvalidState,
                    "an inactive consent takes no claim changes",
                )
                .with_precondition("CONSENT_STATE", req.site_id.clone(), "inactive")
                .into());
            }
        }

        info!(
            "Consent claim {} {} for profile {} site {}",
            req.claim_name,
            if req.grant { "granted" } else { "revoked" },
            profile_id,
            req.site_id
        );

        Ok(Response::new(()))
    }

    async fn disconnect_site(
        &self,
        request: Request<DisconnectSiteRequest>,
    ) -> Result<Response<()>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let site_id = request.into_inner().site_id;

        if site_id.is_empty() {
            return Err(missing_field("site_id"));
        }

        let record = self
            .storage
            .get_consent_by_client(profile_id, &site_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| consent_not_found(&site_id))?;

        let event = sid_core::models::event::Event::new(
            "sid-account",
            sid_core::models::event::event_types::CONSENT_REVOKED,
        )
        .with_subject(format!("profile/{}", profile_id))
        .with_data(serde_json::json!({
            "profile_id": profile_id.to_string(),
            "site_id": site_id,
            "disconnect": true,
        }));
        let ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            "consent.site_disconnected",
            site_id.clone(),
        ))
        .with_work(event.relay());
        let disconnected = self
            .storage
            .delete_consent(record.id, ctx)
            .await
            .map_err(storage_failure)?;
        if !disconnected {
            // Disconnected meanwhile: that disconnect announced it.
            return Err(consent_not_found(&site_id));
        }

        info!("Site {} disconnected for profile {}", site_id, profile_id);

        Ok(Response::new(()))
    }

    // ── Phone Management ──

    async fn add_phone(
        &self,
        request: Request<AddPhoneRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfilePhone>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let req = request.into_inner();

        if req.e164 == 0 {
            return Err(missing_field("e164"));
        }

        let now = chrono::Utc::now();
        let phone = sid_core::models::ProfilePhone {
            id: sid_core::models::profile_phone::ProfilePhoneId::new(),
            profile_id,
            e164: req.e164,
            extension: req.extension,
            label: proto_phone_label(req.label),
            custom_label: req.custom_label.filter(|s| !s.is_empty()),
            is_primary: req.is_primary,
            can_receive_sms: req.can_receive_sms,
            can_receive_fax: req.can_receive_fax,
            can_receive_voice: req.can_receive_voice,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        };

        // A primary phone takes the flag from the current one in the same write.
        self.storage
            .create_profile_phone(
                &phone,
                AuditEntry::user(
                    profile_id.to_string(),
                    "phone.added",
                    phone.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Phone {} added for profile {}", phone.id.0, profile_id);
        Ok(Response::new(super::convert::phone_to_proto(&phone)))
    }

    async fn remove_phone(
        &self,
        request: Request<RemovePhoneRequest>,
    ) -> Result<Response<()>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let phone_id = parse_phone_id(&request.into_inner().phone_id)?;

        // Another profile's phone is not found, as one that does not exist.
        self.owned_phone(profile_id, phone_id).await?;

        self.storage
            .delete_profile_phone(
                phone_id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "phone.removed",
                    phone_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(()))
    }

    async fn update_phone(
        &self,
        request: Request<UpdatePhoneRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfilePhone>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let req = request.into_inner();
        let phone_id = parse_phone_id(&req.phone_id)?;

        // Only the settings given are written, on this profile's phone: the
        // number, its verification and the primary flag stay as stored.
        let settings = sid_core::models::PhoneSettings {
            label: req.label.map(proto_phone_label),
            custom_label: req.custom_label.map(|s| Some(s).filter(|s| !s.is_empty())),
            can_receive_sms: req.can_receive_sms,
            can_receive_fax: req.can_receive_fax,
            can_receive_voice: req.can_receive_voice,
        };
        let updated = self
            .storage
            .update_profile_phone_settings(
                profile_id,
                phone_id,
                &settings,
                chrono::Utc::now(),
                AuditEntry::user(
                    profile_id.to_string(),
                    "phone.updated",
                    phone_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            return Err(phone_not_found(phone_id));
        }
        let phone = self.owned_phone(profile_id, phone_id).await?;

        Ok(Response::new(super::convert::phone_to_proto(&phone)))
    }

    async fn set_primary_phone(
        &self,
        request: Request<SetPrimaryPhoneRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfilePhone>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let phone_id = parse_phone_id(&request.into_inner().phone_id)?;

        // The flag moves from the current primary in one write.
        let moved = self
            .storage
            .set_primary_profile_phone(
                profile_id,
                phone_id,
                chrono::Utc::now(),
                AuditEntry::user(
                    profile_id.to_string(),
                    "phone.primary_set",
                    phone_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !moved {
            return Err(phone_not_found(phone_id));
        }
        let phone = self.owned_phone(profile_id, phone_id).await?;

        Ok(Response::new(super::convert::phone_to_proto(&phone)))
    }

    async fn list_phones(
        &self,
        request: Request<()>,
    ) -> Result<Response<ListPhonesResponse>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;

        let phones = self
            .storage
            .list_profile_phones(profile_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListPhonesResponse {
            phones: phones.iter().map(super::convert::phone_to_proto).collect(),
        }))
    }

    // ── Email Management ──

    async fn add_email(
        &self,
        request: Request<AddEmailRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfileEmail>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let req = request.into_inner();

        if req.email.is_empty() {
            return Err(missing_field("email"));
        }
        // A contact keeps the spelling given (its delivery address); only an
        // invalid mailbox is refused, and nothing is folded.
        let address =
            sid_authn::email::parse(req.email.trim(), &sid_authn::email::EmailPolicy::LOCAL)
                .map_err(|e| invalid_field("email", e.to_string()))?
                .delivery;

        let now = chrono::Utc::now();
        let email = sid_core::models::ProfileEmail {
            id: sid_core::models::profile_email::ProfileEmailId::new(),
            profile_id,
            email: address,
            label: proto_email_label(req.label),
            custom_label: req.custom_label.filter(|s| !s.is_empty()),
            is_primary: req.is_primary,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        };

        // A primary email takes the flag from the current one in the same write.
        self.storage
            .create_profile_email(
                &email,
                AuditEntry::user(
                    profile_id.to_string(),
                    "email.added",
                    email.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Email {} added for profile {}", email.id.0, profile_id);
        Ok(Response::new(super::convert::email_to_proto(&email)))
    }

    async fn remove_email(
        &self,
        request: Request<RemoveEmailRequest>,
    ) -> Result<Response<()>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let email_id = parse_email_id(&request.into_inner().email_id)?;

        // Another profile's email is not found, as one that does not exist.
        self.owned_email(profile_id, email_id).await?;

        self.storage
            .delete_profile_email(
                email_id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "email.removed",
                    email_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(()))
    }

    async fn update_email(
        &self,
        request: Request<UpdateEmailRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfileEmail>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let req = request.into_inner();
        let email_id = parse_email_id(&req.email_id)?;

        // Only the label is written, on this profile's email: the address, its
        // verification and the primary flag stay as stored.
        let settings = sid_core::models::EmailSettings {
            label: req.label.map(proto_email_label),
            custom_label: req.custom_label.map(|s| Some(s).filter(|s| !s.is_empty())),
        };
        let updated = self
            .storage
            .update_profile_email_settings(
                profile_id,
                email_id,
                &settings,
                chrono::Utc::now(),
                AuditEntry::user(
                    profile_id.to_string(),
                    "email.updated",
                    email_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            return Err(email_not_found(email_id));
        }
        let email = self.owned_email(profile_id, email_id).await?;

        Ok(Response::new(super::convert::email_to_proto(&email)))
    }

    async fn set_primary_email(
        &self,
        request: Request<SetPrimaryEmailRequest>,
    ) -> Result<Response<sid_proto::sid::v1::ProfileEmail>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;
        let email_id = parse_email_id(&request.into_inner().email_id)?;

        // The flag moves from the current primary in one write.
        let moved = self
            .storage
            .set_primary_profile_email(
                profile_id,
                email_id,
                chrono::Utc::now(),
                AuditEntry::user(
                    profile_id.to_string(),
                    "email.primary_set",
                    email_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !moved {
            return Err(email_not_found(email_id));
        }
        let email = self.owned_email(profile_id, email_id).await?;

        Ok(Response::new(super::convert::email_to_proto(&email)))
    }

    async fn list_emails(
        &self,
        request: Request<()>,
    ) -> Result<Response<ListEmailsResponse>, Status> {
        let profile_id = self.extract_profile_id(&request).await?;

        let emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListEmailsResponse {
            emails: emails.iter().map(super::convert::email_to_proto).collect(),
        }))
    }

    // ── Activity History (not yet implemented) ──

    async fn list_activity_events(
        &self,
        _request: Request<ListActivityEventsRequest>,
    ) -> Result<Response<ListActivityEventsResponse>, Status> {
        Err(not_in_this_build("activity_history"))
    }

    async fn get_activity_event_detail(
        &self,
        _request: Request<GetActivityEventDetailRequest>,
    ) -> Result<Response<ActivityEvent>, Status> {
        Err(not_in_this_build("activity_history"))
    }

    async fn report_suspicious_event(
        &self,
        _request: Request<ReportSuspiciousEventRequest>,
    ) -> Result<Response<()>, Status> {
        Err(not_in_this_build("activity_history"))
    }

    // ── Linked Accounts (not yet implemented) ──

    async fn list_linked_accounts(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ListLinkedAccountsResponse>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    async fn link_account(
        &self,
        _request: Request<LinkAccountRequest>,
    ) -> Result<Response<LinkAccountResponse>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    async fn unlink_account(
        &self,
        _request: Request<UnlinkAccountRequest>,
    ) -> Result<Response<()>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    async fn reauthenticate_link(
        &self,
        _request: Request<ReauthenticateLinkRequest>,
    ) -> Result<Response<ReauthenticateLinkResponse>, Status> {
        Err(not_in_this_build("linked_accounts"))
    }

    // ── App Launcher (not yet implemented) ──

    async fn list_available_apps(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ListAvailableAppsResponse>, Status> {
        Err(not_in_this_build("app_launcher"))
    }

    async fn launch_app(
        &self,
        _request: Request<LaunchAppRequest>,
    ) -> Result<Response<LaunchAppResponse>, Status> {
        Err(not_in_this_build("app_launcher"))
    }

    // ── Notification Preferences (not yet implemented) ──

    async fn get_notification_preferences(
        &self,
        _request: Request<()>,
    ) -> Result<Response<NotificationPreferences>, Status> {
        Err(not_in_this_build("notification_preferences"))
    }

    async fn update_notification_preferences(
        &self,
        _request: Request<UpdateNotificationPreferencesRequest>,
    ) -> Result<Response<NotificationPreferences>, Status> {
        Err(not_in_this_build("notification_preferences"))
    }

    // ── Passwordless (not yet implemented) ──

    async fn get_passwordless_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<PasswordlessStatus>, Status> {
        Err(not_in_this_build("passwordless"))
    }

    async fn enable_passwordless(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        Err(not_in_this_build("passwordless"))
    }

    async fn disable_passwordless(
        &self,
        _request: Request<()>,
    ) -> Result<Response<DisablePasswordlessResponse>, Status> {
        Err(not_in_this_build("passwordless"))
    }
}

#[cfg(test)]
mod tests;
