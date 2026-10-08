// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 gRPC service implementation.
//!
//! Implements `ScimService` trait generated from `proto/sid/v1/scim.proto`.
//! All storage writes include `AuditEntry` (audit by construction).

use std::sync::Arc;

use sid_authn::connector_auth::{ConnectorCaller, authenticate_connector};
use sid_authn::resource_token::ResourceTokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{dependency_unavailable, storage_failure};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{
    AuditEntry, DirectoryGroupWrite, DirectoryUserWrite, DirectoryWriteMode, Group, GroupId,
    GroupMember, MutationContext, OrgId, Principal, PrincipalType, ProfileId, ProfileMetadata,
    ProfileStatus, ResourceId, RevocationReason, SCIM_GROUP_CREATE, SCIM_GROUP_DELETE,
    SCIM_GROUP_MEMBERSHIP, SCIM_GROUP_READ, SCIM_GROUP_UPDATE, SCIM_USER_CREATE,
    SCIM_USER_DEACTIVATE, SCIM_USER_READ, SCIM_USER_UPDATE, SessionEnd,
    event::{Event, event_types},
};
use sid_plugin::StorageBackend;
use sid_plugin::authz::{AuthzCheckRequest, AuthzEngine};
use sid_proto::sid::v1 as proto;
use sid_proto::sid::v1::scim_service_server::ScimService;
use tonic::{Request, Response, Status};
use tracing::{instrument, warn};
use uuid::Uuid;

use crate::filter;
use crate::mapping::{
    CreateUserMapping, MappingError, ScimOrgContext, check_single_primary, corporate_contact,
    email_contact, email_key, email_principal, phone_contact, phone_digits,
    scim_create_group_to_sid, scim_create_user_to_sid, sid_to_scim_group, sid_to_scim_user,
};
use crate::patch;
use crate::refusal;

/// SCIM gRPC service implementation.
pub struct ScimServiceImpl {
    storage: Arc<dyn StorageBackend>,
    org_ctx: ScimOrgContext,
    base_url: String,
    directory: ScimDirectory,
    engine: Arc<dyn AuthzEngine>,
    revocation: Arc<RevocationCache>,
    /// Verifies the directory resource's access tokens (connectors using
    /// OAuth client credentials); without it only SCIM bearers are taken.
    tokens: Option<Arc<ResourceTokenVerifier>>,
}

impl ScimServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        org_ctx: ScimOrgContext,
        base_url: String,
        directory: ScimDirectory,
        engine: Arc<dyn AuthzEngine>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            org_ctx,
            base_url,
            directory,
            engine,
            revocation,
            tokens: None,
        }
    }

    /// Also accept the directory resource's access tokens `tokens` verifies.
    pub fn with_access_tokens(mut self, tokens: Arc<ResourceTokenVerifier>) -> Self {
        self.tokens = Some(tokens);
        self
    }

    /// Apply one request's changes to a user in one write, then stop the
    /// tokens of every session a deprovisioning ended (the write already
    /// owes their back-channel logouts).
    #[allow(clippy::result_large_err)]
    async fn write_user(
        &self,
        write: &DirectoryUserWrite,
        ctx: MutationContext,
    ) -> Result<(), Status> {
        let ended = self
            .storage
            .write_directory_user(write, ctx)
            .await
            .map_err(|e| refusal::user_write(write.profile_id(), e))?;
        for session in &ended {
            if let Err(e) = self.revocation.revoke_session(session.id.to_string()).await {
                warn!(
                    session_id = %session.id,
                    error = %e,
                    "ended session not propagated to the revocation cache"
                );
            }
        }
        Ok(())
    }

    /// Authenticate the inbound connector of this directory and require
    /// `action` of it. An administrator's sign-in is no connector credential.
    #[allow(clippy::result_large_err)]
    async fn provisioner<T>(
        &self,
        request: &Request<T>,
        action: &str,
    ) -> Result<ConnectorCaller, Status> {
        let caller = authenticate_connector(
            request,
            self.storage.as_ref(),
            self.directory.org,
            self.tokens.as_deref(),
        )
        .await?;
        self.authorize(&caller, action).await?;
        Ok(caller)
    }

    /// Require `action` of `caller` on this directory's resource: within its
    /// token's scopes, and as its current role assignments decide.
    #[allow(clippy::result_large_err)]
    async fn authorize(&self, caller: &ConnectorCaller, action: &str) -> Result<(), Status> {
        if !caller.may(action) {
            return Err(ApiError::new(
                ErrorReason::ScopeNotGranted,
                "the access token does not grant this operation",
            )
            .into());
        }
        let decision = self
            .engine
            .check(&AuthzCheckRequest {
                subject: format!("provisioning_connector:{}", caller.connector.id),
                action: action.to_owned(),
                resource: format!("oauth_resource:{}", self.directory.resource),
                context: Default::default(),
            })
            .await
            .map_err(|e| dependency_unavailable("provisioning authorization", e))?;
        if decision.is_allowed() {
            Ok(())
        } else {
            Err(ApiError::new(
                ErrorReason::InsufficientPermissions,
                "the connector may not perform this operation",
            )
            .into())
        }
    }
}

/// The directory a SCIM endpoint serves: its organization and the protected
/// resource provisioning connectors hold their roles on.
#[derive(Debug, Clone, Copy)]
pub struct ScimDirectory {
    pub org: OrgId,
    pub resource: ResourceId,
}

/// The audit entry of `caller`'s `action` on `target`: the connector is the
/// actor, its credential and direction ride along (never the secret).
fn by_connector(caller: &ConnectorCaller, action: &str, target: &str) -> AuditEntry {
    AuditEntry::connector(caller.connector.id.to_string(), action, target).with_metadata(
        serde_json::json!({
            "credential_id": caller.credential_id.to_string(),
            "direction": "inbound",
            "org_id": caller.connector.org_id.to_string(),
        }),
    )
}

/// The audit entry of a SCIM write, owing its lifecycle event (outbound
/// provisioning, invitations) in the same transaction, and committing only
/// while the connector's authority still holds.
fn audited(caller: &ConnectorCaller, audit: AuditEntry, event: &Event) -> MutationContext {
    MutationContext::from(audit)
        .with_work(event.relay())
        .fenced_by(caller.fence())
}

/// Deprovisioning ends every session as an administrative action by SCIM.
fn deprovision() -> SessionEnd {
    SessionEnd::new(RevocationReason::Admin, "scim")
}

// ── Helpers ──

/// The user identifier in `attribute` (`id`, or a group member's `value`).
#[allow(clippy::result_large_err)]
fn parse_profile_id(attribute: &str, id: &str) -> Result<ProfileId, Status> {
    ProfileId::parse(id).map_err(|_| refusal::invalid_id(attribute))
}

#[allow(clippy::result_large_err)]
fn parse_group_id(id: &str) -> Result<GroupId, Status> {
    Uuid::parse_str(id)
        .map(GroupId)
        .map_err(|_| refusal::invalid_id("id"))
}

#[tonic::async_trait]
impl ScimService for ScimServiceImpl {
    // ── User CRUD ──

    #[instrument(skip_all, fields(user_name = %request.get_ref().user_name))]
    async fn create_user(
        &self,
        request: Request<proto::ScimCreateUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_CREATE).await?;
        let req = request.into_inner();

        if req.user_name.is_empty() {
            return Err(refusal::required("userName"));
        }

        let CreateUserMapping {
            profile,
            principals,
            metadata,
            emails,
            phones,
        } = scim_create_user_to_sid(&req, &self.org_ctx).map_err(refusal::mapping)?;
        let profile_id_str = profile.id.to_string();

        // The provisioning event triggers the sid-notify invitation.
        let email = req.emails.first().map(|e| e.value.as_str()).unwrap_or("");
        let event = Event::new("sid-scim", event_types::SCIM_USER_PROVISIONED)
            .with_subject(format!("profile/{}", profile_id_str))
            .with_data(serde_json::json!({
                "profile_id": profile_id_str,
                "user_name": req.user_name,
                "email": email,
                "org_domain": self.org_ctx.org_domain,
            }));

        // One write: an account whose login handle is taken (RFC 7644 §3.3,
        // 409) or that cannot be stored whole leaves nothing behind.
        let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Create, profile.clone());
        write.bind = principals.clone();
        write.add_emails = emails;
        write.add_phones = phones;
        write.set_metadata = metadata.clone();
        let mut audit = by_connector(&caller, "scim.user.create", &profile_id_str);
        audit.metadata["external_id"] = serde_json::json!(req.external_id);
        self.write_user(&write, audited(&caller, audit, &event))
            .await?;

        Ok(Response::new(sid_to_scim_user(
            &profile,
            &principals,
            &write.add_emails,
            &metadata,
            &[],
            &self.org_ctx.org_domain,
            &self.base_url,
        )))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn get_user(
        &self,
        request: Request<proto::ScimGetUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        self.provisioner(&request, SCIM_USER_READ).await?;
        let req = request.into_inner();
        let profile_id = parse_profile_id("id", &req.id)?;

        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(profile_id))?;

        let identifiers = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;

        let metadata = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(storage_failure)?;

        let groups = self
            .storage
            .list_groups_for_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        let group_refs: Vec<(GroupId, String)> =
            groups.iter().map(|g| (g.id, g.name.clone())).collect();
        let emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;

        let scim_user = sid_to_scim_user(
            &profile,
            &identifiers,
            &emails,
            &metadata,
            &group_refs,
            &self.org_ctx.org_domain,
            &self.base_url,
        );

        Ok(Response::new(scim_user))
    }

    #[instrument(skip_all, fields(filter = %request.get_ref().filter))]
    async fn list_users(
        &self,
        request: Request<proto::ScimListUsersRequest>,
    ) -> Result<Response<proto::ScimListUsersResponse>, Status> {
        self.provisioner(&request, SCIM_USER_READ).await?;
        let req = request.into_inner();

        // SCIM pagination: 1-based startIndex
        let start_index = std::cmp::max(req.start_index, 1);
        let count = if req.count <= 0 {
            100
        } else {
            std::cmp::min(req.count, 1000)
        };

        // Parse SCIM filter (if provided)
        let parsed_filter = if !req.filter.is_empty() {
            Some(filter::parse_filter(&req.filter).map_err(|_| refusal::invalid_filter())?)
        } else {
            None
        };

        // When filter is present, we need to fetch all profiles then filter in-memory.
        // When no filter, use storage-level pagination.
        if let Some(ref f) = parsed_filter {
            // Fetch all profiles (filter requires full scan)
            let profiles = self
                .storage
                .list_profiles(0, 10000) // CE: reasonable upper bound
                .await
                .map_err(storage_failure)?;

            // Contacts are read before matching only when the filter names
            // them; otherwise only for the users that match.
            let filter_needs_emails = f.references("emails");
            let mut all_resources = Vec::new();
            for profile in &profiles {
                let identifiers = self
                    .storage
                    .get_principals_by_profile(profile.id)
                    .await
                    .map_err(storage_failure)?;
                let metadata = self
                    .storage
                    .list_profile_metadata(profile.id)
                    .await
                    .map_err(storage_failure)?;
                let mut emails = Vec::new();
                if filter_needs_emails {
                    emails = self
                        .storage
                        .list_profile_emails(profile.id)
                        .await
                        .map_err(storage_failure)?;
                }
                let user = |emails: &[sid_core::models::ProfileEmail]| {
                    sid_to_scim_user(
                        profile,
                        &identifiers,
                        emails,
                        &metadata,
                        &[], // Skip group lookups for list (performance)
                        &self.org_ctx.org_domain,
                        &self.base_url,
                    )
                };

                if !filter::matches_user_multivalued(f, &user(&emails)) {
                    continue;
                }
                if !filter_needs_emails {
                    emails = self
                        .storage
                        .list_profile_emails(profile.id)
                        .await
                        .map_err(storage_failure)?;
                }
                all_resources.push(user(&emails));
            }

            let total = all_resources.len() as i32;
            let offset = (start_index - 1) as usize;
            let resources: Vec<proto::ScimUser> = all_resources
                .into_iter()
                .skip(offset)
                .take(count as usize)
                .collect();

            Ok(Response::new(proto::ScimListUsersResponse {
                resources,
                total_results: total,
                start_index,
                items_per_page: count,
            }))
        } else {
            // No filter: use storage-level pagination
            let offset = (start_index - 1) as u64;
            let profiles = self
                .storage
                .list_profiles(offset, count as u64)
                .await
                .map_err(storage_failure)?;

            let total = self
                .storage
                .count_profiles()
                .await
                .map_err(storage_failure)?;

            let mut resources = Vec::with_capacity(profiles.len());
            for profile in &profiles {
                let identifiers = self
                    .storage
                    .get_principals_by_profile(profile.id)
                    .await
                    .map_err(storage_failure)?;
                let metadata = self
                    .storage
                    .list_profile_metadata(profile.id)
                    .await
                    .map_err(storage_failure)?;
                let emails = self
                    .storage
                    .list_profile_emails(profile.id)
                    .await
                    .map_err(storage_failure)?;

                resources.push(sid_to_scim_user(
                    profile,
                    &identifiers,
                    &emails,
                    &metadata,
                    &[],
                    &self.org_ctx.org_domain,
                    &self.base_url,
                ));
            }

            Ok(Response::new(proto::ScimListUsersResponse {
                resources,
                total_results: total as i32,
                start_index,
                items_per_page: count,
            }))
        }
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn replace_user(
        &self,
        request: Request<proto::ScimReplaceUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_UPDATE).await?;
        let req = request.into_inner();
        let profile_id = parse_profile_id("id", &req.id)?;

        let mut profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(profile_id))?;

        let profile_id_str = profile.id.to_string();

        // Update name from SCIM structured name or display_name fallback
        if let Some(name) = &req.name {
            if !name.given_name.is_empty() {
                profile.given_name = Some(name.given_name.clone());
            }
            if !name.family_name.is_empty() {
                profile.family_name = Some(name.family_name.clone());
            }
            if !name.middle_name.is_empty() {
                profile.middle_name = Some(name.middle_name.clone());
            }
        } else if !req.display_name.is_empty() {
            // No structured name provided — use display_name as given_name fallback
            profile.given_name = Some(req.display_name.clone());
            profile.family_name = None;
        }

        check_single_primary(&req.emails, &req.phone_numbers).map_err(refusal::mapping)?;
        let now = chrono::Utc::now();
        let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Update, profile.clone());

        // Replace contact emails and phones (profile_emails, profile_phones).
        write.remove_emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .map(|e| e.id)
            .collect();
        write.add_emails = req
            .emails
            .iter()
            .filter(|e| !e.value.is_empty())
            .map(|e| email_contact(profile_id, e, now))
            .collect::<Result<_, _>>()
            .map_err(refusal::mapping)?;
        write.remove_phones = self
            .storage
            .list_profile_phones(profile_id)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .map(|p| p.id)
            .collect();
        for phone in req.phone_numbers.iter().filter(|p| !p.value.is_empty()) {
            write.add_phones.push(
                phone_contact(profile_id, &phone.value, &phone.r#type, phone.primary, now)
                    .map_err(refusal::mapping)?,
            );
        }

        // Update active status.
        // SCIM active=false → Suspended.
        // SCIM active=true + currently Suspended → reactivate to Provisioned or Active
        //   depending on whether the user has claimed the profile.
        //   Provisioned profiles MUST NOT transition to Active via SCIM —
        //   only via secure channel claim (the user binds an OPAQUE password).
        if !req.active {
            profile.status = ProfileStatus::Suspended;
        } else if profile.status == ProfileStatus::Suspended {
            // Reactivate: if profile was previously Provisioned (never claimed),
            // go back to Provisioned — not Active.
            // We use a heuristic: if no credentials exist, profile was never claimed.
            // For now, check if profile has any login-enabled identifiers that are verified.
            // Unverified = never claimed = restore to Provisioned.
            let identifiers = self
                .storage
                .get_principals_by_profile(profile_id)
                .await
                .map_err(storage_failure)?;
            let has_verified_login = identifiers.iter().any(|i| i.verified);
            if has_verified_login {
                profile.status = ProfileStatus::Active;
            } else {
                profile.status = ProfileStatus::Provisioned;
            }
        }

        write.profile = profile.clone();
        if !req.active {
            write.end_access = Some(deprovision());
        }

        // Replace the contact principals the directory manages; the
        // corporate login handle stays.
        let old_identifiers = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        write.unbind = old_identifiers
            .iter()
            .filter(|i| {
                matches!(
                    i.principal_type,
                    PrincipalType::Email | PrincipalType::Phone
                )
            })
            .map(|i| i.id)
            .collect();
        let new_emails: Vec<Principal> = req
            .emails
            .iter()
            .filter(|e| !e.value.is_empty())
            .map(|e| email_principal(profile_id, e))
            .collect::<Result<_, _>>()
            .map_err(refusal::mapping)?;
        let new_identifiers: Vec<Principal> = new_emails
            .into_iter()
            .chain(
                req.phone_numbers
                    .iter()
                    .filter(|p| !p.value.is_empty())
                    .map(|p| {
                        corporate_contact(
                            profile_id,
                            PrincipalType::Phone,
                            p.value.clone(),
                            p.primary,
                        )
                    }),
            )
            .collect();
        write.bind = new_identifiers.clone();

        // RFC 7644 §3.5.1: PUT replaces the resource, so an attribute the
        // request leaves empty is cleared.
        let mut new_metadata = Vec::new();
        for (key, value) in [
            ("employee_id", &req.external_id),
            ("department", &req.department),
            ("title", &req.title),
        ] {
            if value.is_empty() {
                write.remove_metadata.push(key.to_string());
            } else {
                new_metadata.push(ProfileMetadata::new(
                    profile_id,
                    key,
                    serde_json::Value::String(value.clone()),
                ));
            }
        }
        write.set_metadata = new_metadata.clone();

        let event = Event::new("sid-scim", event_types::SCIM_USER_UPDATED)
            .with_subject(format!("profile/{}", profile_id_str))
            .with_data(serde_json::json!({
                "profile_id": profile_id_str,
                "trigger": "scim_replace",
                "org_domain": self.org_ctx.org_domain,
            }));
        self.write_user(
            &write,
            audited(
                &caller,
                by_connector(&caller, "scim.user.replace", &profile_id_str),
                &event,
            ),
        )
        .await?;

        let all_identifiers: Vec<Principal> = old_identifiers
            .into_iter()
            .filter(|i| i.principal_type == PrincipalType::Username)
            .chain(new_identifiers)
            .collect();
        let group_refs = self.load_group_refs(profile_id).await?;
        let emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;
        Ok(Response::new(sid_to_scim_user(
            &profile,
            &all_identifiers,
            &emails,
            &new_metadata,
            &group_refs,
            &self.org_ctx.org_domain,
            &self.base_url,
        )))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn patch_user(
        &self,
        request: Request<proto::ScimPatchUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_UPDATE).await?;
        let req = request.into_inner();
        let profile_id = parse_profile_id("id", &req.id)?;

        let mut profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(profile_id))?;

        let profile_id_str = profile.id.to_string();

        // Apply PATCH operations
        let patch_result =
            patch::apply_user_patch(&mut profile, &req.operations).map_err(refusal::patch)?;

        // Resolve reactivation target state.
        // Provisioned profiles MUST NOT become Active via SCIM — only via secure channel claim.
        if patch_result.needs_reactivation {
            let identifiers = self
                .storage
                .get_principals_by_profile(profile_id)
                .await
                .map_err(storage_failure)?;
            let has_verified_login = identifiers.iter().any(|i| i.verified);
            profile.status = if has_verified_login {
                ProfileStatus::Active
            } else {
                ProfileStatus::Provisioned
            };
        }

        // RFC 7643 §2.4: at most one added value per attribute is primary.
        for (id_type, attribute) in [
            (PrincipalType::Email, "emails"),
            (PrincipalType::Phone, "phoneNumbers"),
        ] {
            let primaries = patch_result
                .add_identifiers
                .iter()
                .filter(|pi| pi.id_type == id_type && pi.is_primary)
                .count();
            if primaries > 1 {
                return Err(refusal::mapping(MappingError::MultiplePrimary(attribute)));
            }
        }

        let now = chrono::Utc::now();
        let identifiers = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        let emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;
        let phones = self
            .storage
            .list_profile_phones(profile_id)
            .await
            .map_err(storage_failure)?;
        let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Update, profile.clone());
        if profile.status == ProfileStatus::Suspended {
            write.end_access = Some(deprovision());
        }

        // Remove identifiers and their contact records by value.
        for (id_type, value) in &patch_result.remove_identifier_values {
            // An email is matched by its resolution key: the principal holds
            // it, and the contact's spelling folds to it.
            let key = match id_type {
                PrincipalType::Email => email_key(value),
                _ => Some(value.clone()),
            };
            if let Some(ident) = identifiers
                .iter()
                .find(|i| i.principal_type == *id_type && Some(&i.value) == key.as_ref())
            {
                write.unbind.push(ident.id);
            }
            match id_type {
                PrincipalType::Email => write.remove_emails.extend(
                    emails
                        .iter()
                        .filter(|e| key.is_some() && email_key(&e.email) == key)
                        .map(|e| e.id),
                ),
                PrincipalType::Phone => {
                    if let Ok(e164) = phone_digits(value) {
                        write
                            .remove_phones
                            .extend(phones.iter().filter(|p| p.e164 == e164).map(|p| p.id));
                    }
                }
                _ => {}
            }
        }

        // RFC 7644 §3.5.2: a value added as primary makes the attribute's
        // other values non-primary, so the current primary is demoted first.
        for pi in patch_result
            .add_identifiers
            .iter()
            .filter(|pi| pi.is_primary)
        {
            for held in identifiers.iter().filter(|i| {
                i.principal_type == pi.id_type && i.is_primary && !write.unbind.contains(&i.id)
            }) {
                let mut demoted = held.clone();
                demoted.is_primary = false;
                write.bind.push(demoted);
            }
            match pi.id_type {
                PrincipalType::Email => {
                    for held in emails
                        .iter()
                        .filter(|e| e.is_primary && !write.remove_emails.contains(&e.id))
                    {
                        let mut demoted = held.clone();
                        demoted.is_primary = false;
                        demoted.updated_at = now;
                        write.add_emails.push(demoted);
                    }
                }
                PrincipalType::Phone => {
                    for held in phones
                        .iter()
                        .filter(|p| p.is_primary && !write.remove_phones.contains(&p.id))
                    {
                        let mut demoted = held.clone();
                        demoted.is_primary = false;
                        demoted.updated_at = now;
                        write.add_phones.push(demoted);
                    }
                }
                _ => {}
            }
        }

        // Add identifiers with their contact records.
        for pi in &patch_result.add_identifiers {
            match pi.id_type {
                PrincipalType::Email => {
                    let email = proto::ScimEmail {
                        value: pi.value.clone(),
                        r#type: "work".into(),
                        primary: pi.is_primary,
                    };
                    write
                        .bind
                        .push(email_principal(profile_id, &email).map_err(refusal::mapping)?);
                    write
                        .add_emails
                        .push(email_contact(profile_id, &email, now).map_err(refusal::mapping)?);
                }
                PrincipalType::Phone => {
                    write.bind.push(corporate_contact(
                        profile_id,
                        pi.id_type,
                        pi.value.clone(),
                        pi.is_primary,
                    ));
                    write.add_phones.push(
                        phone_contact(profile_id, &pi.value, "work", pi.is_primary, now)
                            .map_err(refusal::mapping)?,
                    );
                }
                _ => write.bind.push(corporate_contact(
                    profile_id,
                    pi.id_type,
                    pi.value.clone(),
                    pi.is_primary,
                )),
            }
        }

        write.set_metadata = patch_result
            .set_metadata
            .iter()
            .map(|(key, value)| ProfileMetadata::new(profile_id, key, value.clone()))
            .collect();
        write.remove_metadata = patch_result.remove_metadata.clone();

        let event = Event::new("sid-scim", event_types::SCIM_USER_UPDATED)
            .with_subject(format!("profile/{}", profile_id_str))
            .with_data(serde_json::json!({
                "profile_id": profile_id_str,
                "trigger": "scim_patch",
                "org_domain": self.org_ctx.org_domain,
            }));
        self.write_user(
            &write,
            audited(
                &caller,
                by_connector(&caller, "scim.user.patch", &profile_id_str),
                &event,
            ),
        )
        .await?;

        // Build response with fresh data
        let identifiers = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        let metadata = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(storage_failure)?;
        let group_refs = self.load_group_refs(profile_id).await?;
        let emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(sid_to_scim_user(
            &profile,
            &identifiers,
            &emails,
            &metadata,
            &group_refs,
            &self.org_ctx.org_domain,
            &self.base_url,
        )))
    }

    /// SCIM DELETE = **deactivate** (soft delete), NOT hard delete: the profile
    /// is suspended, every live sign-in ends, downstream apps receive
    /// `active=false` via SCIM outbound.
    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn delete_user(
        &self,
        request: Request<proto::ScimDeleteUserRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_DEACTIVATE).await?;
        let req = request.into_inner();
        let profile_id = parse_profile_id("id", &req.id)?;

        let mut profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(profile_id))?;

        // Soft delete: deactivate, don't destroy.
        // Arch doc: "deactivate, not delete — downstream retains audit"
        profile.status = ProfileStatus::Suspended;

        let profile_id_str = profile_id.to_string();

        let event = Event::new("sid-scim", event_types::SCIM_USER_DEACTIVATED)
            .with_subject(format!("profile/{}", profile_id_str))
            .with_data(serde_json::json!({
                "profile_id": profile_id_str,
                "trigger": "scim_delete",
            }));
        let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Update, profile);
        write.end_access = Some(deprovision());
        self.write_user(
            &write,
            audited(
                &caller,
                by_connector(&caller, "scim.user.deactivate", &profile_id_str),
                &event,
            ),
        )
        .await?;

        Ok(Response::new(()))
    }

    // ── Group CRUD ──

    #[instrument(skip_all, fields(display_name = %request.get_ref().display_name))]
    async fn create_group(
        &self,
        request: Request<proto::ScimCreateGroupRequest>,
    ) -> Result<Response<proto::ScimGroup>, Status> {
        let caller = self.provisioner(&request, SCIM_GROUP_CREATE).await?;
        let req = request.into_inner();

        if req.display_name.is_empty() {
            return Err(refusal::required("displayName"));
        }
        // Members given at creation are membership writes like any other.
        if !req.members.is_empty() {
            self.authorize(&caller, SCIM_GROUP_MEMBERSHIP).await?;
        }

        let group = scim_create_group_to_sid(&req, self.org_ctx.project_id);
        let group_id_str = group.id.0.to_string();

        let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
        for member_ref in &req.members {
            let pid = parse_profile_id("members", &member_ref.value)?;
            write.add_members.push(GroupMember::new(group.id, pid));
        }
        let event = Event::new("sid-scim", event_types::SCIM_GROUP_CREATED)
            .with_subject(format!("group/{}", group_id_str))
            .with_data(serde_json::json!({
                "group_id": group_id_str,
                "display_name": group.name,
                "member_count": write.add_members.len(),
            }));
        self.storage
            .write_directory_group(
                &write,
                audited(
                    &caller,
                    by_connector(&caller, "scim.group.create", &group_id_str),
                    &event,
                ),
            )
            .await
            .map_err(|e| refusal::group_write(group.id, e))?;

        let members = self.load_member_refs(group.id).await?;
        Ok(Response::new(sid_to_scim_group(
            &group,
            &members,
            &self.base_url,
        )))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn get_group(
        &self,
        request: Request<proto::ScimGetGroupRequest>,
    ) -> Result<Response<proto::ScimGroup>, Status> {
        self.provisioner(&request, SCIM_GROUP_READ).await?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.id)?;

        let group = self
            .storage
            .get_group(group_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::group_not_found(group_id))?;

        let members = self.load_member_refs(group_id).await?;
        let scim_group = sid_to_scim_group(&group, &members, &self.base_url);

        Ok(Response::new(scim_group))
    }

    #[instrument(skip_all)]
    async fn list_groups(
        &self,
        request: Request<proto::ScimListGroupsRequest>,
    ) -> Result<Response<proto::ScimListGroupsResponse>, Status> {
        self.provisioner(&request, SCIM_GROUP_READ).await?;
        let req = request.into_inner();

        let start_index = std::cmp::max(req.start_index, 1);
        let count = if req.count <= 0 {
            100
        } else {
            std::cmp::min(req.count, 1000)
        };

        let groups = self
            .storage
            .list_groups(self.org_ctx.project_id)
            .await
            .map_err(storage_failure)?;

        let total = groups.len() as i32;

        // Apply pagination (list_groups doesn't support offset/limit)
        let offset = (start_index - 1) as usize;
        let paged: Vec<&Group> = groups.iter().skip(offset).take(count as usize).collect();

        let mut resources = Vec::with_capacity(paged.len());
        for group in paged {
            let members = self.load_member_refs(group.id).await?;
            resources.push(sid_to_scim_group(group, &members, &self.base_url));
        }

        Ok(Response::new(proto::ScimListGroupsResponse {
            resources,
            total_results: total,
            start_index,
            items_per_page: count,
        }))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn patch_group(
        &self,
        request: Request<proto::ScimPatchGroupRequest>,
    ) -> Result<Response<proto::ScimGroup>, Status> {
        let caller = self.provisioner(&request, SCIM_GROUP_UPDATE).await?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.id)?;

        let mut group = self
            .storage
            .get_group(group_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::group_not_found(group_id))?;

        let group_id_str = group.id.0.to_string();

        let patch_result = patch::apply_group_patch(&req.operations).map_err(refusal::patch)?;
        if !patch_result.add_members.is_empty() || !patch_result.remove_members.is_empty() {
            self.authorize(&caller, SCIM_GROUP_MEMBERSHIP).await?;
        }

        if let Some(new_name) = &patch_result.display_name {
            group.name = new_name.clone();
        }
        let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Update, group.clone());
        for member_id in &patch_result.add_members {
            let pid = parse_profile_id("members", member_id)?;
            write.add_members.push(GroupMember::new(group.id, pid));
        }
        for member_id in &patch_result.remove_members {
            write
                .remove_members
                .push(parse_profile_id("members", member_id)?);
        }
        let event = Event::new("sid-scim", event_types::SCIM_GROUP_UPDATED)
            .with_subject(format!("group/{}", group_id_str))
            .with_data(serde_json::json!({
                "group_id": group_id_str,
                "add_members": patch_result.add_members,
                "remove_members": patch_result.remove_members,
                "display_name_changed": patch_result.display_name.is_some(),
            }));
        self.storage
            .write_directory_group(
                &write,
                audited(
                    &caller,
                    by_connector(&caller, "scim.group.update", &group_id_str),
                    &event,
                ),
            )
            .await
            .map_err(|e| refusal::group_write(group.id, e))?;

        let members = self.load_member_refs(group_id).await?;
        Ok(Response::new(sid_to_scim_group(
            &group,
            &members,
            &self.base_url,
        )))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn delete_group(
        &self,
        request: Request<proto::ScimDeleteGroupRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.provisioner(&request, SCIM_GROUP_DELETE).await?;
        let req = request.into_inner();
        let group_id = parse_group_id(&req.id)?;

        let _group = self
            .storage
            .get_group(group_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::group_not_found(group_id))?;

        let group_id_str = group_id.0.to_string();

        let event = Event::new("sid-scim", event_types::SCIM_GROUP_DELETED)
            .with_subject(format!("group/{}", group_id_str))
            .with_data(serde_json::json!({
                "group_id": group_id_str,
            }));
        self.storage
            .delete_group(
                group_id,
                audited(
                    &caller,
                    by_connector(&caller, "scim.group.delete", &group_id_str),
                    &event,
                ),
            )
            .await
            .map_err(|e| refusal::group_write(group_id, e))?;

        Ok(Response::new(()))
    }

    // ── Discovery Endpoints ──

    async fn get_service_provider_config(
        &self,
        _request: Request<proto::ScimGetServiceProviderConfigRequest>,
    ) -> Result<Response<proto::ScimServiceProviderConfig>, Status> {
        Ok(Response::new(proto::ScimServiceProviderConfig {
            meta: Some(proto::ScimMeta {
                resource_type: "ServiceProviderConfig".into(),
                location: format!("{}/scim/v2/ServiceProviderConfig", self.base_url),
                ..Default::default()
            }),
            documentation_uri: "https://docs.structured.id/scim".into(),
            patch: Some(proto::ScimConfigSupport {
                supported: true,
                ..Default::default()
            }),
            bulk: Some(proto::ScimConfigSupport {
                supported: false,
                ..Default::default()
            }),
            filter: Some(proto::ScimConfigSupport {
                supported: true,
                ..Default::default()
            }),
            change_password: Some(proto::ScimConfigSupport {
                supported: false,
                ..Default::default()
            }),
            sort: Some(proto::ScimConfigSupport {
                supported: false,
                ..Default::default()
            }),
            etag: Some(proto::ScimConfigSupport {
                supported: false,
                ..Default::default()
            }),
            authentication_schemes: vec![proto::ScimAuthenticationScheme {
                r#type: "oauthbearertoken".into(),
                name: "OAuth Bearer Token".into(),
                description: "Authentication scheme using the OAuth Bearer Token Standard".into(),
                spec_uri: "https://www.rfc-editor.org/rfc/rfc6750".into(),
                documentation_uri: String::new(),
                primary: true,
            }],
            max_results: 1000,
        }))
    }

    async fn get_resource_types(
        &self,
        _request: Request<proto::ScimGetResourceTypesRequest>,
    ) -> Result<Response<proto::ScimResourceTypesResponse>, Status> {
        Ok(Response::new(proto::ScimResourceTypesResponse {
            resources: vec![
                proto::ScimResourceType {
                    id: "User".into(),
                    name: "User".into(),
                    description: "User Account".into(),
                    endpoint: "/scim/v2/Users".into(),
                    schema: "urn:ietf:params:scim:schemas:core:2.0:User".into(),
                    meta: None,
                },
                proto::ScimResourceType {
                    id: "Group".into(),
                    name: "Group".into(),
                    description: "Group".into(),
                    endpoint: "/scim/v2/Groups".into(),
                    schema: "urn:ietf:params:scim:schemas:core:2.0:Group".into(),
                    meta: None,
                },
            ],
        }))
    }

    async fn get_schemas(
        &self,
        _request: Request<proto::ScimGetSchemasRequest>,
    ) -> Result<Response<proto::ScimSchemasResponse>, Status> {
        Ok(Response::new(proto::ScimSchemasResponse {
            resources: vec![
                proto::ScimSchema {
                    id: "urn:ietf:params:scim:schemas:core:2.0:User".into(),
                    name: "User".into(),
                    description: "User Account".into(),
                    attributes: user_schema_attributes(),
                    ..Default::default()
                },
                proto::ScimSchema {
                    id: "urn:ietf:params:scim:schemas:core:2.0:Group".into(),
                    name: "Group".into(),
                    description: "Group".into(),
                    attributes: group_schema_attributes(),
                    ..Default::default()
                },
            ],
        }))
    }
}

// ── Private helpers on ScimServiceImpl ──

impl ScimServiceImpl {
    async fn load_group_refs(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<(GroupId, String)>, Status> {
        let groups = self
            .storage
            .list_groups_for_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        Ok(groups.iter().map(|g| (g.id, g.name.clone())).collect())
    }

    async fn load_member_refs(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<(ProfileId, String)>, Status> {
        let members = self
            .storage
            .list_group_members(group_id)
            .await
            .map_err(storage_failure)?;

        let mut refs = Vec::with_capacity(members.len());
        for gm in &members {
            let display = if let Some(profile) = self
                .storage
                .get_profile(gm.profile_id)
                .await
                .map_err(storage_failure)?
            {
                profile.formatted_name().unwrap_or_default()
            } else {
                String::new()
            };
            refs.push((gm.profile_id, display));
        }
        Ok(refs)
    }
}

// ── Schema attribute definitions ──

fn user_schema_attributes() -> Vec<proto::ScimSchemaAttribute> {
    vec![
        schema_attr("userName", "string", true, false, "readWrite"),
        schema_attr("displayName", "string", false, false, "readWrite"),
        schema_attr("name", "complex", false, false, "readWrite"),
        schema_attr("emails", "complex", false, true, "readWrite"),
        schema_attr("phoneNumbers", "complex", false, true, "readWrite"),
        schema_attr("active", "boolean", false, false, "readWrite"),
        schema_attr("title", "string", false, false, "readWrite"),
        schema_attr("department", "string", false, false, "readWrite"),
        schema_attr("externalId", "string", false, false, "readWrite"),
        schema_attr("groups", "complex", false, true, "readOnly"),
    ]
}

fn group_schema_attributes() -> Vec<proto::ScimSchemaAttribute> {
    vec![
        schema_attr("displayName", "string", true, false, "readWrite"),
        schema_attr("members", "complex", false, true, "readWrite"),
    ]
}

fn schema_attr(
    name: &str,
    r#type: &str,
    required: bool,
    multi_valued: bool,
    mutability: &str,
) -> proto::ScimSchemaAttribute {
    proto::ScimSchemaAttribute {
        name: name.into(),
        r#type: r#type.into(),
        multi_valued,
        description: String::new(),
        required,
        case_exact: false,
        mutability: mutability.into(),
        returned: "default".into(),
        uniqueness: "none".into(),
        sub_attributes: vec![],
    }
}
