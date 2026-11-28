// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 gRPC service implementation.
//!
//! Implements `ScimService` trait generated from `proto/sid/v1/scim.proto`.
//! All storage writes include `AuditEntry` (audit by construction).

use std::sync::Arc;

use sid_authn::connector_auth::ConnectorCaller;
use sid_authn::resource_token::ResourceTokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::{AuthzCheckRequest, CeAuthzEngine};
use sid_core::models::{
    AuditEntry, DirectoryGroupWrite, DirectoryResource, DirectoryRight, DirectoryRights,
    DirectorySource, DirectoryUserId, DirectoryUserWrite, DirectoryWriteMode, Group, GroupId,
    GroupMember, MutationContext, OrgId, Principal, PrincipalType, Profile, ProfileId,
    ProfileMetadata, ProfileStatus, ResourceId, RevocationReason, SCIM_GROUP_CREATE,
    SCIM_GROUP_DELETE, SCIM_GROUP_MEMBERSHIP, SCIM_GROUP_READ, SCIM_GROUP_UPDATE, SCIM_USER_CREATE,
    SCIM_USER_DEACTIVATE, SCIM_USER_READ, SCIM_USER_UPDATE, SessionEnd,
    event::{Event, event_types},
};
use sid_infra::authn::own_token::authenticate_connector;
use sid_infra::grpc_error::refuse::{dependency_unavailable, storage_failure};
use sid_infra::grpc_error::{ApiError, ErrorReason};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1 as proto;
use sid_proto::sid::v1::scim_service_server::ScimService;
use tonic::{Request, Response, Status};
use tracing::{instrument, warn};

use crate::filter;
use crate::mapping::{
    CreateUserMapping, MappingError, ScimOrgContext, check_single_primary, corporate_contact,
    email_binding, email_key, phone_contact, phone_digits, scim_create_group_to_sid,
    scim_create_user_to_sid, sid_to_scim_group, sid_to_scim_user,
};
use crate::patch;
use crate::refusal;

/// SCIM gRPC service implementation.
pub struct ScimServiceImpl {
    storage: Arc<dyn StorageBackend>,
    org_ctx: ScimOrgContext,
    base_url: String,
    directory: ScimDirectory,
    engine: Arc<CeAuthzEngine<dyn StorageBackend>>,
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
        engine: Arc<CeAuthzEngine<dyn StorageBackend>>,
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

    /// Where this directory renders a user resource that shows `active`,
    /// for a source that knows the user as `external_id`.
    fn place<'a>(
        &'a self,
        external_id: Option<&'a str>,
        active: bool,
    ) -> crate::mapping::ScimPlace<'a> {
        crate::mapping::ScimPlace {
            org_domain: &self.org_ctx.org_domain,
            base_url: &self.base_url,
            external_id,
            active,
        }
    }

    /// The correlation `caller` itself has with the user `resource`, if any.
    #[allow(clippy::result_large_err)]
    async fn source_of(
        &self,
        caller: &ConnectorCaller,
        resource: DirectoryUserId,
    ) -> Result<Option<DirectorySource>, Status> {
        Ok(self
            .storage
            .directory_sources(Some(caller.connector.id), &[resource])
            .await
            .map_err(storage_failure)?
            .into_iter()
            .next())
    }

    /// What `caller` itself calls the user `resource`, if anything: another
    /// source's identifier is never shown to it (RFC 7643 3.1).
    #[allow(clippy::result_large_err)]
    async fn external_id_of(
        &self,
        caller: &ConnectorCaller,
        resource: DirectoryUserId,
    ) -> Result<Option<String>, Status> {
        Ok(self
            .source_of(caller, resource)
            .await?
            .and_then(|source| source.external_id))
    }

    /// Refuse a request whose `effects` on a user exceed what `caller`
    /// manages of it now: what it may change of every user of the directory
    /// and what it was assigned of this one (`source`). Having created the
    /// user or knowing it gives nothing. The connector is read at the
    /// revision it authenticated at and the write is fenced on that
    /// revision, so a selection or assignment changed since refuses the
    /// commit.
    #[allow(clippy::result_large_err)]
    fn require_rights(
        caller: &ConnectorCaller,
        source: Option<&DirectorySource>,
        effects: DirectoryRights,
    ) -> Result<(), Status> {
        let held = source.map_or(caller.connector.directory_rights, |source| {
            caller.connector.directory_rights.union(source.managed)
        });
        if held.lacking(effects).is_empty() {
            Ok(())
        } else {
            Err(refusal::not_managed())
        }
    }

    /// Record in `write` the rename of the organization's login of
    /// `account` to `wanted`, when `wanted` is another name than the one in
    /// `held`, with the right it takes in `effects`. The one path PUT and
    /// PATCH rename through. `userName` is not case-exact (RFC 7643 4.1.1):
    /// the name restated in another case is no rename. The user keeps its
    /// resource, its account and its sources' identifiers; the name it
    /// leaves is released with the principal.
    #[allow(clippy::result_large_err)]
    fn rename_login(
        &self,
        wanted: &str,
        account: &Profile,
        held: &[Principal],
        write: &mut DirectoryUserWrite,
        effects: &mut DirectoryRights,
    ) -> Result<(), Status> {
        let suffix = format!("#{}", self.org_ctx.org_domain);
        let login = held
            .iter()
            .find(|i| i.principal_type == PrincipalType::Username && i.value.ends_with(&suffix));
        let name = login.and_then(|i| i.value.strip_suffix(&suffix));
        if name.is_some_and(|name| name.to_lowercase() == wanted.to_lowercase()) {
            return Ok(());
        }
        // The login of an identity that signs in elsewhere is its issuer's:
        // no delegation here covers it.
        if matches!(Target::of(account), Target::Relationship) {
            return if wanted.is_empty() {
                Ok(())
            } else {
                Err(refusal::not_managed())
            };
        }
        if wanted.is_empty() {
            return Err(refusal::required("userName"));
        }
        if let Some(login) = login {
            write.unbind.push(login.id);
        }
        write.bind.push(crate::mapping::organization_login(
            account.id,
            wanted,
            &self.org_ctx.org_domain,
        ));
        *effects = effects.with(DirectoryRight::UserName);
        Ok(())
    }

    /// Whether the account `profile` has what a deactivation ends: a
    /// sign-in or a usable token. Read before the write: one issued after
    /// it is not this request's to end.
    #[allow(clippy::result_large_err)]
    async fn has_live_access(&self, profile: ProfileId) -> Result<bool, Status> {
        if !self
            .storage
            .list_sessions(&profile)
            .await
            .map_err(storage_failure)?
            .is_empty()
        {
            return Ok(true);
        }
        Ok(self
            .storage
            .count_active_pats_by_profile(profile)
            .await
            .map_err(storage_failure)?
            > 0)
    }

    /// The user `resource` as `caller` is shown it, read from the store.
    #[allow(clippy::result_large_err)]
    async fn shown(
        &self,
        caller: &ConnectorCaller,
        resource: DirectoryUserId,
        profile_id: ProfileId,
    ) -> Result<proto::ScimUser, Status> {
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(resource))?;
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
        let external_id = self.external_id_of(caller, resource).await?;
        let found = self
            .storage
            .find_directory_user(resource)
            .await
            .map_err(storage_failure)?
            .filter(DirectoryResource::is_live)
            .ok_or_else(|| refusal::user_not_found(resource))?;
        Ok(sid_to_scim_user(
            resource,
            &profile,
            &identifiers,
            &emails,
            &metadata,
            &group_refs,
            self.place(external_id.as_deref(), found.shows_active(&profile)),
        ))
    }

    /// Also accept the directory resource's access tokens `tokens` verifies.
    pub fn with_access_tokens(mut self, tokens: Arc<ResourceTokenVerifier>) -> Self {
        self.tokens = Some(tokens);
        self
    }

    /// Whether a login handle `write` binds for a new user is already held.
    #[allow(clippy::result_large_err)]
    async fn login_taken(&self, write: &DirectoryUserWrite) -> Result<bool, Status> {
        if !matches!(write.mode, DirectoryWriteMode::Create) {
            return Ok(false);
        }
        for login in write
            .bind
            .iter()
            .filter(|p| p.principal_type == PrincipalType::Username)
        {
            if self
                .storage
                .get_principal_by_value(PrincipalType::Username, &login.value)
                .await
                .map_err(storage_failure)?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
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
        let ended = match self.storage.write_directory_user(write, ctx).await {
            Ok(ended) => ended,
            Err(e) => {
                // A conflict is the login handle when the one being bound is
                // taken (a repeated create collides on both and is told so),
                // and the source's own identifier when the source already
                // gives it to another user.
                if let (sid_core::Error::Conflict(_), Some(source)) = (&e, &write.source)
                    && let Some(external_id) = &source.external_id
                    && !self.login_taken(write).await?
                    && self
                        .storage
                        .find_directory_source(source.connector, external_id)
                        .await
                        .map_err(storage_failure)?
                        .is_some_and(|held| Some(held.resource) != write.resource)
                {
                    return Err(refusal::external_id_taken());
                }
                // A refusal names the user as the client knows it, never by
                // the account's identifier.
                return Err(match write.resource {
                    Some(resource) => refusal::user_write(resource, e),
                    None => refusal::user_write("", e),
                });
            }
        };
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

use sid_core::models::DirectoryTarget as Target;

/// The right that covers the account attribute stored under metadata `key`.
#[allow(clippy::result_large_err)]
fn metadata_right(key: &str) -> Result<DirectoryRight, Status> {
    Ok(match key {
        "title" => DirectoryRight::Title,
        "department" => DirectoryRight::Department,
        "employee_id" => DirectoryRight::EmployeeNumber,
        "cost_center" => DirectoryRight::CostCenter,
        "organization" => DirectoryRight::Organization,
        "division" => DirectoryRight::Division,
        // An attribute no right covers is not a connector's to write.
        _ => return Err(refusal::not_managed()),
    })
}

/// What a requested `active` changes of a user.
enum Activity {
    /// The user already shows it, or what holds it back is not the
    /// directory's to lift.
    Unchanged,
    /// The relationship's own state; the account and its other grounds of
    /// access are left as they are.
    Relationship(bool),
    /// Every access of the managed account ends; an account in use is
    /// suspended with it.
    Ended,
    /// The managed account's suspension is lifted.
    Restored,
}

impl Activity {
    /// Record the change in `write` and the right it takes in `effects`;
    /// whether it is a deactivation.
    fn apply(&self, write: &mut DirectoryUserWrite, effects: &mut DirectoryRights) -> bool {
        match self {
            Self::Unchanged => return false,
            Self::Relationship(active) => write.resource_active = Some(*active),
            Self::Ended => write.end_access = Some(deprovision()),
            Self::Restored => {}
        }
        *effects = effects.with(DirectoryRight::Active);
        matches!(self, Self::Relationship(false) | Self::Ended)
    }
}

/// Decide what the `wanted` SCIM `active` changes of the user `found`
/// stands for, moving the status of `account` when the account itself is
/// the target. `claimed`: the user has taken the account over. `live`:
/// the account has a sign-in or a token a deactivation would end.
fn set_active(
    wanted: bool,
    found: &DirectoryResource,
    before: &Profile,
    claimed: bool,
    live: bool,
    account: &mut Profile,
) -> Activity {
    match (Target::of(before), wanted) {
        // An account that already shows inactive and has nothing live left:
        // the request restates what it read and ends nothing. The same
        // request while access is live does end it, below, and takes the
        // authority for that.
        (Target::Account, false) if !before.status.is_in_use() && !live => Activity::Unchanged,
        (Target::Relationship, _) if wanted != found.active => Activity::Relationship(wanted),
        // Restated; when the identity's own account is what holds the user
        // inactive, that is no directory client's to lift.
        (Target::Relationship, _) => Activity::Unchanged,
        // The deactivation already stands: its access ended with it.
        (Target::Account, false) if before.status == ProfileStatus::Suspended => {
            Activity::Unchanged
        }
        // Only an account in use is suspended: a closure under way, a
        // terminal state or a legal hold is not the directory's to rewrite.
        // It stays, and the access ends all the same.
        (Target::Account, false) => {
            if before.status.is_in_use() {
                account.status = ProfileStatus::Suspended;
            }
            Activity::Ended
        }
        // Only a suspension is lifted, for the same reason. An account
        // never claimed returns to provisioned, not to active: activation
        // is the user's own step.
        (Target::Account, true) if before.status == ProfileStatus::Suspended => {
            account.status = if claimed {
                ProfileStatus::Active
            } else {
                ProfileStatus::Provisioned
            };
            Activity::Restored
        }
        (Target::Account, true) => Activity::Unchanged,
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

#[allow(clippy::result_large_err)]
fn parse_group_id(id: &str) -> Result<GroupId, Status> {
    GroupId::parse(id).map_err(|_| refusal::invalid_id("id"))
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
        // The source's own identifier of the user is its correlation with
        // the resource, never an attribute of the account (RFC 7643 3.1).
        let external_id = (!req.external_id.is_empty()).then(|| req.external_id.clone());
        let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Create, profile.clone())
            .by_source(caller.connector.id, external_id.clone());
        write.bind = principals.clone();
        write.add_emails = emails;
        write.add_phones = phones;
        write.set_metadata = metadata.clone();
        let mut audit = by_connector(&caller, "scim.user.create", &profile_id_str);
        audit.metadata["external_id"] = serde_json::json!(req.external_id);
        self.write_user(&write, audited(&caller, audit, &event))
            .await?;
        let resource = self.resource_of(profile.id).await?;

        Ok(Response::new(sid_to_scim_user(
            resource,
            &profile,
            &principals,
            &write.add_emails,
            &metadata,
            &[],
            // A new resource's relationship is active.
            self.place(external_id.as_deref(), profile.status.is_in_use()),
        )))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn get_user(
        &self,
        request: Request<proto::ScimGetUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_READ).await?;
        let req = request.into_inner();
        let (resource, profile_id) = self.user(&req.id).await?;
        Ok(Response::new(
            self.shown(&caller, resource, profile_id).await?,
        ))
    }

    #[instrument(skip_all, fields(filter = %request.get_ref().filter))]
    async fn list_users(
        &self,
        request: Request<proto::ScimListUsersRequest>,
    ) -> Result<Response<proto::ScimListUsersResponse>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_READ).await?;
        let req = request.into_inner();

        // SCIM pagination: 1-based startIndex
        let start_index = std::cmp::max(req.start_index, 1);
        let count = if req.count <= 0 {
            100
        } else {
            std::cmp::min(req.count, 1000)
        };

        // The filter is applied by storage, before the page, over the whole
        // directory (RFC 7644 §3.4.2.2, §3.4.2.4).
        let filter = if req.filter.is_empty() {
            None
        } else {
            let parsed =
                filter::parse_filter(&req.filter).map_err(|_| refusal::invalid_filter())?;
            Some(filter::to_directory(&parsed).map_err(|_| refusal::invalid_filter())?)
        };
        let query = sid_core::models::DirectoryQuery {
            org_domain: self.org_ctx.org_domain.clone(),
            filter,
            offset: u64::try_from(start_index - 1).expect("start_index is at least 1"),
            limit: u64::try_from(count).expect("count is positive"),
            // externalId is shown and compared as the caller's own.
            source: Some(caller.connector.id),
        };
        let page = match self.storage.query_directory(&query).await {
            Ok(page) => page,
            // A comparison the attribute does not support (`active gt`).
            Err(sid_core::Error::Validation(_)) => return Err(refusal::invalid_filter()),
            Err(e) => return Err(storage_failure(e)),
        };
        let resources: Vec<proto::ScimUser> = page
            .users
            .iter()
            .map(|user| {
                sid_to_scim_user(
                    user.id,
                    &user.profile,
                    &user.principals,
                    &user.emails,
                    &user.metadata,
                    &[], // Groups are read per user, not for a list.
                    self.place(user.external_id.as_deref(), user.active),
                )
            })
            .collect();

        Ok(Response::new(proto::ScimListUsersResponse {
            total_results: i32::try_from(page.total).unwrap_or(i32::MAX),
            start_index,
            // RFC 7644 §3.4.2: the number of resources returned.
            items_per_page: i32::try_from(resources.len()).expect("a page is at most 1000"),
            resources,
        }))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn replace_user(
        &self,
        request: Request<proto::ScimReplaceUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_UPDATE).await?;
        let req = request.into_inner();
        let found = self.found(&req.id).await?;
        let (resource, profile_id) = (found.id, found.profile_id);

        let before = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(resource))?;
        let mut profile = before.clone();
        // What the request changes of the user as it stands. A value the
        // request repeats is no change: a client that manages one attribute
        // sends the whole resource back (RFC 7644 §3.5.1) and changes that
        // attribute alone.
        let mut effects = DirectoryRights::NONE;

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

        if (
            &profile.given_name,
            &profile.family_name,
            &profile.middle_name,
        ) != (&before.given_name, &before.family_name, &before.middle_name)
        {
            effects = effects.with(DirectoryRight::Name);
        }

        check_single_primary(&req.emails, &req.phone_numbers).map_err(refusal::mapping)?;
        let now = jiff::Timestamp::now();
        let mut write =
            DirectoryUserWrite::new(DirectoryWriteMode::Update, profile.clone()).through(resource);

        // PUT replaces the caller's own identifier of the user with the one
        // given, absent included; another source's is not its to touch. A
        // connector that is no source of the user is made one only by its
        // manager, never by naming the user in a request.
        let source = self.source_of(&caller, resource).await?;
        let requested_id = (!req.external_id.is_empty()).then(|| req.external_id.clone());
        if requested_id != source.as_ref().and_then(|s| s.external_id.clone()) {
            if source.is_none() {
                return Err(refusal::not_managed());
            }
            effects = effects.with(DirectoryRight::ExternalId);
            write = write.by_source(caller.connector.id, requested_id);
        }

        let old_identifiers = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;
        let mut new_identifiers: Vec<Principal> = Vec::new();

        // Emails: the contacts and the login handles made of them are
        // replaced only when the request states another set.
        let held_emails = self
            .storage
            .list_profile_emails(profile_id)
            .await
            .map_err(storage_failure)?;
        let email_bindings: Vec<(Principal, sid_core::models::ProfileEmail)> = req
            .emails
            .iter()
            .filter(|e| !e.value.is_empty())
            .map(|e| email_binding(profile_id, e, now))
            .collect::<Result<_, _>>()
            .map_err(refusal::mapping)?;
        let stated = |contacts: &mut dyn Iterator<Item = &sid_core::models::ProfileEmail>| {
            let mut set: Vec<_> = contacts
                .map(|c| (c.email.clone(), c.is_primary, format!("{:?}", c.label)))
                .collect();
            set.sort();
            set
        };
        if stated(&mut held_emails.iter()) != stated(&mut email_bindings.iter().map(|(_, c)| c)) {
            effects = effects.with(DirectoryRight::Emails);
            write.remove_emails = held_emails.iter().map(|e| e.id).collect();
            write.add_emails = email_bindings.iter().map(|(_, c)| c.clone()).collect();
            write.unbind.extend(
                old_identifiers
                    .iter()
                    .filter(|i| i.principal_type == PrincipalType::Email)
                    .map(|i| i.id),
            );
            new_identifiers.extend(email_bindings.into_iter().map(|(principal, _)| principal));
        }

        // Phone numbers likewise.
        let held_phones = self
            .storage
            .list_profile_phones(profile_id)
            .await
            .map_err(storage_failure)?;
        let mut phone_contacts = Vec::new();
        for phone in req.phone_numbers.iter().filter(|p| !p.value.is_empty()) {
            phone_contacts.push(
                phone_contact(profile_id, &phone.value, &phone.r#type, phone.primary, now)
                    .map_err(refusal::mapping)?,
            );
        }
        let numbers = |contacts: &[sid_core::models::ProfilePhone]| {
            let mut set: Vec<_> = contacts
                .iter()
                .map(|c| (c.e164, c.is_primary, format!("{:?}", c.label)))
                .collect();
            set.sort();
            set
        };
        if numbers(&held_phones) != numbers(&phone_contacts) {
            effects = effects.with(DirectoryRight::PhoneNumbers);
            write.remove_phones = held_phones.iter().map(|p| p.id).collect();
            write.add_phones = phone_contacts;
            write.unbind.extend(
                old_identifiers
                    .iter()
                    .filter(|i| i.principal_type == PrincipalType::Phone)
                    .map(|i| i.id),
            );
            new_identifiers.extend(
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
            );
        }
        write.bind = new_identifiers;
        self.rename_login(
            &req.user_name,
            &before,
            &old_identifiers,
            &mut write,
            &mut effects,
        )?;

        // `active` is a change only when it differs from what the user
        // shows. What the change does follows what the resource stands for.
        let claimed = old_identifiers.iter().any(|i| i.verified);
        // Read only where it decides: an account that already shows
        // inactive and is asked to stay so.
        let live =
            req.active || before.status.is_in_use() || self.has_live_access(profile_id).await?;
        let activity = set_active(req.active, &found, &before, claimed, live, &mut profile);
        let deactivating = activity.apply(&mut write, &mut effects);
        write.profile = profile.clone();

        // RFC 7644 §3.5.1: PUT replaces the resource, so an attribute the
        // request leaves empty is cleared.
        let held_metadata = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(storage_failure)?;
        for (key, right, value) in [
            (
                "employee_id",
                DirectoryRight::EmployeeNumber,
                &req.employee_number,
            ),
            ("department", DirectoryRight::Department, &req.department),
            ("title", DirectoryRight::Title, &req.title),
        ] {
            let held = held_metadata
                .iter()
                .find(|m| m.key == key)
                .and_then(|m| m.value.as_str())
                .unwrap_or_default();
            if held == value {
                continue;
            }
            effects = effects.with(right);
            if value.is_empty() {
                write.remove_metadata.push(key.to_string());
            } else {
                write.set_metadata.push(ProfileMetadata::new(
                    profile_id,
                    key,
                    serde_json::Value::String(value.clone()),
                ));
            }
        }

        // A request that restates the user changes nothing and writes
        // nothing; one that changes anything is within what the connector
        // manages of this user as a whole, or is refused as a whole.
        if effects.is_empty() {
            return Ok(Response::new(
                self.shown(&caller, resource, profile_id).await?,
            ));
        }
        Self::require_rights(&caller, source.as_ref(), effects)?;
        if deactivating {
            self.authorize(&caller, SCIM_USER_DEACTIVATE).await?;
        }

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

        // As stored.
        Ok(Response::new(
            self.shown(&caller, resource, profile_id).await?,
        ))
    }

    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn patch_user(
        &self,
        request: Request<proto::ScimPatchUserRequest>,
    ) -> Result<Response<proto::ScimUser>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_UPDATE).await?;
        let req = request.into_inner();
        let found = self.found(&req.id).await?;
        let (resource, profile_id) = (found.id, found.profile_id);

        let before = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(resource))?;
        let mut profile = before.clone();

        let profile_id_str = profile.id.to_string();

        // Apply PATCH operations
        let patch_result =
            patch::apply_user_patch(&mut profile, &req.operations).map_err(refusal::patch)?;

        // What the request changes of the user as it stands: an operation
        // that restates a value is no change and takes no right.
        let mut effects = DirectoryRights::NONE;
        if (
            &profile.given_name,
            &profile.family_name,
            &profile.middle_name,
        ) != (&before.given_name, &before.family_name, &before.middle_name)
        {
            effects = effects.with(DirectoryRight::Name);
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

        let now = jiff::Timestamp::now();
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
        let mut write =
            DirectoryUserWrite::new(DirectoryWriteMode::Update, profile.clone()).through(resource);
        // Only a request that names externalId changes the caller's own
        // identifier of the user, and only a source of the user has one: a
        // connector is made a source by its manager, never by a request.
        let source = self.source_of(&caller, resource).await?;
        if let Some(external_id) = &patch_result.external_id
            && *external_id != source.as_ref().and_then(|s| s.external_id.clone())
        {
            if source.is_none() {
                return Err(refusal::not_managed());
            }
            effects = effects.with(DirectoryRight::ExternalId);
            write = write.by_source(caller.connector.id, external_id.clone());
        }
        if let Some(name) = &patch_result.user_name {
            self.rename_login(name, &before, &identifiers, &mut write, &mut effects)?;
        }
        let mut deactivating = false;
        if let Some(wanted) = patch_result.active {
            let claimed = identifiers.iter().any(|i| i.verified);
            let live =
                wanted || before.status.is_in_use() || self.has_live_access(profile_id).await?;
            deactivating = set_active(wanted, &found, &before, claimed, live, &mut profile)
                .apply(&mut write, &mut effects);
            write.profile = profile.clone();
        }
        for id_type in patch_result
            .add_identifiers
            .iter()
            .map(|pi| pi.id_type)
            .chain(
                patch_result
                    .remove_identifier_values
                    .iter()
                    .map(|(t, _)| *t),
            )
        {
            match id_type {
                PrincipalType::Email => effects = effects.with(DirectoryRight::Emails),
                PrincipalType::Phone => effects = effects.with(DirectoryRight::PhoneNumbers),
                _ => {}
            }
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
                    let (principal, contact) =
                        email_binding(profile_id, &email, now).map_err(refusal::mapping)?;
                    write.bind.push(principal);
                    write.add_emails.push(contact);
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

        let held_metadata = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(storage_failure)?;
        let held = |key: &str| held_metadata.iter().find(|m| m.key == key);
        for (key, value) in &patch_result.set_metadata {
            if held(key).is_some_and(|m| m.value == *value) {
                continue;
            }
            effects = effects.with(metadata_right(key)?);
            write
                .set_metadata
                .push(ProfileMetadata::new(profile_id, key, value.clone()));
        }
        for key in &patch_result.remove_metadata {
            if held(key).is_none() {
                continue;
            }
            effects = effects.with(metadata_right(key)?);
            write.remove_metadata.push(key.clone());
        }

        // A request that changes nothing writes nothing; one that changes
        // anything is within what the connector manages of this user as a
        // whole, or is refused as a whole.
        if effects.is_empty() {
            return Ok(Response::new(
                self.shown(&caller, resource, profile_id).await?,
            ));
        }
        Self::require_rights(&caller, source.as_ref(), effects)?;
        if deactivating {
            self.authorize(&caller, SCIM_USER_DEACTIVATE).await?;
        }

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

        // As stored.
        Ok(Response::new(
            self.shown(&caller, resource, profile_id).await?,
        ))
    }

    /// SCIM DELETE deletes the user resource (RFC 7644 3.6): one commit
    /// marks it deleted, suspends the account it stands for and ends every
    /// live sign-in. The resource is served by no read afterwards and a
    /// repeat is not found; the account's record stays for the installation.
    #[instrument(skip_all, fields(id = %request.get_ref().id))]
    async fn delete_user(
        &self,
        request: Request<proto::ScimDeleteUserRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.provisioner(&request, SCIM_USER_DEACTIVATE).await?;
        let req = request.into_inner();
        let (resource, profile_id) = self.user(&req.id).await?;

        let mut profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| refusal::user_not_found(resource))?;

        // What the deletion ends follows what the resource stands for. The
        // whole of it is within what the connector manages of this user, or
        // nothing is written.
        let source = self.source_of(&caller, resource).await?;
        let target = Target::of(&profile);
        let needed = match target {
            // The relationship alone: the identity's own sign-in and what
            // it holds here on other grounds stay.
            Target::Relationship => DirectoryRights::of(&[DirectoryRight::Delete]),
            // The account's local offboarding: its access ends with it.
            Target::Account => {
                DirectoryRights::of(&[DirectoryRight::Delete, DirectoryRight::Active])
            }
        };
        Self::require_rights(&caller, source.as_ref(), needed)?;

        // Ending local access suspends an account that is in use. A closure
        // under way, a terminal state or a legal hold is not the directory's
        // to rewrite: it stays, and the access ends all the same.
        if matches!(target, Target::Account) && profile.status.is_in_use() {
            profile.status = ProfileStatus::Suspended;
        }

        let profile_id_str = profile_id.to_string();

        let event = Event::new("sid-scim", event_types::SCIM_USER_DEACTIVATED)
            .with_subject(format!("profile/{}", profile_id_str))
            .with_data(serde_json::json!({
                "profile_id": profile_id_str,
                "trigger": "scim_delete",
            }));
        let mut write =
            DirectoryUserWrite::new(DirectoryWriteMode::Update, profile).through(resource);
        write.delete_resource = true;
        if matches!(target, Target::Account) {
            write.end_access = Some(deprovision());
        }
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
        let group_id_str = group.id.to_string();

        // The members are this connector's own assignments.
        let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone())
            .by_source(caller.connector.id);
        for member_ref in &req.members {
            let pid = self.member(&member_ref.value, false).await?;
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

        let group_id_str = group.id.to_string();

        let patch_result = patch::apply_group_patch(&req.operations).map_err(refusal::patch)?;
        if !patch_result.add_members.is_empty() || !patch_result.remove_members.is_empty() {
            self.authorize(&caller, SCIM_GROUP_MEMBERSHIP).await?;
        }

        if let Some(new_name) = &patch_result.display_name {
            group.name = new_name.clone();
        }
        // Members are named by their user resources; the write and the
        // event carry the accounts they stand for. The connector adds and
        // withdraws its own assignments: another source's, or a local one,
        // keeps the member in the group.
        let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Update, group.clone())
            .by_source(caller.connector.id);
        for member_id in &patch_result.add_members {
            let pid = self.member(member_id, false).await?;
            write.add_members.push(GroupMember::new(group.id, pid));
        }
        for member_id in &patch_result.remove_members {
            write
                .remove_members
                .push(self.member(member_id, true).await?);
        }
        let accounts = |ids: &[ProfileId]| ids.iter().map(ToString::to_string).collect::<Vec<_>>();
        let added: Vec<ProfileId> = write.add_members.iter().map(|m| m.profile_id).collect();
        let event = Event::new("sid-scim", event_types::SCIM_GROUP_UPDATED)
            .with_subject(format!("group/{}", group_id_str))
            .with_data(serde_json::json!({
                "group_id": group_id_str,
                "add_members": accounts(&added),
                "remove_members": accounts(&write.remove_members),
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

        let group_id_str = group_id.to_string();

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
                    // RFC 7643 §6: a User may carry the enterprise extension
                    // and may omit it entirely.
                    schema_extensions: vec![proto::ScimSchemaExtension {
                        schema: crate::protocol::ENTERPRISE_SCHEMA.into(),
                        required: false,
                    }],
                },
                proto::ScimResourceType {
                    id: "Group".into(),
                    name: "Group".into(),
                    description: "Group".into(),
                    endpoint: "/scim/v2/Groups".into(),
                    schema: "urn:ietf:params:scim:schemas:core:2.0:Group".into(),
                    meta: None,
                    schema_extensions: Vec::new(),
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
                // RFC 7643 §4.3: the attributes a User carries under the
                // enterprise extension's own schema URI.
                proto::ScimSchema {
                    id: crate::protocol::ENTERPRISE_SCHEMA.into(),
                    name: "EnterpriseUser".into(),
                    description: "Enterprise User".into(),
                    attributes: vec![
                        schema_attr("employeeNumber", "string", false, false, "readWrite"),
                        schema_attr("department", "string", false, false, "readWrite"),
                    ],
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

    /// A group's members as the directory serves them: by their resource
    /// identifiers, a member whose resource was deleted left out.
    async fn load_member_refs(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<(DirectoryUserId, String)>, Status> {
        let members = self
            .storage
            .list_group_members(group_id)
            .await
            .map_err(storage_failure)?;
        let accounts: Vec<ProfileId> = members.iter().map(|gm| gm.profile_id).collect();
        let resources = self
            .storage
            .directory_users_of(&accounts)
            .await
            .map_err(storage_failure)?;

        let mut refs = Vec::with_capacity(resources.len());
        for gm in &members {
            let Some(resource) = resources.iter().find(|r| r.profile_id == gm.profile_id) else {
                continue;
            };
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
            refs.push((resource.id, display));
        }
        Ok(refs)
    }

    /// The live user resource a client names by `id` and the account it
    /// stands for. An identifier that is malformed is the client's mistake;
    /// one never assigned or deleted is not found (RFC 7644 3.6).
    #[allow(clippy::result_large_err)]
    async fn user(&self, id: &str) -> Result<(DirectoryUserId, ProfileId), Status> {
        let found = self.found(id).await?;
        Ok((found.id, found.profile_id))
    }

    /// [`Self::user`], with the resource's own state.
    #[allow(clippy::result_large_err)]
    async fn found(&self, id: &str) -> Result<DirectoryResource, Status> {
        let resource = DirectoryUserId::parse(id).ok_or_else(|| refusal::invalid_id("id"))?;
        match self
            .storage
            .find_directory_user(resource)
            .await
            .map_err(storage_failure)?
        {
            Some(found) if found.is_live() => Ok(found),
            _ => Err(refusal::user_not_found(resource)),
        }
    }

    /// The account of the group member a client names by its user resource.
    /// A member is added by a live resource only. A removal also names a
    /// deleted one: a client deletes a user and then withdraws its
    /// memberships, which the deletion left in place. An identifier never
    /// assigned names no user either way.
    #[allow(clippy::result_large_err)]
    async fn member(&self, value: &str, removal: bool) -> Result<ProfileId, Status> {
        let resource =
            DirectoryUserId::parse(value).ok_or_else(|| refusal::invalid_id("members"))?;
        match self
            .storage
            .find_directory_user(resource)
            .await
            .map_err(storage_failure)?
        {
            Some(found) if removal || found.is_live() => Ok(found.profile_id),
            _ => Err(refusal::not_a_user()),
        }
    }

    /// The resource identifier the directory assigned to the account it has
    /// just created.
    #[allow(clippy::result_large_err)]
    async fn resource_of(&self, account: ProfileId) -> Result<DirectoryUserId, Status> {
        self.storage
            .directory_users_of(&[account])
            .await
            .map_err(storage_failure)?
            .first()
            .map(|r| r.id)
            .ok_or_else(|| {
                sid_infra::grpc_error::refuse::internal(
                    "scim user",
                    "a created user has no resource",
                )
            })
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
