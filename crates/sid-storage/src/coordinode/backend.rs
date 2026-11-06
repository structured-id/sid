// SPDX-License-Identifier: AGPL-3.0-only
//! The storage contract over CoordiNode. Each capability either runs on this
//! backend or is refused by name: a host reaching a capability the backend
//! does not hold gets an error naming it, never a partial effect.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::anomaly_event::AnomalyEventRecord;
use sid_core::models::consent::{ConsentId, ConsentRecord};
use sid_core::models::device_attestation::{DeviceAttestation, DeviceAttestationId};
use sid_core::models::machine_user::MachineUserStatus;
use sid_core::models::organization::OrgId;
use sid_core::models::provisioning_connector::{
    ConnectorState, ProvisioningConnector, ProvisioningConnectorId, ProvisioningCredential,
    ProvisioningCredentialId,
};
use sid_core::models::{
    AccessRequest, AccessRequestId, AuthCodeRedemption, AuthorizationCode, BrowserSecretHash,
    CedarPolicy, CedarPolicyId, ClosureRequest, Credential, CredentialId, CredentialType, Device,
    DeviceAuthCodeId, DeviceAuthorizationCode, DeviceId, DeviceTrustChange, DirectoryGroupWrite,
    DirectoryUserWrite, EmailSettings, ExportJob, Group, GroupId, GroupMember, HistoryCommit,
    ImpersonationGrant, InitialAccessToken, InitialAccessTokenId, Invite, InviteFilter, InviteId,
    IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, MachineUser, MachineUserCredential,
    MachineUserId, MagicLinkSession, MutationContext, NewRegistration, OAuth2Client, OidcIssuer,
    OutboundDlqEntry, OutboundEntityType, PasswordHistory, PatId, PersonalAccessToken,
    PhoneSettings, PolicyScope, Principal, PrincipalBinding, PrincipalEntity, PrincipalId,
    PrincipalType, Profile, ProfileEmail, ProfileEmailId, ProfileGrant, ProfileGrantId, ProfileId,
    ProfileMetadata, ProfilePhone, ProfilePhoneId, Project, ProjectChange, ProjectId,
    ProtectedResource, RefreshToken, RegistrationSource, RegistrationSourceType, ResourceAccess,
    ResourceId, ResourceIndicator, Role, RoleAssignment, RoleAssignmentId, RoleId,
    ScimOutboundRecord, ScimOutboundTarget, ScimOutboundTargetId, Session, SessionAuthentication,
    SessionEnd, SessionId, SignInProof, SodConflictRule, UpstreamIdentity, UpstreamIdentityId,
    UpstreamLogin, UpstreamProvider, UpstreamProviderId,
};
use sid_core::{Error as SidError, Result};
use sid_plugin::storage::{JobLock, StorageBackend};
use sid_plugin::{
    ClientResourceRegistry, CredentialStore, GrantStore, IssuerStore, PrincipalStore,
    SignInHistoryStore,
};
use uuid::Uuid;

use super::CoordinodeBackend;

/// The refusal of `capability`, which this backend does not hold.
fn refused<T>(capability: &str) -> Result<T> {
    Err(SidError::Unavailable(format!(
        "CoordiNode storage does not hold {capability}"
    )))
}

#[async_trait]
impl ClientResourceRegistry for CoordinodeBackend {
    async fn get_oauth2_client(&self, client_id: &str) -> Result<Option<OAuth2Client>> {
        CoordinodeBackend::get_oauth2_client(self, client_id).await
    }

    async fn get_protected_resource(&self, id: ResourceId) -> Result<Option<ProtectedResource>> {
        CoordinodeBackend::get_protected_resource(self, id).await
    }

    async fn protected_resource_by_indicator(
        &self,
        issuer: IssuerId,
        indicator: &ResourceIndicator,
    ) -> Result<Option<ProtectedResource>> {
        CoordinodeBackend::protected_resource_by_indicator(self, issuer, indicator).await
    }

    async fn resource_access(
        &self,
        client_id: &str,
        resource: ResourceId,
    ) -> Result<Option<ResourceAccess>> {
        CoordinodeBackend::resource_access(self, client_id, resource).await
    }
}

#[async_trait]
impl IssuerStore for CoordinodeBackend {
    async fn oidc_issuer_for(
        &self,
        authority: IssuerAuthority,
        recipient_org: OrgId,
    ) -> Result<Option<OidcIssuer>> {
        CoordinodeBackend::oidc_issuer_for(self, authority, recipient_org).await
    }

    async fn oidc_issuer_by_handle(&self, handle: &IssuerHandle) -> Result<Option<OidcIssuer>> {
        CoordinodeBackend::oidc_issuer_by_handle(self, handle).await
    }

    async fn insert_oidc_issuer(
        &self,
        issuer: &OidcIssuer,
        first_key: &IssuerSigningKey,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::insert_oidc_issuer(self, issuer, first_key, ctx).await
    }

    async fn oidc_issuer_signing_keys(&self, issuer: IssuerId) -> Result<Vec<IssuerSigningKey>> {
        CoordinodeBackend::oidc_issuer_signing_keys(self, issuer).await
    }
}

#[async_trait]
impl GrantStore for CoordinodeBackend {
    type Owner = ProfileId;

    async fn create_session_atomic(
        &self,
        session: &Session,
        max_sessions: u32,
        proved_by: Option<SignInProof<'_>>,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>> {
        CoordinodeBackend::create_session_atomic(self, session, max_sessions, proved_by, None, ctx)
            .await
    }

    async fn complete_pending_session(
        &self,
        pending: SessionId,
        end: &SessionEnd,
        session: &Session,
        max_sessions: u32,
        proved_by: Option<SignInProof<'_>>,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>> {
        CoordinodeBackend::create_session_atomic(
            self,
            session,
            max_sessions,
            proved_by,
            Some((pending, end)),
            ctx,
        )
        .await
    }

    async fn get_session(&self, id: SessionId) -> Result<Option<Session>> {
        CoordinodeBackend::get_session(self, id).await
    }

    async fn get_session_by_browser_secret(
        &self,
        hash: &BrowserSecretHash,
    ) -> Result<Option<Session>> {
        CoordinodeBackend::get_session_by_browser_secret(self, hash).await
    }

    async fn list_sessions(&self, owner: &ProfileId) -> Result<Vec<Session>> {
        CoordinodeBackend::list_sessions(self, *owner).await
    }

    async fn touch_session(&self, id: SessionId, at: DateTime<Utc>) -> Result<()> {
        CoordinodeBackend::touch_session(self, id, at).await
    }

    async fn delete_session(
        &self,
        id: SessionId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>> {
        CoordinodeBackend::delete_session(self, id, end, ctx).await
    }

    async fn get_refresh_token_by_hash(&self, token_hash: &[u8]) -> Result<Option<RefreshToken>> {
        CoordinodeBackend::get_refresh_token_by_hash(self, token_hash).await
    }

    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: SessionId,
        ctx: MutationContext,
    ) -> Result<u64> {
        CoordinodeBackend::revoke_refresh_tokens_by_session(self, session_id, ctx).await
    }

    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: Uuid,
        ctx: MutationContext,
    ) -> Result<u64> {
        CoordinodeBackend::revoke_refresh_tokens_by_family(self, family_id, ctx).await
    }

    async fn rotate_refresh_token(
        &self,
        old_id: Uuid,
        new: &RefreshToken,
        grace_expires_at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::rotate_refresh_token(self, old_id, new, grace_expires_at, ctx).await
    }

    async fn issue_native_generation(
        &self,
        generation: &sid_core::models::NativeGeneration,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::issue_native_generation(self, generation, ctx).await
    }

    async fn native_generation_by_credential(
        &self,
        hash: &[u8],
    ) -> Result<Option<sid_core::models::NativePresented>> {
        CoordinodeBackend::native_generation_by_credential(self, hash).await
    }

    async fn rotate_native_generation(
        &self,
        rotation: sid_core::models::NativeRotation<'_>,
        ctx: MutationContext,
    ) -> Result<sid_core::models::NativeRotationOutcome> {
        CoordinodeBackend::rotate_native_generation(self, rotation, ctx).await
    }

    async fn create_auth_code(&self, code: &AuthorizationCode, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_auth_code(self, code, ctx).await
    }

    async fn get_auth_code_by_hash(&self, code_hash: &[u8]) -> Result<Option<AuthorizationCode>> {
        CoordinodeBackend::get_auth_code_by_hash(self, code_hash).await
    }

    async fn redeem_auth_code(
        &self,
        code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        ctx: MutationContext,
    ) -> Result<AuthCodeRedemption> {
        CoordinodeBackend::redeem_auth_code(self, code_hash, session, refresh_token, ctx).await
    }
}

#[async_trait]
impl CredentialStore for CoordinodeBackend {
    type Owner = ProfileId;

    async fn get_credential(&self, id: CredentialId) -> Result<Option<Credential>> {
        CoordinodeBackend::get_credential(self, id).await
    }

    async fn get_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> Result<Vec<Credential>> {
        CoordinodeBackend::get_credentials_by_profile(self, profile_id, credential_type).await
    }

    async fn create_credential(&self, credential: &Credential, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_credential(self, credential, ctx).await
    }

    async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::set_credential_label(self, id, label, ctx).await
    }

    async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::change_password(self, id, expected, new, history, ctx).await
    }

    async fn get_password_history(&self, owner: ProfileId) -> Result<PasswordHistory> {
        CoordinodeBackend::get_password_history(self, owner).await
    }

    async fn history_write_cutoff(&self) -> Result<Option<DateTime<Utc>>> {
        CoordinodeBackend::history_write_cutoff(self).await
    }

    async fn raise_history_write_cutoff(
        &self,
        not_before: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<DateTime<Utc>> {
        CoordinodeBackend::raise_history_write_cutoff(self, not_before, ctx).await
    }

    async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::reseal_credential_data(self, id, expected, data, ctx).await
    }

    async fn mark_credential_used(&self, id: CredentialId, ctx: MutationContext) -> Result<bool> {
        CoordinodeBackend::mark_credential_used(self, id, ctx).await
    }

    async fn replace_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::replace_credential_data(self, id, expected, data, ctx).await
    }

    async fn replace_credential(
        &self,
        credential: &Credential,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::replace_credential(self, credential, ctx).await
    }

    async fn enroll_credential(
        &self,
        credential: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::enroll_credential(self, credential, recovery, ctx).await
    }

    async fn delete_credential(&self, id: CredentialId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_credential(self, id, ctx).await
    }

    async fn revoke_credential(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> Result<sid_core::models::CredentialRevocation> {
        CoordinodeBackend::revoke_credential(self, id, ctx).await
    }

    async fn delete_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<u64> {
        CoordinodeBackend::delete_credentials_by_profile(self, profile_id, ctx).await
    }

    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: ProfileId,
        rp_id: &str,
        candidate: sid_core::models::WebAuthnUserHandle,
        ctx: MutationContext,
    ) -> Result<sid_core::models::WebAuthnUserHandle> {
        CoordinodeBackend::ensure_webauthn_user_handle(self, profile_id, rp_id, candidate, ctx)
            .await
    }

    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: sid_core::models::WebAuthnUserHandle,
    ) -> Result<Option<ProfileId>> {
        CoordinodeBackend::get_profile_by_webauthn_user_handle(self, rp_id, handle).await
    }
}

#[async_trait]
impl PrincipalStore for CoordinodeBackend {
    type Owner = ProfileId;

    async fn resolve_sign_in_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
        key_revision: Option<i64>,
    ) -> Result<Option<ProfileId>> {
        sid_plugin::principal_store::resolve_profile_principal(
            self,
            principal_type,
            value,
            key_revision,
        )
        .await
    }
}

#[async_trait]
impl SignInHistoryStore for CoordinodeBackend {
    type Owner = ProfileId;

    async fn get_most_recent_session_ip(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Option<(std::net::IpAddr, DateTime<Utc>)>> {
        refused("sign-in history")
    }

    async fn has_recent_session_from_ip(
        &self,
        _profile_id: ProfileId,
        _ip: std::net::IpAddr,
        _window: std::time::Duration,
    ) -> Result<bool> {
        refused("sign-in history")
    }

    async fn has_recent_session_from_device(
        &self,
        _profile_id: ProfileId,
        _device_id: Uuid,
        _window: std::time::Duration,
    ) -> Result<bool> {
        refused("sign-in history")
    }

    async fn record_login_location(
        &self,
        _profile_id: ProfileId,
        _country: &str,
        _latitude: f64,
        _longitude: f64,
        _designated_threshold: u32,
    ) -> Result<()> {
        refused("sign-in history")
    }

    async fn get_designated_countries(&self, _profile_id: ProfileId) -> Result<Vec<String>> {
        refused("sign-in history")
    }
}

#[async_trait]
impl StorageBackend for CoordinodeBackend {
    fn name(&self) -> &'static str {
        "coordinode"
    }

    // === PROFILES ===

    async fn get_profile(&self, id: ProfileId) -> Result<Option<Profile>> {
        CoordinodeBackend::get_profile(self, id).await
    }

    async fn get_profile_by_username(&self, username: &str) -> Result<Option<Profile>> {
        CoordinodeBackend::get_profile_by_username(self, username).await
    }

    async fn get_profile_by_email(&self, email: &str) -> Result<Option<Profile>> {
        CoordinodeBackend::get_profile_by_email(self, email).await
    }

    async fn create_profile(&self, profile: &Profile, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_profile(self, profile, ctx).await
    }

    async fn update_profile(&self, profile: &Profile, ctx: MutationContext) -> Result<bool> {
        CoordinodeBackend::update_profile(self, profile, ctx).await
    }

    async fn delete_profile(&self, id: ProfileId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_profile(self, id, ctx).await
    }

    async fn register_profile(
        &self,
        registration: &NewRegistration,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::register_profile(self, registration, ctx).await
    }

    async fn write_directory_user(
        &self,
        _write: &DirectoryUserWrite,
        _ctx: MutationContext,
    ) -> Result<Vec<Session>> {
        refused("directory writes")
    }

    async fn write_directory_group(
        &self,
        _write: &DirectoryGroupWrite,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("directory writes")
    }

    // === CONTACTS ===

    async fn get_profile_phone(&self, id: ProfilePhoneId) -> Result<Option<ProfilePhone>> {
        CoordinodeBackend::get_profile_phone(self, id).await
    }

    async fn list_profile_phones(&self, profile_id: ProfileId) -> Result<Vec<ProfilePhone>> {
        CoordinodeBackend::list_profile_phones(self, profile_id).await
    }

    async fn get_primary_profile_phone(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<ProfilePhone>> {
        CoordinodeBackend::get_primary_profile_phone(self, profile_id).await
    }

    async fn create_profile_phone(&self, phone: &ProfilePhone, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_profile_phone(self, phone, ctx).await
    }

    async fn update_profile_phone_settings(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        settings: &PhoneSettings,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_profile_phone_settings(self, profile_id, id, settings, at, ctx)
            .await
    }

    async fn set_primary_profile_phone(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::set_primary_profile_phone(self, profile_id, id, at, ctx).await
    }

    async fn delete_profile_phone(&self, id: ProfilePhoneId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_profile_phone(self, id, ctx).await
    }

    async fn get_profile_email(&self, id: ProfileEmailId) -> Result<Option<ProfileEmail>> {
        CoordinodeBackend::get_profile_email(self, id).await
    }

    async fn list_profile_emails(&self, profile_id: ProfileId) -> Result<Vec<ProfileEmail>> {
        CoordinodeBackend::list_profile_emails(self, profile_id).await
    }

    async fn get_primary_profile_email(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<ProfileEmail>> {
        CoordinodeBackend::get_primary_profile_email(self, profile_id).await
    }

    async fn create_profile_email(&self, email: &ProfileEmail, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_profile_email(self, email, ctx).await
    }

    async fn update_profile_email_settings(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        settings: &EmailSettings,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_profile_email_settings(self, profile_id, id, settings, at, ctx)
            .await
    }

    async fn set_primary_profile_email(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::set_primary_profile_email(self, profile_id, id, at, ctx).await
    }

    async fn delete_profile_email(&self, id: ProfileEmailId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_profile_email(self, id, ctx).await
    }

    // === PRINCIPALS ===

    async fn get_principal(&self, id: PrincipalId) -> Result<Option<Principal>> {
        CoordinodeBackend::get_principal(self, id).await
    }

    async fn get_principals_by_profile(&self, profile_id: ProfileId) -> Result<Vec<Principal>> {
        CoordinodeBackend::get_principals_by_profile(self, profile_id).await
    }

    async fn get_profile_by_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> Result<Option<Profile>> {
        CoordinodeBackend::get_profile_by_principal(self, principal_type, value).await
    }

    async fn save_principal(&self, principal: &Principal, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::save_principal(self, principal, ctx).await
    }

    async fn unbind_principal(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::unbind_principal(self, principal_id, profile_id, ctx).await
    }

    async fn count_active_principal_bindings(&self, principal_id: PrincipalId) -> Result<i64> {
        CoordinodeBackend::count_active_principal_bindings(self, principal_id).await
    }

    async fn get_principal_bindings(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Vec<PrincipalBinding>> {
        CoordinodeBackend::get_principal_bindings(self, principal_id).await
    }

    async fn get_principal_by_value(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> Result<Option<PrincipalEntity>> {
        CoordinodeBackend::get_principal_by_value(self, principal_type, value).await
    }

    async fn expire_principal_verifications(&self) -> Result<i64> {
        CoordinodeBackend::expire_principal_verifications(self).await
    }

    async fn reconcile_email_key(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        contact: &ProfileEmail,
        reason: &str,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::reconcile_email_key(self, principal_id, profile_id, contact, reason, ctx)
            .await
    }

    // === CONSENTS ===

    async fn revoke_consents_by_profile(
        &self,
        _profile_id: ProfileId,
        _ctx: MutationContext,
    ) -> Result<u64> {
        refused("consents")
    }

    async fn create_consent(&self, _consent: &ConsentRecord, _ctx: MutationContext) -> Result<()> {
        refused("consents")
    }

    async fn change_claim_grant(
        &self,
        _id: ConsentId,
        _claim_name: &str,
        _decision: sid_core::models::consent::ClaimDecision,
        _ctx: MutationContext,
    ) -> Result<sid_core::models::consent::ClaimGrantChange> {
        refused("consents")
    }

    async fn get_consent(&self, _id: ConsentId) -> Result<Option<ConsentRecord>> {
        refused("consents")
    }

    async fn get_consent_by_client(
        &self,
        _profile_id: ProfileId,
        _client_id: &str,
    ) -> Result<Option<ConsentRecord>> {
        refused("consents")
    }

    async fn list_consents_by_profile(&self, _profile_id: ProfileId) -> Result<Vec<ConsentRecord>> {
        refused("consents")
    }

    async fn delete_consent(&self, _id: ConsentId, _ctx: MutationContext) -> Result<bool> {
        refused("consents")
    }

    // === SIGNALS ===

    async fn save_anomaly_event(&self, _event: &AnomalyEventRecord) -> Result<()> {
        refused("anomaly events")
    }

    async fn list_anomaly_events(
        &self,
        _rule_id: Option<&str>,
        _limit: i32,
        _offset: i32,
    ) -> Result<Vec<AnomalyEventRecord>> {
        refused("anomaly events")
    }

    async fn record_ip_reputation_event(&self, _ip: &str, _success: bool) -> Result<()> {
        refused("IP reputation")
    }

    async fn get_ip_reputation_score(&self, _ip: &str) -> Result<Option<f32>> {
        refused("IP reputation")
    }

    async fn list_suspicious_ips(
        &self,
        _min_score: f32,
        _limit: i64,
    ) -> Result<Vec<(String, f32)>> {
        refused("IP reputation")
    }

    async fn decay_ip_reputation(&self, _older_than: std::time::Duration) -> Result<u64> {
        refused("IP reputation")
    }

    async fn add_ip_allowlist_entry(
        &self,
        _cidr: &str,
        _description: &str,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("the IP allowlist")
    }

    async fn remove_ip_allowlist_entry(&self, _cidr: &str, _ctx: MutationContext) -> Result<()> {
        refused("the IP allowlist")
    }

    async fn list_ip_allowlist_entries(&self) -> Result<Vec<(String, String, DateTime<Utc>)>> {
        refused("the IP allowlist")
    }

    // === SESSIONS ===

    async fn create_session(&self, session: &Session, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_session(self, session, ctx).await
    }

    async fn record_session_authentication(
        &self,
        id: SessionId,
        expected: &SessionAuthentication,
        new: &SessionAuthentication,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::record_session_authentication(self, id, expected, new, ctx).await
    }

    async fn delete_sessions_by_profile(
        &self,
        profile_id: ProfileId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> Result<Vec<Session>> {
        CoordinodeBackend::delete_sessions_by_profile(self, profile_id, end, ctx).await
    }

    // === PROJECTS ===

    async fn get_project(&self, id: ProjectId) -> Result<Option<Project>> {
        CoordinodeBackend::get_project(self, id).await
    }

    async fn create_project(&self, project: &Project, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_project(self, project, ctx).await
    }

    async fn update_project(
        &self,
        id: ProjectId,
        change: &ProjectChange,
        ctx: MutationContext,
    ) -> Result<Option<Project>> {
        CoordinodeBackend::update_project(self, id, change, ctx).await
    }

    async fn delete_project(&self, id: ProjectId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_project(self, id, ctx).await
    }

    async fn list_projects(&self, offset: u64, limit: u64) -> Result<Vec<Project>> {
        CoordinodeBackend::list_projects(self, offset, limit).await
    }

    async fn count_projects(&self) -> Result<u64> {
        CoordinodeBackend::count_projects(self).await
    }

    async fn list_oauth2_clients_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<OAuth2Client>> {
        CoordinodeBackend::list_oauth2_clients(self, Some(project_id), offset, limit).await
    }

    async fn ensure_system_project(&self, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::ensure_system_project(self, ctx).await
    }

    // === CLIENTS AND APPLICATIONS ===

    async fn update_oauth2_client(
        &self,
        client: &OAuth2Client,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_oauth2_client(self, client, ctx).await
    }

    async fn create_oauth2_client(
        &self,
        client: &OAuth2Client,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_oauth2_client(self, client, ctx).await
    }

    async fn delete_oauth2_client(&self, client_id: &str, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_oauth2_client(self, client_id, ctx).await
    }

    async fn list_oauth2_clients(&self, offset: u64, limit: u64) -> Result<Vec<OAuth2Client>> {
        CoordinodeBackend::list_oauth2_clients(self, None, offset, limit).await
    }

    async fn oauth2_client_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> Result<Option<OAuth2Client>> {
        CoordinodeBackend::oauth2_client_of_application(self, id).await
    }

    async fn create_application(
        &self,
        app: &sid_core::models::Application,
        client: Option<&OAuth2Client>,
        resource: Option<&ProtectedResource>,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_application(self, app, client, resource, ctx).await
    }

    async fn get_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> Result<Option<sid_core::models::Application>> {
        CoordinodeBackend::get_application(self, id).await
    }

    async fn system_application(
        &self,
        kind: sid_core::models::SystemIntegration,
    ) -> Result<Option<sid_core::models::Application>> {
        CoordinodeBackend::system_application(self, kind).await
    }

    async fn list_applications_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<sid_core::models::Application>> {
        CoordinodeBackend::list_applications_by_project(self, project_id, offset, limit).await
    }

    async fn update_application(
        &self,
        app: &sid_core::models::Application,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_application(self, app, ctx).await
    }

    async fn delete_application(
        &self,
        id: sid_core::models::ApplicationId,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::delete_application(self, id, ctx).await
    }

    async fn create_protected_resource(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_protected_resource(self, resource, ctx).await
    }

    async fn protected_resource_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> Result<Option<ProtectedResource>> {
        CoordinodeBackend::protected_resource_of_application(self, id).await
    }

    async fn list_protected_resources(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<ProtectedResource>> {
        CoordinodeBackend::list_protected_resources(self, offset, limit).await
    }

    async fn import_protected_resource(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::import_protected_resource(self, resource, ctx).await
    }

    async fn update_protected_resource(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_protected_resource(self, resource, ctx).await
    }

    async fn set_resource_access(
        &self,
        access: &ResourceAccess,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::set_resource_access(self, access, ctx).await
    }

    async fn remove_resource_access(
        &self,
        client_id: &str,
        resource: ResourceId,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::remove_resource_access(self, client_id, resource, ctx).await
    }

    async fn list_resource_access_by_client(&self, client_id: &str) -> Result<Vec<ResourceAccess>> {
        CoordinodeBackend::list_resource_access(
            self,
            "client_id",
            coordinode_core::graph::types::Value::String(client_id.to_owned()),
            "resource_id",
        )
        .await
    }

    async fn list_resource_access_by_resource(
        &self,
        resource: ResourceId,
    ) -> Result<Vec<ResourceAccess>> {
        CoordinodeBackend::list_resource_access(
            self,
            "resource_id",
            super::uuid(resource.as_uuid()),
            "client_id",
        )
        .await
    }

    // === ADMIN QUERIES ===

    async fn list_profiles(&self, offset: u64, limit: u64) -> Result<Vec<Profile>> {
        CoordinodeBackend::list_profiles(self, offset, limit).await
    }

    async fn count_profiles(&self) -> Result<u64> {
        CoordinodeBackend::count_profiles(self).await
    }

    async fn query_directory(
        &self,
        _query: &sid_core::models::DirectoryQuery,
    ) -> Result<sid_core::models::DirectoryPage> {
        refused("the directory")
    }

    async fn list_profiles_with_status(
        &self,
        status: sid_core::models::ProfileStatus,
    ) -> Result<Vec<Profile>> {
        CoordinodeBackend::list_profiles_with_status(self, status).await
    }

    async fn list_profiles_with_pending_migration(&self) -> Result<Vec<Profile>> {
        CoordinodeBackend::list_profiles_with_pending_migration(self).await
    }

    async fn end_legacy_migration(&self, profile: &Profile, ctx: MutationContext) -> Result<bool> {
        CoordinodeBackend::end_legacy_migration(self, profile, ctx).await
    }

    async fn export_password_history(
        &self,
        owner: ProfileId,
    ) -> Result<Option<sid_core::models::HistoryArchive>> {
        CoordinodeBackend::export_password_history(self, owner).await
    }

    async fn import_password_history(
        &self,
        archive: &sid_core::models::HistoryArchive,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::import_password_history(self, archive, ctx).await
    }

    // === TOKENS ===

    async fn create_refresh_token(&self, token: &RefreshToken, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_refresh_token(self, token, ctx).await
    }

    async fn create_initial_access_token(
        &self,
        token: &InitialAccessToken,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_initial_access_token(self, token, ctx).await
    }

    async fn register_dynamic_client(
        &self,
        app: &sid_core::models::Application,
        client: &OAuth2Client,
        iat: InitialAccessTokenId,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::register_dynamic_client(self, app, client, iat, ctx).await
    }

    async fn list_key_versions(&self) -> Result<Vec<sid_keys::KeyVersionParams>> {
        refused("field-encryption key versions")
    }

    async fn insert_key_version(
        &self,
        _params: &sid_keys::KeyVersionParams,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("field-encryption key versions")
    }

    // === INSTALLATION ===

    async fn admin_exists(&self) -> Result<bool> {
        CoordinodeBackend::admin_exists(self).await
    }

    async fn bootstrap_policy(&self) -> Result<sid_core::models::BootstrapPolicy> {
        CoordinodeBackend::bootstrap_policy(self).await
    }

    async fn adopt_central_management(
        &self,
        ctx: MutationContext,
    ) -> Result<sid_core::models::CentralAdoption> {
        CoordinodeBackend::adopt_central_management(self, ctx).await
    }

    async fn enrollment_policy(&self) -> Result<Option<sid_core::models::EnrollmentPolicy>> {
        CoordinodeBackend::enrollment_policy(self).await
    }

    async fn set_enrollment_policy(
        &self,
        policy: &sid_core::models::EnrollmentPolicy,
        mode: sid_core::models::ModeWrite,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::set_enrollment_policy(self, policy, mode, ctx).await
    }

    async fn claim_first_admin(
        &self,
        claim_sealed: &[u8],
        profile: ProfileId,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::claim_first_admin(self, claim_sealed, profile, ctx).await
    }

    async fn instance_organization(&self) -> Result<Option<sid_core::models::Organization>> {
        CoordinodeBackend::instance_organization(self).await
    }

    async fn insert_instance_organization(
        &self,
        org: &sid_core::models::Organization,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::insert_instance_organization(self, org, ctx).await
    }

    async fn assign_unowned_clients(
        &self,
        org_id: sid_core::models::OrgId,
        ctx: MutationContext,
    ) -> Result<u64> {
        CoordinodeBackend::assign_unowned_clients(self, org_id, ctx).await
    }

    // === SERVICE BINDINGS ===

    async fn service_binding(
        &self,
        _profile_id: ProfileId,
        _scope: &sid_core::models::BindingScope,
        _ctx: MutationContext,
    ) -> Result<sid_core::models::ServiceBinding> {
        refused("service bindings")
    }

    async fn list_service_bindings(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Vec<sid_core::models::ServiceBinding>> {
        refused("service bindings")
    }

    async fn import_service_binding(
        &self,
        _binding: &sid_core::models::ServiceBinding,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("service bindings")
    }

    async fn find_service_binding(
        &self,
        _profile_id: ProfileId,
        _scope: &sid_core::models::BindingScope,
    ) -> Result<Option<sid_core::models::ServiceBinding>> {
        refused("service bindings")
    }

    async fn list_credentials_by_type(
        &self,
        credential_type: CredentialType,
        after: Option<CredentialId>,
        limit: u32,
    ) -> Result<Vec<Credential>> {
        CoordinodeBackend::list_credentials_by_type(self, credential_type, after, limit).await
    }

    async fn get_initial_access_token(
        &self,
        id: InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken>> {
        CoordinodeBackend::get_initial_access_token(self, id).await
    }

    async fn get_initial_access_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<InitialAccessToken>> {
        CoordinodeBackend::get_initial_access_token_by_hash(self, token_hash).await
    }

    async fn list_initial_access_tokens_by_project(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<InitialAccessToken>> {
        CoordinodeBackend::list_initial_access_tokens_by_project(self, project_id).await
    }

    async fn revoke_initial_access_token(
        &self,
        id: InitialAccessTokenId,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::revoke_initial_access_token(self, id, ctx).await
    }

    // === ROLES ===

    async fn get_role(&self, id: RoleId) -> Result<Option<Role>> {
        CoordinodeBackend::get_role(self, id).await
    }

    async fn get_roles(&self, ids: &[RoleId]) -> Result<Vec<Role>> {
        CoordinodeBackend::get_roles(self, ids).await
    }

    async fn get_role_by_name(&self, project_id: ProjectId, name: &str) -> Result<Option<Role>> {
        CoordinodeBackend::get_role_by_name(self, project_id, name).await
    }

    async fn create_role(&self, role: &Role, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_role(self, role, ctx).await
    }

    async fn update_role(&self, role: &Role, ctx: MutationContext) -> Result<bool> {
        CoordinodeBackend::update_role(self, role, ctx).await
    }

    async fn update_role_fenced(
        &self,
        role: &Role,
        fence: &sid_core::models::RoleEditFence,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_role_fenced(self, role, fence, ctx).await
    }

    async fn delete_role(&self, id: RoleId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_role(self, id, ctx).await
    }

    async fn list_roles(&self, project_id: ProjectId) -> Result<Vec<Role>> {
        CoordinodeBackend::list_roles(self, project_id).await
    }

    // === GROUPS ===

    async fn get_group(&self, id: GroupId) -> Result<Option<Group>> {
        CoordinodeBackend::get_group(self, id).await
    }

    async fn create_group(&self, group: &Group, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_group(self, group, ctx).await
    }

    async fn set_group_description(
        &self,
        id: GroupId,
        description: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::set_group_description(self, id, description, ctx).await
    }

    async fn delete_group(&self, id: GroupId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_group(self, id, ctx).await
    }

    async fn list_groups(&self, project_id: ProjectId) -> Result<Vec<Group>> {
        CoordinodeBackend::list_groups(self, project_id).await
    }

    async fn add_to_group(&self, member: &GroupMember, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::add_to_group(self, member, ctx).await
    }

    async fn remove_from_group(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::remove_from_group(self, group_id, profile_id, ctx).await
    }

    async fn list_group_members(&self, group_id: GroupId) -> Result<Vec<GroupMember>> {
        CoordinodeBackend::list_group_members(self, group_id).await
    }

    async fn list_groups_for_profile(&self, profile_id: ProfileId) -> Result<Vec<Group>> {
        CoordinodeBackend::list_groups_for_profile(self, profile_id).await
    }

    // === ROLE ASSIGNMENTS ===

    async fn create_role_assignment(
        &self,
        assignment: &RoleAssignment,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_role_assignment(self, assignment, ctx).await
    }

    async fn delete_role_assignment(
        &self,
        id: RoleAssignmentId,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::delete_role_assignment(self, id, ctx).await
    }

    async fn get_role_assignment(&self, id: RoleAssignmentId) -> Result<Option<RoleAssignment>> {
        CoordinodeBackend::get_role_assignment(self, id).await
    }

    async fn create_role_assignment_fenced(
        &self,
        assignment: &RoleAssignment,
        fence: &sid_core::models::AssignmentFence,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_role_assignment_fenced(self, assignment, fence, ctx).await
    }

    async fn delete_role_assignment_fenced(
        &self,
        id: RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::delete_role_assignment_fenced(self, id, fence, ctx).await
    }

    async fn list_role_assignments_for_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_for_profile(self, profile_id).await
    }

    async fn list_role_assignments_for_group(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_for_group(self, group_id).await
    }

    async fn list_role_assignments_held_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_held_by_profile(self, profile_id).await
    }

    async fn list_role_assignments_for_machine_user(
        &self,
        machine_user_id: MachineUserId,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_for_machine_user(self, machine_user_id).await
    }

    async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_for_oauth_client(self, client_id).await
    }

    async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_for_provisioning_connector(self, connector_id)
            .await
    }

    async fn list_role_assignments_for_role(&self, role_id: RoleId) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_role_assignments_for_role(self, role_id).await
    }

    async fn list_expiring_role_assignments(
        &self,
        within_hours: i64,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::list_expiring_role_assignments(self, within_hours).await
    }

    async fn cleanup_expired_role_assignments(
        &self,
        ctx: MutationContext,
    ) -> Result<Vec<RoleAssignment>> {
        CoordinodeBackend::cleanup_expired_role_assignments(self, ctx).await
    }

    async fn list_sod_rules(&self) -> Result<Vec<SodConflictRule>> {
        // No write path stores separation-of-duties rules: none are held.
        Ok(Vec::new())
    }

    // === CEDAR POLICIES ===

    async fn get_cedar_policy(&self, id: CedarPolicyId) -> Result<Option<CedarPolicy>> {
        CoordinodeBackend::get_cedar_policy(self, id).await
    }

    async fn create_cedar_policy(&self, policy: &CedarPolicy, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_cedar_policy(self, policy, ctx).await
    }

    async fn update_cedar_policy(
        &self,
        policy: &CedarPolicy,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::update_cedar_policy(self, policy, ctx).await
    }

    async fn delete_cedar_policy(&self, id: CedarPolicyId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::delete_cedar_policy(self, id, ctx).await
    }

    async fn list_cedar_policies(&self, scope: PolicyScope) -> Result<Vec<CedarPolicy>> {
        CoordinodeBackend::list_cedar_policies(self, scope).await
    }

    // === PROFILE METADATA ===

    async fn get_profile_metadata(
        &self,
        _profile_id: ProfileId,
        _key: &str,
    ) -> Result<Option<ProfileMetadata>> {
        refused("profile metadata")
    }

    async fn set_profile_metadata(
        &self,
        _metadata: &ProfileMetadata,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("profile metadata")
    }

    async fn delete_profile_metadata(
        &self,
        _profile_id: ProfileId,
        _key: &str,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("profile metadata")
    }

    async fn list_profile_metadata(&self, _profile_id: ProfileId) -> Result<Vec<ProfileMetadata>> {
        refused("profile metadata")
    }

    // === DEVICES ===

    async fn create_device(&self, _device: &Device, _ctx: MutationContext) -> Result<()> {
        refused("devices")
    }

    async fn rename_device(
        &self,
        _id: DeviceId,
        _display_name: Option<&str>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("devices")
    }

    async fn set_device_trust(
        &self,
        _id: DeviceId,
        _trusted: bool,
        _max_trusted: usize,
        _ctx: MutationContext,
    ) -> Result<DeviceTrustChange> {
        refused("devices")
    }

    async fn get_device(&self, _id: DeviceId) -> Result<Option<Device>> {
        refused("devices")
    }

    async fn list_devices_by_profile(&self, _profile_id: ProfileId) -> Result<Vec<Device>> {
        refused("devices")
    }

    async fn delete_device(&self, _id: DeviceId, _ctx: MutationContext) -> Result<()> {
        refused("devices")
    }

    async fn get_device_by_fingerprint(
        &self,
        _profile_id: ProfileId,
        _fingerprint_hash: &str,
    ) -> Result<Option<Device>> {
        refused("devices")
    }

    async fn create_device_attestation(
        &self,
        _attestation: &DeviceAttestation,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("device attestations")
    }

    async fn rotate_device_attestation(
        &self,
        _device_id: DeviceId,
        _device_public_key: &[u8],
        _attestation_object: Option<&[u8]>,
        _attestation_certificate: Option<&[u8]>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("device attestations")
    }

    async fn revoke_device_attestation(
        &self,
        _device_id: DeviceId,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("device attestations")
    }

    async fn get_device_attestation(
        &self,
        _id: DeviceAttestationId,
    ) -> Result<Option<DeviceAttestation>> {
        refused("device attestations")
    }

    async fn get_device_attestation_by_device_id(
        &self,
        _device_id: DeviceId,
    ) -> Result<Option<DeviceAttestation>> {
        refused("device attestations")
    }

    async fn list_device_attestations_by_profile(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Vec<DeviceAttestation>> {
        refused("device attestations")
    }

    async fn delete_device_attestation(
        &self,
        _device_id: DeviceId,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("device attestations")
    }

    // === DEVICE AUTHORIZATION ===

    async fn create_device_auth_code(
        &self,
        _code: &DeviceAuthorizationCode,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("device authorization")
    }

    async fn get_device_auth_by_device_code_hash(
        &self,
        _device_code_hash: &[u8],
    ) -> Result<Option<DeviceAuthorizationCode>> {
        refused("device authorization")
    }

    async fn get_device_auth_by_user_code(
        &self,
        _user_code: &str,
    ) -> Result<Option<DeviceAuthorizationCode>> {
        refused("device authorization")
    }

    async fn decide_device_auth(
        &self,
        _id: DeviceAuthCodeId,
        _decision: sid_core::models::DeviceAuthDecision,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("device authorization")
    }

    async fn record_device_poll(
        &self,
        _id: DeviceAuthCodeId,
        _ctx: MutationContext,
    ) -> Result<sid_core::models::DevicePoll> {
        refused("device authorization")
    }

    async fn redeem_device_code(
        &self,
        _device_code_hash: &[u8],
        _session: &Session,
        _refresh_token: &RefreshToken,
        _ctx: MutationContext,
    ) -> Result<sid_core::models::DeviceCodeRedemption> {
        refused("device authorization")
    }

    async fn cleanup_expired_device_auth_codes(&self, _ctx: MutationContext) -> Result<u64> {
        refused("device authorization")
    }

    // === PROFILE GRANTS ===

    async fn get_profile_grant(&self, _id: ProfileGrantId) -> Result<Option<ProfileGrant>> {
        refused("profile grants")
    }

    async fn create_profile_grant(
        &self,
        _grant: &ProfileGrant,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("profile grants")
    }

    async fn delete_profile_grant(&self, _id: ProfileGrantId, _ctx: MutationContext) -> Result<()> {
        refused("profile grants")
    }

    async fn list_profile_grants_for_profile(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Vec<ProfileGrant>> {
        refused("profile grants")
    }

    async fn list_profile_grants_for_project(
        &self,
        _project_id: ProjectId,
    ) -> Result<Vec<ProfileGrant>> {
        refused("profile grants")
    }

    // === UPSTREAM PROVIDERS ===

    async fn get_upstream_provider(
        &self,
        _id: UpstreamProviderId,
    ) -> Result<Option<UpstreamProvider>> {
        refused("upstream providers")
    }

    async fn create_upstream_provider(
        &self,
        _provider: &UpstreamProvider,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("upstream providers")
    }

    async fn update_upstream_provider(
        &self,
        _provider: &UpstreamProvider,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("upstream providers")
    }

    async fn delete_upstream_provider(
        &self,
        _id: UpstreamProviderId,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("upstream providers")
    }

    async fn list_enabled_upstream_providers(&self) -> Result<Vec<UpstreamProvider>> {
        refused("upstream providers")
    }

    async fn get_upstream_identity_by_provider_subject(
        &self,
        _provider_id: UpstreamProviderId,
        _upstream_subject: &str,
    ) -> Result<Option<UpstreamIdentity>> {
        refused("upstream identities")
    }

    async fn create_upstream_identity(
        &self,
        _identity: &UpstreamIdentity,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("upstream identities")
    }

    async fn record_upstream_login(
        &self,
        _id: UpstreamIdentityId,
        _login: &UpstreamLogin,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("upstream identities")
    }

    async fn list_upstream_identities_by_profile(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Vec<UpstreamIdentity>> {
        refused("upstream identities")
    }

    async fn delete_upstream_identity(
        &self,
        _id: UpstreamIdentityId,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("upstream identities")
    }

    // === PERSONAL ACCESS TOKENS ===

    async fn get_pat(&self, _id: PatId) -> Result<Option<PersonalAccessToken>> {
        refused("personal access tokens")
    }

    async fn get_pat_by_token_hash(
        &self,
        _token_hash: &str,
    ) -> Result<Option<PersonalAccessToken>> {
        refused("personal access tokens")
    }

    async fn create_pat(
        &self,
        _pat: &PersonalAccessToken,
        _active_limit: Option<u64>,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("personal access tokens")
    }

    async fn record_pat_use(
        &self,
        _id: PatId,
        _ip: Option<&str>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("personal access tokens")
    }

    async fn revoke_pat(
        &self,
        _id: PatId,
        _revoked_by: &str,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("personal access tokens")
    }

    async fn list_pats_by_profile(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Vec<PersonalAccessToken>> {
        refused("personal access tokens")
    }

    async fn list_all_pats(&self) -> Result<Vec<PersonalAccessToken>> {
        refused("personal access tokens")
    }

    async fn count_active_pats_by_profile(&self, _profile_id: ProfileId) -> Result<u64> {
        refused("personal access tokens")
    }

    async fn revoke_active_pats_by_profile(
        &self,
        _profile_id: ProfileId,
        _revoked_by: &str,
        _ctx: MutationContext,
    ) -> Result<u64> {
        refused("personal access tokens")
    }

    async fn revoke_unused_pats(&self, _days: u32, _ctx: MutationContext) -> Result<u64> {
        refused("personal access tokens")
    }

    // === MACHINE USERS ===

    async fn get_machine_user(&self, _id: MachineUserId) -> Result<Option<MachineUser>> {
        refused("machine users")
    }

    async fn get_machine_user_by_client_id(&self, _client_id: &str) -> Result<Option<MachineUser>> {
        refused("machine users")
    }

    async fn create_machine_user(&self, _mu: &MachineUser, _ctx: MutationContext) -> Result<()> {
        refused("machine users")
    }

    async fn update_machine_user(&self, _mu: &MachineUser, _ctx: MutationContext) -> Result<bool> {
        refused("machine users")
    }

    async fn transition_machine_user(
        &self,
        _id: MachineUserId,
        _from: MachineUserStatus,
        _to: MachineUserStatus,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("machine users")
    }

    async fn delete_machine_user(&self, _id: MachineUserId, _ctx: MutationContext) -> Result<()> {
        refused("machine users")
    }

    async fn list_machine_users_by_project(
        &self,
        _project_id: ProjectId,
    ) -> Result<Vec<MachineUser>> {
        refused("machine users")
    }

    async fn get_machine_credential_by_kid(
        &self,
        _kid: &str,
    ) -> Result<Option<MachineUserCredential>> {
        refused("machine credentials")
    }

    async fn add_machine_credential(
        &self,
        _cred: &MachineUserCredential,
        _active_limit: Option<u64>,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("machine credentials")
    }

    async fn rotate_machine_credential(
        &self,
        _machine_user_id: MachineUserId,
        _old_kid: &str,
        _new: &MachineUserCredential,
        _grace_until: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("machine credentials")
    }

    async fn revoke_machine_credential(
        &self,
        _machine_user_id: MachineUserId,
        _kid: &str,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("machine credentials")
    }

    async fn revoke_active_machine_credentials_by_user(
        &self,
        _id: MachineUserId,
        _ctx: MutationContext,
    ) -> Result<u64> {
        refused("machine credentials")
    }

    async fn list_machine_credentials_by_user(
        &self,
        _id: MachineUserId,
    ) -> Result<Vec<MachineUserCredential>> {
        refused("machine credentials")
    }

    async fn list_expiring_machine_credentials(
        &self,
        _within_days: u32,
    ) -> Result<Vec<MachineUserCredential>> {
        refused("machine credentials")
    }

    // === PROVISIONING CONNECTORS ===

    async fn get_provisioning_connector(
        &self,
        _id: ProvisioningConnectorId,
    ) -> Result<Option<ProvisioningConnector>> {
        refused("provisioning connectors")
    }

    async fn get_provisioning_connector_by_client_id(
        &self,
        _client_id: &str,
    ) -> Result<Option<ProvisioningConnector>> {
        refused("provisioning connectors")
    }

    async fn list_provisioning_connectors(
        &self,
        _org_id: OrgId,
    ) -> Result<Vec<ProvisioningConnector>> {
        refused("provisioning connectors")
    }

    async fn create_provisioning_connector(
        &self,
        _connector: &ProvisioningConnector,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("provisioning connectors")
    }

    async fn rename_provisioning_connector(
        &self,
        _id: ProvisioningConnectorId,
        _revision: i64,
        _display_name: &str,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("provisioning connectors")
    }

    async fn transition_provisioning_connector(
        &self,
        _id: ProvisioningConnectorId,
        _from: ConnectorState,
        _to: ConnectorState,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("provisioning connectors")
    }

    async fn add_provisioning_credential(
        &self,
        _credential: &ProvisioningCredential,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("provisioning credentials")
    }

    async fn rotate_provisioning_credential(
        &self,
        _connector_id: ProvisioningConnectorId,
        _old: ProvisioningCredentialId,
        _new: &ProvisioningCredential,
        _grace_until: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("provisioning credentials")
    }

    async fn revoke_provisioning_credential(
        &self,
        _connector_id: ProvisioningConnectorId,
        _id: ProvisioningCredentialId,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("provisioning credentials")
    }

    async fn list_provisioning_credentials(
        &self,
        _connector_id: ProvisioningConnectorId,
    ) -> Result<Vec<ProvisioningCredential>> {
        refused("provisioning credentials")
    }

    async fn find_provisioning_credential(
        &self,
        _verifier: &str,
    ) -> Result<Option<(ProvisioningCredential, ProvisioningConnector)>> {
        refused("provisioning credentials")
    }

    // === IMPERSONATION GRANTS ===

    async fn save_impersonation_grant(
        &self,
        _grant: &ImpersonationGrant,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("impersonation grants")
    }

    async fn delete_impersonation_grant(
        &self,
        _machine_user_id: MachineUserId,
        _target_type: &str,
        _target: &str,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("impersonation grants")
    }

    async fn list_impersonation_grants(
        &self,
        _machine_user_id: MachineUserId,
    ) -> Result<Vec<ImpersonationGrant>> {
        refused("impersonation grants")
    }

    // === QUARANTINE AND CLOSURE ===

    async fn quarantine_principal(
        &self,
        principal_hash: &str,
        principal_type: &str,
        quarantine_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::quarantine_principal(
            self,
            principal_hash,
            principal_type,
            quarantine_until,
            ctx,
        )
        .await
    }

    async fn is_principal_quarantined(&self, principal_hash: &str) -> Result<bool> {
        CoordinodeBackend::is_principal_quarantined(self, principal_hash).await
    }

    async fn cleanup_expired_quarantine(&self, ctx: MutationContext) -> Result<u64> {
        CoordinodeBackend::cleanup_expired_quarantine(self, ctx).await
    }

    async fn create_closure_request(
        &self,
        _req: &ClosureRequest,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("closure requests")
    }

    async fn request_profile_closure(
        &self,
        _profile: &Profile,
        _req: &ClosureRequest,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("closure requests")
    }

    async fn cancel_profile_closure(
        &self,
        _profile: &Profile,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("closure requests")
    }

    async fn get_closure_request(&self, _profile_id: ProfileId) -> Result<Option<ClosureRequest>> {
        refused("closure requests")
    }

    // === DATA EXPORT ===

    async fn create_export_job(&self, _job: &ExportJob, _ctx: MutationContext) -> Result<()> {
        refused("export jobs")
    }

    async fn acknowledge_export_job(
        &self,
        _id: Uuid,
        _at: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("export jobs")
    }

    async fn expire_export_job(
        &self,
        _id: Uuid,
        _at: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("export jobs")
    }

    async fn get_export_job(&self, _profile_id: ProfileId) -> Result<Option<ExportJob>> {
        refused("export jobs")
    }

    async fn get_export_job_by_id(&self, _job_id: Uuid) -> Result<Option<ExportJob>> {
        refused("export jobs")
    }

    // === MAGIC LINKS ===

    async fn create_magic_link_session(
        &self,
        _session: &MagicLinkSession,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("magic links")
    }

    async fn get_magic_link_session(&self, _id: Uuid) -> Result<Option<MagicLinkSession>> {
        refused("magic links")
    }

    async fn consume_magic_link_session(&self, _id: Uuid, _ctx: MutationContext) -> Result<()> {
        refused("magic links")
    }

    async fn try_consume_magic_link_session(
        &self,
        _id: Uuid,
        _ctx: MutationContext,
    ) -> Result<Option<MagicLinkSession>> {
        refused("magic links")
    }

    async fn delete_expired_magic_link_sessions(&self, _ctx: MutationContext) -> Result<u64> {
        refused("magic links")
    }

    async fn count_active_magic_links_for_email(&self, _email: &str) -> Result<u32> {
        refused("magic links")
    }

    // === SCIM OUTBOUND ===

    async fn create_scim_outbound_target(
        &self,
        _target: &ScimOutboundTarget,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    async fn get_scim_outbound_target(
        &self,
        _id: ScimOutboundTargetId,
    ) -> Result<Option<ScimOutboundTarget>> {
        refused("SCIM outbound provisioning")
    }

    async fn list_scim_outbound_targets(
        &self,
        _project_id: ProjectId,
    ) -> Result<Vec<ScimOutboundTarget>> {
        refused("SCIM outbound provisioning")
    }

    async fn delete_scim_outbound_target(
        &self,
        _id: ScimOutboundTargetId,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    async fn create_scim_outbound_record(
        &self,
        _record: &ScimOutboundRecord,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    async fn record_scim_outbound_sync(
        &self,
        _record: &ScimOutboundRecord,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    async fn record_scim_outbound_dead_letter(
        &self,
        _entry: &OutboundDlqEntry,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    async fn get_scim_outbound_record(
        &self,
        _target_id: ScimOutboundTargetId,
        _sid_entity_id: Uuid,
        _entity_type: OutboundEntityType,
    ) -> Result<Option<ScimOutboundRecord>> {
        refused("SCIM outbound provisioning")
    }

    async fn create_outbound_dlq_entry(
        &self,
        _entry: &OutboundDlqEntry,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    async fn list_outbound_dlq_entries(
        &self,
        _target_id: ScimOutboundTargetId,
    ) -> Result<Vec<OutboundDlqEntry>> {
        refused("SCIM outbound provisioning")
    }

    async fn delete_outbound_dlq_entry(&self, _id: Uuid, _ctx: MutationContext) -> Result<()> {
        refused("SCIM outbound provisioning")
    }

    // === FLOWS ===

    async fn get_flow_config(
        &self,
        _project_id: ProjectId,
        _flow_type: sid_core::models::FlowType,
    ) -> Result<Option<sid_core::models::FlowConfig>> {
        refused("flow configurations")
    }

    async fn save_flow_config(
        &self,
        _config: &sid_core::models::FlowConfig,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("flow configurations")
    }

    async fn list_flow_configs(
        &self,
        _project_id: ProjectId,
    ) -> Result<Vec<sid_core::models::FlowConfig>> {
        refused("flow configurations")
    }

    async fn create_flow_action(
        &self,
        _action: &sid_core::models::FlowAction,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("flow actions")
    }

    async fn update_flow_action(
        &self,
        _action: &sid_core::models::FlowAction,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("flow actions")
    }

    async fn get_flow_action(
        &self,
        _id: sid_core::models::ActionId,
    ) -> Result<Option<sid_core::models::FlowAction>> {
        refused("flow actions")
    }

    async fn list_flow_actions(
        &self,
        _project_id: ProjectId,
        _flow_type: sid_core::models::FlowType,
        _action_point: Option<sid_core::models::ActionPoint>,
    ) -> Result<Vec<sid_core::models::FlowAction>> {
        refused("flow actions")
    }

    async fn delete_flow_action(
        &self,
        _id: sid_core::models::ActionId,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("flow actions")
    }

    // === BRANDING ===

    async fn create_branding_config(
        &self,
        _config: &sid_core::models::BrandingConfig,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("branding")
    }

    async fn update_branding_draft(
        &self,
        _config: &sid_core::models::BrandingConfig,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("branding")
    }

    async fn publish_branding_config(
        &self,
        _id: sid_core::models::BrandingConfigId,
        _project_id: ProjectId,
        _at: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("branding")
    }

    async fn get_published_branding(
        &self,
        _project_id: ProjectId,
    ) -> Result<Option<sid_core::models::BrandingConfig>> {
        refused("branding")
    }

    async fn get_branding_config(
        &self,
        _id: sid_core::models::BrandingConfigId,
    ) -> Result<Option<sid_core::models::BrandingConfig>> {
        refused("branding")
    }

    async fn list_branding_configs(
        &self,
        _project_id: ProjectId,
    ) -> Result<Vec<sid_core::models::BrandingConfig>> {
        refused("branding")
    }

    async fn delete_branding_config(
        &self,
        _id: sid_core::models::BrandingConfigId,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("branding")
    }

    // === INVITES AND REGISTRATION SOURCES ===

    async fn create_invites(&self, invites: &[Invite], ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::create_invites(self, invites, ctx).await
    }

    async fn get_invite(&self, id: InviteId) -> Result<Option<Invite>> {
        CoordinodeBackend::get_invite(self, id).await
    }

    async fn get_invite_by_code(&self, code: &str) -> Result<Option<Invite>> {
        CoordinodeBackend::get_invite_by_code(self, code).await
    }

    async fn list_invites(
        &self,
        filter: &InviteFilter,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Invite>> {
        CoordinodeBackend::list_invites(self, filter, offset, limit).await
    }

    async fn count_invites(&self, filter: &InviteFilter) -> Result<u64> {
        CoordinodeBackend::count_invites(self, filter).await
    }

    async fn list_invite_redemptions(
        &self,
        id: InviteId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<sid_core::models::InviteRedemption>> {
        CoordinodeBackend::list_invite_redemptions(self, id, offset, limit).await
    }

    async fn try_use_invite(&self, id: InviteId, ctx: MutationContext) -> Result<Option<Invite>> {
        CoordinodeBackend::try_use_invite(self, id, ctx).await
    }

    async fn revoke_invite(&self, id: InviteId, ctx: MutationContext) -> Result<()> {
        CoordinodeBackend::revoke_invite(self, id, ctx).await
    }

    async fn get_registration_source(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<RegistrationSource>> {
        CoordinodeBackend::get_registration_source(self, profile_id).await
    }

    async fn count_registrations_by_source(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Vec<(RegistrationSourceType, u64)>> {
        CoordinodeBackend::count_registrations_by_source(self, since).await
    }

    async fn top_referrers(
        &self,
        since: DateTime<Utc>,
        limit: u64,
    ) -> Result<Vec<(ProfileId, u64)>> {
        CoordinodeBackend::top_referrers(self, since, limit).await
    }

    // === JOBS AND AUDIT RETENTION ===

    async fn try_job_lock(&self, _job: i64) -> Result<Option<JobLock>> {
        refused("job locks")
    }

    async fn ensure_audit_partition(&self, _month_start: chrono::NaiveDate) -> Result<bool> {
        // Audit records live in one store here: nothing to prepare.
        Ok(false)
    }

    async fn drop_expired_audit_records(
        &self,
        _cut_before: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> Result<u64> {
        refused("audit retention")
    }

    // === NOTIFICATION PREFERENCES ===

    async fn get_notification_preferences(
        &self,
        _profile_id: ProfileId,
    ) -> Result<Option<sid_core::models::notification::NotificationPreferences>> {
        refused("notification preferences")
    }

    async fn save_notification_preferences(
        &self,
        _preferences: &sid_core::models::notification::NotificationPreferences,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("notification preferences")
    }

    // === INTEGRITY ===

    async fn count_orphaned_sessions(&self) -> Result<u64> {
        refused("integrity counts")
    }

    async fn count_orphaned_credentials(&self) -> Result<u64> {
        refused("integrity counts")
    }

    async fn count_orphaned_role_assignments(&self) -> Result<u64> {
        refused("integrity counts")
    }

    // === ACCESS REQUESTS ===

    async fn create_access_request(
        &self,
        request: &AccessRequest,
        ctx: MutationContext,
    ) -> Result<()> {
        CoordinodeBackend::create_access_request(self, request, ctx).await
    }

    async fn get_access_request(&self, id: AccessRequestId) -> Result<Option<AccessRequest>> {
        CoordinodeBackend::get_access_request(self, id).await
    }

    async fn list_pending_access_requests(&self) -> Result<Vec<AccessRequest>> {
        CoordinodeBackend::list_pending_access_requests(self).await
    }

    async fn decide_access_request(
        &self,
        request: &AccessRequest,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::decide_access_request(self, request, ctx).await
    }

    async fn approve_access_request(
        &self,
        request: &AccessRequest,
        grant: &RoleAssignment,
        ctx: MutationContext,
    ) -> Result<bool> {
        CoordinodeBackend::approve_access_request(self, request, grant, ctx).await
    }

    // === PASSWORD RESET ===

    async fn create_reset_session(
        &self,
        _session: &sid_core::models::PasswordResetSession,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("password resets")
    }

    async fn get_reset_session(
        &self,
        _id: sid_core::models::ResetSessionId,
    ) -> Result<Option<sid_core::models::PasswordResetSession>> {
        refused("password resets")
    }

    async fn verify_reset_session(
        &self,
        _id: sid_core::models::ResetSessionId,
        _ctx: MutationContext,
    ) -> Result<bool> {
        refused("password resets")
    }

    async fn complete_password_reset(
        &self,
        _id: sid_core::models::ResetSessionId,
        _credential: &Credential,
        _history: Option<&HistoryCommit>,
        _end: &SessionEnd,
        _ctx: MutationContext,
    ) -> Result<Option<Vec<Session>>> {
        refused("password resets")
    }

    async fn count_active_reset_sessions(&self, _profile_id: ProfileId) -> Result<u32> {
        refused("password resets")
    }

    async fn delete_expired_reset_sessions(&self, _ctx: MutationContext) -> Result<u64> {
        refused("password resets")
    }

    // === EMAIL PROVIDER ===

    async fn get_email_provider_config(
        &self,
    ) -> Result<Option<sid_core::models::EmailProviderConfig>> {
        refused("the email provider configuration")
    }

    async fn upsert_email_provider_config(
        &self,
        _config: &sid_core::models::EmailProviderConfig,
        _ctx: MutationContext,
    ) -> Result<()> {
        refused("the email provider configuration")
    }
}
