// SPDX-License-Identifier: AGPL-3.0-only
//! Shared in-memory mock storage for authz tests.
//!
//! Implements all StorageBackend methods. RBAC/group operations are functional;
//! all others return `unimplemented!()` (they should never be called in authz tests).

use sid_core::Result;
use sid_core::models::*;
use std::sync::Mutex;

pub struct MockStorage {
    pub roles: Mutex<Vec<Role>>,
    pub groups: Mutex<Vec<Group>>,
    pub group_members: Mutex<Vec<GroupMember>>,
    pub role_assignments: Mutex<Vec<RoleAssignment>>,
    pub cedar_policies: Mutex<Vec<CedarPolicy>>,
}

impl MockStorage {
    pub fn new() -> Self {
        Self {
            roles: Mutex::new(Vec::new()),
            groups: Mutex::new(Vec::new()),
            group_members: Mutex::new(Vec::new()),
            role_assignments: Mutex::new(Vec::new()),
            cedar_policies: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl sid_plugin::WorkStore for MockStorage {
    async fn enqueue_work(&self, _: &NewWork, _: u64) -> Result<bool> {
        unimplemented!()
    }
    async fn claim_work(
        &self,
        _: &[WorkKind],
        _: &str,
        _: u32,
        _: std::time::Duration,
    ) -> Result<Vec<ClaimedWork>> {
        unimplemented!()
    }
    async fn complete_work(&self, _: WorkId, _: i64, _: Option<&str>) -> Result<bool> {
        unimplemented!()
    }
    async fn fail_work(&self, _: WorkId, _: i64, _: &WorkFailure) -> Result<bool> {
        unimplemented!()
    }
    async fn get_work(&self, _: WorkId) -> Result<Option<WorkRecord>> {
        unimplemented!()
    }
    async fn export_work(&self) -> Result<Vec<WorkSnapshot>> {
        unimplemented!()
    }
    async fn import_work(&self, _: &WorkSnapshot) -> Result<bool> {
        unimplemented!()
    }
}

#[async_trait::async_trait]
impl sid_plugin::StorageBackend for MockStorage {
    fn name(&self) -> &'static str {
        "mock"
    }

    // === PROFILE ===
    async fn get_profile(&self, _: ProfileId) -> Result<Option<Profile>> {
        unimplemented!()
    }
    async fn get_profile_by_username(&self, _: &str) -> Result<Option<Profile>> {
        unimplemented!()
    }
    async fn get_profile_by_email(&self, _: &str) -> Result<Option<Profile>> {
        unimplemented!()
    }
    async fn create_profile(&self, _: &Profile, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn update_profile(&self, _: &Profile, _audit: MutationContext) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_profile(&self, _: ProfileId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn register_profile(&self, _: &NewRegistration, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn replace_credential(&self, _: &Credential, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn enroll_credential(
        &self,
        _: &Credential,
        _: Option<&Credential>,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn write_directory_user(
        &self,
        _: &DirectoryUserWrite,
        _: MutationContext,
    ) -> Result<Vec<Session>> {
        unimplemented!()
    }
    async fn write_directory_group(
        &self,
        _: &DirectoryGroupWrite,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }

    // === PROFILE PHONE ===
    async fn get_profile_phone(&self, _: ProfilePhoneId) -> Result<Option<ProfilePhone>> {
        unimplemented!()
    }
    async fn list_profile_phones(&self, _: ProfileId) -> Result<Vec<ProfilePhone>> {
        unimplemented!()
    }
    async fn get_primary_profile_phone(&self, _: ProfileId) -> Result<Option<ProfilePhone>> {
        unimplemented!()
    }
    async fn create_profile_phone(&self, _: &ProfilePhone, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn update_profile_phone_settings(
        &self,
        _: ProfileId,
        _: ProfilePhoneId,
        _: &PhoneSettings,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn set_primary_profile_phone(
        &self,
        _: ProfileId,
        _: ProfilePhoneId,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_profile_phone(&self, _: ProfilePhoneId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }

    // === PROFILE EMAIL ===
    async fn get_profile_email(&self, _: ProfileEmailId) -> Result<Option<ProfileEmail>> {
        unimplemented!()
    }
    async fn list_profile_emails(&self, _: ProfileId) -> Result<Vec<ProfileEmail>> {
        unimplemented!()
    }
    async fn get_primary_profile_email(&self, _: ProfileId) -> Result<Option<ProfileEmail>> {
        unimplemented!()
    }
    async fn create_profile_email(&self, _: &ProfileEmail, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn update_profile_email_settings(
        &self,
        _: ProfileId,
        _: ProfileEmailId,
        _: &EmailSettings,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn set_primary_profile_email(
        &self,
        _: ProfileId,
        _: ProfileEmailId,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_profile_email(&self, _: ProfileEmailId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }

    // === PRINCIPAL ===
    async fn get_principal(&self, _: PrincipalId) -> Result<Option<Principal>> {
        unimplemented!()
    }
    async fn get_principals_by_profile(&self, _: ProfileId) -> Result<Vec<Principal>> {
        unimplemented!()
    }
    async fn get_profile_by_principal(&self, _: PrincipalType, _: &str) -> Result<Option<Profile>> {
        unimplemented!()
    }
    async fn save_principal(&self, _: &Principal, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }

    // === CREDENTIAL ===
    async fn get_credential(&self, _: CredentialId) -> Result<Option<Credential>> {
        unimplemented!()
    }
    async fn get_credentials_by_profile(
        &self,
        _: ProfileId,
        _: Option<CredentialType>,
    ) -> Result<Vec<Credential>> {
        unimplemented!()
    }
    async fn mark_credential_used(
        &self,
        _: sid_core::models::CredentialId,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn replace_credential_data(
        &self,
        _: CredentialId,
        _: &[u8],
        _: &[u8],
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn create_credential(&self, _: &Credential, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn set_credential_label(
        &self,
        _: CredentialId,
        _: Option<&str>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn change_password(
        &self,
        _: CredentialId,
        _: &[u8],
        _: &Credential,
        _: Option<&sid_core::models::HistoryCommit>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn get_password_history(
        &self,
        _: ProfileId,
    ) -> Result<sid_core::models::PasswordHistory> {
        unimplemented!()
    }
    async fn get_history_epochs(&self, _: ProfileId) -> Result<sid_core::models::HistoryEpochs> {
        unimplemented!()
    }
    async fn ensure_history_epoch(
        &self,
        _: &sid_core::models::NewHistoryEpoch,
        _: MutationContext,
    ) -> Result<sid_core::models::HistoryEpoch> {
        unimplemented!()
    }
    async fn rotate_history_epoch(
        &self,
        _: &sid_core::models::NewHistoryEpoch,
        _: sid_core::models::HistoryEpochId,
        _: MutationContext,
    ) -> Result<sid_core::models::HistoryEpoch> {
        unimplemented!()
    }
    async fn prepare_history_epochs(
        &self,
        _: &sid_core::models::HistoryPreparation,
        _: MutationContext,
    ) -> Result<Vec<sid_core::models::HistoryEpoch>> {
        unimplemented!()
    }
    async fn get_history_epoch_key(
        &self,
        _: sid_core::models::HistoryEpochId,
    ) -> Result<Option<sid_core::models::WrappedHistoryKey>> {
        unimplemented!()
    }
    async fn reseal_credential_data(
        &self,
        _: CredentialId,
        _: &[u8],
        _: &[u8],
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_credential(&self, _: CredentialId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn revoke_credential(
        &self,
        _: CredentialId,
        _: MutationContext,
    ) -> Result<CredentialRevocation> {
        unimplemented!()
    }
    async fn delete_credentials_by_profile(&self, _: ProfileId, _: MutationContext) -> Result<u64> {
        Ok(0)
    }
    async fn ensure_webauthn_user_handle(
        &self,
        _: ProfileId,
        _: &str,
        _: WebAuthnUserHandle,
        _: MutationContext,
    ) -> Result<WebAuthnUserHandle> {
        unimplemented!()
    }
    async fn get_profile_by_webauthn_user_handle(
        &self,
        _: &str,
        _: WebAuthnUserHandle,
    ) -> Result<Option<ProfileId>> {
        unimplemented!()
    }
    async fn revoke_consents_by_profile(&self, _: ProfileId, _: MutationContext) -> Result<u64> {
        Ok(0)
    }
    async fn create_consent(
        &self,
        _: &sid_core::models::consent::ConsentRecord,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn change_claim_grant(
        &self,
        _: sid_core::models::consent::ConsentId,
        _: &str,
        _: sid_core::models::consent::ClaimDecision,
        _: MutationContext,
    ) -> Result<sid_core::models::consent::ClaimGrantChange> {
        unimplemented!()
    }
    async fn get_consent(
        &self,
        _: sid_core::models::consent::ConsentId,
    ) -> Result<Option<sid_core::models::consent::ConsentRecord>> {
        Ok(None)
    }
    async fn get_consent_by_client(
        &self,
        _: ProfileId,
        _: &str,
    ) -> Result<Option<sid_core::models::consent::ConsentRecord>> {
        Ok(None)
    }
    async fn list_consents_by_profile(
        &self,
        _: ProfileId,
    ) -> Result<Vec<sid_core::models::consent::ConsentRecord>> {
        Ok(vec![])
    }
    async fn delete_consent(
        &self,
        _: sid_core::models::consent::ConsentId,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    // === ANOMALY EVENTS ===
    async fn save_anomaly_event(&self, _: &sid_core::models::AnomalyEventRecord) -> Result<()> {
        Ok(())
    }
    async fn list_anomaly_events(
        &self,
        _: Option<&str>,
        _: i32,
        _: i32,
    ) -> Result<Vec<sid_core::models::AnomalyEventRecord>> {
        Ok(vec![])
    }
    async fn record_ip_reputation_event(&self, _: &str, _: bool) -> Result<()> {
        Ok(())
    }
    async fn get_ip_reputation_score(&self, _: &str) -> Result<Option<f32>> {
        Ok(None)
    }
    async fn list_suspicious_ips(&self, _: f32, _: i64) -> Result<Vec<(String, f32)>> {
        Ok(vec![])
    }
    async fn decay_ip_reputation(&self, _: std::time::Duration) -> Result<u64> {
        Ok(0)
    }
    async fn add_ip_allowlist_entry(&self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
    async fn remove_ip_allowlist_entry(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn list_ip_allowlist_entries(
        &self,
    ) -> Result<Vec<(String, String, chrono::DateTime<chrono::Utc>)>> {
        Ok(vec![])
    }

    // === SESSION ===
    async fn create_session(&self, _: &Session, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn record_session_authentication(
        &self,
        _: SessionId,
        _: &sid_core::models::SessionAuthentication,
        _: &sid_core::models::SessionAuthentication,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn create_session_atomic(
        &self,
        _: &Session,
        _: u32,
        _: MutationContext,
    ) -> Result<Vec<SessionId>> {
        unimplemented!()
    }
    async fn get_session(&self, _: SessionId) -> Result<Option<Session>> {
        unimplemented!()
    }
    async fn get_session_by_browser_secret(
        &self,
        _: &sid_core::models::BrowserSecretHash,
    ) -> Result<Option<Session>> {
        unimplemented!()
    }
    async fn touch_session(&self, _: SessionId, _: chrono::DateTime<chrono::Utc>) -> Result<()> {
        unimplemented!()
    }
    async fn delete_session(
        &self,
        _: SessionId,
        _: &sid_core::models::SessionEnd,
        _audit: MutationContext,
    ) -> Result<Vec<SessionId>> {
        unimplemented!()
    }
    async fn delete_sessions_by_profile(
        &self,
        _: ProfileId,
        _: &sid_core::models::SessionEnd,
        _audit: MutationContext,
    ) -> Result<Vec<Session>> {
        unimplemented!()
    }

    // === PROJECT ===
    async fn get_project(&self, _: ProjectId) -> Result<Option<Project>> {
        unimplemented!()
    }
    async fn create_project(&self, _: &Project, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn update_project(
        &self,
        _: ProjectId,
        _: &ProjectChange,
        _audit: MutationContext,
    ) -> Result<Option<Project>> {
        unimplemented!()
    }
    async fn delete_project(&self, _: ProjectId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn list_projects(&self, _: u64, _: u64) -> Result<Vec<Project>> {
        unimplemented!()
    }
    async fn count_projects(&self) -> Result<u64> {
        unimplemented!()
    }
    async fn list_oauth2_clients_by_project(
        &self,
        _: ProjectId,
        _: u64,
        _: u64,
    ) -> Result<Vec<OAuth2Client>> {
        unimplemented!()
    }
    async fn ensure_system_project(&self, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }

    // === OAUTH2 CLIENT ===
    async fn get_oauth2_client(&self, _: &str) -> Result<Option<OAuth2Client>> {
        unimplemented!()
    }
    async fn update_oauth2_client(
        &self,
        _: &OAuth2Client,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn create_oauth2_client(&self, _: &OAuth2Client, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn delete_oauth2_client(&self, _: &str, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn list_oauth2_clients(&self, _: u64, _: u64) -> Result<Vec<OAuth2Client>> {
        unimplemented!()
    }

    // === ADMIN QUERIES ===
    async fn list_profiles(&self, _: u64, _: u64) -> Result<Vec<Profile>> {
        unimplemented!()
    }
    async fn count_profiles(&self) -> Result<u64> {
        unimplemented!()
    }
    async fn list_profiles_with_status(&self, _: ProfileStatus) -> Result<Vec<Profile>> {
        Ok(vec![])
    }
    async fn list_profiles_with_pending_migration(&self) -> Result<Vec<Profile>> {
        Ok(vec![])
    }
    async fn end_legacy_migration(&self, _: &Profile, _: MutationContext) -> Result<bool> {
        unimplemented!()
    }
    async fn list_sessions_by_profile(&self, _: ProfileId) -> Result<Vec<Session>> {
        unimplemented!()
    }
    async fn get_most_recent_session_ip(
        &self,
        _: ProfileId,
    ) -> Result<Option<(String, chrono::DateTime<chrono::Utc>)>> {
        Ok(None)
    }
    async fn has_recent_session_from_ip(
        &self,
        _: ProfileId,
        _: &str,
        _: std::time::Duration,
    ) -> Result<bool> {
        Ok(false)
    }
    async fn has_recent_session_from_device(
        &self,
        _: ProfileId,
        _: uuid::Uuid,
        _: std::time::Duration,
    ) -> Result<bool> {
        Ok(false)
    }
    async fn record_login_location(
        &self,
        _: ProfileId,
        _: &str,
        _: f64,
        _: f64,
        _: u32,
    ) -> Result<()> {
        Ok(())
    }
    async fn get_designated_countries(&self, _: ProfileId) -> Result<Vec<String>> {
        Ok(vec![])
    }

    // === REFRESH TOKEN ===
    async fn create_refresh_token(&self, _: &RefreshToken, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn get_refresh_token_by_hash(&self, _: &[u8]) -> Result<Option<RefreshToken>> {
        unimplemented!()
    }
    async fn revoke_refresh_tokens_by_session(
        &self,
        _: SessionId,
        _audit: MutationContext,
    ) -> Result<u64> {
        unimplemented!()
    }
    async fn revoke_refresh_tokens_by_family(
        &self,
        _: uuid::Uuid,
        _audit: MutationContext,
    ) -> Result<u64> {
        unimplemented!()
    }
    async fn rotate_refresh_token(
        &self,
        _: uuid::Uuid,
        _: &RefreshToken,
        _: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    // === AUTHORIZATION CODE ===
    async fn create_auth_code(&self, _: &AuthorizationCode, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn get_auth_code_by_hash(&self, _: &[u8]) -> Result<Option<AuthorizationCode>> {
        unimplemented!()
    }
    async fn redeem_auth_code(
        &self,
        _: &[u8],
        _: &Session,
        _: &RefreshToken,
        _audit: MutationContext,
    ) -> Result<sid_core::models::AuthCodeRedemption> {
        unimplemented!()
    }

    // === INITIAL ACCESS TOKEN OPERATIONS (DCR) ===

    async fn create_initial_access_token(
        &self,
        _token: &InitialAccessToken,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }

    async fn list_key_versions(&self) -> Result<Vec<sid_plugin::KeyVersionParams>> {
        unimplemented!()
    }
    async fn insert_key_version(
        &self,
        _: &sid_plugin::KeyVersionParams,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn get_instance_secret(
        &self,
        _: sid_core::models::InstanceSecret,
    ) -> Result<Option<Vec<u8>>> {
        unimplemented!()
    }
    async fn insert_instance_secret(
        &self,
        _: sid_core::models::InstanceSecret,
        _: &[u8],
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn instance_organization(&self) -> Result<Option<Organization>> {
        unimplemented!()
    }
    async fn insert_instance_organization(
        &self,
        _: &Organization,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn assign_unowned_clients(&self, _: OrgId, _audit: MutationContext) -> Result<u64> {
        unimplemented!()
    }
    async fn oidc_issuer_for(
        &self,
        _: sid_core::models::IssuerAuthority,
        _: OrgId,
    ) -> Result<Option<sid_core::models::OidcIssuer>> {
        unimplemented!()
    }
    async fn oidc_issuer_by_handle(
        &self,
        _: &sid_core::models::IssuerHandle,
    ) -> Result<Option<sid_core::models::OidcIssuer>> {
        unimplemented!()
    }
    async fn insert_oidc_issuer(
        &self,
        _: &sid_core::models::OidcIssuer,
        _: &sid_core::models::IssuerSigningKey,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn oidc_issuer_signing_keys(
        &self,
        _: sid_core::models::IssuerId,
    ) -> Result<Vec<sid_core::models::IssuerSigningKey>> {
        unimplemented!()
    }
    async fn admin_exists(&self) -> Result<bool> {
        unimplemented!()
    }
    async fn claim_first_admin(
        &self,
        _: &[u8],
        _: &sid_core::models::Profile,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn service_binding(
        &self,
        _: ProfileId,
        _: &sid_core::models::BindingScope,
        _: MutationContext,
    ) -> Result<sid_core::models::ServiceBinding> {
        unimplemented!()
    }
    async fn find_service_binding(
        &self,
        _: ProfileId,
        _: &sid_core::models::BindingScope,
    ) -> Result<Option<sid_core::models::ServiceBinding>> {
        unimplemented!()
    }
    async fn list_service_bindings(
        &self,
        _: ProfileId,
    ) -> Result<Vec<sid_core::models::ServiceBinding>> {
        unimplemented!()
    }
    async fn import_service_binding(
        &self,
        _: &sid_core::models::ServiceBinding,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn list_credentials_by_type(
        &self,
        _: CredentialType,
        _: Option<CredentialId>,
        _: u32,
    ) -> Result<Vec<Credential>> {
        unimplemented!()
    }
    async fn register_dynamic_client(
        &self,
        _: &sid_core::models::Application,
        _: &OAuth2Client,
        _: InitialAccessTokenId,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn oauth2_client_of_application(
        &self,
        _: sid_core::models::ApplicationId,
    ) -> Result<Option<OAuth2Client>> {
        unimplemented!()
    }
    async fn create_application(
        &self,
        _: &sid_core::models::Application,
        _: Option<&OAuth2Client>,
        _: Option<&sid_core::models::ProtectedResource>,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn get_application(
        &self,
        _: sid_core::models::ApplicationId,
    ) -> Result<Option<sid_core::models::Application>> {
        unimplemented!()
    }
    async fn system_application(
        &self,
        _: sid_core::models::SystemIntegration,
    ) -> Result<Option<sid_core::models::Application>> {
        unimplemented!()
    }
    async fn list_applications_by_project(
        &self,
        _: ProjectId,
        _: u64,
        _: u64,
    ) -> Result<Vec<sid_core::models::Application>> {
        unimplemented!()
    }
    async fn update_application(
        &self,
        _: &sid_core::models::Application,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_application(
        &self,
        _: sid_core::models::ApplicationId,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn create_protected_resource(
        &self,
        _: &sid_core::models::ProtectedResource,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn get_protected_resource(
        &self,
        _: sid_core::models::ResourceId,
    ) -> Result<Option<sid_core::models::ProtectedResource>> {
        unimplemented!()
    }
    async fn protected_resource_of_application(
        &self,
        _: sid_core::models::ApplicationId,
    ) -> Result<Option<sid_core::models::ProtectedResource>> {
        unimplemented!()
    }
    async fn list_protected_resources(
        &self,
        _: u64,
        _: u64,
    ) -> Result<Vec<sid_core::models::ProtectedResource>> {
        unimplemented!()
    }
    async fn import_protected_resource(
        &self,
        _: &sid_core::models::ProtectedResource,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn protected_resource_by_indicator(
        &self,
        _: sid_core::models::IssuerId,
        _: &sid_core::models::ResourceIndicator,
    ) -> Result<Option<sid_core::models::ProtectedResource>> {
        unimplemented!()
    }
    async fn update_protected_resource(
        &self,
        _: &sid_core::models::ProtectedResource,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn set_resource_access(
        &self,
        _: &sid_core::models::ResourceAccess,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn remove_resource_access(
        &self,
        _: &str,
        _: sid_core::models::ResourceId,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn resource_access(
        &self,
        _: &str,
        _: sid_core::models::ResourceId,
    ) -> Result<Option<sid_core::models::ResourceAccess>> {
        unimplemented!()
    }
    async fn list_resource_access_by_client(
        &self,
        _: &str,
    ) -> Result<Vec<sid_core::models::ResourceAccess>> {
        unimplemented!()
    }
    async fn list_resource_access_by_resource(
        &self,
        _: sid_core::models::ResourceId,
    ) -> Result<Vec<sid_core::models::ResourceAccess>> {
        unimplemented!()
    }
    async fn get_initial_access_token(
        &self,
        _id: InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken>> {
        unimplemented!()
    }

    async fn get_initial_access_token_by_hash(
        &self,
        _token_hash: &[u8],
    ) -> Result<Option<InitialAccessToken>> {
        unimplemented!()
    }

    async fn list_initial_access_tokens_by_project(
        &self,
        _project_id: ProjectId,
    ) -> Result<Vec<InitialAccessToken>> {
        unimplemented!()
    }

    async fn revoke_initial_access_token(
        &self,
        _id: InitialAccessTokenId,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    // === ROLE OPERATIONS (functional) ===
    async fn get_role(&self, id: RoleId) -> Result<Option<Role>> {
        let roles = self.roles.lock().unwrap();
        Ok(roles.iter().find(|r| r.id == id).cloned())
    }
    async fn get_role_by_name(&self, project_id: ProjectId, name: &str) -> Result<Option<Role>> {
        let roles = self.roles.lock().unwrap();
        Ok(roles
            .iter()
            .find(|r| r.project_id == project_id && r.name == name)
            .cloned())
    }
    async fn create_role(&self, role: &Role, _audit: MutationContext) -> Result<()> {
        let mut roles = self.roles.lock().unwrap();
        if roles.iter().any(|r| {
            r.id == role.id
                || (r.project_id == role.project_id && (r.key == role.key || r.name == role.name))
        }) {
            return Err(sid_core::Error::Conflict("role already exists".into()));
        }
        roles.push(role.clone());
        Ok(())
    }
    async fn update_role(&self, role: &Role, _audit: MutationContext) -> Result<bool> {
        let mut roles = self.roles.lock().unwrap();
        let Some(stored) = roles
            .iter_mut()
            .find(|r| r.id == role.id && r.revision == role.revision)
        else {
            return Ok(false);
        };
        stored.name.clone_from(&role.name);
        stored.description.clone_from(&role.description);
        stored.group.clone_from(&role.group);
        stored.permissions.clone_from(&role.permissions);
        stored.updated_at = role.updated_at;
        stored.revision += 1;
        Ok(true)
    }
    async fn delete_role(&self, id: RoleId, _audit: MutationContext) -> Result<()> {
        let mut roles = self.roles.lock().unwrap();
        roles.retain(|r| r.id != id);
        Ok(())
    }
    async fn list_roles(&self, project_id: ProjectId) -> Result<Vec<Role>> {
        let roles = self.roles.lock().unwrap();
        Ok(roles
            .iter()
            .filter(|r| r.project_id == project_id)
            .cloned()
            .collect())
    }

    // === GROUP OPERATIONS (functional) ===
    async fn get_group(&self, id: GroupId) -> Result<Option<Group>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.id == id).cloned())
    }
    async fn create_group(&self, group: &Group, _audit: MutationContext) -> Result<()> {
        let mut groups = self.groups.lock().unwrap();
        if groups
            .iter()
            .any(|g| g.id == group.id || (g.project_id == group.project_id && g.name == group.name))
        {
            return Err(sid_core::Error::Conflict("group already exists".into()));
        }
        groups.push(group.clone());
        Ok(())
    }
    async fn set_group_description(
        &self,
        id: GroupId,
        description: Option<&str>,
        _audit: MutationContext,
    ) -> Result<bool> {
        let mut groups = self.groups.lock().unwrap();
        let Some(group) = groups.iter_mut().find(|g| g.id == id) else {
            return Ok(false);
        };
        group.description = description.map(str::to_owned);
        group.updated_at = chrono::Utc::now();
        Ok(true)
    }
    async fn delete_group(&self, id: GroupId, _audit: MutationContext) -> Result<()> {
        let mut groups = self.groups.lock().unwrap();
        groups.retain(|g| g.id != id);
        Ok(())
    }
    async fn list_groups(&self, project_id: ProjectId) -> Result<Vec<Group>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.project_id == project_id)
            .cloned()
            .collect())
    }
    async fn add_to_group(&self, member: &GroupMember, _audit: MutationContext) -> Result<()> {
        let mut members = self.group_members.lock().unwrap();
        members.push(member.clone());
        Ok(())
    }
    async fn remove_from_group(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
        _audit: MutationContext,
    ) -> Result<()> {
        let mut members = self.group_members.lock().unwrap();
        members.retain(|m| !(m.group_id == group_id && m.profile_id == profile_id));
        Ok(())
    }
    async fn list_group_members(&self, group_id: GroupId) -> Result<Vec<GroupMember>> {
        let members = self.group_members.lock().unwrap();
        Ok(members
            .iter()
            .filter(|m| m.group_id == group_id)
            .cloned()
            .collect())
    }
    async fn list_groups_for_profile(&self, profile_id: ProfileId) -> Result<Vec<Group>> {
        let members = self.group_members.lock().unwrap();
        let group_ids: Vec<GroupId> = members
            .iter()
            .filter(|m| m.profile_id == profile_id)
            .map(|m| m.group_id)
            .collect();
        drop(members);
        let groups = self.groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| group_ids.contains(&g.id))
            .cloned()
            .collect())
    }

    // === ROLE ASSIGNMENT OPERATIONS (functional) ===
    async fn create_role_assignment(
        &self,
        assignment: &RoleAssignment,
        _audit: MutationContext,
    ) -> Result<()> {
        let mut assignments = self.role_assignments.lock().unwrap();
        if assignments.iter().any(|a| a.id == assignment.id) {
            return Err(sid_core::Error::Conflict(
                "role assignment already exists".into(),
            ));
        }
        assignments.push(assignment.clone());
        Ok(())
    }
    async fn get_role_assignment(&self, id: RoleAssignmentId) -> Result<Option<RoleAssignment>> {
        Ok(self
            .role_assignments
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }
    async fn create_role_assignment_fenced(
        &self,
        _: &RoleAssignment,
        _: &sid_core::models::AssignmentFence,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!("fenced writes are exercised against the storage engines")
    }
    async fn delete_role_assignment_fenced(
        &self,
        _: RoleAssignmentId,
        _: &sid_core::models::AssignmentFence,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!("fenced writes are exercised against the storage engines")
    }
    async fn update_role_fenced(
        &self,
        _: &Role,
        _: &sid_core::models::RoleEditFence,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!("fenced writes are exercised against the storage engines")
    }
    async fn delete_role_assignment(
        &self,
        id: RoleAssignmentId,
        _audit: MutationContext,
    ) -> Result<()> {
        let mut assignments = self.role_assignments.lock().unwrap();
        assignments.retain(|a| a.id != id);
        Ok(())
    }
    async fn list_role_assignments_for_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<RoleAssignment>> {
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(|a| {
                matches!(&a.principal, RoleAssignmentPrincipal::Profile(pid) if *pid == profile_id)
            })
            .cloned()
            .collect())
    }
    async fn list_role_assignments_for_group(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<RoleAssignment>> {
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(
                |a| matches!(&a.principal, RoleAssignmentPrincipal::Group(gid) if *gid == group_id),
            )
            .cloned()
            .collect())
    }
    async fn list_role_assignments_for_machine_user(
        &self,
        machine_user_id: MachineUserId,
    ) -> Result<Vec<RoleAssignment>> {
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(|a| {
                matches!(&a.principal, RoleAssignmentPrincipal::MachineUser(mid) if *mid == machine_user_id)
            })
            .cloned()
            .collect())
    }

    async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<RoleAssignment>> {
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(|a| {
                matches!(&a.principal, RoleAssignmentPrincipal::OAuthClient(c) if c == client_id)
            })
            .cloned()
            .collect())
    }

    async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector: sid_core::models::ProvisioningConnectorId,
    ) -> Result<Vec<RoleAssignment>> {
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(|a| {
                matches!(&a.principal, RoleAssignmentPrincipal::ProvisioningConnector(c) if *c == connector)
            })
            .cloned()
            .collect())
    }

    async fn list_role_assignments_for_role(&self, role_id: RoleId) -> Result<Vec<RoleAssignment>> {
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(|a| a.role_id == role_id)
            .cloned()
            .collect())
    }
    async fn list_expiring_role_assignments(
        &self,
        within_hours: i64,
    ) -> Result<Vec<RoleAssignment>> {
        let deadline = chrono::Utc::now() + chrono::Duration::hours(within_hours);
        let assignments = self.role_assignments.lock().unwrap();
        Ok(assignments
            .iter()
            .filter(|a| a.expires_at.is_some_and(|exp| exp <= deadline))
            .cloned()
            .collect())
    }
    async fn cleanup_expired_role_assignments(
        &self,
        _audit: MutationContext,
    ) -> Result<Vec<RoleAssignment>> {
        let now = chrono::Utc::now();
        let mut assignments = self.role_assignments.lock().unwrap();
        let (expired, kept) = assignments
            .drain(..)
            .partition(|a| a.expires_at.is_some_and(|exp| exp <= now));
        *assignments = kept;
        Ok(expired)
    }
    async fn list_sod_rules(&self) -> Result<Vec<sid_core::models::SodConflictRule>> {
        Ok(vec![])
    }

    // === CEDAR POLICY ===
    async fn get_cedar_policy(&self, id: CedarPolicyId) -> Result<Option<CedarPolicy>> {
        Ok(self
            .cedar_policies
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.id == id)
            .cloned())
    }
    async fn create_cedar_policy(
        &self,
        policy: &CedarPolicy,
        _audit: MutationContext,
    ) -> Result<()> {
        let mut policies = self.cedar_policies.lock().unwrap();
        if policies.iter().any(|p| {
            p.id == policy.id || (p.project_id == policy.project_id && p.name == policy.name)
        }) {
            return Err(sid_core::Error::Conflict("policy already exists".into()));
        }
        policies.push(policy.clone());
        Ok(())
    }
    async fn update_cedar_policy(
        &self,
        policy: &CedarPolicy,
        _audit: MutationContext,
    ) -> Result<bool> {
        let mut policies = self.cedar_policies.lock().unwrap();
        let Some(stored) = policies
            .iter_mut()
            .find(|p| p.id == policy.id && p.revision == policy.revision)
        else {
            return Ok(false);
        };
        *stored = CedarPolicy {
            revision: policy.revision + 1,
            ..policy.clone()
        };
        Ok(true)
    }
    async fn delete_cedar_policy(&self, id: CedarPolicyId, _audit: MutationContext) -> Result<()> {
        self.cedar_policies.lock().unwrap().retain(|p| p.id != id);
        Ok(())
    }
    async fn list_cedar_policies(&self, project_id: ProjectId) -> Result<Vec<CedarPolicy>> {
        Ok(self
            .cedar_policies
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.project_id == project_id)
            .cloned()
            .collect())
    }

    // === PROFILE METADATA ===
    async fn get_profile_metadata(&self, _: ProfileId, _: &str) -> Result<Option<ProfileMetadata>> {
        unimplemented!()
    }
    async fn set_profile_metadata(
        &self,
        _: &ProfileMetadata,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn delete_profile_metadata(
        &self,
        _: ProfileId,
        _: &str,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn list_profile_metadata(&self, _: ProfileId) -> Result<Vec<ProfileMetadata>> {
        unimplemented!()
    }

    // === PROFILE GRANT ===
    async fn get_profile_grant(&self, _: ProfileGrantId) -> Result<Option<ProfileGrant>> {
        unimplemented!()
    }
    async fn create_profile_grant(&self, _: &ProfileGrant, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn delete_profile_grant(&self, _: ProfileGrantId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn list_profile_grants_for_profile(&self, _: ProfileId) -> Result<Vec<ProfileGrant>> {
        unimplemented!()
    }
    async fn list_profile_grants_for_project(&self, _: ProjectId) -> Result<Vec<ProfileGrant>> {
        unimplemented!()
    }

    // === DEVICE MANAGEMENT ===
    async fn create_device(&self, _: &Device, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn rename_device(
        &self,
        _: DeviceId,
        _: Option<&str>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn set_device_trust(
        &self,
        _: DeviceId,
        _: bool,
        _: usize,
        _: MutationContext,
    ) -> Result<DeviceTrustChange> {
        unimplemented!()
    }
    async fn get_device(&self, _: DeviceId) -> Result<Option<Device>> {
        unimplemented!()
    }
    async fn list_devices_by_profile(&self, _: ProfileId) -> Result<Vec<Device>> {
        unimplemented!()
    }
    async fn delete_device(&self, _: DeviceId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn get_device_by_fingerprint(&self, _: ProfileId, _: &str) -> Result<Option<Device>> {
        unimplemented!()
    }

    // === DEVICE ATTESTATION ===
    async fn create_device_attestation(
        &self,
        _: &sid_core::models::DeviceAttestation,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn rotate_device_attestation(
        &self,
        _: DeviceId,
        _: &[u8],
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn revoke_device_attestation(&self, _: DeviceId, _: MutationContext) -> Result<bool> {
        unimplemented!()
    }
    async fn get_device_attestation(
        &self,
        _: sid_core::models::DeviceAttestationId,
    ) -> Result<Option<sid_core::models::DeviceAttestation>> {
        unimplemented!()
    }
    async fn get_device_attestation_by_device_id(
        &self,
        _: DeviceId,
    ) -> Result<Option<sid_core::models::DeviceAttestation>> {
        unimplemented!()
    }
    async fn list_device_attestations_by_profile(
        &self,
        _: ProfileId,
    ) -> Result<Vec<sid_core::models::DeviceAttestation>> {
        unimplemented!()
    }
    async fn delete_device_attestation(&self, _: DeviceId, _: MutationContext) -> Result<()> {
        unimplemented!()
    }

    // === DEVICE AUTHORIZATION ===
    async fn create_device_auth_code(
        &self,
        _: &DeviceAuthorizationCode,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn get_device_auth_by_device_code_hash(
        &self,
        _: &[u8],
    ) -> Result<Option<DeviceAuthorizationCode>> {
        unimplemented!()
    }
    async fn get_device_auth_by_user_code(
        &self,
        _: &str,
    ) -> Result<Option<DeviceAuthorizationCode>> {
        unimplemented!()
    }
    async fn decide_device_auth(
        &self,
        _: DeviceAuthCodeId,
        _: sid_core::models::DeviceAuthDecision,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn record_device_poll(
        &self,
        _: DeviceAuthCodeId,
        _audit: MutationContext,
    ) -> Result<sid_core::models::DevicePoll> {
        unimplemented!()
    }
    async fn redeem_device_code(
        &self,
        _: &[u8],
        _: &Session,
        _: &RefreshToken,
        _audit: MutationContext,
    ) -> Result<sid_core::models::DeviceCodeRedemption> {
        unimplemented!()
    }
    async fn cleanup_expired_device_auth_codes(&self, _audit: MutationContext) -> Result<u64> {
        unimplemented!()
    }

    // === UPSTREAM PROVIDER ===
    async fn get_upstream_provider(
        &self,
        _: UpstreamProviderId,
    ) -> Result<Option<UpstreamProvider>> {
        unimplemented!()
    }
    async fn create_upstream_provider(
        &self,
        _: &UpstreamProvider,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn update_upstream_provider(
        &self,
        _: &UpstreamProvider,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_upstream_provider(
        &self,
        _: UpstreamProviderId,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn list_enabled_upstream_providers(&self) -> Result<Vec<UpstreamProvider>> {
        unimplemented!()
    }

    // === UPSTREAM IDENTITY ===
    async fn get_upstream_identity_by_provider_subject(
        &self,
        _: UpstreamProviderId,
        _: &str,
    ) -> Result<Option<UpstreamIdentity>> {
        unimplemented!()
    }
    async fn create_upstream_identity(
        &self,
        _: &UpstreamIdentity,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn record_upstream_login(
        &self,
        _: UpstreamIdentityId,
        _: &UpstreamLogin,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn list_upstream_identities_by_profile(
        &self,
        _: ProfileId,
    ) -> Result<Vec<UpstreamIdentity>> {
        unimplemented!()
    }
    async fn delete_upstream_identity(
        &self,
        _: UpstreamIdentityId,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }

    // === PERSONAL ACCESS TOKEN ===
    async fn get_pat(&self, _: PatId) -> Result<Option<PersonalAccessToken>> {
        unimplemented!()
    }
    async fn get_pat_by_token_hash(&self, _: &str) -> Result<Option<PersonalAccessToken>> {
        unimplemented!()
    }
    async fn create_pat(
        &self,
        _: &PersonalAccessToken,
        _: Option<u64>,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn record_pat_use(
        &self,
        _: PatId,
        _: Option<&str>,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn revoke_pat(&self, _: PatId, _: &str, _audit: MutationContext) -> Result<bool> {
        unimplemented!()
    }
    async fn list_pats_by_profile(&self, _: ProfileId) -> Result<Vec<PersonalAccessToken>> {
        unimplemented!()
    }
    async fn list_all_pats(&self) -> Result<Vec<PersonalAccessToken>> {
        unimplemented!()
    }
    async fn count_active_pats_by_profile(&self, _: ProfileId) -> Result<u64> {
        unimplemented!()
    }
    async fn revoke_active_pats_by_profile(
        &self,
        _: ProfileId,
        _: &str,
        _audit: MutationContext,
    ) -> Result<u64> {
        unimplemented!()
    }
    async fn revoke_unused_pats(&self, _: u32, _audit: MutationContext) -> Result<u64> {
        unimplemented!()
    }

    // === MACHINE USER ===
    async fn get_machine_user(&self, _: MachineUserId) -> Result<Option<MachineUser>> {
        unimplemented!()
    }
    async fn get_machine_user_by_client_id(&self, _: &str) -> Result<Option<MachineUser>> {
        unimplemented!()
    }
    async fn create_machine_user(&self, _: &MachineUser, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn update_machine_user(&self, _: &MachineUser, _audit: MutationContext) -> Result<bool> {
        unimplemented!()
    }
    async fn transition_machine_user(
        &self,
        _: MachineUserId,
        _: sid_core::models::machine_user::MachineUserStatus,
        _: sid_core::models::machine_user::MachineUserStatus,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn delete_machine_user(&self, _: MachineUserId, _audit: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn list_machine_users_by_project(&self, _: ProjectId) -> Result<Vec<MachineUser>> {
        unimplemented!()
    }

    // === MACHINE USER CREDENTIAL ===
    async fn get_machine_credential_by_kid(
        &self,
        _: &str,
    ) -> Result<Option<MachineUserCredential>> {
        unimplemented!()
    }
    async fn add_machine_credential(
        &self,
        _: &MachineUserCredential,
        _: Option<u64>,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn rotate_machine_credential(
        &self,
        _: MachineUserId,
        _: &str,
        _: &MachineUserCredential,
        _: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn revoke_machine_credential(
        &self,
        _: MachineUserId,
        _: &str,
        _audit: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn revoke_active_machine_credentials_by_user(
        &self,
        _: MachineUserId,
        _audit: MutationContext,
    ) -> Result<u64> {
        unimplemented!()
    }
    async fn list_machine_credentials_by_user(
        &self,
        _: MachineUserId,
    ) -> Result<Vec<MachineUserCredential>> {
        unimplemented!()
    }

    async fn get_provisioning_connector(
        &self,
        _: sid_core::models::ProvisioningConnectorId,
    ) -> Result<Option<sid_core::models::ProvisioningConnector>> {
        unimplemented!()
    }

    async fn get_provisioning_connector_by_client_id(
        &self,
        _: &str,
    ) -> Result<Option<sid_core::models::ProvisioningConnector>> {
        unimplemented!()
    }

    async fn list_provisioning_connectors(
        &self,
        _: sid_core::models::OrgId,
    ) -> Result<Vec<sid_core::models::ProvisioningConnector>> {
        unimplemented!()
    }

    async fn create_provisioning_connector(
        &self,
        _: &sid_core::models::ProvisioningConnector,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }

    async fn rename_provisioning_connector(
        &self,
        _: sid_core::models::ProvisioningConnectorId,
        _: i64,
        _: &str,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    async fn transition_provisioning_connector(
        &self,
        _: sid_core::models::ProvisioningConnectorId,
        _: sid_core::models::ConnectorState,
        _: sid_core::models::ConnectorState,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    async fn add_provisioning_credential(
        &self,
        _: &sid_core::models::ProvisioningCredential,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    async fn rotate_provisioning_credential(
        &self,
        _: sid_core::models::ProvisioningConnectorId,
        _: sid_core::models::ProvisioningCredentialId,
        _: &sid_core::models::ProvisioningCredential,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    async fn revoke_provisioning_credential(
        &self,
        _: sid_core::models::ProvisioningConnectorId,
        _: sid_core::models::ProvisioningCredentialId,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }

    async fn list_provisioning_credentials(
        &self,
        _: sid_core::models::ProvisioningConnectorId,
    ) -> Result<Vec<sid_core::models::ProvisioningCredential>> {
        unimplemented!()
    }

    async fn find_provisioning_credential(
        &self,
        _: &str,
    ) -> Result<
        Option<(
            sid_core::models::ProvisioningCredential,
            sid_core::models::ProvisioningConnector,
        )>,
    > {
        unimplemented!()
    }
    async fn list_expiring_machine_credentials(
        &self,
        _: u32,
    ) -> Result<Vec<MachineUserCredential>> {
        Ok(vec![])
    }

    // === IMPERSONATION GRANT ===
    async fn save_impersonation_grant(
        &self,
        _: &ImpersonationGrant,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn delete_impersonation_grant(
        &self,
        _: MachineUserId,
        _: &str,
        _: &str,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn list_impersonation_grants(&self, _: MachineUserId) -> Result<Vec<ImpersonationGrant>> {
        unimplemented!()
    }

    // === PRINCIPAL QUARANTINE ===
    async fn quarantine_principal(
        &self,
        _: &str,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn is_principal_quarantined(&self, _: &str) -> Result<bool> {
        unimplemented!()
    }
    async fn cleanup_expired_quarantine(&self, _audit: MutationContext) -> Result<u64> {
        unimplemented!()
    }

    // === CLOSURE REQUEST ===
    async fn create_closure_request(
        &self,
        _: &ClosureRequest,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn request_profile_closure(
        &self,
        _: &Profile,
        _: &ClosureRequest,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn cancel_profile_closure(&self, _: &Profile, _: MutationContext) -> Result<bool> {
        unimplemented!()
    }
    async fn get_closure_request(&self, _: ProfileId) -> Result<Option<ClosureRequest>> {
        unimplemented!()
    }

    // === DATA EXPORT ===
    async fn create_export_job(&self, _: &ExportJob, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn acknowledge_export_job(
        &self,
        _: uuid::Uuid,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        Ok(false)
    }
    async fn expire_export_job(
        &self,
        _: uuid::Uuid,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        Ok(false)
    }
    async fn get_export_job(&self, _: ProfileId) -> Result<Option<ExportJob>> {
        Ok(None)
    }
    async fn get_export_job_by_id(&self, _: uuid::Uuid) -> Result<Option<ExportJob>> {
        Ok(None)
    }
    async fn create_magic_link_session(
        &self,
        _: &MagicLinkSession,
        _audit: MutationContext,
    ) -> Result<()> {
        unimplemented!("magic links are not used by the authz unit tests")
    }
    async fn get_magic_link_session(&self, _: uuid::Uuid) -> Result<Option<MagicLinkSession>> {
        Ok(None)
    }
    async fn consume_magic_link_session(
        &self,
        _: uuid::Uuid,
        _audit: MutationContext,
    ) -> Result<()> {
        Ok(())
    }
    async fn try_consume_magic_link_session(
        &self,
        _: uuid::Uuid,
        _audit: MutationContext,
    ) -> Result<Option<MagicLinkSession>> {
        Ok(None)
    }
    async fn delete_expired_magic_link_sessions(&self, _audit: MutationContext) -> Result<u64> {
        Ok(0)
    }
    async fn count_active_magic_links_for_email(&self, _: &str) -> Result<u32> {
        Ok(0)
    }
    async fn create_scim_outbound_target(
        &self,
        _: &ScimOutboundTarget,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn get_scim_outbound_target(
        &self,
        _: ScimOutboundTargetId,
    ) -> Result<Option<ScimOutboundTarget>> {
        unimplemented!()
    }
    async fn list_scim_outbound_targets(&self, _: ProjectId) -> Result<Vec<ScimOutboundTarget>> {
        unimplemented!()
    }
    async fn delete_scim_outbound_target(
        &self,
        _: ScimOutboundTargetId,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn create_scim_outbound_record(
        &self,
        _: &ScimOutboundRecord,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn record_scim_outbound_sync(
        &self,
        _: &ScimOutboundRecord,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn record_scim_outbound_failure(
        &self,
        _: ScimOutboundTargetId,
        _: uuid::Uuid,
        _: OutboundEntityType,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!()
    }
    async fn get_scim_outbound_record(
        &self,
        _: ScimOutboundTargetId,
        _: uuid::Uuid,
        _: OutboundEntityType,
    ) -> Result<Option<ScimOutboundRecord>> {
        unimplemented!()
    }
    async fn create_outbound_dlq_entry(
        &self,
        _: &OutboundDlqEntry,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn list_outbound_dlq_entries(
        &self,
        _: ScimOutboundTargetId,
    ) -> Result<Vec<OutboundDlqEntry>> {
        unimplemented!()
    }
    async fn delete_outbound_dlq_entry(&self, _: uuid::Uuid, _: MutationContext) -> Result<()> {
        unimplemented!()
    }
    async fn try_job_lock(&self, _: i64) -> Result<Option<sid_plugin::storage::JobLock>> {
        unimplemented!()
    }
    async fn ensure_audit_partition(&self, _: chrono::NaiveDate) -> Result<bool> {
        unimplemented!()
    }
    async fn drop_expired_audit_records(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<u64> {
        unimplemented!()
    }
    async fn get_operation_result(
        &self,
        _: &str,
        _: &OperationKey,
    ) -> Result<Option<OperationRecord>> {
        unimplemented!()
    }
    async fn export_operation_results(&self) -> Result<Vec<OperationRecord>> {
        unimplemented!()
    }
    async fn import_operation_result(&self, _: &OperationRecord) -> Result<bool> {
        unimplemented!()
    }
    async fn get_flow_config(&self, _: ProjectId, _: FlowType) -> Result<Option<FlowConfig>> {
        Ok(None)
    }
    async fn save_flow_config(&self, _: &FlowConfig, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn list_flow_configs(&self, _: ProjectId) -> Result<Vec<FlowConfig>> {
        Ok(vec![])
    }
    async fn create_flow_action(&self, _: &FlowAction, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn update_flow_action(&self, _: &FlowAction, _: MutationContext) -> Result<bool> {
        Ok(false)
    }
    async fn get_flow_action(&self, _: ActionId) -> Result<Option<FlowAction>> {
        Ok(None)
    }
    async fn list_flow_actions(
        &self,
        _: ProjectId,
        _: FlowType,
        _: Option<ActionPoint>,
    ) -> Result<Vec<FlowAction>> {
        Ok(vec![])
    }
    async fn delete_flow_action(&self, _: ActionId, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn create_branding_config(&self, _: &BrandingConfig, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn update_branding_draft(&self, _: &BrandingConfig, _: MutationContext) -> Result<bool> {
        Ok(false)
    }
    async fn publish_branding_config(
        &self,
        _: BrandingConfigId,
        _: ProjectId,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> Result<bool> {
        Ok(false)
    }
    async fn get_published_branding(&self, _: ProjectId) -> Result<Option<BrandingConfig>> {
        Ok(None)
    }
    async fn get_branding_config(&self, _: BrandingConfigId) -> Result<Option<BrandingConfig>> {
        Ok(None)
    }
    async fn list_branding_configs(&self, _: ProjectId) -> Result<Vec<BrandingConfig>> {
        Ok(vec![])
    }
    async fn delete_branding_config(
        &self,
        _: BrandingConfigId,
        _: MutationContext,
    ) -> Result<bool> {
        Ok(false)
    }

    // ── Invite operations ──
    async fn create_invite(&self, _: &sid_core::models::Invite, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn get_invite(
        &self,
        _: sid_core::models::InviteId,
    ) -> Result<Option<sid_core::models::Invite>> {
        Ok(None)
    }
    async fn get_invite_by_code(&self, _: &str) -> Result<Option<sid_core::models::Invite>> {
        Ok(None)
    }
    async fn list_invites(
        &self,
        _: &sid_core::models::InviteFilter,
        _: u64,
        _: u64,
    ) -> Result<Vec<sid_core::models::Invite>> {
        Ok(vec![])
    }
    async fn count_invites(&self, _: &sid_core::models::InviteFilter) -> Result<u64> {
        Ok(0)
    }
    async fn try_use_invite(
        &self,
        _: sid_core::models::InviteId,
        _: MutationContext,
    ) -> Result<Option<sid_core::models::Invite>> {
        Ok(None)
    }
    async fn revoke_invite(&self, _: sid_core::models::InviteId, _: MutationContext) -> Result<()> {
        Ok(())
    }

    // ── Registration source operations ──
    async fn get_registration_source(
        &self,
        _: ProfileId,
    ) -> Result<Option<sid_core::models::RegistrationSource>> {
        Ok(None)
    }
    async fn count_registrations_by_source(
        &self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(sid_core::models::RegistrationSourceType, u64)>> {
        Ok(vec![])
    }
    async fn top_referrers(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: u64,
    ) -> Result<Vec<(ProfileId, u64)>> {
        Ok(vec![])
    }
    async fn get_notification_preferences(
        &self,
        _: ProfileId,
    ) -> Result<Option<sid_core::models::notification::NotificationPreferences>> {
        Ok(None)
    }
    async fn save_notification_preferences(
        &self,
        _: &sid_core::models::notification::NotificationPreferences,
        _: MutationContext,
    ) -> Result<()> {
        Ok(())
    }
    async fn count_orphaned_sessions(&self) -> Result<u64> {
        Ok(0)
    }
    async fn count_orphaned_credentials(&self) -> Result<u64> {
        Ok(0)
    }
    async fn count_orphaned_role_assignments(&self) -> Result<u64> {
        Ok(0)
    }
    // ── Access request operations ──
    async fn create_access_request(&self, _: &AccessRequest, _: MutationContext) -> Result<()> {
        Ok(())
    }
    async fn get_access_request(&self, _: AccessRequestId) -> Result<Option<AccessRequest>> {
        Ok(None)
    }
    async fn list_pending_access_requests(&self) -> Result<Vec<AccessRequest>> {
        Ok(vec![])
    }
    async fn decide_access_request(&self, _: &AccessRequest, _: MutationContext) -> Result<bool> {
        unimplemented!("access requests are not used by the authz unit tests")
    }
    async fn approve_access_request(
        &self,
        _: &AccessRequest,
        _: &RoleAssignment,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!("access requests are not used by the authz unit tests")
    }
    // ── Not used by the authz unit tests ──
    async fn count_active_principal_bindings(&self, _: PrincipalId) -> Result<i64> {
        unimplemented!("principal bindings are not used by the authz unit tests")
    }
    async fn get_principal_bindings(&self, _: PrincipalId) -> Result<Vec<PrincipalBinding>> {
        unimplemented!("principal bindings are not used by the authz unit tests")
    }
    async fn unbind_principal(
        &self,
        _: PrincipalId,
        _: ProfileId,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!("principal bindings are not used by the authz unit tests")
    }
    async fn get_principal_by_value(
        &self,
        _: PrincipalType,
        _: &str,
    ) -> Result<Option<PrincipalEntity>> {
        unimplemented!("principals are not used by the authz unit tests")
    }
    async fn expire_principal_verifications(&self) -> Result<i64> {
        unimplemented!("principals are not used by the authz unit tests")
    }
    async fn reconcile_email_key(
        &self,
        _: PrincipalId,
        _: ProfileId,
        _: &ProfileEmail,
        _: &str,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!("principals are not used by the authz unit tests")
    }
    async fn create_reset_session(
        &self,
        _: &sid_core::models::PasswordResetSession,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!("password resets are not used by the authz unit tests")
    }
    async fn get_reset_session(
        &self,
        _: sid_core::models::ResetSessionId,
    ) -> Result<Option<sid_core::models::PasswordResetSession>> {
        unimplemented!("password resets are not used by the authz unit tests")
    }
    async fn verify_reset_session(
        &self,
        _: sid_core::models::ResetSessionId,
        _: MutationContext,
    ) -> Result<bool> {
        unimplemented!("password resets are not used by the authz unit tests")
    }
    async fn complete_password_reset(
        &self,
        _: sid_core::models::ResetSessionId,
        _: &Credential,
        _: Option<&sid_core::models::HistoryCommit>,
        _: &SessionEnd,
        _: MutationContext,
    ) -> Result<Option<Vec<Session>>> {
        unimplemented!("password resets are not used by the authz unit tests")
    }
    async fn count_active_reset_sessions(&self, _: ProfileId) -> Result<u32> {
        unimplemented!("password resets are not used by the authz unit tests")
    }
    async fn delete_expired_reset_sessions(&self, _: MutationContext) -> Result<u64> {
        unimplemented!("password resets are not used by the authz unit tests")
    }
    async fn get_email_provider_config(
        &self,
    ) -> Result<Option<sid_core::models::EmailProviderConfig>> {
        unimplemented!("email configuration is not used by the authz unit tests")
    }
    async fn upsert_email_provider_config(
        &self,
        _: &sid_core::models::EmailProviderConfig,
        _: MutationContext,
    ) -> Result<()> {
        unimplemented!("email configuration is not used by the authz unit tests")
    }
}
