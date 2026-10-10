// SPDX-License-Identifier: AGPL-3.0-only
//! In-memory mock StorageBackend for integration tests.

use async_trait::async_trait;
use sid_core::Result as SidResult;
use sid_core::models::*;
use sid_plugin::StorageBackend;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub struct MockStorageInner {
    profiles: HashMap<ProfileId, Profile>,
    profiles_by_username: HashMap<String, ProfileId>,
    profiles_by_email: HashMap<String, ProfileId>,
    credentials: HashMap<Uuid, Credential>,
    sessions: HashMap<SessionId, Session>,
    oauth2_clients: HashMap<String, OAuth2Client>,
    applications: HashMap<ApplicationId, Application>,
    roles: HashMap<RoleId, Role>,
    role_assignments: Vec<RoleAssignment>,
    resources: HashMap<ResourceId, ProtectedResource>,
    resource_access: Vec<ResourceAccess>,
    pub refresh_tokens_by_hash: HashMap<Vec<u8>, RefreshToken>,
    auth_codes_by_hash: HashMap<Vec<u8>, AuthorizationCode>,
    projects: HashMap<Uuid, Project>,
    principals: HashMap<Uuid, Principal>,
    /// Uniqueness index: (principal_type, normalized_value) → principal_id
    principal_unique: HashSet<(String, String)>,
    /// Consent records: consent_id → ConsentRecord.
    consents: HashMap<Uuid, consent::ConsentRecord>,
    /// Anomaly event records.
    anomaly_events: Vec<AnomalyEventRecord>,
    /// Profile emails: email_id → ProfileEmail.
    profile_emails: HashMap<Uuid, ProfileEmail>,
    /// Profile phones: phone_id → ProfilePhone.
    profile_phones: HashMap<Uuid, ProfilePhone>,
    reset_sessions: HashMap<Uuid, PasswordResetSession>,
    access_requests: HashMap<Uuid, sid_core::models::AccessRequest>,
    email_provider: Option<sid_core::models::EmailProviderConfig>,
    machine_users: HashMap<MachineUserId, sid_core::models::MachineUser>,
    machine_credentials: Vec<sid_core::models::MachineUserCredential>,
    provisioning_connectors: HashMap<ProvisioningConnectorId, ProvisioningConnector>,
    provisioning_credentials: Vec<ProvisioningCredential>,
    impersonation_grants: Vec<ImpersonationGrant>,
    initial_access_tokens: HashMap<Uuid, InitialAccessToken>,
    magic_links: HashMap<Uuid, MagicLinkSession>,
    device_codes: HashMap<DeviceAuthCodeId, DeviceAuthorizationCode>,
    key_versions: Vec<sid_keys::KeyVersionParams>,
    instance_secrets: HashMap<sid_core::models::InstanceSecret, Vec<u8>>,
    instance_organization: Option<sid_core::models::Organization>,
    oidc_issuers: Vec<sid_core::models::OidcIssuer>,
    oidc_issuer_keys: Vec<sid_core::models::IssuerSigningKey>,
    service_bindings: Vec<sid_core::models::ServiceBinding>,
    /// Audit entries passed to `save_session`, in order.
    session_audits: Vec<AuditEntry>,
    /// Audit entries passed to `create_machine_user`, in order.
    machine_user_audits: Vec<AuditEntry>,
    devices: HashMap<DeviceId, Device>,
    /// Audit entries of device writes, in order.
    device_audits: Vec<AuditEntry>,
    /// Upstream providers passed to `create_upstream_provider`, with their
    /// audit entries, in order.
    upstream_creations: Vec<(UpstreamProvider, AuditEntry)>,
    /// Refresh-token revocation fails as a storage fault would.
    refresh_revocation_fails: bool,
    /// Refresh-token rotation fails as a storage fault would.
    refresh_rotation_fails: bool,
    /// Counting a profile's active reset sessions fails as a storage fault would.
    reset_count_fails: bool,
    /// Storing a reset session fails as a storage fault would.
    reset_save_fails: bool,
    /// Reading a profile's sign-in history (recent sessions, designated
    /// countries) fails as a storage fault would.
    login_history_fails: bool,
    /// Reading a profile's primary contacts and metadata fails as a storage
    /// fault would.
    contact_reads_fail: bool,
    /// Listing a profile's credentials fails as a storage fault would.
    credential_reads_fail: bool,
    /// Reading an OAuth2 client fails as a storage fault would.
    client_reads_fail: bool,
    /// Reading roles and role assignments fails as a storage fault would.
    role_reads_fail: bool,
    /// Reading a session by id fails as a storage fault would.
    session_reads_fail: bool,
    /// Listing a profile's principals fails as a storage fault would.
    principal_reads_fail: bool,
    /// Reading a magic link session fails as a storage fault would.
    magic_link_reads_fail: bool,
    /// Reading a profile by id fails as a storage fault would.
    profile_reads_fail: bool,
    /// Consuming a magic link session fails as a storage fault would.
    magic_link_consume_fails: bool,
    /// Durable work items with their payload and lease deadline.
    work: HashMap<WorkId, StoredWork>,
    /// Completions of keyed commands by (namespace, key).
    operations: HashMap<(String, String), OperationRecord>,
    export_jobs: HashMap<Uuid, ExportJob>,
    /// Password histories by owner, as the checker reads them.
    histories: HashMap<ProfileId, PasswordHistory>,
    /// The history evaluator's own store, in the same mock as a standalone
    /// installation keeps it in the same database: its epochs by owner
    /// domain, retired ones included, with their sealed keys.
    key_epochs: HashMap<[u8; 32], Vec<NewKeyEpoch>>,
    /// The evaluator's newest accepted (revision, live set) per owner domain.
    key_lifecycle: HashMap<[u8; 32], (i64, Vec<HistoryEpochId>)>,
    /// The revision from which each replaced epoch stopped being active.
    key_replaced: HashMap<HistoryEpochId, i64>,
    /// (operation, epoch, expiry) of each epoch a prepared operation uses.
    key_uses: Vec<(Uuid, HistoryEpochId, chrono::DateTime<chrono::Utc>)>,
    /// The evaluator's audit entries, in order.
    key_audits: Vec<AuditEntry>,
    /// The credential side's history write cutoff.
    history_write_cutoff: Option<chrono::DateTime<chrono::Utc>>,
    /// The evaluator's history write cutoff.
    key_write_cutoff: Option<chrono::DateTime<chrono::Utc>>,
    /// WebAuthn user handles by (profile, relying party).
    webauthn_user_handles: HashMap<(ProfileId, String), WebAuthnUserHandle>,
}

type StoredWork = (WorkRecord, Vec<u8>, Option<chrono::DateTime<chrono::Utc>>);

impl MockStorageInner {
    /// Whether `fence` still holds, as the storage engines check it at
    /// commit. This mock keeps no group memberships, so a membership fence
    /// never holds.
    fn check_fence(&self, fence: &AssignmentFence) -> SidResult<()> {
        let fenced = |what: &str| Err(sid_core::Error::Fenced(format!("{what} changed")));
        if let Some((basis, revision)) = fence.basis {
            let held = self
                .role_assignments
                .iter()
                .any(|a| a.id == basis && a.revision == revision && !a.is_expired());
            if !held {
                return fenced("the authorizing assignment");
            }
        }
        let (role, checked) = &fence.role;
        let same = self.roles.get(role).is_some_and(|r| {
            r.permissions
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                == *checked
        });
        if !same {
            return fenced("the role's permissions");
        }
        if fence.recipient_membership.is_some() {
            return fenced("the group membership");
        }
        // No memberships here: a grantor is always outside the group.
        Ok(())
    }

    /// Remove assignment `id` and every assignment depending on it, as the
    /// engines' cascade does; whether it existed.
    fn remove_assignment(&mut self, id: RoleAssignmentId) -> bool {
        let existed = self.role_assignments.iter().any(|a| a.id == id);
        let mut gone = vec![id];
        while let Some(next) = gone.pop() {
            let dependents: Vec<RoleAssignmentId> = self
                .role_assignments
                .iter()
                .filter(|a| {
                    a.provenance
                        .as_ref()
                        .is_some_and(|p| p.depends_on == Some(next))
                })
                .map(|a| a.id)
                .collect();
            self.role_assignments.retain(|a| a.id != next);
            gone.extend(dependents);
        }
        existed
    }

    /// Why `client` cannot become the client role of its application, as the
    /// storage contract refuses it: the application must exist in the
    /// client's project and have no client role, and the id must be free.
    fn check_new_client(&self, client: &OAuth2Client) -> SidResult<()> {
        match self.applications.get(&client.application_id) {
            Some(app) if app.project_id == client.project_id => {}
            _ => {
                return Err(sid_core::Error::Storage(format!(
                    "application {} of client {} does not exist in its project",
                    client.application_id, client.client_id
                )));
            }
        }
        let taken = self.oauth2_clients.contains_key(&client.client_id)
            || self
                .oauth2_clients
                .values()
                .any(|c| c.application_id == client.application_id);
        if taken {
            return Err(sid_core::Error::Conflict(format!(
                "oauth2 client {} exists, or application {} already has a client role",
                client.client_id, client.application_id
            )));
        }
        if let Some(default) = client.default_resource
            && !self.resources.contains_key(&default)
        {
            return Err(sid_core::Error::Storage(format!(
                "default resource {default} does not exist"
            )));
        }
        Ok(())
    }

    /// Why `resource` cannot become the resource role of its application.
    fn check_new_resource(&self, resource: &ProtectedResource) -> SidResult<()> {
        let Some(app) = resource.application_id else {
            return Err(sid_core::Error::Validation(
                "a new resource names its application".into(),
            ));
        };
        if resource.state == ResourceState::Retired {
            return Err(sid_core::Error::Validation(
                "a new resource is not retired".into(),
            ));
        }
        let taken = self.resources.values().any(|r| {
            r.application_id == Some(app)
                || (r.issuer_id == resource.issuer_id && r.indicator == resource.indicator)
        }) || self.resources.contains_key(&resource.id);
        if taken {
            return Err(sid_core::Error::Conflict(
                "protected resource already exists".into(),
            ));
        }
        Ok(())
    }
}

pub struct MockStorage {
    pub inner: Mutex<MockStorageInner>,
}

impl MockStorage {
    /// An installation already claimed by its first administrator (a profile
    /// no test signs in as), the state every installation serves users in.
    pub fn new() -> Self {
        let storage = Self::unclaimed();
        let mut admin = Profile::new(Some("site_administrator"));
        admin.roles = vec!["admin".to_string()];
        storage
            .inner
            .lock()
            .unwrap()
            .profiles
            .insert(admin.id, admin);
        storage
    }

    /// A fresh installation without an administrator: registration then
    /// requires the instance claim.
    pub fn unclaimed() -> Self {
        Self {
            inner: Mutex::new(MockStorageInner::default()),
        }
    }

    /// Storage whose refresh-token revocation fails with a storage fault.
    #[allow(dead_code)]
    pub fn with_failing_refresh_revocation(self) -> Self {
        self.inner.lock().unwrap().refresh_revocation_fails = true;
        self
    }

    /// Storage whose refresh-token rotation fails with a storage fault.
    #[allow(dead_code)]
    pub fn with_failing_refresh_rotation(self) -> Self {
        self.inner.lock().unwrap().refresh_rotation_fails = true;
        self
    }

    /// Every device's last poll moved past its interval, as if the device
    /// waited before polling again.
    #[allow(dead_code)]
    pub fn age_device_polls(&self) {
        let mut inner = self.inner.lock().unwrap();
        for code in inner.device_codes.values_mut() {
            if let Some(t) = code.last_polled_at.as_mut() {
                *t -= chrono::Duration::seconds(code.interval.into());
            }
        }
    }

    /// How many reset sessions are stored, whatever their state.
    #[allow(dead_code)]
    pub fn stored_reset_sessions(&self) -> usize {
        self.inner.lock().unwrap().reset_sessions.len()
    }

    /// Storage that cannot count a profile's active reset sessions.
    #[allow(dead_code)]
    pub fn with_failing_reset_count(self) -> Self {
        self.inner.lock().unwrap().reset_count_fails = true;
        self
    }

    /// Storage that cannot store a reset session.
    #[allow(dead_code)]
    pub fn with_failing_reset_save(self) -> Self {
        self.inner.lock().unwrap().reset_save_fails = true;
        self
    }

    /// Storage that cannot read a profile's sign-in history.
    #[allow(dead_code)]
    pub fn with_failing_login_history(self) -> Self {
        self.inner.lock().unwrap().login_history_fails = true;
        self
    }

    /// From now on, reading an OAuth2 client fails.
    #[allow(dead_code)]
    pub fn fail_client_reads(&self) {
        self.inner.lock().unwrap().client_reads_fail = true;
    }

    /// From now on, reading a profile by id fails.
    #[allow(dead_code)]
    pub fn fail_profile_reads(&self) {
        self.inner.lock().unwrap().profile_reads_fail = true;
    }

    /// From now on, reading a magic link session fails.
    #[allow(dead_code)]
    pub fn fail_magic_link_reads(&self) {
        self.inner.lock().unwrap().magic_link_reads_fail = true;
    }

    /// From now on, consuming a magic link session fails.
    #[allow(dead_code)]
    pub fn fail_magic_link_consume(&self) {
        self.inner.lock().unwrap().magic_link_consume_fails = true;
    }

    /// From now on, listing a profile's principals fails.
    #[allow(dead_code)]
    pub fn fail_principal_reads(&self) {
        self.inner.lock().unwrap().principal_reads_fail = true;
    }

    /// From now on, reading a profile's primary contacts and metadata fails.
    #[allow(dead_code)]
    pub fn fail_contact_reads(&self) {
        self.inner.lock().unwrap().contact_reads_fail = true;
    }

    /// From now on, listing a profile's credentials fails.
    #[allow(dead_code)]
    pub fn fail_credential_reads(&self) {
        self.inner.lock().unwrap().credential_reads_fail = true;
    }

    /// Storage holding `client` as the client role of an application of its
    /// own (created when the client's application is not stored yet).
    pub fn with_client(self, client: OAuth2Client) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner
            .applications
            .entry(client.application_id)
            .or_insert_with(|| Application {
                id: client.application_id,
                project_id: client.project_id,
                name: client.client_name.clone(),
                system: None,
                revision: 0,
                created_at: client.created_at,
                updated_at: client.created_at,
            });
        inner
            .oauth2_clients
            .insert(client.client_id.clone(), client);
        drop(inner);
        self
    }

    /// From now on, reading role assignments fails.
    #[allow(dead_code)]
    pub fn fail_role_reads(&self) {
        self.inner.lock().unwrap().role_reads_fail = true;
    }

    /// From now on, reading a session by id fails.
    #[allow(dead_code)]
    pub fn fail_session_reads(&self) {
        self.inner.lock().unwrap().session_reads_fail = true;
    }

    /// Stored role assignments that satisfy `keep`.
    fn assignments_where(
        &self,
        keep: impl Fn(&RoleAssignment) -> bool,
    ) -> SidResult<Vec<RoleAssignment>> {
        let inner = self.inner.lock().unwrap();
        if inner.role_reads_fail {
            return Err(sid_core::Error::Storage(
                "role assignments unreadable".into(),
            ));
        }
        Ok(inner
            .role_assignments
            .iter()
            .filter(|a| keep(a))
            .cloned()
            .collect())
    }

    /// Every stored client may obtain tokens for `resource` with all its
    /// scopes, and a client with no default resource uses it when a request
    /// names none: the choice an administrator makes for OIDC-only sign-in.
    pub fn open_to_every_client(&self, resource: &ProtectedResource) {
        let mut inner = self.inner.lock().unwrap();
        let clients: Vec<String> = inner.oauth2_clients.keys().cloned().collect();
        for client_id in clients {
            if !inner
                .resource_access
                .iter()
                .any(|a| a.client_id == client_id && a.resource_id == resource.id)
            {
                inner.resource_access.push(ResourceAccess {
                    client_id: client_id.clone(),
                    resource_id: resource.id,
                    scopes: resource.scopes.clone(),
                    created_at: chrono::Utc::now(),
                });
            }
            let client = inner
                .oauth2_clients
                .get_mut(&client_id)
                .expect("listed above");
            client.default_resource.get_or_insert(resource.id);
        }
    }

    pub fn with_project(self, project: Project) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.projects.insert(project.id.0, project);
        drop(inner);
        self
    }

    pub fn with_system_project(self) -> Self {
        self.with_project(Project::system())
    }

    pub fn with_profile(self, profile: Profile) -> Self {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ref username) = profile.username {
            inner
                .profiles_by_username
                .insert(username.clone(), profile.id);
        }
        inner.profiles.insert(profile.id, profile);
        drop(inner);
        self
    }

    /// `profile` holding its user name as a sign-in principal, as registration
    /// and import create an account: sign-in resolves only principals.
    #[allow(dead_code)]
    pub fn with_login_profile(self, profile: Profile) -> Self {
        let username = profile
            .username
            .clone()
            .expect("a login profile has a user name");
        let principal = sid_core::models::Principal::new_username(profile.id, username);
        let storage = self.with_profile(profile);
        storage
            .inner
            .lock()
            .unwrap()
            .bind_principal(&principal)
            .expect("the user name is free");
        storage
    }

    pub fn with_credential(self, credential: Credential) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.credentials.insert(credential.id.0, credential);
        drop(inner);
        self
    }

    /// Put a stored credential into the state a test needs (revoked, other
    /// data), bypassing the rules the storage methods enforce.
    #[allow(dead_code)]
    pub fn set_credential(&self, credential: &Credential) {
        self.inner
            .lock()
            .unwrap()
            .credentials
            .insert(credential.id.0, credential.clone());
    }

    /// Put the email key `value` into the state the email policy cutover
    /// leaves a key written before revisions in: revision 0, quarantined.
    #[allow(dead_code)]
    pub fn quarantine_email_key(&self, value: &str) {
        for principal in self.inner.lock().unwrap().principals.values_mut() {
            if principal.principal_type == PrincipalType::Email && principal.value == value {
                principal.email_policy_revision = Some(0);
            }
        }
    }

    #[allow(dead_code)]
    pub fn with_session(self, session: Session) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.sessions.insert(session.id, session);
        drop(inner);
        self
    }

    pub fn with_consent(self, consent: sid_core::models::consent::ConsentRecord) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.consents.insert(consent.id.0, consent);
        drop(inner);
        self
    }

    pub fn with_machine_user(self, mu: sid_core::models::MachineUser) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.machine_users.insert(mu.id, mu);
        drop(inner);
        self
    }

    pub fn with_machine_credential(self, cred: sid_core::models::MachineUserCredential) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.machine_credentials.push(cred);
        drop(inner);
        self
    }

    pub fn with_impersonation_grant(self, grant: ImpersonationGrant) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.impersonation_grants.push(grant);
        drop(inner);
        self
    }

    /// Audit entries written with sessions (`save_session`), in order.
    #[allow(dead_code)]
    pub fn session_audits(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().session_audits.clone()
    }

    /// Audit entries written with created machine users, in order.
    #[allow(dead_code)]
    pub fn machine_user_audits(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().machine_user_audits.clone()
    }

    /// Audit entries of device writes, in order.
    #[allow(dead_code)]
    pub fn device_audits(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().device_audits.clone()
    }

    /// Upstream providers created, with the audit entry of each, in order.
    #[allow(dead_code)]
    pub fn upstream_creations(&self) -> Vec<(UpstreamProvider, AuditEntry)> {
        self.inner.lock().unwrap().upstream_creations.clone()
    }

    pub fn with_initial_access_token(self, iat: InitialAccessToken) -> Self {
        let mut inner = self.inner.lock().unwrap();
        inner.initial_access_tokens.insert(iat.id.0, iat);
        drop(inner);
        self
    }

    /// The history evaluator's audit entries, in order.
    #[allow(dead_code)]
    pub fn history_key_audits(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().key_audits.clone()
    }
}

/// The owner's epochs not retired, in creation order.
fn live_key_epochs(epochs: &[NewKeyEpoch]) -> Vec<KeyEpoch> {
    let mut live: Vec<KeyEpoch> = epochs
        .iter()
        .map(|e| e.epoch.clone())
        .filter(|e| e.status != HistoryEpochUse::Retired)
        .collect();
    live.sort_by_key(|e| (e.created_at, e.id));
    live
}

/// The history evaluator's store, as the real backends keep it: keyed by
/// owner domain, one lock as one transaction.
#[async_trait]
impl sid_plugin::history_keys::HistoryKeyStore for MockStorage {
    async fn get_key_epochs(&self, owner_domain: &[u8; 32]) -> SidResult<KeyEpochs> {
        let inner = self.inner.lock().unwrap();
        Ok(KeyEpochs {
            epochs: live_key_epochs(inner.key_epochs.get(owner_domain).map_or(&[], |e| e)),
        })
    }

    async fn create_first_epoch(
        &self,
        new: &NewKeyEpoch,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        let mut inner = self.inner.lock().unwrap();
        let existing = inner.key_epochs.entry(new.epoch.owner_domain).or_default();
        match existing.as_slice() {
            [] => {}
            [only] if only.epoch == new.epoch => return Ok(only.epoch.clone()),
            _ => {
                return Err(sid_core::Error::Conflict(
                    "the owner already has a history epoch".into(),
                ));
            }
        }
        existing.push(new.clone());
        inner.key_audits.push(audit);
        Ok(new.epoch.clone())
    }

    async fn ensure_epoch(&self, new: &NewKeyEpoch, audit: AuditEntry) -> SidResult<KeyEpoch> {
        let mut inner = self.inner.lock().unwrap();
        let existing = inner.key_epochs.entry(new.epoch.owner_domain).or_default();
        if let Some(active) = existing
            .iter()
            .find(|e| e.epoch.status == HistoryEpochUse::Active)
        {
            return Ok(active.epoch.clone());
        }
        existing.push(new.clone());
        inner.key_audits.push(audit);
        Ok(new.epoch.clone())
    }

    async fn rotate_epoch(
        &self,
        new: &NewKeyEpoch,
        replaces: HistoryEpochId,
        replaced_at_revision: i64,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        let mut inner = self.inner.lock().unwrap();
        let existing = inner.key_epochs.entry(new.epoch.owner_domain).or_default();
        if let Some(active) = existing
            .iter()
            .find(|e| e.epoch.status == HistoryEpochUse::Active)
            && active.epoch.id != replaces
        {
            return Ok(active.epoch.clone());
        }
        for e in existing.iter_mut() {
            if e.epoch.id == replaces && e.epoch.status == HistoryEpochUse::Active {
                e.epoch.status = HistoryEpochUse::CompareOnly;
            }
        }
        existing.push(new.clone());
        inner
            .key_replaced
            .entry(replaces)
            .or_insert(replaced_at_revision);
        inner.key_audits.push(audit);
        Ok(new.epoch.clone())
    }

    async fn prepare_epochs(
        &self,
        prep: &sid_core::models::HistoryPreparation,
        audit: AuditEntry,
    ) -> SidResult<Vec<KeyEpoch>> {
        let mut inner = self.inner.lock().unwrap();
        let domain = prep.owner_domain;
        let owned: HashSet<HistoryEpochId> = inner
            .key_epochs
            .get(&domain)
            .map(|e| e.iter().map(|e| e.epoch.id).collect())
            .unwrap_or_default();
        if prep.live.live.iter().any(|e| !owned.contains(e)) {
            return Err(sid_core::Error::Validation(
                "the live set names an epoch that is not the owner's".into(),
            ));
        }
        let (revision, recorded) = match inner.key_lifecycle.get(&domain).cloned() {
            Some((stored, live)) if stored == prep.live.revision && live != prep.live.live => {
                return Err(sid_core::Error::Conflict(format!(
                    "history revision {stored} already has another live set"
                )));
            }
            Some(kept) if kept.0 >= prep.live.revision => kept,
            _ => (prep.live.revision, prep.live.live.clone()),
        };
        inner
            .key_lifecycle
            .insert(domain, (revision, recorded.clone()));
        inner.key_uses.retain(|(op, epoch, expires)| {
            !owned.contains(epoch) || (!prep.live.settled.contains(op) && *expires > prep.now)
        });
        let used: HashSet<HistoryEpochId> = inner.key_uses.iter().map(|u| u.1).collect();
        let replaced = inner.key_replaced.clone();
        let epochs = inner.key_epochs.entry(domain).or_default();
        for e in epochs.iter_mut() {
            if e.epoch.status == HistoryEpochUse::CompareOnly
                && replaced.get(&e.epoch.id).is_some_and(|r| *r <= revision)
                && !recorded.contains(&e.epoch.id)
                && !used.contains(&e.epoch.id)
            {
                e.epoch.status = HistoryEpochUse::Retired;
            }
        }
        let mut selected: Vec<KeyEpoch> = live_key_epochs(epochs)
            .into_iter()
            .filter(|e| {
                e.status == HistoryEpochUse::Active
                    || (e.status == HistoryEpochUse::CompareOnly && prep.live.live.contains(&e.id))
            })
            .collect();
        selected.sort_by_key(|e| (e.status != HistoryEpochUse::Active, e.created_at, e.id));
        for epoch in &selected {
            inner
                .key_uses
                .retain(|u| !(u.0 == prep.operation && u.1 == epoch.id));
            inner
                .key_uses
                .push((prep.operation, epoch.id, prep.expires_at));
        }
        inner.key_audits.push(audit);
        Ok(selected)
    }

    async fn get_epoch_key(&self, epoch: HistoryEpochId) -> SidResult<Option<WrappedHistoryKey>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .key_epochs
            .values()
            .flatten()
            .find(|e| e.epoch.id == epoch)
            .map(|e| e.key.clone()))
    }

    async fn write_cutoff(&self) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
        Ok(self.inner.lock().unwrap().key_write_cutoff)
    }

    async fn raise_write_cutoff(
        &self,
        not_before: chrono::DateTime<chrono::Utc>,
        audit: AuditEntry,
    ) -> SidResult<chrono::DateTime<chrono::Utc>> {
        let not_before = sid_core::models::password_history::write_cutoff_instant(not_before);
        let mut inner = self.inner.lock().unwrap();
        match inner.key_write_cutoff {
            Some(current) if current >= not_before => Ok(current),
            _ => {
                inner.key_write_cutoff = Some(not_before);
                inner.key_audits.push(audit);
                Ok(not_before)
            }
        }
    }

    async fn export_keys(&self, _: &[u8; 32]) -> SidResult<Option<KeyArchive>> {
        unimplemented!("instance transfer is tested against the real backends")
    }

    async fn import_keys(&self, _: &KeyArchive, _: AuditEntry) -> SidResult<bool> {
        unimplemented!("instance transfer is tested against the real backends")
    }
}

#[async_trait]
impl StorageBackend for MockStorage {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn get_profile(&self, id: ProfileId) -> SidResult<Option<Profile>> {
        let inner = self.inner.lock().unwrap();
        if inner.profile_reads_fail {
            return Err(sid_core::Error::Storage("read profile".into()));
        }
        Ok(inner.profiles.get(&id).cloned())
    }

    async fn get_profile_by_username(&self, username: &str) -> SidResult<Option<Profile>> {
        let inner = self.inner.lock().unwrap();
        let profile = inner
            .profiles_by_username
            .get(username)
            .and_then(|id| inner.profiles.get(id))
            .cloned();
        Ok(profile)
    }

    async fn get_profile_by_email(&self, email: &str) -> SidResult<Option<Profile>> {
        let inner = self.inner.lock().unwrap();
        let profile = inner
            .profiles_by_email
            .get(email)
            .and_then(|id| inner.profiles.get(id))
            .cloned();
        Ok(profile)
    }

    async fn create_profile(&self, profile: &Profile, ctx: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let name_taken = profile
            .username
            .as_ref()
            .is_some_and(|u| inner.profiles_by_username.contains_key(u));
        if inner.profiles.contains_key(&profile.id) || name_taken {
            return Err(sid_core::Error::Conflict("profile already exists".into()));
        }
        inner.profiles.insert(profile.id, profile.clone());
        if let Some(ref username) = profile.username {
            inner
                .profiles_by_username
                .insert(username.clone(), profile.id);
        }
        inner.owe(&ctx)
    }

    async fn update_profile(&self, profile: &Profile, ctx: MutationContext) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(stored) = inner.profiles.get(&profile.id) else {
            return Ok(false);
        };
        if stored.revision != profile.revision {
            return Ok(false);
        }
        let old_username = stored.username.clone();
        let mut next = profile.clone();
        next.created_at = stored.created_at;
        next.revision += 1;
        inner.profiles.insert(profile.id, next);
        if let Some(old) = old_username {
            inner.profiles_by_username.remove(&old);
        }
        if let Some(ref username) = profile.username {
            inner
                .profiles_by_username
                .insert(username.clone(), profile.id);
        }
        inner.owe(&ctx)?;
        Ok(true)
    }

    async fn delete_profile(&self, id: ProfileId, ctx: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.profiles.remove(&id);
        inner.owe(&ctx)
    }

    async fn register_profile(
        &self,
        registration: &NewRegistration,
        ctx: MutationContext,
    ) -> SidResult<()> {
        // One lock for the whole registration: atomic for the mock, as a transaction
        // is for the real backends.
        let mut inner = self.inner.lock().unwrap();
        let principal = &registration.principal;
        let taken = inner
            .principals
            .values()
            .any(|p| p.principal_type == principal.principal_type && p.value == principal.value);
        if taken {
            return Err(sid_core::Error::Conflict(
                "principal already registered".into(),
            ));
        }
        if let Some(ref claim) = registration.instance_claim {
            let key = sid_core::models::InstanceSecret::AdminClaim;
            let open = inner.instance_secrets.get(&key) == Some(claim)
                && !inner.profiles.values().any(Profile::is_admin);
            if !open {
                return Err(sid_core::Error::InvalidState(
                    "the installation has no open administrator claim".into(),
                ));
            }
            inner.instance_secrets.remove(&key);
        }
        let profile = &registration.profile;
        if let Some(ref username) = profile.username {
            inner
                .profiles_by_username
                .insert(username.clone(), profile.id);
        }
        inner.profiles.insert(profile.id, profile.clone());
        if let Some(ref email) = registration.email {
            inner
                .profiles_by_email
                .insert(email.email.clone(), email.profile_id);
            inner.profile_emails.insert(email.id.0, email.clone());
        }
        if let Some(ref phone) = registration.phone {
            inner.profile_phones.insert(phone.id.0, phone.clone());
        }
        inner.bind_principal(principal)?;
        if let Some(ref credential) = registration.credential {
            inner
                .credentials
                .insert(credential.id.0, credential.clone());
        }
        if let Some(ref history) = registration.history
            && !inner.apply_history(history)?
        {
            return Err(sid_core::Error::Conflict(
                "password history moved past the registration's revision".into(),
            ));
        }
        inner.owe(&ctx)
    }

    async fn write_directory_user(
        &self,
        _: &sid_core::models::DirectoryUserWrite,
        _: MutationContext,
    ) -> SidResult<Vec<Session>> {
        unimplemented!("directory writes are exercised by the storage conformance suite")
    }

    async fn write_directory_group(
        &self,
        _: &sid_core::models::DirectoryGroupWrite,
        _: MutationContext,
    ) -> SidResult<()> {
        unimplemented!("directory writes are exercised by the storage conformance suite")
    }

    async fn replace_credential(
        &self,
        credential: &Credential,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let replaced = credential.credential_type.replaces();
        if replaced.is_empty() {
            return Err(sid_core::Error::Validation(
                "this credential type is added, not replaced".into(),
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        inner.credentials.retain(|_, c| {
            c.profile_id != credential.profile_id || !replaced.contains(&c.credential_type)
        });
        inner
            .credentials
            .insert(credential.id.0, credential.clone());
        Ok(())
    }

    async fn enroll_credential(
        &self,
        credential: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if let Some(set) = recovery
            && set.credential_type != CredentialType::Recovery
        {
            return Err(sid_core::Error::Validation(
                "not a recovery-code set".into(),
            ));
        }
        self.create_credential(credential, ctx).await?;
        if let Some(set) = recovery {
            self.replace_credential(set, AuditEntry::system("mock", "enroll").into())
                .await?;
        }
        Ok(())
    }

    // === PROFILE PHONE ===
    async fn get_profile_phone(&self, id: ProfilePhoneId) -> SidResult<Option<ProfilePhone>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.profile_phones.get(&id.0).cloned())
    }
    async fn list_profile_phones(&self, profile_id: ProfileId) -> SidResult<Vec<ProfilePhone>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .profile_phones
            .values()
            .filter(|p| p.profile_id == profile_id)
            .cloned()
            .collect())
    }
    async fn get_primary_profile_phone(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ProfilePhone>> {
        let inner = self.inner.lock().unwrap();
        if inner.contact_reads_fail {
            return Err(sid_core::Error::Storage("read primary phone".into()));
        }
        Ok(inner
            .profile_phones
            .values()
            .find(|p| p.profile_id == profile_id && p.is_primary)
            .cloned())
    }
    async fn create_profile_phone(
        &self,
        phone: &ProfilePhone,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.profile_phones.contains_key(&phone.id.0) {
            return Err(sid_core::Error::Conflict("phone already exists".into()));
        }
        if phone.is_primary {
            for p in inner.profile_phones.values_mut() {
                if p.profile_id == phone.profile_id {
                    p.is_primary = false;
                }
            }
        }
        inner.profile_phones.insert(phone.id.0, phone.clone());
        Ok(())
    }
    async fn update_profile_phone_settings(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        settings: &sid_core::models::PhoneSettings,
        at: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(phone) = inner
            .profile_phones
            .get_mut(&id.0)
            .filter(|p| p.profile_id == profile_id)
        else {
            return Ok(false);
        };
        if let Some(label) = &settings.label {
            phone.label = label.clone();
        }
        if let Some(custom) = &settings.custom_label {
            phone.custom_label = custom.clone();
        }
        if let Some(v) = settings.can_receive_sms {
            phone.can_receive_sms = v;
        }
        if let Some(v) = settings.can_receive_fax {
            phone.can_receive_fax = v;
        }
        if let Some(v) = settings.can_receive_voice {
            phone.can_receive_voice = v;
        }
        phone.updated_at = at;
        Ok(true)
    }
    async fn set_primary_profile_phone(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        _at: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .profile_phones
            .get(&id.0)
            .is_some_and(|p| p.profile_id == profile_id)
        {
            return Ok(false);
        }
        for p in inner.profile_phones.values_mut() {
            if p.profile_id == profile_id {
                p.is_primary = p.id == id;
            }
        }
        Ok(true)
    }
    async fn delete_profile_phone(
        &self,
        id: ProfilePhoneId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.profile_phones.remove(&id.0);
        Ok(())
    }

    // === PROFILE EMAIL ===
    async fn get_profile_email(&self, id: ProfileEmailId) -> SidResult<Option<ProfileEmail>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.profile_emails.get(&id.0).cloned())
    }
    async fn list_profile_emails(&self, profile_id: ProfileId) -> SidResult<Vec<ProfileEmail>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .profile_emails
            .values()
            .filter(|e| e.profile_id == profile_id)
            .cloned()
            .collect())
    }
    async fn get_primary_profile_email(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ProfileEmail>> {
        let inner = self.inner.lock().unwrap();
        if inner.contact_reads_fail {
            return Err(sid_core::Error::Storage("read primary email".into()));
        }
        Ok(inner
            .profile_emails
            .values()
            .find(|e| e.profile_id == profile_id && e.is_primary)
            .cloned())
    }
    async fn create_profile_email(
        &self,
        email: &ProfileEmail,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.profile_emails.contains_key(&email.id.0) {
            return Err(sid_core::Error::Conflict("email already exists".into()));
        }
        if email.is_primary {
            for e in inner.profile_emails.values_mut() {
                if e.profile_id == email.profile_id {
                    e.is_primary = false;
                }
            }
        }
        inner
            .profiles_by_email
            .insert(email.email.clone(), email.profile_id);
        inner.profile_emails.insert(email.id.0, email.clone());
        Ok(())
    }
    async fn update_profile_email_settings(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        settings: &sid_core::models::EmailSettings,
        at: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(email) = inner
            .profile_emails
            .get_mut(&id.0)
            .filter(|e| e.profile_id == profile_id)
        else {
            return Ok(false);
        };
        if let Some(label) = &settings.label {
            email.label = label.clone();
        }
        if let Some(custom) = &settings.custom_label {
            email.custom_label = custom.clone();
        }
        email.updated_at = at;
        Ok(true)
    }
    async fn set_primary_profile_email(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        _at: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .profile_emails
            .get(&id.0)
            .is_some_and(|e| e.profile_id == profile_id)
        {
            return Ok(false);
        }
        for e in inner.profile_emails.values_mut() {
            if e.profile_id == profile_id {
                e.is_primary = e.id == id;
            }
        }
        Ok(true)
    }
    async fn delete_profile_email(
        &self,
        id: ProfileEmailId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.profile_emails.remove(&id.0);
        Ok(())
    }

    async fn get_principal(&self, id: PrincipalId) -> SidResult<Option<Principal>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .claims(id)
            .next()
            .cloned()
            .map(Principal::as_seen_by_subject))
    }

    async fn get_principals_by_profile(&self, profile_id: ProfileId) -> SidResult<Vec<Principal>> {
        let inner = self.inner.lock().unwrap();
        if inner.principal_reads_fail {
            return Err(sid_core::Error::Storage("list principals".into()));
        }
        Ok(inner
            .principals
            .values()
            .filter(|p| p.profile_id == profile_id)
            .cloned()
            .map(Principal::as_seen_by_subject)
            .collect())
    }

    async fn get_profile_by_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<Profile>> {
        let inner = self.inner.lock().unwrap();
        let Some(entity) = inner
            .principals
            .values()
            .find(|p| p.principal_type == principal_type && p.value == value)
        else {
            return Ok(None);
        };
        let Some(assigned) = entity.assigned_profile_id else {
            return Ok(None);
        };
        let holds = inner.claims(entity.id).any(|p| p.profile_id == assigned);
        Ok(holds
            .then(|| inner.profiles.get(&assigned).cloned())
            .flatten())
    }

    async fn save_principal(&self, principal: &Principal, ctx: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        // A refused bind commits nothing, owed work included.
        inner.check_login_handle(principal)?;
        inner.owe(&ctx)?;
        inner.bind_principal(principal)
    }

    async fn get_principal_by_value(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<PrincipalEntity>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .principals
            .values()
            .find(|p| p.principal_type == principal_type && p.value == value)
            .map(PrincipalEntity::from))
    }

    async fn unbind_principal(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(key) = inner
            .principals
            .iter()
            .find(|(_, p)| p.id == principal_id && p.profile_id == profile_id)
            .map(|(key, _)| *key)
        else {
            return Ok(false);
        };
        inner.owe(&ctx)?;
        inner.principals.remove(&key);
        // The holder's release clears the route and the proof; nobody is
        // elected in its place.
        for row in inner
            .principals
            .values_mut()
            .filter(|p| p.id == principal_id)
        {
            if row.assigned_profile_id == Some(profile_id) {
                row.assigned_profile_id = None;
                row.assignment_revision += 1;
                row.verified = false;
                row.verified_at = None;
                row.verification_expires = None;
            }
        }
        Ok(true)
    }

    async fn expire_principal_verifications(&self) -> SidResult<i64> {
        let mut inner = self.inner.lock().unwrap();
        let now = chrono::Utc::now();
        let mut lapsed = std::collections::HashSet::new();
        for principal in inner.principals.values_mut() {
            if principal.verified && principal.verification_expires.is_some_and(|e| e < now) {
                principal.verified = false;
                lapsed.insert(principal.id);
            }
        }
        Ok(lapsed.len() as i64)
    }

    async fn reconcile_email_key(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        contact: &ProfileEmail,
        _reason: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if contact.profile_id != profile_id {
            return Err(sid_core::Error::Validation(
                "the evidence is a contact of another profile".into(),
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        let quarantined = inner.principals.values().any(|p| {
            p.id == principal_id
                && p.email_policy_revision == Some(0)
                && p.assigned_profile_id == Some(profile_id)
        });
        if !quarantined {
            return Ok(false);
        }
        inner.owe(&ctx)?;
        inner.profile_emails.insert(contact.id.0, contact.clone());
        for p in inner
            .principals
            .values_mut()
            .filter(|p| p.id == principal_id)
        {
            p.email_policy_revision = Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION);
            if p.profile_id == profile_id {
                p.source_field = Some("email".into());
                p.source_email_id = Some(contact.id);
            }
        }
        Ok(true)
    }

    async fn get_principal_bindings(
        &self,
        principal_id: PrincipalId,
    ) -> SidResult<Vec<sid_core::models::PrincipalBinding>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .claims(principal_id)
            .map(|p| sid_core::models::PrincipalBinding::new(principal_id, p.profile_id))
            .collect())
    }

    async fn count_active_principal_bindings(&self, principal_id: PrincipalId) -> SidResult<i64> {
        let inner = self.inner.lock().unwrap();
        let count = inner
            .claims(principal_id)
            .filter(|p| {
                inner
                    .profiles
                    .get(&p.profile_id)
                    .is_some_and(|prof| prof.status == ProfileStatus::Active)
            })
            .count();
        Ok(count as i64)
    }

    async fn get_credential(&self, id: CredentialId) -> SidResult<Option<Credential>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.credentials.get(&id.0).cloned())
    }

    async fn get_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> SidResult<Vec<Credential>> {
        let inner = self.inner.lock().unwrap();
        if inner.credential_reads_fail {
            return Err(sid_core::Error::Storage("credentials unreadable".into()));
        }
        Ok(inner
            .credentials
            .values()
            .filter(|c| {
                c.profile_id == profile_id && credential_type.is_none_or(|t| c.credential_type == t)
            })
            .cloned()
            .collect())
    }

    async fn mark_credential_used(
        &self,
        id: sid_core::models::CredentialId,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.credentials.get_mut(&id.0) {
            Some(credential) if credential.status.is_active() => {
                credential.mark_used();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn replace_credential_data(
        &self,
        id: sid_core::models::CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.credentials.get_mut(&id.0) {
            Some(credential)
                if credential.status.is_active() && credential.data.expose() == expected =>
            {
                credential.data = sid_core::models::CredentialData::new(data.to_vec());
                credential.mark_used();
                // Work is owed only by the swap that happened.
                inner.owe(&ctx)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn create_credential(
        &self,
        credential: &Credential,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        // Same invariants as the keys of the real backends: a create never
        // replaces, and one active OPAQUE credential per profile.
        let is_active_password =
            |c: &Credential| c.credential_type == CredentialType::Opaque && c.status.is_active();
        if inner.credentials.contains_key(&credential.id.0)
            || (is_active_password(credential)
                && inner
                    .credentials
                    .values()
                    .any(|c| c.profile_id == credential.profile_id && is_active_password(c)))
        {
            return Err(sid_core::Error::Conflict(
                "credential already exists".into(),
            ));
        }
        inner.owe(&ctx)?;
        inner
            .credentials
            .insert(credential.id.0, credential.clone());
        Ok(())
    }

    async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .credentials
            .get(&id.0)
            .is_some_and(|c| c.status.is_active())
        {
            return Ok(false);
        }
        inner.owe(&ctx)?;
        if let Some(credential) = inner.credentials.get_mut(&id.0) {
            credential.label = label.map(str::to_string);
        }
        Ok(true)
    }

    async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .credentials
            .get(&id.0)
            .is_some_and(|c| c.status.is_active() && c.data.expose() == expected)
        {
            return Ok(false);
        }
        if let Some(history) = history {
            if Some(history.owner) != inner.credentials.get(&id.0).map(|c| c.profile_id) {
                return Err(sid_core::Error::Validation(
                    "password history belongs to the credential's profile".into(),
                ));
            }
            if !inner.apply_history(history)? {
                return Ok(false);
            }
        }
        inner.owe(&ctx)?;
        if let Some(credential) = inner.credentials.get_mut(&id.0) {
            credential.data = new.data.clone();
            credential.policy_evidence = new.policy_evidence;
            credential.opaque_credential_identifier = new.opaque_credential_identifier;
            credential.last_used_at = Some(chrono::Utc::now());
        }
        Ok(true)
    }

    async fn get_password_history(&self, owner: ProfileId) -> SidResult<PasswordHistory> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.histories.get(&owner).cloned().unwrap_or_default())
    }

    async fn raise_history_write_cutoff(
        &self,
        not_before: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<chrono::DateTime<chrono::Utc>> {
        let not_before = sid_core::models::password_history::write_cutoff_instant(not_before);
        let mut inner = self.inner.lock().unwrap();
        match inner.history_write_cutoff {
            Some(current) if current >= not_before => Ok(current),
            _ => {
                inner.owe(&ctx)?;
                inner.history_write_cutoff = Some(not_before);
                Ok(not_before)
            }
        }
    }

    async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .credentials
            .get(&id.0)
            .is_some_and(|c| c.data.expose() == expected)
        {
            return Ok(false);
        }
        inner.owe(&ctx)?;
        if let Some(credential) = inner.credentials.get_mut(&id.0) {
            credential.data = sid_core::models::CredentialData::new(data.to_vec());
        }
        Ok(true)
    }

    async fn delete_credential(&self, id: CredentialId, ctx: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.credentials.remove(&id.0);
        inner.owe(&ctx)
    }

    async fn revoke_credential(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> SidResult<CredentialRevocation> {
        // One lock: the check and the revocation are one step, as in a
        // transaction of the real backends.
        let mut inner = self.inner.lock().unwrap();
        let Some(target) = inner.credentials.get(&id.0).cloned() else {
            return Ok(CredentialRevocation::AlreadyGone);
        };
        if !target.status.is_active() {
            return Ok(CredentialRevocation::AlreadyGone);
        }
        let other_primary = inner.credentials.values().any(|c| {
            c.id != id
                && c.profile_id == target.profile_id
                && c.status.is_active()
                && c.credential_type.is_primary()
        });
        if target.credential_type.is_primary() && !other_primary {
            return Ok(CredentialRevocation::LastPrimary);
        }
        if let Some(credential) = inner.credentials.get_mut(&id.0) {
            credential.status = sid_core::models::credential::CredentialStatus::Revoked;
        }
        inner.owe(&ctx)?;
        Ok(CredentialRevocation::Revoked)
    }

    async fn delete_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        _audit: MutationContext,
    ) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.credentials.len();
        inner.credentials.retain(|_, c| c.profile_id != profile_id);
        Ok((before - inner.credentials.len()) as u64)
    }

    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: ProfileId,
        rp_id: &str,
        candidate: WebAuthnUserHandle,
        ctx: MutationContext,
    ) -> SidResult<WebAuthnUserHandle> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.profiles.contains_key(&profile_id) {
            return Err(sid_core::Error::NotFound(format!("profile {profile_id}")));
        }
        let key = (profile_id, rp_id.to_string());
        if let Some(stored) = inner.webauthn_user_handles.get(&key) {
            return Ok(*stored);
        }
        let taken = inner
            .webauthn_user_handles
            .iter()
            .any(|((_, rp), h)| rp == rp_id && *h == candidate);
        if taken {
            return Err(sid_core::Error::Conflict(
                "WebAuthn user handle already exists".into(),
            ));
        }
        inner.owe(&ctx)?;
        inner.webauthn_user_handles.insert(key, candidate);
        Ok(candidate)
    }

    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: WebAuthnUserHandle,
    ) -> SidResult<Option<ProfileId>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .webauthn_user_handles
            .iter()
            .find(|((_, rp), h)| rp == rp_id && **h == handle)
            .map(|((profile, _), _)| *profile))
    }

    async fn revoke_consents_by_profile(
        &self,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        inner.owe(&ctx)?;
        let mut revoked = 0;
        for consent in inner
            .consents
            .values_mut()
            .filter(|c| c.profile_id == profile_id)
        {
            if let Some(active) = consent.as_active() {
                active.revoke_all();
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn create_consent(
        &self,
        consent: &sid_core::models::consent::ConsentRecord,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let taken = inner.consents.values().any(|c| {
            c.id == consent.id
                || (c.profile_id == consent.profile_id && c.client_id == consent.client_id)
        });
        if taken {
            return Err(sid_core::Error::Conflict("consent already exists".into()));
        }
        inner.owe(&ctx)?;
        inner.consents.insert(consent.id.0, consent.clone());
        Ok(())
    }

    async fn change_claim_grant(
        &self,
        id: sid_core::models::consent::ConsentId,
        claim_name: &str,
        decision: sid_core::models::consent::ClaimDecision,
        ctx: MutationContext,
    ) -> SidResult<sid_core::models::consent::ClaimGrantChange> {
        use sid_core::models::consent::{ClaimDecision, ClaimGrantChange};
        let mut inner = self.inner.lock().unwrap();
        let Some(consent) = inner.consents.get(&id.0) else {
            return Ok(ClaimGrantChange::ConsentNotActive);
        };
        if !consent.status.is_active() {
            return Ok(ClaimGrantChange::ConsentNotActive);
        }
        let mut changed = consent.clone();
        match decision {
            ClaimDecision::Grant(claim_type) => changed.grant_claim(claim_name, claim_type),
            ClaimDecision::Revoke => {
                if let Some(mut active) = changed.as_active() {
                    active.revoke_claim(claim_name);
                }
            }
        }
        let active_of = |c: &sid_core::models::consent::ConsentRecord| {
            c.grants
                .iter()
                .any(|g| g.claim_name == claim_name && g.is_active())
        };
        if active_of(consent) == active_of(&changed) {
            return Ok(ClaimGrantChange::Unchanged);
        }
        inner.owe(&ctx)?;
        inner.consents.insert(id.0, changed);
        Ok(ClaimGrantChange::Changed)
    }

    async fn get_consent(
        &self,
        id: sid_core::models::consent::ConsentId,
    ) -> SidResult<Option<sid_core::models::consent::ConsentRecord>> {
        Ok(self.inner.lock().unwrap().consents.get(&id.0).cloned())
    }

    async fn get_consent_by_client(
        &self,
        profile_id: ProfileId,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::consent::ConsentRecord>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .consents
            .values()
            .find(|c| c.profile_id == profile_id && c.client_id == client_id)
            .cloned())
    }

    async fn list_consents_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<sid_core::models::consent::ConsentRecord>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .consents
            .values()
            .filter(|c| c.profile_id == profile_id)
            .cloned()
            .collect())
    }

    async fn delete_consent(
        &self,
        id: sid_core::models::consent::ConsentId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.consents.contains_key(&id.0) {
            return Ok(false);
        }
        inner.owe(&ctx)?;
        inner.consents.remove(&id.0);
        Ok(true)
    }

    async fn save_anomaly_event(&self, event: &AnomalyEventRecord) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.anomaly_events.push(event.clone());
        Ok(())
    }

    async fn list_anomaly_events(
        &self,
        rule_id: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> SidResult<Vec<AnomalyEventRecord>> {
        let inner = self.inner.lock().unwrap();
        let filtered: Vec<_> = inner
            .anomaly_events
            .iter()
            .filter(|e| rule_id.is_none_or(|r| e.rule_id == r))
            .rev() // newest first
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn record_ip_reputation_event(&self, _ip: &str, _success: bool) -> SidResult<()> {
        Ok(())
    }

    async fn get_ip_reputation_score(&self, _ip: &str) -> SidResult<Option<f32>> {
        Ok(None)
    }

    async fn list_suspicious_ips(
        &self,
        _min_score: f32,
        _limit: i64,
    ) -> SidResult<Vec<(String, f32)>> {
        Ok(vec![])
    }

    async fn decay_ip_reputation(&self, _older_than: std::time::Duration) -> SidResult<u64> {
        Ok(0)
    }

    async fn add_ip_allowlist_entry(&self, _cidr: &str, _description: &str) -> SidResult<()> {
        Ok(())
    }
    async fn remove_ip_allowlist_entry(&self, _cidr: &str) -> SidResult<()> {
        Ok(())
    }
    async fn list_ip_allowlist_entries(
        &self,
    ) -> SidResult<Vec<(String, String, chrono::DateTime<chrono::Utc>)>> {
        Ok(vec![])
    }

    async fn create_session(&self, session: &Session, audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sessions.contains_key(&session.id) {
            return Err(sid_core::Error::Conflict("session already exists".into()));
        }
        inner.owe(&audit)?;
        inner.sessions.insert(session.id, session.clone());
        inner.session_audits.push(audit.audit);
        Ok(())
    }

    async fn record_session_authentication(
        &self,
        id: SessionId,
        expected: &sid_core::models::SessionAuthentication,
        new: &sid_core::models::SessionAuthentication,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let applies = inner
            .sessions
            .get(&id)
            .is_some_and(|s| !s.is_expired() && s.authentication() == *expected);
        if !applies {
            return Ok(false);
        }
        inner.owe(&audit)?;
        let session = inner.sessions.get_mut(&id).expect("checked above");
        session.assurance_level = new.assurance_level;
        session.elevation = new.elevation;
        session.authenticated_at = new.authenticated_at;
        session.amr = new.amr.clone();
        inner.session_audits.push(audit.audit);
        Ok(true)
    }

    async fn create_session_atomic(
        &self,
        session: &Session,
        max_sessions: u32,
        ctx: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sessions.contains_key(&session.id) {
            return Err(sid_core::Error::Conflict("session already exists".into()));
        }
        let mut evicted = Vec::new();
        if max_sessions > 0 {
            let now = chrono::Utc::now();
            let mut active: Vec<Session> = inner
                .sessions
                .values()
                .filter(|s| s.profile_id == session.profile_id && s.expires_at > now)
                .cloned()
                .collect();
            active.sort_by_key(|s| s.created_at);
            // Below the limit (the new session included) nothing is evicted.
            let excess = (active.len() + 1).saturating_sub(max_sessions as usize);
            let end = SessionEnd::new(RevocationReason::SessionLimit, "system");
            for oldest in active.into_iter().take(excess) {
                for ended in inner.end_with_dependents(oldest.id) {
                    for owed in end.owed_by(&ended) {
                        inner.enqueue(&owed, u64::MAX)?;
                    }
                    evicted.push(ended.id);
                }
            }
        }
        inner.owe(&ctx)?;
        inner.sessions.insert(session.id, session.clone());
        Ok(evicted)
    }

    async fn get_session(&self, id: SessionId) -> SidResult<Option<Session>> {
        let inner = self.inner.lock().unwrap();
        if inner.session_reads_fail {
            return Err(sid_core::Error::Storage("sessions unreadable".into()));
        }
        Ok(inner.sessions.get(&id).cloned())
    }

    async fn get_session_by_browser_secret(
        &self,
        hash: &sid_core::models::BrowserSecretHash,
    ) -> SidResult<Option<Session>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .sessions
            .values()
            .find(|s| s.browser_secret_hash.as_ref() == Some(hash))
            .cloned())
    }

    async fn touch_session(
        &self,
        id: SessionId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(session) = inner.sessions.get_mut(&id) {
            session.last_activity_at = Some(session.last_activity_at.map_or(at, |t| t.max(at)));
        }
        Ok(())
    }

    async fn delete_session(
        &self,
        id: SessionId,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let mut inner = self.inner.lock().unwrap();
        let ended = inner.end_with_dependents(id);
        for session in &ended {
            ctx.work.extend(end.owed_by(session));
        }
        inner.owe(&ctx)?;
        Ok(ended.into_iter().map(|session| session.id).collect())
    }

    async fn delete_sessions_by_profile(
        &self,
        profile_id: ProfileId,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let mut inner = self.inner.lock().unwrap();
        let ended: Vec<Session> = inner
            .sessions
            .values()
            .filter(|s| s.profile_id == profile_id)
            .cloned()
            .collect();
        inner.sessions.retain(|_, s| s.profile_id != profile_id);
        for session in &ended {
            ctx.work.extend(end.owed_by(session));
        }
        inner.owe(&ctx)?;
        Ok(ended)
    }

    async fn get_oauth2_client(&self, client_id: &str) -> SidResult<Option<OAuth2Client>> {
        let inner = self.inner.lock().unwrap();
        if inner.client_reads_fail {
            return Err(sid_core::Error::Storage("read oauth2 client".into()));
        }
        Ok(inner.oauth2_clients.get(client_id).cloned())
    }

    async fn update_oauth2_client(
        &self,
        client: &OAuth2Client,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(stored) = inner.oauth2_clients.get_mut(&client.client_id) else {
            return Ok(false);
        };
        let same_origin = stored.revision == client.revision
            && stored.registration_iat == client.registration_iat
            && stored.client_id_issued_at == client.client_id_issued_at
            && stored.created_at == client.created_at;
        if !same_origin {
            return Ok(false);
        }
        *stored = client.clone();
        stored.revision += 1;
        Ok(true)
    }

    async fn create_oauth2_client(
        &self,
        client: &OAuth2Client,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.check_new_client(client)?;
        inner
            .oauth2_clients
            .insert(client.client_id.clone(), client.clone());
        Ok(())
    }

    async fn delete_oauth2_client(
        &self,
        client_id: &str,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(client) = inner.oauth2_clients.remove(client_id) {
            inner.resource_access.retain(|a| a.client_id != client_id);
            inner.role_assignments.retain(|a| {
                !matches!(&a.principal, RoleAssignmentPrincipal::OAuthClient(c) if c == client_id)
            });
            let app = client.application_id;
            if !inner
                .resources
                .values()
                .any(|r| r.application_id == Some(app))
            {
                inner.applications.remove(&app);
            }
        }
        Ok(())
    }

    async fn oauth2_client_of_application(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<OAuth2Client>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .oauth2_clients
            .values()
            .find(|c| c.application_id == id)
            .cloned())
    }

    async fn create_application(
        &self,
        app: &Application,
        client: Option<&OAuth2Client>,
        resource: Option<&ProtectedResource>,
        _ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if client.is_some_and(|c| c.application_id != app.id || c.project_id != app.project_id)
            || resource.is_some_and(|r| r.application_id != Some(app.id))
        {
            return Err(sid_core::Error::Validation(
                "a role names another application".into(),
            ));
        }
        if inner.applications.contains_key(&app.id) {
            return Err(sid_core::Error::Conflict("application exists".into()));
        }
        if app.system.is_some() && inner.applications.values().any(|a| a.system == app.system) {
            return Err(sid_core::Error::Conflict(
                "system integration exists".into(),
            ));
        }
        // Checked against a copy holding the application: all or nothing.
        inner.applications.insert(app.id, app.clone());
        let checked = resource
            .map(|r| inner.check_new_resource(r))
            .transpose()
            .and_then(|_| {
                if let Some(r) = resource {
                    inner.resources.insert(r.id, r.clone());
                }
                client.map(|c| inner.check_new_client(c)).transpose()
            });
        if let Err(e) = checked {
            inner.applications.remove(&app.id);
            if let Some(r) = resource {
                inner.resources.remove(&r.id);
            }
            return Err(e);
        }
        if let Some(c) = client {
            inner.oauth2_clients.insert(c.client_id.clone(), c.clone());
        }
        Ok(())
    }

    async fn get_application(&self, id: ApplicationId) -> SidResult<Option<Application>> {
        Ok(self.inner.lock().unwrap().applications.get(&id).cloned())
    }

    async fn system_application(
        &self,
        kind: sid_core::models::SystemIntegration,
    ) -> SidResult<Option<Application>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .applications
            .values()
            .find(|a| a.system == Some(kind))
            .cloned())
    }

    async fn list_applications_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Application>> {
        let inner = self.inner.lock().unwrap();
        let mut apps: Vec<_> = inner
            .applications
            .values()
            .filter(|a| a.project_id == project_id)
            .cloned()
            .collect();
        apps.sort_by_key(|a| (a.created_at, a.id));
        Ok(apps
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn update_application(
        &self,
        app: &Application,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(stored) = inner.applications.get_mut(&app.id) else {
            return Ok(false);
        };
        if stored.revision != app.revision
            || stored.project_id != app.project_id
            || stored.created_at != app.created_at
        {
            return Ok(false);
        }
        stored.name = app.name.clone();
        stored.updated_at = app.updated_at;
        stored.revision += 1;
        Ok(true)
    }

    async fn delete_application(
        &self,
        id: ApplicationId,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.applications.remove(&id).is_none() {
            return Ok(false);
        }
        let removed: Vec<String> = inner
            .oauth2_clients
            .values()
            .filter(|c| c.application_id == id)
            .map(|c| c.client_id.clone())
            .collect();
        for client_id in &removed {
            inner.oauth2_clients.remove(client_id);
        }
        inner
            .resource_access
            .retain(|a| !removed.contains(&a.client_id));
        let retired: Vec<ResourceId> = inner
            .resources
            .values_mut()
            .filter(|r| r.application_id == Some(id))
            .map(|r| {
                r.application_id = None;
                r.state = ResourceState::Retired;
                r.revision += 1;
                r.updated_at = chrono::Utc::now();
                r.id
            })
            .collect();
        inner
            .resource_access
            .retain(|a| !retired.contains(&a.resource_id));
        for client in inner.oauth2_clients.values_mut() {
            if client
                .default_resource
                .is_some_and(|d| retired.contains(&d))
            {
                client.default_resource = None;
                client.revision += 1;
            }
        }
        Ok(true)
    }

    async fn create_protected_resource(
        &self,
        resource: &ProtectedResource,
        _ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if resource
            .application_id
            .is_some_and(|a| !inner.applications.contains_key(&a))
        {
            return Err(sid_core::Error::Storage(
                "application does not exist".into(),
            ));
        }
        inner.check_new_resource(resource)?;
        inner.resources.insert(resource.id, resource.clone());
        Ok(())
    }

    async fn get_protected_resource(&self, id: ResourceId) -> SidResult<Option<ProtectedResource>> {
        Ok(self.inner.lock().unwrap().resources.get(&id).cloned())
    }

    async fn protected_resource_of_application(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<ProtectedResource>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .resources
            .values()
            .find(|r| r.application_id == Some(id))
            .cloned())
    }

    async fn list_protected_resources(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<ProtectedResource>> {
        let inner = self.inner.lock().unwrap();
        let mut all: Vec<_> = inner.resources.values().cloned().collect();
        all.sort_by_key(|r| (r.created_at, r.id));
        Ok(all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn import_protected_resource(
        &self,
        resource: &ProtectedResource,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.resources.contains_key(&resource.id) {
            return Ok(false);
        }
        let taken = inner.resources.values().any(|r| {
            (r.issuer_id == resource.issuer_id && r.indicator == resource.indicator)
                || (resource.application_id.is_some()
                    && r.application_id == resource.application_id)
        });
        if taken {
            return Err(sid_core::Error::Conflict("protected resource".into()));
        }
        inner.resources.insert(resource.id, resource.clone());
        Ok(true)
    }

    async fn protected_resource_by_indicator(
        &self,
        issuer: IssuerId,
        indicator: &ResourceIndicator,
    ) -> SidResult<Option<ProtectedResource>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .resources
            .values()
            .find(|r| r.issuer_id == issuer && &r.indicator == indicator)
            .cloned())
    }

    async fn update_protected_resource(
        &self,
        resource: &ProtectedResource,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        if resource.state == ResourceState::Retired {
            return Ok(false);
        }
        let mut inner = self.inner.lock().unwrap();
        let Some(stored) = inner.resources.get_mut(&resource.id) else {
            return Ok(false);
        };
        let same = stored.revision == resource.revision
            && stored.state != ResourceState::Retired
            && stored.application_id == resource.application_id
            && stored.issuer_id == resource.issuer_id
            && stored.indicator == resource.indicator
            && stored.created_at == resource.created_at;
        if !same {
            return Ok(false);
        }
        stored.scopes = resource.scopes.clone();
        stored.state = resource.state;
        stored.updated_at = resource.updated_at;
        stored.revision += 1;
        Ok(true)
    }

    async fn set_resource_access(
        &self,
        access: &ResourceAccess,
        _ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.resources.get(&access.resource_id) {
            None => return Err(sid_core::Error::NotFound("protected resource".into())),
            Some(r) if r.state == ResourceState::Retired => {
                return Err(sid_core::Error::InvalidState("retired resource".into()));
            }
            Some(_) => {}
        }
        // An OAuth client or a live machine user, as the real stores accept.
        let machine = inner.machine_users.values().any(|m| {
            m.client_id == access.client_id
                && m.status != sid_core::models::machine_user::MachineUserStatus::Deleted
        });
        if !inner.oauth2_clients.contains_key(&access.client_id) && !machine {
            return Err(sid_core::Error::NotFound(format!(
                "client {}",
                access.client_id
            )));
        }
        match inner
            .resource_access
            .iter_mut()
            .find(|a| a.client_id == access.client_id && a.resource_id == access.resource_id)
        {
            Some(existing) => existing.scopes = access.scopes.clone(),
            None => inner.resource_access.push(access.clone()),
        }
        Ok(())
    }

    async fn remove_resource_access(
        &self,
        client_id: &str,
        resource: ResourceId,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.resource_access.len();
        inner
            .resource_access
            .retain(|a| !(a.client_id == client_id && a.resource_id == resource));
        Ok(inner.resource_access.len() != before)
    }

    async fn resource_access(
        &self,
        client_id: &str,
        resource: ResourceId,
    ) -> SidResult<Option<ResourceAccess>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .resource_access
            .iter()
            .find(|a| a.client_id == client_id && a.resource_id == resource)
            .cloned())
    }

    async fn list_resource_access_by_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<ResourceAccess>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .resource_access
            .iter()
            .filter(|a| a.client_id == client_id)
            .cloned()
            .collect())
    }

    async fn list_resource_access_by_resource(
        &self,
        resource: ResourceId,
    ) -> SidResult<Vec<ResourceAccess>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .resource_access
            .iter()
            .filter(|a| a.resource_id == resource)
            .cloned()
            .collect())
    }

    async fn list_oauth2_clients(&self, offset: u64, limit: u64) -> SidResult<Vec<OAuth2Client>> {
        let inner = self.inner.lock().unwrap();
        let clients: Vec<_> = inner
            .oauth2_clients
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(clients)
    }

    async fn list_profiles(&self, offset: u64, limit: u64) -> SidResult<Vec<Profile>> {
        let inner = self.inner.lock().unwrap();
        // The trait's order: oldest first, then id.
        let mut profiles: Vec<_> = inner.profiles.values().collect();
        profiles.sort_by_key(|p| (p.created_at, p.id));
        Ok(profiles
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn count_profiles(&self) -> SidResult<u64> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.profiles.len() as u64)
    }

    async fn list_profiles_with_status(&self, status: ProfileStatus) -> SidResult<Vec<Profile>> {
        let inner = self.inner.lock().unwrap();
        let mut found: Vec<Profile> = inner
            .profiles
            .values()
            .filter(|p| p.status == status)
            .cloned()
            .collect();
        found.sort_by_key(|p| p.id.into_uuid());
        Ok(found)
    }

    async fn list_profiles_with_pending_migration(&self) -> SidResult<Vec<Profile>> {
        Ok(vec![])
    }

    async fn end_legacy_migration(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if !self.update_profile(profile, ctx).await? {
            return Ok(false);
        }
        self.inner.lock().unwrap().credentials.retain(|_, c| {
            c.profile_id != profile.id || c.credential_type != CredentialType::LegacyHash
        });
        Ok(true)
    }

    async fn list_sessions_by_profile(&self, profile_id: ProfileId) -> SidResult<Vec<Session>> {
        let inner = self.inner.lock().unwrap();
        let sessions: Vec<_> = inner
            .sessions
            .values()
            .filter(|s| s.profile_id == profile_id)
            .cloned()
            .collect();
        Ok(sessions)
    }

    async fn get_most_recent_session_ip(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<(String, chrono::DateTime<chrono::Utc>)>> {
        let inner = self.inner.lock().unwrap();
        if inner.login_history_fails {
            return Err(sid_core::Error::Storage("read recent session".into()));
        }
        let most_recent = inner
            .sessions
            .values()
            .filter(|s| s.profile_id == profile_id)
            .max_by_key(|s| s.created_at)
            .map(|s| (s.ip_address.clone(), s.created_at));
        Ok(most_recent)
    }

    async fn has_recent_session_from_ip(
        &self,
        profile_id: ProfileId,
        ip: &str,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let inner = self.inner.lock().unwrap();
        if inner.login_history_fails {
            return Err(sid_core::Error::Storage("read sessions by ip".into()));
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window.as_secs() as i64);
        let found = inner
            .sessions
            .values()
            .any(|s| s.profile_id == profile_id && s.ip_address == ip && s.created_at > cutoff);
        Ok(found)
    }

    async fn has_recent_session_from_device(
        &self,
        profile_id: ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let inner = self.inner.lock().unwrap();
        if inner.login_history_fails {
            return Err(sid_core::Error::Storage("read sessions by device".into()));
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window.as_secs() as i64);
        let found = inner.sessions.values().any(|s| {
            s.profile_id == profile_id && s.device_id == Some(device_id) && s.created_at > cutoff
        });
        Ok(found)
    }

    async fn record_login_location(
        &self,
        _profile_id: ProfileId,
        _country: &str,
        _latitude: f64,
        _longitude: f64,
        _designated_threshold: u32,
    ) -> SidResult<()> {
        Ok(())
    }

    async fn get_designated_countries(&self, _profile_id: ProfileId) -> SidResult<Vec<String>> {
        if self.inner.lock().unwrap().login_history_fails {
            return Err(sid_core::Error::Storage("read designated countries".into()));
        }
        Ok(vec![])
    }

    async fn create_refresh_token(
        &self,
        token: &RefreshToken,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.refresh_tokens_by_hash.contains_key(&token.token_hash) {
            return Err(sid_core::Error::Conflict("refresh token exists".into()));
        }
        inner
            .refresh_tokens_by_hash
            .insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    async fn get_refresh_token_by_hash(&self, hash: &[u8]) -> SidResult<Option<RefreshToken>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.refresh_tokens_by_hash.get(hash).cloned())
    }

    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: SessionId,
        _audit: MutationContext,
    ) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        let mut count = 0u64;
        for token in inner.refresh_tokens_by_hash.values_mut() {
            if token.session_id == session_id
                && (!token.revoked || token.grace_expires_at.is_some())
            {
                token.revoked = true;
                token.grace_expires_at = None;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: Uuid,
        _audit: MutationContext,
    ) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        if inner.refresh_revocation_fails {
            return Err(sid_core::Error::Storage("storage unavailable".into()));
        }
        let mut count = 0u64;
        for token in inner.refresh_tokens_by_hash.values_mut() {
            if token.family_id == family_id && (!token.revoked || token.grace_expires_at.is_some())
            {
                token.revoked = true;
                token.grace_expires_at = None;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn rotate_refresh_token(
        &self,
        old_id: Uuid,
        new: &RefreshToken,
        grace_expires_at: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.refresh_rotation_fails {
            return Err(sid_core::Error::Storage("storage unavailable".into()));
        }
        let Some(old) = inner
            .refresh_tokens_by_hash
            .values_mut()
            .find(|t| t.id == old_id)
        else {
            return Ok(false);
        };
        if old.is_expired() || (old.revoked && !old.is_within_grace_window()) {
            return Ok(false);
        }
        old.revoked = true;
        old.replaced_by = Some(new.id);
        old.grace_expires_at.get_or_insert(grace_expires_at);
        inner
            .refresh_tokens_by_hash
            .insert(new.token_hash.clone(), new.clone());
        Ok(true)
    }

    async fn create_auth_code(
        &self,
        code: &AuthorizationCode,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.auth_codes_by_hash.contains_key(&code.code_hash) {
            return Err(sid_core::Error::Conflict(
                "authorization code exists".into(),
            ));
        }
        inner
            .auth_codes_by_hash
            .insert(code.code_hash.clone(), code.clone());
        Ok(())
    }

    async fn get_auth_code_by_hash(&self, hash: &[u8]) -> SidResult<Option<AuthorizationCode>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.auth_codes_by_hash.get(hash).cloned())
    }

    async fn redeem_auth_code(
        &self,
        hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        _audit: MutationContext,
    ) -> SidResult<AuthCodeRedemption> {
        // One lock covers the check and the writes, like the database transaction.
        let mut inner = self.inner.lock().unwrap();
        let Some(code) = inner.auth_codes_by_hash.get_mut(hash) else {
            return Ok(AuthCodeRedemption::AlreadyRedeemed { session_id: None });
        };
        if code.used {
            return Ok(AuthCodeRedemption::AlreadyRedeemed {
                session_id: code.session_id,
            });
        }
        code.used = true;
        code.session_id = Some(session.id);
        inner.sessions.insert(session.id, session.clone());
        inner
            .refresh_tokens_by_hash
            .insert(refresh_token.token_hash.clone(), refresh_token.clone());
        Ok(AuthCodeRedemption::Redeemed)
    }

    // === INITIAL ACCESS TOKEN OPERATIONS (DCR) ===
    async fn create_initial_access_token(
        &self,
        token: &InitialAccessToken,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .initial_access_tokens
            .insert(token.id.0, token.clone());
        Ok(())
    }
    async fn list_key_versions(&self) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
        let mut versions = self.inner.lock().unwrap().key_versions.clone();
        versions.sort_by_key(|v| v.version);
        Ok(versions)
    }
    async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .key_versions
            .iter()
            .any(|v| v.version == params.version)
        {
            return Ok(false);
        }
        inner.key_versions.push(params.clone());
        Ok(true)
    }

    async fn get_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
    ) -> SidResult<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .instance_secrets
            .get(&secret)
            .cloned())
    }

    async fn insert_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
        sealed: &[u8],
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.instance_secrets.contains_key(&secret) {
            return Ok(false);
        }
        inner.instance_secrets.insert(secret, sealed.to_vec());
        Ok(true)
    }

    async fn instance_organization(&self) -> SidResult<Option<sid_core::models::Organization>> {
        Ok(self.inner.lock().unwrap().instance_organization.clone())
    }

    async fn insert_instance_organization(
        &self,
        org: &sid_core::models::Organization,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.instance_organization.is_some() {
            return Ok(false);
        }
        inner.instance_organization = Some(org.clone());
        Ok(true)
    }

    async fn assign_unowned_clients(
        &self,
        org_id: sid_core::models::OrgId,
        _ctx: MutationContext,
    ) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        let mut assigned = 0;
        for client in inner.oauth2_clients.values_mut() {
            if client.org_id.is_none() {
                client.org_id = Some(org_id);
                client.revision += 1;
                assigned += 1;
            }
        }
        Ok(assigned)
    }

    async fn oidc_issuer_for(
        &self,
        authority: sid_core::models::IssuerAuthority,
        recipient_org: sid_core::models::OrgId,
    ) -> SidResult<Option<sid_core::models::OidcIssuer>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .oidc_issuers
            .iter()
            .find(|i| i.authority == authority && i.recipient_org == recipient_org)
            .cloned())
    }

    async fn oidc_issuer_by_handle(
        &self,
        handle: &sid_core::models::IssuerHandle,
    ) -> SidResult<Option<sid_core::models::OidcIssuer>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .oidc_issuers
            .iter()
            .find(|i| &i.handle == handle)
            .cloned())
    }

    async fn insert_oidc_issuer(
        &self,
        issuer: &sid_core::models::OidcIssuer,
        first_key: &sid_core::models::IssuerSigningKey,
        _ctx: MutationContext,
    ) -> SidResult<bool> {
        issuer.check_first_key(first_key)?;
        let mut inner = self.inner.lock().unwrap();
        if inner
            .oidc_issuers
            .iter()
            .any(|i| i.authority == issuer.authority && i.recipient_org == issuer.recipient_org)
        {
            return Ok(false);
        }
        if inner
            .oidc_issuers
            .iter()
            .any(|i| i.handle == issuer.handle || i.canonical_url == issuer.canonical_url)
        {
            return Err(sid_core::Error::Conflict(
                "oidc issuer already exists".into(),
            ));
        }
        inner.oidc_issuers.push(issuer.clone());
        inner.oidc_issuer_keys.push(first_key.clone());
        Ok(true)
    }

    async fn oidc_issuer_signing_keys(
        &self,
        issuer: sid_core::models::IssuerId,
    ) -> SidResult<Vec<sid_core::models::IssuerSigningKey>> {
        let inner = self.inner.lock().unwrap();
        let mut keys: Vec<_> = inner
            .oidc_issuer_keys
            .iter()
            .filter(|k| k.issuer_id == issuer)
            .cloned()
            .collect();
        keys.sort_by_key(|k| k.generation);
        Ok(keys)
    }

    async fn admin_exists(&self) -> SidResult<bool> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.profiles.values().any(Profile::is_admin))
    }

    async fn claim_first_admin(
        &self,
        claim_sealed: &[u8],
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        {
            let mut inner = self.inner.lock().unwrap();
            let claim = sid_core::models::InstanceSecret::AdminClaim;
            if inner.instance_secrets.get(&claim).map(Vec::as_slice) != Some(claim_sealed) {
                return Ok(false);
            }
            inner.instance_secrets.remove(&claim);
            if inner.profiles.values().any(Profile::is_admin) {
                return Ok(false);
            }
        }
        let updated = self.update_profile(profile, ctx).await?;
        if !updated {
            // The real backends roll the claim removal back with the write.
            self.inner.lock().unwrap().instance_secrets.insert(
                sid_core::models::InstanceSecret::AdminClaim,
                claim_sealed.to_vec(),
            );
        }
        Ok(updated)
    }
    async fn service_binding(
        &self,
        profile_id: ProfileId,
        scope: &sid_core::models::BindingScope,
        ctx: MutationContext,
    ) -> SidResult<sid_core::models::ServiceBinding> {
        let mut inner = self.inner.lock().unwrap();
        let now = chrono::Utc::now();
        if let Some(existing) = inner
            .service_bindings
            .iter_mut()
            .find(|b| b.profile_id == profile_id && b.scope == *scope)
        {
            existing.last_used_at = now;
            return Ok(existing.clone());
        }
        if !inner.profiles.contains_key(&profile_id) {
            return Err(sid_core::Error::NotFound(format!("profile {profile_id}")));
        }
        let binding_index = inner
            .service_bindings
            .iter()
            .filter(|b| b.profile_id == profile_id)
            .map(|b| b.binding_index + 1)
            .max()
            .unwrap_or(0);
        let binding = sid_core::models::ServiceBinding {
            binding_id: sid_core::models::BindingId::generate(),
            profile_id,
            scope: scope.clone(),
            binding_index,
            created_at: now,
            last_used_at: now,
        };
        inner.owe(&ctx)?;
        inner.service_bindings.push(binding.clone());
        Ok(binding)
    }
    async fn find_service_binding(
        &self,
        profile_id: ProfileId,
        scope: &sid_core::models::BindingScope,
    ) -> SidResult<Option<sid_core::models::ServiceBinding>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .service_bindings
            .iter()
            .find(|b| b.profile_id == profile_id && b.scope == *scope)
            .cloned())
    }
    async fn list_service_bindings(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<sid_core::models::ServiceBinding>> {
        let inner = self.inner.lock().unwrap();
        let mut found: Vec<_> = inner
            .service_bindings
            .iter()
            .filter(|b| b.profile_id == profile_id)
            .cloned()
            .collect();
        found.sort_by_key(|b| b.binding_index);
        Ok(found)
    }
    async fn import_service_binding(
        &self,
        imported: &sid_core::models::ServiceBinding,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let clash = inner.service_bindings.iter().find(|b| {
            b.binding_id == imported.binding_id
                || (b.profile_id == imported.profile_id
                    && (b.scope == imported.scope || b.binding_index == imported.binding_index))
        });
        match clash {
            Some(b)
                if b.binding_id == imported.binding_id
                    && b.profile_id == imported.profile_id
                    && b.scope == imported.scope
                    && b.binding_index == imported.binding_index =>
            {
                Ok(false)
            }
            Some(_) => Err(sid_core::Error::Conflict(format!(
                "binding {} collides with a stored binding",
                imported.binding_id
            ))),
            None => {
                inner.owe(&ctx)?;
                inner.service_bindings.push(imported.clone());
                Ok(true)
            }
        }
    }
    async fn list_credentials_by_type(
        &self,
        credential_type: CredentialType,
        after: Option<CredentialId>,
        limit: u32,
    ) -> SidResult<Vec<Credential>> {
        let inner = self.inner.lock().unwrap();
        let mut found: Vec<Credential> = inner
            .credentials
            .values()
            .filter(|c| c.credential_type == credential_type)
            .filter(|c| after.is_none_or(|a| c.id.0 > a.0))
            .cloned()
            .collect();
        found.sort_by_key(|c| c.id.0);
        found.truncate(limit as usize);
        Ok(found)
    }
    async fn register_dynamic_client(
        &self,
        app: &Application,
        client: &OAuth2Client,
        iat: InitialAccessTokenId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if client.application_id != app.id || client.project_id != app.project_id {
            return Err(sid_core::Error::Validation(
                "registered client names another application".into(),
            ));
        }
        let token = inner
            .initial_access_tokens
            .get(&iat.0)
            .ok_or_else(|| sid_core::Error::NotFound(format!("initial access token {}", iat.0)))?;
        if token.revoked {
            return Err(sid_core::Error::Revoked("initial access token".into()));
        }
        if token.expires_at <= chrono::Utc::now() {
            return Err(sid_core::Error::Expired("initial access token".into()));
        }
        if token.max_clients > 0 && token.clients_registered >= token.max_clients {
            return Err(sid_core::Error::InvalidState(
                "initial access token reached its client limit".into(),
            ));
        }
        if inner.applications.contains_key(&app.id) {
            return Err(sid_core::Error::Conflict("application exists".into()));
        }
        inner.applications.insert(app.id, app.clone());
        if let Err(e) = inner.check_new_client(client) {
            inner.applications.remove(&app.id);
            return Err(e);
        }
        if let Some(token) = inner.initial_access_tokens.get_mut(&iat.0) {
            token.clients_registered += 1;
        }
        inner
            .oauth2_clients
            .insert(client.client_id.clone(), client.clone());
        Ok(())
    }
    async fn get_initial_access_token(
        &self,
        id: InitialAccessTokenId,
    ) -> SidResult<Option<InitialAccessToken>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.initial_access_tokens.get(&id.0).cloned())
    }
    async fn get_initial_access_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<InitialAccessToken>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .initial_access_tokens
            .values()
            .find(|t| t.token_hash == token_hash)
            .cloned())
    }
    async fn list_initial_access_tokens_by_project(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<InitialAccessToken>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .initial_access_tokens
            .values()
            .filter(|t| t.project_id == project_id)
            .cloned()
            .collect())
    }
    async fn revoke_initial_access_token(
        &self,
        id: InitialAccessTokenId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(iat) = inner.initial_access_tokens.get_mut(&id.0) {
            iat.revoked = true;
        }
        Ok(())
    }

    // === PROJECT OPERATIONS ===
    async fn get_project(&self, id: ProjectId) -> SidResult<Option<Project>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.projects.get(&id.0).cloned())
    }

    async fn create_project(&self, project: &Project, ctx: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.projects.contains_key(&project.id.0) {
            return Err(sid_core::Error::Conflict("project already exists".into()));
        }
        inner.owe(&ctx)?;
        inner.projects.insert(project.id.0, project.clone());
        Ok(())
    }

    async fn update_project(
        &self,
        id: ProjectId,
        change: &sid_core::models::ProjectChange,
        ctx: MutationContext,
    ) -> SidResult<Option<Project>> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.projects.get(&id.0).is_some_and(|p| !p.is_system) {
            return Ok(None);
        }
        inner.owe(&ctx)?;
        let project = inner.projects.get_mut(&id.0).expect("checked above");
        if let Some(name) = &change.name {
            project.name = name.clone();
        }
        if let Some(description) = &change.description {
            project.description = description.clone();
        }
        project.updated_at = change.updated_at;
        Ok(Some(project.clone()))
    }

    async fn delete_project(&self, id: ProjectId, _audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(project) = inner.projects.get(&id.0)
            && project.is_system
        {
            return Err(sid_core::Error::Validation(
                "Cannot delete system project".into(),
            ));
        }
        inner.projects.remove(&id.0);
        Ok(())
    }

    async fn list_projects(&self, offset: u64, limit: u64) -> SidResult<Vec<Project>> {
        let inner = self.inner.lock().unwrap();
        let projects: Vec<_> = inner
            .projects
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(projects)
    }

    async fn count_projects(&self) -> SidResult<u64> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.projects.len() as u64)
    }

    async fn list_oauth2_clients_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<OAuth2Client>> {
        let inner = self.inner.lock().unwrap();
        let clients: Vec<_> = inner
            .oauth2_clients
            .values()
            .filter(|c| c.project_id == project_id)
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(clients)
    }

    async fn ensure_system_project(&self, _audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let system_id = ProjectId::system();
        if !inner.projects.contains_key(&system_id.0) {
            let system = Project::system();
            inner.projects.insert(system.id.0, system);
        }
        Ok(())
    }

    // === ROLE OPERATIONS (RBAC) ===
    async fn get_role(&self, id: RoleId) -> SidResult<Option<Role>> {
        Ok(self.inner.lock().unwrap().roles.get(&id).cloned())
    }
    async fn get_role_by_name(&self, p: ProjectId, n: &str) -> SidResult<Option<Role>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .roles
            .values()
            .find(|r| r.project_id == p && r.name == n)
            .cloned())
    }
    async fn create_role(&self, r: &Role, _audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        // A project holds one role per key and per name; a role is never replaced.
        if inner.roles.contains_key(&r.id)
            || inner
                .roles
                .values()
                .any(|s| s.project_id == r.project_id && (s.key == r.key || s.name == r.name))
        {
            return Err(sid_core::Error::Conflict(format!("role {}", r.key)));
        }
        inner.roles.insert(r.id, r.clone());
        Ok(())
    }
    async fn update_role(&self, r: &Role, _audit: MutationContext) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.roles.get_mut(&r.id) {
            Some(stored) if stored.revision == r.revision => {
                let key = stored.key.clone();
                *stored = r.clone();
                stored.key = key;
                stored.revision += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn update_role_fenced(
        &self,
        r: &Role,
        fence: &sid_core::models::RoleEditFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        {
            let inner = self.inner.lock().unwrap();
            let fenced = |what: &str| Err(sid_core::Error::Fenced(format!("{what} changed")));
            if let Some((authority, revision)) = fence.authority {
                let held = inner
                    .role_assignments
                    .iter()
                    .any(|a| a.id == authority && a.revision == revision && !a.is_expired());
                if !held {
                    return fenced("the editor's authority");
                }
            }
            if let Some(bounded) = &fence.bounded {
                let unseen = inner.role_assignments.iter().any(|a| {
                    a.role_id == r.id
                        && a.provenance.as_ref().is_some_and(|p| p.ceiling.is_some())
                        && !bounded.contains(&a.id)
                });
                if unseen {
                    return fenced("the approved assignments");
                }
            }
        }
        self.update_role(r, audit).await
    }
    async fn delete_role(&self, id: RoleId, _audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.roles.remove(&id);
        inner.role_assignments.retain(|a| a.role_id != id);
        Ok(())
    }
    async fn list_roles(&self, p: ProjectId) -> SidResult<Vec<Role>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .roles
            .values()
            .filter(|r| r.project_id == p)
            .cloned()
            .collect())
    }

    // === GROUP OPERATIONS — stubs ===
    async fn get_group(&self, _id: GroupId) -> SidResult<Option<Group>> {
        Ok(None)
    }
    async fn create_group(&self, _g: &Group, _audit: MutationContext) -> SidResult<()> {
        Ok(())
    }
    async fn set_group_description(
        &self,
        _id: GroupId,
        _description: Option<&str>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        // No group is ever stored, so none can be changed.
        Ok(false)
    }
    async fn delete_group(&self, _id: GroupId, _audit: MutationContext) -> SidResult<()> {
        Ok(())
    }
    async fn list_groups(&self, _p: ProjectId) -> SidResult<Vec<Group>> {
        Ok(vec![])
    }
    async fn add_to_group(&self, _m: &GroupMember, _audit: MutationContext) -> SidResult<()> {
        Ok(())
    }
    async fn remove_from_group(
        &self,
        _g: GroupId,
        _p: ProfileId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_group_members(&self, _g: GroupId) -> SidResult<Vec<GroupMember>> {
        Ok(vec![])
    }
    async fn list_groups_for_profile(&self, _p: ProfileId) -> SidResult<Vec<Group>> {
        Ok(vec![])
    }

    // === ROLE ASSIGNMENT OPERATIONS ===
    async fn create_role_assignment(
        &self,
        a: &RoleAssignment,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.role_assignments.iter().any(|s| s.id == a.id) {
            return Err(sid_core::Error::Conflict(format!("assignment {}", a.id.0)));
        }
        // An OAuth client principal must exist, as its foreign key requires.
        if let RoleAssignmentPrincipal::OAuthClient(client) = &a.principal
            && !inner.oauth2_clients.contains_key(client)
        {
            return Err(sid_core::Error::Storage(format!(
                "oauth client {client} does not exist"
            )));
        }
        inner.role_assignments.push(a.clone());
        Ok(())
    }
    async fn delete_role_assignment(
        &self,
        id: RoleAssignmentId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        self.inner.lock().unwrap().remove_assignment(id);
        Ok(())
    }
    async fn get_role_assignment(&self, id: RoleAssignmentId) -> SidResult<Option<RoleAssignment>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .role_assignments
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }
    async fn create_role_assignment_fenced(
        &self,
        a: &RoleAssignment,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.inner.lock().unwrap().check_fence(fence)?;
        self.create_role_assignment(a, audit).await
    }
    async fn delete_role_assignment_fenced(
        &self,
        id: RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        inner.check_fence(fence)?;
        Ok(inner.remove_assignment(id))
    }
    async fn list_role_assignments_for_profile(
        &self,
        p: ProfileId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.assignments_where(|a| a.principal == RoleAssignmentPrincipal::Profile(p))
    }
    async fn list_role_assignments_for_group(&self, g: GroupId) -> SidResult<Vec<RoleAssignment>> {
        self.assignments_where(|a| a.principal == RoleAssignmentPrincipal::Group(g))
    }
    async fn list_role_assignments_for_machine_user(
        &self,
        m: MachineUserId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.assignments_where(|a| a.principal == RoleAssignmentPrincipal::MachineUser(m))
    }
    async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.assignments_where(
            |a| matches!(&a.principal, RoleAssignmentPrincipal::OAuthClient(c) if c == client_id),
        )
    }
    async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector: sid_ids::ProvisioningConnectorId,
    ) -> SidResult<Vec<RoleAssignment>> {
        self.assignments_where(|a| {
            matches!(&a.principal, RoleAssignmentPrincipal::ProvisioningConnector(c) if *c == connector)
        })
    }
    async fn list_role_assignments_for_role(&self, r: RoleId) -> SidResult<Vec<RoleAssignment>> {
        self.assignments_where(|a| a.role_id == r)
    }
    async fn list_expiring_role_assignments(
        &self,
        _within_hours: i64,
    ) -> SidResult<Vec<RoleAssignment>> {
        Ok(vec![])
    }
    async fn cleanup_expired_role_assignments(
        &self,
        _audit: MutationContext,
    ) -> SidResult<Vec<RoleAssignment>> {
        Ok(vec![])
    }
    async fn list_sod_rules(&self) -> SidResult<Vec<SodConflictRule>> {
        Ok(vec![])
    }

    // === CEDAR POLICY OPERATIONS — stubs ===
    async fn get_cedar_policy(&self, _id: CedarPolicyId) -> SidResult<Option<CedarPolicy>> {
        Ok(None)
    }
    async fn create_cedar_policy(
        &self,
        _p: &CedarPolicy,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn update_cedar_policy(
        &self,
        _p: &CedarPolicy,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn delete_cedar_policy(
        &self,
        _id: CedarPolicyId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_cedar_policies(&self, _p: ProjectId) -> SidResult<Vec<CedarPolicy>> {
        Ok(vec![])
    }

    // === PROFILE METADATA ===
    async fn get_profile_metadata(
        &self,
        _profile_id: ProfileId,
        _key: &str,
    ) -> SidResult<Option<ProfileMetadata>> {
        Ok(None)
    }
    async fn set_profile_metadata(
        &self,
        metadata: &ProfileMetadata,
        _audit: MutationContext,
    ) -> SidResult<()> {
        if !self
            .inner
            .lock()
            .unwrap()
            .profiles
            .contains_key(&metadata.profile_id)
        {
            return Err(sid_core::Error::NotFound(format!(
                "profile {}",
                metadata.profile_id
            )));
        }
        Ok(())
    }
    async fn delete_profile_metadata(
        &self,
        _profile_id: ProfileId,
        _key: &str,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_profile_metadata(
        &self,
        _profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileMetadata>> {
        if self.inner.lock().unwrap().contact_reads_fail {
            return Err(sid_core::Error::Storage("read profile metadata".into()));
        }
        Ok(vec![])
    }

    // === PROFILE GRANT OPERATIONS — stubs ===
    async fn get_profile_grant(&self, _id: ProfileGrantId) -> SidResult<Option<ProfileGrant>> {
        Ok(None)
    }
    async fn create_profile_grant(
        &self,
        _grant: &ProfileGrant,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn delete_profile_grant(
        &self,
        _id: ProfileGrantId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_profile_grants_for_profile(
        &self,
        _profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileGrant>> {
        Ok(vec![])
    }
    async fn list_profile_grants_for_project(
        &self,
        _project_id: ProjectId,
    ) -> SidResult<Vec<ProfileGrant>> {
        Ok(vec![])
    }

    // === DEVICE MANAGEMENT ===
    async fn create_device(&self, device: &Device, audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.devices.insert(device.id, device.clone());
        inner.device_audits.push(audit.audit);
        Ok(())
    }
    async fn rename_device(
        &self,
        id: DeviceId,
        display_name: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(device) = inner.devices.get_mut(&id) else {
            return Ok(false);
        };
        device.display_name = display_name.map(str::to_owned);
        inner.device_audits.push(audit.audit);
        Ok(true)
    }
    async fn set_device_trust(
        &self,
        id: DeviceId,
        trusted: bool,
        max_trusted: usize,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DeviceTrustChange> {
        use sid_core::models::DeviceTrustChange;
        let mut inner = self.inner.lock().unwrap();
        let Some(device) = inner.devices.get(&id).cloned() else {
            return Ok(DeviceTrustChange::NotFound);
        };
        if device.trusted == trusted {
            return Ok(DeviceTrustChange::Unchanged);
        }
        let already_trusted = inner
            .devices
            .values()
            .filter(|d| d.profile_id == device.profile_id && d.trusted)
            .count();
        if trusted && already_trusted >= max_trusted {
            return Ok(DeviceTrustChange::LimitReached);
        }
        inner.devices.get_mut(&id).expect("read above").trusted = trusted;
        inner.device_audits.push(audit.audit);
        Ok(DeviceTrustChange::Changed)
    }
    async fn get_device(&self, id: DeviceId) -> SidResult<Option<Device>> {
        Ok(self.inner.lock().unwrap().devices.get(&id).cloned())
    }
    async fn list_devices_by_profile(&self, profile_id: ProfileId) -> SidResult<Vec<Device>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .devices
            .values()
            .filter(|d| d.profile_id == profile_id)
            .cloned()
            .collect())
    }
    async fn delete_device(&self, id: DeviceId, audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.devices.remove(&id);
        inner.device_audits.push(audit.audit);
        Ok(())
    }
    async fn get_device_by_fingerprint(
        &self,
        _profile_id: ProfileId,
        _fingerprint_hash: &str,
    ) -> SidResult<Option<Device>> {
        Ok(None)
    }

    // === DEVICE ATTESTATION — stubs ===
    async fn create_device_attestation(
        &self,
        _att: &sid_core::models::DeviceAttestation,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn rotate_device_attestation(
        &self,
        _device_id: DeviceId,
        _device_public_key: &[u8],
        _attestation_object: Option<&[u8]>,
        _attestation_certificate: Option<&[u8]>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn revoke_device_attestation(
        &self,
        _device_id: DeviceId,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn get_device_attestation(
        &self,
        _id: sid_core::models::DeviceAttestationId,
    ) -> SidResult<Option<sid_core::models::DeviceAttestation>> {
        Ok(None)
    }
    async fn get_device_attestation_by_device_id(
        &self,
        _device_id: DeviceId,
    ) -> SidResult<Option<sid_core::models::DeviceAttestation>> {
        Ok(None)
    }
    async fn list_device_attestations_by_profile(
        &self,
        _profile_id: ProfileId,
    ) -> SidResult<Vec<sid_core::models::DeviceAttestation>> {
        Ok(vec![])
    }
    async fn delete_device_attestation(
        &self,
        _device_id: DeviceId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }

    // === DEVICE AUTHORIZATION — stubs ===
    async fn create_device_auth_code(
        &self,
        code: &DeviceAuthorizationCode,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let taken = inner.device_codes.values().any(|c| {
            c.id == code.id
                || c.device_code_hash == code.device_code_hash
                || c.user_code == code.user_code
        });
        if taken {
            return Err(sid_core::Error::Conflict(
                "device authorization already exists".into(),
            ));
        }
        inner.owe(&audit)?;
        inner.device_codes.insert(code.id, code.clone());
        Ok(())
    }
    async fn get_device_auth_by_device_code_hash(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<DeviceAuthorizationCode>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .device_codes
            .values()
            .find(|c| c.device_code_hash == hash)
            .cloned())
    }
    async fn get_device_auth_by_user_code(
        &self,
        code: &str,
    ) -> SidResult<Option<DeviceAuthorizationCode>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .device_codes
            .values()
            .find(|c| c.user_code == code)
            .cloned())
    }
    async fn decide_device_auth(
        &self,
        id: DeviceAuthCodeId,
        decision: sid_core::models::DeviceAuthDecision,
        audit: MutationContext,
    ) -> SidResult<bool> {
        use sid_core::models::DeviceAuthDecision;
        let mut inner = self.inner.lock().unwrap();
        let pending = inner
            .device_codes
            .get(&id)
            .is_some_and(|c| c.status == DeviceAuthStatus::Pending && !c.is_expired());
        if !pending {
            return Ok(false);
        }
        inner.owe(&audit)?;
        let code = inner.device_codes.get_mut(&id).expect("checked above");
        let pending = code.as_pending().expect("checked above");
        match decision {
            DeviceAuthDecision::Authorize(profile_id) => pending.authorize(profile_id),
            DeviceAuthDecision::Deny => pending.deny(),
        }
        Ok(true)
    }
    async fn record_device_poll(
        &self,
        id: DeviceAuthCodeId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DevicePoll> {
        use sid_core::models::DevicePoll;
        let mut inner = self.inner.lock().unwrap();
        inner.owe(&audit)?;
        let code = inner
            .device_codes
            .get_mut(&id)
            .ok_or_else(|| sid_core::Error::NotFound(format!("device authorization {id}")))?;
        let now = chrono::Utc::now();
        let too_soon = code
            .last_polled_at
            .is_some_and(|t| now - t < chrono::Duration::seconds(code.interval.into()));
        code.last_polled_at = Some(now);
        if too_soon {
            code.interval += 5;
            return Ok(DevicePoll::SlowDown);
        }
        Ok(DevicePoll::Allowed)
    }
    async fn redeem_device_code(
        &self,
        hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DeviceCodeRedemption> {
        use sid_core::models::DeviceCodeRedemption;
        // One lock covers the check and the writes, like the database transaction.
        let mut inner = self.inner.lock().unwrap();
        let Some(code) = inner
            .device_codes
            .values()
            .find(|c| c.device_code_hash == hash)
        else {
            return Ok(DeviceCodeRedemption::NotAuthorized);
        };
        match code.status {
            DeviceAuthStatus::Redeemed => {
                return Ok(DeviceCodeRedemption::AlreadyRedeemed {
                    session_id: code.redeemed_session_id,
                });
            }
            DeviceAuthStatus::Authorized if !code.is_expired() => {}
            _ => return Ok(DeviceCodeRedemption::NotAuthorized),
        }
        let id = code.id;
        inner.owe(&audit)?;
        let code = inner.device_codes.get_mut(&id).expect("found above");
        code.status = DeviceAuthStatus::Redeemed;
        code.redeemed_session_id = Some(session.id);
        inner.sessions.insert(session.id, session.clone());
        inner
            .refresh_tokens_by_hash
            .insert(refresh_token.token_hash.clone(), refresh_token.clone());
        Ok(DeviceCodeRedemption::Redeemed)
    }
    async fn cleanup_expired_device_auth_codes(&self, _audit: MutationContext) -> SidResult<u64> {
        Ok(0)
    }

    // === UPSTREAM PROVIDER — stubs ===
    async fn get_upstream_provider(
        &self,
        _id: UpstreamProviderId,
    ) -> SidResult<Option<UpstreamProvider>> {
        Ok(None)
    }
    async fn create_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.inner
            .lock()
            .unwrap()
            .upstream_creations
            .push((provider.clone(), audit.audit));
        Ok(())
    }
    async fn update_upstream_provider(
        &self,
        _provider: &UpstreamProvider,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn delete_upstream_provider(
        &self,
        _id: UpstreamProviderId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_enabled_upstream_providers(&self) -> SidResult<Vec<UpstreamProvider>> {
        Ok(vec![])
    }

    // === UPSTREAM IDENTITY — stubs ===
    async fn get_upstream_identity_by_provider_subject(
        &self,
        _provider_id: UpstreamProviderId,
        _upstream_subject: &str,
    ) -> SidResult<Option<UpstreamIdentity>> {
        Ok(None)
    }
    async fn create_upstream_identity(
        &self,
        _identity: &UpstreamIdentity,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn record_upstream_login(
        &self,
        _id: sid_core::models::UpstreamIdentityId,
        _login: &sid_core::models::UpstreamLogin,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn list_upstream_identities_by_profile(
        &self,
        _profile_id: ProfileId,
    ) -> SidResult<Vec<UpstreamIdentity>> {
        Ok(vec![])
    }
    async fn delete_upstream_identity(
        &self,
        _id: UpstreamIdentityId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }

    // === PERSONAL ACCESS TOKEN — stubs ===
    async fn get_pat(&self, _id: PatId) -> SidResult<Option<PersonalAccessToken>> {
        Ok(None)
    }
    async fn get_pat_by_token_hash(
        &self,
        _token_hash: &str,
    ) -> SidResult<Option<PersonalAccessToken>> {
        Ok(None)
    }
    async fn create_pat(
        &self,
        _pat: &PersonalAccessToken,
        _active_limit: Option<u64>,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn record_pat_use(
        &self,
        _id: PatId,
        _ip: Option<&str>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn revoke_pat(
        &self,
        _id: PatId,
        _revoked_by: &str,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn list_pats_by_profile(
        &self,
        _profile_id: ProfileId,
    ) -> SidResult<Vec<PersonalAccessToken>> {
        Ok(vec![])
    }
    async fn list_all_pats(&self) -> SidResult<Vec<PersonalAccessToken>> {
        Ok(vec![])
    }
    async fn count_active_pats_by_profile(&self, _profile_id: ProfileId) -> SidResult<u64> {
        Ok(0)
    }
    async fn revoke_active_pats_by_profile(
        &self,
        _profile_id: ProfileId,
        _revoked_by: &str,
        _audit: MutationContext,
    ) -> SidResult<u64> {
        Ok(0)
    }
    async fn revoke_unused_pats(&self, _days: u32, _audit: MutationContext) -> SidResult<u64> {
        Ok(0)
    }

    // === MACHINE USER — stubs ===
    async fn get_machine_user(&self, id: MachineUserId) -> SidResult<Option<MachineUser>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.machine_users.get(&id).cloned())
    }
    async fn get_machine_user_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<MachineUser>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .machine_users
            .values()
            .find(|mu| mu.client_id == client_id)
            .cloned())
    }
    async fn create_machine_user(&self, mu: &MachineUser, audit: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.machine_users.contains_key(&mu.id) {
            return Err(sid_core::Error::Conflict(
                "machine user already exists".into(),
            ));
        }
        inner.machine_users.insert(mu.id, mu.clone());
        inner.machine_user_audits.push(audit.audit);
        Ok(())
    }
    async fn update_machine_user(
        &self,
        mu: &MachineUser,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(stored) = inner.machine_users.get_mut(&mu.id) else {
            return Ok(false);
        };
        if stored.status == sid_core::models::machine_user::MachineUserStatus::Deleted {
            return Ok(false);
        }
        let status = stored.status;
        *stored = mu.clone();
        stored.status = status;
        stored.updated_at = chrono::Utc::now();
        Ok(true)
    }
    async fn transition_machine_user(
        &self,
        id: MachineUserId,
        from: sid_core::models::machine_user::MachineUserStatus,
        to: sid_core::models::machine_user::MachineUserStatus,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.machine_users.get_mut(&id) {
            Some(stored) if stored.status == from => {
                stored.status = to;
                stored.updated_at = chrono::Utc::now();
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn delete_machine_user(
        &self,
        id: MachineUserId,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        // A deleted machine user keeps no access to any resource.
        if let Some(mu) = inner.machine_users.remove(&id) {
            inner
                .resource_access
                .retain(|a| a.client_id != mu.client_id);
        }
        Ok(())
    }
    async fn list_machine_users_by_project(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<MachineUser>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .machine_users
            .values()
            .filter(|mu| mu.project_id == project_id)
            .cloned()
            .collect())
    }

    // === MACHINE USER CREDENTIAL ===
    async fn get_machine_credential_by_kid(
        &self,
        kid: &str,
    ) -> SidResult<Option<MachineUserCredential>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .machine_credentials
            .iter()
            .find(|c| c.kid == kid)
            .cloned())
    }
    async fn get_provisioning_connector(
        &self,
        id: ProvisioningConnectorId,
    ) -> SidResult<Option<ProvisioningConnector>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .provisioning_connectors
            .get(&id)
            .cloned())
    }

    async fn get_provisioning_connector_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<ProvisioningConnector>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .provisioning_connectors
            .values()
            .find(|c| c.client_id == client_id)
            .cloned())
    }

    async fn list_provisioning_connectors(
        &self,
        org_id: OrgId,
    ) -> SidResult<Vec<ProvisioningConnector>> {
        let inner = self.inner.lock().unwrap();
        let mut found: Vec<_> = inner
            .provisioning_connectors
            .values()
            .filter(|c| c.org_id == org_id)
            .cloned()
            .collect();
        found.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        Ok(found)
    }

    async fn create_provisioning_connector(
        &self,
        connector: &ProvisioningConnector,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.provisioning_connectors.contains_key(&connector.id)
            || inner
                .provisioning_connectors
                .values()
                .any(|c| c.client_id == connector.client_id)
        {
            return Err(sid_core::Error::Conflict(
                "provisioning connector already exists".into(),
            ));
        }
        inner.owe(&ctx)?;
        inner
            .provisioning_connectors
            .insert(connector.id, connector.clone());
        Ok(())
    }

    async fn rename_provisioning_connector(
        &self,
        id: ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(c) = inner.provisioning_connectors.get(&id) else {
            return Ok(false);
        };
        if c.revision != revision || c.state == ConnectorState::Retired {
            return Ok(false);
        }
        inner.owe(&ctx)?;
        let c = inner
            .provisioning_connectors
            .get_mut(&id)
            .expect("read above");
        c.display_name = display_name.to_string();
        c.revision += 1;
        c.updated_at = chrono::Utc::now();
        Ok(true)
    }

    async fn transition_provisioning_connector(
        &self,
        id: ProvisioningConnectorId,
        from: ConnectorState,
        to: ConnectorState,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !from.may_become(to)
            || inner.provisioning_connectors.get(&id).map(|c| c.state) != Some(from)
        {
            return Ok(false);
        }
        inner.owe(&ctx)?;
        let c = inner
            .provisioning_connectors
            .get_mut(&id)
            .expect("read above");
        c.state = to;
        c.revision += 1;
        c.updated_at = chrono::Utc::now();
        if to == ConnectorState::Retired {
            for cred in inner
                .provisioning_credentials
                .iter_mut()
                .filter(|cred| cred.connector_id == id && cred.status.is_usable())
            {
                cred.status = sid_core::models::machine_user::CredentialStatus::Revoked;
            }
        }
        Ok(true)
    }

    async fn add_provisioning_credential(
        &self,
        credential: &ProvisioningCredential,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .provisioning_connectors
            .get(&credential.connector_id)
            .is_some_and(ProvisioningConnector::is_active)
        {
            return Ok(false);
        }
        if inner
            .provisioning_credentials
            .iter()
            .any(|c| c.id == credential.id || c.verifier == credential.verifier)
        {
            return Err(sid_core::Error::Conflict(
                "provisioning credential already exists".into(),
            ));
        }
        let usable = inner
            .provisioning_credentials
            .iter()
            .filter(|c| c.connector_id == credential.connector_id && c.status.is_usable())
            .count();
        if usable >= sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS {
            return Err(sid_core::Error::ResourceExhausted(
                "too many connector credentials".into(),
            ));
        }
        inner.owe(&ctx)?;
        inner.provisioning_credentials.push(credential.clone());
        Ok(true)
    }

    async fn rotate_provisioning_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        old: ProvisioningCredentialId,
        new: &ProvisioningCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        use sid_core::models::machine_user::CredentialStatus;

        let mut inner = self.inner.lock().unwrap();
        let active_connector = inner
            .provisioning_connectors
            .get(&connector_id)
            .is_some_and(ProvisioningConnector::is_active);
        let Some(index) = inner.provisioning_credentials.iter().position(|c| {
            c.id == old && c.connector_id == connector_id && c.status == CredentialStatus::Active
        }) else {
            return Ok(false);
        };
        if !active_connector {
            return Ok(false);
        }
        if inner
            .provisioning_credentials
            .iter()
            .any(|c| c.id == new.id || c.verifier == new.verifier)
        {
            return Err(sid_core::Error::Conflict(
                "provisioning credential already exists".into(),
            ));
        }
        inner.owe(&ctx)?;
        let old_cred = &mut inner.provisioning_credentials[index];
        old_cred.status = CredentialStatus::GracePeriod;
        old_cred.expires_at = Some(grace_until);
        inner.provisioning_credentials.push(new.clone());
        Ok(true)
    }

    async fn revoke_provisioning_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        id: ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(index) = inner
            .provisioning_credentials
            .iter()
            .position(|c| c.id == id && c.connector_id == connector_id && c.status.is_usable())
        else {
            return Ok(false);
        };
        inner.owe(&ctx)?;
        inner.provisioning_credentials[index].status =
            sid_core::models::machine_user::CredentialStatus::Revoked;
        Ok(true)
    }

    async fn list_provisioning_credentials(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> SidResult<Vec<ProvisioningCredential>> {
        let inner = self.inner.lock().unwrap();
        let mut found: Vec<_> = inner
            .provisioning_credentials
            .iter()
            .filter(|c| c.connector_id == connector_id)
            .cloned()
            .collect();
        found.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(found)
    }

    async fn find_provisioning_credential(
        &self,
        verifier: &str,
    ) -> SidResult<Option<(ProvisioningCredential, ProvisioningConnector)>> {
        let inner = self.inner.lock().unwrap();
        let Some(cred) = inner
            .provisioning_credentials
            .iter()
            .find(|c| c.verifier == verifier)
        else {
            return Ok(None);
        };
        let connector = inner
            .provisioning_connectors
            .get(&cred.connector_id)
            .cloned()
            .ok_or_else(|| {
                sid_core::Error::Storage(format!("credential {} names no connector", cred.id))
            })?;
        Ok(Some((cred.clone(), connector)))
    }

    async fn add_machine_credential(
        &self,
        cred: &MachineUserCredential,
        active_limit: Option<u64>,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.machine_credentials.iter().any(|c| c.kid == cred.kid) {
            return Err(sid_core::Error::Conflict(
                "machine credential already exists".into(),
            ));
        }
        let usable = inner
            .machine_credentials
            .iter()
            .filter(|c| c.machine_user_id == cred.machine_user_id && c.status.is_usable())
            .count() as u64;
        if active_limit.is_some_and(|limit| usable >= limit) {
            return Err(sid_core::Error::ResourceExhausted(
                "too many machine credentials".into(),
            ));
        }
        inner.machine_credentials.push(cred.clone());
        Ok(())
    }
    async fn rotate_machine_credential(
        &self,
        machine_user_id: MachineUserId,
        old_kid: &str,
        new: &MachineUserCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(old) = inner.machine_credentials.iter_mut().find(|c| {
            c.kid == old_kid
                && c.machine_user_id == machine_user_id
                && c.status == sid_core::models::CredentialStatus::Active
        }) else {
            return Ok(false);
        };
        old.status = sid_core::models::CredentialStatus::GracePeriod;
        old.expires_at = Some(
            old.expires_at
                .map_or(grace_until, |own| own.min(grace_until)),
        );
        inner.machine_credentials.push(new.clone());
        Ok(true)
    }
    async fn revoke_machine_credential(
        &self,
        machine_user_id: MachineUserId,
        kid: &str,
        _audit: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner
            .machine_credentials
            .iter_mut()
            .find(|c| c.kid == kid && c.machine_user_id == machine_user_id && c.status.is_usable())
        {
            Some(c) => {
                c.status = sid_core::models::CredentialStatus::Revoked;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    async fn revoke_active_machine_credentials_by_user(
        &self,
        id: MachineUserId,
        _audit: MutationContext,
    ) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        let mut count = 0u64;
        for c in &mut inner.machine_credentials {
            if c.machine_user_id == id
                && matches!(c.status, sid_core::models::CredentialStatus::Active)
            {
                c.status = sid_core::models::CredentialStatus::Revoked;
                count += 1;
            }
        }
        Ok(count)
    }
    async fn list_machine_credentials_by_user(
        &self,
        id: MachineUserId,
    ) -> SidResult<Vec<MachineUserCredential>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .machine_credentials
            .iter()
            .filter(|c| c.machine_user_id == id)
            .cloned()
            .collect())
    }
    async fn list_expiring_machine_credentials(
        &self,
        _within_days: u32,
    ) -> SidResult<Vec<MachineUserCredential>> {
        Ok(vec![])
    }

    // === IMPERSONATION GRANT ===
    async fn save_impersonation_grant(
        &self,
        grant: &ImpersonationGrant,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.impersonation_grants.push(grant.clone());
        Ok(())
    }
    async fn delete_impersonation_grant(
        &self,
        machine_user_id: MachineUserId,
        target_type: &str,
        target: &str,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.impersonation_grants.retain(|g| {
            !(g.machine_user_id == machine_user_id
                && format!("{:?}", g.target_type).to_lowercase() == target_type
                && g.target == target)
        });
        Ok(())
    }
    async fn list_impersonation_grants(
        &self,
        machine_user_id: MachineUserId,
    ) -> SidResult<Vec<ImpersonationGrant>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .impersonation_grants
            .iter()
            .filter(|g| g.machine_user_id == machine_user_id)
            .cloned()
            .collect())
    }

    // === PRINCIPAL QUARANTINE ===
    async fn quarantine_principal(
        &self,
        _: &str,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn is_principal_quarantined(&self, _: &str) -> SidResult<bool> {
        Ok(false)
    }
    async fn cleanup_expired_quarantine(&self, _audit: MutationContext) -> SidResult<u64> {
        Ok(0)
    }

    // === CLOSURE REQUEST ===
    async fn create_closure_request(
        &self,
        _: &ClosureRequest,
        _audit: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn request_profile_closure(
        &self,
        profile: &Profile,
        _: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if profile.is_admin() {
            // As the stores do: another administrator must stay.
            let others = self
                .inner
                .lock()
                .unwrap()
                .profiles
                .values()
                .filter(|p| {
                    p.id != profile.id
                        && p.is_admin()
                        && matches!(
                            p.status,
                            sid_core::models::ProfileStatus::Active
                                | sid_core::models::ProfileStatus::Suspended
                        )
                })
                .count();
            if others == 0 {
                return Err(sid_core::Error::InvalidState(
                    "the last administrator cannot request closure".into(),
                ));
            }
        }
        self.update_profile(profile, ctx).await
    }
    async fn cancel_profile_closure(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_profile(profile, ctx).await
    }
    async fn get_closure_request(&self, _: ProfileId) -> SidResult<Option<ClosureRequest>> {
        Ok(None)
    }

    // === DATA EXPORT ===
    async fn create_export_job(&self, job: &ExportJob, _: MutationContext) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.export_jobs.contains_key(&job.id) {
            return Err(sid_core::Error::Conflict(
                "export job already exists".into(),
            ));
        }
        inner.export_jobs.insert(job.id, job.clone());
        Ok(())
    }
    async fn acknowledge_export_job(
        &self,
        id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.export_jobs.get_mut(&id) {
            Some(job)
                if job.status == ExportStatus::Ready && job.expires_at.is_some_and(|e| e > at) =>
            {
                job.status = ExportStatus::Downloaded;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn expire_export_job(
        &self,
        id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.export_jobs.get_mut(&id) {
            Some(job)
                if job.status == ExportStatus::Ready && job.expires_at.is_some_and(|e| e <= at) =>
            {
                job.status = ExportStatus::Expired;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn get_export_job(&self, profile_id: ProfileId) -> SidResult<Option<ExportJob>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .export_jobs
            .values()
            .filter(|j| j.profile_id == profile_id)
            .max_by_key(|j| j.created_at)
            .cloned())
    }
    async fn get_export_job_by_id(&self, id: uuid::Uuid) -> SidResult<Option<ExportJob>> {
        Ok(self.inner.lock().unwrap().export_jobs.get(&id).cloned())
    }

    // === MAGIC LINK ===
    async fn create_magic_link_session(
        &self,
        session: &MagicLinkSession,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.magic_links.contains_key(&session.id) {
            return Err(sid_core::Error::Conflict(
                "magic link already exists".into(),
            ));
        }
        inner.owe(&audit)?;
        inner.magic_links.insert(session.id, session.clone());
        Ok(())
    }
    async fn get_magic_link_session(&self, id: uuid::Uuid) -> SidResult<Option<MagicLinkSession>> {
        let inner = self.inner.lock().unwrap();
        if inner.magic_link_reads_fail {
            return Err(sid_core::Error::Storage("read magic link".into()));
        }
        Ok(inner.magic_links.get(&id).cloned())
    }
    async fn consume_magic_link_session(
        &self,
        id: uuid::Uuid,
        _audit: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(link) = inner.magic_links.get_mut(&id) {
            link.consumed = true;
        }
        Ok(())
    }
    async fn try_consume_magic_link_session(
        &self,
        id: uuid::Uuid,
        _audit: MutationContext,
    ) -> SidResult<Option<MagicLinkSession>> {
        let mut inner = self.inner.lock().unwrap();
        if inner.magic_link_consume_fails {
            return Err(sid_core::Error::Storage("consume magic link".into()));
        }
        match inner.magic_links.get_mut(&id) {
            Some(link) if !link.consumed => {
                link.consumed = true;
                Ok(Some(link.clone()))
            }
            _ => Ok(None),
        }
    }
    async fn delete_expired_magic_link_sessions(&self, _audit: MutationContext) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.magic_links.len();
        inner.magic_links.retain(|_, link| !link.is_expired());
        Ok((before - inner.magic_links.len()) as u64)
    }
    async fn count_active_magic_links_for_email(&self, email: &str) -> SidResult<u32> {
        let inner = self.inner.lock().unwrap();
        let active = inner
            .magic_links
            .values()
            .filter(|link| link.email == email && !link.consumed && !link.is_expired())
            .count();
        Ok(active as u32)
    }
    async fn create_scim_outbound_target(
        &self,
        _: &ScimOutboundTarget,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn get_scim_outbound_target(
        &self,
        _: ScimOutboundTargetId,
    ) -> SidResult<Option<ScimOutboundTarget>> {
        Ok(None)
    }
    async fn list_scim_outbound_targets(&self, _: ProjectId) -> SidResult<Vec<ScimOutboundTarget>> {
        Ok(vec![])
    }
    async fn delete_scim_outbound_target(
        &self,
        _: ScimOutboundTargetId,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn create_scim_outbound_record(
        &self,
        _: &ScimOutboundRecord,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn record_scim_outbound_sync(
        &self,
        _: &ScimOutboundRecord,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn record_scim_outbound_failure(
        &self,
        _: ScimOutboundTargetId,
        _: Uuid,
        _: sid_core::models::OutboundEntityType,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn get_scim_outbound_record(
        &self,
        _: ScimOutboundTargetId,
        _: Uuid,
        _: OutboundEntityType,
    ) -> SidResult<Option<ScimOutboundRecord>> {
        Ok(None)
    }
    async fn create_outbound_dlq_entry(
        &self,
        _: &OutboundDlqEntry,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_outbound_dlq_entries(
        &self,
        _: ScimOutboundTargetId,
    ) -> SidResult<Vec<OutboundDlqEntry>> {
        Ok(vec![])
    }
    async fn delete_outbound_dlq_entry(&self, _: Uuid, _: MutationContext) -> SidResult<()> {
        Ok(())
    }
    async fn get_flow_config(
        &self,
        _: ProjectId,
        _: sid_core::models::FlowType,
    ) -> SidResult<Option<sid_core::models::FlowConfig>> {
        Ok(None)
    }
    async fn save_flow_config(
        &self,
        _: &sid_core::models::FlowConfig,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn list_flow_configs(
        &self,
        _: ProjectId,
    ) -> SidResult<Vec<sid_core::models::FlowConfig>> {
        Ok(vec![])
    }
    async fn create_flow_action(
        &self,
        _: &sid_core::models::FlowAction,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn update_flow_action(
        &self,
        _: &sid_core::models::FlowAction,
        _: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn get_flow_action(
        &self,
        _: sid_core::models::ActionId,
    ) -> SidResult<Option<sid_core::models::FlowAction>> {
        Ok(None)
    }
    async fn list_flow_actions(
        &self,
        _: ProjectId,
        _: sid_core::models::FlowType,
        _: Option<sid_core::models::ActionPoint>,
    ) -> SidResult<Vec<sid_core::models::FlowAction>> {
        Ok(vec![])
    }
    async fn delete_flow_action(
        &self,
        _: sid_core::models::ActionId,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn create_branding_config(
        &self,
        _: &sid_core::models::BrandingConfig,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn update_branding_draft(
        &self,
        _: &sid_core::models::BrandingConfig,
        _: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn publish_branding_config(
        &self,
        _: sid_core::models::BrandingConfigId,
        _: ProjectId,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn get_published_branding(
        &self,
        _: ProjectId,
    ) -> SidResult<Option<sid_core::models::BrandingConfig>> {
        Ok(None)
    }
    async fn get_branding_config(
        &self,
        _: sid_core::models::BrandingConfigId,
    ) -> SidResult<Option<sid_core::models::BrandingConfig>> {
        Ok(None)
    }
    async fn list_branding_configs(
        &self,
        _: ProjectId,
    ) -> SidResult<Vec<sid_core::models::BrandingConfig>> {
        Ok(vec![])
    }
    async fn delete_branding_config(
        &self,
        _: sid_core::models::BrandingConfigId,
        _: MutationContext,
    ) -> SidResult<bool> {
        Ok(false)
    }
    async fn create_invite(
        &self,
        _: &sid_core::models::Invite,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn get_invite(
        &self,
        _: sid_core::models::InviteId,
    ) -> SidResult<Option<sid_core::models::Invite>> {
        Ok(None)
    }
    async fn get_invite_by_code(&self, _: &str) -> SidResult<Option<sid_core::models::Invite>> {
        Ok(None)
    }
    async fn list_invites(
        &self,
        _: &sid_core::models::InviteFilter,
        _: u64,
        _: u64,
    ) -> SidResult<Vec<sid_core::models::Invite>> {
        Ok(vec![])
    }
    async fn count_invites(&self, _: &sid_core::models::InviteFilter) -> SidResult<u64> {
        Ok(0)
    }
    async fn try_use_invite(
        &self,
        _: sid_core::models::InviteId,
        _: MutationContext,
    ) -> SidResult<Option<sid_core::models::Invite>> {
        Ok(None)
    }
    async fn revoke_invite(
        &self,
        _: sid_core::models::InviteId,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn get_registration_source(
        &self,
        _: ProfileId,
    ) -> SidResult<Option<sid_core::models::RegistrationSource>> {
        Ok(None)
    }
    async fn count_registrations_by_source(
        &self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<Vec<(sid_core::models::RegistrationSourceType, u64)>> {
        Ok(vec![])
    }
    async fn top_referrers(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: u64,
    ) -> SidResult<Vec<(ProfileId, u64)>> {
        Ok(vec![])
    }
    async fn try_job_lock(&self, _: i64) -> SidResult<Option<sid_plugin::storage::JobLock>> {
        unimplemented!("job locks are exercised by the storage conformance suite")
    }
    async fn ensure_audit_partition(&self, _: chrono::NaiveDate) -> SidResult<bool> {
        unimplemented!("audit retention is exercised by the storage conformance suite")
    }
    async fn drop_expired_audit_records(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: MutationContext,
    ) -> SidResult<u64> {
        unimplemented!("audit retention is exercised by the storage conformance suite")
    }
    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &OperationKey,
    ) -> SidResult<Option<OperationRecord>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .operations
            .get(&(namespace.to_string(), key.as_str().to_string()))
            .cloned())
    }
    async fn export_operation_results(&self) -> SidResult<Vec<OperationRecord>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .operations
            .values()
            .cloned()
            .collect())
    }
    async fn import_operation_result(&self, record: &OperationRecord) -> SidResult<bool> {
        let slot = (
            record.completion.namespace.clone(),
            record.completion.key.as_str().to_string(),
        );
        let mut inner = self.inner.lock().unwrap();
        if inner.operations.contains_key(&slot) {
            return Ok(false);
        }
        inner.operations.insert(slot, record.clone());
        Ok(true)
    }
    async fn get_notification_preferences(
        &self,
        _: sid_core::models::ProfileId,
    ) -> SidResult<Option<sid_core::models::notification::NotificationPreferences>> {
        Ok(None)
    }
    async fn save_notification_preferences(
        &self,
        _: &sid_core::models::notification::NotificationPreferences,
        _: MutationContext,
    ) -> SidResult<()> {
        Ok(())
    }
    async fn count_orphaned_sessions(&self) -> SidResult<u64> {
        Ok(0)
    }
    async fn count_orphaned_credentials(&self) -> SidResult<u64> {
        Ok(0)
    }
    async fn count_orphaned_role_assignments(&self) -> SidResult<u64> {
        Ok(0)
    }
    async fn create_access_request(
        &self,
        request: &sid_core::models::AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.access_requests.contains_key(&request.id.0) {
            return Err(sid_core::Error::Conflict(
                "access request already exists".into(),
            ));
        }
        inner.access_requests.insert(request.id.0, request.clone());
        inner.owe(&ctx)
    }
    async fn get_access_request(
        &self,
        id: sid_core::models::AccessRequestId,
    ) -> SidResult<Option<sid_core::models::AccessRequest>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .access_requests
            .get(&id.0)
            .cloned())
    }
    async fn list_pending_access_requests(
        &self,
    ) -> SidResult<Vec<sid_core::models::AccessRequest>> {
        let now = chrono::Utc::now();
        Ok(self
            .inner
            .lock()
            .unwrap()
            .access_requests
            .values()
            .filter(|r| {
                r.status == sid_core::models::AccessRequestStatus::Pending
                    && r.expires_at.is_none_or(|e| e > now)
            })
            .cloned()
            .collect())
    }
    async fn decide_access_request(
        &self,
        request: &sid_core::models::AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        request.check_plain_decision()?;
        let mut inner = self.inner.lock().unwrap();
        let Some(stored) = inner.access_requests.get_mut(&request.id.0) else {
            return Ok(false);
        };
        if stored.status != sid_core::models::AccessRequestStatus::Pending {
            return Ok(false);
        }
        stored.status = request.status;
        stored.reviewed_by = request.reviewed_by;
        stored.review_comment = request.review_comment.clone();
        stored.reviewed_at = request.reviewed_at;
        inner.owe(&ctx)?;
        Ok(true)
    }

    async fn approve_access_request(
        &self,
        request: &sid_core::models::AccessRequest,
        grant: &RoleAssignment,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        request.check_approval(grant)?;
        let mut inner = self.inner.lock().unwrap();
        match inner.access_requests.get(&request.id.0) {
            Some(stored) if stored.status == sid_core::models::AccessRequestStatus::Pending => {}
            _ => return Ok(false),
        }
        // The assignment is checked before anything is written, as one
        // transaction would roll back both.
        if !inner.roles.contains_key(&grant.role_id) {
            return Err(sid_core::Error::Storage(format!(
                "role {} does not exist",
                grant.role_id.0
            )));
        }
        if inner.role_assignments.iter().any(|a| a.id == grant.id) {
            return Err(sid_core::Error::Conflict(format!(
                "assignment {}",
                grant.id.0
            )));
        }
        inner.owe(&ctx)?;
        let stored = inner
            .access_requests
            .get_mut(&request.id.0)
            .expect("checked above");
        stored.status = request.status;
        stored.reviewed_by = request.reviewed_by;
        stored.review_comment = request.review_comment.clone();
        stored.reviewed_at = request.reviewed_at;
        inner.role_assignments.push(grant.clone());
        Ok(true)
    }

    // ── Password Reset Session ──

    async fn create_reset_session(
        &self,
        session: &PasswordResetSession,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.reset_save_fails {
            return Err(sid_core::Error::Storage("save reset session".into()));
        }
        if inner.reset_sessions.contains_key(&session.id.0) {
            return Err(sid_core::Error::Conflict(
                "reset session already exists".into(),
            ));
        }
        inner.owe(&ctx)?;
        inner.reset_sessions.insert(session.id.0, session.clone());
        Ok(())
    }

    async fn get_reset_session(
        &self,
        id: ResetSessionId,
    ) -> SidResult<Option<PasswordResetSession>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .reset_sessions
            .get(&id.0)
            .cloned())
    }

    async fn verify_reset_session(
        &self,
        id: ResetSessionId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let Some(reset) = inner.reset_sessions.get_mut(&id.0) else {
            return Ok(false);
        };
        if reset.status != ResetSessionStatus::Pending || reset.is_expired() {
            return Ok(false);
        }
        reset.status = ResetSessionStatus::Verified;
        reset.verified_at = Some(chrono::Utc::now());
        inner.owe(&ctx)?;
        Ok(true)
    }

    async fn complete_password_reset(
        &self,
        id: ResetSessionId,
        credential: &Credential,
        history: Option<&HistoryCommit>,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Option<Vec<Session>>> {
        if history.is_some_and(|h| h.owner != credential.profile_id) {
            return Err(sid_core::Error::Validation(
                "password history belongs to the credential's profile".into(),
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        let Some(reset) = inner.reset_sessions.get(&id.0) else {
            return Ok(None);
        };
        if reset.status != ResetSessionStatus::Verified || reset.is_expired() {
            return Ok(None);
        }
        if reset.profile_id != credential.profile_id {
            return Err(sid_core::Error::Validation(
                "the new password belongs to another profile than the reset".into(),
            ));
        }
        if let Some(history) = history
            && !inner.apply_history(history)?
        {
            return Ok(None);
        }
        let reset = inner.reset_sessions.get_mut(&id.0).expect("checked above");
        reset.status = ResetSessionStatus::Completed;
        reset.completed_at = Some(chrono::Utc::now());
        let profile_id = reset.profile_id;
        inner.credentials.retain(|_, c| {
            c.profile_id != profile_id
                || !matches!(
                    c.credential_type,
                    CredentialType::Opaque | CredentialType::LegacyHash
                )
        });
        inner
            .credentials
            .insert(credential.id.0, credential.clone());
        let ended: Vec<Session> = inner
            .sessions
            .values()
            .filter(|s| s.profile_id == profile_id)
            .cloned()
            .collect();
        inner.sessions.retain(|_, s| s.profile_id != profile_id);
        for session in &ended {
            ctx.work.extend(end.owed_by(session));
        }
        inner.owe(&ctx)?;
        Ok(Some(ended))
    }

    async fn delete_expired_reset_sessions(&self, ctx: MutationContext) -> SidResult<u64> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.reset_sessions.len();
        inner
            .reset_sessions
            .retain(|_, s| !(s.is_expired() && s.status == ResetSessionStatus::Pending));
        let removed = (before - inner.reset_sessions.len()) as u64;
        inner.owe(&ctx)?;
        Ok(removed)
    }

    async fn get_email_provider_config(
        &self,
    ) -> SidResult<Option<sid_core::models::EmailProviderConfig>> {
        Ok(self.inner.lock().unwrap().email_provider.clone())
    }

    async fn upsert_email_provider_config(
        &self,
        config: &sid_core::models::EmailProviderConfig,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.email_provider = Some(config.clone());
        inner.owe(&ctx)
    }

    async fn count_active_reset_sessions(&self, profile_id: ProfileId) -> SidResult<u32> {
        let inner = self.inner.lock().unwrap();
        if inner.reset_count_fails {
            return Err(sid_core::Error::Storage("count reset sessions".into()));
        }
        let count = inner
            .reset_sessions
            .values()
            .filter(|s| {
                s.profile_id == profile_id
                    && !s.is_expired()
                    && matches!(
                        s.status,
                        ResetSessionStatus::Pending | ResetSessionStatus::Verified
                    )
            })
            .count();
        Ok(count as u32)
    }
}

impl MockStorageInner {
    /// Record `p`'s claim as the real backends do: one row per claim, all
    /// rows of a value sharing its entity state. A new value is first used by
    /// its claimant; an existing one keeps its assignment and proof. A login
    /// handle held by another subject is `Conflict`.
    fn bind_principal(&mut self, p: &Principal) -> SidResult<()> {
        self.check_login_handle(p)?;
        let entity = self
            .principals
            .values()
            .find(|r| r.principal_type == p.principal_type && r.value == p.value)
            .cloned();
        let mut row = p.clone();
        match entity {
            Some(e) => {
                row.id = e.id;
                row.verified = e.verified;
                row.verified_at = e.verified_at;
                row.verification_expires = e.verification_expires;
                row.assigned_profile_id = e.assigned_profile_id;
                row.assignment_revision = e.assignment_revision;
                row.created_at = e.created_at;
                row.updated_at = e.updated_at;
            }
            None => {
                row.assigned_profile_id = Some(p.profile_id);
                row.assignment_revision = 1;
            }
        }
        let key = self
            .principals
            .iter()
            .find(|(_, r)| r.id == row.id && r.profile_id == row.profile_id)
            .map_or_else(Uuid::now_v7, |(key, _)| *key);
        self.principals.insert(key, row);
        Ok(())
    }

    /// A login handle another profile holds refuses `p`'s claim.
    fn check_login_handle(&self, p: &Principal) -> SidResult<()> {
        let taken = !p.principal_type.is_contestable()
            && self.principals.values().any(|r| {
                r.principal_type == p.principal_type
                    && r.value == p.value
                    && r.profile_id != p.profile_id
            });
        if taken {
            return Err(sid_core::Error::Conflict(
                "login handle already exists".into(),
            ));
        }
        Ok(())
    }

    /// The claim rows of principal `id`.
    fn claims(&self, id: PrincipalId) -> impl Iterator<Item = &Principal> {
        self.principals.values().filter(move |r| r.id == id)
    }

    /// Remove session `id` and the sessions it authenticated; returns them.
    fn end_with_dependents(&mut self, id: SessionId) -> Vec<Session> {
        let ended: Vec<Session> = self
            .sessions
            .values()
            .filter(|s| s.id == id || s.authenticated_by == Some(id))
            .cloned()
            .collect();
        for session in &ended {
            self.sessions.remove(&session.id);
        }
        ended
    }

    /// Apply `commit` to its owner's history as the real backends do:
    /// `Ok(false)` when the history is no longer at the commit's revision;
    /// a description that differs from the recorded one, or names another
    /// owner's epoch, is a conflict and changes nothing. The first epoch
    /// becomes the owner's one active epoch, every other one it names or
    /// that was active compare-only.
    fn apply_history(&mut self, commit: &HistoryCommit) -> SidResult<bool> {
        commit.validate()?;
        commit.check_write_cutoff(self.history_write_cutoff)?;
        for d in &commit.epochs {
            let recorded = self
                .histories
                .iter()
                .find_map(|(owner, h)| h.epochs.iter().find(|e| e.id == d.id).map(|e| (*owner, e)));
            if let Some((owner, e)) = recorded
                && (owner != commit.owner || e.descriptor() != *d)
            {
                return Err(sid_core::Error::Conflict(
                    "the history epoch is recorded with another description".into(),
                ));
            }
        }
        let history = self.histories.entry(commit.owner).or_default();
        if history.revision != commit.expected_revision {
            return Ok(false);
        }
        history.revision += 1;
        for d in &commit.epochs {
            if !history.epochs.iter().any(|e| e.id == d.id) {
                history.epochs.push(HistoryEpoch {
                    id: d.id,
                    owner: commit.owner,
                    suite: d.suite,
                    public_key: d.public_key,
                    ksf: d.ksf,
                    ksf_salt: d.ksf_salt,
                    status: HistoryEpochUse::CompareOnly,
                    created_at: d.created_at,
                });
            }
        }
        let active = commit.epochs[0].id;
        for epoch in &mut history.epochs {
            if epoch.id == active {
                epoch.status = HistoryEpochUse::Active;
            } else if epoch.status == HistoryEpochUse::Active {
                epoch.status = HistoryEpochUse::CompareOnly;
            }
        }
        let seq = history.entries.iter().map(|e| e.seq).max().unwrap_or(0) + 1;
        for (epoch, entry) in &commit.entries {
            history.entries.push(HistoryEntry {
                epoch: *epoch,
                seq,
                entry: *entry,
                evidence: commit.evidence.clone(),
                created_at: chrono::Utc::now(),
            });
        }
        // Retain the newest `depth` accepted passwords; an emptied epoch is
        // retired by the evaluator's preparation, not here.
        history
            .entries
            .retain(|e| e.seq > seq - i64::from(commit.depth));
        Ok(true)
    }

    /// Commit the work a mutation owes, as a backend does in its transaction.
    /// Commit what `ctx` carries besides the mutation. Called before the
    /// mutation's own change: a keyed command already completed commits
    /// nothing.
    fn owe(&mut self, ctx: &MutationContext) -> SidResult<()> {
        if let Some(operation) = &ctx.operation {
            let slot = (
                operation.namespace.clone(),
                operation.key.as_str().to_string(),
            );
            if self.operations.contains_key(&slot) {
                return Err(sid_core::Error::OperationCompleted(slot.1));
            }
            self.operations.insert(
                slot,
                OperationRecord {
                    completion: operation.clone(),
                    completed_at: chrono::Utc::now(),
                },
            );
        }
        for owed in &ctx.work {
            self.enqueue(owed, u64::MAX)?;
        }
        Ok(())
    }

    fn enqueue(&mut self, work: &NewWork, capacity: u64) -> SidResult<bool> {
        if self.work.contains_key(&work.id) {
            return Ok(false);
        }
        let open = self
            .work
            .values()
            .filter(|(r, _, _)| {
                r.kind == work.kind && matches!(r.state, WorkState::Pending | WorkState::Claimed)
            })
            .count() as u64;
        if open >= capacity {
            return Err(sid_core::Error::ResourceExhausted(
                "durable work queue full".into(),
            ));
        }
        let now = chrono::Utc::now();
        let record = WorkRecord {
            id: work.id,
            kind: work.kind.clone(),
            state: WorkState::Pending,
            attempts: 0,
            max_attempts: work.max_attempts,
            generation: 0,
            last_error: None,
            ambiguous: false,
            result: None,
            not_before: work.not_before.unwrap_or(now),
            expires_at: work.expires_at,
            created_at: now,
            updated_at: now,
        };
        self.work
            .insert(work.id, (record, work.payload.clone(), None));
        Ok(true)
    }
}

#[async_trait]
impl sid_plugin::WorkStore for MockStorage {
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> SidResult<bool> {
        self.inner.lock().unwrap().enqueue(work, capacity)
    }

    async fn claim_work(
        &self,
        kinds: &[WorkKind],
        _worker: &str,
        limit: u32,
        lease: std::time::Duration,
    ) -> SidResult<Vec<ClaimedWork>> {
        let now = chrono::Utc::now();
        let lease_until = now + chrono::Duration::from_std(lease).expect("lease in range");
        let mut inner = self.inner.lock().unwrap();
        let mut claimed = Vec::new();
        for (record, payload, until) in inner.work.values_mut() {
            if !kinds.contains(&record.kind) {
                continue;
            }
            let open = matches!(record.state, WorkState::Pending | WorkState::Claimed);
            if open && record.expires_at.is_some_and(|e| e <= now) {
                record.state = WorkState::Expired;
                *until = None;
                continue;
            }
            let lease_over = record.state == WorkState::Claimed && until.is_some_and(|u| u <= now);
            if lease_over && record.attempts >= record.max_attempts {
                record.state = WorkState::Failed;
                *until = None;
                continue;
            }
            let due =
                (record.state == WorkState::Pending && record.not_before <= now) || lease_over;
            if !due || claimed.len() >= limit as usize {
                continue;
            }
            record.state = WorkState::Claimed;
            record.attempts += 1;
            record.generation += 1;
            record.updated_at = now;
            *until = Some(lease_until);
            claimed.push(ClaimedWork {
                id: record.id,
                kind: record.kind.clone(),
                payload: payload.clone(),
                attempt: record.attempts,
                max_attempts: record.max_attempts,
                generation: record.generation,
                expires_at: record.expires_at,
            });
        }
        Ok(claimed)
    }

    async fn complete_work(
        &self,
        id: WorkId,
        generation: i64,
        result: Option<&str>,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.work.get_mut(&id) {
            Some((r, _, until)) if r.generation == generation && r.state == WorkState::Claimed => {
                r.state = WorkState::Completed;
                r.result = result.map(str::to_string);
                r.updated_at = chrono::Utc::now();
                *until = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn fail_work(
        &self,
        id: WorkId,
        generation: i64,
        failure: &WorkFailure,
    ) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let dead = match inner.work.get_mut(&id) {
            Some((r, _, until)) if r.generation == generation && r.state == WorkState::Claimed => {
                let dead = failure.retry_at.is_none() || r.attempts >= r.max_attempts;
                r.state = if dead {
                    WorkState::Failed
                } else {
                    WorkState::Pending
                };
                if let Some(at) = failure.retry_at {
                    r.not_before = at;
                }
                r.last_error = Some(failure.error.clone());
                r.ambiguous = failure.ambiguous;
                r.updated_at = chrono::Utc::now();
                *until = None;
                dead
            }
            _ => return Ok(false),
        };
        if dead && let Some(alert) = &failure.on_dead {
            inner.enqueue(alert, u64::MAX)?;
        }
        Ok(true)
    }

    async fn get_work(&self, id: WorkId) -> SidResult<Option<WorkRecord>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .work
            .get(&id)
            .map(|(r, _, _)| r.clone()))
    }

    async fn export_work(&self) -> SidResult<Vec<WorkSnapshot>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .work
            .values()
            .map(|(record, payload, _)| WorkSnapshot {
                record: record.clone(),
                payload: payload.clone(),
            })
            .collect())
    }

    async fn import_work(&self, work: &WorkSnapshot) -> SidResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.work.contains_key(&work.record.id) {
            return Ok(false);
        }
        inner
            .work
            .insert(work.record.id, (work.at_rest(), work.payload.clone(), None));
        Ok(true)
    }
}
