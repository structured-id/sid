// SPDX-License-Identifier: AGPL-3.0-only
//! Storage backend plugin traits.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::Result;
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
    AccessRequest, AccessRequestId, AuthCodeRedemption, AuthorizationCode, CedarPolicy,
    CedarPolicyId, ClosureRequest, Credential, CredentialId, CredentialType, Device,
    DeviceAuthCodeId, DeviceAuthorizationCode, DeviceId, DeviceTrustChange, DirectoryGroupWrite,
    DirectoryUserWrite, EmailSettings, ExportJob, Group, GroupId, GroupMember, HistoryCommit,
    HistoryEpoch, HistoryEpochId, ImpersonationGrant, InitialAccessToken, InitialAccessTokenId,
    Invite, InviteFilter, InviteId, MachineUser, MachineUserCredential, MachineUserId,
    MagicLinkSession, MutationContext, NewHistoryEpoch, NewRegistration, OAuth2Client,
    OutboundDlqEntry, OutboundEntityType, PasswordHistory, PatId, PersonalAccessToken,
    PhoneSettings, Principal, PrincipalBinding, PrincipalEntity, PrincipalId, PrincipalType,
    Profile, ProfileEmail, ProfileEmailId, ProfileGrant, ProfileGrantId, ProfileId,
    ProfileMetadata, ProfilePhone, ProfilePhoneId, Project, ProjectChange, ProjectId, RefreshToken,
    RegistrationSource, RegistrationSourceType, Role, RoleAssignment, RoleAssignmentId, RoleId,
    ScimOutboundRecord, ScimOutboundTarget, ScimOutboundTargetId, Session, SessionAuthentication,
    SessionEnd, SessionId, SodConflictRule, UpstreamIdentity, UpstreamIdentityId, UpstreamLogin,
    UpstreamProvider, UpstreamProviderId, WrappedHistoryKey,
};
use uuid::Uuid;

use crate::WorkStore;

/// The right to run one background job, exclusive across every instance on
/// the same store until released.
pub struct JobLock(Box<dyn JobLockHolder>);

/// A backend's hold on a job lock. A holder dropped without `release` must
/// still free the lock on its own (closed connection, expired lease), so a
/// crashed job does not stop the job everywhere for good.
#[async_trait]
pub trait JobLockHolder: Send + Sync {
    /// Free the lock now.
    async fn release(self: Box<Self>) -> Result<()>;
}

impl JobLock {
    /// Wrap a backend's hold on a job lock.
    pub fn new(holder: impl JobLockHolder + 'static) -> Self {
        Self(Box::new(holder))
    }

    /// Free the lock so another instance can run the job.
    pub async fn release(self) -> Result<()> {
        self.0.release().await
    }
}

/// Storage backend plugin trait.
///
/// Implement this trait to add new storage backends to StructuredID.
///
/// **Audit and owed work by construction:** every write method takes a
/// [`MutationContext`]: the audit entry of the action and the required work
/// the mutation creates. The storage layer persists the mutation, its audit
/// entry and its work in one transaction; a backend that cannot do that for
/// an operation refuses work there instead of storing it apart.
#[async_trait]
pub trait StorageBackend: WorkStore + Send + Sync + 'static {
    /// Returns the unique name of this backend.
    fn name(&self) -> &'static str;

    // === PROFILE OPERATIONS ===

    /// Get a profile by ID.
    async fn get_profile(&self, id: ProfileId) -> Result<Option<Profile>>;

    /// Get a profile by username.
    async fn get_profile_by_username(&self, username: &str) -> Result<Option<Profile>>;

    /// Get a profile by email (via profile_emails join).
    async fn get_profile_by_email(&self, email: &str) -> Result<Option<Profile>>;

    /// Store a new profile; an existing id or user name is `Conflict`, never
    /// an update.
    async fn create_profile(&self, profile: &Profile, ctx: MutationContext) -> Result<()>;

    /// Write `profile` while the stored one is still at `profile.revision`,
    /// moving the revision on. False when it did not apply: the profile was
    /// deleted (it is never recreated) or changed since it was read, so a
    /// stale copy never writes back a status, role or name.
    async fn update_profile(&self, profile: &Profile, ctx: MutationContext) -> Result<bool>;

    /// Delete a profile by ID.
    async fn delete_profile(&self, id: ProfileId, ctx: MutationContext) -> Result<()>;

    /// Commit a self-registration in one transaction: profile, contact row,
    /// principal with its binding, and the first credential.
    ///
    /// The principal must not exist yet. If any profile already holds it (an
    /// earlier or concurrent registration), nothing is written and
    /// `Error::Conflict` is returned; a registration never attaches to an
    /// existing account.
    async fn register_profile(
        &self,
        registration: &NewRegistration,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Install `credential` in place of its profile's credentials of the types
    /// it replaces (`CredentialType::replaces`: a password, a recovery-code
    /// set) in one transaction: those are deleted and the new one inserted. A
    /// crash leaves either the old ones or the new one, never none and never
    /// both. A type that replaces nothing is refused with `Error::Validation`.
    async fn replace_credential(&self, credential: &Credential, ctx: MutationContext)
    -> Result<()>;

    /// Insert a newly enrolled `credential` (an existing id is `Conflict`)
    /// and, with `recovery`, replace the profile's recovery codes by that set,
    /// in one transaction: a factor is never stored without the codes issued
    /// for it. A `recovery` that is not a recovery-code set is refused with
    /// `Error::Validation`.
    async fn enroll_credential(
        &self,
        credential: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Apply one directory write to a user account in one transaction, with
    /// its audit entry and owed work. On create, an existing account or a
    /// login handle already held refuses everything with `Error::Conflict`;
    /// on update, a missing account refuses with `Error::NotFound`. Returns
    /// the sessions a deprovisioning ended, so their tokens can be revoked.
    async fn write_directory_user(
        &self,
        write: &DirectoryUserWrite,
        ctx: MutationContext,
    ) -> Result<Vec<Session>>;

    /// Apply one directory write to a group in one transaction, with its
    /// audit entry and owed work (`Error::Conflict` on create over an
    /// existing group, `Error::NotFound` on update of a missing one).
    async fn write_directory_group(
        &self,
        write: &DirectoryGroupWrite,
        ctx: MutationContext,
    ) -> Result<()>;

    // === PROFILE PHONE OPERATIONS ===

    /// Get a profile phone by ID.
    async fn get_profile_phone(&self, id: ProfilePhoneId) -> Result<Option<ProfilePhone>>;

    /// List all phones for a profile.
    async fn list_profile_phones(&self, profile_id: ProfileId) -> Result<Vec<ProfilePhone>>;

    /// Get the primary phone for a profile.
    async fn get_primary_profile_phone(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<ProfilePhone>>;

    /// Insert a new phone; an existing id is `Conflict`. A primary phone
    /// takes the flag from the profile's current primary in the same write.
    async fn create_profile_phone(&self, phone: &ProfilePhone, ctx: MutationContext) -> Result<()>;

    /// Apply the owner's settings to `profile_id`'s phone `id`; `false` when
    /// the profile has no such phone.
    async fn update_profile_phone_settings(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        settings: &PhoneSettings,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Make `profile_id`'s phone `id` its primary phone, taking the flag from
    /// the current one in the same write; `false` when there is no such phone.
    async fn set_primary_profile_phone(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete a profile phone by ID.
    async fn delete_profile_phone(&self, id: ProfilePhoneId, ctx: MutationContext) -> Result<()>;

    // === PROFILE EMAIL OPERATIONS ===

    /// Get a profile email by ID.
    async fn get_profile_email(&self, id: ProfileEmailId) -> Result<Option<ProfileEmail>>;

    /// List all emails for a profile.
    async fn list_profile_emails(&self, profile_id: ProfileId) -> Result<Vec<ProfileEmail>>;

    /// Get the primary email for a profile.
    async fn get_primary_profile_email(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<ProfileEmail>>;

    /// Insert a new email; an existing id is `Conflict`. A primary email
    /// takes the flag from the profile's current primary in the same write.
    async fn create_profile_email(&self, email: &ProfileEmail, ctx: MutationContext) -> Result<()>;

    /// Apply the owner's label to `profile_id`'s email `id`; `false` when the
    /// profile has no such email.
    async fn update_profile_email_settings(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        settings: &EmailSettings,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Make `profile_id`'s email `id` its primary email, taking the flag from
    /// the current one in the same write; `false` when there is no such email.
    async fn set_primary_profile_email(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete a profile email by ID.
    async fn delete_profile_email(&self, id: ProfileEmailId, ctx: MutationContext) -> Result<()>;

    // === PRINCIPAL OPERATIONS ===
    //
    // Principals are independent entities (one per type+value).
    // PrincipalBindings link them to the Profiles claiming them, M:N.

    /// Get a principal by ID (with first binding context).
    async fn get_principal(&self, id: PrincipalId) -> Result<Option<Principal>>;

    /// Get all principals bound to a profile.
    async fn get_principals_by_profile(&self, profile_id: ProfileId) -> Result<Vec<Principal>>;

    /// The profile a principal is assigned to, while that profile still
    /// claims it. Other claimants are never returned.
    async fn get_profile_by_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> Result<Option<Profile>>;

    /// Record `principal.profile_id`'s claim on the principal. A value never
    /// used before is created and assigned to that Profile with the proof
    /// `principal` carries; an existing one gains the claim and keeps its
    /// assignment and proof unchanged.
    async fn save_principal(&self, principal: &Principal, ctx: MutationContext) -> Result<()>;

    /// Remove `profile_id`'s claim on a principal; other claims stay. The
    /// assigned Profile releasing its claim clears the assignment and its
    /// proof and advances the revision without electing another claimant.
    /// The principal goes with its last claim, so a value nobody claims can
    /// be registered again. `false` when the Profile held no such claim.
    async fn unbind_principal(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Count claims on a principal held by active profiles.
    async fn count_active_principal_bindings(&self, principal_id: PrincipalId) -> Result<i64>;

    /// Get all bindings for a principal entity.
    async fn get_principal_bindings(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Vec<PrincipalBinding>>;

    /// Get a principal entity by type+value (without binding context),
    /// carrying its assignment for login routing.
    async fn get_principal_by_value(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> Result<Option<PrincipalEntity>>;

    /// Clear every channel proof past its lifetime; assignments stay.
    /// Returns the number of principals whose proof lapsed.
    async fn expire_principal_verifications(&self) -> Result<i64>;

    /// Bring a quarantined email key (written before email policy revisions,
    /// its address unknown) back into routing on the evidence of `contact`:
    /// an address of `profile_id` an authorized operation established, whose
    /// key under the active rules is the principal's value. In one
    /// transaction the contact is stored, the key moves to the active
    /// revision, `profile_id`'s claim links to the contact and the key's
    /// disposition becomes migrated for `reason`. `false`, and nothing
    /// written, when the key is no longer quarantined or no longer assigned
    /// to `profile_id`.
    async fn reconcile_email_key(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        contact: &ProfileEmail,
        reason: &str,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === CREDENTIAL OPERATIONS ===

    /// Get a credential by ID.
    async fn get_credential(&self, id: CredentialId) -> Result<Option<Credential>>;

    /// Get credentials by profile ID and type.
    async fn get_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> Result<Vec<Credential>>;

    /// Store a new credential. An existing id is refused with
    /// `Error::Conflict` and nothing is written: a create never replaces a
    /// credential, so it cannot revive a revoked one.
    async fn create_credential(&self, credential: &Credential, ctx: MutationContext) -> Result<()>;

    /// Set the label of an active credential. Returns `false`, writing
    /// nothing, when it is no longer active.
    async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Replace an active password credential's data and its policy evidence
    /// (policy version, verification) with those of `new` and mark it used,
    /// only if its data is still `expected`, and with it apply `history` (the
    /// accepted password's entries) to its owner's history. Returns `false`,
    /// writing nothing, when another change came first, the credential is no
    /// longer active or the history moved past `history.expected_revision`.
    async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === PASSWORD HISTORY ===
    //
    // The history checker reads epochs and entries,
    // never key material; the evaluator reads an epoch's sealed key.

    /// `owner`'s history: its revision, every epoch not retired and every
    /// retained entry. An owner with no history reads as revision 0, empty.
    async fn get_password_history(&self, owner: ProfileId) -> Result<PasswordHistory>;

    /// Consistent complete durable history, including retired epochs and sealed
    /// keys, for offline same-authority transfer; None only if no history exists.
    async fn export_password_history(
        &self,
        _owner: ProfileId,
    ) -> Result<Option<sid_core::models::HistoryArchive>> {
        Err(sid_core::Error::Unavailable(
            "history transfer is unsupported by this backend".into(),
        ))
    }

    /// Atomically install a complete history only when absent. Exact existing
    /// content is an idempotent no-op; any difference is a conflict, never a
    /// rollback or merge. Callers must quiesce writers for instance migration.
    async fn import_password_history(
        &self,
        _archive: &sid_core::models::HistoryArchive,
        _ctx: MutationContext,
    ) -> Result<bool> {
        Err(sid_core::Error::Unavailable(
            "history transfer is unsupported by this backend".into(),
        ))
    }

    /// Store `new` as `owner`'s active epoch with its sealed key, before the
    /// key's first use, and move the history revision on. When the owner
    /// already has an active epoch nothing is written and that epoch is
    /// returned, so concurrent preparations agree on one key. The owner
    /// must exist (`Error::NotFound` otherwise).
    async fn ensure_history_epoch(
        &self,
        new: &NewHistoryEpoch,
        ctx: MutationContext,
    ) -> Result<HistoryEpoch>;

    /// Replace `owner`'s active epoch `replaces` with `new`, before the new
    /// key's first use, and move the history revision on. The replaced epoch
    /// stops taking entries: it stays comparable while it retains entries
    /// and is retired, its sealed key destroyed, when it retains none. When
    /// `replaces` is no longer the active epoch nothing is written and the
    /// current active epoch is returned, so concurrent rotations agree on one
    /// key. The owner must exist (`Error::NotFound` otherwise).
    async fn rotate_history_epoch(
        &self,
        new: &NewHistoryEpoch,
        replaces: HistoryEpochId,
        ctx: MutationContext,
    ) -> Result<HistoryEpoch>;

    /// The sealed VOPRF key of an epoch, for the evaluator; `None` when no
    /// such epoch is stored.
    async fn get_history_epoch_key(
        &self,
        epoch: HistoryEpochId,
    ) -> Result<Option<WrappedHistoryKey>>;

    /// Replace a credential's data with the same secret sealed differently,
    /// only if its data is still `expected`. Its status and last use are left
    /// as they are (a revoked secret is sealed too, and stays revoked).
    /// Returns `false`, writing nothing, otherwise.
    async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Record that an active credential was just used. Returns `false`,
    /// writing nothing, when the credential is no longer active (revoked
    /// meanwhile), so a sign-in in flight cannot complete on it or revive it.
    async fn mark_credential_used(&self, id: CredentialId, ctx: MutationContext) -> Result<bool>;

    /// Replace an active credential's data with `data` and mark it used, only
    /// if its data is still `expected`. Returns `false`, writing nothing, when
    /// another writer changed it first or it is no longer active: consuming one
    /// of several one-time secrets is a compare-and-swap, so a secret is spent
    /// once even under concurrent use.
    async fn replace_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete a credential by ID.
    async fn delete_credential(&self, id: CredentialId, ctx: MutationContext) -> Result<()>;

    /// Revoke a credential, keeping the record. A profile's last active
    /// primary credential ([`CredentialType::is_primary`]) is not revoked
    /// (`LastPrimary`, nothing written); the check and the revocation are one
    /// step for concurrent revocations of the same profile, so two requests
    /// cannot each remove one of its last two sign-in methods.
    async fn revoke_credential(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> Result<sid_core::models::CredentialRevocation>;

    /// Delete all credentials for a profile (cascade revocation).
    /// Returns the number of credentials deleted.
    async fn delete_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<u64>;

    // === WEBAUTHN USER HANDLES ===
    //
    // One opaque handle per
    // Profile and relying party, created once and kept for all its passkeys.

    /// `profile_id`'s user handle at `rp_id`, storing `candidate` when it has
    /// none. Concurrent calls agree on one stored handle; an existing one is
    /// never replaced. `Error::NotFound` when the profile does not exist,
    /// `Error::Conflict` when `candidate` is another profile's handle there.
    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: ProfileId,
        rp_id: &str,
        candidate: sid_core::models::WebAuthnUserHandle,
        ctx: MutationContext,
    ) -> Result<sid_core::models::WebAuthnUserHandle>;

    /// The profile whose user handle at `rp_id` is `handle`, if any.
    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: sid_core::models::WebAuthnUserHandle,
    ) -> Result<Option<ProfileId>>;

    /// Revoke all active consents of a profile and their claim grants
    /// (cascade revocation / GDPR). Returns the number of consents revoked.
    async fn revoke_consents_by_profile(
        &self,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// Store a new consent with its grants. An existing consent (same id, or
    /// same profile and client) is never replaced (`Conflict`).
    async fn create_consent(&self, consent: &ConsentRecord, ctx: MutationContext) -> Result<()>;

    /// Apply `decision` to claim `claim_name` of the active consent `id`, in
    /// one step with any concurrent decision or ending of that consent: a
    /// granted claim has one active grant, and a consent that was revoked or
    /// deleted is left as it is. `ctx` commits only when a claim changed.
    async fn change_claim_grant(
        &self,
        id: ConsentId,
        claim_name: &str,
        decision: sid_core::models::consent::ClaimDecision,
        ctx: MutationContext,
    ) -> Result<sid_core::models::consent::ClaimGrantChange>;

    /// Get a consent record by ID.
    async fn get_consent(&self, id: ConsentId) -> Result<Option<ConsentRecord>>;

    /// Get a consent record by profile + client_id (unique pair).
    async fn get_consent_by_client(
        &self,
        profile_id: ProfileId,
        client_id: &str,
    ) -> Result<Option<ConsentRecord>>;

    /// List all consent records for a profile.
    async fn list_consents_by_profile(&self, profile_id: ProfileId) -> Result<Vec<ConsentRecord>>;

    /// Delete a consent and its grants (disconnect). True when it existed;
    /// `ctx` commits only then, so a repeated disconnect owes nothing.
    async fn delete_consent(&self, id: ConsentId, ctx: MutationContext) -> Result<bool>;

    // === ANOMALY EVENT OPERATIONS ===

    /// Save an anomaly event record (append-only).
    async fn save_anomaly_event(&self, event: &AnomalyEventRecord) -> Result<()>;

    /// List anomaly events with optional rule_id filter and pagination.
    /// Returns events ordered by timestamp DESC (newest first).
    async fn list_anomaly_events(
        &self,
        rule_id: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<AnomalyEventRecord>>;

    // === IP REPUTATION ===

    /// Record a login event for IP reputation tracking.
    ///
    /// UPSERT: increments failed_count or success_count and recomputes score.
    /// Score formula: `failed_count / (failed_count + success_count + 1.0)`.
    async fn record_ip_reputation_event(&self, ip: &str, success: bool) -> Result<()>;

    /// Get the reputation score for a specific IP address.
    ///
    /// Returns `Some(score)` if the IP has recorded events, `None` if unknown.
    /// Used by `SelfLearnedReputationProvider::classify()` for per-call DB lookup.
    async fn get_ip_reputation_score(&self, ip: &str) -> Result<Option<f32>>;

    /// List IPs with reputation score above the given threshold.
    ///
    /// Used by `SelfLearnedReputationProvider::refresh()` to populate
    /// in-memory classification cache.
    async fn list_suspicious_ips(&self, min_score: f32, limit: i64) -> Result<Vec<(String, f32)>>;

    /// Decay IP reputation scores for entries not updated within the given window.
    ///
    /// Called by background cleanup task. Halves counters for stale entries
    /// and deletes entries with both counters at zero.
    async fn decay_ip_reputation(&self, older_than: std::time::Duration) -> Result<u64>;

    // === IP ALLOWLIST ===

    /// Add a CIDR to the admin-configured IP allowlist.
    async fn add_ip_allowlist_entry(&self, cidr: &str, description: &str) -> Result<()>;

    /// Remove a CIDR from the IP allowlist.
    async fn remove_ip_allowlist_entry(&self, cidr: &str) -> Result<()>;

    /// List all IP allowlist entries.
    async fn list_ip_allowlist_entries(
        &self,
    ) -> Result<Vec<(String, String, chrono::DateTime<chrono::Utc>)>>;

    // === SESSION OPERATIONS ===

    /// Store a new session. An existing session with its id is never
    /// replaced (`Conflict`).
    async fn create_session(&self, session: &Session, ctx: MutationContext) -> Result<()>;

    /// Record an authentication completed on session `id`: its level,
    /// step-up, authentication time and methods become `new`, only while the
    /// stored ones still equal `expected` and the session has not expired.
    /// False when it did not apply: the session was ended (it is never
    /// recreated), expired, or authenticated again since `expected` was read.
    async fn record_session_authentication(
        &self,
        id: SessionId,
        expected: &SessionAuthentication,
        new: &SessionAuthentication,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Atomic session creation with concurrent limit enforcement.
    ///
    /// Session creation is serialized per profile, so two concurrent logins
    /// cannot both pass the limit check. The session is inserted like
    /// [`Self::create_session`]: an existing id is a `Conflict`.
    ///
    /// If `max_sessions` is 0, no limit is enforced.
    /// If the profile has `max_sessions` or more active sessions, the oldest are
    /// evicted (FIFO) to make room for the new one, with the sessions they
    /// authenticated; each evicted session owes what [`SessionEnd`] names,
    /// with reason `SessionLimit`.
    ///
    /// Returns the list of evicted session IDs (empty if under limit or unlimited).
    async fn create_session_atomic(
        &self,
        session: &Session,
        max_sessions: u32,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>>;

    /// Get a session by ID.
    async fn get_session(&self, id: SessionId) -> Result<Option<Session>>;

    /// The session a browser signed in with, by the hash of its cookie's
    /// secret; expiry and revocation are the caller's to check.
    async fn get_session_by_browser_secret(
        &self,
        hash: &sid_core::models::BrowserSecretHash,
    ) -> Result<Option<Session>>;

    /// Record activity on session `id` at `at`; last activity only moves
    /// forward. An unknown session is left alone.
    async fn touch_session(&self, id: SessionId, at: chrono::DateTime<chrono::Utc>) -> Result<()>;

    /// Delete a session by ID and the sessions it authenticated
    /// (`authenticated_by`), returning the ids of every session ended. Each
    /// ended session's work under `end` ([`SessionEnd::owed`]) commits with
    /// the deletion; deleting a session that is already gone ends and owes
    /// nothing.
    async fn delete_session(
        &self,
        id: SessionId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>>;

    /// Delete all sessions of a profile and return them. Every deleted session
    /// owes what [`SessionEnd::owed`] names under `end` (its client's
    /// back-channel logout, the revoked event); that work commits in the same
    /// transaction as the deletion, so a session created concurrently is either
    /// kept or ended with what it owes, never ended without it.
    async fn delete_sessions_by_profile(
        &self,
        profile_id: ProfileId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> Result<Vec<Session>>;

    // === PROJECT OPERATIONS ===

    /// Get a project by ID.
    async fn get_project(&self, id: ProjectId) -> Result<Option<Project>>;

    /// Insert a new project; an existing id is `Conflict`, never replaced.
    async fn create_project(&self, project: &Project, ctx: MutationContext) -> Result<()>;

    /// Apply `change` to a user project and return it as stored; `None` when
    /// it was deleted or is a system project. Never recreates a project.
    async fn update_project(
        &self,
        id: ProjectId,
        change: &ProjectChange,
        ctx: MutationContext,
    ) -> Result<Option<Project>>;

    /// Delete a project by ID. Fails if project is a system project.
    async fn delete_project(&self, id: ProjectId, ctx: MutationContext) -> Result<()>;

    /// List projects with pagination.
    async fn list_projects(&self, offset: u64, limit: u64) -> Result<Vec<Project>>;

    /// Count total projects.
    async fn count_projects(&self) -> Result<u64>;

    /// List OAuth2 clients in a specific project.
    async fn list_oauth2_clients_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<OAuth2Client>>;

    /// Ensure the default system project exists (idempotent).
    async fn ensure_system_project(&self, ctx: MutationContext) -> Result<()>;

    // === OAUTH2 CLIENT OPERATIONS ===

    /// Get an OAuth2 client by client_id.
    async fn get_oauth2_client(&self, client_id: &str) -> Result<Option<OAuth2Client>>;

    /// Store `client` over the stored client of its `client_id` while that is
    /// still at `client.revision`, moving the revision on; `client_id`,
    /// creation time and registration origin never change. False when it did
    /// not apply: the client was deleted (it is never recreated) or changed
    /// since it was read.
    async fn update_oauth2_client(
        &self,
        client: &OAuth2Client,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Add `client` as the client role of its stored application. An
    /// existing `client_id`, or an application that already has a client
    /// role, is `Error::Conflict` and nothing is written, so a new
    /// registration cannot take over another client. An application that
    /// does not exist, or is in another project, is refused.
    async fn create_oauth2_client(&self, client: &OAuth2Client, ctx: MutationContext)
    -> Result<()>;

    /// Delete an OAuth2 client and its resource access. Its application goes
    /// with it unless the application also holds a resource role.
    async fn delete_oauth2_client(&self, client_id: &str, ctx: MutationContext) -> Result<()>;

    /// List OAuth2 clients with pagination.
    async fn list_oauth2_clients(&self, offset: u64, limit: u64) -> Result<Vec<OAuth2Client>>;

    /// The client role of application `id`, if it has one.
    async fn oauth2_client_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> Result<Option<OAuth2Client>>;

    // === APPLICATIONS ===

    /// Store a new application with the roles it starts with, in one
    /// transaction: all of them or nothing. A role must name `app`. An
    /// existing application id, client id or resource indicator of the
    /// issuer is `Error::Conflict`.
    async fn create_application(
        &self,
        app: &sid_core::models::Application,
        client: Option<&OAuth2Client>,
        resource: Option<&sid_core::models::ProtectedResource>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// An application by id.
    async fn get_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> Result<Option<sid_core::models::Application>>;

    /// The installation's own integration `kind`, if it was provisioned. At
    /// most one exists: creating a second is `Error::Conflict`.
    async fn system_application(
        &self,
        kind: sid_core::models::SystemIntegration,
    ) -> Result<Option<sid_core::models::Application>>;

    /// Applications of a project, oldest first.
    async fn list_applications_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<sid_core::models::Application>>;

    /// Store `app`'s name over the stored application while that is still at
    /// `app.revision`, moving the revision on. Project and creation time
    /// never change. False when it did not apply: deleted or changed since
    /// it was read.
    async fn update_application(
        &self,
        app: &sid_core::models::Application,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Remove application `id` in one transaction: its client role and every
    /// access that client held are deleted, its resource role is retired
    /// (its indicator stays reserved) and every access to it is deleted.
    /// False when there was no such application.
    async fn delete_application(
        &self,
        id: sid_core::models::ApplicationId,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === PROTECTED RESOURCES ===

    /// Add `resource` as the resource role of its stored application. An
    /// application that already has one, or an indicator already registered
    /// (or retired) under the issuer, is `Error::Conflict`.
    async fn create_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> Result<()>;

    /// A protected resource by id, retired ones included.
    async fn get_protected_resource(
        &self,
        id: sid_core::models::ResourceId,
    ) -> Result<Option<sid_core::models::ProtectedResource>>;

    /// The resource role of application `id`, if it has one.
    async fn protected_resource_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> Result<Option<sid_core::models::ProtectedResource>>;

    /// Every protected resource, retired ones included, oldest first.
    async fn list_protected_resources(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<sid_core::models::ProtectedResource>>;

    /// Store `resource` exactly as given (snapshot import): id, application,
    /// state and revision are kept, a retired one stays retired. Returns
    /// `false`, writing nothing, when that resource is already stored; a
    /// different resource holding its indicator under the issuer, or an
    /// application that already has another resource role, is
    /// `Error::Conflict`.
    async fn import_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// The resource `indicator` names under `issuer`, retired ones included.
    async fn protected_resource_by_indicator(
        &self,
        issuer: sid_core::models::IssuerId,
        indicator: &sid_core::models::ResourceIndicator,
    ) -> Result<Option<sid_core::models::ProtectedResource>>;

    /// Store `resource`'s scopes and state over the stored resource while
    /// that is still at `resource.revision` and not retired, moving the
    /// revision on. Application, issuer, indicator and creation time never
    /// change and a resource is retired only with its application. False
    /// when it did not apply.
    async fn update_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === RESOURCE ACCESS ===

    /// Give `access.client_id` access to `access.resource_id` with exactly
    /// `access.scopes`, replacing the scopes of an existing access (its
    /// creation time is kept). A missing client or resource, or a retired
    /// resource, is refused.
    async fn set_resource_access(
        &self,
        access: &sid_core::models::ResourceAccess,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Remove a client's access to a resource; false when it had none.
    async fn remove_resource_access(
        &self,
        client_id: &str,
        resource: sid_core::models::ResourceId,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// The access `client_id` has to `resource`, if any.
    async fn resource_access(
        &self,
        client_id: &str,
        resource: sid_core::models::ResourceId,
    ) -> Result<Option<sid_core::models::ResourceAccess>>;

    /// Every access `client_id` holds, oldest first.
    async fn list_resource_access_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<sid_core::models::ResourceAccess>>;

    /// Every access to `resource`, oldest first.
    async fn list_resource_access_by_resource(
        &self,
        resource: sid_core::models::ResourceId,
    ) -> Result<Vec<sid_core::models::ResourceAccess>>;

    // === ADMIN QUERY OPERATIONS ===

    /// Profiles `offset..offset + limit` in one total order, oldest first
    /// (creation time, then id), so consecutive pages cover every profile
    /// once. `offset` and `limit` fit a SQL BIGINT.
    async fn list_profiles(&self, offset: u64, limit: u64) -> Result<Vec<Profile>>;

    /// Count total profiles.
    async fn count_profiles(&self) -> Result<u64>;

    /// Profiles in `status` (for lifecycle jobs: closures due, purges due).
    async fn list_profiles_with_status(
        &self,
        status: sid_core::models::ProfileStatus,
    ) -> Result<Vec<Profile>>;

    /// List profiles with pending password migration (legacy hash → OPAQUE).
    async fn list_profiles_with_pending_migration(&self) -> Result<Vec<Profile>>;

    /// End a profile's legacy password migration: store `profile` (its
    /// migration flag cleared) over the revision it was read at and delete
    /// its legacy password hashes, in one transaction. `false` when the
    /// profile changed meanwhile: nothing is stored or deleted.
    async fn end_legacy_migration(&self, profile: &Profile, ctx: MutationContext) -> Result<bool>;

    /// List sessions for a profile.
    async fn list_sessions_by_profile(&self, profile_id: ProfileId) -> Result<Vec<Session>>;

    /// Get the most recent session's IP address and timestamp for a profile.
    ///
    /// Used for impossible travel detection: resolves previous IP via GeoIP
    /// to get lat/lon, then compares with current login location.
    async fn get_most_recent_session_ip(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<(String, chrono::DateTime<chrono::Utc>)>>;

    /// Check if a profile has had a session from a given IP within the time window.
    ///
    /// Used for `new_ip` anomaly detection: returns `true` if the IP has been
    /// seen before, `false` if the IP is new for this profile.
    async fn has_recent_session_from_ip(
        &self,
        profile_id: ProfileId,
        ip: &str,
        window: std::time::Duration,
    ) -> Result<bool>;

    /// Check if a profile has had a session with a given device_id within the time window.
    ///
    /// Used for `new_device` anomaly detection: returns `true` if the device
    /// has been seen before, `false` if the device is new for this profile.
    async fn has_recent_session_from_device(
        &self,
        profile_id: ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> Result<bool>;

    /// Record a login location for designated location tracking.
    ///
    /// UPSERT per (profile_id, country): increments login_count, updates last_seen,
    /// sets designated=true when login_count >= threshold (default 3).
    async fn record_login_location(
        &self,
        profile_id: ProfileId,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> Result<()>;

    /// Get designated countries for a profile (login_count >= threshold).
    ///
    /// Used by impossible travel rule to suppress false positives from
    /// roaming/network switching between known locations.
    async fn get_designated_countries(&self, profile_id: ProfileId) -> Result<Vec<String>>;

    // === REFRESH TOKEN OPERATIONS ===

    /// Insert a refresh token; an existing id or token hash is `Conflict`,
    /// never replaced.
    async fn create_refresh_token(&self, token: &RefreshToken, ctx: MutationContext) -> Result<()>;

    /// Get a refresh token by its hash.
    async fn get_refresh_token_by_hash(&self, token_hash: &[u8]) -> Result<Option<RefreshToken>>;

    /// Revoke all refresh tokens for a session. Returns count revoked.
    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: SessionId,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// Revoke every refresh token of a rotation family, including those still
    /// inside a grace window, so none of them can be used again. Returns the
    /// count changed. Used when a rotated token is reused (theft).
    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: Uuid,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// Rotate a refresh token in one transaction: `old_id` is marked replaced
    /// by `new` (revoked, usable until `grace_expires_at` for a client retry,
    /// an existing grace window is kept) and `new` is stored. Returns `false`,
    /// writing nothing, when `old_id` is neither active nor inside its grace
    /// window (expired, or revoked by sign-out or theft meanwhile).
    async fn rotate_refresh_token(
        &self,
        old_id: Uuid,
        new: &RefreshToken,
        grace_expires_at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === AUTHORIZATION CODE OPERATIONS ===

    /// Insert an authorization code; an existing code hash is `Conflict`.
    async fn create_auth_code(&self, code: &AuthorizationCode, ctx: MutationContext) -> Result<()>;

    /// Get an authorization code by its hash.
    async fn get_auth_code_by_hash(&self, code_hash: &[u8]) -> Result<Option<AuthorizationCode>>;

    /// Redeem an authorization code exactly once (RFC 6749 §4.1.2).
    ///
    /// In one transaction: mark the code used only if it is not used yet, bind
    /// it to `session`, and store `session` and `refresh_token`. Of any number
    /// of concurrent redemptions exactly one gets `Redeemed`; the others get
    /// `AlreadyRedeemed` with the first redemption's session and store nothing.
    async fn redeem_auth_code(
        &self,
        code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        ctx: MutationContext,
    ) -> Result<AuthCodeRedemption>;

    // === INITIAL ACCESS TOKEN OPERATIONS (DCR) ===

    /// Store a new initial access token; an existing id or hash is
    /// `Conflict`, so a revoked token is never reactivated by a repeated
    /// create and its registration count is never reset.
    async fn create_initial_access_token(
        &self,
        token: &InitialAccessToken,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Register a dynamically registered client against initial access token
    /// `iat`, in one transaction: the token is locked, one use is counted and
    /// `app` is inserted with `client` as its client role, or nothing is stored.
    ///
    /// Errors: `NotFound` (no such token), `Revoked`, `Expired`, `InvalidState`
    /// (client limit reached), `Conflict` (the application or `client_id`
    /// exists; a registration never replaces a client).
    async fn register_dynamic_client(
        &self,
        app: &sid_core::models::Application,
        client: &OAuth2Client,
        iat: InitialAccessTokenId,
        ctx: MutationContext,
    ) -> Result<()>;

    // === FIELD-ENCRYPTION KEY VERSIONS ===

    /// Every stored key version's derivation parameters, ascending by version.
    async fn list_key_versions(&self) -> Result<Vec<sid_keys::KeyVersionParams>>;

    /// Store a new key version. Returns `false`, writing nothing, when that
    /// version already exists: concurrent starters agree on one salt per version.
    async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === INSTANCE SECRETS ===

    /// The sealed value of an instance secret, if one was stored.
    async fn get_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
    ) -> Result<Option<Vec<u8>>>;

    /// Store an instance secret. Returns `false`, writing nothing, when it
    /// already exists: concurrent starters agree on the first value stored.
    async fn insert_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
        sealed: &[u8],
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Whether any profile holds the administrator role.
    async fn admin_exists(&self) -> Result<bool>;

    /// Make `profile` (already carrying the administrator role, at the
    /// revision it was read at) the first administrator, consuming the admin
    /// claim stored as `claim_sealed`. The claim is removed and the profile
    /// written in one transaction. Returns `false`, changing nothing, when
    /// that claim is no longer stored, an administrator already exists or
    /// the profile changed since it was read: of concurrent claimers exactly
    /// one succeeds.
    async fn claim_first_admin(
        &self,
        claim_sealed: &[u8],
        profile: &sid_core::models::Profile,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// The installation's own organization, once created.
    async fn instance_organization(&self) -> Result<Option<sid_core::models::Organization>>;

    /// Store `org` as the installation's own organization. Returns `false`,
    /// writing nothing, when one already exists: concurrent first starts
    /// agree on the first one stored.
    async fn insert_instance_organization(
        &self,
        org: &sid_core::models::Organization,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Give every client that belongs to no organization `org_id`; returns
    /// how many were assigned. Clients already in an organization keep it.
    async fn assign_unowned_clients(
        &self,
        org_id: sid_core::models::OrgId,
        ctx: MutationContext,
    ) -> Result<u64>;

    // === OIDC ISSUERS ===

    /// The issuer of `authority` for `recipient_org`, once provisioned.
    async fn oidc_issuer_for(
        &self,
        authority: sid_core::models::IssuerAuthority,
        recipient_org: sid_core::models::OrgId,
    ) -> Result<Option<sid_core::models::OidcIssuer>>;

    /// The issuer named by `handle`.
    async fn oidc_issuer_by_handle(
        &self,
        handle: &sid_core::models::IssuerHandle,
    ) -> Result<Option<sid_core::models::OidcIssuer>>;

    /// Store `issuer` with its generation-1 signing key in one transaction.
    /// Returns `false`, writing nothing, when its authority and organization
    /// already have an issuer: concurrent provisioners agree on the first.
    /// A key of another issuer or generation is a validation error.
    async fn insert_oidc_issuer(
        &self,
        issuer: &sid_core::models::OidcIssuer,
        first_key: &sid_core::models::IssuerSigningKey,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Every signing key of `issuer`, ascending by generation.
    async fn oidc_issuer_signing_keys(
        &self,
        issuer: sid_core::models::IssuerId,
    ) -> Result<Vec<sid_core::models::IssuerSigningKey>>;

    /// The binding of `profile_id` to `scope`, allocated (with the profile's
    /// next binding index, recorded under `ctx`) when the profile has none
    /// there yet. Of concurrent first uses exactly one allocates and every
    /// caller gets that binding. Refreshes `last_used_at`.
    async fn service_binding(
        &self,
        profile_id: ProfileId,
        scope: &sid_core::models::BindingScope,
        ctx: MutationContext,
    ) -> Result<sid_core::models::ServiceBinding>;

    /// Every binding of `profile_id`, ordered by index (snapshot export).
    async fn list_service_bindings(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<sid_core::models::ServiceBinding>>;

    /// Store a binding exported from another instance, keeping its id and
    /// index so every client keeps its `sub`. `false` when that exact binding
    /// is already stored; another binding holding its profile and scope or its
    /// profile and index is `Error::Conflict` and nothing is written.
    async fn import_service_binding(
        &self,
        binding: &sid_core::models::ServiceBinding,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// The binding of `profile_id` to `scope` if one was allocated; allocates nothing.
    async fn find_service_binding(
        &self,
        profile_id: ProfileId,
        scope: &sid_core::models::BindingScope,
    ) -> Result<Option<sid_core::models::ServiceBinding>>;

    /// Credentials of one type across all profiles, ordered by id, `limit`
    /// at a time after `after` (for maintenance passes such as sealing
    /// secrets stored before field encryption).
    async fn list_credentials_by_type(
        &self,
        credential_type: CredentialType,
        after: Option<CredentialId>,
        limit: u32,
    ) -> Result<Vec<Credential>>;

    /// Get an initial access token by ID.
    async fn get_initial_access_token(
        &self,
        id: InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken>>;

    /// Get an initial access token by its hash.
    async fn get_initial_access_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<InitialAccessToken>>;

    /// List initial access tokens for a project.
    async fn list_initial_access_tokens_by_project(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<InitialAccessToken>>;

    /// Revoke an initial access token by ID.
    async fn revoke_initial_access_token(
        &self,
        id: InitialAccessTokenId,
        ctx: MutationContext,
    ) -> Result<()>;

    // === ROLE OPERATIONS (RBAC) ===

    /// Get a role by ID.
    async fn get_role(&self, id: RoleId) -> Result<Option<Role>>;

    /// Get a role by name within a project.
    async fn get_role_by_name(&self, project_id: ProjectId, name: &str) -> Result<Option<Role>>;

    /// Store a new role. An existing role, or another role of the project
    /// with the same key or name, is never replaced (`Conflict`).
    async fn create_role(&self, role: &Role, ctx: MutationContext) -> Result<()>;

    /// Store `role`'s name, description, group, permissions and update time
    /// while the stored role is still at `role.revision`, moving the revision
    /// on. False when it did not apply: the role was deleted (it is never
    /// recreated) or changed since it was read. Its key and project never
    /// change.
    async fn update_role(&self, role: &Role, ctx: MutationContext) -> Result<bool>;

    /// [`update_role`](Self::update_role) only while `fence` still holds, in
    /// the same transaction, with the role locked against concurrent
    /// assignment: the editor's authority exists unexpired at the checked
    /// revision, and when the edit adds permissions, the role's assignments
    /// carrying an approved ceiling are exactly the checked ones. A broken
    /// fence is `Fenced`, nothing written.
    async fn update_role_fenced(
        &self,
        role: &Role,
        fence: &sid_core::models::RoleEditFence,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete a role by ID.
    async fn delete_role(&self, id: RoleId, ctx: MutationContext) -> Result<()>;

    /// List roles in a project.
    async fn list_roles(&self, project_id: ProjectId) -> Result<Vec<Role>>;

    // === GROUP OPERATIONS ===

    /// Get a group by ID.
    async fn get_group(&self, id: GroupId) -> Result<Option<Group>>;

    /// Store a new group. An existing group, or another group of the project
    /// with the same name, is never replaced (`Conflict`).
    async fn create_group(&self, group: &Group, ctx: MutationContext) -> Result<()>;

    /// Set a stored group's description, touching nothing else. False when
    /// the group does not exist (a deleted group is never recreated).
    async fn set_group_description(
        &self,
        id: GroupId,
        description: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete a group by ID.
    async fn delete_group(&self, id: GroupId, ctx: MutationContext) -> Result<()>;

    /// List groups in a project.
    async fn list_groups(&self, project_id: ProjectId) -> Result<Vec<Group>>;

    /// Add a profile to a group.
    async fn add_to_group(&self, member: &GroupMember, ctx: MutationContext) -> Result<()>;

    /// Remove a profile from a group.
    async fn remove_from_group(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
        ctx: MutationContext,
    ) -> Result<()>;

    /// List members of a group.
    async fn list_group_members(&self, group_id: GroupId) -> Result<Vec<GroupMember>>;

    /// List groups a profile belongs to.
    async fn list_groups_for_profile(&self, profile_id: ProfileId) -> Result<Vec<Group>>;

    // === ROLE ASSIGNMENT OPERATIONS ===

    /// Store a new role assignment; an existing one is never replaced
    /// (`Conflict`).
    async fn create_role_assignment(
        &self,
        assignment: &RoleAssignment,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Delete a role assignment.
    async fn delete_role_assignment(
        &self,
        id: RoleAssignmentId,
        ctx: MutationContext,
    ) -> Result<()>;

    /// The role assignment `id`, with its envelope and provenance.
    async fn get_role_assignment(&self, id: RoleAssignmentId) -> Result<Option<RoleAssignment>>;

    /// Store a new administered assignment only while `fence` still holds,
    /// in the same transaction: its basis exists unexpired at the checked
    /// revision, the role is at the checked revision and the recipient's
    /// group membership holds. A broken fence is `Fenced`, an existing id
    /// `Conflict`; nothing is written either way.
    async fn create_role_assignment_fenced(
        &self,
        assignment: &RoleAssignment,
        fence: &sid_core::models::AssignmentFence,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Delete an administered assignment only while `fence` still holds;
    /// false, writing nothing, when no such assignment exists.
    async fn delete_role_assignment_fenced(
        &self,
        id: RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// List role assignments for a profile.
    async fn list_role_assignments_for_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<RoleAssignment>>;

    /// List role assignments for a group.
    async fn list_role_assignments_for_group(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<RoleAssignment>>;

    /// List role assignments for a machine user.
    async fn list_role_assignments_for_machine_user(
        &self,
        machine_user_id: MachineUserId,
    ) -> Result<Vec<RoleAssignment>>;

    /// List role assignments held by the OAuth client `client_id` as its own
    /// principal. An assignment goes with its client.
    async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<RoleAssignment>>;

    /// A provisioning connector's role assignments, expired ones included.
    async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> Result<Vec<RoleAssignment>>;

    /// List the assignments of the role `role_id`, whatever principal holds them.
    async fn list_role_assignments_for_role(&self, role_id: RoleId) -> Result<Vec<RoleAssignment>>;

    /// List role assignments expiring within the given number of hours (or already expired).
    async fn list_expiring_role_assignments(
        &self,
        within_hours: i64,
    ) -> Result<Vec<RoleAssignment>>;

    /// Delete all expired role assignments and return them. Each deleted
    /// assignment owes its [`RoleAssignment::expired_event`], committed in the
    /// same transaction as the deletion.
    async fn cleanup_expired_role_assignments(
        &self,
        ctx: MutationContext,
    ) -> Result<Vec<RoleAssignment>>;

    // === SOD (SEPARATION OF DUTIES) ===

    /// List all SoD conflict rules.
    async fn list_sod_rules(&self) -> Result<Vec<SodConflictRule>>;

    // === CEDAR POLICY OPERATIONS ===

    /// Get a Cedar policy by ID.
    async fn get_cedar_policy(&self, id: CedarPolicyId) -> Result<Option<CedarPolicy>>;

    /// Store a new Cedar policy; an existing id is `Conflict`, never an update.
    async fn create_cedar_policy(&self, policy: &CedarPolicy, ctx: MutationContext) -> Result<()>;

    /// Store `policy`'s description, text, effect, enabled flag and update time
    /// while the stored policy is still at `policy.revision`, moving the
    /// revision on. False when it did not apply: the policy was deleted (it is
    /// never recreated) or changed since it was read, so a stale copy never
    /// re-enables a policy an administrator disabled.
    async fn update_cedar_policy(&self, policy: &CedarPolicy, ctx: MutationContext)
    -> Result<bool>;

    /// Delete a Cedar policy by ID.
    async fn delete_cedar_policy(&self, id: CedarPolicyId, ctx: MutationContext) -> Result<()>;

    /// List Cedar policies in a project.
    async fn list_cedar_policies(&self, project_id: ProjectId) -> Result<Vec<CedarPolicy>>;

    // === PROFILE METADATA OPERATIONS ===

    /// Get a single metadata entry for a profile.
    async fn get_profile_metadata(
        &self,
        profile_id: ProfileId,
        key: &str,
    ) -> Result<Option<ProfileMetadata>>;

    /// Set a metadata entry for a profile (upsert).
    async fn set_profile_metadata(
        &self,
        metadata: &ProfileMetadata,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Delete a metadata entry for a profile.
    async fn delete_profile_metadata(
        &self,
        profile_id: ProfileId,
        key: &str,
        ctx: MutationContext,
    ) -> Result<()>;

    /// List all metadata entries for a profile.
    async fn list_profile_metadata(&self, profile_id: ProfileId) -> Result<Vec<ProfileMetadata>>;

    // === DEVICE MANAGEMENT OPERATIONS ===

    /// Store a new device; an existing id is `Conflict`, never an update.
    async fn create_device(&self, device: &Device, ctx: MutationContext) -> Result<()>;

    /// Set a stored device's display name, touching nothing else. False when
    /// the device does not exist (a removed device is never recreated).
    async fn rename_device(
        &self,
        id: DeviceId,
        display_name: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Trust or distrust a stored device. Trusting it counts the profile's
    /// trusted devices in the same transaction as the change, so concurrent
    /// requests cannot exceed `max_trusted`; a trusted device is at least
    /// `trusted` assurance and a distrusted one drops back to `recognized`.
    async fn set_device_trust(
        &self,
        id: DeviceId,
        trusted: bool,
        max_trusted: usize,
        ctx: MutationContext,
    ) -> Result<DeviceTrustChange>;

    /// Get a device by ID.
    async fn get_device(&self, id: DeviceId) -> Result<Option<Device>>;

    /// List all devices for a profile.
    async fn list_devices_by_profile(&self, profile_id: ProfileId) -> Result<Vec<Device>>;

    /// Delete a device by ID.
    async fn delete_device(&self, id: DeviceId, ctx: MutationContext) -> Result<()>;

    /// Get a device by fingerprint hash (for recognition).
    async fn get_device_by_fingerprint(
        &self,
        profile_id: ProfileId,
        fingerprint_hash: &str,
    ) -> Result<Option<Device>>;

    // === DEVICE ATTESTATION OPERATIONS ===

    /// Store a device's attestation. It replaces only a revoked one (a new
    /// enrollment after revocation); a device with a live attestation is
    /// `Conflict`.
    async fn create_device_attestation(
        &self,
        attestation: &DeviceAttestation,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Replace the key of a device's live attestation, leaving it unverified.
    /// False when there is none: a revoked key is never replaced.
    async fn rotate_device_attestation(
        &self,
        device_id: DeviceId,
        device_public_key: &[u8],
        attestation_object: Option<&[u8]>,
        attestation_certificate: Option<&[u8]>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Revoke a device's live attestation and, in the same transaction, stop
    /// counting the device as hardware-attested. False when there is none.
    async fn revoke_device_attestation(
        &self,
        device_id: DeviceId,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Get a device attestation by ID.
    async fn get_device_attestation(
        &self,
        id: DeviceAttestationId,
    ) -> Result<Option<DeviceAttestation>>;

    /// Get a device attestation by device ID.
    async fn get_device_attestation_by_device_id(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<DeviceAttestation>>;

    /// List all attestations for a profile.
    async fn list_device_attestations_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<DeviceAttestation>>;

    /// Delete a device attestation by device ID (revoke key).
    async fn delete_device_attestation(
        &self,
        device_id: DeviceId,
        ctx: MutationContext,
    ) -> Result<()>;

    // === DEVICE AUTHORIZATION OPERATIONS (RFC 8628) ===

    /// Store a new device authorization request. An existing id, device code
    /// or user code is never replaced (`Conflict`).
    async fn create_device_auth_code(
        &self,
        code: &DeviceAuthorizationCode,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Get a device authorization code by device code hash.
    async fn get_device_auth_by_device_code_hash(
        &self,
        device_code_hash: &[u8],
    ) -> Result<Option<DeviceAuthorizationCode>>;

    /// Get a device authorization code by user code.
    async fn get_device_auth_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorizationCode>>;

    /// Record the user's decision on request `id` while it is pending and not
    /// expired. False when it was decided first, expired or unknown: of two
    /// concurrent decisions one applies.
    async fn decide_device_auth(
        &self,
        id: DeviceAuthCodeId,
        decision: sid_core::models::DeviceAuthDecision,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Record a poll of request `id`, in one step with concurrent polls: a
    /// poll sooner than the interval after the previous one is `SlowDown` and
    /// grows the interval by 5 seconds (RFC 8628 §3.5).
    async fn record_device_poll(
        &self,
        id: DeviceAuthCodeId,
        ctx: MutationContext,
    ) -> Result<sid_core::models::DevicePoll>;

    /// Redeem the authorized, unexpired request with `device_code_hash`
    /// exactly once: in one transaction mark it redeemed with `session`, and
    /// store `session` and `refresh_token`. Of concurrent or repeated
    /// redemptions one gets `Redeemed`; the others store nothing.
    async fn redeem_device_code(
        &self,
        device_code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        ctx: MutationContext,
    ) -> Result<sid_core::models::DeviceCodeRedemption>;

    /// Delete expired device authorization codes. Returns count deleted.
    async fn cleanup_expired_device_auth_codes(&self, ctx: MutationContext) -> Result<u64>;

    // === PROFILE GRANT OPERATIONS ===

    /// Get a profile grant by ID.
    async fn get_profile_grant(&self, id: ProfileGrantId) -> Result<Option<ProfileGrant>>;

    /// Insert a new profile grant; an existing id is `Conflict`, never replaced.
    async fn create_profile_grant(&self, grant: &ProfileGrant, ctx: MutationContext) -> Result<()>;

    /// Delete a profile grant by ID.
    async fn delete_profile_grant(&self, id: ProfileGrantId, ctx: MutationContext) -> Result<()>;

    /// List all grants for a profile (across all projects).
    async fn list_profile_grants_for_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<ProfileGrant>>;

    /// List all grants in a project.
    async fn list_profile_grants_for_project(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ProfileGrant>>;

    // === UPSTREAM PROVIDER OPERATIONS ===

    /// Get an upstream provider by ID.
    async fn get_upstream_provider(
        &self,
        id: UpstreamProviderId,
    ) -> Result<Option<UpstreamProvider>>;

    /// Insert a new upstream provider; an existing id is `Conflict`, never replaced.
    async fn create_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Write `provider` over the revision it was read at and move the
    /// revision on; `false` when it was deleted or changed since.
    async fn update_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete an upstream provider by ID.
    async fn delete_upstream_provider(
        &self,
        id: UpstreamProviderId,
        ctx: MutationContext,
    ) -> Result<()>;

    /// List enabled upstream providers (for login screen).
    async fn list_enabled_upstream_providers(&self) -> Result<Vec<UpstreamProvider>>;

    // === UPSTREAM IDENTITY OPERATIONS ===

    /// Find upstream identity by provider + upstream subject (for returning users).
    async fn get_upstream_identity_by_provider_subject(
        &self,
        provider_id: UpstreamProviderId,
        upstream_subject: &str,
    ) -> Result<Option<UpstreamIdentity>>;

    /// Link a new upstream identity; an existing id or provider subject is
    /// `Conflict`, never relinked to another profile.
    async fn create_upstream_identity(
        &self,
        identity: &UpstreamIdentity,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Record a login through a linked identity: cached claims replaced, the
    /// login counted in place. `false` when the link was removed.
    async fn record_upstream_login(
        &self,
        id: UpstreamIdentityId,
        login: &UpstreamLogin,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// List all upstream identities for a profile.
    async fn list_upstream_identities_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> Result<Vec<UpstreamIdentity>>;

    /// Delete an upstream identity by ID.
    async fn delete_upstream_identity(
        &self,
        id: UpstreamIdentityId,
        ctx: MutationContext,
    ) -> Result<()>;

    // === PERSONAL ACCESS TOKEN ===

    /// Get a PAT by ID.
    async fn get_pat(&self, id: PatId) -> Result<Option<PersonalAccessToken>>;

    /// Get a PAT by its SHA-256 token hash.
    async fn get_pat_by_token_hash(&self, token_hash: &str) -> Result<Option<PersonalAccessToken>>;

    /// Store a new PAT. An existing id is refused with `Error::Conflict` (a
    /// create never replaces, so a revoked token cannot come back). With
    /// `active_limit`, a profile already holding that many active PATs is
    /// refused with `Error::ResourceExhausted`; the count and the insert are
    /// one step for concurrent creates of one profile.
    async fn create_pat(
        &self,
        pat: &PersonalAccessToken,
        active_limit: Option<u64>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Record a use of a PAT that is active and not expired. Returns
    /// `false`, writing nothing, otherwise: a token revoked or expired since it
    /// was read neither counts a use nor becomes usable again.
    async fn record_pat_use(
        &self,
        id: PatId,
        ip: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Revoke a PAT that is not revoked yet; `false` (nothing written, nothing
    /// audited) when it is already revoked or does not exist, so the first
    /// revocation's time and actor stay on record.
    async fn revoke_pat(&self, id: PatId, revoked_by: &str, ctx: MutationContext) -> Result<bool>;

    /// List all PATs for a profile.
    async fn list_pats_by_profile(&self, profile_id: ProfileId)
    -> Result<Vec<PersonalAccessToken>>;

    /// List all PATs (admin).
    async fn list_all_pats(&self) -> Result<Vec<PersonalAccessToken>>;

    /// Count active PATs for a profile (for limit enforcement).
    async fn count_active_pats_by_profile(&self, profile_id: ProfileId) -> Result<u64>;

    /// Atomically revoke all active PATs for a profile. Returns count of revoked tokens.
    ///
    /// Uses `UPDATE ... WHERE profile_id = ? AND status = 'active'` — no TOCTOU race.
    /// Used by cascade revocation (profile deletion/suspension).
    async fn revoke_active_pats_by_profile(
        &self,
        profile_id: ProfileId,
        revoked_by: &str,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// Revoke PATs unused for more than `days` and return count of revoked tokens.
    ///
    /// A PAT is considered unused if `last_used_at` is `None` and `created_at`
    /// is older than `days`, or if `last_used_at` is older than `days` ago.
    /// Only revokes tokens in Active status.
    async fn revoke_unused_pats(&self, days: u32, ctx: MutationContext) -> Result<u64>;

    // === MACHINE USER OPERATIONS ===

    /// Get a machine user by ID.
    async fn get_machine_user(&self, id: MachineUserId) -> Result<Option<MachineUser>>;

    /// Get a machine user by client_id.
    async fn get_machine_user_by_client_id(&self, client_id: &str) -> Result<Option<MachineUser>>;

    /// Store a new machine user. An existing id is refused with
    /// `Error::Conflict`: a create never replaces, so it cannot revive a
    /// deleted or suspended one.
    async fn create_machine_user(&self, mu: &MachineUser, ctx: MutationContext) -> Result<()>;

    /// Update a machine user's settings (display name, description, scopes,
    /// roles, restrictions, token lifetime, expiry) from `mu`. Its status and
    /// last use stay as stored, so a concurrent suspension is not undone.
    /// Returns `false`, writing nothing, when it is missing or deleted.
    async fn update_machine_user(&self, mu: &MachineUser, ctx: MutationContext) -> Result<bool>;

    /// Move a machine user from `from` to `to`. Returns `false`, writing
    /// nothing, when its status is no longer `from`.
    async fn transition_machine_user(
        &self,
        id: MachineUserId,
        from: MachineUserStatus,
        to: MachineUserStatus,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Delete a machine user (soft delete — sets status=deleted).
    async fn delete_machine_user(&self, id: MachineUserId, ctx: MutationContext) -> Result<()>;

    /// List machine users in a project.
    async fn list_machine_users_by_project(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<MachineUser>>;

    // === MACHINE USER CREDENTIAL OPERATIONS ===

    /// Get a credential by kid.
    async fn get_machine_credential_by_kid(
        &self,
        kid: &str,
    ) -> Result<Option<MachineUserCredential>>;

    /// Store a new credential. An existing kid is refused with
    /// `Error::Conflict`. With `active_limit`, a machine user already holding
    /// that many usable credentials is refused with `Error::ResourceExhausted`;
    /// the count and the insert are one step for concurrent adds.
    async fn add_machine_credential(
        &self,
        cred: &MachineUserCredential,
        active_limit: Option<u64>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Rotate in one transaction: move `old_kid` of `machine_user_id` from
    /// active to its grace period ending at `grace_until` (or at its own
    /// earlier expiry) and store `new`. Returns `false`, writing nothing, when
    /// `old_kid` is not an active credential of that machine user (revoked,
    /// already rotated, someone else's).
    async fn rotate_machine_credential(
        &self,
        machine_user_id: MachineUserId,
        old_kid: &str,
        new: &MachineUserCredential,
        grace_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Revoke a usable credential of `machine_user_id`. Returns `false`,
    /// writing nothing, when it has no usable credential with that kid.
    async fn revoke_machine_credential(
        &self,
        machine_user_id: MachineUserId,
        kid: &str,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Atomically revoke all usable credentials for a machine user. Returns count.
    ///
    /// Uses `UPDATE ... WHERE machine_user_id = ? AND status IN ('active', ...)` — no TOCTOU.
    /// Used by cascade revocation (machine user suspension).
    async fn revoke_active_machine_credentials_by_user(
        &self,
        id: MachineUserId,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// List credentials for a machine user.
    async fn list_machine_credentials_by_user(
        &self,
        id: MachineUserId,
    ) -> Result<Vec<MachineUserCredential>>;

    /// List all active machine credentials expiring within `within_days` days,
    /// plus any already-expired but still Active credentials.
    ///
    /// Used by the background credential expiry scanner.
    async fn list_expiring_machine_credentials(
        &self,
        within_days: u32,
    ) -> Result<Vec<MachineUserCredential>>;

    // === PROVISIONING CONNECTOR OPERATIONS ===

    /// Get a provisioning connector by id, whatever its state.
    async fn get_provisioning_connector(
        &self,
        id: ProvisioningConnectorId,
    ) -> Result<Option<ProvisioningConnector>>;

    /// The connector whose OAuth `client_id` this is, whatever its state.
    async fn get_provisioning_connector_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<ProvisioningConnector>>;

    /// An organization's provisioning connectors, retired ones included.
    async fn list_provisioning_connectors(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<ProvisioningConnector>>;

    /// Store a new connector. An existing id is refused with
    /// `Error::Conflict`: a create never replaces.
    async fn create_provisioning_connector(
        &self,
        connector: &ProvisioningConnector,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Rename a connector that is still at `revision`, advancing it. Returns
    /// `false`, writing nothing, when it is missing, retired or has changed
    /// since (another revision).
    async fn rename_provisioning_connector(
        &self,
        id: ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Move a connector from `from` to `to`, advancing its revision. Retiring
    /// revokes its usable credentials in the same transaction; disabling keeps
    /// them, so enabling again needs no new credential. Returns `false`,
    /// writing nothing, when its state is no longer `from` or the change is
    /// not a lifecycle step ([`ConnectorState::may_become`]).
    async fn transition_provisioning_connector(
        &self,
        id: ProvisioningConnectorId,
        from: ConnectorState,
        to: ConnectorState,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === PROVISIONING CREDENTIAL OPERATIONS ===

    /// Store a new credential of an active connector. An existing id or
    /// verifier is refused with `Error::Conflict`; a connector already holding
    /// [`MAX_USABLE_CONNECTOR_CREDENTIALS`](sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS)
    /// usable credentials with `Error::ResourceExhausted`. The state check,
    /// the count and the insert are one step for concurrent adds. Returns
    /// `false`, writing nothing, when the connector is missing or not active.
    async fn add_provisioning_credential(
        &self,
        credential: &ProvisioningCredential,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Rotate in one transaction: `old` of `connector_id` goes from active to
    /// its grace period ending at `grace_until`, and `new` is stored. Returns
    /// `false`, writing nothing, when `old` is not an active credential of
    /// that connector or the connector is not active.
    async fn rotate_provisioning_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        old: ProvisioningCredentialId,
        new: &ProvisioningCredential,
        grace_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Revoke a usable credential of `connector_id` at once, with no grace.
    /// Returns `false`, writing nothing, when it has no usable credential
    /// with that id.
    async fn revoke_provisioning_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        id: ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// A connector's credentials, revoked ones included (verifiers only).
    async fn list_provisioning_credentials(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> Result<Vec<ProvisioningCredential>>;

    /// The credential stored with `verifier` and its connector, whatever
    /// their states: the caller decides usability at the time of use.
    async fn find_provisioning_credential(
        &self,
        verifier: &str,
    ) -> Result<Option<(ProvisioningCredential, ProvisioningConnector)>>;

    // === IMPERSONATION GRANT OPERATIONS ===

    /// Save an impersonation grant (insert or update).
    async fn save_impersonation_grant(
        &self,
        grant: &ImpersonationGrant,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Delete an impersonation grant.
    async fn delete_impersonation_grant(
        &self,
        machine_user_id: MachineUserId,
        target_type: &str,
        target: &str,
        ctx: MutationContext,
    ) -> Result<()>;

    /// List impersonation grants for a machine user.
    async fn list_impersonation_grants(
        &self,
        machine_user_id: MachineUserId,
    ) -> Result<Vec<ImpersonationGrant>>;

    // === PRINCIPAL QUARANTINE OPERATIONS ===

    /// Quarantine a principal hash (prevent reuse after account closure).
    async fn quarantine_principal(
        &self,
        principal_hash: &str,
        principal_type: &str,
        quarantine_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Check if a principal hash is currently quarantined.
    async fn is_principal_quarantined(&self, principal_hash: &str) -> Result<bool>;

    /// Remove expired quarantine entries. Returns count removed.
    async fn cleanup_expired_quarantine(&self, ctx: MutationContext) -> Result<u64>;

    // === CLOSURE REQUEST OPERATIONS ===

    /// Insert a closure request as it stands (import); an existing request of
    /// the profile is `Conflict`, never replaced.
    async fn create_closure_request(
        &self,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Store `profile` (its closing status) over the revision it was read at
    /// and its closure request in one transaction. A previous request of the
    /// profile is replaced except for its cancel count and legal hold, which
    /// outlive it. `false` when the profile changed meanwhile: nothing stored.
    /// An administrator's request is `InvalidState` unless another
    /// administrator stays active or suspended, decided in the same write so
    /// concurrent requests cannot leave the instance without one.
    async fn request_profile_closure(
        &self,
        profile: &Profile,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Store `profile` (restored from closing) over the revision it was read
    /// at and count the cancellation on its closure request in one
    /// transaction. `false` when the profile changed meanwhile; `NotFound`
    /// when it has no closure request. Nothing is stored in either case.
    async fn cancel_profile_closure(&self, profile: &Profile, ctx: MutationContext)
    -> Result<bool>;

    /// Get a closure request for a profile.
    async fn get_closure_request(&self, profile_id: ProfileId) -> Result<Option<ClosureRequest>>;

    // === DATA EXPORT OPERATIONS ===

    /// Insert a new export job; an existing id is `Conflict`, never replaced.
    async fn create_export_job(&self, job: &ExportJob, ctx: MutationContext) -> Result<()>;

    /// Record the download of a ready, unexpired export; `false` when the
    /// export is not ready, has expired or was already acknowledged.
    async fn acknowledge_export_job(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Close the download window of a ready export whose window has passed;
    /// `false` when it is not ready or its window is still open.
    async fn expire_export_job(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Get the latest export job for a profile.
    async fn get_export_job(&self, profile_id: ProfileId) -> Result<Option<ExportJob>>;

    /// Get an export job by ID.
    async fn get_export_job_by_id(&self, job_id: uuid::Uuid) -> Result<Option<ExportJob>>;

    // === MAGIC LINK OPERATIONS ===

    /// Store a new magic link. An existing link is never replaced
    /// (`Conflict`): a consumed link stays consumed.
    async fn create_magic_link_session(
        &self,
        session: &MagicLinkSession,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Get a magic link session by ID.
    async fn get_magic_link_session(&self, id: Uuid) -> Result<Option<MagicLinkSession>>;

    /// Mark a magic link session as consumed.
    async fn consume_magic_link_session(&self, id: Uuid, ctx: MutationContext) -> Result<()>;

    /// Atomically consume a magic link session (single-use enforcement).
    /// Returns the session if it was successfully consumed (consumed was false → true).
    /// Returns None if already consumed or not found — prevents TOCTOU race.
    /// SQL: `UPDATE ... SET consumed = true WHERE id = ? AND consumed = false RETURNING *`
    async fn try_consume_magic_link_session(
        &self,
        id: Uuid,
        ctx: MutationContext,
    ) -> Result<Option<MagicLinkSession>>;

    /// Delete expired magic link sessions (cleanup).
    async fn delete_expired_magic_link_sessions(&self, ctx: MutationContext) -> Result<u64>;

    /// Count active (non-consumed, non-expired) magic link sessions for an email.
    async fn count_active_magic_links_for_email(&self, email: &str) -> Result<u32>;

    // === SCIM OUTBOUND PROVISIONING ===

    /// Insert a new SCIM outbound target; an existing id is `Conflict`, never replaced.
    async fn create_scim_outbound_target(
        &self,
        target: &ScimOutboundTarget,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Get a SCIM outbound target by ID.
    async fn get_scim_outbound_target(
        &self,
        id: ScimOutboundTargetId,
    ) -> Result<Option<ScimOutboundTarget>>;

    /// List all enabled SCIM outbound targets for a project.
    async fn list_scim_outbound_targets(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ScimOutboundTarget>>;

    /// Delete a SCIM outbound target by ID.
    async fn delete_scim_outbound_target(
        &self,
        id: ScimOutboundTargetId,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Insert a mapping as it stands (snapshot import); an existing mapping
    /// for the same target, entity and type is `Conflict`, never replaced.
    async fn create_scim_outbound_record(
        &self,
        record: &ScimOutboundRecord,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Record a successful provisioning: the mapping points at
    /// `record.downstream_id`, its error and failure count are cleared, its
    /// creation time is kept when it already existed.
    async fn record_scim_outbound_sync(
        &self,
        record: &ScimOutboundRecord,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Count a failed delivery on an existing mapping in place, keeping the
    /// downstream id; `false` when there is no mapping.
    async fn record_scim_outbound_failure(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
        error: &str,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Find downstream ID for a SID entity in a specific target.
    async fn get_scim_outbound_record(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
    ) -> Result<Option<ScimOutboundRecord>>;

    /// Store a failed delivery in the outbound DLQ; an existing id is
    /// `Conflict`, never replaced.
    async fn create_outbound_dlq_entry(
        &self,
        entry: &OutboundDlqEntry,
        ctx: MutationContext,
    ) -> Result<()>;

    /// List outbound DLQ entries for admin review.
    async fn list_outbound_dlq_entries(
        &self,
        target_id: ScimOutboundTargetId,
    ) -> Result<Vec<OutboundDlqEntry>>;

    /// Delete an outbound DLQ entry (after retry or dismissal).
    async fn delete_outbound_dlq_entry(&self, id: Uuid, ctx: MutationContext) -> Result<()>;

    // === AUTH FLOW CONFIGURATION ===

    /// Get flow configuration for a project and flow type.
    async fn get_flow_config(
        &self,
        project_id: sid_core::models::ProjectId,
        flow_type: sid_core::models::FlowType,
    ) -> Result<Option<sid_core::models::FlowConfig>>;

    /// Save flow configuration (insert or update).
    async fn save_flow_config(
        &self,
        config: &sid_core::models::FlowConfig,
        ctx: MutationContext,
    ) -> Result<()>;

    /// List all flow configs for a project.
    async fn list_flow_configs(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> Result<Vec<sid_core::models::FlowConfig>>;

    // === AUTH FLOW ACTIONS ===

    /// Insert a new flow action; an existing id is `Conflict`, never replaced.
    async fn create_flow_action(
        &self,
        action: &sid_core::models::FlowAction,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Write `action` over the revision it was read at and move the revision
    /// on; `false` when it was deleted or changed since.
    async fn update_flow_action(
        &self,
        action: &sid_core::models::FlowAction,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Get a flow action by ID.
    async fn get_flow_action(
        &self,
        id: sid_core::models::ActionId,
    ) -> Result<Option<sid_core::models::FlowAction>>;

    /// List flow actions for a project, flow type, and action point.
    async fn list_flow_actions(
        &self,
        project_id: sid_core::models::ProjectId,
        flow_type: sid_core::models::FlowType,
        action_point: Option<sid_core::models::ActionPoint>,
    ) -> Result<Vec<sid_core::models::FlowAction>>;

    /// Delete a flow action by ID.
    async fn delete_flow_action(
        &self,
        id: sid_core::models::ActionId,
        ctx: MutationContext,
    ) -> Result<()>;

    // === BRANDING OPERATIONS ===

    /// Insert a new branding configuration; an existing id is `Conflict`, and
    /// a second published config for the project is `Conflict`.
    async fn create_branding_config(
        &self,
        config: &sid_core::models::BrandingConfig,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Replace a draft's content over the revision it was read at; `false`
    /// when it is no longer a draft, was deleted, or changed since. The
    /// status is never written here.
    async fn update_branding_draft(
        &self,
        config: &sid_core::models::BrandingConfig,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Publish a draft of `project_id` and archive the project's published
    /// config in one transaction; `false` when `id` is not a draft of that project.
    async fn publish_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
        project_id: sid_core::models::ProjectId,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Get the published branding config for a project.
    async fn get_published_branding(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> Result<Option<sid_core::models::BrandingConfig>>;

    /// Get a branding config by ID.
    async fn get_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
    ) -> Result<Option<sid_core::models::BrandingConfig>>;

    /// List branding configs for a project (all statuses).
    async fn list_branding_configs(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> Result<Vec<sid_core::models::BrandingConfig>>;

    /// Delete a branding config that is not published; `false` when it is
    /// published or gone.
    async fn delete_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === INVITE OPERATIONS ===

    /// Store a new invite; an existing id or code is `Conflict`, so a revoked
    /// or used-up invite is never reactivated by a repeated create.
    async fn create_invite(&self, invite: &Invite, ctx: MutationContext) -> Result<()>;

    /// Get an invite by ID.
    async fn get_invite(&self, id: InviteId) -> Result<Option<Invite>>;

    /// Get an invite by code (case-insensitive).
    async fn get_invite_by_code(&self, code: &str) -> Result<Option<Invite>>;

    /// The invites `filter` selects, newest first in one total order (creation
    /// time, then id), a page of `limit` from `offset`.
    async fn list_invites(
        &self,
        filter: &InviteFilter,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Invite>>;

    /// How many invites `filter` selects.
    async fn count_invites(&self, filter: &InviteFilter) -> Result<u64>;

    /// Atomically increment invite use_count. Returns updated invite if successful
    /// (use_count < max_uses and active and not expired). Returns None if invite
    /// cannot be used — prevents TOCTOU race.
    /// SQL: `UPDATE invites SET use_count = use_count + 1 WHERE id = ? AND active = true
    ///        AND (max_uses = 0 OR use_count < max_uses) AND (expires_at IS NULL OR expires_at > NOW())
    ///        RETURNING *`
    async fn try_use_invite(&self, id: InviteId, ctx: MutationContext) -> Result<Option<Invite>>;

    /// Revoke an invite (set active = false).
    async fn revoke_invite(&self, id: InviteId, ctx: MutationContext) -> Result<()>;

    // === REGISTRATION SOURCE OPERATIONS ===

    /// Get the registration source for a profile.
    async fn get_registration_source(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<RegistrationSource>>;

    /// Count registrations by source type in a time range.
    async fn count_registrations_by_source(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Vec<(RegistrationSourceType, u64)>>;

    /// Get top referrers in a time range.
    async fn top_referrers(
        &self,
        since: DateTime<Utc>,
        limit: u64,
    ) -> Result<Vec<(ProfileId, u64)>>;

    // === DISTRIBUTED LOCKING ===

    /// The committed completion of the keyed command `key` in `namespace`
    /// (recorded through [`MutationContext::operation`]), if any.
    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &sid_core::models::OperationKey,
    ) -> Result<Option<sid_core::models::OperationRecord>>;

    /// Every committed completion, to carry to another store: a retry that
    /// arrives after a migration must still find its result.
    async fn export_operation_results(&self) -> Result<Vec<sid_core::models::OperationRecord>>;

    /// Store an exported completion with its original completion time.
    /// Returns `false`, writing nothing, when its key is already completed in
    /// its namespace.
    async fn import_operation_result(
        &self,
        record: &sid_core::models::OperationRecord,
    ) -> Result<bool>;

    /// Take the lock of background job `job` unless some instance on this
    /// store holds it (`None`: the job is skipped this round). The lock is
    /// held until [`JobLock::release`]; a dropped lock frees itself.
    async fn try_job_lock(&self, job: i64) -> Result<Option<JobLock>>;

    /// Prepare audit storage for the calendar month starting at `month_start`
    /// (the first day of a month), so that month's records have a place
    /// before it begins; `true` when something was created. A backend that
    /// keeps audit records in one store has nothing to prepare.
    async fn ensure_audit_partition(&self, month_start: chrono::NaiveDate) -> Result<bool>;

    /// Remove the audit records of every calendar month that ended at or
    /// before `cut_before`, never a record of a month still running on it,
    /// and in the same transaction record for every chain touched the last
    /// removed record's sequence and hash, so the chain still verifies from
    /// there. Returns the number of records removed.
    async fn drop_expired_audit_records(
        &self,
        cut_before: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<u64>;

    // === NOTIFICATION PREFERENCES ===

    /// Get notification preferences for a profile.
    /// Returns None if the profile hasn't customized preferences (use defaults).
    async fn get_notification_preferences(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<sid_core::models::notification::NotificationPreferences>>;

    /// Save notification preferences for a profile (upsert).
    async fn save_notification_preferences(
        &self,
        preferences: &sid_core::models::notification::NotificationPreferences,
        ctx: MutationContext,
    ) -> Result<()>;

    // === INTEGRITY VERIFICATION ===

    /// Count orphaned sessions (sessions referencing non-existent profiles).
    async fn count_orphaned_sessions(&self) -> Result<u64>;

    /// Count orphaned credentials (credentials referencing non-existent profiles).
    async fn count_orphaned_credentials(&self) -> Result<u64>;

    /// Count orphaned role assignments (assignments referencing non-existent profiles or roles).
    async fn count_orphaned_role_assignments(&self) -> Result<u64>;

    // === ACCESS REQUEST OPERATIONS ===

    /// Insert a new access request; an existing id is `Conflict`, never
    /// replaced (a decision goes through `decide_access_request`).
    async fn create_access_request(
        &self,
        request: &AccessRequest,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Get an access request by ID.
    async fn get_access_request(&self, id: AccessRequestId) -> Result<Option<AccessRequest>>;

    /// List pending access requests (status = Pending, not expired).
    async fn list_pending_access_requests(&self) -> Result<Vec<AccessRequest>>;

    /// Record the decision in `request` (status, reviewer, comment, review
    /// time) on a request that is still pending in storage. Returns `false`
    /// and writes nothing when it was already decided, so of concurrent
    /// reviewers exactly one decides. An approval is refused here
    /// (`Validation`): it goes through [`Self::approve_access_request`].
    async fn decide_access_request(
        &self,
        request: &AccessRequest,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Record the approval in `request` together with `grant`, the
    /// requester's assignment of the requested role, in one write. Returns
    /// `false` and writes nothing when the request was already decided; an
    /// assignment that cannot be stored fails the whole approval and leaves
    /// the request pending.
    async fn approve_access_request(
        &self,
        request: &AccessRequest,
        grant: &RoleAssignment,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === PASSWORD RESET SESSION OPERATIONS ===

    /// Store a new password reset session. An existing one is never replaced
    /// (`Conflict`).
    async fn create_reset_session(
        &self,
        session: &sid_core::models::PasswordResetSession,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Get a password reset session by ID.
    async fn get_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
    ) -> Result<Option<sid_core::models::PasswordResetSession>>;

    /// Mark a pending, unexpired reset session verified (its emailed token
    /// was checked). Returns `false` and writes nothing otherwise, so a token
    /// is verified once across concurrent requests.
    async fn verify_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Complete a verified, unexpired reset in one transaction: mark it
    /// completed, install `credential` (OPAQUE) as the profile's only
    /// password, apply `history` (the accepted password's entries) to its
    /// owner's history and end every session of the profile under `end`
    /// (each owes what `end` says). Returns the ended sessions, or `None`
    /// with nothing written when the reset is not verified, has expired or
    /// the history moved past `history.expected_revision`, so of concurrent
    /// completions exactly one sets a password.
    async fn complete_password_reset(
        &self,
        id: sid_core::models::ResetSessionId,
        credential: &Credential,
        history: Option<&HistoryCommit>,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> Result<Option<Vec<Session>>>;

    /// Count active (pending/verified, non-expired) reset sessions for a profile.
    async fn count_active_reset_sessions(&self, profile_id: ProfileId) -> Result<u32>;

    /// Delete expired reset sessions.
    async fn delete_expired_reset_sessions(&self, ctx: MutationContext) -> Result<u64>;

    // No blind vault: data is stored in plaintext, without a data_key.

    // ── Email provider config ────────────────────────────────────────────────

    /// Get the instance-level email provider configuration (singleton row).
    ///
    /// Returns `None` if the admin has not yet configured SMTP (sid-notify
    /// then falls back to env-var config).
    async fn get_email_provider_config(
        &self,
    ) -> Result<Option<sid_core::models::EmailProviderConfig>>;

    /// Insert or update the instance-level email provider configuration.
    ///
    /// Always writes the singleton row (id = `00000000-0000-0000-0000-000000000001`).
    /// The audit entry is written in the same transaction.
    async fn upsert_email_provider_config(
        &self,
        config: &sid_core::models::EmailProviderConfig,
        ctx: MutationContext,
    ) -> Result<()>;
}
