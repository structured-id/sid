// SPDX-License-Identifier: AGPL-3.0-only
//! SID's records in a host's CoordiNode database, through the database handle
//! the host already holds. Every change runs in one interactive transaction:
//! CoordiNode refuses a commit whose write set another transaction changed
//! since it began, or whose pinned reads ([`Statements::hold`]) changed, and
//! the whole transaction is run again from the start. A plain read is not
//! checked at commit: what a decision rests on is either written or held.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use coordinode_core::graph::node::NodeId;
use coordinode_core::graph::types::Value;
use coordinode_embed::{Database, DatabaseError, TransactionId};
use sid_core::models::MutationContext;
use sid_core::{Error as SidError, Result as SidResult};

mod audit;
mod backend;
mod ceremony;
mod credential;
mod directory;
mod enrollment;
mod instance_secret;
mod login_policy;
mod machine;
mod operation;
mod principal;
mod profile;
mod project;
mod rbac;
mod registry;
mod session;
mod work;

/// How often one change is run again after a conflicting commit before it is
/// reported: each retry follows a commit that changed what it read, so a
/// change that keeps losing is contended past any useful bound.
const CONFLICT_RETRIES: u32 = 64;

/// The pause before a run again, multiplied by the round (up to 40).
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_micros(50);

/// The schema SID's records rely on: what keeps an identifier unique across
/// concurrent writers. Nodes that writers of one thing meet on (a work kind's
/// admission, an audit chain's head, a command key) are unique too, so the
/// first writers create one node and conflict instead of each creating its
/// own.
const SCHEMA: &[&str] = &[
    "CREATE CONSTRAINT sid_work_id FOR (w:SidWork) REQUIRE w.id IS UNIQUE",
    "CREATE CONSTRAINT sid_work_kind FOR (k:SidWorkKind) REQUIRE k.kind IS UNIQUE",
    "CREATE CONSTRAINT sid_audit_head FOR (h:SidAuditHead) REQUIRE h.chain IS UNIQUE",
    "CREATE CONSTRAINT sid_audit_record FOR (r:SidAuditRecord) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT sid_operation_slot FOR (o:SidOperation) REQUIRE o.slot IS UNIQUE",
    "CREATE CONSTRAINT sid_operation_period FOR (p:SidOperationPeriod) REQUIRE p.period IS UNIQUE",
    "CREATE CONSTRAINT sid_operation_state FOR (s:SidOperationState) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT sid_ceremony_state FOR (c:SidCeremonyState) REQUIRE c.slot IS UNIQUE",
    "CREATE CONSTRAINT sid_ceremony_count FOR (c:SidCeremonyCount) REQUIRE c.slot IS UNIQUE",
    "CREATE CONSTRAINT sid_instance_secret FOR (s:SidInstanceSecret) REQUIRE s.name IS UNIQUE",
    "CREATE CONSTRAINT sid_profile_id FOR (p:SidProfile) REQUIRE p.id IS UNIQUE",
    "CREATE CONSTRAINT sid_profile_username FOR (p:SidProfile) REQUIRE p.username IS UNIQUE",
    "CREATE INDEX sid_profile_status ON :SidProfile(status)",
    "CREATE INDEX sid_profile_migration ON :SidProfile(migration_pending)",
    "CREATE CONSTRAINT sid_phone_id FOR (c:SidPhone) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_phone_number FOR (c:SidPhone) REQUIRE c.number_key IS UNIQUE",
    "CREATE CONSTRAINT sid_phone_primary FOR (c:SidPhone) REQUIRE c.primary_of IS UNIQUE",
    "CREATE INDEX sid_phone_profile ON :SidPhone(profile_id)",
    "CREATE CONSTRAINT sid_email_id FOR (c:SidEmail) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_email_address FOR (c:SidEmail) REQUIRE c.address_key IS UNIQUE",
    "CREATE CONSTRAINT sid_email_primary FOR (c:SidEmail) REQUIRE c.primary_of IS UNIQUE",
    "CREATE INDEX sid_email_profile ON :SidEmail(profile_id)",
    "CREATE INDEX sid_email_address_lookup ON :SidEmail(email)",
    "CREATE CONSTRAINT sid_principal_id FOR (p:SidPrincipal) REQUIRE p.id IS UNIQUE",
    "CREATE CONSTRAINT sid_principal_value FOR (p:SidPrincipal) REQUIRE p.type_value IS UNIQUE",
    "CREATE INDEX sid_principal_assigned ON :SidPrincipal(assigned_profile_id)",
    "CREATE CONSTRAINT sid_principal_binding_id FOR (b:SidPrincipalBinding) REQUIRE b.id IS UNIQUE",
    "CREATE CONSTRAINT sid_principal_binding_pair FOR (b:SidPrincipalBinding) REQUIRE b.pair IS UNIQUE",
    "CREATE INDEX sid_principal_binding_principal ON :SidPrincipalBinding(principal_id)",
    "CREATE INDEX sid_principal_binding_profile ON :SidPrincipalBinding(profile_id)",
    "CREATE CONSTRAINT sid_email_policy FOR (a:SidEmailPolicy) REQUIRE a.scope IS UNIQUE",
    "CREATE CONSTRAINT sid_email_disposition FOR (d:SidEmailDisposition) REQUIRE d.principal_id IS UNIQUE",
    "CREATE CONSTRAINT sid_principal_quarantine FOR (q:SidPrincipalQuarantine) REQUIRE q.hash IS UNIQUE",
    "CREATE CONSTRAINT sid_project_id FOR (j:SidProject) REQUIRE j.id IS UNIQUE",
    "CREATE INDEX sid_project_owner ON :SidProject(owner_id)",
    "CREATE CONSTRAINT sid_session_id FOR (s:SidSession) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT sid_session_browser FOR (s:SidSession) REQUIRE s.browser_secret_hash IS UNIQUE",
    "CREATE INDEX sid_session_profile ON :SidSession(profile_id)",
    "CREATE INDEX sid_session_authenticated_by ON :SidSession(authenticated_by)",
    "CREATE CONSTRAINT sid_refresh_token_id FOR (t:SidRefreshToken) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT sid_refresh_token_hash FOR (t:SidRefreshToken) REQUIRE t.token_hash IS UNIQUE",
    "CREATE INDEX sid_refresh_token_session ON :SidRefreshToken(session_id)",
    "CREATE INDEX sid_refresh_token_family ON :SidRefreshToken(family_id)",
    "CREATE INDEX sid_refresh_token_profile ON :SidRefreshToken(profile_id)",
    "CREATE CONSTRAINT sid_auth_code_hash FOR (a:SidAuthCode) REQUIRE a.code_hash IS UNIQUE",
    "CREATE INDEX sid_auth_code_session ON :SidAuthCode(authorizing_session_id)",
    "CREATE INDEX sid_auth_code_profile ON :SidAuthCode(profile_id)",
    "CREATE CONSTRAINT sid_native_generation_id FOR (g:SidNativeGeneration) REQUIRE g.id IS UNIQUE",
    "CREATE CONSTRAINT sid_native_generation_successor FOR (g:SidNativeGeneration) REQUIRE g.successor_id IS UNIQUE",
    "CREATE INDEX sid_native_generation_session ON :SidNativeGeneration(session_id)",
    "CREATE CONSTRAINT sid_native_credential FOR (c:SidNativeCredential) REQUIRE c.credential_hash IS UNIQUE",
    "CREATE INDEX sid_native_credential_generation ON :SidNativeCredential(generation_id)",
    "CREATE CONSTRAINT sid_issuer_id FOR (i:SidIssuer) REQUIRE i.id IS UNIQUE",
    "CREATE CONSTRAINT sid_issuer_handle FOR (i:SidIssuer) REQUIRE i.handle IS UNIQUE",
    "CREATE CONSTRAINT sid_issuer_authority FOR (i:SidIssuer) REQUIRE i.authority_key IS UNIQUE",
    "CREATE CONSTRAINT sid_issuer_key FOR (k:SidIssuerKey) REQUIRE k.generation_key IS UNIQUE",
    "CREATE INDEX sid_issuer_key_issuer ON :SidIssuerKey(issuer_id)",
    "CREATE CONSTRAINT sid_organization_id FOR (o:SidOrganization) REQUIRE o.id IS UNIQUE",
    "CREATE CONSTRAINT sid_organization_instance FOR (o:SidOrganization) REQUIRE o.is_instance IS UNIQUE",
    "CREATE CONSTRAINT sid_application_id FOR (a:SidApplication) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT sid_application_system FOR (a:SidApplication) REQUIRE a.system_integration IS UNIQUE",
    "CREATE INDEX sid_application_project ON :SidApplication(project_id)",
    "CREATE CONSTRAINT sid_client_id FOR (c:SidClient) REQUIRE c.client_id IS UNIQUE",
    "CREATE CONSTRAINT sid_client_application FOR (c:SidClient) REQUIRE c.application_id IS UNIQUE",
    "CREATE INDEX sid_client_project ON :SidClient(project_id)",
    "CREATE INDEX sid_client_default_resource ON :SidClient(default_resource)",
    "CREATE CONSTRAINT sid_resource_id FOR (r:SidResource) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT sid_resource_indicator FOR (r:SidResource) REQUIRE r.indicator_key IS UNIQUE",
    "CREATE CONSTRAINT sid_resource_application FOR (r:SidResource) REQUIRE r.application_id IS UNIQUE",
    "CREATE CONSTRAINT sid_resource_access FOR (x:SidResourceAccess) REQUIRE x.pair IS UNIQUE",
    "CREATE INDEX sid_resource_access_client ON :SidResourceAccess(client_id)",
    "CREATE INDEX sid_resource_access_resource ON :SidResourceAccess(resource_id)",
    "CREATE CONSTRAINT sid_iat_id FOR (t:SidInitialAccessToken) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT sid_iat_hash FOR (t:SidInitialAccessToken) REQUIRE t.token_hash IS UNIQUE",
    "CREATE INDEX sid_iat_project ON :SidInitialAccessToken(project_id)",
    "CREATE CONSTRAINT sid_credential_id FOR (c:SidCredential) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_credential_active_password FOR (c:SidCredential) REQUIRE c.active_password_of IS UNIQUE",
    "CREATE INDEX sid_credential_profile ON :SidCredential(profile_id)",
    "CREATE INDEX sid_credential_type ON :SidCredential(credential_type)",
    "CREATE CONSTRAINT sid_webauthn_pair FOR (w:SidWebAuthnHandle) REQUIRE w.pair IS UNIQUE",
    "CREATE CONSTRAINT sid_webauthn_handle FOR (w:SidWebAuthnHandle) REQUIRE w.handle_key IS UNIQUE",
    "CREATE INDEX sid_webauthn_profile ON :SidWebAuthnHandle(profile_id)",
    "CREATE CONSTRAINT sid_password_history FOR (r:SidPasswordHistory) REQUIRE r.owner_id IS UNIQUE",
    "CREATE CONSTRAINT sid_history_epoch_id FOR (e:SidHistoryEpoch) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT sid_history_epoch_active FOR (e:SidHistoryEpoch) REQUIRE e.active_of IS UNIQUE",
    "CREATE INDEX sid_history_epoch_owner ON :SidHistoryEpoch(owner_id)",
    "CREATE CONSTRAINT sid_history_entry FOR (h:SidHistoryEntry) REQUIRE h.key IS UNIQUE",
    "CREATE INDEX sid_history_entry_owner ON :SidHistoryEntry(owner_id)",
    "CREATE CONSTRAINT sid_history_cutoff FOR (c:SidHistoryCutoff) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_role_id FOR (r:SidRole) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT sid_role_key FOR (r:SidRole) REQUIRE r.project_key IS UNIQUE",
    "CREATE CONSTRAINT sid_role_name FOR (r:SidRole) REQUIRE r.project_name IS UNIQUE",
    "CREATE INDEX sid_role_project ON :SidRole(project_id)",
    "CREATE CONSTRAINT sid_group_id FOR (g:SidGroup) REQUIRE g.id IS UNIQUE",
    "CREATE CONSTRAINT sid_group_name FOR (g:SidGroup) REQUIRE g.project_name IS UNIQUE",
    "CREATE INDEX sid_group_project ON :SidGroup(project_id)",
    "CREATE INDEX sid_group_parent ON :SidGroup(parent_group_id)",
    "CREATE CONSTRAINT sid_group_member FOR (m:SidGroupMember) REQUIRE m.pair IS UNIQUE",
    "CREATE INDEX sid_group_member_group ON :SidGroupMember(group_id)",
    "CREATE INDEX sid_group_member_profile ON :SidGroupMember(profile_id)",
    "CREATE CONSTRAINT sid_assignment_id FOR (a:SidRoleAssignment) REQUIRE a.id IS UNIQUE",
    "CREATE INDEX sid_assignment_profile ON :SidRoleAssignment(profile_id)",
    "CREATE INDEX sid_assignment_group ON :SidRoleAssignment(group_id)",
    "CREATE INDEX sid_assignment_machine_user ON :SidRoleAssignment(machine_user_id)",
    "CREATE INDEX sid_assignment_client ON :SidRoleAssignment(oauth_client_id)",
    "CREATE INDEX sid_assignment_connector ON :SidRoleAssignment(connector_id)",
    "CREATE INDEX sid_assignment_role ON :SidRoleAssignment(role_id)",
    "CREATE INDEX sid_assignment_depends_on ON :SidRoleAssignment(depends_on_id)",
    "CREATE INDEX sid_assignment_admin_group ON :SidRoleAssignment(admin_group)",
    "CREATE INDEX sid_assignment_expires ON :SidRoleAssignment(expires_at)",
    "CREATE CONSTRAINT sid_admin_role FOR (e:SidAdminRole) REQUIRE e.pair IS UNIQUE",
    "CREATE INDEX sid_admin_role_assignment ON :SidAdminRole(assignment_id)",
    "CREATE INDEX sid_admin_role_role ON :SidAdminRole(role_id)",
    "CREATE CONSTRAINT sid_policy_id FOR (c:SidCedarPolicy) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_policy_name FOR (c:SidCedarPolicy) REQUIRE c.scope_name IS UNIQUE",
    "CREATE INDEX sid_policy_kind ON :SidCedarPolicy(scope_kind)",
    "CREATE INDEX sid_policy_project ON :SidCedarPolicy(project_id)",
    "CREATE INDEX sid_policy_resource ON :SidCedarPolicy(resource_id)",
    "CREATE CONSTRAINT sid_access_request_id FOR (q:SidAccessRequest) REQUIRE q.id IS UNIQUE",
    "CREATE INDEX sid_access_request_status ON :SidAccessRequest(status)",
    "CREATE INDEX sid_access_request_requester ON :SidAccessRequest(requester_id)",
    "CREATE INDEX sid_access_request_project ON :SidAccessRequest(project_id)",
    "CREATE CONSTRAINT sid_enrollment_policy FOR (p:SidEnrollmentPolicy) REQUIRE p.scope IS UNIQUE",
    "CREATE CONSTRAINT sid_bootstrap_policy FOR (p:SidBootstrapPolicy) REQUIRE p.scope IS UNIQUE",
    "CREATE CONSTRAINT sid_invite_id FOR (i:SidInvite) REQUIRE i.id IS UNIQUE",
    "CREATE CONSTRAINT sid_invite_code FOR (i:SidInvite) REQUIRE i.code_key IS UNIQUE",
    "CREATE CONSTRAINT sid_invite_redemption FOR (r:SidInviteRedemption) REQUIRE r.pair IS UNIQUE",
    "CREATE INDEX sid_invite_redemption_invite ON :SidInviteRedemption(invite_id)",
    "CREATE INDEX sid_invite_redemption_profile ON :SidInviteRedemption(profile_id)",
    "CREATE CONSTRAINT sid_registration_source FOR (s:SidRegistrationSource) REQUIRE s.profile_id IS UNIQUE",
    "CREATE INDEX sid_registration_source_created ON :SidRegistrationSource(created_at)",
    "CREATE CONSTRAINT sid_machine_user_id FOR (m:SidMachineUser) REQUIRE m.id IS UNIQUE",
    "CREATE CONSTRAINT sid_machine_user_client FOR (m:SidMachineUser) REQUIRE m.client_id IS UNIQUE",
    "CREATE INDEX sid_machine_user_project ON :SidMachineUser(project_id)",
    "CREATE CONSTRAINT sid_machine_credential FOR (k:SidMachineCredential) REQUIRE k.kid IS UNIQUE",
    "CREATE INDEX sid_machine_credential_user ON :SidMachineCredential(machine_user_id)",
    "CREATE INDEX sid_machine_credential_expires ON :SidMachineCredential(expires_at)",
    "CREATE CONSTRAINT sid_impersonation_grant FOR (g:SidImpersonationGrant) REQUIRE g.triple IS UNIQUE",
    "CREATE INDEX sid_impersonation_grant_user ON :SidImpersonationGrant(machine_user_id)",
    "CREATE CONSTRAINT sid_connector_id FOR (c:SidProvisioningConnector) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_connector_client FOR (c:SidProvisioningConnector) REQUIRE c.client_id IS UNIQUE",
    "CREATE INDEX sid_connector_org ON :SidProvisioningConnector(org_id)",
    "CREATE CONSTRAINT sid_connector_credential_id FOR (k:SidProvisioningCredential) REQUIRE k.id IS UNIQUE",
    "CREATE CONSTRAINT sid_connector_credential_verifier FOR (k:SidProvisioningCredential) REQUIRE k.verifier IS UNIQUE",
    "CREATE INDEX sid_connector_credential_connector ON :SidProvisioningCredential(connector_id)",
    "CREATE CONSTRAINT sid_login_policy_epoch FOR (e:SidLoginPolicyEpoch) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT sid_profile_metadata FOR (m:SidProfileMetadata) REQUIRE m.pair IS UNIQUE",
    "CREATE INDEX sid_profile_metadata_profile ON :SidProfileMetadata(profile_id)",
    "CREATE CONSTRAINT sid_pat_id FOR (t:SidPat) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT sid_pat_hash FOR (t:SidPat) REQUIRE t.token_hash IS UNIQUE",
    "CREATE INDEX sid_pat_profile ON :SidPat(profile_id)",
    "CREATE INDEX sid_pat_status ON :SidPat(status)",
];

/// SID's storage over the host's CoordiNode database.
#[derive(Clone)]
pub struct CoordinodeBackend {
    db: Arc<Database>,
}

impl CoordinodeBackend {
    /// SID's storage in `db`, the host's own database. Declares the schema
    /// SID's records need; a constraint declared before is kept as it is.
    pub async fn new(db: Arc<Database>) -> SidResult<Self> {
        let backend = Self { db };
        backend
            .blocking(|db| {
                for statement in SCHEMA {
                    match db.execute_cypher_shared(statement, None, None, None, None) {
                        Ok(_) | Err(DatabaseError::CatalogObjectExists { .. }) => {}
                        Err(e) => return Err(storage(e)),
                    }
                }
                Ok(())
            })
            .await?;
        backend.transaction(operation::init_state).await?;
        backend.transaction(principal::init_email_policy).await?;
        backend.transaction(project::init_system_project).await?;
        backend.transaction(credential::init_cutoff).await?;
        backend.transaction(enrollment::init_policies).await?;
        Ok(backend)
    }

    /// Run `f` on the database off the async runtime: CoordiNode's API
    /// blocks the calling thread.
    async fn blocking<T, F>(&self, f: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> SidResult<T> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db))
            .await
            .map_err(|e| SidError::Internal(format!("CoordiNode call: {e}")))?
    }

    /// Run `change` in a transaction and commit what it decided, again from
    /// the start whenever the commit conflicts.
    async fn transaction<T, F>(&self, change: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnMut(&Statements<'_>) -> SidResult<Decision<T>> + Send + 'static,
    {
        self.blocking(move |db| in_transaction(db, change)).await
    }

    /// Run `read` in a transaction that writes nothing.
    async fn read<T, F>(&self, mut read: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnMut(&Statements<'_>) -> SidResult<T> + Send + 'static,
    {
        self.transaction(move |tx| read(tx).map(Decision::Abandon))
            .await
    }

    /// Commit `ctx` with whatever `change` wrote in the same transaction:
    /// its audit record on `chain`, its command completion and its owed
    /// work, all of it or none.
    async fn mutate<F>(&self, chain: String, ctx: MutationContext, mut change: F) -> SidResult<()>
    where
        F: FnMut(&Statements<'_>) -> SidResult<()> + Send + 'static,
    {
        self.transaction(move |tx| {
            change(tx)?;
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(()))
        })
        .await
    }
}

/// What every mutation commits besides its own state, in its transaction.
fn finalize(tx: &Statements<'_>, chain: &str, ctx: MutationContext) -> SidResult<()> {
    // The authority first: a write whose actor or policy changed commits
    // nothing. What the fence names is held for the commit.
    match ctx.fence {
        Some(sid_core::models::ActorFence::Connector {
            connector,
            revision,
            credential,
        }) => machine::check_connector_fence(tx, connector, revision, credential)?,
        Some(sid_core::models::ActorFence::LoginPolicy { epoch }) => {
            login_policy::check_fence(tx, epoch)?
        }
        Some(sid_core::models::ActorFence::Authority(basis)) => rbac::check_authority(tx, &basis)?,
        None => {}
    }
    // Then the completion: a keyed command another commit already completed
    // commits nothing, not even its audit or work.
    if let Some(completion) = &ctx.operation {
        operation::record(tx, completion)?;
    }
    audit::append(tx, chain, ctx.audit, chrono::Utc::now())?;
    for owed in &ctx.work {
        work::insert(tx, owed, sid_plugin::OWED_WORK_CAPACITY)?;
    }
    Ok(())
}

/// What a transaction's body decided.
pub(super) enum Decision<T> {
    /// Commit its writes and answer `T`.
    Commit(T),
    /// Write nothing and answer `T`.
    Abandon(T),
}

/// The statements of one open transaction.
pub(super) struct Statements<'a> {
    db: &'a Database,
    id: TransactionId,
    /// Set when a statement was refused for a concurrent transaction: the
    /// whole transaction runs again rather than failing.
    contended: Cell<bool>,
}

impl Statements<'_> {
    pub(super) fn run(&self, query: &str, params: Params) -> SidResult<Vec<Row>> {
        self.db
            .execute_in_transaction(self.id, query, Some(params.0))
            .map_err(|e| {
                if contention(&e) {
                    self.contended.set(true);
                }
                storage(e)
            })
    }

    /// Commit only while the node `node` (its `id(n)`) stays as it is now:
    /// a decision built on it is refused, and run again, when another commit
    /// changed or deleted it meanwhile. `false` when it is gone already.
    pub(super) fn hold(&self, node: i64) -> SidResult<bool> {
        let node = NodeId::from_raw(
            u64::try_from(node).map_err(|_| SidError::Storage(format!("bad node id {node}")))?,
        );
        let Some(version) = self.db.node_version(node).map_err(storage)? else {
            return Ok(false);
        };
        self.db
            .expect_node_version(self.id, node, Some(version))
            .map_err(storage)?;
        Ok(true)
    }
}

/// One result row, by column name (CoordiNode's row shape).
pub(super) type Row = std::collections::BTreeMap<String, Value>;

/// Statement parameters by name.
#[derive(Default, Clone)]
pub(super) struct Params(HashMap<String, Value>);

impl Params {
    pub(super) fn with(mut self, name: &str, value: Value) -> Self {
        self.0.insert(name.to_owned(), value);
        self
    }
}

fn in_transaction<T, F>(db: &Database, mut change: F) -> SidResult<T>
where
    F: FnMut(&Statements<'_>) -> SidResult<Decision<T>>,
{
    for attempt in 0..=CONFLICT_RETRIES {
        if attempt > 0 {
            // A refusal for a claim another transaction holds clears only
            // when that one ends: give it the time, longer each round.
            std::thread::sleep(RETRY_PAUSE * attempt.min(40));
        }
        let id = db.begin_transaction().map_err(storage)?;
        let statements = Statements {
            db,
            id,
            contended: Cell::new(false),
        };
        let decided = match change(&statements) {
            Ok(decided) => decided,
            Err(e) => {
                // A failed statement already ended the transaction.
                db.rollback_transaction(id).ok();
                if statements.contended.get() {
                    continue;
                }
                return Err(e);
            }
        };
        match decided {
            Decision::Abandon(answer) => {
                db.rollback_transaction(id).map_err(storage)?;
                return Ok(answer);
            }
            Decision::Commit(answer) => match db.commit_transaction(id) {
                Ok(_) => return Ok(answer),
                Err(e) if contention(&e) => continue,
                Err(e) => return Err(storage(e)),
            },
        }
    }
    Err(SidError::Storage(format!(
        "CoordiNode transaction conflicted {CONFLICT_RETRIES} times in a row"
    )))
}

/// A refusal caused by a concurrent transaction, which nothing applied and
/// a run again resolves on what that transaction left.
fn contention(e: &DatabaseError) -> bool {
    matches!(
        e,
        DatabaseError::TransactionConflict { .. }
            | DatabaseError::RevisionMismatch { .. }
            | DatabaseError::InvariantRefused { .. }
    )
}

fn storage(e: DatabaseError) -> SidError {
    match e {
        // A unique key already held: the record exists. The index names it;
        // the value is the caller's input and stays out of the message.
        DatabaseError::UniqueViolation { index, .. } => {
            SidError::Conflict(format!("{index} already exists"))
        }
        e => SidError::Storage(format!("CoordiNode: {e}")),
    }
}

// ─── Values ───

/// The node key of `key` in `namespace`: the namespace's length first, so
/// no two pairs share one.
pub(super) fn slot(namespace: &str, key: &str) -> SidResult<Vec<u8>> {
    let length = u32::try_from(namespace.len())
        .map_err(|_| SidError::Validation("namespace too long".into()))?;
    let mut slot = Vec::with_capacity(4 + namespace.len() + key.len());
    slot.extend_from_slice(&length.to_be_bytes());
    slot.extend_from_slice(namespace.as_bytes());
    slot.extend_from_slice(key.as_bytes());
    Ok(slot)
}

/// A UUID as its 16 bytes.
pub(super) fn uuid(id: &uuid::Uuid) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

pub(super) fn opt_uuid(id: Option<&uuid::Uuid>) -> Value {
    id.map_or(Value::Null, uuid)
}

/// Key bytes of `parts`, each prefixed by its length, so no two lists of
/// parts share one.
pub(super) fn key(parts: &[&[u8]]) -> SidResult<Value> {
    let mut key = Vec::with_capacity(parts.iter().map(|p| 4 + p.len()).sum());
    for part in parts {
        let length = u32::try_from(part.len())
            .map_err(|_| SidError::Validation("key part too long".into()))?;
        key.extend_from_slice(&length.to_be_bytes());
        key.extend_from_slice(part);
    }
    Ok(Value::Binary(key))
}

pub(super) fn texts(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

pub(super) fn get_uuid(row: &Row, name: &str) -> SidResult<uuid::Uuid> {
    uuid::Uuid::from_slice(&get_bytes(row, name)?)
        .map_err(|e| SidError::Storage(format!("{name} is no UUID: {e}")))
}

pub(super) fn get_opt_uuid(row: &Row, name: &str) -> SidResult<Option<uuid::Uuid>> {
    get_opt_bytes(row, name)?
        .map(|b| {
            uuid::Uuid::from_slice(&b)
                .map_err(|e| SidError::Storage(format!("{name} is no UUID: {e}")))
        })
        .transpose()
}

pub(super) fn get_texts(row: &Row, name: &str) -> SidResult<Vec<String>> {
    match field(row, name)? {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Ok(s.clone()),
                other => Err(SidError::Storage(format!("{name} holds {other:?}"))),
            })
            .collect(),
        other => Err(SidError::Storage(format!(
            "{name} is not a list: {other:?}"
        ))),
    }
}

/// A stored name of an owning enum; an unknown one is an error, never a
/// default.
pub(super) fn get_parsed<T: std::str::FromStr<Err = String>>(
    row: &Row,
    name: &str,
) -> SidResult<T> {
    get_text(row, name)?
        .parse()
        .map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

pub(super) fn get_opt_parsed<T: std::str::FromStr<Err = String>>(
    row: &Row,
    name: &str,
) -> SidResult<Option<T>> {
    get_opt_text(row, name)?
        .map(|text| {
            text.parse()
                .map_err(|e| SidError::Storage(format!("{name}: {e}")))
        })
        .transpose()
}

/// Hold the node the first row's `node` column names for the commit:
/// true when there is one and it still stands as read.
pub(super) fn hold_first(tx: &Statements<'_>, rows: &[Row]) -> SidResult<bool> {
    match rows.first() {
        Some(row) => tx.hold(get_int(row, "node")?),
        None => Ok(false),
    }
}

/// The count a `count(..) AS n` query returned.
pub(super) fn get_count(rows: &[Row]) -> SidResult<u64> {
    let n = rows
        .first()
        .map(|row| get_int(row, "n"))
        .transpose()?
        .unwrap_or(0);
    u64::try_from(n).map_err(|_| SidError::Storage(format!("bad count: {n}")))
}

/// Page `offset..offset + limit` of `items`, ordered by `key`. CoordiNode
/// orders no binary values (coordinode#84), and ids are 16 bytes: an order
/// they break ties of is taken here.
pub(super) fn sorted_page<T, K: Ord>(
    mut items: Vec<T>,
    key: impl Fn(&T) -> K,
    offset: u64,
    limit: u64,
) -> Vec<T> {
    items.sort_by_key(|item| key(item));
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    items.into_iter().skip(offset).take(limit).collect()
}

/// A page bound as the statement's integer.
pub(super) fn page(value: u64) -> SidResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| SidError::Validation(format!("page bound {value} out of range")))
}

pub(super) fn time(t: chrono::DateTime<chrono::Utc>) -> Value {
    Value::Int(t.timestamp_micros())
}

pub(super) fn opt_time(t: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    t.map_or(Value::Null, time)
}

pub(super) fn opt_text(t: Option<&str>) -> Value {
    t.map_or(Value::Null, |t| Value::String(t.to_owned()))
}

/// The value `name` of `row`; a missing column is a storage error.
fn field<'r>(row: &'r Row, name: &str) -> SidResult<&'r Value> {
    row.get(name)
        .ok_or_else(|| SidError::Storage(format!("CoordiNode row without {name}")))
}

pub(super) fn get_int(row: &Row, name: &str) -> SidResult<i64> {
    match field(row, name)? {
        Value::Int(v) => Ok(*v),
        other => Err(SidError::Storage(format!(
            "{name} is not an integer: {other:?}"
        ))),
    }
}

pub(super) fn get_bool(row: &Row, name: &str) -> SidResult<bool> {
    match field(row, name)? {
        Value::Bool(v) => Ok(*v),
        other => Err(SidError::Storage(format!(
            "{name} is not a boolean: {other:?}"
        ))),
    }
}

pub(super) fn get_text(row: &Row, name: &str) -> SidResult<String> {
    match field(row, name)? {
        Value::String(v) => Ok(v.clone()),
        other => Err(SidError::Storage(format!("{name} is not text: {other:?}"))),
    }
}

pub(super) fn get_opt_text(row: &Row, name: &str) -> SidResult<Option<String>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.clone())),
        Some(other) => Err(SidError::Storage(format!("{name} is not text: {other:?}"))),
    }
}

pub(super) fn get_opt_int(row: &Row, name: &str) -> SidResult<Option<i64>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_int(row, name).map(Some),
    }
}

pub(super) fn get_opt_bytes(row: &Row, name: &str) -> SidResult<Option<Vec<u8>>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_bytes(row, name).map(Some),
    }
}

pub(super) fn get_bytes(row: &Row, name: &str) -> SidResult<Vec<u8>> {
    match field(row, name)? {
        Value::Binary(v) => Ok(v.clone()),
        other => Err(SidError::Storage(format!(
            "{name} is not binary: {other:?}"
        ))),
    }
}

pub(super) fn get_time(row: &Row, name: &str) -> SidResult<chrono::DateTime<chrono::Utc>> {
    let micros = get_int(row, name)?;
    chrono::DateTime::from_timestamp_micros(micros)
        .ok_or_else(|| SidError::Storage(format!("{name} is no instant: {micros}")))
}

pub(super) fn get_opt_time(
    row: &Row,
    name: &str,
) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_time(row, name).map(Some),
    }
}
