// SPDX-License-Identifier: AGPL-3.0-only
//! Credentials, WebAuthn user handles and the credential service's side of
//! password history in CoordiNode.
//!
//! Every change of a profile's set of credentials (a new one, a
//! replacement, an enrollment, a revocation, a deletion) writes the
//! profile's `credential_turn`, so those changes of one profile apply one
//! after another: two revocations cannot each leave the other's credential
//! as the last primary one, and two replacements cannot both add a set.
//! A change of one credential's data writes that credential. A history
//! commit moves its owner's revision on the history node and holds the
//! write cutoff, so a raise of the cutoff committed meanwhile refuses it.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::credential::CredentialStatus;
use sid_core::models::{
    Credential, CredentialData, CredentialId, CredentialRevocation, CredentialType, HistoryArchive,
    HistoryCommit, HistoryEntry, HistoryEpoch, HistoryEpochDescriptor, HistoryEpochId,
    HistoryEpochUse, HistoryEvidence, HistoryKsf, HistorySuite, MutationContext, PasswordHistory,
    Profile, ProfileId, StoredUserHandle, WebAuthnUserHandle,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bool,
    get_bytes, get_count, get_int, get_opt_bytes, get_opt_int, get_opt_text, get_opt_time,
    get_text, get_time, get_uuid, hold_first, key, opt_text, opt_time, profile::profile_value,
    sorted_page, time, uuid,
};

const CREDENTIAL: &str = "c.id AS id, c.profile_id AS profile_id,
    c.credential_type AS credential_type, c.status AS status, c.data AS data,
    c.credential_label AS credential_label,
    c.policy_version AS policy_version, c.zkpp_verified AS zkpp_verified,
    c.zkpp_artifact AS zkpp_artifact, c.opaque_curve AS opaque_curve,
    c.legacy_algorithm AS legacy_algorithm,
    c.opaque_credential_identifier AS opaque_credential_identifier,
    c.created_at AS created_at, c.last_used_at AS last_used_at";

const EPOCH: &str = "e.id AS id, e.owner_id AS owner_id, e.suite AS suite,
    e.public_key AS public_key, e.ksf_memory_kib AS ksf_memory_kib, e.ksf_passes AS ksf_passes,
    e.ksf_lanes AS ksf_lanes, e.ksf_salt AS ksf_salt, e.status AS status,
    e.created_at AS created_at";

const ENTRY: &str = "h.epoch_id AS epoch_id, h.seq AS seq, h.entry AS entry,
    h.operation_id AS operation_id, h.policy_version AS policy_version,
    h.created_at AS created_at";

pub(super) fn fixed32(row: &Row, name: &str) -> SidResult<[u8; 32]> {
    get_bytes(row, name)?
        .try_into()
        .map_err(|_| SidError::Storage(format!("{name}: not 32 bytes")))
}

/// A type, status or id this build cannot read is refused: read as a default
/// it would sign in as a password or stay active after revocation.
pub(super) fn credential(row: &Row) -> SidResult<Credential> {
    let credential_type: CredentialType = get_text(row, "credential_type")?
        .parse()
        .map_err(SidError::Storage)?;
    let status: CredentialStatus = get_text(row, "status")?
        .parse()
        .map_err(SidError::Storage)?;
    let policy_version = get_opt_int(row, "policy_version")?
        .map(|v| i32::try_from(v).map_err(|_| SidError::Storage(format!("policy_version: {v}"))))
        .transpose()?;
    Ok(Credential {
        id: CredentialId(get_uuid(row, "id")?),
        profile_id: ProfileId::from_uuid(get_uuid(row, "profile_id")?)
            .map_err(|e| SidError::Storage(format!("credential profile: {e}")))?,
        credential_type,
        status,
        data: CredentialData::from(get_bytes(row, "data")?),
        label: get_opt_text(row, "credential_label")?,
        created_at: get_time(row, "created_at")?,
        last_used_at: get_opt_time(row, "last_used_at")?,
        policy_evidence: crate::policy_evidence::from_columns(
            get_bool(row, "zkpp_verified")?,
            policy_version,
            get_opt_bytes(row, "zkpp_artifact")?,
        )?,
        opaque_curve: get_opt_int(row, "opaque_curve")?
            .map(|v| u8::try_from(v).map_err(|_| SidError::Storage(format!("opaque_curve: {v}"))))
            .transpose()?,
        opaque_credential_identifier: get_opt_bytes(row, "opaque_credential_identifier")?
            .map(|bytes| {
                <[u8; 16]>::try_from(bytes).map_err(|_| {
                    SidError::Storage("opaque_credential_identifier: not 16 bytes".into())
                })
            })
            .transpose()?,
        legacy_algorithm: get_opt_text(row, "legacy_algorithm")?,
    })
}

fn get(tx: &Statements<'_>, id: CredentialId) -> SidResult<Option<Credential>> {
    let rows = tx.run(
        &format!("MATCH (c:SidCredential) WHERE c.id = $id RETURN {CREDENTIAL}"),
        Params::default().with("id", uuid(&id.0)),
    )?;
    rows.first().map(credential).transpose()
}

/// Whether credential `id` is stored, read in `tx`.
pub(super) fn exists(tx: &Statements<'_>, id: CredentialId) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (c:SidCredential) WHERE c.id = $id RETURN c.id AS id",
        Params::default().with("id", uuid(&id.0)),
    )?;
    Ok(!rows.is_empty())
}

/// `active_password_of` of a credential: its profile while it is the
/// profile's active password, which a profile has one of.
fn active_password_of(credential: &Credential) -> Value {
    if credential.credential_type == CredentialType::Opaque
        && credential.status == CredentialStatus::Active
    {
        profile_value(credential.profile_id)
    } else {
        Value::Null
    }
}

/// Take `profile`'s turn at changing its credentials: concurrent changes of
/// one profile's set conflict here. `NotFound` when the profile is gone.
fn credential_turn(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (p:SidProfile) WHERE p.id = $id
         SET p.credential_turn = coalesce(p.credential_turn, 0) + 1
         RETURN p.id AS id",
        Params::default().with("id", profile_value(profile)),
    )?;
    if rows.is_empty() {
        return Err(SidError::NotFound(format!("profile {profile}")));
    }
    Ok(())
}

/// Store a new credential in `tx`; an existing id is `Conflict`.
pub(super) fn insert(tx: &Statements<'_>, credential: &Credential) -> SidResult<()> {
    let (verified, policy_version, artifact) =
        crate::policy_evidence::columns(&credential.policy_evidence)?;
    credential_turn(tx, credential.profile_id)?;
    if get(tx, credential.id)?.is_some() {
        return Err(SidError::Conflict("credential already exists".into()));
    }
    tx.run(
        "CREATE (c:SidCredential {id: $id, profile_id: $profile_id,
            credential_type: $credential_type, status: $status, data: $data, credential_label: $label,
            policy_version: $policy_version, zkpp_verified: $zkpp_verified,
            zkpp_artifact: $zkpp_artifact, opaque_curve: $opaque_curve,
            legacy_algorithm: $legacy_algorithm,
            opaque_credential_identifier: $opaque_credential_identifier,
            active_password_of: $active_password_of, created_at: $created_at,
            last_used_at: $last_used_at})",
        Params::default()
            .with("id", uuid(&credential.id.0))
            .with("profile_id", profile_value(credential.profile_id))
            .with(
                "credential_type",
                Value::String(credential.credential_type.as_str().into()),
            )
            .with("status", Value::String(credential.status.as_str().into()))
            .with("data", Value::Binary(credential.data.expose().to_vec()))
            .with("label", opt_text(credential.label.as_deref()))
            .with(
                "policy_version",
                policy_version.map_or(Value::Null, |v| Value::Int(i64::from(v))),
            )
            .with("zkpp_verified", Value::Bool(verified))
            .with("zkpp_artifact", artifact.map_or(Value::Null, Value::Binary))
            .with(
                "opaque_curve",
                credential
                    .opaque_curve
                    .map_or(Value::Null, |v| Value::Int(i64::from(v))),
            )
            .with(
                "legacy_algorithm",
                opt_text(credential.legacy_algorithm.as_deref()),
            )
            .with(
                "opaque_credential_identifier",
                credential
                    .opaque_credential_identifier
                    .map_or(Value::Null, |id| Value::Binary(id.to_vec())),
            )
            .with("active_password_of", active_password_of(credential))
            .with("created_at", time(credential.created_at))
            .with("last_used_at", opt_time(credential.last_used_at)),
    )?;
    Ok(())
}

/// Replace the profile's credentials of the types `credential` replaces (its
/// one password, its recovery-code set) with it, in `tx`.
pub(super) fn replace(tx: &Statements<'_>, credential: &Credential) -> SidResult<()> {
    let replaced = credential.credential_type.replaces();
    if replaced.is_empty() {
        return Err(SidError::Validation(format!(
            "a {} credential is added, not replaced",
            credential.credential_type.as_str()
        )));
    }
    credential_turn(tx, credential.profile_id)?;
    for kind in replaced {
        tx.run(
            "MATCH (c:SidCredential) WHERE c.profile_id = $profile AND c.credential_type = $kind
             DETACH DELETE c",
            Params::default()
                .with("profile", profile_value(credential.profile_id))
                .with("kind", Value::String(kind.as_str().into())),
        )?;
    }
    insert(tx, credential)
}

/// Delete every credential, user handle and history of `profile`, in `tx`.
pub(super) fn delete_profile_credentials(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for query in [
        "MATCH (c:SidCredential) WHERE c.profile_id = $profile DETACH DELETE c",
        "MATCH (w:SidWebAuthnHandle) WHERE w.profile_id = $profile DETACH DELETE w",
        "MATCH (h:SidHistoryEntry) WHERE h.owner_id = $profile DETACH DELETE h",
        "MATCH (e:SidHistoryEpoch) WHERE e.owner_id = $profile DETACH DELETE e",
        "MATCH (r:SidPasswordHistory) WHERE r.owner_id = $profile DETACH DELETE r",
    ] {
        tx.run(
            query,
            Params::default().with("profile", profile_value(profile)),
        )?;
    }
    Ok(())
}

// === Password history ===

fn epoch(row: &Row) -> SidResult<HistoryEpoch> {
    let positive = |name: &str| -> SidResult<u32> {
        let value = get_int(row, name)?;
        u32::try_from(value)
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| SidError::Storage(format!("{name}: not positive")))
    };
    Ok(HistoryEpoch {
        id: HistoryEpochId(get_uuid(row, "id")?),
        owner: ProfileId::from_uuid(get_uuid(row, "owner_id")?)
            .map_err(|e| SidError::Storage(format!("epoch owner: {e}")))?,
        suite: HistorySuite::parse(&get_text(row, "suite")?)?,
        public_key: fixed32(row, "public_key")?,
        ksf: HistoryKsf {
            memory_kib: positive("ksf_memory_kib")?,
            passes: positive("ksf_passes")?,
            lanes: positive("ksf_lanes")?,
        },
        ksf_salt: fixed32(row, "ksf_salt")?,
        status: HistoryEpochUse::parse(&get_text(row, "status")?)?,
        created_at: get_time(row, "created_at")?,
    })
}

fn entry(row: &Row) -> SidResult<HistoryEntry> {
    let policy_version = get_int(row, "policy_version")?;
    Ok(HistoryEntry {
        epoch: HistoryEpochId(get_uuid(row, "epoch_id")?),
        seq: get_int(row, "seq")?,
        entry: fixed32(row, "entry")?,
        evidence: HistoryEvidence {
            operation: get_uuid(row, "operation_id")?,
            policy_version: u32::try_from(policy_version)
                .map_err(|_| SidError::Storage("policy_version: negative".into()))?,
        },
        created_at: get_time(row, "created_at")?,
    })
}

/// The owner's revision, every epoch and every entry, in the order every
/// backend exports them; `None` without history.
fn read_history(tx: &Statements<'_>, owner: ProfileId) -> SidResult<Option<HistoryArchive>> {
    let params = || Params::default().with("owner", profile_value(owner));
    let revision = tx.run(
        "MATCH (r:SidPasswordHistory) WHERE r.owner_id = $owner RETURN r.revision AS revision",
        params(),
    )?;
    let Some(row) = revision.first() else {
        return Ok(None);
    };
    let revision = get_int(row, "revision")?;
    let rows = tx.run(
        &format!("MATCH (e:SidHistoryEpoch) WHERE e.owner_id = $owner RETURN {EPOCH}"),
        params(),
    )?;
    let epochs = rows.iter().map(epoch).collect::<SidResult<Vec<_>>>()?;
    let epochs = sorted_page(epochs, |e| (e.created_at, e.id), 0, u64::MAX);
    let rows = tx.run(
        &format!("MATCH (h:SidHistoryEntry) WHERE h.owner_id = $owner RETURN {ENTRY}"),
        params(),
    )?;
    let entries = rows.iter().map(entry).collect::<SidResult<Vec<_>>>()?;
    // Newest first, then by epoch.
    let entries = sorted_page(
        entries,
        |h| (std::cmp::Reverse(h.seq), h.epoch),
        0,
        u64::MAX,
    );
    Ok(Some(HistoryArchive {
        owner,
        revision,
        epochs,
        entries,
    }))
}

fn insert_epoch(
    tx: &Statements<'_>,
    owner: ProfileId,
    d: &HistoryEpochDescriptor,
    status: HistoryEpochUse,
) -> SidResult<()> {
    tx.run(
        "CREATE (e:SidHistoryEpoch {id: $id, owner_id: $owner, suite: $suite,
            public_key: $public_key, ksf_memory_kib: $memory, ksf_passes: $passes,
            ksf_lanes: $lanes, ksf_salt: $salt, status: $status, active_of: $active_of,
            created_at: $created_at})",
        Params::default()
            .with("id", uuid(&d.id.0))
            .with("owner", profile_value(owner))
            .with("suite", Value::String(d.suite.as_str().into()))
            .with("public_key", Value::Binary(d.public_key.to_vec()))
            .with("memory", Value::Int(i64::from(d.ksf.memory_kib)))
            .with("passes", Value::Int(i64::from(d.ksf.passes)))
            .with("lanes", Value::Int(i64::from(d.ksf.lanes)))
            .with("salt", Value::Binary(d.ksf_salt.to_vec()))
            .with("status", Value::String(status.as_str().into()))
            .with(
                "active_of",
                if status == HistoryEpochUse::Active {
                    profile_value(owner)
                } else {
                    Value::Null
                },
            )
            .with("created_at", time(d.created_at)),
    )?;
    Ok(())
}

fn get_epoch(tx: &Statements<'_>, id: HistoryEpochId) -> SidResult<Option<HistoryEpoch>> {
    let rows = tx.run(
        &format!("MATCH (e:SidHistoryEpoch) WHERE e.id = $id RETURN {EPOCH}"),
        Params::default().with("id", uuid(&id.0)),
    )?;
    rows.first().map(epoch).transpose()
}

/// Record the descriptor `d` for `owner` unless it is recorded already; one
/// recorded with any other immutable field, or for another owner, is a
/// `Conflict`: the evaluator never issues two descriptors for one epoch.
fn record_descriptor(
    tx: &Statements<'_>,
    owner: ProfileId,
    d: &HistoryEpochDescriptor,
) -> SidResult<()> {
    match get_epoch(tx, d.id)? {
        None => insert_epoch(tx, owner, d, HistoryEpochUse::CompareOnly),
        Some(recorded) if recorded.owner == owner && recorded.descriptor() == *d => Ok(()),
        Some(_) => Err(SidError::Conflict(format!(
            "history epoch {} is recorded with another descriptor",
            d.id.0
        ))),
    }
}

/// The history write cutoff, held for the open transaction: a raise
/// committed meanwhile refuses it.
fn held_cutoff(tx: &Statements<'_>) -> SidResult<Option<DateTime<Utc>>> {
    let rows = tx.run(
        "MATCH (c:SidHistoryCutoff) WHERE c.id = $id RETURN id(c) AS node, c.not_before AS not_before",
        Params::default().with("id", Cutoff::Credential.slot()),
    )?;
    if !hold_first(tx, &rows)? {
        return Err(SidError::Storage("history write cutoff missing".into()));
    }
    rows.first()
        .map(|row| get_opt_time(row, "not_before"))
        .transpose()
        .map(Option::flatten)
}

/// A history write cutoff: the credential service's, which fences history
/// commits, or the history evaluator's, which fences its key selection.
#[derive(Clone, Copy)]
pub(super) enum Cutoff {
    Credential,
    Evaluator,
}

impl Cutoff {
    const ALL: [Self; 2] = [Self::Credential, Self::Evaluator];

    fn slot(self) -> Value {
        Value::Int(match self {
            Self::Credential => 1,
            Self::Evaluator => 2,
        })
    }
}

/// Create the history write cutoffs of an empty store: none set yet.
pub(super) fn init_cutoff(tx: &Statements<'_>) -> SidResult<Decision<()>> {
    let mut created = false;
    for which in Cutoff::ALL {
        let params = Params::default().with("id", which.slot());
        let rows = tx.run(
            "MATCH (c:SidHistoryCutoff) WHERE c.id = $id RETURN c.id AS id",
            params.clone(),
        )?;
        if rows.is_empty() {
            tx.run(
                "CREATE (c:SidHistoryCutoff {id: $id, not_before: null})",
                params,
            )?;
            created = true;
        }
    }
    Ok(if created {
        Decision::Commit(())
    } else {
        Decision::Abandon(())
    })
}

/// The write cutoff `which` records, read in `tx`; `None` when none was set.
pub(super) fn read_cutoff(tx: &Statements<'_>, which: Cutoff) -> SidResult<Option<DateTime<Utc>>> {
    let rows = tx.run(
        "MATCH (c:SidHistoryCutoff) WHERE c.id = $id RETURN c.not_before AS not_before",
        Params::default().with("id", which.slot()),
    )?;
    rows.first()
        .map(|row| get_opt_time(row, "not_before"))
        .transpose()
        .map(Option::flatten)
}

/// Raise the write cutoff `which` to `not_before` in `tx`, monotonically:
/// an equal or earlier value changes nothing. The cutoff in force, and
/// whether it moved.
pub(super) fn raise_cutoff(
    tx: &Statements<'_>,
    which: Cutoff,
    not_before: DateTime<Utc>,
) -> SidResult<(DateTime<Utc>, bool)> {
    let not_before = sid_core::models::password_history::stored_instant(not_before);
    if let Some(current) = read_cutoff(tx, which)?
        && current >= not_before
    {
        return Ok((current, false));
    }
    tx.run(
        "MATCH (c:SidHistoryCutoff) WHERE c.id = $id SET c.not_before = $not_before",
        Params::default()
            .with("id", which.slot())
            .with("not_before", time(not_before)),
    )?;
    Ok((not_before, true))
}

/// Apply `commit` in `tx`. `Ok(false)` when the owner's history is no longer
/// at `commit.expected_revision`: the caller drops everything.
pub(super) fn apply_history(tx: &Statements<'_>, commit: &HistoryCommit) -> SidResult<bool> {
    commit.validate()?;
    commit.check_write_cutoff(held_cutoff(tx)?)?;
    let owner = commit.owner;
    super::profile::claim_profile(tx, owner)?;
    let params = || Params::default().with("owner", profile_value(owner));
    let moved = if commit.expected_revision == 0 {
        let exists = tx.run(
            "MATCH (r:SidPasswordHistory) WHERE r.owner_id = $owner RETURN r.owner_id AS id",
            params(),
        )?;
        if exists.is_empty() {
            // Concurrent first commits create one unique history node.
            tx.run(
                "CREATE (r:SidPasswordHistory {owner_id: $owner, revision: 1})",
                params(),
            )?;
            true
        } else {
            false
        }
    } else {
        !tx.run(
            "MATCH (r:SidPasswordHistory) WHERE r.owner_id = $owner AND r.revision = $revision
             SET r.revision = r.revision + 1 RETURN r.owner_id AS id",
            params().with("revision", Value::Int(commit.expected_revision)),
        )?
        .is_empty()
    };
    if !moved {
        return Ok(false);
    }
    // The operation's epochs as the evaluator described them, published with
    // the entries; the revision fence makes this the newest selection.
    for d in &commit.epochs {
        record_descriptor(tx, owner, d)?;
    }
    let accepted_at = Utc::now();
    let active = commit.epochs[0].id;
    tx.run(
        "MATCH (e:SidHistoryEpoch) WHERE e.owner_id = $owner AND e.status = 'active'
           AND e.id <> $active
         SET e.status = 'compare_only', e.active_of = null",
        params().with("active", uuid(&active.0)),
    )?;
    tx.run(
        "MATCH (e:SidHistoryEpoch) WHERE e.id = $active
         SET e.status = 'active', e.active_of = $owner",
        params().with("active", uuid(&active.0)),
    )?;
    let newest = tx.run(
        "MATCH (h:SidHistoryEntry) WHERE h.owner_id = $owner RETURN max(h.seq) AS seq",
        params(),
    )?;
    let seq = newest
        .first()
        .map(|row| get_opt_int(row, "seq"))
        .transpose()?
        .flatten()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| SidError::Storage("history sequence exhausted".into()))?;
    for (epoch, value) in &commit.entries {
        tx.run(
            "CREATE (h:SidHistoryEntry {key: $key, epoch_id: $epoch, owner_id: $owner,
                seq: $seq, entry: $entry, operation_id: $operation,
                policy_version: $policy_version, created_at: $created_at})",
            params()
                .with("key", key(&[epoch.0.as_bytes(), &seq.to_be_bytes()])?)
                .with("epoch", uuid(&epoch.0))
                .with("seq", Value::Int(seq))
                .with("entry", Value::Binary(value.to_vec()))
                .with("operation", uuid(&commit.evidence.operation))
                .with(
                    "policy_version",
                    Value::Int(i64::from(commit.evidence.policy_version)),
                )
                .with("created_at", time(accepted_at)),
        )?;
    }
    // Retain the newest `depth` accepted passwords; every commit takes the
    // next seq, so those are the last `depth` seqs. An epoch emptied here is
    // retired by the evaluator, from the live set, never by this commit.
    tx.run(
        "MATCH (h:SidHistoryEntry) WHERE h.owner_id = $owner AND h.seq <= $oldest
         DETACH DELETE h",
        params().with("oldest", Value::Int(seq - i64::from(commit.depth))),
    )?;
    // Age retention, under the same revision fence: older accepted passwords
    // go, the newest (this commit's) always stays.
    if let Some(before) = commit.expires_before(accepted_at) {
        tx.run(
            "MATCH (h:SidHistoryEntry) WHERE h.owner_id = $owner AND h.seq < $seq
               AND h.created_at < $before
             DETACH DELETE h",
            params()
                .with("seq", Value::Int(seq))
                .with("before", time(before)),
        )?;
    }
    Ok(true)
}

/// When a credential update applies.
#[derive(Clone)]
enum When {
    /// The credential is active.
    Active,
    /// The credential holds the given data, whatever its status.
    Holding(Vec<u8>),
    /// The credential is active and holds the given data.
    ActiveHolding(Vec<u8>),
}

impl When {
    fn holds(&self, stored: &Credential) -> bool {
        let active = stored.status == CredentialStatus::Active;
        match self {
            Self::Active => active,
            Self::Holding(data) => stored.data.expose() == data.as_slice(),
            Self::ActiveHolding(data) => active && stored.data.expose() == data.as_slice(),
        }
    }
}

/// Spend `spend` inside a mutation's transaction: the credential must still
/// be active and hold the data as read, else the mutation commits nothing.
pub(super) fn spend(
    tx: &Statements<'_>,
    spend: &sid_core::models::CredentialSpend,
) -> SidResult<()> {
    let holds = get(tx, spend.credential)?
        .is_some_and(|stored| When::ActiveHolding(spend.read.clone()).holds(&stored));
    if !holds {
        return Err(SidError::Fenced(
            "the credential state it spends changed".into(),
        ));
    }
    tx.run(
        "MATCH (c:SidCredential) WHERE c.id = $id SET c.data = $data, c.last_used_at = $now",
        Params::default()
            .with("id", uuid(&spend.credential.0))
            .with("data", Value::Binary(spend.left.clone()))
            .with("now", time(Utc::now())),
    )?;
    Ok(())
}

/// A conditional write of one credential's properties.
struct Update {
    when: When,
    set: &'static str,
    params: Params,
}

fn handle_key(rp_id: &str, handle: &WebAuthnUserHandle) -> SidResult<Value> {
    key(&[rp_id.as_bytes(), handle.0.as_slice()])
}

const HANDLE: &str = "w.profile_id AS profile_id, w.rp_id AS rp_id, w.user_handle AS user_handle,
    w.created_at AS created_at";

fn stored_handle(row: &Row) -> SidResult<StoredUserHandle> {
    Ok(StoredUserHandle {
        profile_id: ProfileId::from_uuid(get_uuid(row, "profile_id")?)
            .map_err(|e| SidError::Storage(format!("handle profile: {e}")))?,
        rp_id: get_text(row, "rp_id")?,
        handle: WebAuthnUserHandle::from_slice(&get_bytes(row, "user_handle")?)
            .ok_or_else(|| SidError::Storage("user_handle: not 16 bytes".into()))?,
        created_at: get_time(row, "created_at")?,
    })
}

impl CoordinodeBackend {
    pub(super) async fn get_credential(&self, id: CredentialId) -> SidResult<Option<Credential>> {
        self.read(move |tx| get(tx, id)).await
    }

    pub(super) async fn get_credentials_by_profile(
        &self,
        owner: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> SidResult<Vec<Credential>> {
        self.read(move |tx| {
            let (filter, params) = match credential_type {
                Some(kind) => (
                    " AND c.credential_type = $kind",
                    Params::default().with("kind", Value::String(kind.as_str().into())),
                ),
                None => ("", Params::default()),
            };
            let rows = tx.run(
                &format!(
                    "MATCH (c:SidCredential) WHERE c.profile_id = $profile{filter} RETURN {CREDENTIAL}"
                ),
                params.with("profile", profile_value(owner)),
            )?;
            let all = rows.iter().map(credential).collect::<SidResult<Vec<_>>>()?;
            Ok(sorted_page(all, |c| (c.created_at, c.id.0), 0, u64::MAX))
        })
        .await
    }

    pub(super) async fn list_credentials_by_type(
        &self,
        credential_type: CredentialType,
        after: Option<CredentialId>,
        limit: u32,
    ) -> SidResult<Vec<Credential>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (c:SidCredential) WHERE c.credential_type = $kind RETURN {CREDENTIAL}"
                ),
                Params::default().with("kind", Value::String(credential_type.as_str().into())),
            )?;
            let all = rows
                .iter()
                .map(credential)
                .collect::<SidResult<Vec<_>>>()?
                .into_iter()
                .filter(|c| after.is_none_or(|after| c.id.0 > after.0))
                .collect();
            Ok(sorted_page(all, |c| c.id.0, 0, u64::from(limit)))
        })
        .await
    }

    pub(super) async fn create_credential(
        &self,
        stored: &Credential,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = stored.clone();
        self.mutate(format!("credential:{}", stored.id.0), ctx, move |tx| {
            insert(tx, &stored)
        })
        .await
    }

    /// Apply `update` to the credential `id` while its condition holds;
    /// commits `ctx` on its profile's chain only when it applied.
    async fn update_credential(
        &self,
        id: CredentialId,
        update: Update,
        history: Option<HistoryCommit>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let Some(stored) = get(tx, id)? else {
                return Ok(Decision::Abandon(false));
            };
            if !update.when.holds(&stored) {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                &format!(
                    "MATCH (c:SidCredential) WHERE c.id = $id SET {}",
                    update.set
                ),
                update.params.clone().with("id", uuid(&id.0)),
            )?;
            if let Some(history) = &history {
                if history.owner != stored.profile_id {
                    return Err(SidError::Validation(
                        "password history belongs to the credential's profile".into(),
                    ));
                }
                if !apply_history(tx, history)? {
                    return Ok(Decision::Abandon(false));
                }
            }
            finalize(tx, &format!("profile:{}", stored.profile_id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let update = Update {
            when: When::Active,
            set: "c.credential_label = $label",
            params: Params::default().with("label", opt_text(label)),
        };
        self.update_credential(id, update, None, ctx).await
    }

    pub(super) async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (verified, policy_version, artifact) =
            crate::policy_evidence::columns(&new.policy_evidence)?;
        let update = Update {
            when: When::ActiveHolding(expected.to_vec()),
            set: "c.data = $data, c.policy_version = $policy_version, c.zkpp_verified = $verified,
             c.opaque_credential_identifier = $identifier, c.zkpp_artifact = $artifact,
             c.last_used_at = $now",
            params: Params::default()
                .with("data", Value::Binary(new.data.expose().to_vec()))
                .with(
                    "policy_version",
                    policy_version.map_or(Value::Null, |v| Value::Int(i64::from(v))),
                )
                .with("verified", Value::Bool(verified))
                .with(
                    "identifier",
                    new.opaque_credential_identifier
                        .map_or(Value::Null, |id| Value::Binary(id.to_vec())),
                )
                .with("artifact", artifact.map_or(Value::Null, Value::Binary))
                .with("now", time(Utc::now())),
        };
        self.update_credential(id, update, history.cloned(), ctx)
            .await
    }

    pub(super) async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> SidResult<bool> {
        // A revoked secret is sealed too, and stays revoked.
        let update = Update {
            when: When::Holding(expected.to_vec()),
            set: "c.data = $data",
            params: Params::default().with("data", Value::Binary(data.to_vec())),
        };
        self.update_credential(id, update, None, ctx).await
    }

    pub(super) async fn mark_credential_used(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let update = Update {
            when: When::Active,
            set: "c.last_used_at = $now",
            params: Params::default().with("now", time(Utc::now())),
        };
        self.update_credential(id, update, None, ctx).await
    }

    pub(super) async fn replace_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let update = Update {
            when: When::ActiveHolding(expected.to_vec()),
            set: "c.data = $data, c.last_used_at = $now",
            params: Params::default()
                .with("data", Value::Binary(data.to_vec()))
                .with("now", time(Utc::now())),
        };
        self.update_credential(id, update, None, ctx).await
    }

    pub(super) async fn replace_credential(
        &self,
        stored: &Credential,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = stored.clone();
        self.mutate(format!("profile:{}", stored.profile_id), ctx, move |tx| {
            replace(tx, &stored)
        })
        .await
    }

    pub(super) async fn enroll_credential(
        &self,
        stored: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if let Some(set) = recovery
            && set.credential_type != CredentialType::Recovery
        {
            return Err(SidError::Validation(
                "only recovery codes are issued with an enrolled factor".into(),
            ));
        }
        let (stored, recovery) = (stored.clone(), recovery.cloned());
        self.mutate(format!("profile:{}", stored.profile_id), ctx, move |tx| {
            insert(tx, &stored)?;
            if let Some(set) = &recovery {
                replace(tx, set)?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn delete_credential(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("credential:{}", id.0), ctx, move |tx| {
            if let Some(stored) = get(tx, id)? {
                credential_turn(tx, stored.profile_id)?;
                tx.run(
                    "MATCH (c:SidCredential) WHERE c.id = $id DETACH DELETE c",
                    Params::default().with("id", uuid(&id.0)),
                )?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn revoke_credential(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> SidResult<CredentialRevocation> {
        self.transaction(move |tx| {
            let Some(stored) = get(tx, id)? else {
                return Ok(Decision::Abandon(CredentialRevocation::AlreadyGone));
            };
            if stored.status != CredentialStatus::Active {
                return Ok(Decision::Abandon(CredentialRevocation::AlreadyGone));
            }
            // The profile's turn makes the count and the revocation one step
            // for concurrent revocations of one profile.
            credential_turn(tx, stored.profile_id)?;
            if stored.credential_type.is_primary() {
                let others = tx.run(
                    &format!(
                        "MATCH (c:SidCredential) WHERE c.profile_id = $profile AND c.status = 'active'
                         RETURN {CREDENTIAL}"
                    ),
                    Params::default().with("profile", profile_value(stored.profile_id)),
                )?;
                let others = others
                    .iter()
                    .map(credential)
                    .collect::<SidResult<Vec<_>>>()?
                    .into_iter()
                    .filter(|c| c.id != id && c.credential_type.is_primary())
                    .count();
                if others == 0 {
                    return Ok(Decision::Abandon(CredentialRevocation::LastPrimary));
                }
            }
            tx.run(
                "MATCH (c:SidCredential) WHERE c.id = $id
                 SET c.status = 'revoked', c.active_password_of = null",
                Params::default().with("id", uuid(&id.0)),
            )?;
            finalize(tx, &format!("credential:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(CredentialRevocation::Revoked))
        })
        .await
    }

    pub(super) async fn delete_credentials_by_profile(
        &self,
        owner: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            credential_turn(tx, owner)?;
            let deleted = get_count(&tx.run(
                "MATCH (c:SidCredential) WHERE c.profile_id = $profile DETACH DELETE c
                 RETURN count(*) AS n",
                Params::default().with("profile", profile_value(owner)),
            )?)?;
            finalize(tx, &format!("profile:{owner}"), ctx.clone())?;
            Ok(Decision::Commit(deleted))
        })
        .await
    }

    // === WebAuthn user handles ===

    pub(super) async fn ensure_webauthn_user_handle(
        &self,
        owner: ProfileId,
        rp_id: &str,
        candidate: WebAuthnUserHandle,
        ctx: MutationContext,
    ) -> SidResult<WebAuthnUserHandle> {
        let rp_id = rp_id.to_owned();
        self.transaction(move |tx| {
            let pair = key(&[owner.as_bytes(), rp_id.as_bytes()])?;
            let stored = tx.run(
                "MATCH (w:SidWebAuthnHandle) WHERE w.pair = $pair RETURN w.user_handle AS handle",
                Params::default().with("pair", pair.clone()),
            )?;
            if let Some(row) = stored.first() {
                let handle = WebAuthnUserHandle::from_slice(&get_bytes(row, "handle")?)
                    .ok_or_else(|| SidError::Storage("user_handle: not 16 bytes".into()))?;
                return Ok(Decision::Abandon(handle));
            }
            // The profile is claimed: its deletion, which removes the handles
            // it reads, conflicts with this one either way round.
            let profile = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", profile_value(owner)),
            )?;
            if !claim_first(tx, &profile)? {
                return Err(SidError::NotFound(format!("profile {owner}")));
            }
            tx.run(
                "CREATE (w:SidWebAuthnHandle {pair: $pair, handle_key: $handle_key,
                    profile_id: $profile, rp_id: $rp_id, user_handle: $handle, created_at: $now})",
                Params::default()
                    .with("pair", pair)
                    .with("handle_key", handle_key(&rp_id, &candidate)?)
                    .with("profile", profile_value(owner))
                    .with("rp_id", Value::String(rp_id.clone()))
                    .with("handle", Value::Binary(candidate.0.to_vec()))
                    .with("now", time(Utc::now())),
            )?;
            finalize(tx, &format!("profile:{owner}"), ctx.clone())?;
            Ok(Decision::Commit(candidate))
        })
        .await
    }

    pub(super) async fn export_webauthn_user_handles(
        &self,
        owner: ProfileId,
    ) -> SidResult<Vec<StoredUserHandle>> {
        self.read(move |tx| {
            let mut handles = tx
                .run(
                    &format!(
                        "MATCH (w:SidWebAuthnHandle) WHERE w.profile_id = $id RETURN {HANDLE}"
                    ),
                    Params::default().with("id", profile_value(owner)),
                )?
                .iter()
                .map(stored_handle)
                .collect::<SidResult<Vec<_>>>()?;
            handles.sort_by(|a, b| a.rp_id.cmp(&b.rp_id));
            Ok(handles)
        })
        .await
    }

    pub(super) async fn import_webauthn_user_handle(
        &self,
        handle: &StoredUserHandle,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let handle = handle.clone();
        self.transaction(move |tx| {
            let pair = key(&[handle.profile_id.as_bytes(), handle.rp_id.as_bytes()])?;
            let by_key = handle_key(&handle.rp_id, &handle.handle)?;
            let held = tx
                .run(
                    &format!(
                        "MATCH (w:SidWebAuthnHandle) WHERE w.pair = $pair OR w.handle_key = $key
                         RETURN {HANDLE}"
                    ),
                    Params::default()
                        .with("pair", pair.clone())
                        .with("key", by_key.clone()),
                )?
                .iter()
                .map(stored_handle)
                .collect::<SidResult<Vec<_>>>()?;
            if held.iter().any(|h| *h != handle) {
                return Err(SidError::Conflict(
                    "another user handle is stored at the relying party".into(),
                ));
            }
            if !held.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            let profile = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", profile_value(handle.profile_id)),
            )?;
            if !claim_first(tx, &profile)? {
                return Err(SidError::NotFound(format!("profile {}", handle.profile_id)));
            }
            tx.run(
                "CREATE (w:SidWebAuthnHandle {pair: $pair, handle_key: $handle_key,
                    profile_id: $profile, rp_id: $rp_id, user_handle: $handle,
                    created_at: $created_at})",
                Params::default()
                    .with("pair", pair)
                    .with("handle_key", by_key)
                    .with("profile", profile_value(handle.profile_id))
                    .with("rp_id", Value::String(handle.rp_id.clone()))
                    .with("handle", Value::Binary(handle.handle.0.to_vec()))
                    .with("created_at", time(handle.created_at)),
            )?;
            finalize(tx, &format!("profile:{}", handle.profile_id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: WebAuthnUserHandle,
    ) -> SidResult<Option<ProfileId>> {
        let rp_id = rp_id.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (w:SidWebAuthnHandle) WHERE w.handle_key = $key RETURN w.profile_id AS profile",
                Params::default().with("key", handle_key(&rp_id, &handle)?),
            )?;
            rows.first()
                .map(|row| {
                    ProfileId::from_uuid(get_uuid(row, "profile")?)
                        .map_err(|e| SidError::Storage(format!("handle profile: {e}")))
                })
                .transpose()
        })
        .await
    }

    // === Password history ===

    pub(super) async fn get_password_history(
        &self,
        owner: ProfileId,
    ) -> SidResult<PasswordHistory> {
        self.read(move |tx| {
            Ok(match read_history(tx, owner)? {
                Some(stored) => PasswordHistory {
                    revision: stored.revision,
                    epochs: stored
                        .epochs
                        .into_iter()
                        .filter(|e| e.status != HistoryEpochUse::Retired)
                        .collect(),
                    entries: stored.entries,
                },
                None => PasswordHistory::default(),
            })
        })
        .await
    }

    pub(super) async fn history_write_cutoff(&self) -> SidResult<Option<DateTime<Utc>>> {
        self.read(|tx| read_cutoff(tx, Cutoff::Credential)).await
    }

    pub(super) async fn raise_history_write_cutoff(
        &self,
        not_before: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<DateTime<Utc>> {
        self.transaction(move |tx| {
            let (cutoff, moved) = raise_cutoff(tx, Cutoff::Credential, not_before)?;
            if !moved {
                return Ok(Decision::Abandon(cutoff));
            }
            finalize(tx, "password_history_write_cutoff", ctx.clone())?;
            Ok(Decision::Commit(cutoff))
        })
        .await
    }

    pub(super) async fn export_password_history(
        &self,
        owner: ProfileId,
    ) -> SidResult<Option<HistoryArchive>> {
        let archive = self.read(move |tx| read_history(tx, owner)).await?;
        if let Some(archive) = &archive {
            archive.validate()?;
        }
        Ok(archive)
    }

    pub(super) async fn import_password_history(
        &self,
        archive: &HistoryArchive,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        archive.validate()?;
        let archive = archive.clone();
        self.transaction(move |tx| {
            if let Some(existing) = read_history(tx, archive.owner)? {
                if existing == archive {
                    return Ok(Decision::Abandon(false));
                }
                return Err(SidError::Conflict(
                    "existing password history differs from archive".into(),
                ));
            }
            super::profile::claim_profile(tx, archive.owner)?;
            tx.run(
                "CREATE (r:SidPasswordHistory {owner_id: $owner, revision: $revision})",
                Params::default()
                    .with("owner", profile_value(archive.owner))
                    .with("revision", Value::Int(archive.revision)),
            )?;
            for epoch in &archive.epochs {
                insert_epoch(tx, archive.owner, &epoch.descriptor(), epoch.status)?;
            }
            for entry in &archive.entries {
                tx.run(
                    "CREATE (h:SidHistoryEntry {key: $key, epoch_id: $epoch, owner_id: $owner,
                        seq: $seq, entry: $entry, operation_id: $operation,
                        policy_version: $policy_version, created_at: $created_at})",
                    Params::default()
                        .with(
                            "key",
                            key(&[entry.epoch.0.as_bytes(), &entry.seq.to_be_bytes()])?,
                        )
                        .with("epoch", uuid(&entry.epoch.0))
                        .with("owner", profile_value(archive.owner))
                        .with("seq", Value::Int(entry.seq))
                        .with("entry", Value::Binary(entry.entry.to_vec()))
                        .with("operation", uuid(&entry.evidence.operation))
                        .with(
                            "policy_version",
                            Value::Int(i64::from(entry.evidence.policy_version)),
                        )
                        .with("created_at", time(entry.created_at)),
                )?;
            }
            finalize(tx, &format!("profile:{}", archive.owner), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn end_legacy_migration(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let profile = profile.clone();
        self.transaction(move |tx| {
            if !super::profile::update(tx, &profile)? {
                return Ok(Decision::Abandon(false));
            }
            credential_turn(tx, profile.id)?;
            tx.run(
                "MATCH (c:SidCredential) WHERE c.profile_id = $profile
                   AND c.credential_type = 'legacy_hash'
                 DETACH DELETE c",
                Params::default().with("profile", profile_value(profile.id)),
            )?;
            finalize(tx, &format!("profile:{}", profile.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}
