// SPDX-License-Identifier: AGPL-3.0-only
//! The directory in CoordiNode: profile metadata, personal access tokens,
//! the directory (SCIM) writes that change an account or a group in one
//! transaction, and the directory query.
//!
//! A metadata value is stored as a CoordiNode document, never as serialized
//! text. Creating a token takes its owner's turn, so the count of active
//! tokens it is checked against conflicts with a concurrent creation.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::directory_query::metadata_keys;
use sid_core::models::pat::{PatId, PatStatus, PersonalAccessToken};
use sid_core::models::{
    DirectoryAttribute as Attr, DirectoryFilter, DirectoryGroupWrite, DirectoryOperator as Op,
    DirectoryPage, DirectoryQuery, DirectoryUserWrite, DirectoryWriteMode, MutationContext,
    PrincipalType, Profile, ProfileId, ProfileMetadata, ProfileStatus, Session,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bytes,
    get_int, get_opt_text, get_opt_time, get_parsed, get_text, get_texts, get_time, get_uuid, key,
    opt_text, opt_time, texts, time, uuid,
};

const METADATA: &str = "m.profile_id AS profile_id, m.meta_key AS meta_key, m.value AS value,
    m.created_at AS created_at, m.updated_at AS updated_at";

const PAT: &str = "t.id AS id, t.profile_id AS profile_id, t.name AS name,
    t.description AS description, t.token_hash AS token_hash, t.token_prefix AS token_prefix,
    t.scopes AS scopes, t.ip_allowlist AS ip_allowlist, t.status AS status,
    t.expires_at AS expires_at, t.last_used_at AS last_used_at,
    t.last_used_ip AS last_used_ip, t.use_count AS use_count, t.revoked_at AS revoked_at,
    t.revoked_by AS revoked_by, t.created_at AS created_at";

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn profile_of(row: &Row, name: &str) -> SidResult<ProfileId> {
    ProfileId::from_slice(&get_bytes(row, name)?)
        .map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

// === Profile metadata ===

fn metadata(row: &Row) -> SidResult<ProfileMetadata> {
    Ok(ProfileMetadata {
        profile_id: profile_of(row, "profile_id")?,
        key: get_text(row, "meta_key")?,
        value: super::get_document(row, "value")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn metadata_pair(profile: ProfileId, meta_key: &str) -> SidResult<Value> {
    key(&[profile.as_bytes(), meta_key.as_bytes()])
}

fn metadata_of(tx: &Statements<'_>, profile: ProfileId) -> SidResult<Vec<ProfileMetadata>> {
    let rows = tx.run(
        &format!("MATCH (m:SidProfileMetadata) WHERE m.profile_id = $id RETURN {METADATA}"),
        Params::default().with("id", bin(profile.as_bytes())),
    )?;
    rows.iter().map(metadata).collect()
}

/// Set one metadata key of a profile in `tx`, claiming the profile, which is
/// deleted with its metadata. `created` names a profile this transaction
/// created itself, which needs no claim.
fn set_metadata(
    tx: &Statements<'_>,
    m: &ProfileMetadata,
    created: Option<ProfileId>,
) -> SidResult<()> {
    if created != Some(m.profile_id) {
        let held = tx.run(
            "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
            Params::default().with("id", bin(m.profile_id.as_bytes())),
        )?;
        if !claim_first(tx, &held)? {
            return Err(SidError::NotFound(format!("profile {}", m.profile_id)));
        }
    }
    let document = super::document(&m.value, "metadata value")?;
    let pair = metadata_pair(m.profile_id, &m.key)?;
    let updated = tx.run(
        "MATCH (m:SidProfileMetadata) WHERE m.pair = $pair
         SET m.value = $value, m.updated_at = $updated_at RETURN m.pair AS pair",
        Params::default()
            .with("pair", pair.clone())
            .with("value", document.clone())
            .with("updated_at", time(m.updated_at)),
    )?;
    if updated.is_empty() {
        tx.run(
            "CREATE (m:SidProfileMetadata {pair: $pair, profile_id: $profile, meta_key: $key,
                value: $value, created_at: $created_at, updated_at: $updated_at})",
            Params::default()
                .with("pair", pair)
                .with("profile", bin(m.profile_id.as_bytes()))
                .with("key", Value::String(m.key.clone()))
                .with("value", document)
                .with("created_at", time(m.created_at))
                .with("updated_at", time(m.updated_at)),
        )?;
    }
    Ok(())
}

fn delete_metadata(tx: &Statements<'_>, profile: ProfileId, meta_key: &str) -> SidResult<()> {
    tx.run(
        "MATCH (m:SidProfileMetadata) WHERE m.pair = $pair DETACH DELETE m",
        Params::default().with("pair", metadata_pair(profile, meta_key)?),
    )?;
    Ok(())
}

// === Personal access tokens ===

fn pat(row: &Row) -> SidResult<PersonalAccessToken> {
    let use_count = get_int(row, "use_count")?;
    Ok(PersonalAccessToken {
        id: PatId(get_uuid(row, "id")?),
        profile_id: profile_of(row, "profile_id")?,
        name: get_text(row, "name")?,
        description: get_opt_text(row, "description")?,
        token_hash: get_text(row, "token_hash")?,
        token_prefix: get_text(row, "token_prefix")?,
        scopes: get_texts(row, "scopes")?,
        ip_allowlist: get_texts(row, "ip_allowlist")?,
        status: get_parsed::<PatStatus>(row, "status")?,
        expires_at: get_opt_time(row, "expires_at")?,
        last_used_at: get_opt_time(row, "last_used_at")?,
        last_used_ip: get_opt_text(row, "last_used_ip")?,
        use_count: u64::try_from(use_count)
            .map_err(|_| SidError::Storage(format!("use_count: {use_count}")))?,
        revoked_at: get_opt_time(row, "revoked_at")?,
        revoked_by: get_opt_text(row, "revoked_by")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn pats_where(
    tx: &Statements<'_>,
    filter: &str,
    value: Value,
) -> SidResult<Vec<PersonalAccessToken>> {
    let rows = tx.run(
        &format!("MATCH (t:SidPat) WHERE {filter} RETURN {PAT}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(pat).collect()
}

/// Revoke `ids` by `revoked_by` in `tx`.
fn revoke(tx: &Statements<'_>, ids: &[PatId], revoked_by: Option<&str>) -> SidResult<()> {
    let now = time(Utc::now());
    for id in ids {
        tx.run(
            "MATCH (t:SidPat) WHERE t.id = $id
             SET t.status = 'revoked', t.revoked_at = $now, t.revoked_by = $by",
            Params::default()
                .with("id", uuid(&id.0))
                .with("now", now.clone())
                .with("by", opt_text(revoked_by)),
        )?;
    }
    Ok(())
}

/// Revoke every active token of `profile` in `tx`; how many.
fn revoke_active(tx: &Statements<'_>, profile: ProfileId, revoked_by: &str) -> SidResult<u64> {
    let active: Vec<PatId> = pats_where(tx, "t.profile_id = $value", bin(profile.as_bytes()))?
        .into_iter()
        .filter(|t| t.status == PatStatus::Active)
        .map(|t| t.id)
        .collect();
    revoke(tx, &active, Some(revoked_by))?;
    u64::try_from(active.len()).map_err(|_| SidError::Storage("revoked count".into()))
}

/// Delete in `tx` the metadata and tokens of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for query in [
        "MATCH (m:SidProfileMetadata) WHERE m.profile_id = $id DETACH DELETE m",
        "MATCH (t:SidPat) WHERE t.profile_id = $id DETACH DELETE t",
    ] {
        tx.run(query, Params::default().with("id", bin(profile.as_bytes())))?;
    }
    Ok(())
}

// === Directory query ===

/// Simple lower case of each code point, as the SQL backends fold
/// (`caseExact: false`, RFC 7643 §2.2).
fn fold(text: &str) -> String {
    text.chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

/// What one user of the directory is filtered on.
struct Candidate {
    profile: Profile,
    usernames: Vec<String>,
    emails: Vec<String>,
    phones: Vec<String>,
    metadata: Vec<ProfileMetadata>,
}

impl Candidate {
    /// The non-empty string value of metadata `key`.
    fn metadata(&self, meta_key: &str) -> Option<String> {
        self.metadata
            .iter()
            .find(|m| m.key == meta_key)
            .and_then(|m| m.value.as_str())
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    }

    fn display(&self) -> Option<String> {
        let p = &self.profile;
        let parts: Vec<&str> = [
            &p.honorific_prefix,
            &p.given_name,
            &p.middle_name,
            &p.family_name,
            &p.honorific_suffix,
        ]
        .into_iter()
        .filter_map(|part| part.as_deref().filter(|s| !s.is_empty()))
        .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    fn single(&self, attr: Attr) -> Option<String> {
        let non_empty = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
        match attr {
            Attr::GivenName => non_empty(&self.profile.given_name),
            Attr::FamilyName => non_empty(&self.profile.family_name),
            Attr::DisplayName => self.display(),
            Attr::FormattedName => {
                let named = non_empty(&self.profile.given_name).is_some()
                    || non_empty(&self.profile.family_name).is_some();
                if named { self.display() } else { None }
            }
            Attr::ExternalId => self.metadata(metadata_keys::EXTERNAL_ID),
            Attr::Title => self.metadata(metadata_keys::TITLE),
            Attr::Department => self.metadata(metadata_keys::DEPARTMENT),
            Attr::Active | Attr::UserName | Attr::Email | Attr::Phone => None,
        }
    }

    fn values(&self, attr: Attr) -> &[String] {
        match attr {
            Attr::UserName => &self.usernames,
            Attr::Email => &self.emails,
            Attr::Phone => &self.phones,
            _ => &[],
        }
    }

    fn matches(&self, filter: &DirectoryFilter) -> SidResult<bool> {
        Ok(match filter {
            DirectoryFilter::And(a, b) => self.matches(a)? && self.matches(b)?,
            DirectoryFilter::Or(a, b) => self.matches(a)? || self.matches(b)?,
            DirectoryFilter::Not(inner) => !self.matches(inner)?,
            DirectoryFilter::Present(attr) => match attr {
                Attr::Active => true,
                Attr::UserName | Attr::Email | Attr::Phone => {
                    self.values(*attr).iter().any(|v| !v.is_empty())
                }
                _ => self.single(*attr).is_some(),
            },
            DirectoryFilter::Compare {
                attribute,
                operator,
                value,
            } => self.compare(*attribute, *operator, value)?,
        })
    }

    fn compare(&self, attr: Attr, op: Op, value: &str) -> SidResult<bool> {
        match attr {
            Attr::Active => {
                // RFC 7644 §3.4.2.2: a boolean compares only by eq/ne.
                let wanted = match value.to_ascii_lowercase().as_str() {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(SidError::Validation(
                            "active compares with true or false".into(),
                        ));
                    }
                };
                let wanted = match op {
                    Op::Eq => wanted,
                    Op::Ne => !wanted,
                    _ => {
                        return Err(SidError::Validation(
                            "active compares by eq or ne only".into(),
                        ));
                    }
                };
                Ok((self.profile.status != ProfileStatus::Suspended) == wanted)
            }
            Attr::UserName | Attr::Email | Attr::Phone => Ok(self
                .values(attr)
                .iter()
                .filter(|v| !v.is_empty())
                .any(|v| compare(v, op, value, attr.case_exact()))),
            // A missing value matches no comparison.
            _ => Ok(self
                .single(attr)
                .is_some_and(|v| compare(&v, op, value, attr.case_exact()))),
        }
    }
}

/// `stored op wanted`, case folded unless the attribute is case-exact;
/// ordering compares code points.
fn compare(stored: &str, op: Op, wanted: &str, case_exact: bool) -> bool {
    let (a, b) = if case_exact {
        (stored.to_owned(), wanted.to_owned())
    } else {
        (fold(stored), fold(wanted))
    };
    match op {
        Op::Eq => a == b,
        Op::Ne => a != b,
        Op::Contains => a.contains(&b),
        Op::StartsWith => a.starts_with(&b),
        Op::EndsWith => a.ends_with(&b),
        Op::Greater => a > b,
        Op::GreaterOrEqual => a >= b,
        Op::Less => a < b,
        Op::LessOrEqual => a <= b,
    }
}

/// The directory's users matching `query`, oldest first, then by id.
fn query_directory(tx: &Statements<'_>, query: &DirectoryQuery) -> SidResult<DirectoryPage> {
    // A corporate login is `{userName}#{domain}`: only logins of this domain
    // carry a userName, the suffix stripped.
    let suffix = format!("#{}", query.org_domain);
    let mut matching = Vec::new();
    for profile in super::profile::profiles(tx, "", Params::default())? {
        // Retired profiles (closed, purged) are never part of the directory.
        if matches!(
            profile.status,
            ProfileStatus::Closed | ProfileStatus::Purged
        ) {
            continue;
        }
        let principals = super::principal::held_by(tx, profile.id)?;
        let candidate = Candidate {
            usernames: principals
                .iter()
                .filter(|p| p.principal_type == PrincipalType::Username)
                .filter_map(|p| {
                    p.value
                        .strip_suffix(&suffix)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                })
                .collect(),
            phones: principals
                .iter()
                .filter(|p| p.principal_type == PrincipalType::Phone)
                .map(|p| p.value.clone())
                .collect(),
            emails: super::profile::emails_of(tx, profile.id)?
                .into_iter()
                .map(|e| e.email)
                .collect(),
            metadata: metadata_of(tx, profile.id)?,
            profile,
        };
        let selected = match &query.filter {
            Some(filter) => candidate.matches(filter)?,
            None => true,
        };
        if selected {
            matching.push(candidate.profile);
        }
    }
    let total = u64::try_from(matching.len()).map_err(|_| SidError::Storage("total".into()))?;
    let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
    let profiles: Vec<Profile> = matching.into_iter().skip(offset).take(limit).collect();
    let (mut principals, mut emails, mut metadata) = (Vec::new(), Vec::new(), Vec::new());
    for profile in &profiles {
        principals.extend(super::principal::held_by(tx, profile.id)?);
        emails.extend(super::profile::emails_of(tx, profile.id)?);
        metadata.extend(metadata_of(tx, profile.id)?);
    }
    Ok(DirectoryPage {
        total,
        users: crate::directory_query::assemble(profiles, principals, emails, metadata),
    })
}

// === Directory writes ===

fn write_user(
    tx: &Statements<'_>,
    write: &DirectoryUserWrite,
    ctx: &mut MutationContext,
) -> SidResult<Vec<Session>> {
    let profile_id = write.profile_id();
    let created = match write.mode {
        DirectoryWriteMode::Create => {
            super::profile::insert(tx, &write.profile)?;
            Some(profile_id)
        }
        DirectoryWriteMode::Update => {
            // A missing account or one changed since it was read refuses
            // the whole write.
            if !super::profile::update(tx, &write.profile)? {
                return Err(match super::profile::get(tx, profile_id)? {
                    None => SidError::NotFound(format!("profile {profile_id}")),
                    Some(_) => SidError::InvalidState(format!(
                        "profile {profile_id} changed since it was read"
                    )),
                });
            }
            None
        }
    };
    for id in &write.unbind {
        super::principal::unbind(tx, *id, profile_id)?;
    }
    // Contacts before bindings: an email binding names the contact that
    // holds its mailbox.
    for id in &write.remove_emails {
        super::profile::delete_email(tx, *id, Some(profile_id))?;
    }
    for email in &write.add_emails {
        super::profile::upsert_email(tx, email)?;
    }
    for p in &write.bind {
        if p.profile_id != profile_id {
            return Err(SidError::Validation(
                "a directory write binds principals to its own account only".into(),
            ));
        }
        super::principal::bind(tx, p)?;
    }
    for id in &write.remove_phones {
        super::profile::delete_phone(tx, *id, Some(profile_id))?;
    }
    for phone in &write.add_phones {
        super::profile::upsert_phone(tx, phone)?;
    }
    for meta_key in &write.remove_metadata {
        delete_metadata(tx, profile_id, meta_key)?;
    }
    for m in &write.set_metadata {
        if m.profile_id != profile_id {
            return Err(SidError::Validation(
                "a directory write sets its own account's metadata only".into(),
            ));
        }
        set_metadata(tx, m, created)?;
    }
    Ok(match &write.end_access {
        Some(end) => {
            let ended = super::session::end_profile_sessions(tx, profile_id, end, ctx)?;
            revoke_active(tx, profile_id, &end.by)?;
            ended
        }
        None => Vec::new(),
    })
}

fn write_group(tx: &Statements<'_>, write: &DirectoryGroupWrite) -> SidResult<()> {
    let group_id = write.group.id;
    match write.mode {
        DirectoryWriteMode::Create => super::rbac::insert_group(tx, &write.group)?,
        DirectoryWriteMode::Update => {
            if !super::rbac::update_group(tx, &write.group)? {
                return Err(SidError::NotFound(format!("group {group_id}")));
            }
        }
    }
    for profile in &write.remove_members {
        super::rbac::remove_member(tx, group_id, *profile)?;
    }
    for member in &write.add_members {
        if member.group_id != group_id {
            return Err(SidError::Validation(
                "a group write adds members to its own group only".into(),
            ));
        }
        super::rbac::add_member(tx, member)?;
    }
    Ok(())
}

impl CoordinodeBackend {
    // === Directory ===

    pub(super) async fn write_directory_user(
        &self,
        write: &DirectoryUserWrite,
        ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let write = write.clone();
        self.transaction(move |tx| {
            let mut ctx = ctx.clone();
            let ended = write_user(tx, &write, &mut ctx)?;
            finalize(tx, &format!("profile:{}", write.profile_id()), ctx)?;
            Ok(Decision::Commit(ended))
        })
        .await
    }

    pub(super) async fn write_directory_group(
        &self,
        write: &DirectoryGroupWrite,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let write = write.clone();
        self.mutate(format!("group:{}", write.group.id), ctx, move |tx| {
            write_group(tx, &write)
        })
        .await
    }

    pub(super) async fn query_directory(&self, query: &DirectoryQuery) -> SidResult<DirectoryPage> {
        let query = query.clone();
        // The total and the page read one snapshot.
        self.read(move |tx| query_directory(tx, &query)).await
    }

    // === Profile metadata ===

    pub(super) async fn get_profile_metadata(
        &self,
        profile: ProfileId,
        meta_key: &str,
    ) -> SidResult<Option<ProfileMetadata>> {
        let meta_key = meta_key.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (m:SidProfileMetadata) WHERE m.pair = $pair RETURN {METADATA}"),
                Params::default().with("pair", metadata_pair(profile, &meta_key)?),
            )?;
            rows.first().map(metadata).transpose()
        })
        .await
    }

    pub(super) async fn set_profile_metadata(
        &self,
        m: &ProfileMetadata,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let m = m.clone();
        self.mutate(format!("profile:{}", m.profile_id), ctx, move |tx| {
            set_metadata(tx, &m, None)
        })
        .await
    }

    pub(super) async fn delete_profile_metadata(
        &self,
        profile: ProfileId,
        meta_key: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let meta_key = meta_key.to_owned();
        self.mutate(format!("profile:{profile}"), ctx, move |tx| {
            delete_metadata(tx, profile, &meta_key)
        })
        .await
    }

    pub(super) async fn list_profile_metadata(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<ProfileMetadata>> {
        self.read(move |tx| metadata_of(tx, profile)).await
    }

    // === Personal access tokens ===

    pub(super) async fn get_pat(&self, id: PatId) -> SidResult<Option<PersonalAccessToken>> {
        self.read(move |tx| Ok(pats_where(tx, "t.id = $value", uuid(&id.0))?.pop()))
            .await
    }

    pub(super) async fn get_pat_by_token_hash(
        &self,
        token_hash: &str,
    ) -> SidResult<Option<PersonalAccessToken>> {
        let token_hash = token_hash.to_owned();
        self.read(move |tx| {
            Ok(pats_where(
                tx,
                "t.token_hash = $value",
                Value::String(token_hash.clone()),
            )?
            .pop())
        })
        .await
    }

    pub(super) async fn create_pat(
        &self,
        t: &PersonalAccessToken,
        active_limit: Option<u64>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let t = t.clone();
        self.mutate(format!("pat:{}", t.id.0), ctx, move |tx| {
            // The owner's turn makes the count and the insert one step.
            let owner = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id
                 SET p.pat_turn = coalesce(p.pat_turn, 0) + 1 RETURN p.id AS id",
                Params::default().with("id", bin(t.profile_id.as_bytes())),
            )?;
            if owner.is_empty() {
                return Err(SidError::NotFound(format!("profile {}", t.profile_id)));
            }
            let held = pats_where(tx, "t.profile_id = $value", bin(t.profile_id.as_bytes()))?;
            if held.iter().any(|h| h.id == t.id) {
                return Err(SidError::Conflict("PAT already exists".into()));
            }
            if let Some(limit) = active_limit {
                let active = held
                    .iter()
                    .filter(|h| h.status == PatStatus::Active)
                    .count();
                if u64::try_from(active).is_ok_and(|n| n >= limit) {
                    return Err(SidError::ResourceExhausted(format!(
                        "profile already holds {limit} active PATs"
                    )));
                }
            }
            tx.run(
                "CREATE (t:SidPat {id: $id, profile_id: $profile_id, name: $name,
                    description: $description, token_hash: $token_hash,
                    token_prefix: $token_prefix, scopes: $scopes, ip_allowlist: $ip_allowlist,
                    status: $status, expires_at: $expires_at, last_used_at: $last_used_at,
                    last_used_ip: $last_used_ip, use_count: $use_count, revoked_at: $revoked_at,
                    revoked_by: $revoked_by, created_at: $created_at})",
                Params::default()
                    .with("id", uuid(&t.id.0))
                    .with("profile_id", bin(t.profile_id.as_bytes()))
                    .with("name", Value::String(t.name.clone()))
                    .with("description", opt_text(t.description.as_deref()))
                    .with("token_hash", Value::String(t.token_hash.clone()))
                    .with("token_prefix", Value::String(t.token_prefix.clone()))
                    .with("scopes", texts(&t.scopes))
                    .with("ip_allowlist", texts(&t.ip_allowlist))
                    .with("status", Value::String(t.status.as_str().into()))
                    .with("expires_at", opt_time(t.expires_at))
                    .with("last_used_at", opt_time(t.last_used_at))
                    .with("last_used_ip", opt_text(t.last_used_ip.as_deref()))
                    .with(
                        "use_count",
                        Value::Int(
                            i64::try_from(t.use_count)
                                .map_err(|_| SidError::Validation("use count".into()))?,
                        ),
                    )
                    .with("revoked_at", opt_time(t.revoked_at))
                    .with("revoked_by", opt_text(t.revoked_by.as_deref()))
                    .with("created_at", time(t.created_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn record_pat_use(
        &self,
        id: PatId,
        ip: Option<&str>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let ip = ip.map(str::to_owned);
        self.transaction(move |tx| {
            let now = Utc::now();
            let usable = pats_where(tx, "t.id = $value", uuid(&id.0))?
                .pop()
                .is_some_and(|t| {
                    t.status == PatStatus::Active && t.expires_at.is_none_or(|end| end > now)
                });
            if !usable {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (t:SidPat) WHERE t.id = $id AND t.status = 'active'
                 SET t.last_used_at = $now, t.last_used_ip = $ip, t.use_count = t.use_count + 1",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("now", time(now))
                    .with("ip", opt_text(ip.as_deref())),
            )?;
            finalize(tx, &format!("pat:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn revoke_pat(
        &self,
        id: PatId,
        revoked_by: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let revoked_by = revoked_by.to_owned();
        self.transaction(move |tx| {
            let open = pats_where(tx, "t.id = $value", uuid(&id.0))?
                .pop()
                .is_some_and(|t| t.status != PatStatus::Revoked);
            if !open {
                return Ok(Decision::Abandon(false));
            }
            revoke(tx, &[id], Some(&revoked_by))?;
            finalize(tx, &format!("pat:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn list_pats_by_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<PersonalAccessToken>> {
        self.read(move |tx| pats_where(tx, "t.profile_id = $value", bin(profile.as_bytes())))
            .await
    }

    pub(super) async fn list_all_pats(&self) -> SidResult<Vec<PersonalAccessToken>> {
        self.read(|tx| {
            let rows = tx.run(&format!("MATCH (t:SidPat) RETURN {PAT}"), Params::default())?;
            rows.iter().map(pat).collect()
        })
        .await
    }

    pub(super) async fn count_active_pats_by_profile(&self, profile: ProfileId) -> SidResult<u64> {
        let held = self.list_pats_by_profile(profile).await?;
        let active = held
            .iter()
            .filter(|t| t.status == PatStatus::Active)
            .count();
        u64::try_from(active).map_err(|_| SidError::Storage("active count".into()))
    }

    pub(super) async fn revoke_active_pats_by_profile(
        &self,
        profile: ProfileId,
        revoked_by: &str,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        let revoked_by = revoked_by.to_owned();
        self.transaction(move |tx| {
            let revoked = revoke_active(tx, profile, &revoked_by)?;
            if revoked == 0 && ctx.work.is_empty() && ctx.operation.is_none() {
                return Ok(Decision::Abandon(0));
            }
            finalize(
                tx,
                &format!("pat:cascade_revoke:profile:{profile}"),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(revoked))
        })
        .await
    }

    pub(super) async fn revoke_unused_pats(
        &self,
        days: u32,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(days));
        self.transaction(move |tx| {
            // Unused since the cutoff: the last use, or the creation of one
            // never used, came before it.
            let unused: Vec<PatId> =
                pats_where(tx, "t.status = $value", Value::String("active".into()))?
                    .into_iter()
                    .filter(|t| t.last_used_at.unwrap_or(t.created_at) < cutoff)
                    .map(|t| t.id)
                    .collect();
            revoke(tx, &unused, None)?;
            let revoked =
                u64::try_from(unused.len()).map_err(|_| SidError::Storage("count".into()))?;
            if revoked == 0 && ctx.work.is_empty() && ctx.operation.is_none() {
                return Ok(Decision::Abandon(0));
            }
            finalize(tx, "pat:revoke_unused", ctx.clone())?;
            Ok(Decision::Commit(revoked))
        })
        .await
    }
}
