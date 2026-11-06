// SPDX-License-Identifier: AGPL-3.0-only
//! Profiles and their own phones and emails in CoordiNode. A profile is one
//! `SidProfile` node; each contact is its own node naming the profile, so a
//! contact change never rewrites the profile. A profile's numbers and
//! addresses are unique per profile through a key of both; its one primary
//! contact through `primary_of`, which only the primary carries.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::{
    EmailLabel, EmailSettings, MutationContext, PhoneLabel, PhoneSettings, Profile, ProfileEmail,
    ProfileEmailId, ProfileId, ProfilePhone, ProfilePhoneId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bool, get_count, get_int,
    get_opt_int, get_opt_text, get_opt_time, get_opt_uuid, get_text, get_texts, get_time, get_uuid,
    key, opt_text, opt_time, opt_uuid, page, texts, time, uuid,
};

/// Every property of a profile node, as `RETURN` lists them.
pub(super) const PROFILE: &str = "p.id AS id, p.profile_type AS profile_type,
    p.username AS username, p.given_name AS given_name, p.family_name AS family_name,
    p.middle_name AS middle_name, p.honorific_prefix AS honorific_prefix,
    p.honorific_suffix AS honorific_suffix, p.roles AS roles, p.status AS status,
    p.max_assurance AS max_assurance, p.visibility AS visibility, p.manager_id AS manager_id,
    p.migration_pending AS migration_pending, p.migration_started_at AS migration_started_at,
    p.migration_completed_at AS migration_completed_at, p.revision AS revision,
    p.created_at AS created_at, p.updated_at AS updated_at";

const PHONE: &str = "c.id AS id, c.profile_id AS profile_id, c.e164 AS e164,
    c.extension AS extension, c.contact_label AS contact_label, c.custom_label AS custom_label,
    c.is_primary AS is_primary, c.can_receive_sms AS can_receive_sms,
    c.can_receive_fax AS can_receive_fax, c.can_receive_voice AS can_receive_voice,
    c.verified AS verified, c.verified_at AS verified_at, c.created_at AS created_at,
    c.updated_at AS updated_at";

const EMAIL: &str = "c.id AS id, c.profile_id AS profile_id, c.email AS email,
    c.contact_label AS contact_label, c.custom_label AS custom_label, c.is_primary AS is_primary,
    c.verified AS verified, c.verified_at AS verified_at, c.created_at AS created_at,
    c.updated_at AS updated_at";

/// Labels of the nodes a profile owns, deleted with it.
const OWNED: &[&str] = &["SidPhone", "SidEmail"];

fn profile_id(id: ProfileId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn revision(value: u64) -> SidResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| SidError::Validation(format!("profile revision {value} out of range")))
}

/// The profile `row` holds. An unknown type, status, assurance or
/// visibility is an error: read as a default it would reopen a closed or
/// suspended account.
pub(super) fn profile(row: &Row) -> SidResult<Profile> {
    fn parsed<T: std::str::FromStr<Err = String>>(row: &Row, name: &str) -> SidResult<T> {
        get_text(row, name)?.parse().map_err(SidError::Storage)
    }
    let stored = |name: &str| -> SidResult<u64> {
        let value = get_int(row, name)?;
        u64::try_from(value).map_err(|_| SidError::Storage(format!("{name}: {value}")))
    };
    Ok(Profile {
        id: ProfileId::from_slice(&super::get_bytes(row, "id")?)
            .map_err(|e| SidError::Storage(format!("profile id: {e}")))?,
        profile_type: parsed(row, "profile_type")?,
        username: get_opt_text(row, "username")?,
        given_name: get_opt_text(row, "given_name")?,
        family_name: get_opt_text(row, "family_name")?,
        middle_name: get_opt_text(row, "middle_name")?,
        honorific_prefix: get_opt_text(row, "honorific_prefix")?,
        honorific_suffix: get_opt_text(row, "honorific_suffix")?,
        roles: get_texts(row, "roles")?,
        status: parsed(row, "status")?,
        max_assurance: parsed(row, "max_assurance")?,
        visibility: parsed(row, "visibility")?,
        manager_id: get_opt_uuid(row, "manager_id")?
            .map(ProfileId::from_uuid)
            .transpose()
            .map_err(|e| SidError::Storage(format!("manager id: {e}")))?,
        migration_pending: get_bool(row, "migration_pending")?,
        migration_started_at: get_opt_time(row, "migration_started_at")?,
        migration_completed_at: get_opt_time(row, "migration_completed_at")?,
        revision: stored("revision")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// The properties `profile` stores, its revision as given.
fn profile_params(profile: &Profile) -> SidResult<Params> {
    Ok(Params::default()
        .with("id", profile_id(profile.id))
        .with(
            "profile_type",
            Value::String(profile.profile_type.as_str().into()),
        )
        .with("username", opt_text(profile.username.as_deref()))
        .with("given_name", opt_text(profile.given_name.as_deref()))
        .with("family_name", opt_text(profile.family_name.as_deref()))
        .with("middle_name", opt_text(profile.middle_name.as_deref()))
        .with(
            "honorific_prefix",
            opt_text(profile.honorific_prefix.as_deref()),
        )
        .with(
            "honorific_suffix",
            opt_text(profile.honorific_suffix.as_deref()),
        )
        .with("roles", texts(&profile.roles))
        .with("status", Value::String(profile.status.as_str().into()))
        .with(
            "max_assurance",
            Value::String(profile.max_assurance.as_str().into()),
        )
        .with(
            "visibility",
            Value::String(profile.visibility.as_str().into()),
        )
        .with(
            "manager_id",
            opt_uuid(profile.manager_id.as_ref().map(|m| m.as_uuid())),
        )
        .with("migration_pending", Value::Bool(profile.migration_pending))
        .with(
            "migration_started_at",
            opt_time(profile.migration_started_at),
        )
        .with(
            "migration_completed_at",
            opt_time(profile.migration_completed_at),
        )
        .with("revision", revision(profile.revision)?)
        .with("created_at", time(profile.created_at))
        .with("updated_at", time(profile.updated_at)))
}

/// Store a new profile in `tx`; an existing id or user name is `Conflict`.
pub(super) fn insert(tx: &Statements<'_>, profile: &Profile) -> SidResult<()> {
    let found = tx.run(
        "MATCH (p:SidProfile) WHERE p.id = $id RETURN p.id AS id",
        Params::default().with("id", profile_id(profile.id)),
    )?;
    if !found.is_empty() {
        return Err(SidError::Conflict("profile already exists".into()));
    }
    tx.run(
        "CREATE (p:SidProfile {id: $id, profile_type: $profile_type, username: $username,
            given_name: $given_name, family_name: $family_name, middle_name: $middle_name,
            honorific_prefix: $honorific_prefix, honorific_suffix: $honorific_suffix,
            roles: $roles, status: $status, max_assurance: $max_assurance,
            visibility: $visibility, manager_id: $manager_id,
            migration_pending: $migration_pending, migration_started_at: $migration_started_at,
            migration_completed_at: $migration_completed_at, revision: $revision,
            created_at: $created_at, updated_at: $updated_at})",
        profile_params(profile)?,
    )?;
    Ok(())
}

/// Write `profile` over the stored one while it is still at
/// `profile.revision`, moving the revision on; its id and creation time
/// never change. False when it is gone or changed since it was read.
pub(super) fn update(tx: &Statements<'_>, profile: &Profile) -> SidResult<bool> {
    let next = profile
        .revision
        .checked_add(1)
        .ok_or_else(|| SidError::Validation("profile revision exhausted".into()))?;
    let rows = tx.run(
        "MATCH (p:SidProfile) WHERE p.id = $id AND p.revision = $revision
         SET p.profile_type = $profile_type, p.username = $username,
             p.given_name = $given_name, p.family_name = $family_name,
             p.middle_name = $middle_name, p.honorific_prefix = $honorific_prefix,
             p.honorific_suffix = $honorific_suffix, p.roles = $roles, p.status = $status,
             p.visibility = $visibility, p.max_assurance = $max_assurance,
             p.manager_id = $manager_id, p.migration_pending = $migration_pending,
             p.migration_started_at = $migration_started_at,
             p.migration_completed_at = $migration_completed_at,
             p.updated_at = $updated_at, p.revision = $next
         RETURN p.id AS id",
        profile_params(profile)?.with("next", revision(next)?),
    )?;
    Ok(!rows.is_empty())
}

/// The profile `id`, read in `tx`.
pub(super) fn get(tx: &Statements<'_>, id: ProfileId) -> SidResult<Option<Profile>> {
    let rows = tx.run(
        &format!("MATCH (p:SidProfile) WHERE p.id = $id RETURN {PROFILE}"),
        Params::default().with("id", profile_id(id)),
    )?;
    rows.first().map(profile).transpose()
}

/// Delete profile `id` with everything it owns, in `tx`.
pub(super) fn delete(tx: &Statements<'_>, id: ProfileId) -> SidResult<()> {
    for label in OWNED {
        tx.run(
            &format!("MATCH (o:{label}) WHERE o.profile_id = $id DETACH DELETE o"),
            Params::default().with("id", profile_id(id)),
        )?;
    }
    super::project::disown(tx, id)?;
    tx.run(
        "MATCH (p:SidProfile) WHERE p.id = $id DETACH DELETE p",
        Params::default().with("id", profile_id(id)),
    )?;
    Ok(())
}

fn phone(row: &Row) -> SidResult<ProfilePhone> {
    let e164 = get_int(row, "e164")?;
    Ok(ProfilePhone {
        id: ProfilePhoneId(get_uuid(row, "id")?),
        profile_id: ProfileId::from_uuid(get_uuid(row, "profile_id")?)
            .map_err(|e| SidError::Storage(format!("phone profile: {e}")))?,
        e164: u64::try_from(e164).map_err(|_| SidError::Storage(format!("e164: {e164}")))?,
        extension: get_opt_int(row, "extension")?
            .map(|e| u32::try_from(e).map_err(|_| SidError::Storage(format!("extension: {e}"))))
            .transpose()?,
        label: PhoneLabel::from_str_lossy(&get_text(row, "contact_label")?),
        custom_label: get_opt_text(row, "custom_label")?,
        is_primary: get_bool(row, "is_primary")?,
        can_receive_sms: get_bool(row, "can_receive_sms")?,
        can_receive_fax: get_bool(row, "can_receive_fax")?,
        can_receive_voice: get_bool(row, "can_receive_voice")?,
        verified: get_bool(row, "verified")?,
        verified_at: get_opt_time(row, "verified_at")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn email(row: &Row) -> SidResult<ProfileEmail> {
    Ok(ProfileEmail {
        id: ProfileEmailId(get_uuid(row, "id")?),
        profile_id: ProfileId::from_uuid(get_uuid(row, "profile_id")?)
            .map_err(|e| SidError::Storage(format!("email profile: {e}")))?,
        email: get_text(row, "email")?,
        label: EmailLabel::from_str_lossy(&get_text(row, "contact_label")?),
        custom_label: get_opt_text(row, "custom_label")?,
        is_primary: get_bool(row, "is_primary")?,
        verified: get_bool(row, "verified")?,
        verified_at: get_opt_time(row, "verified_at")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// `primary_of` of a contact: its profile while it is the primary one.
fn primary_of(profile: ProfileId, is_primary: bool) -> Value {
    if is_primary {
        profile_id(profile)
    } else {
        Value::Null
    }
}

/// Take the primary flag from `profile`'s primary contact of `label` at `at`.
fn clear_primary(
    tx: &Statements<'_>,
    label: &str,
    profile: ProfileId,
    at: DateTime<Utc>,
) -> SidResult<()> {
    tx.run(
        &format!(
            "MATCH (c:{label}) WHERE c.primary_of = $profile
             SET c.is_primary = false, c.primary_of = null, c.updated_at = $at"
        ),
        Params::default()
            .with("profile", profile_id(profile))
            .with("at", time(at)),
    )?;
    Ok(())
}

/// Store a new phone in `tx`; its id or its number on the profile already
/// stored is `Conflict`.
pub(super) fn insert_phone(tx: &Statements<'_>, phone: &ProfilePhone) -> SidResult<()> {
    let e164 = i64::try_from(phone.e164)
        .map_err(|_| SidError::Validation(format!("e164 {} out of range", phone.e164)))?;
    if !tx
        .run(
            "MATCH (c:SidPhone) WHERE c.id = $id RETURN c.id AS id",
            Params::default().with("id", uuid(&phone.id.0)),
        )?
        .is_empty()
    {
        return Err(SidError::Conflict("profile phone already exists".into()));
    }
    if phone.is_primary {
        clear_primary(tx, "SidPhone", phone.profile_id, phone.updated_at)?;
    }
    tx.run(
        "CREATE (c:SidPhone {id: $id, profile_id: $profile_id, number_key: $number_key,
            primary_of: $primary_of, e164: $e164, extension: $extension, contact_label: $label,
            custom_label: $custom_label, is_primary: $is_primary,
            can_receive_sms: $can_receive_sms, can_receive_fax: $can_receive_fax,
            can_receive_voice: $can_receive_voice, verified: $verified,
            verified_at: $verified_at, created_at: $created_at, updated_at: $updated_at})",
        Params::default()
            .with("id", uuid(&phone.id.0))
            .with("profile_id", profile_id(phone.profile_id))
            .with(
                "number_key",
                key(&[phone.profile_id.as_bytes(), &e164.to_be_bytes()])?,
            )
            .with("primary_of", primary_of(phone.profile_id, phone.is_primary))
            .with("e164", Value::Int(e164))
            .with(
                "extension",
                phone
                    .extension
                    .map_or(Value::Null, |e| Value::Int(i64::from(e))),
            )
            .with("label", Value::String(phone.label.as_str().into()))
            .with("custom_label", opt_text(phone.custom_label.as_deref()))
            .with("is_primary", Value::Bool(phone.is_primary))
            .with("can_receive_sms", Value::Bool(phone.can_receive_sms))
            .with("can_receive_fax", Value::Bool(phone.can_receive_fax))
            .with("can_receive_voice", Value::Bool(phone.can_receive_voice))
            .with("verified", Value::Bool(phone.verified))
            .with("verified_at", opt_time(phone.verified_at))
            .with("created_at", time(phone.created_at))
            .with("updated_at", time(phone.updated_at)),
    )?;
    Ok(())
}

/// Store a new email in `tx`; its id or its address on the profile already
/// stored is `Conflict`.
pub(super) fn insert_email(tx: &Statements<'_>, email: &ProfileEmail) -> SidResult<()> {
    if !tx
        .run(
            "MATCH (c:SidEmail) WHERE c.id = $id RETURN c.id AS id",
            Params::default().with("id", uuid(&email.id.0)),
        )?
        .is_empty()
    {
        return Err(SidError::Conflict("profile email already exists".into()));
    }
    if email.is_primary {
        clear_primary(tx, "SidEmail", email.profile_id, email.updated_at)?;
    }
    tx.run(
        "CREATE (c:SidEmail {id: $id, profile_id: $profile_id, address_key: $address_key,
            primary_of: $primary_of, email: $email, contact_label: $label,
            custom_label: $custom_label, is_primary: $is_primary, verified: $verified,
            verified_at: $verified_at, created_at: $created_at, updated_at: $updated_at})",
        Params::default()
            .with("id", uuid(&email.id.0))
            .with("profile_id", profile_id(email.profile_id))
            .with(
                "address_key",
                key(&[email.profile_id.as_bytes(), email.email.as_bytes()])?,
            )
            .with("primary_of", primary_of(email.profile_id, email.is_primary))
            .with("email", Value::String(email.email.clone()))
            .with("label", Value::String(email.label.as_str().into()))
            .with("custom_label", opt_text(email.custom_label.as_deref()))
            .with("is_primary", Value::Bool(email.is_primary))
            .with("verified", Value::Bool(email.verified))
            .with("verified_at", opt_time(email.verified_at))
            .with("created_at", time(email.created_at))
            .with("updated_at", time(email.updated_at)),
    )?;
    Ok(())
}

/// Store `email`, or write it over the stored email with its id; its
/// creation time and profile stay as stored.
pub(super) fn upsert_email(tx: &Statements<'_>, email: &ProfileEmail) -> SidResult<()> {
    let updated = tx.run(
        "MATCH (c:SidEmail) WHERE c.id = $id
         SET c.email = $email, c.address_key = $address_key, c.contact_label = $label,
             c.custom_label = $custom_label, c.is_primary = $is_primary,
             c.primary_of = $primary_of, c.verified = $verified,
             c.verified_at = $verified_at, c.updated_at = $updated_at
         RETURN c.id AS id",
        Params::default()
            .with("id", uuid(&email.id.0))
            .with(
                "address_key",
                key(&[email.profile_id.as_bytes(), email.email.as_bytes()])?,
            )
            .with("primary_of", primary_of(email.profile_id, email.is_primary))
            .with("email", Value::String(email.email.clone()))
            .with("label", Value::String(email.label.as_str().into()))
            .with("custom_label", opt_text(email.custom_label.as_deref()))
            .with("is_primary", Value::Bool(email.is_primary))
            .with("verified", Value::Bool(email.verified))
            .with("verified_at", opt_time(email.verified_at))
            .with("updated_at", time(email.updated_at)),
    )?;
    if updated.is_empty() {
        insert_email(tx, email)?;
    }
    Ok(())
}

/// Delete contact `id` of `label`; only `owner`'s when given.
fn delete_contact(
    tx: &Statements<'_>,
    label: &str,
    id: &uuid::Uuid,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    let params = Params::default().with("id", uuid(id));
    match owner {
        Some(owner) => tx.run(
            &format!(
                "MATCH (c:{label}) WHERE c.id = $id AND c.profile_id = $owner DETACH DELETE c"
            ),
            params.with("owner", profile_id(owner)),
        )?,
        None => tx.run(
            &format!("MATCH (c:{label}) WHERE c.id = $id DETACH DELETE c"),
            params,
        )?,
    };
    Ok(())
}

pub(super) fn delete_phone(
    tx: &Statements<'_>,
    id: ProfilePhoneId,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    delete_contact(tx, "SidPhone", &id.0, owner)
}

pub(super) fn delete_email(
    tx: &Statements<'_>,
    id: ProfileEmailId,
    owner: Option<ProfileId>,
) -> SidResult<()> {
    delete_contact(tx, "SidEmail", &id.0, owner)
}

/// `profile`'s contacts of `label`, primary first, then oldest first.
fn contacts<T>(
    tx: &Statements<'_>,
    label: &str,
    fields: &str,
    profile: ProfileId,
    decode: fn(&Row) -> SidResult<T>,
) -> SidResult<Vec<T>> {
    let rows = tx.run(
        &format!(
            "MATCH (c:{label}) WHERE c.profile_id = $profile RETURN {fields}
             ORDER BY c.is_primary DESC, c.created_at"
        ),
        Params::default().with("profile", profile_id(profile)),
    )?;
    rows.iter().map(decode).collect()
}

fn contact<T>(
    tx: &Statements<'_>,
    label: &str,
    fields: &str,
    id: &uuid::Uuid,
    decode: fn(&Row) -> SidResult<T>,
) -> SidResult<Option<T>> {
    let rows = tx.run(
        &format!("MATCH (c:{label}) WHERE c.id = $id RETURN {fields}"),
        Params::default().with("id", uuid(id)),
    )?;
    rows.first().map(decode).transpose()
}

fn primary<T>(
    tx: &Statements<'_>,
    label: &str,
    fields: &str,
    profile: ProfileId,
    decode: fn(&Row) -> SidResult<T>,
) -> SidResult<Option<T>> {
    let rows = tx.run(
        &format!("MATCH (c:{label}) WHERE c.primary_of = $profile RETURN {fields}"),
        Params::default().with("profile", profile_id(profile)),
    )?;
    rows.first().map(decode).transpose()
}

/// Make `id` of `label` `profile`'s primary contact at `at`; false when the
/// profile has no such contact.
fn set_primary(
    tx: &Statements<'_>,
    label: &str,
    profile: ProfileId,
    id: &uuid::Uuid,
    at: DateTime<Utc>,
) -> SidResult<bool> {
    let owned = tx.run(
        &format!(
            "MATCH (c:{label}) WHERE c.id = $id AND c.profile_id = $profile RETURN c.id AS id"
        ),
        Params::default()
            .with("id", uuid(id))
            .with("profile", profile_id(profile)),
    )?;
    if owned.is_empty() {
        return Ok(false);
    }
    clear_primary(tx, label, profile, at)?;
    tx.run(
        &format!(
            "MATCH (c:{label}) WHERE c.id = $id
             SET c.is_primary = true, c.primary_of = $profile, c.updated_at = $at"
        ),
        Params::default()
            .with("id", uuid(id))
            .with("profile", profile_id(profile))
            .with("at", time(at)),
    )?;
    Ok(true)
}

impl CoordinodeBackend {
    async fn read<T, F>(&self, read: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnMut(&Statements<'_>) -> SidResult<T> + Send + 'static,
    {
        let mut read = read;
        self.transaction(move |tx| read(tx).map(Decision::Abandon))
            .await
    }

    pub(super) async fn get_profile(&self, id: ProfileId) -> SidResult<Option<Profile>> {
        self.read(move |tx| get(tx, id)).await
    }

    pub(super) async fn get_profile_by_username(
        &self,
        username: &str,
    ) -> SidResult<Option<Profile>> {
        let username = username.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (p:SidProfile) WHERE p.username = $username RETURN {PROFILE}"),
                Params::default().with("username", Value::String(username.clone())),
            )?;
            rows.first().map(profile).transpose()
        })
        .await
    }

    pub(super) async fn get_profile_by_email(&self, address: &str) -> SidResult<Option<Profile>> {
        let address = address.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidEmail) WHERE c.email = $email RETURN c.profile_id AS profile_id LIMIT 1",
                Params::default().with("email", Value::String(address.clone())),
            )?;
            let Some(row) = rows.first() else {
                return Ok(None);
            };
            let id = ProfileId::from_uuid(get_uuid(row, "profile_id")?)
                .map_err(|e| SidError::Storage(format!("email profile: {e}")))?;
            get(tx, id)
        })
        .await
    }

    pub(super) async fn create_profile(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = profile.clone();
        self.mutate(format!("profile:{}", profile.id), ctx, move |tx| {
            insert(tx, &stored)
        })
        .await
    }

    pub(super) async fn update_profile(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (stored, chain) = (profile.clone(), format!("profile:{}", profile.id));
        self.transaction(move |tx| {
            if !update(tx, &stored)? {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_profile(
        &self,
        id: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("profile:{id}"), ctx, move |tx| delete(tx, id))
            .await
    }

    pub(super) async fn list_profiles(&self, offset: u64, limit: u64) -> SidResult<Vec<Profile>> {
        let (offset, limit) = (page(offset)?, page(limit)?);
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (p:SidProfile) RETURN {PROFILE}
                     ORDER BY p.created_at, p.id SKIP $offset LIMIT $limit"
                ),
                Params::default()
                    .with("offset", offset.clone())
                    .with("limit", limit.clone()),
            )?;
            rows.iter().map(profile).collect()
        })
        .await
    }

    pub(super) async fn count_profiles(&self) -> SidResult<u64> {
        self.read(|tx| {
            get_count(&tx.run(
                "MATCH (p:SidProfile) RETURN count(p) AS n",
                Params::default(),
            )?)
        })
        .await
    }

    pub(super) async fn list_profiles_with_status(
        &self,
        status: sid_core::models::ProfileStatus,
    ) -> SidResult<Vec<Profile>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (p:SidProfile) WHERE p.status = $status RETURN {PROFILE}
                     ORDER BY p.created_at, p.id"
                ),
                Params::default().with("status", Value::String(status.as_str().into())),
            )?;
            rows.iter().map(profile).collect()
        })
        .await
    }

    pub(super) async fn list_profiles_with_pending_migration(&self) -> SidResult<Vec<Profile>> {
        self.read(|tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (p:SidProfile) WHERE p.migration_pending = true RETURN {PROFILE}
                     ORDER BY p.created_at, p.id"
                ),
                Params::default(),
            )?;
            rows.iter().map(profile).collect()
        })
        .await
    }

    // === Contacts ===

    pub(super) async fn get_profile_phone(
        &self,
        id: ProfilePhoneId,
    ) -> SidResult<Option<ProfilePhone>> {
        self.read(move |tx| contact(tx, "SidPhone", PHONE, &id.0, phone))
            .await
    }

    pub(super) async fn list_profile_phones(
        &self,
        owner: ProfileId,
    ) -> SidResult<Vec<ProfilePhone>> {
        self.read(move |tx| contacts(tx, "SidPhone", PHONE, owner, phone))
            .await
    }

    pub(super) async fn get_primary_profile_phone(
        &self,
        owner: ProfileId,
    ) -> SidResult<Option<ProfilePhone>> {
        self.read(move |tx| primary(tx, "SidPhone", PHONE, owner, phone))
            .await
    }

    pub(super) async fn create_profile_phone(
        &self,
        stored: &ProfilePhone,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = stored.clone();
        self.mutate(format!("profile_phone:{}", stored.id.0), ctx, move |tx| {
            insert_phone(tx, &stored)
        })
        .await
    }

    pub(super) async fn update_profile_phone_settings(
        &self,
        owner: ProfileId,
        id: ProfilePhoneId,
        settings: &PhoneSettings,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let settings = settings.clone();
        self.transaction(move |tx| {
            let Some(mut stored) = contact(tx, "SidPhone", PHONE, &id.0, phone)? else {
                return Ok(Decision::Abandon(false));
            };
            if stored.profile_id != owner {
                return Ok(Decision::Abandon(false));
            }
            settings.apply_to(&mut stored);
            stored.updated_at = at;
            tx.run(
                "MATCH (c:SidPhone) WHERE c.id = $id
                 SET c.contact_label = $label, c.custom_label = $custom_label,
                     c.can_receive_sms = $sms, c.can_receive_fax = $fax,
                     c.can_receive_voice = $voice, c.updated_at = $at",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("label", Value::String(stored.label.as_str().into()))
                    .with("custom_label", opt_text(stored.custom_label.as_deref()))
                    .with("sms", Value::Bool(stored.can_receive_sms))
                    .with("fax", Value::Bool(stored.can_receive_fax))
                    .with("voice", Value::Bool(stored.can_receive_voice))
                    .with("at", time(at)),
            )?;
            let mut ctx = ctx.clone();
            ctx.record_effect(&stored)?;
            finalize(tx, &format!("profile_phone:{}", id.0), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn set_primary_profile_phone(
        &self,
        owner: ProfileId,
        id: ProfilePhoneId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            if !set_primary(tx, "SidPhone", owner, &id.0, at)? {
                return Ok(Decision::Abandon(false));
            }
            let stored = contact(tx, "SidPhone", PHONE, &id.0, phone)?
                .ok_or_else(|| SidError::Storage("primary phone vanished".into()))?;
            let mut ctx = ctx.clone();
            ctx.record_effect(&stored)?;
            finalize(tx, &format!("profile_phone:{}", id.0), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_profile_phone(
        &self,
        id: ProfilePhoneId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("profile_phone:{}", id.0), ctx, move |tx| {
            delete_phone(tx, id, None)
        })
        .await
    }

    pub(super) async fn get_profile_email(
        &self,
        id: ProfileEmailId,
    ) -> SidResult<Option<ProfileEmail>> {
        self.read(move |tx| contact(tx, "SidEmail", EMAIL, &id.0, email))
            .await
    }

    pub(super) async fn list_profile_emails(
        &self,
        owner: ProfileId,
    ) -> SidResult<Vec<ProfileEmail>> {
        self.read(move |tx| contacts(tx, "SidEmail", EMAIL, owner, email))
            .await
    }

    pub(super) async fn get_primary_profile_email(
        &self,
        owner: ProfileId,
    ) -> SidResult<Option<ProfileEmail>> {
        self.read(move |tx| primary(tx, "SidEmail", EMAIL, owner, email))
            .await
    }

    pub(super) async fn create_profile_email(
        &self,
        stored: &ProfileEmail,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = stored.clone();
        self.mutate(format!("profile_email:{}", stored.id.0), ctx, move |tx| {
            insert_email(tx, &stored)
        })
        .await
    }

    pub(super) async fn update_profile_email_settings(
        &self,
        owner: ProfileId,
        id: ProfileEmailId,
        settings: &EmailSettings,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let settings = settings.clone();
        self.transaction(move |tx| {
            let Some(mut stored) = contact(tx, "SidEmail", EMAIL, &id.0, email)? else {
                return Ok(Decision::Abandon(false));
            };
            if stored.profile_id != owner {
                return Ok(Decision::Abandon(false));
            }
            settings.apply_to(&mut stored);
            stored.updated_at = at;
            tx.run(
                "MATCH (c:SidEmail) WHERE c.id = $id
                 SET c.contact_label = $label, c.custom_label = $custom_label, c.updated_at = $at",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("label", Value::String(stored.label.as_str().into()))
                    .with("custom_label", opt_text(stored.custom_label.as_deref()))
                    .with("at", time(at)),
            )?;
            let mut ctx = ctx.clone();
            ctx.record_effect(&stored)?;
            finalize(tx, &format!("profile_email:{}", id.0), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn set_primary_profile_email(
        &self,
        owner: ProfileId,
        id: ProfileEmailId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            if !set_primary(tx, "SidEmail", owner, &id.0, at)? {
                return Ok(Decision::Abandon(false));
            }
            let stored = contact(tx, "SidEmail", EMAIL, &id.0, email)?
                .ok_or_else(|| SidError::Storage("primary email vanished".into()))?;
            let mut ctx = ctx.clone();
            ctx.record_effect(&stored)?;
            finalize(tx, &format!("profile_email:{}", id.0), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_profile_email(
        &self,
        id: ProfileEmailId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("profile_email:{}", id.0), ctx, move |tx| {
            delete_email(tx, id, None)
        })
        .await
    }
}
