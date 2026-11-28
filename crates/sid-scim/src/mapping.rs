// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM ↔ SID type conversion.
//!
//! Maps SCIM 2.0 resources (RFC 7643) to SID domain models.
//!
//! Key rules from identity model:
//! - SCIM `userName` → Principal(Username, `{value}#{domain}`) — federated org login
//! - SCIM `emails` → Principal(Email) — contact email as login handle
//! - SCIM `phoneNumbers` → Principal(Phone) — contact phone as login handle
//! - Corporate profiles start as `Provisioned` (unclaimed by their user)
//! - All principals start `verified: false`

use jiff::Timestamp;
use sid_core::models::{
    DirectoryUserId, Group, GroupId, Principal, PrincipalId, PrincipalType, Profile, ProfileEmail,
    ProfileEmailId, ProfileId, ProfileMetadata, ProfilePhone, ProfilePhoneId, ProfileStatus,
    ProfileType, ProfileVisibility, profile_email::EmailLabel, profile_phone::PhoneLabel,
};
use sid_proto::sid::v1 as proto;

/// Context for SCIM operations: organization domain for corporate login formatting.
pub struct ScimOrgContext {
    /// Organization domain (e.g., "acme.corp").
    /// Used to construct corporate login identifiers: `{userName}#{domain}`.
    pub org_domain: String,

    /// Project ID for group scoping.
    pub project_id: sid_core::models::ProjectId,
}

impl ScimOrgContext {
    /// The context of an installation whose directory belongs to `org`: its
    /// logins carry the organization's own domain, its groups the system
    /// project.
    pub fn installation(org: &sid_core::models::Organization) -> Self {
        Self {
            org_domain: org.canonical_domain.clone(),
            project_id: sid_core::models::ProjectId::SYSTEM,
        }
    }
}

/// Why a SCIM resource cannot be mapped (RFC 7644 §3.12 `invalidValue`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    /// RFC 7643 §2.4: the `primary` attribute is true for at most one value.
    #[error("{0}: more than one value is primary")]
    MultiplePrimary(&'static str),
    #[error("phoneNumbers: '{0}' is not a telephone number")]
    InvalidPhone(String),
    #[error("emails: '{0}' is not an admissible email address: {1}")]
    InvalidEmail(String, String),
}

/// Result of mapping a SCIM CreateUser request to SID entities.
pub struct CreateUserMapping {
    pub profile: Profile,
    pub principals: Vec<Principal>,
    pub metadata: Vec<ProfileMetadata>,
    /// Contact email records (profile_emails table).
    pub emails: Vec<ProfileEmail>,
    /// Contact phone records (profile_phones table).
    pub phones: Vec<ProfilePhone>,
}

/// Map SCIM CreateUser request to SID Profile + Identifiers + Metadata.
pub fn scim_create_user_to_sid(
    req: &proto::ScimCreateUserRequest,
    ctx: &ScimOrgContext,
) -> Result<CreateUserMapping, MappingError> {
    check_single_primary(&req.emails, &req.phone_numbers)?;
    let profile_id = ProfileId::generate();
    let now = Timestamp::now();

    // Extract structured name components from SCIM name object
    let (given_name, family_name, middle_name) = req
        .name
        .as_ref()
        .map(|n| {
            (
                non_empty(&n.given_name),
                non_empty(&n.family_name),
                non_empty(&n.middle_name),
            )
        })
        .unwrap_or((None, None, None));

    let profile = Profile::new_corporate(profile_id, given_name, family_name, middle_name, now);

    let mut principals = Vec::new();
    let mut metadata = Vec::new();

    // userName → Principal(Username, "{userName}#{domain}") — federated org login
    if !req.user_name.is_empty() {
        principals.push(organization_login(
            profile_id,
            &req.user_name,
            &ctx.org_domain,
        ));
    }

    let mut emails = Vec::new();
    let mut phones = Vec::new();

    // emails → Principal(Email) + ProfileEmail
    for email in req.emails.iter().filter(|e| !e.value.is_empty()) {
        let (principal, contact) = email_binding(profile_id, email, now)?;
        principals.push(principal);
        emails.push(contact);
    }

    // phoneNumbers → Principal(Phone) + ProfilePhone
    for phone in req.phone_numbers.iter().filter(|p| !p.value.is_empty()) {
        principals.push(corporate_contact(
            profile_id,
            PrincipalType::Phone,
            phone.value.clone(),
            phone.primary,
        ));
        phones.push(phone_contact(
            profile_id,
            &phone.value,
            &phone.r#type,
            phone.primary,
            now,
        )?);
    }

    // department, title → metadata. externalId is the asking source's own
    // identifier of the user (RFC 7643 3.1), not an attribute of the account.
    for (key, value) in [
        // The enterprise extension's employeeNumber (RFC 7643 §4.3).
        ("employee_id", &req.employee_number),
        ("department", &req.department),
        ("title", &req.title),
    ] {
        if !value.is_empty() {
            metadata.push(ProfileMetadata::new(
                profile_id,
                key,
                serde_json::Value::String(value.clone()),
            ));
        }
    }

    Ok(CreateUserMapping {
        profile,
        principals,
        metadata,
        emails,
        phones,
    })
}

/// RFC 7643 §2.4: at most one email and one phone number are primary.
pub fn check_single_primary(
    emails: &[proto::ScimEmail],
    phones: &[proto::ScimPhoneNumber],
) -> Result<(), MappingError> {
    if emails.iter().filter(|e| e.primary).count() > 1 {
        return Err(MappingError::MultiplePrimary("emails"));
    }
    if phones.iter().filter(|p| p.primary).count() > 1 {
        return Err(MappingError::MultiplePrimary("phoneNumbers"));
    }
    Ok(())
}

/// A SCIM email validated as a login handle of the installation the
/// directory provisions into (its own managed accounts, one namespace with
/// every other entry point): its resolution key and the spelling mail goes to.
fn scim_email(email: &proto::ScimEmail) -> Result<sid_authn::email::EmailHandle, MappingError> {
    sid_authn::email::parse(email.value.trim(), &sid_authn::email::EmailPolicy::LOCAL)
        .map_err(|e| MappingError::InvalidEmail(email.value.clone(), e.to_string()))
}

/// The resolution key of `address` in the installation's namespace; `None`
/// when it is no admissible address, so it matches nothing.
pub fn email_key(address: &str) -> Option<String> {
    sid_authn::email::parse(address.trim(), &sid_authn::email::EmailPolicy::LOCAL)
        .ok()
        .map(|handle| handle.key)
}

/// A SCIM email as the account keeps it: the login handle (the
/// installation's principal, keyed under its current email policy revision)
/// and the contact holding the spelling given, the principal naming that
/// contact as the mailbox its login mail goes to.
pub fn email_binding(
    profile_id: ProfileId,
    email: &proto::ScimEmail,
    now: Timestamp,
) -> Result<(Principal, ProfileEmail), MappingError> {
    let handle = scim_email(email)?;
    let contact = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id,
        email: handle.delivery,
        label: scim_email_type_to_label(&email.r#type),
        custom_label: None,
        is_primary: email.primary,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };
    let mut principal =
        corporate_contact(profile_id, PrincipalType::Email, handle.key, email.primary);
    principal.email_policy_revision = Some(handle.revision);
    principal.source_email_id = Some(contact.id);
    Ok((principal, contact))
}

/// The contact record of a SCIM phone number.
pub fn phone_contact(
    profile_id: ProfileId,
    value: &str,
    scim_type: &str,
    primary: bool,
    now: Timestamp,
) -> Result<ProfilePhone, MappingError> {
    Ok(ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id,
        e164: phone_digits(value)?,
        extension: None,
        label: scim_phone_type_to_label(scim_type),
        custom_label: None,
        is_primary: primary,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    })
}

/// The digits of a SCIM phone number. RFC 7643 §4.1.2 recommends RFC 3966
/// form: a `tel:` prefix and visual separators (RFC 3966 §3 `-`, `.`, `(`,
/// `)`, and spaces as written by directories) are dropped; anything else
/// that is not a digit makes the value unreadable.
pub fn phone_digits(value: &str) -> Result<u64, MappingError> {
    let number = value.strip_prefix("tel:").unwrap_or(value);
    let cleaned: String = number
        .chars()
        .filter(|c| !matches!(c, '-' | '.' | '(' | ')' | ' '))
        .collect();
    sid_core::models::registration::parse_e164(&cleaned)
        .map_err(|_| MappingError::InvalidPhone(value.to_string()))
}

/// Where and for whom a user resource is rendered: the organization domain
/// its corporate login ends with, the base address its location is under,
/// and the asking source's own identifier of the user, if it has one.
#[derive(Debug, Clone, Copy)]
pub struct ScimPlace<'a> {
    pub org_domain: &'a str,
    pub base_url: &'a str,
    pub external_id: Option<&'a str>,
    /// SCIM `active` of the user: its directory relationship is active and
    /// its account can be used (`DirectoryResource::shows_active`).
    pub active: bool,
}

/// The SCIM `type` an email contact is served under (RFC 7643 4.1.2). A
/// label SCIM has no word for is served as `other`; a request that restates
/// it compares equal and leaves the stored label as it is.
pub fn email_type(label: &EmailLabel) -> &'static str {
    match label {
        EmailLabel::Work => "work",
        EmailLabel::Personal => "home",
        EmailLabel::School => "school",
        EmailLabel::Other | EmailLabel::Custom => "other",
    }
}

/// The SCIM `type` a phone contact is served under, as [`email_type`].
pub fn phone_type(label: &PhoneLabel) -> &'static str {
    match label {
        PhoneLabel::Work => "work",
        PhoneLabel::Home => "home",
        PhoneLabel::Mobile => "mobile",
        PhoneLabel::Fax => "fax",
        PhoneLabel::Pager => "pager",
        PhoneLabel::Main | PhoneLabel::Other | PhoneLabel::Custom => "other",
    }
}

/// Map SID Profile + Principals + contacts + Metadata + Groups to SCIM
/// User response. `emails` come from the contacts, in the spelling the
/// directory gave: a principal holds only the login key. A phone number is
/// served with the type of its contact in `phones`. `id` is the directory
/// resource's identifier, never the account's.
#[allow(clippy::too_many_arguments)]
pub fn sid_to_scim_user(
    id: DirectoryUserId,
    profile: &Profile,
    principals: &[Principal],
    emails: &[ProfileEmail],
    phones: &[ProfilePhone],
    metadata: &[ProfileMetadata],
    group_memberships: &[(GroupId, String)], // (group_id, group_display_name)
    place: ScimPlace<'_>,
) -> proto::ScimUser {
    let ScimPlace {
        org_domain,
        base_url,
        external_id,
        active,
    } = place;
    let mut user = proto::ScimUser {
        id: id.to_string(),
        display_name: profile.formatted_name().unwrap_or_default(),
        active,
        ..Default::default()
    };

    // Extract userName from federated username principal ({value}#{domain})
    let domain_suffix = format!("#{}", org_domain);
    for principal in principals {
        match principal.principal_type {
            PrincipalType::Username if principal.value.ends_with(&domain_suffix) => {
                // Strip #domain to get userName
                user.user_name = principal.value.trim_end_matches(&domain_suffix).to_string();
            }
            PrincipalType::Phone => {
                // The contact of this number holds its type; a number with
                // no contact is the organization's own.
                let contact = phone_digits(&principal.value)
                    .ok()
                    .and_then(|digits| phones.iter().find(|p| p.e164 == digits));
                user.phone_numbers.push(proto::ScimPhoneNumber {
                    value: principal.value.clone(),
                    r#type: contact.map_or("work", |p| phone_type(&p.label)).into(),
                    primary: principal.is_primary,
                });
            }
            _ => {}
        }
    }
    user.emails = emails
        .iter()
        .map(|e| proto::ScimEmail {
            value: e.email.clone(),
            r#type: email_type(&e.label).into(),
            primary: e.is_primary,
        })
        .collect();

    // Name from Profile fields (structured name components)
    let given = profile.given_name.clone().unwrap_or_default();
    let family = profile.family_name.clone().unwrap_or_default();
    if !given.is_empty() || !family.is_empty() {
        user.name = Some(proto::ScimName {
            given_name: given.clone(),
            family_name: family.clone(),
            middle_name: profile.middle_name.clone().unwrap_or_default(),
            formatted: profile
                .formatted_name()
                .unwrap_or_else(|| format!("{} {}", given, family).trim().to_string()),
            ..Default::default()
        });
    }

    // Metadata fields
    user.external_id = external_id.unwrap_or_default().to_owned();
    user.employee_number = metadata_str(metadata, "employee_id");
    user.department = metadata_str(metadata, "department");
    user.title = metadata_str(metadata, "title");

    // Group refs (read-only)
    for (gid, display) in group_memberships {
        user.groups.push(proto::ScimGroupRef {
            value: gid.to_string(),
            display: display.clone(),
        });
    }

    // Meta
    user.meta = Some(proto::ScimMeta {
        resource_type: "User".into(),
        created: timestamp_to_proto(profile.created_at),
        last_modified: timestamp_to_proto(profile.updated_at),
        location: format!("{}/scim/v2/Users/{}", base_url, id),
        ..Default::default()
    });

    user
}

/// Map SCIM CreateGroup request to SID Group.
pub fn scim_create_group_to_sid(
    req: &proto::ScimCreateGroupRequest,
    project_id: sid_core::models::ProjectId,
) -> Group {
    Group::new(project_id, &req.display_name)
}

/// Map SID Group + Members to SCIM Group response.
pub fn sid_to_scim_group(
    group: &Group,
    members: &[(DirectoryUserId, String)], // (the member's resource id, display name)
    base_url: &str,
) -> proto::ScimGroup {
    proto::ScimGroup {
        id: group.id.to_string(),
        display_name: group.name.clone(),
        members: members
            .iter()
            .map(|(pid, display)| proto::ScimMemberRef {
                value: pid.to_string(),
                display: display.clone(),
            })
            .collect(),
        meta: Some(proto::ScimMeta {
            resource_type: "Group".into(),
            created: timestamp_to_proto(group.created_at),
            last_modified: timestamp_to_proto(group.updated_at),
            location: format!("{}/scim/v2/Groups/{}", base_url, group.id),
            ..Default::default()
        }),
    }
}

/// A contact principal a directory gives an account (never verified by it).
pub fn corporate_contact(
    profile_id: ProfileId,
    principal_type: PrincipalType,
    value: String,
    is_primary: bool,
) -> Principal {
    let now = Timestamp::now();
    // Link Principal to Profile field: email→"email", phone→"phone"
    let source_field = match principal_type {
        PrincipalType::Email => Some("email".to_string()),
        PrincipalType::Phone => Some("phone".to_string()),
        _ => None,
    };
    Principal {
        id: PrincipalId::new(),
        profile_id,
        principal_type,
        value,
        verified: false,
        verified_at: None,
        verification_expires: None,
        assigned_profile_id: None,
        assignment_revision: 0,
        // An email key's revision is set by `email_binding`, which derives it.
        email_policy_revision: None,
        is_primary,
        source_field,
        source_email_id: None,
        source_phone_id: None,
        created_at: now,
        updated_at: now,
    }
}

// ── Helpers ──

/// Map SCIM email type string to EmailLabel.
fn scim_email_type_to_label(scim_type: &str) -> EmailLabel {
    match scim_type {
        "work" => EmailLabel::Work,
        "home" | "personal" => EmailLabel::Personal,
        "school" => EmailLabel::School,
        "other" => EmailLabel::Other,
        _ => EmailLabel::Work, // SCIM default for corporate provisioning
    }
}

/// Map SCIM phone type string to PhoneLabel.
fn scim_phone_type_to_label(scim_type: &str) -> PhoneLabel {
    match scim_type {
        "work" => PhoneLabel::Work,
        "home" => PhoneLabel::Home,
        "mobile" => PhoneLabel::Mobile,
        "fax" => PhoneLabel::Fax,
        "pager" => PhoneLabel::Pager,
        "other" => PhoneLabel::Other,
        _ => PhoneLabel::Work,
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn metadata_str(metadata: &[ProfileMetadata], key: &str) -> String {
    metadata
        .iter()
        .find(|m| m.key == key)
        .and_then(|m| m.value.as_str())
        .unwrap_or("")
        .to_string()
}

fn timestamp_to_proto(dt: Timestamp) -> Option<prost_types::Timestamp> {
    Some(sid_proto::time::to_proto(dt))
}

// ── Extension traits for SID models (corporate profile creation) ──

trait ProfileExt {
    fn new_corporate(
        id: ProfileId,
        given_name: Option<String>,
        family_name: Option<String>,
        middle_name: Option<String>,
        now: Timestamp,
    ) -> Profile;
}

impl ProfileExt for Profile {
    fn new_corporate(
        id: ProfileId,
        given_name: Option<String>,
        family_name: Option<String>,
        middle_name: Option<String>,
        now: Timestamp,
    ) -> Profile {
        Profile {
            id,
            profile_type: ProfileType::Corporate,
            username: Some(id.to_string()), // corporate profiles use profileId as placeholder when no username provided
            given_name,
            family_name,
            middle_name,
            honorific_prefix: None,
            honorific_suffix: None,
            roles: vec![],
            status: ProfileStatus::Provisioned,
            max_assurance: sid_core::models::ProfileAssurance::Anonymous,
            visibility: ProfileVisibility::Private,
            manager_id: None,
            migration_pending: false,
            migration_started_at: None,
            migration_completed_at: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        }
    }
}

/// The organization's login of `profile_id` for SCIM `userName`:
/// `{userName}#{domain}`, the one form a create and a rename assign.
pub fn organization_login(profile_id: ProfileId, user_name: &str, org_domain: &str) -> Principal {
    let value = format!("{user_name}#{org_domain}");
    let mut login = corporate_contact(profile_id, PrincipalType::Username, value, true);
    login.source_field = None;
    login
}

#[cfg(test)]
mod tests;
