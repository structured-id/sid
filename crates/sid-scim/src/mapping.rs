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

use chrono::{DateTime, Utc};
use sid_core::models::{
    Group, GroupId, Principal, PrincipalId, PrincipalType, Profile, ProfileEmail, ProfileEmailId,
    ProfileId, ProfileMetadata, ProfilePhone, ProfilePhoneId, ProfileStatus, ProfileType,
    ProfileVisibility, profile_email::EmailLabel, profile_phone::PhoneLabel,
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
            project_id: sid_core::models::ProjectId::system(),
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
    let now = Utc::now();

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
        let corporate_login = format!("{}#{}", req.user_name, ctx.org_domain);
        principals.push(Principal::new_corporate_login(profile_id, corporate_login));
    }

    let mut emails = Vec::new();
    let mut phones = Vec::new();

    // emails → Principal(Email) + ProfileEmail
    for email in req.emails.iter().filter(|e| !e.value.is_empty()) {
        principals.push(email_principal(profile_id, email)?);
        emails.push(email_contact(profile_id, email, now)?);
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

    // externalId, department, title → metadata
    for (key, value) in [
        ("employee_id", &req.external_id),
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

/// The login handle of a SCIM email: the installation's principal, keyed
/// under its current email policy revision.
pub fn email_principal(
    profile_id: ProfileId,
    email: &proto::ScimEmail,
) -> Result<Principal, MappingError> {
    let handle = scim_email(email)?;
    let mut principal =
        corporate_contact(profile_id, PrincipalType::Email, handle.key, email.primary);
    principal.email_policy_revision = Some(handle.revision);
    Ok(principal)
}

/// The contact record of a SCIM email, keeping the spelling given.
pub fn email_contact(
    profile_id: ProfileId,
    email: &proto::ScimEmail,
    now: DateTime<Utc>,
) -> Result<ProfileEmail, MappingError> {
    Ok(ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id,
        email: scim_email(email)?.delivery,
        label: scim_email_type_to_label(&email.r#type),
        custom_label: None,
        is_primary: email.primary,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    })
}

/// The contact record of a SCIM phone number.
pub fn phone_contact(
    profile_id: ProfileId,
    value: &str,
    scim_type: &str,
    primary: bool,
    now: DateTime<Utc>,
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

/// Map SID Profile + Principals + email contacts + Metadata + Groups to SCIM
/// User response. `emails` come from the contacts, in the spelling the
/// directory gave: a principal holds only the login key.
pub fn sid_to_scim_user(
    profile: &Profile,
    principals: &[Principal],
    emails: &[ProfileEmail],
    metadata: &[ProfileMetadata],
    group_memberships: &[(GroupId, String)], // (group_id, group_display_name)
    org_domain: &str,
    base_url: &str,
) -> proto::ScimUser {
    let mut user = proto::ScimUser {
        id: profile.id.to_string(),
        display_name: profile.formatted_name().unwrap_or_default(),
        active: !matches!(profile.status, ProfileStatus::Suspended),
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
                user.phone_numbers.push(proto::ScimPhoneNumber {
                    value: principal.value.clone(),
                    r#type: "work".into(),
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
            r#type: "work".into(),
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
    user.external_id = metadata_str(metadata, "employee_id");
    user.department = metadata_str(metadata, "department");
    user.title = metadata_str(metadata, "title");

    // Group refs (read-only)
    for (gid, display) in group_memberships {
        user.groups.push(proto::ScimGroupRef {
            value: gid.0.to_string(),
            display: display.clone(),
        });
    }

    // Meta
    user.meta = Some(proto::ScimMeta {
        resource_type: "User".into(),
        created: timestamp_to_proto(profile.created_at),
        last_modified: timestamp_to_proto(profile.updated_at),
        location: format!("{}/scim/v2/Users/{}", base_url, profile.id),
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
    members: &[(ProfileId, String)], // (profile_id, display_name)
    base_url: &str,
) -> proto::ScimGroup {
    proto::ScimGroup {
        id: group.id.0.to_string(),
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
            location: format!("{}/scim/v2/Groups/{}", base_url, group.id.0),
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
    let now = Utc::now();
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
        // An email key's revision is set by `email_principal`, which derives it.
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

fn timestamp_to_proto(dt: DateTime<Utc>) -> Option<prost_types::Timestamp> {
    Some(prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

// ── Extension traits for SID models (corporate profile creation) ──

trait ProfileExt {
    fn new_corporate(
        id: ProfileId,
        given_name: Option<String>,
        family_name: Option<String>,
        middle_name: Option<String>,
        now: DateTime<Utc>,
    ) -> Profile;
}

impl ProfileExt for Profile {
    fn new_corporate(
        id: ProfileId,
        given_name: Option<String>,
        family_name: Option<String>,
        middle_name: Option<String>,
        now: DateTime<Utc>,
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

trait PrincipalExt {
    /// Create a corporate login principal (Username, verified=false).
    fn new_corporate_login(profile_id: ProfileId, value: String) -> Principal;
}

impl PrincipalExt for Principal {
    fn new_corporate_login(profile_id: ProfileId, value: String) -> Principal {
        let mut login = corporate_contact(profile_id, PrincipalType::Username, value, true);
        login.source_field = None;
        login
    }
}

#[cfg(test)]
mod tests;
