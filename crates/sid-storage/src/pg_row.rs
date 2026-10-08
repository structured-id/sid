// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL row types for sqlx `FromRow` deserialization.
//!
//! Each struct maps 1:1 to a PostgreSQL table, using native PG types
//! (UUID, TIMESTAMPTZ, BOOL, BYTEA, JSONB). Conversion to domain types
//! is done via `into_domain()` methods.
//!
//! These types replace SeaORM entity `Model` structs for query results.
//!
//! Identifier columns decode straight into the validated id types, so a row
//! holding a malformed id fails at the decode step, not somewhere downstream.

#![allow(dead_code)] // Structs will be used incrementally as methods migrate

use chrono::{DateTime, Utc};
use secrecy::SecretBox;
use uuid::Uuid;

use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::EncryptedField;

use sid_core::models::{
    self, AssignmentProvenance, AuthorizationCode, CedarPolicy, CedarPolicyId, ClosureMode,
    ClosureRequest, Credential, CredentialData, CredentialId, Device as CoreDevice,
    DeviceAuthCodeId, DeviceAuthorizationCode as CoreDeviceAuth, DeviceId as CoreDeviceId,
    EmailLabel, ExportJob, ExportStatus, Group, GroupId, GroupMember, ImpersonationGrant,
    InitialAccessToken, InitialAccessTokenId, MachineRestrictions, MachineUser,
    MachineUserCredential, MachineUserId, MachineUserStatus, MagicLinkSession, OAuth2Client,
    OutboundDlqEntry, PatId, PatStatus, PersonalAccessToken, PhoneLabel, Principal,
    PrincipalBinding, PrincipalBindingId, PrincipalEntity, PrincipalId, PrincipalType, Profile,
    ProfileEmail, ProfileEmailId, ProfileGrant, ProfileGrantId, ProfileId, ProfileMetadata,
    ProfilePhone, ProfilePhoneId, Project, ProjectId, RefreshToken, Role, RoleAssignment,
    RoleAssignmentId, RoleAssignmentPrincipal, RoleId, ScimOutboundRecord, ScimOutboundTarget,
    ScimOutboundTargetId, Session, SessionId, SodConflictRule, UpstreamIdentity,
    UpstreamIdentityId, UpstreamProvider, UpstreamProviderId,
    credential::CredentialStatus as CoreCredentialStatus,
    device::DeviceAssurance,
    device_attestation::{DeviceAttestation, DeviceAttestationId},
    invite::InviteId,
    session::AuthLevel,
};

// ─── Helper: parse whitespace-separated strings ───

fn split_ws(s: &str) -> Vec<String> {
    s.split_whitespace()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Parse a stored text value through the type's `FromStr`; an unknown value
/// is an error, never a default.
fn parsed<T>(column: &str, value: &str) -> SidResult<T>
where
    T: std::str::FromStr<Err = String>,
{
    value
        .parse()
        .map_err(|e: String| SidError::Storage(format!("column {column}: {e}")))
}

/// A stored count that must fit the domain type.
fn count<T: TryFrom<i64>>(column: &str, value: i64) -> SidResult<T> {
    T::try_from(value).map_err(|_| SidError::Storage(format!("column {column}: bad count {value}")))
}

// ═══════════════════════════════════════════════════════════════════
// Profile
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ProfileRow {
    pub id: ProfileId,
    pub profile_type: String,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub honorific_prefix: Option<String>,
    pub honorific_suffix: Option<String>,
    pub roles: String,
    pub status: String,
    pub visibility: String,
    pub max_assurance: String,
    pub manager_id: Option<ProfileId>,
    pub migration_pending: bool,
    pub migration_started_at: Option<DateTime<Utc>>,
    pub migration_completed_at: Option<DateTime<Utc>>,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfileRow {
    /// An unknown type, status, assurance or visibility is an error: reading
    /// an unknown status as active would reopen a closed or suspended account.
    pub fn into_domain(self) -> sid_core::Result<Profile> {
        let stored = |e: String| sid_core::Error::Storage(format!("profile {}: {e}", self.id));
        Ok(Profile {
            id: self.id,
            profile_type: self.profile_type.parse().map_err(stored)?,
            username: self.username,
            given_name: self.given_name,
            family_name: self.family_name,
            middle_name: self.middle_name,
            honorific_prefix: self.honorific_prefix,
            honorific_suffix: self.honorific_suffix,
            roles: split_ws(&self.roles),
            status: self.status.parse().map_err(stored)?,
            max_assurance: self.max_assurance.parse().map_err(stored)?,
            visibility: self.visibility.parse().map_err(stored)?,
            manager_id: self.manager_id,
            migration_pending: self.migration_pending,
            migration_started_at: self.migration_started_at,
            migration_completed_at: self.migration_completed_at,
            revision: u64::try_from(self.revision).map_err(|e| stored(format!("revision: {e}")))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// ProfilePhone (DB table: profile_phones)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ProfilePhoneRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub e164: i64,
    pub extension: Option<i32>,
    pub label: String,
    pub custom_label: Option<String>,
    pub is_primary: bool,
    pub can_receive_sms: bool,
    pub can_receive_fax: bool,
    pub can_receive_voice: bool,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfilePhoneRow {
    pub fn into_domain(self) -> ProfilePhone {
        ProfilePhone {
            id: ProfilePhoneId(self.id),
            profile_id: self.profile_id,
            e164: self.e164 as u64,
            extension: self.extension.map(|e| e as u32),
            label: PhoneLabel::from_str_lossy(&self.label),
            custom_label: self.custom_label,
            is_primary: self.is_primary,
            can_receive_sms: self.can_receive_sms,
            can_receive_fax: self.can_receive_fax,
            can_receive_voice: self.can_receive_voice,
            verified: self.verified,
            verified_at: self.verified_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ProfileEmail (DB table: profile_emails)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ProfileEmailRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub email: String,
    pub label: String,
    pub custom_label: Option<String>,
    pub is_primary: bool,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfileEmailRow {
    pub fn into_domain(self) -> ProfileEmail {
        ProfileEmail {
            id: ProfileEmailId(self.id),
            profile_id: self.profile_id,
            email: self.email,
            label: EmailLabel::from_str_lossy(&self.label),
            custom_label: self.custom_label,
            is_primary: self.is_primary,
            verified: self.verified,
            verified_at: self.verified_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Principal (DB table: principals)
// ═══════════════════════════════════════════════════════════════════

/// Row from the `principals` table alone (entity-only queries).
#[derive(Debug, sqlx::FromRow)]
pub struct PrincipalEntityRow {
    pub id: Uuid,
    pub principal_type: String,
    pub value: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verification_expires: Option<DateTime<Utc>>,
    pub assigned_profile_id: Option<ProfileId>,
    pub assignment_revision: i64,
    pub email_policy_revision: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PrincipalEntityRow {
    pub fn into_domain(self) -> SidResult<PrincipalEntity> {
        Ok(PrincipalEntity {
            id: PrincipalId(self.id),
            principal_type: parse_principal_type(&self.principal_type)?,
            value: self.value,
            verified: self.verified,
            verified_at: self.verified_at,
            verification_expires: self.verification_expires,
            assigned_profile_id: self.assigned_profile_id,
            assignment_revision: self.assignment_revision,
            email_policy_revision: self.email_policy_revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Row from `principals JOIN principal_bindings` query.
/// Combines entity fields (from principals) with binding fields (from principal_bindings).
#[derive(Debug, sqlx::FromRow)]
pub struct PrincipalRow {
    // ── Principal entity fields ──
    pub id: Uuid,
    pub principal_type: String,
    pub value: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verification_expires: Option<DateTime<Utc>>,
    pub assigned_profile_id: Option<ProfileId>,
    pub assignment_revision: i64,
    pub email_policy_revision: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // ── Binding fields (from JOIN) ──
    pub binding_id: Uuid,
    pub profile_id: ProfileId,
    pub is_primary: bool,
    pub source_field: Option<String>,
    pub source_email_id: Option<Uuid>,
    pub source_phone_id: Option<Uuid>,
}

fn parse_principal_type(s: &str) -> SidResult<PrincipalType> {
    s.parse()
        .map_err(|e| SidError::Storage(format!("principal: {e}")))
}

impl PrincipalRow {
    /// The principal as its claiming Profile sees it (proof only for the holder).
    pub fn into_domain(self) -> SidResult<Principal> {
        let principal = Principal {
            id: PrincipalId(self.id),
            profile_id: self.profile_id,
            principal_type: parse_principal_type(&self.principal_type)?,
            value: self.value,
            verified: self.verified,
            verified_at: self.verified_at,
            verification_expires: self.verification_expires,
            assigned_profile_id: self.assigned_profile_id,
            assignment_revision: self.assignment_revision,
            email_policy_revision: self.email_policy_revision,
            is_primary: self.is_primary,
            source_field: self.source_field,
            source_email_id: self.source_email_id.map(ProfileEmailId),
            source_phone_id: self.source_phone_id.map(ProfilePhoneId),
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        Ok(principal.as_seen_by_subject())
    }
}

/// Row from `principal_bindings` table only (used for binding-specific queries).
#[derive(Debug, sqlx::FromRow)]
pub struct PrincipalBindingRow {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub profile_id: ProfileId,
    pub is_primary: bool,
    pub source_field: Option<String>,
    pub source_email_id: Option<Uuid>,
    pub source_phone_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl PrincipalBindingRow {
    pub fn into_domain(self) -> SidResult<PrincipalBinding> {
        Ok(PrincipalBinding {
            id: PrincipalBindingId(self.id),
            principal_id: PrincipalId(self.principal_id),
            profile_id: self.profile_id,
            is_primary: self.is_primary,
            source_field: self.source_field,
            source_email_id: self.source_email_id.map(ProfileEmailId),
            source_phone_id: self.source_phone_id.map(ProfilePhoneId),
            created_at: self.created_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Credential
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub credential_type: String,
    pub status: String,
    pub data: Vec<u8>,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub policy_version: Option<i32>,
    pub zkpp_verified: bool,
    pub opaque_curve: Option<i16>,
    pub opaque_credential_identifier: Option<Vec<u8>>,
    pub legacy_algorithm: Option<String>,
}

impl CredentialRow {
    /// A row whose type or status is not one this build knows is refused: read
    /// as a default it would sign in as a password or stay active after revocation.
    pub fn into_domain(self) -> SidResult<Credential> {
        let opaque_credential_identifier = self
            .opaque_credential_identifier
            .map(|bytes| {
                <[u8; 16]>::try_from(bytes).map_err(|_| {
                    SidError::Storage("column opaque_credential_identifier: not 16 bytes".into())
                })
            })
            .transpose()?;
        Ok(Credential {
            id: CredentialId(self.id),
            profile_id: self.profile_id,
            credential_type: self.credential_type.parse().map_err(SidError::Storage)?,
            status: self
                .status
                .parse::<CoreCredentialStatus>()
                .map_err(SidError::Storage)?,
            data: CredentialData::from(self.data),
            label: self.label,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            policy_version: self.policy_version.map(|v| v as u32),
            zkpp_verified: self.zkpp_verified,
            opaque_curve: self.opaque_curve.map(|v| v as u8),
            opaque_credential_identifier,
            legacy_algorithm: self.legacy_algorithm,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Session
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct SessionRow {
    pub id: SessionId,
    pub profile_id: ProfileId,
    pub client_id: Option<String>,
    pub device_id: Option<Uuid>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub scopes: String,
    pub assurance_level: String,
    pub elevation_level: Option<String>,
    pub elevation_until: Option<DateTime<Utc>>,
    pub authenticated_at: DateTime<Utc>,
    pub amr: String,
    pub is_provisional: bool,
    pub passkey_prompt: bool,
    pub policy_grace: bool,
    pub grace_deadline: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub browser_secret_hash: Option<Vec<u8>>,
    pub authenticated_by: Option<SessionId>,
}

/// A stored assurance level; an unknown one is an error, never `Basic`.
fn auth_level(column: &str, value: &str) -> SidResult<AuthLevel> {
    AuthLevel::from_acr_value(value)
        .ok_or_else(|| SidError::Storage(format!("column {column}: unknown level {value}")))
}

/// A stored step-up: its level and the time it lapses, both or neither.
fn elevation(
    level: Option<String>,
    until: Option<DateTime<Utc>>,
) -> SidResult<Option<sid_core::models::session::Elevation>> {
    match (level, until) {
        (Some(level), Some(until)) => Ok(Some(sid_core::models::session::Elevation {
            level: auth_level("elevation_level", &level)?,
            until,
        })),
        (None, None) => Ok(None),
        _ => Err(SidError::Storage(
            "elevation level and time must be stored together".into(),
        )),
    }
}

impl SessionRow {
    pub fn into_domain(self) -> SidResult<Session> {
        let elevation = elevation(self.elevation_level, self.elevation_until)?;
        Ok(Session {
            id: self.id,
            profile_id: self.profile_id,
            client_id: self.client_id,
            device_id: self.device_id,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            scopes: Session::parse_scopes(&self.scopes),
            assurance_level: auth_level("assurance_level", &self.assurance_level)?,
            elevation,
            authenticated_at: self.authenticated_at,
            amr: split_ws(&self.amr),
            is_provisional: self.is_provisional,
            passkey_prompt: self.passkey_prompt,
            policy_grace: self.policy_grace,
            grace_deadline: self.grace_deadline,
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_activity_at: self.last_activity_at,
            browser_secret_hash: self
                .browser_secret_hash
                .as_deref()
                .map(sid_core::models::BrowserSecretHash::try_from)
                .transpose()?,
            authenticated_by: self.authenticated_by,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Project
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ProjectRow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub owner_id: Option<ProfileId>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProjectRow {
    pub fn into_domain(self) -> Project {
        Project {
            id: ProjectId(self.id),
            name: self.name,
            description: self.description,
            owner_id: self.owner_id,
            is_system: self.is_system,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2Client
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct OAuth2ClientRow {
    pub client_id: String,
    pub project_id: Uuid,
    pub application_id: sid_core::models::ApplicationId,
    pub default_resource: Option<sid_core::models::ResourceId>,
    pub application_type: String,
    pub client_secret_hash: Option<Vec<u8>>,
    pub jwks: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: String,
    pub grant_types: String,
    pub client_name: String,
    pub logo_uri: Option<String>,
    pub active: bool,
    pub required_acr: Option<String>,
    pub required_amr: String,
    pub enforcement_mode: String,
    pub min_device_assurance: Option<String>,
    pub require_verified_email: Option<bool>,
    pub require_verified_phone: Option<bool>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    pub post_logout_redirect_uris: Vec<String>,
    pub claim_mappings: Option<String>,
    pub login_strategy: String,
    pub show_federation_button: bool,
    pub federation_timeout_ms: i32,
    pub unified_input: bool,
    pub subject_type: String,
    pub sector_identifier_uri: Option<String>,
    pub token_endpoint_auth_method: String,
    pub response_types: String,
    pub contacts: Vec<String>,
    pub registration_iat: Option<Uuid>,
    pub registration_access_token_hash: Option<Vec<u8>>,
    pub org_id: Option<sid_core::models::OrgId>,
    pub client_id_issued_at: DateTime<Utc>,
    pub client_secret_expires_at: Option<DateTime<Utc>>,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
}

impl OAuth2ClientRow {
    /// Unknown stored settings are errors, never a default: an unknown
    /// subject type is not read as public, an unknown mode not as audit.
    pub fn into_domain(self) -> SidResult<OAuth2Client> {
        let parse = |column: &str, e: String| SidError::Storage(format!("column {column}: {e}"));
        Ok(OAuth2Client {
            client_id: self.client_id,
            project_id: ProjectId(self.project_id),
            application_id: self.application_id,
            default_resource: self.default_resource,
            application_type: self
                .application_type
                .parse()
                .map_err(|e| parse("application_type", e))?,
            client_secret_hash: self.client_secret_hash,
            jwks: self
                .jwks
                .as_deref()
                .map(sid_core::models::ClientKeySet::from_json)
                .transpose()
                .map_err(|e| parse("jwks", e))?,
            redirect_uris: self.redirect_uris,
            allowed_scopes: split_ws(&self.allowed_scopes),
            grant_types: split_ws(&self.grant_types),
            client_name: self.client_name,
            logo_uri: self.logo_uri,
            active: self.active,
            token_endpoint_auth_method: self
                .token_endpoint_auth_method
                .parse()
                .map_err(|e| parse("token_endpoint_auth_method", e))?,
            response_types: split_ws(&self.response_types),
            subject_type: self
                .subject_type
                .parse()
                .map_err(|e| parse("subject_type", e))?,
            sector_identifier_uri: self.sector_identifier_uri,
            contacts: self.contacts,
            client_id_issued_at: self.client_id_issued_at,
            client_secret_expires_at: self.client_secret_expires_at,
            registration_iat: self
                .registration_iat
                .map(sid_core::models::InitialAccessTokenId),
            registration_access_token_hash: self.registration_access_token_hash,
            required_acr: self
                .required_acr
                .as_deref()
                .map(|s| {
                    AuthLevel::from_acr_value(s)
                        .ok_or_else(|| parse("required_acr", format!("unknown level {s:?}")))
                })
                .transpose()?,
            required_amr: split_ws(&self.required_amr),
            enforcement_mode: self
                .enforcement_mode
                .parse()
                .map_err(|e| parse("enforcement_mode", e))?,
            min_device_assurance: self
                .min_device_assurance
                .as_deref()
                .map(str::parse::<DeviceAssurance>)
                .transpose()
                .map_err(|e| parse("min_device_assurance", e))?,
            require_verified_email: self.require_verified_email,
            require_verified_phone: self.require_verified_phone,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            claim_mappings: self
                .claim_mappings
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| parse("claim_mappings", e.to_string()))?
                .unwrap_or_default(),
            login_strategy: self
                .login_strategy
                .parse()
                .map_err(|e| parse("login_strategy", e))?,
            show_federation_button: self.show_federation_button,
            federation_timeout_ms: u32::try_from(self.federation_timeout_ms)
                .map_err(|e| parse("federation_timeout_ms", e.to_string()))?,
            unified_input: self.unified_input,
            org_id: self.org_id,
            revision: u64::try_from(self.revision).map_err(|e| parse("revision", e.to_string()))?,
            created_at: self.created_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Applications, protected resources, resource access
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ApplicationRow {
    pub id: sid_core::models::ApplicationId,
    pub project_id: Uuid,
    pub name: String,
    pub system_integration: Option<String>,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApplicationRow {
    pub fn into_domain(self) -> SidResult<sid_core::models::Application> {
        Ok(sid_core::models::Application {
            id: self.id,
            project_id: ProjectId(self.project_id),
            name: self.name,
            system: self
                .system_integration
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|e: String| {
                    SidError::Storage(format!("column system_integration: {e}"))
                })?,
            revision: u64::try_from(self.revision)
                .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct ProtectedResourceRow {
    pub id: sid_core::models::ResourceId,
    pub application_id: Option<sid_core::models::ApplicationId>,
    pub issuer_id: sid_core::models::IssuerId,
    pub indicator: String,
    pub scopes: String,
    pub state: String,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProtectedResourceRow {
    /// A stored indicator or state that no longer parses is an error, never
    /// a default.
    pub fn into_domain(self) -> SidResult<sid_core::models::ProtectedResource> {
        let parse = |column: &str, e: String| SidError::Storage(format!("column {column}: {e}"));
        Ok(sid_core::models::ProtectedResource {
            id: self.id,
            application_id: self.application_id,
            issuer_id: self.issuer_id,
            indicator: sid_core::models::ResourceIndicator::parse(&self.indicator)
                .map_err(|e| parse("indicator", e))?,
            scopes: split_ws(&self.scopes),
            state: self.state.parse().map_err(|e| parse("state", e))?,
            revision: u64::try_from(self.revision).map_err(|e| parse("revision", e.to_string()))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct ResourceAccessRow {
    pub client_id: String,
    pub resource_id: sid_core::models::ResourceId,
    pub scopes: String,
    pub created_at: DateTime<Utc>,
}

impl ResourceAccessRow {
    pub fn into_domain(self) -> sid_core::models::ResourceAccess {
        sid_core::models::ResourceAccess {
            client_id: self.client_id,
            resource_id: self.resource_id,
            scopes: split_ws(&self.scopes),
            created_at: self.created_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// RefreshToken
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub session_id: SessionId,
    pub profile_id: ProfileId,
    pub client_id: String,
    pub scopes: String,
    pub resource_id: sid_core::models::ResourceId,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    pub replaced_by: Option<Uuid>,
    pub family_id: Uuid,
    pub grace_expires_at: Option<DateTime<Utc>>,
    pub dpop_jkt: Option<String>,
}

impl RefreshTokenRow {
    pub fn into_domain(self) -> RefreshToken {
        RefreshToken {
            id: self.id,
            token_hash: self.token_hash,
            session_id: self.session_id,
            profile_id: self.profile_id,
            client_id: self.client_id,
            scopes: split_ws(&self.scopes),
            resource: self.resource_id,
            expires_at: self.expires_at,
            created_at: self.created_at,
            revoked: self.revoked,
            replaced_by: self.replaced_by,
            family_id: self.family_id,
            grace_expires_at: self.grace_expires_at,
            dpop_jkt: self.dpop_jkt,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// AuthorizationCode
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct AuthCodeRow {
    pub code_hash: Vec<u8>,
    pub profile_id: ProfileId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub resource_id: sid_core::models::ResourceId,
    pub code_challenge: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
    pub session_id: Option<SessionId>,
    pub authorizing_session_id: SessionId,
    pub authenticated_at: DateTime<Utc>,
    pub amr: String,
    pub assurance_level: String,
    pub elevation_level: Option<String>,
    pub elevation_until: Option<DateTime<Utc>>,
}

impl AuthCodeRow {
    pub fn into_domain(self) -> SidResult<AuthorizationCode> {
        Ok(AuthorizationCode {
            code_hash: self.code_hash,
            profile_id: self.profile_id,
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scopes: split_ws(&self.scopes),
            resource: self.resource_id,
            code_challenge: self.code_challenge,
            nonce: self.nonce,
            authentication: sid_core::models::GrantAuthentication {
                session: self.authorizing_session_id,
                authenticated_at: self.authenticated_at,
                amr: split_ws(&self.amr),
                assurance_level: auth_level("assurance_level", &self.assurance_level)?,
                elevation: elevation(self.elevation_level, self.elevation_until)?,
            },
            expires_at: self.expires_at,
            created_at: self.created_at,
            used: self.used,
            session_id: self.session_id,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Role
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct RoleRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub group_label: Option<String>,
    pub permissions: String,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RoleRow {
    pub fn into_domain(self) -> sid_core::Result<Role> {
        Ok(Role {
            id: RoleId(self.id),
            project_id: ProjectId(self.project_id),
            key: self.key,
            name: self.name,
            description: self.description,
            group: self.group_label,
            permissions: Role::parse_permissions(&self.permissions),
            revision: u64::try_from(self.revision)
                .map_err(|e| sid_core::Error::Storage(format!("role {} revision: {e}", self.id)))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Group
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub parent_group_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl GroupRow {
    pub fn into_domain(self) -> Group {
        Group {
            id: GroupId(self.id),
            project_id: ProjectId(self.project_id),
            name: self.name,
            description: self.description,
            parent_group_id: self.parent_group_id.map(GroupId),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// GroupMember
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct GroupMemberRow {
    pub group_id: Uuid,
    pub profile_id: ProfileId,
    pub added_at: DateTime<Utc>,
}

impl GroupMemberRow {
    pub fn into_domain(self) -> GroupMember {
        GroupMember {
            group_id: GroupId(self.group_id),
            profile_id: self.profile_id,
            added_at: self.added_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// RoleAssignment
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct RoleAssignmentRow {
    pub id: Uuid,
    pub profile_id: Option<ProfileId>,
    pub group_id: Option<Uuid>,
    pub machine_user_id: Option<MachineUserId>,
    pub oauth_client_id: Option<String>,
    pub provisioning_connector_id: Option<sid_core::models::ProvisioningConnectorId>,
    pub role_id: Uuid,
    pub scope: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub granted_by: Option<String>,
    pub basis_assignment_id: Option<Uuid>,
    pub depends_on_assignment_id: Option<Uuid>,
    pub revision: i64,
}

impl RoleAssignmentRow {
    /// Exactly one principal column is set (`chk_principal` in the schema);
    /// a row breaking that is reported, not patched over.
    pub fn into_domain(self) -> SidResult<RoleAssignment> {
        let principal = if let Some(pid) = self.profile_id {
            RoleAssignmentPrincipal::Profile(pid)
        } else if let Some(gid) = self.group_id {
            RoleAssignmentPrincipal::Group(GroupId(gid))
        } else if let Some(mid) = self.machine_user_id {
            RoleAssignmentPrincipal::MachineUser(mid)
        } else if let Some(client_id) = self.oauth_client_id {
            RoleAssignmentPrincipal::OAuthClient(client_id)
        } else if let Some(connector) = self.provisioning_connector_id {
            RoleAssignmentPrincipal::ProvisioningConnector(connector)
        } else {
            return Err(SidError::Storage(format!(
                "role_assignment {} has no principal",
                self.id
            )));
        };

        Ok(RoleAssignment {
            id: RoleAssignmentId(self.id),
            principal,
            role_id: RoleId(self.role_id),
            scope: self.scope,
            expires_at: self.expires_at,
            created_at: self.created_at,
            // The envelope lives in its own tables; the store attaches it.
            admin: None,
            provenance: self.granted_by.map(|granted_by| AssignmentProvenance {
                granted_by,
                basis: self.basis_assignment_id.map(RoleAssignmentId),
                depends_on: self.depends_on_assignment_id.map(RoleAssignmentId),
                // The ceiling lives in its own table; the store attaches it.
                ceiling: None,
            }),
            revision: u64::try_from(self.revision).map_err(|_| {
                SidError::Storage(format!(
                    "role_assignment {} has a negative revision",
                    self.id
                ))
            })?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// CedarPolicy
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct CedarPolicyRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_text: String,
    pub effect: String,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CedarPolicyRow {
    /// An unknown effect is an error: read as permit, a forbid policy would
    /// grant what it was written to deny.
    pub fn into_domain(self) -> SidResult<CedarPolicy> {
        Ok(CedarPolicy {
            id: CedarPolicyId(self.id),
            project_id: ProjectId(self.project_id),
            name: self.name,
            description: self.description,
            policy_text: self.policy_text,
            effect: parsed("effect", &self.effect)?,
            enabled: self.enabled,
            revision: count("revision", self.revision)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// ProfileMetadata
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ProfileMetadataRow {
    pub profile_id: ProfileId,
    pub key: String,
    pub value: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfileMetadataRow {
    pub fn into_domain(self) -> ProfileMetadata {
        ProfileMetadata {
            profile_id: self.profile_id,
            key: self.key,
            value: self.value,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ProfileGrant
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ProfileGrantRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub profile_id: ProfileId,
    pub role_keys: String,
    pub granted_by: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfileGrantRow {
    pub fn into_domain(self) -> ProfileGrant {
        ProfileGrant {
            id: ProfileGrantId(self.id),
            project_id: ProjectId(self.project_id),
            profile_id: self.profile_id,
            // Written space-separated, like role permissions.
            role_keys: split_ws(&self.role_keys),
            granted_by: self.granted_by,
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Device
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: CoreDeviceId,
    pub profile_id: ProfileId,
    pub display_name: Option<String>,
    pub device_type: String,
    pub os_info: Option<String>,
    pub assurance: String,
    pub trusted: bool,
    pub hardware_attested: bool,
    pub fingerprint_hash: Option<String>,
    pub last_ip_geo: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl DeviceRow {
    pub fn into_domain(self) -> sid_core::Result<CoreDevice> {
        let stored = |e: String| sid_core::Error::Storage(format!("device {}: {e}", self.id));
        Ok(CoreDevice {
            id: self.id,
            profile_id: self.profile_id,
            display_name: self.display_name,
            device_type: self.device_type.parse().map_err(stored)?,
            os_info: self.os_info,
            assurance: self.assurance.parse().map_err(stored)?,
            trusted: self.trusted,
            hardware_attested: self.hardware_attested,
            fingerprint_hash: self.fingerprint_hash,
            last_ip_geo: self.last_ip_geo,
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// DeviceAttestation
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceAttestationRow {
    pub id: Uuid,
    pub device_id: CoreDeviceId,
    pub profile_id: ProfileId,
    pub format: String,
    pub key_storage: String,
    pub status: String,
    pub device_public_key: Vec<u8>,
    pub attestation_object: Option<Vec<u8>>,
    pub attestation_certificate: Option<Vec<u8>>,
    pub aaguid: Option<String>,
    pub credential_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl DeviceAttestationRow {
    pub fn into_domain(self) -> SidResult<DeviceAttestation> {
        Ok(DeviceAttestation {
            id: DeviceAttestationId(self.id),
            device_id: self.device_id,
            profile_id: self.profile_id,
            format: self.format.parse().map_err(SidError::Storage)?,
            key_storage: self.key_storage.parse().map_err(SidError::Storage)?,
            status: self.status.parse().map_err(SidError::Storage)?,
            device_public_key: self.device_public_key,
            attestation_object: self.attestation_object,
            attestation_certificate: self.attestation_certificate,
            aaguid: self.aaguid,
            credential_id: self.credential_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            revoked_at: self.revoked_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// DeviceAuthorizationCode
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceAuthRow {
    pub id: Uuid,
    pub client_id: String,
    pub device_code_hash: Vec<u8>,
    pub user_code: String,
    pub scope: Option<String>,
    pub resource_id: sid_core::models::ResourceId,
    pub status: String,
    pub authorized_by: Option<ProfileId>,
    pub project_id: Uuid,
    pub interval_secs: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authorized_at: Option<DateTime<Utc>>,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub redeemed_session_id: Option<SessionId>,
}

impl DeviceAuthRow {
    /// An unknown status is an error, never a pending request.
    pub fn into_domain(self) -> SidResult<CoreDeviceAuth> {
        Ok(CoreDeviceAuth {
            id: DeviceAuthCodeId(self.id),
            client_id: self.client_id,
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            scope: self.scope,
            resource: self.resource_id,
            status: self.status.parse().map_err(SidError::Storage)?,
            authorized_by: self.authorized_by,
            project_id: ProjectId(self.project_id),
            interval: self.interval_secs,
            created_at: self.created_at,
            expires_at: self.expires_at,
            authorized_at: self.authorized_at,
            last_polled_at: self.last_polled_at,
            redeemed_session_id: self.redeemed_session_id,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// UpstreamProvider
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct UpstreamProviderRow {
    pub id: Uuid,
    pub name: String,
    pub protocol: String,
    pub trust_category: String,
    pub enabled: bool,
    pub client_id: String,
    pub client_secret: Vec<u8>,
    pub discovery_url: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub scopes: serde_json::Value,
    pub show_on_login: bool,
    pub display_order: i32,
    pub logo_url: Option<String>,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UpstreamProviderRow {
    /// A malformed secret, scope list, protocol or trust category is an error:
    /// never a made-up secret, no scopes, OIDC or social.
    pub fn into_domain(self) -> SidResult<UpstreamProvider> {
        let scopes: Vec<String> = serde_json::from_value(self.scopes)
            .map_err(|e| SidError::Storage(format!("column scopes: {e}")))?;
        let client_secret = EncryptedField::from_bytes(&self.client_secret)
            .map_err(|e| SidError::Storage(format!("column client_secret: {e}")))?;

        Ok(UpstreamProvider {
            id: UpstreamProviderId(self.id),
            name: self.name,
            protocol: parsed("protocol", &self.protocol)?,
            trust_category: parsed("trust_category", &self.trust_category)?,
            revision: count("revision", self.revision)?,
            enabled: self.enabled,
            client_id: self.client_id,
            client_secret,
            discovery_url: self.discovery_url,
            authorization_endpoint: self.authorization_endpoint,
            token_endpoint: self.token_endpoint,
            userinfo_endpoint: self.userinfo_endpoint,
            scopes,
            show_on_login: self.show_on_login,
            display_order: self.display_order,
            logo_url: self.logo_url,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// UpstreamIdentity
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct UpstreamIdentityRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub provider_id: Uuid,
    pub upstream_subject: String,
    pub upstream_issuer: Option<String>,
    pub upstream_email: Option<String>,
    pub upstream_name: Option<String>,
    pub upstream_picture: Option<String>,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub login_count: i64,
}

impl UpstreamIdentityRow {
    pub fn into_domain(self) -> SidResult<UpstreamIdentity> {
        Ok(UpstreamIdentity {
            id: UpstreamIdentityId(self.id),
            profile_id: self.profile_id,
            provider_id: UpstreamProviderId(self.provider_id),
            upstream_subject: self.upstream_subject,
            upstream_issuer: self.upstream_issuer,
            upstream_email: self.upstream_email,
            upstream_name: self.upstream_name,
            upstream_picture: self.upstream_picture,
            linked_at: self.linked_at,
            last_login_at: self.last_login_at,
            login_count: count("login_count", self.login_count)?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// PersonalAccessToken (PAT)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct PatRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub name: String,
    pub description: Option<String>,
    pub token_hash: String,
    pub token_prefix: String,
    pub scopes: String,
    pub ip_allowlist: String,
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub use_count: i64,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl PatRow {
    pub fn into_domain(self) -> SidResult<PersonalAccessToken> {
        Ok(PersonalAccessToken {
            id: PatId(self.id),
            profile_id: self.profile_id,
            name: self.name,
            description: self.description,
            token_hash: self.token_hash,
            token_prefix: self.token_prefix,
            scopes: split_ws(&self.scopes),
            ip_allowlist: split_ws(&self.ip_allowlist),
            status: parsed::<PatStatus>("status", &self.status)?,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            last_used_ip: self.last_used_ip,
            use_count: count("use_count", self.use_count)?,
            revoked_at: self.revoked_at,
            revoked_by: self.revoked_by,
            created_at: self.created_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// MachineUser
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct MachineUserRow {
    pub id: MachineUserId,
    pub project_id: Uuid,
    pub machine_type: String,
    pub owner_type: String,
    pub owner_id: String,
    pub client_id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: String,
    pub scopes: String,
    pub ip_allowlist: String,
    pub rate_limit_rpm: i32,
    pub max_token_lifetime: Option<i32>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl MachineUserRow {
    pub fn into_domain(self) -> SidResult<MachineUser> {
        // Unknown stored values are errors, never an active service owned by a Profile.
        let status: MachineUserStatus = self.status.parse().map_err(SidError::Storage)?;
        Ok(MachineUser {
            id: self.id,
            project_id: ProjectId(self.project_id),
            machine_type: self.machine_type.parse().map_err(SidError::Storage)?,
            owner_type: self.owner_type.parse().map_err(SidError::Storage)?,
            owner_id: self.owner_id,
            client_id: self.client_id,
            display_name: self.display_name,
            description: self.description,
            status,
            scopes: split_ws(&self.scopes),
            restrictions: MachineRestrictions {
                ip_allowlist: split_ws(&self.ip_allowlist),
                rate_limit_rpm: self.rate_limit_rpm as u32,
            },
            max_token_lifetime: self.max_token_lifetime.map(|v| v as u32),
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// MachineUserCredential
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct MachineCredentialRow {
    pub kid: String,
    pub machine_user_id: MachineUserId,
    pub credential_type: String,
    pub status: String,
    pub credential_data: String,
    pub algorithm: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl MachineCredentialRow {
    pub fn into_domain(self) -> SidResult<MachineUserCredential> {
        // Unknown stored values are errors, never a usable client secret.
        Ok(MachineUserCredential {
            kid: self.kid,
            machine_user_id: self.machine_user_id,
            credential_type: self.credential_type.parse().map_err(SidError::Storage)?,
            status: self.status.parse().map_err(SidError::Storage)?,
            credential_data: self.credential_data,
            algorithm: self.algorithm,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// ImpersonationGrant
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ImpersonationGrantRow {
    pub machine_user_id: MachineUserId,
    pub target_type: String,
    pub target: String,
    pub allowed_scopes: String,
    pub created_at: DateTime<Utc>,
}

impl ImpersonationGrantRow {
    pub fn into_domain(self) -> SidResult<ImpersonationGrant> {
        // An unknown target type is an error, never a role-wide grant.
        Ok(ImpersonationGrant {
            machine_user_id: self.machine_user_id,
            target_type: self.target_type.parse().map_err(SidError::Storage)?,
            target: self.target,
            allowed_scopes: split_ws(&self.allowed_scopes),
            created_at: self.created_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// InitialAccessToken (IAT)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct InitialAccessTokenRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub token_hash: Vec<u8>,
    pub max_clients: i32,
    pub clients_registered: i32,
    pub allowed_scopes: String,
    pub allowed_grant_types: String,
    pub allowed_redirect_patterns: String,
    pub created_by: String,
    pub revoked: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl InitialAccessTokenRow {
    pub fn into_domain(self) -> InitialAccessToken {
        InitialAccessToken {
            id: InitialAccessTokenId(self.id),
            project_id: ProjectId(self.project_id),
            token_hash: self.token_hash,
            max_clients: self.max_clients as u32,
            clients_registered: self.clients_registered as u32,
            allowed_scopes: split_ws(&self.allowed_scopes),
            allowed_grant_types: split_ws(&self.allowed_grant_types),
            allowed_redirect_patterns: split_ws(&self.allowed_redirect_patterns),
            created_by: self.created_by,
            revoked: self.revoked,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ClosureRequest
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ClosureRequestRow {
    pub profile_id: ProfileId,
    pub mode: String,
    pub closure_reason: Option<String>,
    pub requested_by: ProfileId,
    pub requested_at: DateTime<Utc>,
    pub grace_period_end: Option<DateTime<Utc>>,
    pub export_status: String,
    pub cancel_count: i32,
    pub legal_hold: Option<serde_json::Value>,
}

impl ClosureRequestRow {
    pub fn into_domain(self) -> SidResult<ClosureRequest> {
        let legal_hold = self
            .legal_hold
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| SidError::Storage(format!("legal_hold decode failed: {e}")))?;
        Ok(ClosureRequest {
            profile_id: self.profile_id,
            mode: parsed::<ClosureMode>("mode", &self.mode)?,
            closure_reason: self.closure_reason,
            requested_by: self.requested_by,
            requested_at: self.requested_at,
            grace_period_end: self.grace_period_end,
            export_status: parsed::<ExportStatus>("export_status", &self.export_status)?,
            legal_hold,
            cancel_count: count("cancel_count", i64::from(self.cancel_count))?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// MagicLinkSession
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct MagicLinkRow {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub consumed: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl MagicLinkRow {
    pub fn into_domain(self) -> MagicLinkSession {
        MagicLinkSession {
            id: self.id,
            email: self.email,
            token_hash: self.token_hash,
            consumed: self.consumed,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ExportJob
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ExportJobRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub format: String,
    pub status: String,
    pub archive_path: Option<String>,
    pub size_bytes: Option<i64>,
    pub checksum_sha256: Option<String>,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ExportJobRow {
    pub fn into_domain(self) -> SidResult<ExportJob> {
        Ok(ExportJob {
            id: self.id,
            profile_id: self.profile_id,
            format: parsed::<models::ExportFormat>("format", &self.format)?,
            status: parsed::<ExportStatus>("status", &self.status)?,
            archive_path: self.archive_path,
            size_bytes: self.size_bytes,
            checksum_sha256: self.checksum_sha256,
            created_at: self.created_at,
            ready_at: self.ready_at,
            expires_at: self.expires_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// SodConflictRule
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct SodRuleRow {
    pub name: String,
    pub description: Option<String>,
    pub conflicting_roles: String,
    pub severity: String,
}

impl SodRuleRow {
    /// An unknown severity is an error: read as a warning, a blocking rule
    /// would stop blocking.
    pub fn into_domain(self) -> SidResult<SodConflictRule> {
        Ok(SodConflictRule {
            name: self.name,
            description: self.description,
            conflicting_roles: split_ws(&self.conflicting_roles),
            severity: parsed("severity", &self.severity)?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// SCIM Outbound Target
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ScimOutboundTargetRow {
    pub id: Uuid,
    pub client_id: String,
    pub project_id: Uuid,
    pub display_name: String,
    pub endpoint_url: String,
    pub auth_config: serde_json::Value,
    pub attribute_mapping: serde_json::Value,
    pub group_push: serde_json::Value,
    pub sync_config: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScimOutboundTargetRow {
    pub fn into_domain(self) -> SidResult<ScimOutboundTarget> {
        let field = |name: &str, e: serde_json::Error| {
            SidError::Storage(format!("scim outbound target {name}: {e}"))
        };
        Ok(ScimOutboundTarget {
            id: ScimOutboundTargetId(self.id),
            client_id: self.client_id,
            project_id: ProjectId(self.project_id),
            display_name: self.display_name,
            endpoint_url: self.endpoint_url,
            auth: serde_json::from_value(self.auth_config).map_err(|e| field("auth", e))?,
            attribute_mapping: serde_json::from_value(self.attribute_mapping)
                .map_err(|e| field("attribute mapping", e))?,
            group_push: serde_json::from_value(self.group_push)
                .map_err(|e| field("group push", e))?,
            sync_config: serde_json::from_value(self.sync_config)
                .map_err(|e| field("sync config", e))?,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// SCIM Outbound Record
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ScimOutboundRecordRow {
    pub target_id: Uuid,
    pub sid_entity_id: Uuid,
    pub entity_type: String,
    pub downstream_id: Option<String>,
    pub last_synced_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub failure_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScimOutboundRecordRow {
    pub fn into_domain(self) -> SidResult<ScimOutboundRecord> {
        Ok(ScimOutboundRecord {
            target_id: ScimOutboundTargetId(self.target_id),
            sid_entity_id: self.sid_entity_id,
            entity_type: self.entity_type.parse().map_err(SidError::Storage)?,
            downstream_id: self.downstream_id.unwrap_or_default(),
            last_synced_at: self.last_synced_at,
            last_error: self.last_error,
            failure_count: u32::try_from(self.failure_count)
                .map_err(|e| SidError::Storage(format!("failure_count: {e}")))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// SCIM Outbound DLQ
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct ScimOutboundDlqRow {
    pub id: Uuid,
    pub target_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub sid_entity_id: Uuid,
    pub entity_type: String,
    pub error: String,
    pub attempts: i32,
    pub first_attempt: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
}

impl ScimOutboundDlqRow {
    pub fn into_domain(self) -> SidResult<OutboundDlqEntry> {
        Ok(OutboundDlqEntry {
            id: self.id,
            target_id: ScimOutboundTargetId(self.target_id),
            event_type: self.event_type,
            payload: self.payload,
            sid_entity_id: self.sid_entity_id,
            entity_type: self.entity_type.parse().map_err(SidError::Storage)?,
            error: self.error,
            attempts: u32::try_from(self.attempts)
                .map_err(|e| SidError::Storage(format!("attempts: {e}")))?,
            first_attempt: self.first_attempt,
            last_attempt: self.last_attempt,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Invite
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct InviteRow {
    pub id: Uuid,
    pub code: String,
    pub created_by: ProfileId,
    pub created_by_name: String,
    pub metadata: serde_json::Value,
    pub max_uses: i32,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

impl InviteRow {
    pub fn into_domain(self) -> SidResult<models::Invite> {
        let metadata: std::collections::HashMap<String, String> =
            serde_json::from_value(self.metadata)
                .map_err(|e| SidError::Storage(format!("invite metadata: {e}")))?;
        Ok(models::Invite {
            id: InviteId(self.id),
            code: self.code,
            created_by: self.created_by,
            created_by_name: self.created_by_name,
            metadata,
            max_uses: self.max_uses as u32,
            use_count: self.use_count as u32,
            expires_at: self.expires_at,
            active: self.active,
            created_at: self.created_at,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Registration Source
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, sqlx::FromRow)]
pub struct RegistrationSourceRow {
    pub profile_id: ProfileId,
    pub source_type: String,
    pub source_id: String,
    pub referrer_id: Option<ProfileId>,
    pub utm_source: String,
    pub utm_medium: String,
    pub utm_campaign: String,
    pub utm_term: String,
    pub utm_content: String,
    pub client_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl RegistrationSourceRow {
    pub fn into_domain(self) -> SidResult<models::RegistrationSource> {
        Ok(models::RegistrationSource {
            source_type: parse_source_type(&self.source_type)?,
            source_id: self.source_id,
            referrer_id: self.referrer_id,
            utm: models::UtmParams {
                source: self.utm_source,
                medium: self.utm_medium,
                campaign: self.utm_campaign,
                term: self.utm_term,
                content: self.utm_content,
            },
            client_id: self.client_id,
            created_at: self.created_at,
        })
    }
}

// === PASSWORD RESET SESSION ===

#[derive(Debug, sqlx::FromRow)]
pub struct PasswordResetSessionRow {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub email: String,
    pub token_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl PasswordResetSessionRow {
    pub fn into_domain(self) -> SidResult<models::PasswordResetSession> {
        Ok(models::PasswordResetSession {
            id: models::ResetSessionId(self.id),
            profile_id: self.profile_id,
            email: self.email,
            token_hash: self.token_hash,
            status: self.status.parse().map_err(SidError::Storage)?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            verified_at: self.verified_at,
            completed_at: self.completed_at,
        })
    }
}

// ── Email provider config ──────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct EmailProviderConfigRow {
    pub smtp_host: String,
    pub smtp_port: i32,
    pub from_address: String,
    pub from_display_name: String,
    pub reply_to: String,
    pub encryption: String,
    pub auth_type: String,
    pub username: String,
    pub password_enc: String,
    // XOAUTH2 fields (all nullable, populated only when auth_type = 'xoauth2')
    pub oauth2_provider: Option<String>,
    pub oauth2_tenant_id: Option<String>,
    pub oauth2_client_id: Option<String>,
    pub oauth2_client_secret: Option<String>,
    pub oauth2_service_account_key: Option<String>,
    pub oauth2_token_endpoint: Option<String>,
}

impl EmailProviderConfigRow {
    pub fn into_domain(self) -> models::EmailProviderConfig {
        let xoauth2 = if let Some(provider_str) = &self.oauth2_provider {
            models::XOAuth2Provider::from_db_str(provider_str).map(|provider| {
                models::XOAuth2Config {
                    provider,
                    tenant_id: self.oauth2_tenant_id.clone(),
                    client_id: self.oauth2_client_id.clone().unwrap_or_default(),
                    client_secret: SecretBox::new(Box::new(
                        self.oauth2_client_secret.clone().unwrap_or_default(),
                    )),
                    service_account_key: self
                        .oauth2_service_account_key
                        .clone()
                        .map(|k| SecretBox::new(Box::new(k))),
                    token_endpoint: self.oauth2_token_endpoint.clone(),
                    user_email: self.username.clone(),
                }
            })
        } else {
            None
        };

        models::EmailProviderConfig {
            smtp_host: self.smtp_host,
            smtp_port: self.smtp_port as u16,
            from_address: self.from_address,
            from_display_name: self.from_display_name,
            reply_to: self.reply_to,
            encryption: models::SmtpEncryption::from_db_str(&self.encryption),
            auth_type: models::SmtpAuthMethod::from_db_str(&self.auth_type),
            username: self.username,
            password: SecretBox::new(Box::new(self.password_enc)),
            xoauth2,
        }
    }
}

pub fn parse_source_type(s: &str) -> SidResult<models::RegistrationSourceType> {
    s.parse().map_err(SidError::Storage)
}
