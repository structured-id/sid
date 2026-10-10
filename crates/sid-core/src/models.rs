// SPDX-License-Identifier: AGPL-3.0-only
//! Domain models for StructuredID.

/// `FromStr` accepting exactly the values `as_str` writes; anything else is
/// refused, never read as a default.
macro_rules! parse_stored {
    ($t:ident, $what:literal, [$($v:ident),+ $(,)?]) => {
        impl std::str::FromStr for $t {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                [$(Self::$v),+]
                    .into_iter()
                    .find(|v| v.as_str() == s)
                    .ok_or_else(|| format!("unknown {}: {s:?}", $what))
            }
        }
    };
}

pub mod access_request;
pub mod anomaly_event;
pub mod application;
pub mod audit;
pub mod auth_code;
pub mod auth_flow;
pub mod authz;
pub mod backchannel_logout;
pub mod blob;
pub mod branding;
pub mod certificate;
pub mod claim_mapping;
pub mod consent;
pub mod credential;
pub mod device;
pub mod device_attestation;
pub mod device_authorization;
pub mod directory;
pub mod dpop;
pub mod durable_work;
pub mod email_provider;
pub mod enforcement;
pub mod enterprise_registration;
pub mod event;
pub mod incident;
pub mod instance_secret;
pub mod invite;
pub mod machine_user;
pub mod magic_link;
pub mod mapped_claims;
pub mod mfa;
pub mod mutation;
pub mod notification;
pub mod oauth2_client;
pub mod oidc_issuer;
pub mod operation;
pub mod organization;
pub mod password_history;
pub mod password_reset;
pub mod pat;
pub mod principal;
pub mod principal_contest;
pub mod principal_verification;
pub mod profile;
pub mod profile_email;
pub mod profile_metadata;
pub mod profile_phone;
pub mod project;
pub mod provisioning_connector;
pub mod refresh_token;
pub mod registration;
pub mod registration_source;
pub mod revocation;
pub mod scim_outbound;
pub mod security_policy;
pub mod service_binding;
pub mod session;
pub mod session_end;
pub mod site_registration;
pub mod upstream_identity;
pub mod upstream_provider;
pub mod username;
pub mod webauthn;

pub use access_request::{AccessRequest, AccessRequestId, AccessRequestStatus};
pub use anomaly_event::{AnomalyEventId, AnomalyEventRecord};
pub use application::{
    Application, ApplicationId, ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator,
    ResourceState, SystemIntegration, scope_list,
};
pub use audit::{ActorType, AuditEntry, AuditError, AuditOutcome, AuditRecord, ChainHead};
pub use auth_code::{AuthCodeError, AuthCodeRedemption, AuthorizationCode, ExchangedCode};
pub use auth_flow::{
    ActionConfig, ActionId, ActionOnError, ActionPoint, ActionType, FlowAction, FlowConfig,
    FlowType, StepConfig,
};
pub use authz::{
    AUTHZ_CHECK, AdminEnvelope, AdminOperation, AssignmentFence, AssignmentProvenance,
    AuthzPrincipal, CedarPolicy, CedarPolicyId, EnvelopeError, Group, GroupId, GroupMember,
    PERMISSION_CHECKER_ROLE, PolicyEffect, ProfileGrant, ProfileGrantId, RecipientKind, Role,
    RoleAssignment, RoleAssignmentId, RoleAssignmentPrincipal, RoleEditFence, RoleId,
    SCIM_ACTION_PREFIX, SCIM_ACTIONS, SCIM_GROUP_CREATE, SCIM_GROUP_DELETE, SCIM_GROUP_MEMBERSHIP,
    SCIM_GROUP_READ, SCIM_GROUP_UPDATE, SCIM_PROVISIONER_ROLE, SCIM_USER_CREATE,
    SCIM_USER_DEACTIVATE, SCIM_USER_DELETE, SCIM_USER_READ, SCIM_USER_UPDATE, ScopeType,
    SodConflictRule, TOKEN_INSPECTOR_ROLE, TOKEN_INTROSPECT, Uncovered,
};
pub use backchannel_logout::{LOGOUT_DELIVERY_ATTEMPTS, LOGOUT_DELIVERY_KIND, LogoutDelivery};
pub use blob::{BlobError, BlobMeta, BlobStorageStatus, EncryptedBlob};
pub use branding::{
    BackgroundConfig, BrandingAssets, BrandingConfig, BrandingConfigId, BrandingStatus,
    BrandingText, ButtonStyle, DarkModeConfig, DarkModeTokens, DesignTokens,
};
pub use certificate::{Certificate, CertificateId, CertificateType};
pub use claim_mapping::{ClaimMapping, ClaimTransform};
pub use consent::{
    ClaimGrant, ClaimGrantId, ClaimLevel, ClaimRequest, ClaimType, ConsentId, ConsentRecord,
    ConsentStatus,
};
pub use credential::{
    ActiveCredential, Credential, CredentialData, CredentialId, CredentialRevocation,
    CredentialType, PolicyEvidence, WebAuthnUserHandle,
};
pub use device::{Device, DeviceAssurance, DeviceId, DeviceTrustChange, DeviceType};
pub use device_attestation::{
    AttestationStatus, DeviceAttestation, DeviceAttestationFormat, DeviceAttestationId,
    KeyStorageType,
};
pub use device_authorization::{
    DEVICE_CODE_LIFETIME_SECS, DEVICE_CODE_POLL_INTERVAL_SECS, DeviceAuthCodeId,
    DeviceAuthDecision, DeviceAuthStatus, DeviceAuthorizationCode, DeviceCodeRedemption,
    DevicePoll, USER_CODE_LENGTH,
};
pub use directory::{DirectoryGroupWrite, DirectoryUserWrite, DirectoryWriteMode};
pub use dpop::{DPopBinding, DPopProof, HttpMethod};
pub use durable_work::{
    ClaimedWork, NewWork, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot, WorkState,
};
pub use email_provider::{
    EmailProviderConfig, SmtpAuthMethod, SmtpEncryption, XOAuth2Config, XOAuth2Provider,
};
pub use enforcement::{EnforcementAction, EnforcementDecision, PolicyViolation, RequiredAction};
pub use enterprise_registration::{EnterpriseId, EnterpriseRegistration};
pub use event::{EVENT_RELAY_ATTEMPTS, EVENT_RELAY_KIND, Event, EventFilter};
pub use incident::{
    AffectedEntity, AffectedEntityType, ContainmentAction, DetectionSource, Impact, Incident,
    IncidentCategory, IncidentData, IncidentId, PostMortemReport, Severity, TimelineEntry,
};
pub use instance_secret::InstanceSecret;
pub use invite::{
    INVITE_CODE_LENGTH, Invite, InviteFilter, InviteId, InviteStatus, generate_invite_code,
    normalize_invite_code,
};
pub use machine_user::{
    CredentialStatus, ImpersonationGrant, ImpersonationTargetType, MachineCredentialType,
    MachineRestrictions, MachineUser, MachineUserCredential, MachineUserId, MachineUserStatus,
    MachineUserType, OwnerType,
};
pub use magic_link::{MAGIC_LINK_EXPIRY_SECS, MAGIC_LINK_RATE_LIMIT_MAX, MagicLinkSession};
pub use mapped_claims::MappedClaims;
pub use mfa::{
    ChallengeStatus, EnrollmentStatus, FactorCategory, FactorProperties, MfaChallenge,
    MfaEnrollment, MfaMethod, PhishingResistance, RecoveryCode, RecoveryCodeSet,
};
pub use mutation::{ActorFence, MutationContext};
pub use notification::{
    DeliveryResult, DeliveryStatus, NotificationChannel, NotificationId, NotificationPriority,
    NotificationRequest,
};
pub use oauth2_client::{
    ApplicationType, ClientKeySet, InitialAccessToken, InitialAccessTokenId, LoginStrategy,
    OAuth2Client, RegistrationPolicy, SubjectType, TokenEndpointAuthMethod,
};
pub use oidc_issuer::{IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, OidcIssuer};
pub use operation::{OperationCompletion, OperationKey, OperationRecord};
pub use organization::{OrgId, OrgStatus, OrgType, Organization};
pub use password_history::{
    HistoryArchive, HistoryCommit, HistoryEntry, HistoryEpoch, HistoryEpochDescriptor,
    HistoryEpochId, HistoryEpochUse, HistoryEvidence, HistoryKsf, HistoryLiveSet,
    HistoryPreparation, HistorySuite, KeyArchive, KeyEpoch, KeyEpochs, NewKeyEpoch,
    PasswordHistory, WrappedHistoryKey, history_key_context,
};
pub use password_reset::{
    PasswordResetSession, RESET_SESSION_TTL_SECS, ResetSessionId, ResetSessionStatus,
};
pub use pat::{PatId, PatModel, PatStatus, PersonalAccessToken};
pub use principal::{
    INSTALLATION_EMAIL_POLICY_REVISION, Principal, PrincipalBinding, PrincipalBindingId,
    PrincipalEligibility, PrincipalEntity, PrincipalId, PrincipalType, UnknownPrincipalType,
    check_principal_eligibility,
};
pub use principal_contest::{
    ContestCheck, PRINCIPAL_CONTEST_CHECK_ATTEMPTS, PRINCIPAL_CONTEST_CHECK_KIND,
};
pub use principal_verification::{AssuranceLevel, VerificationSource};
pub use principal_verification::{PrincipalVerification, VerificationId};
pub use profile::{
    ClosureMode, ClosureRequest, EXPORT_DOWNLOAD_WINDOW_HOURS, ExportFormat, ExportJob,
    ExportStatus, IDENTIFIER_QUARANTINE_DAYS, LegalHold, MAX_CANCEL_CYCLES_PER_YEAR, Profile,
    ProfileAssurance, ProfileId, ProfileStatus, ProfileType, ProfileVisibility,
};
pub use profile_email::{EmailLabel, EmailSettings, ProfileEmail, ProfileEmailId};
pub use profile_metadata::ProfileMetadata;
pub use profile_phone::{PhoneLabel, PhoneSettings, ProfilePhone, ProfilePhoneId};
pub use project::{Project, ProjectChange, ProjectId};
pub use provisioning_connector::{
    ConnectorCredentialKind, ConnectorState, ProvisioningConnector, ProvisioningConnectorId,
    ProvisioningCredential, ProvisioningCredentialId, ProvisioningDirection,
};
pub use refresh_token::{RefreshToken, RefreshTokenError, ValidatedRefreshToken};
pub use registration::{NewRegistration, SignupIdentifier};
pub use registration_source::{RegistrationSource, RegistrationSourceType, UtmParams};
pub use revocation::{
    CascadeEntry, CascadeTier, RevocationId, RevocationMode, RevocationReason, RevocationRequest,
    RevocationTarget,
};
pub use scim_outbound::{
    AttributeMapping, AttributeMappingEntry, GroupMappingEntry, GroupPushConfig, MappingSource,
    OutboundAuthConfig, OutboundDlqEntry, OutboundEntityType, OutboundSyncConfig,
    ScimOutboundRecord, ScimOutboundTarget, ScimOutboundTargetId,
};
pub use security_policy::{
    AuthPolicy, CountryMode, CurrentPasswordRule, DevicePolicy, EnforcementConfig, EnforcementMode,
    EnrollmentMode, EnrollmentPolicy, GraceExpiryAction, InviteConfig, MfaEnforcement,
    NetworkPolicy, NetworkViolationReaction, PasswordPolicy, PrincipalPolicy, SecurityPolicy,
    SecurityPolicyId, SessionDecayConfig, SessionPolicy,
};
pub use service_binding::{BindingId, BindingScope, EmptyBindingScope, ServiceBinding};
pub use session::{
    AuthLevel, BrowserSecretHash, GrantAuthentication, Session, SessionAuthentication,
    SessionDecayLevel, SessionId,
};
pub use session_end::SessionEnd;
pub use site_registration::{SiteId, SiteRegistration, VerificationStatus};
pub use upstream_identity::{UpstreamIdentity, UpstreamIdentityId, UpstreamLogin};
pub use upstream_provider::{
    ProviderTrustCategory, UpstreamProtocol, UpstreamProvider, UpstreamProviderId,
};
pub use username::{
    SuspensionReason, UsernameError, UsernameStatus, validate_corporate_login, validate_username,
};
pub use webauthn::{AttestationFormat, WebAuthnCredential, WebAuthnTransport};
