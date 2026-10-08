// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC error model: every error a service returns is a canonical
//! `google.rpc.Status` carrying a `google.rpc.ErrorInfo`.
//!
//! [`ApiError`] is the one value handlers build; its conversion into
//! `tonic::Status` attaches `ErrorInfo` always and the typed details
//! (`BadRequest`, `PreconditionFailure`, `RetryInfo`, `LocalizedMessage`) that
//! the error carries. Clients switch on `ErrorInfo.reason` and localize on their
//! side; they never parse `Status.message`.
//!
//! Authentication failures and internal errors send a fixed generic message;
//! their detail belongs in logs and audit, never in the response.

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use tonic::Code;
use tonic_types::{ErrorDetails, StatusExt};

pub mod refuse;

/// Error domain of this server's reasons. AIP-193: a reason is stable within
/// its domain, and the domain is globally unique, so it is the product's
/// domain name, the same for every installation whatever host serves it.
pub const DOMAIN_SID: &str = "structured.id";

/// Message sent for authentication failures, whatever went wrong.
const GENERIC_AUTH_MESSAGE: &str = "authentication failed";
/// Message sent for internal errors; the cause goes to the log.
const GENERIC_INTERNAL_MESSAGE: &str = "internal error";

/// Machine-readable reason, the value of `ErrorInfo.reason`.
///
/// Mirrors `sid.v1.common.ErrorReason` in the CE proto; each reason fixes its
/// gRPC code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorReason {
    // NOT_FOUND
    ProfileNotFound,
    ApplicationNotFound,
    SessionNotFound,
    CredentialNotFound,
    RoleNotFound,
    ProjectNotFound,
    OidcIssuerNotFound,
    ResourceNotFound,
    ForwardAuthApplicationNotFound,
    InitialAccessTokenNotFound,
    UpstreamProviderNotFound,
    MachineUserNotFound,
    ConsentNotFound,
    PhoneNotFound,
    EmailNotFound,
    DeviceNotFound,
    PrincipalNotFound,
    ExportNotFound,
    ClosureRequestNotFound,
    GroupNotFound,
    PolicyNotFound,
    AccessRequestNotFound,
    TemplateNotFound,
    AttestationNotFound,
    ProfileMetadataNotFound,
    BrandingNotFound,
    FlowConfigNotFound,
    FlowActionNotFound,
    InviteNotFound,
    OrganizationNotFound,
    ProvisioningConnectorNotFound,

    // UNAUTHENTICATED
    AuthenticationFailed,
    TokenExpired,
    TokenInvalid,

    // PERMISSION_DENIED
    InsufficientPermissions,
    ScopeNotGranted,
    SignInRefused,
    RegistrationRestricted,

    // ALREADY_EXISTS
    ProfileAlreadyExists,
    EmailAlreadyRegistered,
    UsernameAlreadyTaken,
    OperationKeyConflict,
    ApplicationRoleExists,
    ResourceIndicatorTaken,
    PhoneAlreadyRegistered,
    RoleAlreadyExists,
    UpstreamProviderAlreadyExists,
    PrincipalAlreadyHeld,
    GroupAlreadyExists,
    PolicyAlreadyExists,
    AttestationAlreadyExists,

    // INVALID_ARGUMENT
    InvalidFieldValue,
    RequiredFieldMissing,
    PasswordProofInvalid,

    // FAILED_PRECONDITION
    MfaRequired,
    AccountSuspended,
    AccountLocked,
    ConsentRequired,
    CredentialRevoked,
    AccountClosed,
    OperationResultUnavailable,
    OperationExpired,
    ResourceRetired,
    IssuerMismatch,
    SystemIntegrationUnavailable,
    SystemManaged,
    PasswordReused,
    StepUpRequired,
    CaptchaRequired,
    LegacyMigrationRequired,
    InvalidState,
    FeatureNotConfigured,

    // RESOURCE_EXHAUSTED
    RateLimitExceeded,
    QuotaExceeded,

    // ABORTED
    ConcurrentModification,
    OperationInProgress,

    // UNAVAILABLE
    PasswordHistoryUnavailable,
    ServiceMaintenance,
    DependencyUnavailable,

    // UNKNOWN
    OperationOutcomeUnknown,

    // UNIMPLEMENTED
    FeatureNotAvailable,

    // INTERNAL
    InternalError,
}

impl ErrorReason {
    /// Every reason, for exhaustive checks against the proto enum.
    pub const ALL: [ErrorReason; 82] = [
        Self::InviteNotFound,
        Self::OrganizationNotFound,
        Self::ProvisioningConnectorNotFound,
        Self::FlowConfigNotFound,
        Self::FlowActionNotFound,
        Self::BrandingNotFound,
        Self::ProfileMetadataNotFound,
        Self::AttestationNotFound,
        Self::AttestationAlreadyExists,
        Self::GroupNotFound,
        Self::PolicyNotFound,
        Self::AccessRequestNotFound,
        Self::TemplateNotFound,
        Self::GroupAlreadyExists,
        Self::PolicyAlreadyExists,
        Self::RegistrationRestricted,
        Self::SignInRefused,
        Self::ExportNotFound,
        Self::ClosureRequestNotFound,
        Self::PrincipalNotFound,
        Self::PrincipalAlreadyHeld,
        Self::DeviceNotFound,
        Self::ConsentNotFound,
        Self::PhoneNotFound,
        Self::EmailNotFound,
        Self::MachineUserNotFound,
        Self::UpstreamProviderNotFound,
        Self::UpstreamProviderAlreadyExists,
        Self::QuotaExceeded,
        Self::InitialAccessTokenNotFound,
        Self::RoleAlreadyExists,
        Self::PhoneAlreadyRegistered,
        Self::StepUpRequired,
        Self::CaptchaRequired,
        Self::LegacyMigrationRequired,
        Self::InvalidState,
        Self::FeatureNotConfigured,
        Self::ServiceMaintenance,
        Self::DependencyUnavailable,
        Self::PasswordProofInvalid,
        Self::PasswordReused,
        Self::PasswordHistoryUnavailable,
        Self::ProfileNotFound,
        Self::ApplicationNotFound,
        Self::SessionNotFound,
        Self::CredentialNotFound,
        Self::RoleNotFound,
        Self::ProjectNotFound,
        Self::OidcIssuerNotFound,
        Self::ResourceNotFound,
        Self::ForwardAuthApplicationNotFound,
        Self::ApplicationRoleExists,
        Self::ResourceIndicatorTaken,
        Self::ResourceRetired,
        Self::IssuerMismatch,
        Self::SystemIntegrationUnavailable,
        Self::SystemManaged,
        Self::AuthenticationFailed,
        Self::TokenExpired,
        Self::TokenInvalid,
        Self::InsufficientPermissions,
        Self::ScopeNotGranted,
        Self::ProfileAlreadyExists,
        Self::EmailAlreadyRegistered,
        Self::UsernameAlreadyTaken,
        Self::OperationKeyConflict,
        Self::InvalidFieldValue,
        Self::RequiredFieldMissing,
        Self::MfaRequired,
        Self::AccountSuspended,
        Self::AccountLocked,
        Self::ConsentRequired,
        Self::CredentialRevoked,
        Self::AccountClosed,
        Self::OperationResultUnavailable,
        Self::OperationExpired,
        Self::RateLimitExceeded,
        Self::ConcurrentModification,
        Self::OperationInProgress,
        Self::OperationOutcomeUnknown,
        Self::FeatureNotAvailable,
        Self::InternalError,
    ];

    /// The `ErrorInfo.reason` string (the proto enum value name).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProfileNotFound => "PROFILE_NOT_FOUND",
            Self::ApplicationNotFound => "APPLICATION_NOT_FOUND",
            Self::SessionNotFound => "SESSION_NOT_FOUND",
            Self::CredentialNotFound => "CREDENTIAL_NOT_FOUND",
            Self::RoleNotFound => "ROLE_NOT_FOUND",
            Self::ProjectNotFound => "PROJECT_NOT_FOUND",
            Self::OidcIssuerNotFound => "OIDC_ISSUER_NOT_FOUND",
            Self::ResourceNotFound => "RESOURCE_NOT_FOUND",
            Self::ForwardAuthApplicationNotFound => "FORWARD_AUTH_APPLICATION_NOT_FOUND",
            Self::ApplicationRoleExists => "APPLICATION_ROLE_EXISTS",
            Self::ResourceIndicatorTaken => "RESOURCE_INDICATOR_TAKEN",
            Self::ResourceRetired => "RESOURCE_RETIRED",
            Self::IssuerMismatch => "ISSUER_MISMATCH",
            Self::SystemIntegrationUnavailable => "SYSTEM_INTEGRATION_UNAVAILABLE",
            Self::SystemManaged => "SYSTEM_MANAGED",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenInvalid => "TOKEN_INVALID",
            Self::InsufficientPermissions => "INSUFFICIENT_PERMISSIONS",
            Self::ScopeNotGranted => "SCOPE_NOT_GRANTED",
            Self::SignInRefused => "SIGN_IN_REFUSED",
            Self::RegistrationRestricted => "REGISTRATION_RESTRICTED",
            Self::ProfileAlreadyExists => "PROFILE_ALREADY_EXISTS",
            Self::EmailAlreadyRegistered => "EMAIL_ALREADY_REGISTERED",
            Self::UsernameAlreadyTaken => "USERNAME_ALREADY_TAKEN",
            Self::OperationKeyConflict => "OPERATION_KEY_CONFLICT",
            Self::OperationResultUnavailable => "OPERATION_RESULT_UNAVAILABLE",
            Self::OperationExpired => "OPERATION_EXPIRED",
            Self::OperationInProgress => "OPERATION_IN_PROGRESS",
            Self::OperationOutcomeUnknown => "OPERATION_OUTCOME_UNKNOWN",
            Self::InvalidFieldValue => "INVALID_FIELD_VALUE",
            Self::RequiredFieldMissing => "REQUIRED_FIELD_MISSING",
            Self::PasswordProofInvalid => "PASSWORD_PROOF_INVALID",
            Self::PasswordReused => "PASSWORD_REUSED",
            Self::PasswordHistoryUnavailable => "PASSWORD_HISTORY_UNAVAILABLE",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::AccountSuspended => "ACCOUNT_SUSPENDED",
            Self::AccountLocked => "ACCOUNT_LOCKED",
            Self::ConsentRequired => "CONSENT_REQUIRED",
            Self::CredentialRevoked => "CREDENTIAL_REVOKED",
            Self::AccountClosed => "ACCOUNT_CLOSED",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::ConcurrentModification => "CONCURRENT_MODIFICATION",
            Self::FeatureNotAvailable => "FEATURE_NOT_AVAILABLE",
            Self::PhoneAlreadyRegistered => "PHONE_ALREADY_REGISTERED",
            Self::RoleAlreadyExists => "ROLE_ALREADY_EXISTS",
            Self::InitialAccessTokenNotFound => "INITIAL_ACCESS_TOKEN_NOT_FOUND",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::UpstreamProviderNotFound => "UPSTREAM_PROVIDER_NOT_FOUND",
            Self::MachineUserNotFound => "MACHINE_USER_NOT_FOUND",
            Self::ConsentNotFound => "CONSENT_NOT_FOUND",
            Self::PhoneNotFound => "PHONE_NOT_FOUND",
            Self::EmailNotFound => "EMAIL_NOT_FOUND",
            Self::DeviceNotFound => "DEVICE_NOT_FOUND",
            Self::PrincipalNotFound => "PRINCIPAL_NOT_FOUND",
            Self::ExportNotFound => "EXPORT_NOT_FOUND",
            Self::ClosureRequestNotFound => "CLOSURE_REQUEST_NOT_FOUND",
            Self::UpstreamProviderAlreadyExists => "UPSTREAM_PROVIDER_ALREADY_EXISTS",
            Self::PrincipalAlreadyHeld => "PRINCIPAL_ALREADY_HELD",
            Self::GroupNotFound => "GROUP_NOT_FOUND",
            Self::PolicyNotFound => "POLICY_NOT_FOUND",
            Self::AccessRequestNotFound => "ACCESS_REQUEST_NOT_FOUND",
            Self::TemplateNotFound => "TEMPLATE_NOT_FOUND",
            Self::AttestationNotFound => "ATTESTATION_NOT_FOUND",
            Self::ProfileMetadataNotFound => "PROFILE_METADATA_NOT_FOUND",
            Self::BrandingNotFound => "BRANDING_NOT_FOUND",
            Self::FlowConfigNotFound => "FLOW_CONFIG_NOT_FOUND",
            Self::FlowActionNotFound => "FLOW_ACTION_NOT_FOUND",
            Self::InviteNotFound => "INVITE_NOT_FOUND",
            Self::OrganizationNotFound => "ORGANIZATION_NOT_FOUND",
            Self::ProvisioningConnectorNotFound => "PROVISIONING_CONNECTOR_NOT_FOUND",
            Self::AttestationAlreadyExists => "ATTESTATION_ALREADY_EXISTS",
            Self::GroupAlreadyExists => "GROUP_ALREADY_EXISTS",
            Self::PolicyAlreadyExists => "POLICY_ALREADY_EXISTS",
            Self::StepUpRequired => "STEP_UP_REQUIRED",
            Self::CaptchaRequired => "CAPTCHA_REQUIRED",
            Self::LegacyMigrationRequired => "LEGACY_MIGRATION_REQUIRED",
            Self::InvalidState => "INVALID_STATE",
            Self::FeatureNotConfigured => "FEATURE_NOT_CONFIGURED",
            Self::ServiceMaintenance => "SERVICE_MAINTENANCE",
            Self::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    /// The gRPC status code this reason is sent with.
    pub fn grpc_code(&self) -> Code {
        match self {
            Self::ProfileNotFound
            | Self::ApplicationNotFound
            | Self::SessionNotFound
            | Self::CredentialNotFound
            | Self::RoleNotFound
            | Self::ProjectNotFound
            | Self::OidcIssuerNotFound
            | Self::ResourceNotFound
            | Self::ForwardAuthApplicationNotFound
            | Self::InitialAccessTokenNotFound
            | Self::UpstreamProviderNotFound
            | Self::MachineUserNotFound
            | Self::ConsentNotFound
            | Self::PhoneNotFound
            | Self::EmailNotFound
            | Self::DeviceNotFound
            | Self::PrincipalNotFound
            | Self::ExportNotFound
            | Self::ClosureRequestNotFound
            | Self::GroupNotFound
            | Self::PolicyNotFound
            | Self::AccessRequestNotFound
            | Self::TemplateNotFound
            | Self::AttestationNotFound
            | Self::ProfileMetadataNotFound
            | Self::BrandingNotFound
            | Self::FlowConfigNotFound
            | Self::FlowActionNotFound
            | Self::InviteNotFound
            | Self::OrganizationNotFound
            | Self::ProvisioningConnectorNotFound => Code::NotFound,

            Self::AuthenticationFailed | Self::TokenExpired | Self::TokenInvalid => {
                Code::Unauthenticated
            }

            Self::InsufficientPermissions
            | Self::ScopeNotGranted
            | Self::SignInRefused
            | Self::RegistrationRestricted => Code::PermissionDenied,

            Self::ProfileAlreadyExists
            | Self::EmailAlreadyRegistered
            | Self::UsernameAlreadyTaken
            | Self::OperationKeyConflict
            | Self::ApplicationRoleExists
            | Self::ResourceIndicatorTaken
            | Self::PhoneAlreadyRegistered
            | Self::RoleAlreadyExists
            | Self::UpstreamProviderAlreadyExists
            | Self::PrincipalAlreadyHeld
            | Self::GroupAlreadyExists
            | Self::PolicyAlreadyExists
            | Self::AttestationAlreadyExists => Code::AlreadyExists,

            Self::InvalidFieldValue | Self::RequiredFieldMissing | Self::PasswordProofInvalid => {
                Code::InvalidArgument
            }

            Self::MfaRequired
            | Self::AccountSuspended
            | Self::AccountLocked
            | Self::ConsentRequired
            | Self::CredentialRevoked
            | Self::AccountClosed
            | Self::OperationResultUnavailable
            | Self::OperationExpired
            | Self::ResourceRetired
            | Self::IssuerMismatch
            | Self::SystemIntegrationUnavailable
            | Self::SystemManaged
            | Self::PasswordReused
            | Self::StepUpRequired
            | Self::CaptchaRequired
            | Self::LegacyMigrationRequired
            | Self::InvalidState
            | Self::FeatureNotConfigured => Code::FailedPrecondition,

            Self::PasswordHistoryUnavailable
            | Self::ServiceMaintenance
            | Self::DependencyUnavailable => Code::Unavailable,

            Self::RateLimitExceeded | Self::QuotaExceeded => Code::ResourceExhausted,

            Self::ConcurrentModification | Self::OperationInProgress => Code::Aborted,

            Self::OperationOutcomeUnknown => Code::Unknown,

            Self::FeatureNotAvailable => Code::Unimplemented,

            Self::InternalError => Code::Internal,
        }
    }

    /// Whether the client gets a fixed message instead of the handler's text:
    /// authentication failures must not say what failed, internal errors must
    /// not expose their cause.
    fn fixed_message(&self) -> Option<&'static str> {
        match self {
            Self::AuthenticationFailed | Self::TokenExpired | Self::TokenInvalid => {
                Some(GENERIC_AUTH_MESSAGE)
            }
            Self::InternalError => Some(GENERIC_INTERNAL_MESSAGE),
            _ => None,
        }
    }
}

impl std::fmt::Display for ErrorReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A vocabulary of reasons in one error domain. The shared vocabulary is
/// [`ErrorReason`] in [`DOMAIN_SID`]; a tier that defines reasons of its own
/// (EE, SaaS, ops) implements this for its enum in its own domain and
/// uses the shared reasons for everything else, never redefining them.
pub trait Reason: Copy + std::fmt::Debug {
    /// `ErrorInfo.domain` of every reason in this vocabulary.
    const DOMAIN: &'static str;

    /// The `ErrorInfo.reason` string (the proto enum value name).
    fn as_str(self) -> &'static str;

    /// The gRPC status code this reason is sent with.
    fn grpc_code(self) -> Code;

    /// The fixed message sent instead of the handler's text, for reasons whose
    /// text must not reveal what failed.
    fn fixed_message(self) -> Option<&'static str> {
        None
    }
}

impl Reason for ErrorReason {
    const DOMAIN: &'static str = DOMAIN_SID;

    fn as_str(self) -> &'static str {
        ErrorReason::as_str(&self)
    }

    fn grpc_code(self) -> Code {
        ErrorReason::grpc_code(&self)
    }

    fn fixed_message(self) -> Option<&'static str> {
        ErrorReason::fixed_message(&self)
    }
}

/// An error a service returns, converted once into a canonical `tonic::Status`.
/// `R` is the vocabulary of its reason; the shared one unless a tier's own.
#[derive(Debug, Clone)]
pub struct ApiError<R: Reason = ErrorReason> {
    reason: R,
    message: Cow<'static, str>,
    metadata: HashMap<String, String>,
    details: ErrorDetails,
    /// Details no canonical `google.rpc` type carries, packed as `Any`.
    additional: Vec<prost_types::Any>,
}

impl ApiError {
    /// An internal error. The client sees only a generic message; the caller
    /// logs the cause.
    pub fn internal() -> Self {
        Self::new(ErrorReason::InternalError, GENERIC_INTERNAL_MESSAGE)
    }
}

impl<R: Reason> ApiError<R> {
    /// An error with `reason` and a developer-facing `message` (English, not
    /// localized; clients localize from the reason).
    pub fn new(reason: R, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            reason,
            message: message.into(),
            metadata: HashMap::new(),
            details: ErrorDetails::new(),
            additional: Vec::new(),
        }
    }

    /// Add non-sensitive `ErrorInfo` metadata (identifiers the caller already
    /// knows, limits, names of fields).
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add a `BadRequest` field violation.
    pub fn with_field_violation(
        mut self,
        field: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.details.add_bad_request_violation(field, description);
        self
    }

    /// Add a `PreconditionFailure` violation: what must happen before a retry
    /// (`kind`), what it applies to (`subject`), and a description.
    pub fn with_precondition(
        mut self,
        kind: impl Into<String>,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.details
            .add_precondition_failure_violation(kind, subject, description);
        self
    }

    /// Add `ResourceInfo` naming the resource that was not found or already
    /// exists.
    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_name: impl Into<String>,
    ) -> Self {
        self.details
            .set_resource_info(resource_type, resource_name, "", "");
        self
    }

    /// Add a `QuotaFailure` violation: which limit (`subject`) and what it is.
    pub fn with_quota_violation(
        mut self,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.details
            .add_quota_failure_violation(subject, description);
        self
    }

    /// Add `RetryInfo`: the client may retry after `delay`.
    pub fn with_retry_after(mut self, delay: Duration) -> Self {
        self.details.set_retry_info(Some(delay));
        self
    }

    /// Add a `LocalizedMessage` for clients that display server text.
    pub fn with_localized_message(
        mut self,
        locale: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        self.details.set_localized_message(locale, message);
        self
    }

    /// Add a detail no canonical `google.rpc` type carries, beside `ErrorInfo`
    /// and never instead of it. `type_url` is the message's canonical type URL
    /// (`type.googleapis.com/<package>.<Message>`).
    pub fn with_detail(
        mut self,
        type_url: impl Into<String>,
        message: &impl prost::Message,
    ) -> Self {
        self.additional.push(prost_types::Any {
            type_url: type_url.into(),
            value: message.encode_to_vec(),
        });
        self
    }

    /// The reason this error reports.
    pub fn reason(&self) -> R {
        self.reason
    }
}

impl<R: Reason> From<ApiError<R>> for tonic::Status {
    fn from(err: ApiError<R>) -> Self {
        let ApiError {
            reason,
            message,
            metadata,
            mut details,
            additional,
        } = err;
        let message = reason.fixed_message().map(Cow::Borrowed).unwrap_or(message);
        details.set_error_info(reason.as_str(), R::DOMAIN, metadata);
        let status = tonic::Status::with_error_details(reason.grpc_code(), message, details);
        if additional.is_empty() {
            return status;
        }
        // tonic-types packs only the canonical details; the additional ones
        // are appended to the same google.rpc.Status it encoded.
        let mut rpc_status = <tonic_types::Status as prost::Message>::decode(status.details())
            .expect("tonic-types encodes a valid google.rpc.Status");
        rpc_status.details.extend(additional);
        tonic::Status::with_details(
            status.code(),
            status.message().to_owned(),
            prost::Message::encode_to_vec(&rpc_status).into(),
        )
    }
}

/// `ErrorInfo` of a status as (reason, domain, metadata), or `None` when the
/// status carries none.
pub fn extract_error_info(
    status: &tonic::Status,
) -> Option<(String, String, HashMap<String, String>)> {
    let info = status.get_details_error_info()?;
    Some((info.reason, info.domain, info.metadata))
}

/// The `RetryInfo` delay of a status: how long the caller waits before
/// retrying, or `None` when the status does not say.
pub fn extract_retry_delay(status: &tonic::Status) -> Option<Duration> {
    status.get_details_retry_info()?.retry_delay
}

/// Shorthand for handlers that still build a status in one call: `reason`,
/// `message` and `ErrorInfo` metadata.
pub fn status_with_error_info(
    reason: ErrorReason,
    message: impl Into<Cow<'static, str>>,
    metadata: HashMap<String, String>,
) -> tonic::Status {
    let mut err = ApiError::new(reason, message);
    err.metadata = metadata;
    err.into()
}

#[cfg(test)]
mod tests;
