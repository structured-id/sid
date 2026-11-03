// SPDX-License-Identifier: AGPL-3.0-only
//! How each CE method that changes state is safe to retry (the durable
//! operation result contract): its record, checked against the proto by the
//! `operation_coverage` test.

/// What makes a retry of a method safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Requires an operation key; a retry returns the result recorded with
    /// the first commit.
    Keyed,
    /// A protocol ceremony with its own single-use or replay rule, named.
    Ceremony(&'static str),
    /// The effect is the same however often it is applied, for the reason
    /// named.
    Natural(&'static str),
    /// This build refuses every call of the method before any effect.
    NotServed,
}

/// A method this build refuses before any effect.
const OFF: Coverage = Coverage::NotServed;

/// Every mutating CE method and its coverage, by full method name.
pub const COVERAGE: &[(&str, Coverage)] = &[
    (
        "sid.v1.machine.PatService/AdminRevokePat",
        Coverage::Natural(
            "a revoked token stays revoked: a repeat finds it revoked and answers \
             as the first",
        ),
    ),
    ("sid.v1.machine.PatService/CreatePat", Coverage::Keyed),
    ("sid.v1.machine.PatService/ExchangePat", OFF),
    (
        "sid.v1.machine.PatService/RevokePat",
        Coverage::Natural(
            "a revoked token stays revoked: a repeat finds it revoked and answers \
             as the first",
        ),
    ),
    ("sid.v1.admin.RealmService/DeleteTranslationOverride", OFF),
    ("sid.v1.admin.RealmService/ImportRealm", OFF),
    ("sid.v1.admin.RealmService/SetTranslationOverride", OFF),
    ("sid.v1.admin.RealmService/UpdateLocalizationSettings", OFF),
    ("sid.v1.admin.RealmService/UpdateLoginSettings", OFF),
    ("sid.v1.admin.RealmService/UpdateRealm", OFF),
    ("sid.v1.admin.RealmService/UpdateSessionConfig", OFF),
    ("sid.v1.admin.RealmService/UpdateTokenConfig", OFF),
    ("sid.v1.authn.AuthService/AcceptTerms", OFF),
    ("sid.v1.authn.AuthService/ApproveCiba", OFF),
    (
        "sid.v1.authn.AuthService/CompletePasswordReset",
        Coverage::Ceremony(
            "the reset session is consumed by the password it sets: a repeat finds \
             no pending reset and changes nothing",
        ),
    ),
    (
        "sid.v1.authn.AuthService/CompleteStepUp",
        Coverage::Ceremony(
            "its proof counts once: a TOTP time step, recovery code or passkey \
             challenge is spent by its first use, so a repeat elevates nothing",
        ),
    ),
    ("sid.v1.authn.AuthService/ConfirmAccountDeletion", OFF),
    ("sid.v1.authn.AuthService/ConfirmIdpLink", OFF),
    (
        "sid.v1.authn.AuthService/DeleteMfaCredential",
        Coverage::Keyed,
    ),
    ("sid.v1.authn.AuthService/DenyCiba", OFF),
    (
        "sid.v1.authn.AuthService/ExecutePasswordReset",
        Coverage::Ceremony(
            "an OPAQUE step of the reset: it changes no account state, and the \
             reset commits only in its single-use completion",
        ),
    ),
    (
        "sid.v1.authn.AuthService/FinishTotpEnrollment",
        Coverage::Ceremony(
            "the pending enrollment is taken by its first finish: a repeat finds \
             none and enrolls nothing",
        ),
    ),
    (
        "sid.v1.authn.AuthService/GenerateRecoveryCodes",
        Coverage::Keyed,
    ),
    (
        "sid.v1.authn.AuthService/LegacyMigrateFinish",
        Coverage::Ceremony(
            "the migration state is taken by its first finish: a repeat finds \
             none and replaces nothing",
        ),
    ),
    (
        "sid.v1.authn.AuthService/OAuth2Authorize",
        Coverage::Ceremony(
            "RFC 6749 §4.1.1: each authorization request issues its own single-use \
             code",
        ),
    ),
    (
        "sid.v1.authn.AuthService/OAuth2Revoke",
        Coverage::Ceremony(
            "RFC 7009 §2.2: revoking a revoked or unknown token answers success and \
             changes nothing",
        ),
    ),
    (
        "sid.v1.authn.AuthService/OAuth2Token",
        Coverage::Ceremony(
            "RFC 6749 §4.1.2 and §10.4: a code or rotated refresh token is \
             consumed once; a second use is refused, never answered with tokens",
        ),
    ),
    (
        "sid.v1.authn.AuthService/OpaqueLoginFinish",
        Coverage::Ceremony(
            "RFC 9807 §6: the login state is consumed by its finish; a repeat \
             finds none and creates no session",
        ),
    ),
    ("sid.v1.authn.AuthService/OpaqueRegistrationFinish", OFF),
    (
        "sid.v1.authn.AuthService/OpaqueZkppRegistrationFinish",
        Coverage::Ceremony(
            "RFC 9807 §5: the registration's pending operation is consumed by its \
             commit, which records its own outcome",
        ),
    ),
    (
        "sid.v1.authn.AuthService/OpaqueZkppRegistrationStart",
        Coverage::Ceremony(
            "RFC 9807 §5: each start opens its own pending registration; nothing \
             is registered before its finish",
        ),
    ),
    (
        "sid.v1.authn.AuthService/PasswordChangeChallenge",
        Coverage::Ceremony(
            "each challenge opens its own pending change; nothing changes before \
             its finish",
        ),
    ),
    (
        "sid.v1.authn.AuthService/PasswordChangeExecute",
        Coverage::Ceremony(
            "an OPAQUE step of the change: it changes no account state, and the \
             change commits only in its single-use finish",
        ),
    ),
    (
        "sid.v1.authn.AuthService/PasswordChangeFinish",
        Coverage::Ceremony(
            "the change's pending operation is consumed by its commit: a repeat \
             finds none and changes nothing",
        ),
    ),
    (
        "sid.v1.authn.AuthService/RequestMagicLink",
        Coverage::Ceremony(
            "each request issues its own single-use link under the delivery rate \
             limit; no account state changes",
        ),
    ),
    (
        "sid.v1.authn.AuthService/RequestOtp",
        Coverage::Ceremony(
            "each request opens its own code session under the rate limit; no \
             account state changes",
        ),
    ),
    (
        "sid.v1.authn.AuthService/RequestPasswordReset",
        Coverage::Ceremony(
            "each request issues its own single-use reset link under the delivery \
             rate limit; no account state changes",
        ),
    ),
    (
        "sid.v1.authn.AuthService/RequestStepUp",
        Coverage::Ceremony(
            "each request opens its own single-use challenge; nothing is elevated \
             before it completes",
        ),
    ),
    ("sid.v1.authn.AuthService/ResendEmailVerification", OFF),
    (
        "sid.v1.authn.AuthService/ResendOtp",
        Coverage::Ceremony(
            "a new code replaces the session's previous one under the rate limit; \
             no account state changes",
        ),
    ),
    ("sid.v1.authn.AuthService/ResendPhoneVerification", OFF),
    ("sid.v1.authn.AuthService/ResendSmsMfa", OFF),
    ("sid.v1.authn.AuthService/SelectOrganization", OFF),
    (
        "sid.v1.authn.AuthService/StartDeviceAuthorization",
        Coverage::Ceremony("RFC 8628 §3.2: each request issues its own device and user codes"),
    ),
    (
        "sid.v1.authn.AuthService/StartTotpEnrollment",
        Coverage::Ceremony(
            "each start opens its own pending enrollment; nothing is enrolled \
             before its finish",
        ),
    ),
    ("sid.v1.authn.AuthService/SubmitDeferredZkProof", OFF),
    (
        "sid.v1.authn.AuthService/SubmitDeviceUserCode",
        Coverage::Ceremony(
            "RFC 8628 §3.3: a user code is decided once; a repeat is refused as \
             decided and changes nothing",
        ),
    ),
    ("sid.v1.authn.AuthService/SubmitDynamicPrompt", OFF),
    (
        "sid.v1.authn.AuthService/VerifyCaptcha",
        Coverage::Ceremony("a solution counts once, for the challenge a sign-in was asked"),
    ),
    (
        "sid.v1.authn.AuthService/VerifyMagicLink",
        Coverage::Ceremony(
            "the link is single-use: a repeat finds it spent and creates no session",
        ),
    ),
    (
        "sid.v1.authn.AuthService/VerifyOtp",
        Coverage::Ceremony(
            "the code session is consumed by its first valid code; wrong codes \
             count toward its attempt limit",
        ),
    ),
    (
        "sid.v1.authn.AuthService/VerifyPasswordReset",
        Coverage::Ceremony("the reset link is consumed once into a reset session"),
    ),
    ("sid.v1.authn.AuthService/VerifyPhone", OFF),
    (
        "sid.v1.authn.AuthService/VerifyRecoveryCode",
        Coverage::Ceremony(
            "each recovery code is consumed once; a repeat of a used code is \
             refused",
        ),
    ),
    ("sid.v1.authn.AuthService/VerifySmsMfa", OFF),
    (
        "sid.v1.authn.AuthService/VerifyTotp",
        Coverage::Ceremony(
            "RFC 6238 §5.2: a time step's code is accepted once; a replayed code \
             is refused",
        ),
    ),
    (
        "sid.v1.authn.AuthService/WebAuthnAuthenticationFinish",
        Coverage::Ceremony(
            "WebAuthn §13.4.3: the challenge is single-use; a repeat finds it \
             spent and creates no session",
        ),
    ),
    (
        "sid.v1.authn.AuthService/WebAuthnRegistrationFinish",
        Coverage::Ceremony(
            "WebAuthn §13.4.3: the challenge is single-use; a repeat finds it \
             spent and registers nothing",
        ),
    ),
    (
        "sid.v1.identity.IdentityService/AcknowledgeExport",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/AddCredential",
        Coverage::NotServed,
    ),
    (
        "sid.v1.identity.IdentityService/AddPrincipal",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/CancelClosure",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/CreateProfile",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/DeleteProfile",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/PrepareExport",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RecordPasskeyPromptDismissal",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RemoveDevice",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RemovePrincipal",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RequestClosure",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RevokeCredential",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RevokeDeviceTrust",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/RevokeProfile",
        Coverage::Natural(
            "every cascade step ends only what is still active: a repeat ends what \
             an interrupted attempt left and nothing else, and counts what it ended",
        ),
    ),
    (
        "sid.v1.identity.IdentityService/RevokeSession",
        Coverage::Natural(
            "an ended session stays ended: a repeat finds none and answers as the \
             first, disclosing nothing",
        ),
    ),
    (
        "sid.v1.identity.IdentityService/TrustDevice",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/UpdateCredential",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/UpdateDevice",
        Coverage::Keyed,
    ),
    (
        "sid.v1.identity.IdentityService/UpdateProfile",
        Coverage::Keyed,
    ),
    (
        "sid.v1.admin.AdminService/AdminUpdateProfile",
        Coverage::Keyed,
    ),
    (
        "sid.v1.admin.AdminService/ClaimInstance",
        Coverage::Ceremony(
            "the installation claim is single-use: its token opens only an \
             unclaimed installation, so a repeat is refused and changes nothing",
        ),
    ),
    (
        "sid.v1.admin.AdminService/DeleteProfileMetadata",
        Coverage::Keyed,
    ),
    (
        "sid.v1.admin.AdminService/SetProfileMetadata",
        Coverage::Keyed,
    ),
    (
        "sid.v1.admin.AdminService/RevokeAllSessions",
        Coverage::Keyed,
    ),
    ("sid.v1.account.AccountService/AddEmail", Coverage::Keyed),
    ("sid.v1.account.AccountService/AddPhone", Coverage::Keyed),
    (
        "sid.v1.account.AccountService/DisablePasswordless",
        Coverage::NotServed,
    ),
    (
        "sid.v1.account.AccountService/DisconnectSite",
        Coverage::Keyed,
    ),
    (
        "sid.v1.account.AccountService/EnablePasswordless",
        Coverage::NotServed,
    ),
    (
        "sid.v1.account.AccountService/LaunchApp",
        Coverage::NotServed,
    ),
    (
        "sid.v1.account.AccountService/LinkAccount",
        Coverage::NotServed,
    ),
    (
        "sid.v1.account.AccountService/ReauthenticateLink",
        Coverage::NotServed,
    ),
    ("sid.v1.account.AccountService/RemoveEmail", Coverage::Keyed),
    ("sid.v1.account.AccountService/RemovePhone", Coverage::Keyed),
    (
        "sid.v1.account.AccountService/ReportSuspiciousEvent",
        Coverage::NotServed,
    ),
    (
        "sid.v1.account.AccountService/SetPrimaryEmail",
        Coverage::Keyed,
    ),
    (
        "sid.v1.account.AccountService/SetPrimaryPhone",
        Coverage::Keyed,
    ),
    (
        "sid.v1.account.AccountService/UnlinkAccount",
        Coverage::NotServed,
    ),
    (
        "sid.v1.account.AccountService/UpdateClaimConsent",
        Coverage::Keyed,
    ),
    ("sid.v1.account.AccountService/UpdateEmail", Coverage::Keyed),
    (
        "sid.v1.account.AccountService/UpdateNotificationPreferences",
        Coverage::NotServed,
    ),
    ("sid.v1.account.AccountService/UpdatePhone", Coverage::Keyed),
    (
        "sid.v1.projects.ProjectService/AddClientRole",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/AddResourceRole",
        Coverage::Keyed,
    ),
    ("sid.v1.projects.ProjectService/AddRole", Coverage::Keyed),
    (
        "sid.v1.projects.ProjectService/CreateApplication",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/CreateInitialAccessToken",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/CreateProject",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/DeleteApplication",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/DeleteProject",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/DeleteRegisteredClient",
        Coverage::Ceremony(
            "RFC 7592 §2.3: deletion invalidates the client and its registration \
             access token, so a repeat is refused and changes nothing",
        ),
    ),
    (
        "sid.v1.projects.ProjectService/RegisterClient",
        Coverage::Ceremony(
            "RFC 7591 §3: the client presents no operation key; each registration \
             issues a new client, its secret and registration access token once",
        ),
    ),
    (
        "sid.v1.projects.ProjectService/RemoveResourceAccess",
        Coverage::Keyed,
    ),
    ("sid.v1.projects.ProjectService/RemoveRole", Coverage::Keyed),
    (
        "sid.v1.projects.ProjectService/RevokeInitialAccessToken",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/SetResourceAccess",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateApplication",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateClientRole",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateProject",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateRegisteredClient",
        Coverage::Ceremony(
            "RFC 7592 §2.2: the request carries the client's whole metadata and \
             replaces it, so a repeat leaves the same registration",
        ),
    ),
    (
        "sid.v1.projects.ProjectService/UpdateResourceRole",
        Coverage::Keyed,
    ),
];
