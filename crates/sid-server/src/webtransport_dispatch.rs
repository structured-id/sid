// SPDX-License-Identifier: AGPL-3.0-only
//! WebTransport method registration for all CE services.
//!
//! Bridges the WebTransport dispatcher to the existing tonic service
//! trait implementations (AuthService, IdentityService).

use crate::grpc::auth_service::AuthServiceImpl;
use crate::grpc::identity_service::IdentityServiceImpl;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use sid_webtransport::dispatcher::Dispatcher;
use sid_webtransport::register_rpc;
use std::sync::Arc;

/// Register all CE RPC methods on the dispatcher.
pub fn register_all(
    identity_svc: &Arc<IdentityServiceImpl>,
    auth_svc: &Arc<AuthServiceImpl>,
) -> Dispatcher {
    let mut d = Dispatcher::new();

    // ── AuthService ──

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OpaqueRegistrationStart",
        opaque_registration_start,
        OpaqueRegistrationStartRequest,
        OpaqueRegistrationStartResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OpaqueRegistrationFinish",
        opaque_registration_finish,
        OpaqueRegistrationFinishRequest,
        OpaqueRegistrationFinishResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OpaqueLoginStart",
        opaque_login_start,
        OpaqueLoginStartRequest,
        OpaqueLoginStartResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OpaqueLoginFinish",
        opaque_login_finish,
        OpaqueLoginFinishRequest,
        OpaqueLoginFinishResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OpaqueZkppRegistrationStart",
        opaque_zkpp_registration_start,
        OpaqueZkppRegistrationStartRequest,
        OpaqueZkppRegistrationStartResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OpaqueZkppRegistrationFinish",
        opaque_zkpp_registration_finish,
        OpaqueZkppRegistrationFinishRequest,
        OpaqueZkppRegistrationFinishResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/PasswordChangeChallenge",
        password_change_challenge,
        PasswordChangeChallengeRequest,
        PasswordChangeChallengeResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/PasswordChangeExecute",
        password_change_execute,
        PasswordChangeExecuteRequest,
        PasswordChangeExecuteResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/PasswordChangeFinish",
        password_change_finish,
        PasswordChangeFinishRequest,
        PasswordChangeFinishResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/ExecutePasswordReset",
        execute_password_reset,
        ExecutePasswordResetRequest,
        ExecutePasswordResetResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/WebAuthnRegistrationStart",
        web_authn_registration_start,
        WebAuthnRegistrationStartRequest,
        WebAuthnRegistrationStartResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/WebAuthnRegistrationFinish",
        web_authn_registration_finish,
        WebAuthnRegistrationFinishRequest,
        WebAuthnRegistrationFinishResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/WebAuthnAuthenticationStart",
        web_authn_authentication_start,
        WebAuthnAuthenticationStartRequest,
        WebAuthnAuthenticationStartResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/WebAuthnAuthenticationFinish",
        web_authn_authentication_finish,
        WebAuthnAuthenticationFinishRequest,
        WebAuthnAuthenticationFinishResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OAuth2Authorize",
        o_auth2_authorize,
        OAuth2AuthorizeRequest,
        OAuth2AuthorizeResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OAuth2Token",
        o_auth2_token,
        OAuth2TokenRequest,
        OAuth2TokenResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OAuth2Introspect",
        o_auth2_introspect,
        OAuth2IntrospectRequest,
        OAuth2IntrospectResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/OAuth2Revoke",
        o_auth2_revoke,
        OAuth2RevokeRequest,
        OAuth2RevokeResponse
    );

    register_rpc!(
        d,
        auth_svc,
        "sid.v1.AuthService/ValidateSession",
        validate_session,
        ValidateSessionRequest,
        ValidateSessionResponse
    );

    // ── IdentityService ──

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/CreateProfile",
        create_profile,
        CreateProfileRequest,
        CreateProfileResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/GetProfile",
        get_profile,
        GetProfileRequest,
        GetProfileResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/UpdateProfile",
        update_profile,
        UpdateProfileRequest,
        UpdateProfileResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/DeleteProfile",
        delete_profile,
        DeleteProfileRequest,
        DeleteProfileResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/ListProfiles",
        list_profiles,
        ListProfilesRequest,
        ListProfilesResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/AddCredential",
        add_credential,
        AddCredentialRequest,
        AddCredentialResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/ListCredentials",
        list_credentials,
        ListCredentialsRequest,
        ListCredentialsResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/RevokeCredential",
        revoke_credential,
        RevokeCredentialRequest,
        RevokeCredentialResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/ListSessions",
        list_sessions,
        ListSessionsRequest,
        ListSessionsResponse
    );

    register_rpc!(
        d,
        identity_svc,
        "sid.v1.IdentityService/RevokeSession",
        revoke_session,
        RevokeSessionRequest,
        RevokeSessionResponse
    );

    d
}

/// Register TestService RPC methods on the dispatcher (dev-only).
#[cfg(feature = "dev-perf-test")]
pub fn register_test_service(
    d: &mut Dispatcher,
    test_svc: &Arc<crate::grpc::test_service::TestServiceImpl>,
) {
    use sid_proto::sid::v1::test_service_server::TestService;

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/PerfRegistrationStart",
        perf_registration_start,
        PerfTestRequest,
        PerfTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/PerfRegistrationFinish",
        perf_registration_finish,
        PerfTestFinishRequest,
        PerfTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/PerfLoginStart",
        perf_login_start,
        PerfTestRequest,
        PerfTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/PerfLoginFinish",
        perf_login_finish,
        PerfTestFinishRequest,
        PerfTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/PerfVerifyEnvelope",
        perf_verify_envelope,
        PerfTestRequest,
        PerfTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestRegister",
        auth_test_register,
        AuthTestRequest,
        AuthTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestLogin",
        auth_test_login,
        AuthTestRequest,
        AuthTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestChangePassword",
        auth_test_change_password,
        AuthTestChangePasswordRequest,
        AuthTestResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestCheckPolicy",
        auth_test_check_policy,
        AuthTestCheckPolicyRequest,
        AuthTestCheckPolicyResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestReset",
        auth_test_reset,
        AuthTestResetRequest,
        AuthTestResetResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestSetPolicy",
        auth_test_set_policy,
        AuthTestSetPolicyRequest,
        AuthTestSetPolicyResponse
    );

    register_rpc!(
        d,
        test_svc,
        "sid.v1.TestService/AuthTestGetPolicy",
        auth_test_get_policy,
        AuthTestGetPolicyRequest,
        AuthTestGetPolicyResponse
    );
}
