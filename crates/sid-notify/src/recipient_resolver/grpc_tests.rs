use super::*;
use sid_core::models::event::Event;
use sid_proto::sid::v1::identity::identity_service_server::{
    IdentityService, IdentityServiceServer,
};
use sid_proto::sid::v1::identity::*;
use tokio::net::TcpListener;
use tonic::transport::Server;

/// Mock identity service returning predetermined profile + identifiers.
/// Only `get_profile` and `list_identifiers` are implemented; all others
/// return UNIMPLEMENTED (never called by RecipientResolver).
struct MockIdentityService;

/// The Profile the mock identity service knows none of.
const MISSING: &str = "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e";

/// The Profile `CALLER_TOKEN` stands for.
const CALLER_PROFILE: &str = "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9f";

fn profile_id(text: &str) -> sid_ids::ProfileId {
    sid_ids::ProfileId::parse(text).unwrap()
}

/// Helper: build a default Profile proto with given id and email.
fn mock_profile(id: sid_ids::ProfileId, email: &str) -> Profile {
    Profile {
        id: Some(id.into()),
        profile_type: 0,
        username: Some("alice".into()),
        email: Some(email.into()),
        email_verified: true,
        phone: None,
        phone_verified: false,
        given_name: Some("Alice".into()),
        family_name: None,
        middle_name: None,
        honorific_prefix: None,
        honorific_suffix: None,
        formatted_name: Some("Alice".into()),
        principals: vec![],
        status: 0,
        visibility: 0,
        created_at: None,
        updated_at: None,
        last_login_at: None,
        avatar_url: None,
    }
}

/// Use `unimplemented_rpc!()` macro OUTSIDE #[tonic::async_trait] doesn't work.
/// Instead, define a helper module with a blanket stub implementation,
/// then override only the methods we need.
///
/// But tonic doesn't support default method impls, so we must implement all.
/// We use a wrapper that delegates to inner for get_profile + list_identifiers.

#[tonic::async_trait]
impl IdentityService for MockIdentityService {
    async fn get_profile(
        &self,
        request: tonic::Request<GetProfileRequest>,
    ) -> Result<tonic::Response<GetProfileResponse>, tonic::Status> {
        let req = request.into_inner();
        let id = match req.identifier {
            Some(get_profile_request::Identifier::Id(id)) => sid_ids_proto::required(Some(&id))
                .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?,
            _ => return Err(tonic::Status::invalid_argument("id required")),
        };
        if id == profile_id(MISSING) {
            return Err(tonic::Status::not_found("profile not found"));
        }
        Ok(tonic::Response::new(GetProfileResponse {
            profile: Some(mock_profile(id, "alice@sid.example.com")),
        }))
    }

    /// A named Profile's principals; with none named, the caller's own, as
    /// the identity service resolves them from the caller's token.
    async fn list_principals(
        &self,
        request: tonic::Request<ListPrincipalsRequest>,
    ) -> Result<tonic::Response<ListPrincipalsResponse>, tonic::Status> {
        let presented = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let req = request.into_inner();
        match req.profile_id.as_ref() {
            None if presented != Some(format!("Bearer {CALLER_TOKEN}")) => {
                return Err(tonic::Status::unauthenticated("authentication required"));
            }
            None => {}
            Some(named) => {
                let named = sid_ids_proto::required(Some(named))
                    .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
                if named == profile_id(MISSING) {
                    return Ok(tonic::Response::new(ListPrincipalsResponse {
                        principals: vec![],
                    }));
                }
            }
        }
        Ok(tonic::Response::new(ListPrincipalsResponse {
            principals: vec![
                Principal {
                    id: Some(sid_ids::PrincipalId::generate().into()),
                    r#type: PrincipalType::Email as i32,
                    value: "alice@sid.example.com".into(),
                    verified: true,
                    is_primary: true,
                    created_at: None,
                    updated_at: None,
                    source_field: Some("email".into()),
                    ..Default::default()
                },
                Principal {
                    id: Some(sid_ids::PrincipalId::generate().into()),
                    r#type: PrincipalType::Phone as i32,
                    value: "+380501234567".into(),
                    verified: true,
                    is_primary: true,
                    created_at: None,
                    updated_at: None,
                    source_field: Some("phone".into()),
                    ..Default::default()
                },
            ],
        }))
    }

    // Stream type for DownloadExport.
    type DownloadExportStream =
        tokio_stream::wrappers::ReceiverStream<Result<DownloadExportChunk, tonic::Status>>;

    // All RPCs below are stubs — only get_profile and list_identifiers are used.
    async fn create_profile(
        &self,
        _r: tonic::Request<CreateProfileRequest>,
    ) -> Result<tonic::Response<CreateProfileResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn update_profile(
        &self,
        _r: tonic::Request<UpdateProfileRequest>,
    ) -> Result<tonic::Response<UpdateProfileResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn delete_profile(
        &self,
        _r: tonic::Request<DeleteProfileRequest>,
    ) -> Result<tonic::Response<DeleteProfileResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn list_profiles(
        &self,
        _r: tonic::Request<ListProfilesRequest>,
    ) -> Result<tonic::Response<ListProfilesResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn add_credential(
        &self,
        _r: tonic::Request<AddCredentialRequest>,
    ) -> Result<tonic::Response<AddCredentialResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn list_credentials(
        &self,
        _r: tonic::Request<ListCredentialsRequest>,
    ) -> Result<tonic::Response<ListCredentialsResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn update_credential(
        &self,
        _r: tonic::Request<UpdateCredentialRequest>,
    ) -> Result<tonic::Response<UpdateCredentialResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn revoke_credential(
        &self,
        _r: tonic::Request<RevokeCredentialRequest>,
    ) -> Result<tonic::Response<RevokeCredentialResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn add_principal(
        &self,
        _r: tonic::Request<AddPrincipalRequest>,
    ) -> Result<tonic::Response<AddPrincipalResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn remove_principal(
        &self,
        _r: tonic::Request<RemovePrincipalRequest>,
    ) -> Result<tonic::Response<RemovePrincipalResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn list_sessions(
        &self,
        _r: tonic::Request<ListSessionsRequest>,
    ) -> Result<tonic::Response<ListSessionsResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn revoke_session(
        &self,
        _r: tonic::Request<RevokeSessionRequest>,
    ) -> Result<tonic::Response<RevokeSessionResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn get_passkey_prompt_state(
        &self,
        _r: tonic::Request<GetPasskeyPromptStateRequest>,
    ) -> Result<tonic::Response<GetPasskeyPromptStateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn record_passkey_prompt_dismissal(
        &self,
        _r: tonic::Request<RecordPasskeyPromptDismissalRequest>,
    ) -> Result<tonic::Response<RecordPasskeyPromptDismissalResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn revoke_profile(
        &self,
        _r: tonic::Request<RevokeProfileRequest>,
    ) -> Result<tonic::Response<RevokeProfileResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn request_closure(
        &self,
        _r: tonic::Request<RequestClosureRequest>,
    ) -> Result<tonic::Response<RequestClosureResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn cancel_closure(
        &self,
        _r: tonic::Request<CancelClosureRequest>,
    ) -> Result<tonic::Response<CancelClosureResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn get_closure_status(
        &self,
        _r: tonic::Request<GetClosureStatusRequest>,
    ) -> Result<tonic::Response<GetClosureStatusResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn prepare_export(
        &self,
        _r: tonic::Request<PrepareExportRequest>,
    ) -> Result<tonic::Response<PrepareExportResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    async fn get_export_status(
        &self,
        _r: tonic::Request<GetExportStatusRequest>,
    ) -> Result<tonic::Response<GetExportStatusResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }
    /// The caller of `CALLER_TOKEN` only, as the identity service resolves
    /// the Profile a token stands for.
    async fn get_current_profile(
        &self,
        r: tonic::Request<GetCurrentProfileRequest>,
    ) -> Result<tonic::Response<GetProfileResponse>, tonic::Status> {
        let presented = r
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        if presented != Some(&format!("Bearer {CALLER_TOKEN}")) {
            return Err(tonic::Status::unauthenticated("authentication required"));
        }
        Ok(tonic::Response::new(GetProfileResponse {
            profile: Some(mock_profile(
                profile_id(CALLER_PROFILE),
                "caller@sid.example.com",
            )),
        }))
    }
    async fn list_devices(
        &self,
        _r: tonic::Request<ListDevicesRequest>,
    ) -> Result<tonic::Response<ListDevicesResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stub"))
    }

    async fn download_export(
        &self,
        _: tonic::Request<DownloadExportRequest>,
    ) -> Result<tonic::Response<Self::DownloadExportStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }

    async fn acknowledge_export(
        &self,
        _: tonic::Request<AcknowledgeExportRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }

    async fn get_device(
        &self,
        _: tonic::Request<GetDeviceRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::identity::Device>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }

    async fn update_device(
        &self,
        _: tonic::Request<UpdateDeviceRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::identity::Device>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }

    async fn remove_device(
        &self,
        _: tonic::Request<RemoveDeviceRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }

    async fn trust_device(
        &self,
        _: tonic::Request<TrustDeviceRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::identity::Device>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }

    async fn revoke_device_trust(
        &self,
        _: tonic::Request<RevokeDeviceTrustRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::identity::Device>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed for test"))
    }
}

/// Start mock identity server on random port, return address.
async fn start_mock_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    tokio::spawn(async move {
        Server::builder()
            .add_service(IdentityServiceServer::new(MockIdentityService))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Give server a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;
    url
}

#[tokio::test]
async fn test_grpc_resolve_profile_with_email_and_phone() {
    let url = start_mock_server().await;
    let resolver = RecipientResolver::with_identity(&url).await.unwrap();

    let id = sid_ids::ProfileId::generate();
    let event =
        Event::new("sid-server", "sid.session.created.v1").with_subject(format!("profile/{id}"));

    let r = resolver.resolve(&event).await.unwrap();
    assert_eq!(r.profile_id, id.to_string());
    assert_eq!(r.email.as_deref(), Some("alice@sid.example.com"));
    assert_eq!(r.phone.as_deref(), Some("+380501234567"));
}

/// The access token the mock identity service resolves to its caller.
const CALLER_TOKEN: &str = "caller-token";

/// The caller's own Profile and addresses come from the identity service,
/// asked with the caller's own token: the Profile's email and its verified
/// phone. This is what a test send defaults to; another token learns
/// nothing.
#[tokio::test]
async fn test_grpc_current_contact_is_the_callers_own() {
    let url = start_mock_server().await;
    let resolver = RecipientResolver::with_identity(&url).await.unwrap();

    let bearer = format!("Bearer {CALLER_TOKEN}").parse().unwrap();
    let contact = resolver.current_contact(&bearer).await.unwrap();
    assert_eq!(
        contact,
        Some((
            CALLER_PROFILE.to_string(),
            Contact {
                email: Some("caller@sid.example.com".into()),
                phone: Some("+380501234567".into()),
            }
        ))
    );
    let other = "Bearer someone-else".parse().unwrap();
    assert!(matches!(
        resolver.current_contact(&other).await,
        Err(ResolveError::Unavailable(_))
    ));
}

#[tokio::test]
async fn test_grpc_resolve_caches_result() {
    let url = start_mock_server().await;
    let resolver = RecipientResolver::with_identity(&url).await.unwrap();

    let id = sid_ids::ProfileId::generate().to_string();
    let event =
        Event::new("sid-server", "sid.session.created.v1").with_subject(format!("profile/{id}"));

    // First call — gRPC.
    let r1 = resolver.resolve(&event).await.unwrap();
    assert_eq!(r1.email.as_deref(), Some("alice@sid.example.com"));

    // Second call — should hit cache (no gRPC).
    let cached = resolver.get_cached(&id).await;
    assert!(cached.is_some(), "should be cached after first resolve");

    let r2 = resolver.resolve(&event).await.unwrap();
    assert_eq!(r2.email.as_deref(), Some("alice@sid.example.com"));
}

#[tokio::test]
async fn test_grpc_resolve_not_found_is_profile_gone() {
    let url = start_mock_server().await;
    let resolver = RecipientResolver::with_identity(&url).await.unwrap();

    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject(format!("profile/{MISSING}"))
        .with_data(serde_json::json!({
            "email": "fallback@sid.example.com"
        }));

    // A deleted profile is not reached through data the event carried.
    let err = resolver.resolve(&event).await.unwrap_err();
    assert_eq!(err, ResolveError::ProfileGone(MISSING.into()));
}

/// A subject that is not a Profile id names no Profile that could exist:
/// the delivery gives up instead of retrying, and the service is never asked.
#[tokio::test]
async fn test_grpc_resolve_malformed_subject_is_profile_gone() {
    // No server: asking the identity service would be Unavailable.
    let resolver = RecipientResolver::with_identity("http://127.0.0.1:1")
        .await
        .unwrap();

    let event =
        Event::new("sid-server", "sid.session.created.v1").with_subject("profile/not-a-profile");

    let err = resolver.resolve(&event).await.unwrap_err();
    assert_eq!(err, ResolveError::ProfileGone("not-a-profile".into()));
}

#[tokio::test]
async fn test_grpc_resolve_unreachable_is_retryable() {
    // Point to a port with no server.
    let resolver = RecipientResolver::with_identity("http://127.0.0.1:1")
        .await
        .unwrap();

    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject(format!("profile/{}", sid_ids::ProfileId::generate()))
        .with_data(serde_json::json!({
            "email": "event-fallback@sid.example.com"
        }));

    // An unreachable identity service is a failure to retry, never a
    // silent switch to the event's data.
    let err = resolver.resolve(&event).await.unwrap_err();
    assert!(matches!(err, ResolveError::Unavailable(_)), "{err:?}");
}
