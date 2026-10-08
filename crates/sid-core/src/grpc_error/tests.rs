use super::*;

/// Every reason maps to its canonical code, and the code is the one clients see.
#[test]
fn reason_fixes_status_code() {
    for reason in ErrorReason::ALL {
        let status: tonic::Status = ApiError::new(reason, "detail").into();
        assert_eq!(status.code(), reason.grpc_code(), "{reason}");
    }
    assert_eq!(ErrorReason::ProfileNotFound.grpc_code(), Code::NotFound);
    assert_eq!(
        ErrorReason::EmailAlreadyRegistered.grpc_code(),
        Code::AlreadyExists
    );
    assert_eq!(
        ErrorReason::RateLimitExceeded.grpc_code(),
        Code::ResourceExhausted
    );
    assert_eq!(ErrorReason::InternalError.grpc_code(), Code::Internal);
}

/// Every status carries ErrorInfo with the reason string and the SID domain.
#[test]
fn every_status_carries_error_info() {
    for reason in ErrorReason::ALL {
        let status: tonic::Status = ApiError::new(reason, "detail").into();
        let (got, domain, _) = extract_error_info(&status).expect("ErrorInfo");
        assert_eq!(got, reason.as_str());
        assert_eq!(domain, DOMAIN_SID);
    }
}

/// Reason strings are unique, so a client switch cannot confuse two reasons.
#[test]
fn reason_strings_unique() {
    let mut seen = std::collections::HashSet::new();
    for reason in ErrorReason::ALL {
        assert!(seen.insert(reason.as_str()), "duplicate {reason}");
    }
}

/// Authentication failures never say what failed.
#[test]
fn auth_failure_message_is_generic() {
    for reason in [
        ErrorReason::AuthenticationFailed,
        ErrorReason::TokenExpired,
        ErrorReason::TokenInvalid,
    ] {
        let status: tonic::Status =
            ApiError::new(reason, "wrong password for alice@sid.example.com").into();
        assert_eq!(status.message(), GENERIC_AUTH_MESSAGE);
    }
}

/// An internal error never exposes its cause to the client.
#[test]
fn internal_error_message_is_generic() {
    let status: tonic::Status =
        ApiError::new(ErrorReason::InternalError, "relation \"x\" does not exist").into();
    assert_eq!(status.message(), GENERIC_INTERNAL_MESSAGE);
    let status: tonic::Status = ApiError::internal().into();
    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), GENERIC_INTERNAL_MESSAGE);
}

/// Other reasons keep the handler's message.
#[test]
fn ordinary_message_kept() {
    let status: tonic::Status =
        ApiError::new(ErrorReason::RateLimitExceeded, "too many requests").into();
    assert_eq!(status.message(), "too many requests");
}

/// Metadata and the domain reach ErrorInfo; a feature outside this build is
/// UNIMPLEMENTED with its own reason.
#[test]
fn metadata_and_domain_roundtrip() {
    let status: tonic::Status = ApiError::new(
        ErrorReason::FeatureNotAvailable,
        "SAML is not in this build",
    )
    .with_metadata("feature", "saml")
    .into();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    let (reason, domain, metadata) = extract_error_info(&status).unwrap();
    assert_eq!(reason, "FEATURE_NOT_AVAILABLE");
    assert_eq!(domain, DOMAIN_SID);
    assert_eq!(metadata.get("feature").map(String::as_str), Some("saml"));
}

/// Typed details travel with the status next to ErrorInfo.
#[test]
fn typed_details_roundtrip() {
    let status: tonic::Status = ApiError::new(ErrorReason::InvalidFieldValue, "bad input")
        .with_field_violation("email", "not an address")
        .with_precondition("STEP_UP", "acr", "urn:sid:acr:standard")
        .with_retry_after(Duration::from_secs(30))
        .with_localized_message("en", "Check the email address")
        .into();
    let details = status.get_error_details();
    let bad_request = details.bad_request().expect("BadRequest");
    assert_eq!(bad_request.field_violations[0].field, "email");
    let precondition = details.precondition_failure().expect("PreconditionFailure");
    assert_eq!(precondition.violations[0].r#type, "STEP_UP");
    assert_eq!(
        precondition.violations[0].description,
        "urn:sid:acr:standard"
    );
    let retry = details.retry_info().expect("RetryInfo");
    assert_eq!(retry.retry_delay, Some(Duration::from_secs(30)));
    let localized = details.localized_message().expect("LocalizedMessage");
    assert_eq!(localized.locale, "en");
    assert!(details.error_info().is_some());
}

/// A detail no canonical type carries travels as its own `Any` beside
/// ErrorInfo and the canonical details, with the canonical type URL.
#[test]
fn additional_detail_travels_beside_error_info() {
    let payload = prost_types::Duration {
        seconds: 7,
        nanos: 0,
    };
    let status: tonic::Status = ApiError::new(ErrorReason::CaptchaRequired, "solve it")
        .with_precondition("captcha", "sign-in", "solve the challenge")
        .with_detail("type.googleapis.com/test.Payload", &payload)
        .into();
    assert_eq!(status.code(), Code::FailedPrecondition);
    let decoded = <tonic_types::Status as prost::Message>::decode(status.details())
        .expect("google.rpc.Status");
    let extra = decoded
        .details
        .iter()
        .find(|d| d.type_url == "type.googleapis.com/test.Payload")
        .expect("additional detail");
    let back =
        <prost_types::Duration as prost::Message>::decode(extra.value.as_slice()).expect("payload");
    assert_eq!(back.seconds, 7);
    let details = status.get_error_details();
    assert_eq!(
        details.error_info().expect("ErrorInfo").reason,
        "CAPTCHA_REQUIRED"
    );
    assert!(details.precondition_failure().is_some());
}

/// A count limit travels as QuotaFailure naming the limit.
#[test]
fn quota_violation_roundtrip() {
    let status: tonic::Status = ApiError::new(ErrorReason::QuotaExceeded, "too many tokens")
        .with_quota_violation("personal_access_tokens", "at most 20 active tokens")
        .into();
    assert_eq!(status.code(), Code::ResourceExhausted);
    let quota = status.get_details_quota_failure().expect("QuotaFailure");
    assert_eq!(quota.violations[0].subject, "personal_access_tokens");
}

/// The one-call helper builds the same canonical status.
#[test]
fn status_with_error_info_helper() {
    let mut metadata = HashMap::new();
    metadata.insert("field".to_string(), "email".to_string());
    let status = status_with_error_info(ErrorReason::EmailAlreadyRegistered, "taken", metadata);
    assert_eq!(status.code(), Code::AlreadyExists);
    let (reason, _, metadata) = extract_error_info(&status).unwrap();
    assert_eq!(reason, "EMAIL_ALREADY_REGISTERED");
    assert_eq!(metadata.get("field").map(String::as_str), Some("email"));
}

/// A bare status has no ErrorInfo.
#[test]
fn bare_status_has_no_error_info() {
    assert!(extract_error_info(&tonic::Status::not_found("plain")).is_none());
}

/// The retry delay a status carries is read back; a status without RetryInfo
/// has none.
#[test]
fn retry_delay_roundtrip() {
    let status: tonic::Status = ApiError::new(ErrorReason::RateLimitExceeded, "slow down")
        .with_retry_after(Duration::from_secs(10))
        .into();
    assert_eq!(extract_retry_delay(&status), Some(Duration::from_secs(10)));
    let without: tonic::Status = ApiError::new(ErrorReason::RateLimitExceeded, "busy").into();
    assert_eq!(extract_retry_delay(&without), None);
}

/// A tier's own vocabulary, as a tier crate defines it.
#[derive(Debug, Clone, Copy)]
enum TierReason {
    WidgetNotFound,
}

impl Reason for TierReason {
    const DOMAIN: &'static str = "tier.structured.id";

    fn as_str(self) -> &'static str {
        "WIDGET_NOT_FOUND"
    }

    fn grpc_code(self) -> Code {
        Code::NotFound
    }
}

/// A tier's reason travels in the tier's domain with its own code and the
/// handler's message; the shared reasons stay in structured.id.
#[test]
fn tier_vocabulary_carries_its_domain() {
    let status: tonic::Status = ApiError::new(TierReason::WidgetNotFound, "no widget")
        .with_resource("widget", "w1")
        .into();
    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.message(), "no widget");
    let (reason, domain, _) = extract_error_info(&status).expect("ErrorInfo");
    assert_eq!(reason, "WIDGET_NOT_FOUND");
    assert_eq!(domain, "tier.structured.id");

    let shared: tonic::Status = ApiError::internal().into();
    let (_, domain, _) = extract_error_info(&shared).expect("ErrorInfo");
    assert_eq!(domain, DOMAIN_SID);
}
