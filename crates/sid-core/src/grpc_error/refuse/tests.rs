use super::*;
use tonic::Code;
use tonic_types::StatusExt;

/// An internal failure never reaches the client with its cause.
#[test]
fn internal_hides_the_cause() {
    let status = internal("load", "relation \"x\" does not exist");
    assert_eq!(status.code(), Code::Internal);
    assert!(!status.message().contains("relation"));
    assert_eq!(
        status.get_error_details().error_info().unwrap().reason,
        "INTERNAL_ERROR"
    );
}

/// A storage failure is an internal failure that hides its cause too.
#[test]
fn storage_failure_hides_the_cause() {
    let status = storage_failure("connection reset by peer");
    assert_eq!(status.code(), Code::Internal);
    assert!(!status.message().contains("reset"));
}

/// Field refusals name the field in BadRequest, not the submitted value.
#[test]
fn field_refusals_carry_bad_request() {
    let missing = missing_field("cidr");
    assert_eq!(missing.code(), Code::InvalidArgument);
    let violation = &missing.get_details_bad_request().unwrap().field_violations[0];
    assert_eq!(violation.field, "cidr");

    let invalid = invalid_field("page_token", "not a token this service issued");
    assert_eq!(
        invalid.get_error_details().error_info().unwrap().reason,
        "INVALID_FIELD_VALUE"
    );
    assert_eq!(
        invalid.get_details_bad_request().unwrap().field_violations[0].field,
        "page_token"
    );
}

/// NOT_FOUND names the resource kind and its name in ResourceInfo.
#[test]
fn not_found_carries_resource_info() {
    let status = not_found(ErrorReason::RoleNotFound, "Role", "admin");
    assert_eq!(status.code(), Code::NotFound);
    let resource = status.get_details_resource_info().unwrap();
    assert_eq!(resource.resource_type, "Role");
    assert_eq!(resource.resource_name, "admin");
}

/// ABORTED and UNAVAILABLE say when to retry.
#[test]
fn retryable_refusals_carry_retry_info() {
    let aborted = changed_concurrently();
    assert_eq!(aborted.code(), Code::Aborted);
    assert_eq!(
        aborted.get_details_retry_info().unwrap().retry_delay,
        Some(Duration::ZERO)
    );
    let unavailable = dependency_unavailable("cache", "connection refused");
    assert_eq!(unavailable.code(), Code::Unavailable);
    assert!(!unavailable.message().contains("refused"));
    assert_eq!(
        unavailable.get_details_retry_info().unwrap().retry_delay,
        Some(DEPENDENCY_RETRY_AFTER)
    );
}

/// Maintenance is UNAVAILABLE with its own reason and a polling interval.
#[test]
fn maintenance_says_when_to_poll() {
    let status = maintenance();
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(
        status.get_error_details().error_info().unwrap().reason,
        "SERVICE_MAINTENANCE"
    );
    assert_eq!(
        status.get_details_retry_info().unwrap().retry_delay,
        Some(MAINTENANCE_RETRY_AFTER)
    );
}

/// A feature outside the build names the feature and no edition.
#[test]
fn not_in_this_build_names_no_edition() {
    let status = not_in_this_build("password_policy");
    assert_eq!(status.code(), Code::Unimplemented);
    let info = status.get_error_details().error_info().unwrap().clone();
    assert_eq!(info.reason, "FEATURE_NOT_AVAILABLE");
    assert_eq!(info.metadata.get("feature").unwrap(), "password_policy");
    assert!(!status.message().contains("EE") && !status.message().contains("CE"));
}

/// A feature this installation switched off is a precondition an
/// administrator can meet, naming the feature.
#[test]
fn not_configured_names_the_feature() {
    let status = not_configured("magic_links");
    assert_eq!(status.code(), Code::FailedPrecondition);
    let info = status.get_error_details().error_info().unwrap().clone();
    assert_eq!(info.reason, "FEATURE_NOT_CONFIGURED");
    assert_eq!(info.metadata.get("feature").unwrap(), "magic_links");
}
