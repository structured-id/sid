use super::*;
use tonic_types::ErrorDetails;

/// A status without details breaks the contract: the client has no reason
/// to switch on.
#[test]
fn bare_status_is_a_violation() {
    let why = violation(&Status::internal("bare"), &["structured.id"]).expect("violation");
    assert!(why.contains("without ErrorInfo"), "{why}");
}

/// ErrorInfo of another domain breaks it too: (domain, reason) is the
/// identity of the error, and the reason means nothing in a foreign domain.
#[test]
fn foreign_domain_is_a_violation() {
    let status = Status::with_error_details(
        tonic::Code::NotFound,
        "foreign",
        ErrorDetails::with_error_info("X", "example.com", []),
    );
    let why = violation(&status, &["structured.id"]).expect("violation");
    assert!(why.contains("example.com"), "{why}");
}

/// ErrorInfo in the service's domain keeps it.
#[test]
fn own_domain_is_canonical() {
    let status = Status::with_error_details(
        tonic::Code::NotFound,
        "own",
        ErrorDetails::with_error_info("X", "structured.id", []),
    );
    assert_eq!(violation(&status, &["structured.id"]), None);
}

/// A tier's service answers in the shared domain and its own: both keep the
/// contract, a third does not.
#[test]
fn tier_service_has_two_domains() {
    let domains = ["structured.id", "tier.structured.id"];
    let tier = Status::with_error_details(
        tonic::Code::NotFound,
        "tier",
        ErrorDetails::with_error_info("X", "tier.structured.id", []),
    );
    assert_eq!(violation(&tier, &domains), None);
    let other = Status::with_error_details(
        tonic::Code::NotFound,
        "other",
        ErrorDetails::with_error_info("X", "other.structured.id", []),
    );
    assert!(violation(&other, &domains).is_some());
}
