use super::*;

/// Each request state answers as its own wire value.
#[test]
fn test_status_to_proto() {
    for (domain, wire) in [
        (DomainStatus::Pending, AccessRequestStatus::Pending),
        (DomainStatus::Approved, AccessRequestStatus::Approved),
        (DomainStatus::Denied, AccessRequestStatus::Denied),
        (DomainStatus::Expired, AccessRequestStatus::Expired),
        (DomainStatus::Cancelled, AccessRequestStatus::Cancelled),
    ] {
        assert_eq!(status_to_proto(domain), wire as i32);
    }
}
