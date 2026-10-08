use super::*;

#[test]
fn test_domain_status_to_proto() {
    assert_eq!(
        domain_status_to_proto(DomainAccessRequestStatus::Pending),
        AccessRequestStatus::Pending as i32
    );
    assert_eq!(
        domain_status_to_proto(DomainAccessRequestStatus::Approved),
        AccessRequestStatus::Approved as i32
    );
    assert_eq!(
        domain_status_to_proto(DomainAccessRequestStatus::Denied),
        AccessRequestStatus::Denied as i32
    );
    assert_eq!(
        domain_status_to_proto(DomainAccessRequestStatus::Expired),
        AccessRequestStatus::Expired as i32
    );
    assert_eq!(
        domain_status_to_proto(DomainAccessRequestStatus::Cancelled),
        AccessRequestStatus::Cancelled as i32
    );
}
