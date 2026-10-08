use prost::Message;
use sid_core::models::ProfileId;
use sid_proto::sid::v1::authn::OpaqueLoginStartRequest;

fn main() {
    let request = OpaqueLoginStartRequest::default();
    assert!(!ProfileId::generate().to_string().is_empty());
    assert_eq!(
        OpaqueLoginStartRequest::decode(request.encode_to_vec().as_slice()).expect("round trip"),
        request
    );
}
