use prost::Message;
use sid_proto::sid::v1::authn::OpaqueLoginStartRequest;

fn main() {
    let request = OpaqueLoginStartRequest::default();
    let bytes = request.encode_to_vec();
    let decoded = OpaqueLoginStartRequest::decode(bytes.as_slice()).expect("round trip");
    assert_eq!(decoded, request);
}
