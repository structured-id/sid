use super::*;
use sid_core::grpc_error::extract_error_info;
use tower::{Layer, Service, ServiceExt};

fn metadata(keys: &[&str], periods: &[&str]) -> MetadataMap {
    let mut map = MetadataMap::new();
    for key in keys {
        map.append(OPERATION_KEY_HEADER, key.parse().unwrap());
    }
    for period in periods {
        map.append(OPERATION_PERIOD_HEADER, period.parse().unwrap());
    }
    map
}

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

/// The key is decoded from its Structured Field String, the period from its
/// decimal.
#[test]
fn test_context_reads_both_values() {
    let context = metadata_context(&metadata(&[r#""k \"1\"""#], &["42"])).unwrap();
    assert_eq!(context.key.as_str(), r#"k "1""#);
    assert_eq!(context.period, OperationPeriod::new(42));
}

/// A missing, malformed or repeated value is refused, never replaced with a
/// new key or the current period.
#[test]
fn test_context_refuses_missing_malformed_and_repeated() {
    let missing_key = metadata_context(&metadata(&[], &["1"])).unwrap_err();
    assert_eq!(missing_key.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&missing_key), "REQUIRED_FIELD_MISSING");
    let missing_period = metadata_context(&metadata(&[r#""k""#], &[])).unwrap_err();
    assert_eq!(reason(&missing_period), "REQUIRED_FIELD_MISSING");

    // A bare token is not a Structured Field String.
    let bare = metadata_context(&metadata(&["k"], &["1"])).unwrap_err();
    assert_eq!(reason(&bare), "INVALID_FIELD_VALUE");
    let padded = metadata_context(&metadata(&[r#""k""#], &["01"])).unwrap_err();
    assert_eq!(reason(&padded), "INVALID_FIELD_VALUE");

    let twice = metadata_context(&metadata(&[r#""a""#, r#""b""#], &["1"])).unwrap_err();
    assert_eq!(reason(&twice), "INVALID_FIELD_VALUE");
    let two_periods = metadata_context(&metadata(&[r#""a""#], &["1", "2"])).unwrap_err();
    assert_eq!(reason(&two_periods), "INVALID_FIELD_VALUE");
}

/// What the inner service saw of a call.
#[derive(Clone, Default)]
struct Seen(std::sync::Arc<std::sync::Mutex<Vec<Option<OperationContext>>>>);

impl tower::Service<http::Request<()>> for Seen {
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<()>) -> Self::Future {
        self.0
            .lock()
            .unwrap()
            .push(request.extensions().get::<OperationContext>().cloned());
        std::future::ready(Ok(http::Response::new(tonic::body::Body::empty())))
    }
}

fn call(path: &str, headers: &[(&str, &str)]) -> http::Request<()> {
    let mut request = http::Request::builder().uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(()).unwrap()
}

/// A keyed method is not reached without its context and gets the decoded
/// context when it has one; another method passes untouched.
#[tokio::test]
async fn test_layer_admits_keyed_calls_with_context_only() {
    let seen = Seen::default();
    let mut service = OperationContextLayer.layer(seen.clone());
    let keyed = "/sid.v1.projects.ProjectService/CreateProject";
    assert!(sid_proto::keyed::is_keyed_path(keyed));

    let refused = service
        .ready()
        .await
        .unwrap()
        .call(call(keyed, &[]))
        .await
        .unwrap();
    let status = Status::from_header_map(refused.headers()).expect("a gRPC status");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(seen.0.lock().unwrap().is_empty(), "the method never ran");

    service
        .ready()
        .await
        .unwrap()
        .call(call(
            keyed,
            &[
                (OPERATION_KEY_HEADER, r#""k-1""#),
                (OPERATION_PERIOD_HEADER, "3"),
            ],
        ))
        .await
        .unwrap();
    service
        .ready()
        .await
        .unwrap()
        .call(call("/sid.v1.projects.ProjectService/GetProject", &[]))
        .await
        .unwrap();
    let seen = seen.0.lock().unwrap();
    assert_eq!(
        *seen,
        vec![
            Some(OperationContext::new(
                OperationKey::parse("k-1").unwrap(),
                OperationPeriod::new(3)
            )),
            None,
        ]
    );
}
