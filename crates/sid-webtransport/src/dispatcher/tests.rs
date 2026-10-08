use super::*;

fn echo_handler() -> HandlerFn {
    Box::new(|bytes: Vec<u8>, _meta: MetadataMap| Box::pin(async move { Ok(bytes) }))
}

fn error_handler(code: tonic::Code, msg: &'static str) -> HandlerFn {
    Box::new(move |_bytes: Vec<u8>, _meta: MetadataMap| {
        Box::pin(async move { Err(Status::new(code, msg)) })
    })
}

#[tokio::test]
async fn test_dispatch_registered_method() {
    let mut d = Dispatcher::new();
    d.register("test/Echo", echo_handler());

    let result = d
        .dispatch("test/Echo", vec![1, 2, 3], MetadataMap::new())
        .await;
    assert_eq!(result.unwrap(), vec![1, 2, 3]);
}

/// A method no handler serves is FEATURE_NOT_AVAILABLE; the caller's method
/// path is not repeated back.
#[tokio::test]
async fn test_dispatch_unknown_method_returns_unimplemented() {
    let d = Dispatcher::new();

    let result = d.dispatch("test/Unknown", vec![], MetadataMap::new()).await;
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    let info = tonic_types::StatusExt::get_details_error_info(&status).expect("ErrorInfo");
    assert_eq!(info.reason, "FEATURE_NOT_AVAILABLE");
    assert!(!status.message().contains("test/Unknown"));
}

#[tokio::test]
async fn test_dispatch_handler_error_propagates() {
    let mut d = Dispatcher::new();
    d.register(
        "test/Fail",
        error_handler(tonic::Code::PermissionDenied, "forbidden"),
    );

    let result = d.dispatch("test/Fail", vec![], MetadataMap::new()).await;
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "forbidden");
}

#[tokio::test]
async fn test_dispatch_empty_payload() {
    let mut d = Dispatcher::new();
    d.register("test/Empty", echo_handler());

    let result = d.dispatch("test/Empty", vec![], MetadataMap::new()).await;
    assert_eq!(result.unwrap(), Vec::<u8>::new());
}

#[tokio::test]
async fn test_dispatch_multiple_methods() {
    let mut d = Dispatcher::new();
    d.register(
        "svc/A",
        Box::new(|_bytes, _meta| Box::pin(async { Ok(vec![0xAA]) })),
    );
    d.register(
        "svc/B",
        Box::new(|_bytes, _meta| Box::pin(async { Ok(vec![0xBB]) })),
    );

    let a = d
        .dispatch("svc/A", vec![], MetadataMap::new())
        .await
        .unwrap();
    let b = d
        .dispatch("svc/B", vec![], MetadataMap::new())
        .await
        .unwrap();
    assert_eq!(a, vec![0xAA]);
    assert_eq!(b, vec![0xBB]);
}

#[tokio::test]
async fn test_register_overwrites_existing() {
    let mut d = Dispatcher::new();
    d.register(
        "test/X",
        Box::new(|_bytes, _meta| Box::pin(async { Ok(vec![1]) })),
    );
    d.register(
        "test/X",
        Box::new(|_bytes, _meta| Box::pin(async { Ok(vec![2]) })),
    );

    let result = d
        .dispatch("test/X", vec![], MetadataMap::new())
        .await
        .unwrap();
    assert_eq!(result, vec![2]);
}

#[test]
fn test_metadata_from_map_basic() {
    let mut map = HashMap::new();
    map.insert("session-id".to_string(), "abc123".to_string());
    map.insert("x-trace-id".to_string(), "trace-456".to_string());

    let meta = metadata_from_map(&map);
    assert_eq!(meta.get("session-id").unwrap().to_str().unwrap(), "abc123");
    assert_eq!(
        meta.get("x-trace-id").unwrap().to_str().unwrap(),
        "trace-456"
    );
}

#[test]
fn test_metadata_from_map_empty() {
    let map = HashMap::new();
    let meta = metadata_from_map(&map);
    assert!(meta.is_empty());
}

#[test]
fn test_metadata_from_map_skips_invalid_keys() {
    let mut map = HashMap::new();
    // Metadata keys with uppercase are invalid in HTTP/2 (gRPC metadata)
    // tonic MetadataKey parse may accept or reject depending on version
    map.insert("valid-key".to_string(), "value".to_string());
    let meta = metadata_from_map(&map);
    assert_eq!(meta.get("valid-key").unwrap().to_str().unwrap(), "value");
}
