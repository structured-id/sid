use super::*;

#[test]
fn test_operation_key_accepts_visible_ascii() {
    assert_eq!(
        OperationKey::parse("8e03978e-40d5-43e8-bc93-6894a57f9324")
            .unwrap()
            .as_str(),
        "8e03978e-40d5-43e8-bc93-6894a57f9324"
    );
    assert!(OperationKey::parse(&"k".repeat(MAX_OPERATION_KEY_LEN)).is_ok());
}

/// Empty, overlong, whitespace and non-ASCII keys are refused before any
/// effect.
#[test]
fn test_operation_key_rejects_malformed() {
    for bad in [
        String::new(),
        "k".repeat(MAX_OPERATION_KEY_LEN + 1),
        "has space".to_string(),
        "tab\tkey".to_string(),
        "ключ".to_string(),
    ] {
        assert!(OperationKey::parse(&bad).is_err(), "{bad:?}");
    }
}

/// A key read from a snapshot is validated like one from a request.
#[test]
fn test_operation_key_deserialization_validates() {
    let key: OperationKey = serde_json::from_str("\"k-1\"").unwrap();
    assert_eq!(key.as_str(), "k-1");
    assert_eq!(serde_json::to_string(&key).unwrap(), "\"k-1\"");
    assert!(serde_json::from_str::<OperationKey>("\"has space\"").is_err());
    assert!(serde_json::from_str::<OperationKey>("\"\"").is_err());
}

/// A record matches only the same method with the same inputs.
#[test]
fn test_record_matches_same_call_only() {
    let key = OperationKey::parse("k1").unwrap();
    let record = OperationRecord {
        completion: OperationCompletion::new(
            "profile:p",
            key,
            "sid.v1.ProjectService/CreateProject",
            b"inputs",
            b"result".to_vec(),
        ),
        completed_at: Utc::now(),
    };
    assert!(record.matches("sid.v1.ProjectService/CreateProject", b"inputs"));
    assert!(!record.matches("sid.v1.ProjectService/CreateProject", b"other"));
    assert!(!record.matches("sid.v1.ProjectService/DeleteProject", b"inputs"));
}
