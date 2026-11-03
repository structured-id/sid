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

/// Empty, overlong, control and non-ASCII keys are refused before any
/// effect; a space is a character a Structured Field String carries.
#[test]
fn test_operation_key_rejects_malformed() {
    for bad in [
        String::new(),
        "k".repeat(MAX_OPERATION_KEY_LEN + 1),
        "tab\tkey".to_string(),
        "ключ".to_string(),
    ] {
        assert!(OperationKey::parse(&bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        OperationKey::parse("has space").unwrap().as_str(),
        "has space"
    );
}

/// A key read from a snapshot is validated like one from a request.
#[test]
fn test_operation_key_deserialization_validates() {
    let key: OperationKey = serde_json::from_str("\"k-1\"").unwrap();
    assert_eq!(key.as_str(), "k-1");
    assert_eq!(serde_json::to_string(&key).unwrap(), "\"k-1\"");
    assert!(serde_json::from_str::<OperationKey>("\"tab\\tkey\"").is_err());
    assert!(serde_json::from_str::<OperationKey>("\"\"").is_err());
}

/// The header carries a Structured Field String (RFC 9651 §3.3.3): its
/// quotes and escapes are removed once, so the domain key is the logical
/// value, and encoding it gives back the same header.
#[test]
fn test_operation_key_header_is_a_structured_field_string() {
    let key = OperationKey::from_header("\"8e03978e-40d5\"").unwrap();
    assert_eq!(key.as_str(), "8e03978e-40d5");
    assert_eq!(key.to_header(), "\"8e03978e-40d5\"");

    let escaped = OperationKey::from_header(r#""a\"b\\c d""#).unwrap();
    assert_eq!(escaped.as_str(), r#"a"b\c d"#);
    assert_eq!(escaped.to_header(), r#""a\"b\\c d""#);
}

/// A bare token, an unbalanced quote, an unknown escape, an inner quote or an
/// empty string is not a key: the call is refused, never given a new key.
#[test]
fn test_operation_key_header_rejects_non_strings() {
    for bad in [
        "8e03978e",
        "\"unterminated",
        "unopened\"",
        r#""bad \n escape""#,
        r#""in"ner""#,
        "\"\"",
        r#""trailing\""#,
    ] {
        assert!(OperationKey::from_header(bad).is_err(), "{bad:?}");
    }
}

/// A period is one canonical unsigned decimal: no sign, no leading zero
/// except `0`, nothing beyond u64.
#[test]
fn test_operation_period_parses_canonical_decimal_only() {
    assert_eq!(OperationPeriod::parse("0").unwrap().get(), 0);
    assert_eq!(OperationPeriod::parse("42").unwrap().get(), 42);
    assert_eq!(
        OperationPeriod::parse("18446744073709551615")
            .unwrap()
            .get(),
        u64::MAX
    );
    for bad in [
        "",
        "-1",
        "+1",
        "01",
        "00",
        "1.0",
        " 1",
        "18446744073709551616",
        "x",
    ] {
        assert!(OperationPeriod::parse(bad).is_err(), "{bad:?}");
    }
    assert_eq!(OperationPeriod::new(7).to_string(), "7");
}

/// A record matches only the same method with the same inputs under the
/// same period.
#[test]
fn test_record_matches_same_call_only() {
    let key = OperationKey::parse("k1").unwrap();
    let period = Some(OperationPeriod::new(3));
    let record = OperationRecord {
        completion: OperationCompletion::new(
            "profile:p",
            key,
            "sid.v1.ProjectService/CreateProject",
            b"inputs",
            b"result".to_vec(),
        )
        .in_period(OperationPeriod::new(3)),
        completed_at: Utc::now(),
    };
    assert!(record.matches("sid.v1.ProjectService/CreateProject", b"inputs", period));
    assert!(!record.matches("sid.v1.ProjectService/CreateProject", b"other", period));
    assert!(!record.matches("sid.v1.ProjectService/DeleteProject", b"inputs", period));
    assert!(!record.matches(
        "sid.v1.ProjectService/CreateProject",
        b"inputs",
        Some(OperationPeriod::new(4))
    ));
    assert!(!record.matches("sid.v1.ProjectService/CreateProject", b"inputs", None));
}
