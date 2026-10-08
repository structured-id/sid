use super::*;

#[test]
fn test_encrypted_field_roundtrip() {
    let field = EncryptedField {
        ciphertext: vec![1, 2, 3, 4, 5],
        nonce: [10; 12],
        key_version: 3,
        context: "totp:user-123".into(),
    };

    let bytes = field.to_bytes();
    let decoded = EncryptedField::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.key_version, 3);
    assert_eq!(decoded.nonce, [10; 12]);
    assert_eq!(decoded.context, "totp:user-123");
    assert_eq!(decoded.ciphertext, vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_encrypted_field_empty_context() {
    let field = EncryptedField {
        ciphertext: vec![99],
        nonce: [0; 12],
        key_version: 1,
        context: String::new(),
    };

    let bytes = field.to_bytes();
    let decoded = EncryptedField::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.context, "");
    assert_eq!(decoded.ciphertext, vec![99]);
}

#[test]
fn test_encrypted_field_empty_ciphertext() {
    let field = EncryptedField {
        ciphertext: Vec::new(),
        nonce: [4; 12],
        key_version: 7,
        context: "ctx".into(),
    };

    let decoded = EncryptedField::from_bytes(&field.to_bytes()).unwrap();
    assert!(decoded.ciphertext.is_empty());
    assert_eq!(decoded.key_version, 7);
}

#[test]
fn test_encrypted_field_too_short() {
    let result = EncryptedField::from_bytes(&[0; 10]);
    assert!(matches!(result, Err(EncryptedFieldError::InvalidFormat(_))));
}

#[test]
fn test_encrypted_field_empty_input() {
    let result = EncryptedField::from_bytes(&[]);
    assert!(matches!(result, Err(EncryptedFieldError::InvalidFormat(_))));
}

#[test]
fn test_encrypted_field_truncated_context() {
    // key_version(4) + nonce(12) + context_len(4) = 20, but context_len says 100
    let mut data = vec![0u8; 20];
    data[16..20].copy_from_slice(&100u32.to_le_bytes()); // context_len = 100
    let result = EncryptedField::from_bytes(&data);
    assert!(matches!(result, Err(EncryptedFieldError::InvalidFormat(_))));
}

#[test]
fn test_encrypted_field_invalid_utf8_context() {
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&[0xff, 0xfe]); // not valid UTF-8
    data.extend_from_slice(b"ciphertext");

    let result = EncryptedField::from_bytes(&data);
    assert!(matches!(result, Err(EncryptedFieldError::InvalidFormat(_))));
}

#[test]
fn test_encrypted_field_serde_roundtrip() {
    let field = EncryptedField {
        ciphertext: vec![9, 8, 7],
        nonce: [1; 12],
        key_version: 2,
        context: "device:psk".into(),
    };

    let json = serde_json::to_string(&field).unwrap();
    let back: EncryptedField = serde_json::from_str(&json).unwrap();

    assert_eq!(back.ciphertext, field.ciphertext);
    assert_eq!(back.nonce, field.nonce);
    assert_eq!(back.key_version, field.key_version);
    assert_eq!(back.context, field.context);
}
