// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// A handle reads back from its own text and from nothing else: the browser
/// sends it in a path, so one spelling names one connection. Bug prevented:
/// two spellings (upper case, a prefix) reaching the same record.
#[test]
fn a_handle_has_one_spelling() {
    let handle = EntryHandle::generate();
    let text = handle.to_string();
    assert_eq!(text.len(), EntryHandle::LEN);
    assert_eq!(EntryHandle::parse(&text), Ok(handle));
    assert_ne!(EntryHandle::generate(), handle);
    for malformed in [
        text.to_uppercase(),
        text[1..].to_owned(),
        format!("{text}0"),
        format!("0x{}", &text[2..]),
        String::new(),
    ] {
        // A handle of digits only has no upper case to differ by.
        if malformed == text {
            continue;
        }
        assert_eq!(EntryHandle::parse(&malformed), Err(MalformedHandle));
    }
}

/// An issuer identifier is an https URL without query or fragment (OpenID
/// Connect Core 1.0 §1.2); plain http only on a loopback host.
#[test]
fn an_issuer_identifier_is_an_https_url() {
    for issuer in [
        "https://sid.example.com",
        "https://sid.example.com/i/0123456789abcdef0123456789abcdef",
        "http://localhost:8080/i/x",
        "http://127.0.0.1:8080",
    ] {
        assert!(is_issuer_identifier(issuer), "{issuer}");
    }
    for other in [
        "http://sid.example.com",
        "https://sid.example.com/?a=1",
        "https://sid.example.com/#f",
        "ftp://sid.example.com",
        "sid.example.com",
        "",
    ] {
        assert!(!is_issuer_identifier(other), "{other}");
    }
}

/// The credential of one connection is sealed in a context no other
/// connection shares.
#[test]
fn a_credential_context_belongs_to_one_connection() {
    let (a, b) = (EntryHandle::generate(), EntryHandle::generate());
    assert_ne!(credential_context(a), credential_context(b));
    assert_eq!(credential_context(a), credential_context(a));
}
