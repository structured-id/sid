use super::*;

/// A handle is 32 hex characters from 16 random bytes: long enough that one
/// cannot be guessed, never derived from an organization or name.
#[test]
fn generated_handles_are_opaque_and_distinct() {
    let a = IssuerHandle::generate();
    let b = IssuerHandle::generate();
    assert_eq!(a.as_str().len(), IssuerHandle::LEN);
    assert_ne!(a, b);
    assert_eq!(IssuerHandle::parse(a.as_str()).unwrap(), a);
}

/// Only the exact generated shape is a handle: a request path segment that
/// is not one fails before any lookup.
#[test]
fn malformed_handles_are_refused() {
    for text in [
        "",
        "abc",
        "0123456789abcdef0123456789abcde",   // 31 characters
        "0123456789abcdef0123456789abcdef0", // 33 characters
        "0123456789ABCDEF0123456789ABCDEF",  // upper case
        "0123456789abcdef0123456789abcdeg",  // not hex
        "../3456789abcdef0123456789abcdef",  // path traversal
        "0123456789abcdef 123456789abcdef",  // space
    ] {
        assert!(IssuerHandle::parse(text).is_err(), "accepted {text:?}");
    }
}

/// A stored or transmitted handle is validated when it is read back.
#[test]
fn serde_refuses_a_malformed_handle() {
    let handle = IssuerHandle::generate();
    let json = serde_json::to_string(&handle).unwrap();
    assert_eq!(json, format!("\"{handle}\""));
    assert_eq!(serde_json::from_str::<IssuerHandle>(&json).unwrap(), handle);
    assert!(serde_json::from_str::<IssuerHandle>("\"../etc\"").is_err());
}

#[test]
fn authority_round_trips_and_refuses_unknown_values() {
    assert_eq!(
        "local".parse::<IssuerAuthority>().unwrap(),
        IssuerAuthority::Local
    );
    assert_eq!(IssuerAuthority::Local.as_str(), "local");
    assert!("global".parse::<IssuerAuthority>().is_err());
    assert!("".parse::<IssuerAuthority>().is_err());
}

/// The sealed private key is bound to its issuer and generation, so a sealed
/// value copied to another issuer's row does not open there.
#[test]
fn signing_key_context_names_issuer_and_generation() {
    let issuer = IssuerId::generate();
    let one = IssuerSigningKey::sealing_context(issuer, 1);
    assert_eq!(one, format!("oidc-issuer-key:{issuer}:1"));
    assert_ne!(one, IssuerSigningKey::sealing_context(issuer, 2));
    assert_ne!(
        one,
        IssuerSigningKey::sealing_context(IssuerId::generate(), 1)
    );
}

fn key_for(issuer_id: IssuerId, generation: u32) -> IssuerSigningKey {
    IssuerSigningKey {
        issuer_id,
        generation,
        key_id: "kid".into(),
        public_key: [7; 32],
        sealed_private_key: vec![1],
        created_at: chrono::Utc::now(),
    }
}

fn some_issuer() -> OidcIssuer {
    OidcIssuer {
        id: IssuerId::generate(),
        handle: IssuerHandle::generate(),
        canonical_url: "https://sid.example.com/i/x".into(),
        authority: IssuerAuthority::Local,
        recipient_org: OrgId::generate(),
        created_at: chrono::Utc::now(),
    }
}

/// An issuer is created with its own generation-1 key, never another
/// issuer's key or a later generation.
#[test]
fn first_key_must_be_the_issuers_generation_one() {
    let issuer = some_issuer();
    assert!(issuer.check_first_key(&key_for(issuer.id, 1)).is_ok());
    assert!(matches!(
        issuer.check_first_key(&key_for(IssuerId::generate(), 1)),
        Err(crate::Error::Validation(_))
    ));
    assert!(matches!(
        issuer.check_first_key(&key_for(issuer.id, 2)),
        Err(crate::Error::Validation(_))
    ));
    assert!(matches!(
        issuer.check_first_key(&key_for(issuer.id, 0)),
        Err(crate::Error::Validation(_))
    ));
}

/// A client belongs to the issuer of its own organization only: a client of
/// another organization, or of none, gets nothing from this issuer.
#[test]
fn an_issuer_serves_only_its_organizations_clients() {
    let issuer = some_issuer();
    assert!(issuer.serves(Some(issuer.recipient_org)));
    assert!(!issuer.serves(Some(OrgId::generate())));
    assert!(!issuer.serves(None));
}

/// Debug output never contains the sealed key bytes.
#[test]
fn signing_key_debug_hides_the_sealed_key() {
    let key = IssuerSigningKey {
        issuer_id: IssuerId::generate(),
        generation: 1,
        key_id: "kid".into(),
        public_key: [7; 32],
        sealed_private_key: vec![0xAB; 48],
        // A fixed time: the current one can itself contain "171".
        created_at: chrono::DateTime::UNIX_EPOCH,
    };
    let shown = format!("{key:?}");
    assert!(!shown.contains("171"), "sealed bytes printed: {shown}");
    assert!(shown.contains("REDACTED"));
}
