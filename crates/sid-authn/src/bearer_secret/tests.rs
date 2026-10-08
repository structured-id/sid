use super::*;
use secrecy::ExposeSecret;

/// A secret is its prefix and 43 base64url characters (32 random bytes).
#[test]
fn issued_secret_carries_its_prefix_and_full_entropy() {
    let issued = issue("sidscim_");
    let secret = issued.secret.expose_secret();
    let body = secret.strip_prefix("sidscim_").expect("prefix");
    assert_eq!(body.len(), 43);
    assert!(
        body.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
}

/// Two secrets are never the same, nor their verifiers.
#[test]
fn issued_secrets_are_distinct() {
    let a = issue("p_");
    let b = issue("p_");
    assert_ne!(a.secret.expose_secret(), b.secret.expose_secret());
    assert_ne!(a.verifier, b.verifier);
}

/// The stored verifier is the SHA-256 of the whole secret, prefix included,
/// as lowercase hex; it is never the secret itself.
#[test]
fn verifier_is_the_digest_of_the_secret() {
    let issued = issue("p_");
    assert_eq!(issued.verifier, verifier_of(issued.secret.expose_secret()));
    assert_eq!(issued.verifier.len(), 64);
    assert_ne!(issued.verifier, *issued.secret.expose_secret());
}

/// Only the secret matches its verifier: a changed character, a missing
/// prefix or another secret does not.
#[test]
fn only_the_secret_matches_its_verifier() {
    let issued = issue("p_");
    let secret = issued.secret.expose_secret().clone();
    assert!(matches(&secret, &issued.verifier));
    let mut altered = secret.clone();
    let last = altered.pop().expect("non-empty");
    altered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(!matches(&altered, &issued.verifier));
    assert!(!matches(secret.trim_start_matches("p_"), &issued.verifier));
    assert!(!matches(
        issue("p_").secret.expose_secret(),
        &issued.verifier
    ));
}

/// A verifier of another length never matches (no prefix comparison).
#[test]
fn a_truncated_verifier_never_matches() {
    let issued = issue("p_");
    let secret = issued.secret.expose_secret();
    assert!(!matches(secret, &issued.verifier[..32]));
    assert!(!matches(secret, ""));
}

/// The secret's form is recognised by its prefix alone, so an endpoint can
/// tell its own credential kind apart before any lookup.
#[test]
fn has_prefix_recognises_the_form_only() {
    let issued = issue("sidscim_");
    assert!(has_prefix(issued.secret.expose_secret(), "sidscim_"));
    assert!(!has_prefix("sidscim_", "sidscim_"));
    assert!(!has_prefix("eyJhbGciOiJFZERTQSJ9.e30.sig", "sidscim_"));
}
