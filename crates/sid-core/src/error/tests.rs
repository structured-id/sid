use super::*;

#[test]
fn test_error_display() {
    let e = Error::NotFound("profile xyz".into());
    assert_eq!(e.to_string(), "Not found: profile xyz");
}

fn all_errors() -> Vec<Error> {
    vec![
        Error::NotFound("t".into()),
        Error::Validation("t".into()),
        Error::AuthenticationFailed("t".into()),
        Error::AuthorizationDenied("t".into()),
        Error::Conflict("t".into()),
        Error::OperationCompleted("t".into()),
        Error::Fenced("t".into()),
        Error::Expired("t".into()),
        Error::Revoked("t".into()),
        Error::RateLimited("t".into()),
        Error::InvalidState("t".into()),
        Error::PolicyViolation("t".into()),
        Error::Unavailable("t".into()),
        Error::Storage("t".into()),
        Error::Internal("t".into()),
    ]
}

#[test]
fn test_error_display_all_variants() {
    // Verify all variants format correctly.
    let variants = all_errors();
    for v in &variants {
        assert!(v.to_string().contains('t'));
    }
    assert_eq!(variants.len(), 15);
}

#[test]
fn test_is_retryable() {
    assert!(Error::Unavailable("db down".into()).is_retryable());
    assert!(Error::RateLimited("too fast".into()).is_retryable());
    assert!(!Error::NotFound("nope".into()).is_retryable());
    assert!(!Error::AuthenticationFailed("wrong pw".into()).is_retryable());
    assert!(!Error::Internal("bug".into()).is_retryable());
    // A completed operation is resolved, never executed again.
    assert!(!Error::OperationCompleted("k".into()).is_retryable());
    // A fenced mutation committed nothing; deciding it again is safe.
    assert!(Error::Fenced("k".into()).is_retryable());
}

#[test]
fn test_is_client_error() {
    assert!(Error::NotFound("x".into()).is_client_error());
    assert!(Error::Validation("x".into()).is_client_error());
    assert!(Error::AuthenticationFailed("x".into()).is_client_error());
    assert!(Error::AuthorizationDenied("x".into()).is_client_error());
    assert!(Error::Conflict("x".into()).is_client_error());
    assert!(Error::OperationCompleted("x".into()).is_client_error());
    assert!(Error::Expired("x".into()).is_client_error());
    assert!(Error::Revoked("x".into()).is_client_error());
    assert!(Error::RateLimited("x".into()).is_client_error());
    assert!(Error::InvalidState("x".into()).is_client_error());
    assert!(Error::PolicyViolation("x".into()).is_client_error());
    // Server errors are not client errors.
    assert!(!Error::Storage("x".into()).is_client_error());
    assert!(!Error::Internal("x".into()).is_client_error());
    // Unavailable is retryable but NOT a client error.
    assert!(!Error::Unavailable("x".into()).is_client_error());
}

#[test]
fn test_is_server_error() {
    assert!(Error::Unavailable("x".into()).is_server_error());
    assert!(Error::Storage("x".into()).is_server_error());
    assert!(Error::Internal("x".into()).is_server_error());
    assert!(!Error::NotFound("x".into()).is_server_error());
    assert!(!Error::AuthenticationFailed("x".into()).is_server_error());
}

#[test]
fn test_client_server_exclusive() {
    // No error should be both client AND server.
    for e in &all_errors() {
        assert!(
            !(e.is_client_error() && e.is_server_error()),
            "Error '{}' is both client and server",
            e
        );
    }
}

#[test]
fn test_all_errors_classified() {
    // Every error must be client OR server (nothing unclassified).
    for e in &all_errors() {
        assert!(
            e.is_client_error() || e.is_server_error(),
            "Error '{}' is neither client nor server",
            e
        );
    }
}
