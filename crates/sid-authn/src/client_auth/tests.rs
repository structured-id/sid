use super::*;
use secrecy::ExposeSecret;

fn basic(raw: &str) -> String {
    format!("Basic {}", STANDARD.encode(raw))
}

fn parse(
    authorization: Option<&str>,
    client_id: Option<&str>,
    secret: Option<&str>,
    assertion: Option<&str>,
) -> Result<ClientAuthentication, TokenError> {
    ClientAuthentication::from_request(
        authorization,
        client_id,
        secret,
        assertion,
        Some(JWT_BEARER_ASSERTION_TYPE),
    )
}

/// Each method is recognized with its client and credential.
#[test]
fn test_methods() {
    let auth = parse(Some(&basic("app:s3cret")), None, None, None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::ClientSecretBasic);
    assert_eq!(auth.client_id(), "app");
    assert_eq!(auth.secret().unwrap().expose_secret(), "s3cret");

    let auth = parse(None, Some("app"), Some("s3cret"), None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::ClientSecretPost);
    assert_eq!(auth.secret().unwrap().expose_secret(), "s3cret");

    let auth = parse(None, Some("app"), None, Some("jwt")).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::PrivateKeyJwt);
    assert!(auth.secret().is_none());

    let auth = parse(None, Some("app"), None, None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::None);
    assert_eq!(auth.client_id(), "app");
}

/// Basic credentials are form-urlencoded before encoding (RFC 6749 §2.3.1);
/// only the first colon separates them (RFC 7617 §2); the scheme name is
/// case-insensitive.
#[test]
fn test_basic_decoding() {
    let auth = parse(Some(&basic("my%3Aapp:a%2Bb+c:d%")), None, None, None).unwrap();
    assert_eq!(auth.client_id(), "my:app");
    assert_eq!(auth.secret().unwrap().expose_secret(), "a+b c:d%");

    let lower = format!("basic {}", STANDARD.encode("app:s"));
    assert_eq!(
        parse(Some(&lower), None, None, None).unwrap().client_id(),
        "app"
    );
}

/// A Basic value that does not decode to `id:secret` fails authentication.
#[test]
fn test_malformed_basic_is_invalid_client() {
    for value in [
        "Basic !!!".to_string(),
        basic("no-colon"),
        basic(":secret"),
        format!("Basic {}", STANDARD.encode([0xff, b':', b's'])),
        basic("app%ff:s"),
    ] {
        assert!(
            matches!(
                parse(Some(&value), None, None, None),
                Err(TokenError::InvalidClient)
            ),
            "{value}"
        );
    }
}

/// Another Authorization scheme is not a client credential.
#[test]
fn test_other_scheme_is_ignored() {
    let auth = parse(Some("Bearer abc"), Some("app"), Some("s"), None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::ClientSecretPost);
}

/// More than one method, or a body client_id contradicting Basic, is
/// `invalid_request` (RFC 6749 §5.2); the same client_id repeated is fine.
#[test]
fn test_ambiguous_requests_are_invalid_request() {
    let b = basic("app:s");
    for (authorization, client_id, secret, assertion) in [
        (Some(b.as_str()), None, Some("s"), None),
        (Some(b.as_str()), None, None, Some("jwt")),
        (None, Some("app"), Some("s"), Some("jwt")),
        (Some(b.as_str()), Some("other"), None, None),
    ] {
        assert!(matches!(
            parse(authorization, client_id, secret, assertion),
            Err(TokenError::InvalidRequest)
        ));
    }
    assert!(parse(Some(&b), Some("app"), None, None).is_ok());
}

/// Without Basic, the client must name itself; an empty value is omitted
/// (RFC 6749 §3.2).
#[test]
fn test_missing_client_id_is_invalid_request() {
    assert!(matches!(
        parse(None, None, Some("s"), None),
        Err(TokenError::InvalidRequest)
    ));
    assert!(matches!(
        parse(None, Some(""), None, None),
        Err(TokenError::InvalidRequest)
    ));
    let auth = parse(None, Some("app"), Some(""), Some("")).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::None);
}

/// An assertion of an unsupported type cannot authenticate the client
/// (RFC 7521 §4.2.1).
#[test]
fn test_unsupported_assertion_type_is_invalid_client() {
    let result = ClientAuthentication::from_request(
        None,
        Some("app"),
        None,
        Some("jwt"),
        Some("urn:example:other"),
    );
    assert!(matches!(result, Err(TokenError::InvalidClient)));
}

#[test]
fn test_token_error_codes() {
    assert_eq!(TokenError::InvalidClient.code(), "invalid_client");
    assert_eq!(TokenError::InvalidDpopProof.code(), "invalid_dpop_proof");
    assert_eq!(
        TokenError::UnsupportedGrantType.code(),
        "unsupported_grant_type"
    );
    assert_eq!(
        TokenError::AuthorizationPending.code(),
        "authorization_pending"
    );
    assert_eq!(TokenError::SlowDown.code(), "slow_down");
    assert_eq!(TokenError::ExpiredToken.code(), "expired_token");
}
