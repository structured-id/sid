use super::*;

/// Every defined value parses alone and in combination; absent and empty ask
/// for nothing.
#[test]
fn test_prompt_parses_defined_values() {
    assert_eq!(Prompt::parse(None).unwrap(), Prompt::default());
    assert_eq!(Prompt::parse(Some("")).unwrap(), Prompt::default());
    assert!(Prompt::parse(Some("none")).unwrap().none());
    let both = Prompt::parse(Some("login consent")).unwrap();
    assert!(both.asks_interaction() && !both.none());
    assert!(
        Prompt::parse(Some("select_account"))
            .unwrap()
            .asks_interaction()
    );
    assert!(!Prompt::parse(Some("login")).unwrap().asks_interaction());
}

/// `none` with another value, an unknown value and a repeated one are
/// `invalid_request` (OpenID Connect Core §3.1.2.1).
#[test]
fn test_prompt_refuses_invalid_combinations() {
    for value in [
        "none login",
        "consent none",
        "create",
        "Login",
        "login login",
    ] {
        assert_eq!(
            Prompt::parse(Some(value)),
            Err(AuthorizeError::InvalidPrompt),
            "{value}"
        );
    }
    assert_eq!(
        AuthorizeError::InvalidPrompt.oauth_error(),
        "invalid_request"
    );
}

/// `login` and `max_age=0` accept only authentication after the request;
/// `max_age=N` the last N seconds; nothing else sets a limit.
#[test]
fn test_authenticated_after() {
    let now = Utc::now();
    let login = Prompt::parse(Some("login")).unwrap();
    let plain = Prompt::default();
    assert_eq!(login.authenticated_after(None, now), Some(now));
    assert_eq!(login.authenticated_after(Some(600), now), Some(now));
    assert_eq!(plain.authenticated_after(Some(0), now), Some(now));
    assert_eq!(
        plain.authenticated_after(Some(600), now),
        Some(now - Duration::seconds(600))
    );
    assert_eq!(plain.authenticated_after(None, now), None);
}
