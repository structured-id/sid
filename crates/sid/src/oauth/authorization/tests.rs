use super::*;

/// Canonical SID ACR URNs and plain names each name their level.
#[test]
fn requested_acr_reads_urns_and_names() {
    for (value, level) in [
        ("urn:sid:acr:basic", AuthLevel::Basic),
        ("urn:sid:acr:standard", AuthLevel::Standard),
        ("urn:sid:acr:elevated", AuthLevel::Elevated),
        ("urn:sid:acr:critical", AuthLevel::Critical),
        ("basic", AuthLevel::Basic),
        ("standard", AuthLevel::Standard),
        ("elevated", AuthLevel::Elevated),
        ("critical", AuthLevel::Critical),
    ] {
        assert_eq!(requested_acr(value), Some(level), "{value}");
    }
}

/// Of several values the strictest is asked for; unknown ones are ignored,
/// and none known asks for nothing.
#[test]
fn requested_acr_takes_the_highest_known() {
    assert_eq!(
        requested_acr("urn:sid:acr:basic urn:sid:acr:elevated"),
        Some(AuthLevel::Elevated)
    );
    assert_eq!(
        requested_acr("urn:unknown:foo standard urn:other:bar"),
        Some(AuthLevel::Standard)
    );
    assert_eq!(requested_acr("urn:unknown:foo"), None);
    assert_eq!(requested_acr(""), None);
}

/// A kept request is continued exactly as it arrived: the typed request it
/// gives back names the same client, redirect, state and issuer, with no
/// `request_uri` of its own.
#[test]
fn kept_request_continues_as_it_arrived() {
    let asked = OAuth2AuthorizeRequest {
        client_id: "app".to_string(),
        redirect_uri: "https://app.sid.example.com/cb".to_string(),
        response_type: "code".to_string(),
        state: Some("xyz".to_string()),
        issuer_handle: "acme".to_string(),
        request_uri: Some(format!("{REQUEST_URI_PREFIX}ref")),
        ..Default::default()
    };
    let pending = PendingAuthorization::arrived(asked);
    let again = pending.request();
    assert_eq!(again.client_id, "app");
    assert_eq!(again.redirect_uri, "https://app.sid.example.com/cb");
    assert_eq!(again.state.as_deref(), Some("xyz"));
    assert_eq!(again.issuer_handle, "acme");
    assert!(again.request_uri.is_none());
    assert!(!pending.account_offered);
}

/// What a kept request asks of the sign-in, counted from its arrival as the
/// authorization counts it: `prompt=login` an authentication since arrival,
/// `max_age` what is left of it, the stricter of both when both are asked,
/// and the highest known level of `acr_values`. A request asking nothing
/// asks nothing. Bug prevented: an upstream issuer asked for nothing reuses
/// an authentication the authorization then refuses, and the user loops
/// between the sign-in page and the issuer.
#[test]
fn a_kept_request_states_what_it_asks_of_the_sign_in() {
    let arrived = |prompt: Option<&str>, max_age: Option<u32>, acr: Option<&str>| {
        PendingAuthorization::arrived(OAuth2AuthorizeRequest {
            client_id: "app".to_string(),
            redirect_uri: "https://app.sid.example.com/cb".to_string(),
            response_type: "code".to_string(),
            issuer_handle: "acme".to_string(),
            prompt: prompt.map(String::from),
            max_age,
            acr_values: acr.map(String::from),
            ..Default::default()
        })
    };
    let later = |pending: &PendingAuthorization, seconds: i64| {
        pending.sign_in_requirements(pending.arrived_at + jiff::SignedDuration::from_secs(seconds))
    };
    let none = arrived(None, None, None);
    assert_eq!(later(&none, 5), SignInRequirements::default());

    let login = arrived(Some("login consent"), None, None);
    assert_eq!(
        later(&login, 30).max_age,
        Some(std::time::Duration::from_secs(30))
    );

    let aged = arrived(None, Some(300), None);
    assert_eq!(
        later(&aged, 100).max_age,
        Some(std::time::Duration::from_secs(200))
    );
    assert_eq!(later(&aged, 400).max_age, Some(std::time::Duration::ZERO));

    let both = arrived(Some("login"), Some(300), None);
    assert_eq!(
        later(&both, 100).max_age,
        Some(std::time::Duration::from_secs(100))
    );

    let leveled = arrived(None, None, Some("unknown urn:sid:acr:standard"));
    assert_eq!(
        later(&leveled, 0).acr,
        requested_acr("urn:sid:acr:standard")
    );
    assert!(later(&leveled, 0).acr.is_some());
}
