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
    assert!(!pending.interacted);
}
