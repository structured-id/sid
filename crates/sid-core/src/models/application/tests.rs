use super::*;

// --- ResourceIndicator (RFC 8707 §2) ----------------------------------------

#[test]
fn an_absolute_uri_is_a_resource_indicator() {
    for text in [
        "https://resources.example/orders",
        "https://resources.example/orders?tenant=a",
        "https://resources.example:8443/",
        "urn:example:orders",
    ] {
        let indicator = ResourceIndicator::parse(text).expect(text);
        assert_eq!(indicator.as_str(), text);
    }
}

#[test]
fn a_fragment_relative_reference_or_credentials_are_refused() {
    // RFC 8707 §2: an absolute URI without a fragment. Credentials in an
    // audience would be copied into every token.
    for text in [
        "",
        "/orders",
        "orders",
        "https://resources.example/orders#v1",
        "https://user:pw@resources.example/orders",
        "https://user@resources.example/orders",
        " https://resources.example/orders",
    ] {
        assert!(ResourceIndicator::parse(text).is_err(), "{text:?}");
    }
}

#[test]
fn only_the_canonical_spelling_is_accepted() {
    // Bug prevented: two spellings of one URI registering two resources, or a
    // request spelled differently from the registration missing its target.
    let err = ResourceIndicator::parse("HTTPS://Resources.Example/orders").unwrap_err();
    assert!(err.contains("https://resources.example/orders"), "{err}");
    assert!(ResourceIndicator::parse("https://resources.example").is_err());
    assert!(ResourceIndicator::parse("https://resources.example:443/x").is_err());
}

#[test]
fn an_overlong_indicator_is_refused() {
    let long = format!(
        "https://resources.example/{}",
        "a".repeat(ResourceIndicator::MAX_LEN)
    );
    assert!(ResourceIndicator::parse(&long).is_err());
}

#[test]
fn the_indicator_serializes_as_its_string_and_refuses_invalid_input() {
    let indicator = ResourceIndicator::parse("https://resources.example/orders").unwrap();
    let json = serde_json::to_string(&indicator).unwrap();
    assert_eq!(json, "\"https://resources.example/orders\"");
    assert_eq!(
        serde_json::from_str::<ResourceIndicator>(&json).unwrap(),
        indicator
    );
    assert!(serde_json::from_str::<ResourceIndicator>("\"/orders\"").is_err());
}

// --- ResourceState ----------------------------------------------------------

#[test]
fn a_retired_resource_never_comes_back() {
    // A retired identifier stays reserved: it is not reassigned or revived.
    use ResourceState::*;
    assert!(Active.may_become(Inactive));
    assert!(Inactive.may_become(Active));
    assert!(Active.may_become(Retired));
    assert!(Inactive.may_become(Retired));
    assert!(!Retired.may_become(Active));
    assert!(!Retired.may_become(Inactive));
    assert!(Active.may_become(Active));
}

#[test]
fn state_round_trips_through_its_stored_form() {
    for state in [
        ResourceState::Active,
        ResourceState::Inactive,
        ResourceState::Retired,
    ] {
        assert_eq!(state.as_str().parse::<ResourceState>(), Ok(state));
    }
    assert!("deleted".parse::<ResourceState>().is_err());
}

// --- ProtectedResource ------------------------------------------------------

fn resource(state: ResourceState) -> ProtectedResource {
    ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(ApplicationId::generate()),
        issuer_id: IssuerId::generate(),
        indicator: ResourceIndicator::parse("https://resources.example/orders").unwrap(),
        scopes: vec!["orders.read".into(), "orders.write".into()],
        state,
        revision: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn only_an_active_resource_is_a_target() {
    assert!(resource(ResourceState::Active).is_target());
    assert!(!resource(ResourceState::Inactive).is_target());
    assert!(!resource(ResourceState::Retired).is_target());
}

// --- Scope lists ------------------------------------------------------------

#[test]
fn scope_tokens_follow_rfc_6749() {
    // RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). Scopes are
    // stored space-separated, so a space inside one would split it.
    assert_eq!(
        scope_list(&["orders.read".into(), "urn:x:y".into()]),
        Ok(vec!["orders.read".to_string(), "urn:x:y".to_string()])
    );
    for bad in ["", "a b", "quote\"d", "back\\slash", "tab\t", "ünicode"] {
        let err = scope_list(&[bad.to_string()]).unwrap_err();
        assert!(err.contains("scope"), "{bad:?}: {err}");
    }
}

#[test]
fn a_repeated_scope_counts_once() {
    assert_eq!(
        scope_list(&["a".into(), "b".into(), "a".into()]),
        Ok(vec!["a".to_string(), "b".to_string()])
    );
}

// --- ResourceAccess ---------------------------------------------------------

#[test]
fn access_grants_only_scopes_both_allowed_and_supported() {
    // A relationship cannot grant a scope the resource does not support.
    let target = resource(ResourceState::Active);
    let access = ResourceAccess {
        client_id: "orders-web".into(),
        resource_id: target.id,
        scopes: vec!["orders.read".into(), "admin".into()],
        created_at: Utc::now(),
    };
    let requested = vec!["orders.read".into(), "orders.write".into(), "admin".into()];
    assert_eq!(
        access.granted_scopes(&target, &requested),
        vec!["orders.read".to_string()]
    );
}
