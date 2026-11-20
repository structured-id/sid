use super::*;

/// Create a consent in Requested state (default from new()).
fn make_consent_requested() -> ConsentRecord {
    ConsentRecord::new(ProfileId::generate(), "site_abc_client_id")
}

/// Create a consent already granted (Active).
fn make_consent() -> ConsentRecord {
    let mut c = ConsentRecord::new(ProfileId::generate(), "site_abc_client_id");
    c.as_requested().unwrap().grant();
    c
}

fn scopes(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

/// A value of `value`, as an approval records it.
fn value(value: &str) -> DisclosedValue {
    DisclosedValue {
        value: value.into(),
        verified: None,
    }
}

/// Grant `name` in `mode` with the approved `disclosed` value, as an
/// approval leaves it.
fn share(c: &mut ConsentRecord, name: &str, kind: ClaimType, mode: ConsentMode, disclosed: &str) {
    c.grant_claim(name, kind, mode);
    if let Some(grant) = c.grants.iter_mut().find(|g| g.claim_name == name) {
        grant.disclosed = Some(value(disclosed));
    }
}

/// A grant re-enabled from account management carries no approved value:
/// it does not cover a required claim, so the next authorization reviews it
/// rather than issue a code whose UserInfo lacks the required claim.
#[test]
fn test_covers_requires_an_approved_value() {
    let mut c = make_consent();
    let api = ResourceId::generate();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    let email = ClaimRequest::required("email", ClaimType::Data);
    assert!(!c.covers(api, &[], &[&email]));

    share(
        &mut c,
        "email",
        ClaimType::Data,
        ConsentMode::Static,
        "a@sid.example.com",
    );
    assert!(c.covers(api, &[], &[&email]));
}

/// A Profile edit is delivered only through subscriptions, as one complete
/// replacement: every changed field subscribed gives the new values; one
/// changed static field keeps the whole snapshot for the holder's review;
/// nothing changed delivers nothing (identity-model.md, recipient
/// disclosure).
#[test]
fn test_subscribed_delivery_replaces_the_snapshot_or_nothing() {
    let mut c = make_consent();
    share(
        &mut c,
        "name",
        ClaimType::Data,
        ConsentMode::Subscribed,
        "Alice",
    );
    share(
        &mut c,
        "email",
        ClaimType::Data,
        ConsentMode::Static,
        "a@sid.example.com",
    );
    c.grant_claim("phone_number", ClaimType::Data, ConsentMode::Static);
    c.as_active().unwrap().revoke_claim("phone_number");
    let now = |name: &str, email: &str| {
        let (name, email) = (value(name), value(email));
        move |g: &ClaimGrant| match g.claim_name.as_str() {
            "name" => Some(name.clone()),
            "email" => Some(email.clone()),
            _ => Some(value("+380501234567")),
        }
    };

    assert_eq!(
        c.subscribed_delivery(now("Alice", "a@sid.example.com")),
        None
    );

    let delivered = c
        .subscribed_delivery(now("Alicia", "a@sid.example.com"))
        .unwrap();
    assert_eq!(
        delivered,
        vec![DisclosureUpdate {
            claim_name: "name".into(),
            prior: Some(value("Alice")),
            next: Some(value("Alicia")),
        }]
    );

    assert_eq!(
        c.subscribed_delivery(now("Alicia", "b@sid.example.com")),
        None
    );
}

#[test]
fn test_consent_new_is_requested() {
    let c = make_consent_requested();
    assert_eq!(c.client_id, "site_abc_client_id");
    assert_eq!(c.status, ConsentStatus::Requested);
    assert!(c.grants.is_empty());
    assert!(c.scope_grants.is_empty());
    assert!(c.revoked_at.is_none());
}

#[test]
fn test_consent_grant_transitions_to_active() {
    let mut c = make_consent_requested();
    assert!(c.as_requested().is_some());
    assert!(c.as_active().is_none());

    c.as_requested().unwrap().grant();
    assert_eq!(c.status, ConsentStatus::Active);
    assert!(c.as_active().is_some());
    assert!(c.as_requested().is_none());
}

#[test]
fn test_consent_deny_transitions_to_revoked() {
    let mut c = make_consent_requested();
    c.as_requested().unwrap().deny();
    assert_eq!(c.status, ConsentStatus::Revoked);
    assert!(c.revoked_at.is_some());
    assert!(c.as_requested().is_none());
    assert!(c.as_active().is_none());
}

#[test]
fn test_grant_claim() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    c.grant_claim(
        "passport_verified",
        ClaimType::Attestation,
        ConsentMode::Subscribed,
    );

    assert_eq!(c.grants.len(), 2);
    assert_eq!(c.grants[0].claim_name, "email");
    assert_eq!(c.grants[0].claim_type, ClaimType::Data);
    assert_eq!(c.grants[0].mode, ConsentMode::Static);
    assert_eq!(c.grants[1].claim_name, "passport_verified");
    assert_eq!(c.grants[1].claim_type, ClaimType::Attestation);
    assert_eq!(c.grants[1].mode, ConsentMode::Subscribed);
}

/// A later decision on an active claim changes only its update mode: the
/// claim keeps one grant and its grant time, so a snapshot grant becomes a
/// subscription (or back) without counting as a new grant.
#[test]
fn test_grant_claim_again_changes_only_the_mode() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    let granted_at = c.grants[0].granted_at;

    c.grant_claim("email", ClaimType::Data, ConsentMode::Subscribed);
    assert_eq!(c.grants.len(), 1);
    assert_eq!(c.grants[0].mode, ConsentMode::Subscribed);
    assert_eq!(c.grants[0].granted_at, granted_at);
}

/// Granting a revoked claim again renews that one grant with the new mode.
#[test]
fn test_grant_revoked_claim_renews_it() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Subscribed);
    c.as_active().unwrap().revoke_claim("email");

    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    assert_eq!(c.grants.len(), 1);
    assert!(c.grants[0].is_active());
    assert_eq!(c.grants[0].mode, ConsentMode::Static);
}

/// Scopes accumulate per resource without duplicates; another resource gets
/// its own grant, so one resource's scopes never authorize another.
#[test]
fn test_grant_scopes_accumulates_per_resource() {
    let mut c = make_consent();
    let api = ResourceId::generate();
    let other = ResourceId::generate();

    c.grant_scopes(api, &scopes(&["openid", "read"]));
    c.grant_scopes(api, &scopes(&["read", "write"]));
    c.grant_scopes(other, &scopes(&["read"]));

    assert_eq!(c.scope_grants.len(), 2);
    let api_grant = c
        .scope_grants
        .iter()
        .find(|g| g.resource_id == api)
        .unwrap();
    assert_eq!(api_grant.scopes, scopes(&["openid", "read", "write"]));
    assert!(c.covers(api, &scopes(&["write"]), &[]));
    assert!(!c.covers(other, &scopes(&["write"]), &[]));
}

/// The consent covers a request only when every requested scope for that
/// resource and every requested claim is granted.
#[test]
fn test_covers_requires_every_scope_and_claim() {
    let mut c = make_consent();
    let api = ResourceId::generate();
    c.grant_scopes(api, &scopes(&["openid", "read"]));
    share(
        &mut c,
        "email",
        ClaimType::Data,
        ConsentMode::Static,
        "a@sid.example.com",
    );
    let email = ClaimRequest::required("email", ClaimType::Data);
    let phone = ClaimRequest::required("phone", ClaimType::Data);

    assert!(c.covers(api, &scopes(&["openid"]), &[&email]));
    assert!(!c.covers(api, &scopes(&["openid", "write"]), &[&email]));
    assert!(!c.covers(api, &scopes(&["openid"]), &[&email, &phone]));
    assert!(!c.covers(ResourceId::generate(), &scopes(&["openid"]), &[]));
}

/// A grant covers a required claim only as it is requested now: a grant of
/// the attestation does not cover a request for the value, and a grant of
/// the current value alone does not cover a request that needs its later
/// changes.
#[test]
fn test_covers_requires_the_requested_type_and_sharing() {
    let mut c = make_consent();
    let api = ResourceId::generate();
    share(
        &mut c,
        "passport",
        ClaimType::Attestation,
        ConsentMode::Static,
        "",
    );
    share(
        &mut c,
        "email",
        ClaimType::Data,
        ConsentMode::Static,
        "a@sid.example.com",
    );

    let passport_value = ClaimRequest::required("passport", ClaimType::Data);
    let passport_check = ClaimRequest::required("passport", ClaimType::Attestation);
    assert!(!c.covers(api, &[], &[&passport_value]));
    assert!(c.covers(api, &[], &[&passport_check]));

    let email_subscribed = ClaimRequest {
        subscription: ClaimSubscription::Required,
        ..ClaimRequest::required("email", ClaimType::Data)
    };
    assert!(!c.covers(api, &[], &[&email_subscribed]));
    c.grant_claim("email", ClaimType::Data, ConsentMode::Subscribed);
    assert!(c.covers(api, &[], &[&email_subscribed]));
}

/// Granting an active claim again takes the type now approved, not only the
/// mode: a re-approval after the client changed a request to the value
/// records the value.
#[test]
fn test_grant_again_takes_the_approved_type() {
    let mut c = make_consent();
    c.grant_claim("passport", ClaimType::Attestation, ConsentMode::Static);
    c.grant_claim("passport", ClaimType::Data, ConsentMode::Static);
    assert_eq!(c.grants.len(), 1);
    assert_eq!(c.grants[0].claim_type, ClaimType::Data);
}

/// A revoked claim, or a consent that is not active, covers nothing: an old
/// grant cannot skip the screen after the user withdrew it.
#[test]
fn test_covers_nothing_after_revocation() {
    let mut c = make_consent();
    let api = ResourceId::generate();
    c.grant_scopes(api, &scopes(&["openid"]));
    share(
        &mut c,
        "email",
        ClaimType::Data,
        ConsentMode::Static,
        "a@sid.example.com",
    );

    c.as_active().unwrap().revoke_claim("email");
    let email = ClaimRequest::required("email", ClaimType::Data);
    assert!(!c.covers(api, &scopes(&["openid"]), &[&email]));
    assert!(c.covers(api, &scopes(&["openid"]), &[]));

    c.as_active().unwrap().revoke_all();
    assert!(!c.covers(api, &scopes(&["openid"]), &[]));
    assert!(!make_consent_requested().covers(api, &[], &[]));
}

#[test]
fn test_revoke_claim() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    c.grant_claim("phone", ClaimType::Data, ConsentMode::Static);

    c.as_active().unwrap().revoke_claim("email");
    assert!(!c.grants[0].is_active());
    assert!(c.grants[1].is_active());
    assert_eq!(c.active_grants().len(), 1);
}

#[test]
fn test_revoke_all() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    c.grant_claim("phone", ClaimType::Data, ConsentMode::Static);

    c.as_active().unwrap().revoke_all();
    assert_eq!(c.status(), ConsentStatus::Revoked);
    assert!(c.revoked_at.is_some());
    assert!(!c.has_active_grants());
}

#[test]
fn test_gateway_returns_none_after_revoke() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    c.as_active().unwrap().revoke_all();
    assert!(c.as_active().is_none());
}

#[test]
fn test_active_grants() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    c.grant_claim("phone", ClaimType::Data, ConsentMode::Static);
    c.grant_claim("name", ClaimType::Data, ConsentMode::Static);

    c.as_active().unwrap().revoke_claim("phone");
    let active = c.active_grants();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|g| g.claim_name != "phone"));
}

#[test]
fn test_claim_request_required() {
    let r = ClaimRequest::required("email", ClaimType::Data);
    assert_eq!(r.level, ClaimLevel::Required);
    assert!(r.justification.is_none());
}

#[test]
fn test_claim_request_demanded() {
    let r = ClaimRequest::demanded(
        "age_verified",
        ClaimType::Attestation,
        "Age-restricted content by law.",
    );
    assert_eq!(r.level, ClaimLevel::Demanded);
    assert_eq!(
        r.justification.as_deref(),
        Some("Age-restricted content by law.")
    );
}

#[test]
fn test_claim_request_optional() {
    let r = ClaimRequest::optional("phone", ClaimType::Data);
    assert_eq!(r.level, ClaimLevel::Optional);
}

/// The consent screen's rules (authz/consent-flow.md, consent screen UX): a
/// required subscription admits only updates, a subscription of none admits
/// no updates, and a required claim cannot be left unshared in an approval.
#[test]
fn test_claim_request_admits_only_the_offered_choices() {
    let mut r = ClaimRequest::required("email", ClaimType::Data);
    r.subscription = ClaimSubscription::Required;
    assert!(!r.admits(ClaimSharing::None));
    assert!(!r.admits(ClaimSharing::Static));
    assert!(r.admits(ClaimSharing::Subscribed));

    let mut r = ClaimRequest::optional("phone", ClaimType::Data);
    r.subscription = ClaimSubscription::Preferred;
    assert!(r.admits(ClaimSharing::None));
    assert!(r.admits(ClaimSharing::Static));
    assert!(r.admits(ClaimSharing::Subscribed));

    let r = ClaimRequest::demanded("family", ClaimType::Data, "portions");
    assert!(r.admits(ClaimSharing::None));
    assert!(r.admits(ClaimSharing::Static));
    assert!(!r.admits(ClaimSharing::Subscribed));
}

#[test]
fn test_claim_level_serde() {
    let l = ClaimLevel::Demanded;
    let json = serde_json::to_string(&l).unwrap();
    assert_eq!(json, "\"demanded\"");
    let parsed: ClaimLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ClaimLevel::Demanded);
}

#[test]
fn test_claim_type_serde() {
    let t = ClaimType::Attestation;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"attestation\"");
    let parsed: ClaimType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ClaimType::Attestation);
}

#[test]
fn test_consent_status_serde() {
    let s = ConsentStatus::Revoked;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"revoked\"");
    let parsed: ConsentStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ConsentStatus::Revoked);

    let s2 = ConsentStatus::Requested;
    let json2 = serde_json::to_string(&s2).unwrap();
    assert_eq!(json2, "\"requested\"");
    let parsed2: ConsentStatus = serde_json::from_str(&json2).unwrap();
    assert_eq!(parsed2, ConsentStatus::Requested);
}

/// The stored text of every status, claim type and consent mode reads back
/// as itself, and an unknown value is an error rather than a default a
/// stored row never had.
#[test]
fn test_stored_names_parse_back() {
    for s in [
        ConsentStatus::Requested,
        ConsentStatus::Active,
        ConsentStatus::Revoked,
        ConsentStatus::Expired,
    ] {
        assert_eq!(s.as_str().parse::<ConsentStatus>(), Ok(s));
    }
    for t in [ClaimType::Data, ClaimType::Attestation] {
        assert_eq!(t.as_str().parse::<ClaimType>(), Ok(t));
    }
    for m in [ConsentMode::Static, ConsentMode::Subscribed] {
        assert_eq!(m.as_str().parse::<ConsentMode>().ok(), Some(m));
    }
    for l in [
        ClaimLevel::Required,
        ClaimLevel::Demanded,
        ClaimLevel::Optional,
    ] {
        assert_eq!(l.as_str().parse::<ClaimLevel>().ok(), Some(l));
    }
    for s in [
        ClaimSubscription::Required,
        ClaimSubscription::Preferred,
        ClaimSubscription::None,
    ] {
        assert_eq!(s.as_str().parse::<ClaimSubscription>().ok(), Some(s));
    }
    assert!("granted".parse::<ConsentStatus>().is_err());
    assert!("".parse::<ClaimType>().is_err());
    assert!("none".parse::<ConsentMode>().is_err());
}

#[test]
fn test_consent_serde_roundtrip() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Subscribed);
    c.grant_scopes(ResourceId::generate(), &scopes(&["openid"]));

    let json = serde_json::to_string(&c).unwrap();
    let parsed: ConsentRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, c);
}

#[test]
fn test_consent_id_unique() {
    let id1 = ConsentId::new();
    let id2 = ConsentId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_double_claim_revoke_is_idempotent() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data, ConsentMode::Static);

    c.as_active().unwrap().revoke_claim("email");
    let first_revoke = c.grants[0].revoked_at;
    // Second revoke_claim through gateway — claim already revoked, no change.
    c.as_active().unwrap().revoke_claim("email");
    assert_eq!(c.grants[0].revoked_at, first_revoke);
}
