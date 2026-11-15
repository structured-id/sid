// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

const ISSUER: &str = "https://platform.sid.example.com/i/c33049901234268c3b5523658a5fb92b";

/// The host page the tests register.
const HOST: HostContinuation = HostContinuation {
    path: "/corporate-use",
    parameter: "continuation",
};

/// The URL `rd` continues at `issuer` with `HOST` registered; `None` when
/// refused.
fn continuation_of(issuer: &str, rd: &str) -> Option<String> {
    continuation_at(issuer, rd, &[HOST]).map(|c| c.url().to_string())
}

/// The continuation the issuer's sign-in step names is accepted as given,
/// with its application deciding.
#[test]
fn the_issuers_authorization_continuation_is_accepted() {
    let rd = format!("{ISSUER}/oauth2/authorize?client_id=ops&request_uri=urn%3Ax");
    assert_eq!(continuation_of(ISSUER, &rd), Some(rd.clone()));
    let continued = continuation_at(ISSUER, &rd, &[HOST]).unwrap();
    assert_eq!(continued.client_id(), Some("ops"));
}

/// A registered page of the host at the issuer, addressed by its one
/// parameter, is accepted and decided by no application (the
/// organization's requirements): a host page waits for no OAuth client.
#[test]
fn a_registered_host_page_is_accepted_without_an_application() {
    let rd = format!("{ISSUER}/corporate-use?continuation=abc");
    let continued = continuation_at(ISSUER, &rd, &[HOST]).unwrap();
    assert!(matches!(continued, Continuation::Host(_)));
    assert_eq!(continued.client_id(), None);
    assert_eq!(continued.url().as_str(), rd);
}

/// A host page is accepted only as registered: not when none is registered,
/// not at another issuer or origin, not with no, an empty, another or a
/// second parameter, a fragment or credentials. Otherwise the sign-in start
/// would return a signed-in browser to an address of the requester's choice.
#[test]
fn a_host_page_is_accepted_only_as_registered() {
    let rd = format!("{ISSUER}/corporate-use?continuation=abc");
    assert!(continuation_at(ISSUER, &rd, &[]).is_none());
    for rd in [
        "https://platform.sid.example.com/i/00000000000000000000000000000000/corporate-use?continuation=abc".to_owned(),
        "https://evil.sid.example.com/i/c33049901234268c3b5523658a5fb92b/corporate-use?continuation=abc".to_owned(),
        format!("{ISSUER}/corporate-use"),
        format!("{ISSUER}/corporate-use?continuation="),
        format!("{ISSUER}/corporate-use?return=https://evil.sid.example.com"),
        format!("{ISSUER}/corporate-use?continuation=abc&continuation=def"),
        format!("{ISSUER}/corporate-use?continuation=abc&next=x"),
        format!("{ISSUER}/corporate-use?continuation=abc#x"),
        "https://u:p@platform.sid.example.com/i/c33049901234268c3b5523658a5fb92b/corporate-use?continuation=abc".to_owned(),
        format!("{ISSUER}/corporate-use/x?continuation=abc"),
    ] {
        assert_eq!(continuation_of(ISSUER, &rd), None, "{rd}");
    }
}

/// The entry never returns the browser anywhere else: another host, another
/// issuer on the same host, another path of this issuer, a fragment or
/// credentials in the URL, and text that is no URL are all refused. An open
/// redirect through the sign-in start would send the session's browser to a
/// page of the attacker's choosing.
#[test]
fn anything_else_is_refused() {
    for rd in [
        "https://evil.sid.example.com/i/c33049901234268c3b5523658a5fb92b/oauth2/authorize",
        "https://platform.sid.example.com/i/00000000000000000000000000000000/oauth2/authorize",
        "https://platform.sid.example.com/i/c33049901234268c3b5523658a5fb92b/oauth2/token",
        "http://platform.sid.example.com/i/c33049901234268c3b5523658a5fb92b/oauth2/authorize",
        "https://platform.sid.example.com:8443/i/c33049901234268c3b5523658a5fb92b/oauth2/authorize",
        "https://platform.sid.example.com/i/c33049901234268c3b5523658a5fb92b/oauth2/authorize#x",
        "https://u:p@platform.sid.example.com/i/c33049901234268c3b5523658a5fb92b/oauth2/authorize",
        "/i/c33049901234268c3b5523658a5fb92b/oauth2/authorize",
        "",
    ] {
        assert_eq!(continuation_of(ISSUER, rd), None, "{rd}");
    }
}

/// A continuation must name exactly one application: its login policy
/// decides the sign-in, so none, an empty one or two (which application
/// would decide?) are refused.
#[test]
fn a_continuation_names_exactly_one_application() {
    for query in [
        "",
        "?request_uri=urn%3Ax",
        "?client_id=",
        "?client_id=ops&client_id=other",
    ] {
        let rd = format!("{ISSUER}/oauth2/authorize{query}");
        assert_eq!(continuation_of(ISSUER, &rd), None, "{rd}");
    }
    let rd = url::Url::parse(&format!("{ISSUER}/oauth2/authorize?client_id=ops")).unwrap();
    assert_eq!(client_of(&rd).as_deref(), Some("ops"));
}

/// A step-up refusal naming `violations` as (type, subject).
fn step_up(violations: &[(&str, &str)]) -> Status {
    let mut details = tonic_types::ErrorDetails::with_error_info(
        "STEP_UP_REQUIRED",
        "structured.id",
        std::collections::HashMap::new(),
    );
    for (kind, subject) in violations {
        details.add_precondition_failure_violation(*kind, *subject, "required");
    }
    use tonic_types::StatusExt;
    Status::with_error_details(tonic::Code::FailedPrecondition, "step up", details)
}

/// A level and a freshness are asked of the issuer in one further entry,
/// keeping what the first already asked.
#[test]
fn a_level_and_freshness_are_asked_again() {
    let elevated = sid_core::models::AuthLevel::Elevated;
    let further = further_request(
        &step_up(&[("acr", elevated.acr_value()), ("max_age", "300")]),
        &EntryRequest::default(),
    );
    assert_eq!(
        further,
        Some(EntryRequest {
            acr: Some(elevated),
            max_age: Some(std::time::Duration::from_secs(300)),
        })
    );
}

/// An anomaly rule's second factor is asked as the level that means one; the
/// first request asked for no level, so no method is lost by it.
#[test]
fn a_second_factor_is_asked_as_the_multi_factor_level() {
    use sid_core::models::AuthLevel;
    let further = further_request(&step_up(&[("amr", "mfa")]), &EntryRequest::default());
    assert_eq!(
        further,
        Some(EntryRequest {
            acr: Some(AuthLevel::Standard),
            max_age: None,
        })
    );
    // An entry that already asked is not repeated: the return is judged as it
    // is, and acr_values obliges no issuer to meet it (OIDC Core §3.1.2.1).
    for asked in [AuthLevel::Standard, AuthLevel::Elevated] {
        let asked = EntryRequest {
            acr: Some(asked),
            max_age: None,
        };
        assert_eq!(further_request(&step_up(&[("amr", "mfa")]), &asked), None);
    }
}

/// Nothing is asked again when the issuer cannot be asked for it (a method),
/// when the returned entry already asked for it (no loop), or when the
/// refusal is no step-up.
#[test]
fn nothing_is_asked_twice_or_beyond_what_an_issuer_states() {
    let elevated = sid_core::models::AuthLevel::Elevated;
    let asked = EntryRequest {
        acr: Some(elevated),
        max_age: Some(std::time::Duration::from_secs(300)),
    };
    for refusal in [
        step_up(&[("amr", "hwk")]),
        step_up(&[("max_age", "300"), ("amr", "hwk")]),
        step_up(&[]),
    ] {
        assert_eq!(further_request(&refusal, &EntryRequest::default()), None);
    }
    for refusal in [
        step_up(&[("acr", elevated.acr_value())]),
        step_up(&[("max_age", "600")]),
    ] {
        assert_eq!(further_request(&refusal, &asked), None);
    }
    assert_eq!(
        further_request(&Status::permission_denied("no"), &EntryRequest::default()),
        None
    );
}
