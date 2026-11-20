// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{ClaimSubscription, ClaimType};

fn requests() -> Vec<ClaimRequest> {
    let mut email = ClaimRequest::required("email", ClaimType::Data);
    email.subscription = ClaimSubscription::Required;
    let mut phone = ClaimRequest::optional("phone", ClaimType::Data);
    phone.subscription = ClaimSubscription::Preferred;
    vec![email, phone]
}

/// What the review of [`requests`] showed: both claims with a value.
fn shown() -> Vec<(String, Option<DisclosedValue>)> {
    vec![
        (
            "email".into(),
            Some(DisclosedValue {
                value: "alice@sid.example.com".into(),
                verified: Some(true),
            }),
        ),
        (
            "phone".into(),
            Some(DisclosedValue {
                value: "+380501234567".into(),
                verified: Some(false),
            }),
        ),
    ]
}

/// An approval names each requested claim once, with a sharing it admits;
/// the claim's type comes from the registration and its value from the
/// review, never from the browser. A claim not shared carries no value.
#[test]
fn choices_follow_the_registered_requests() {
    let choices = reviewed_choices(
        &requests(),
        &shown(),
        vec![
            ("phone".into(), ClaimSharing::None),
            ("email".into(), ClaimSharing::Subscribed),
        ],
    )
    .unwrap();
    assert_eq!(choices.len(), 2);
    assert_eq!(choices[0].name, "email");
    assert_eq!(choices[0].sharing, ClaimSharing::Subscribed);
    assert_eq!(choices[0].claim_type, ClaimType::Data);
    assert_eq!(
        choices[0].disclosed.as_ref().map(|d| d.value.as_str()),
        Some("alice@sid.example.com")
    );
    assert_eq!(choices[1].sharing, ClaimSharing::None);
    assert!(choices[1].disclosed.is_none());
}

/// A claim the Profile holds no value for can only be left unshared: an
/// approval sharing it is refused, naming it.
#[test]
fn a_claim_without_a_value_cannot_be_shared() {
    let mut shown = shown();
    shown[1].1 = None;
    let refused = reviewed_choices(
        &requests(),
        &shown,
        vec![
            ("email".into(), ClaimSharing::Subscribed),
            ("phone".into(), ClaimSharing::Static),
        ],
    )
    .err()
    .map(|e| e.to_string());
    assert!(refused.unwrap().contains("phone"));
}

/// A retry matches the recorded decision only as a first submission of it
/// would have passed: one choice per requested claim, the recorded sharing
/// for a recorded claim, and not sharing for one the review showed without
/// a value. An extra claim, a duplicate or another sharing is no retry.
#[test]
fn a_retry_matches_only_the_recorded_decision() {
    let mut shown = shown();
    shown[1].1 = None;
    let submitted = |given: &[(&str, ClaimSharing)]| {
        SubmittedDecision::Approve(
            given
                .iter()
                .map(|(name, sharing)| ((*name).to_string(), *sharing))
                .collect(),
        )
    };
    let first = [
        ("email", ClaimSharing::Subscribed),
        ("phone", ClaimSharing::None),
    ];
    let recorded = AuthorizationDecision::Approve {
        choices: reviewed_choices(
            &requests(),
            &shown,
            first.iter().map(|(n, s)| ((*n).to_string(), *s)).collect(),
        )
        .unwrap(),
    };
    let same =
        |given: &[(&str, ClaimSharing)]| same_choices(&requests(), &recorded, &submitted(given));

    assert!(same(&first));
    assert!(same(&[
        ("phone", ClaimSharing::None),
        ("email", ClaimSharing::Subscribed),
    ]));
    assert!(!same(&[("email", ClaimSharing::Subscribed)]));
    assert!(!same(&[
        ("email", ClaimSharing::Subscribed),
        ("phone", ClaimSharing::None),
        ("name", ClaimSharing::None),
    ]));
    assert!(!same(&[
        ("email", ClaimSharing::Subscribed),
        ("email", ClaimSharing::None),
    ]));
    assert!(!same(&[
        ("email", ClaimSharing::Subscribed),
        ("phone", ClaimSharing::Static),
    ]));
    assert!(!same(&[
        ("email", ClaimSharing::Static),
        ("phone", ClaimSharing::None),
    ]));
    assert!(!same_choices(
        &requests(),
        &recorded,
        &SubmittedDecision::Deny
    ));
}

/// Claims the scopes ask for (OIDC Core 1.0 §5.4) join the review as
/// voluntary without updates, after the client's registered requests, which
/// keep their own terms; `openid` alone asks for none, and a claim disclosed
/// before is reviewed again (consent-flow.md, OIDC scope requests).
#[test]
fn the_review_covers_registered_scope_and_earlier_claims() {
    let registered = requests();
    let scopes: Vec<String> = ["openid", "profile", "email"].map(String::from).into();
    let mut held =
        sid_core::models::ConsentRecord::new(sid_core::models::ProfileId::generate(), "rp");
    held.grant_claim(
        "nickname",
        ClaimType::Data,
        sid_core::models::ConsentMode::Static,
    );
    held.as_requested().unwrap().grant();

    let requests =
        sid_core::models::consent::review_requests(&registered, &scopes, held_grants(Some(&held)));
    let names: Vec<&str> = requests.iter().map(|r| r.claim_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "email",
            "phone",
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "preferred_username",
            "nickname"
        ]
    );
    // The registered email keeps its terms.
    assert_eq!(requests[0].level, ClaimLevel::Required);
    assert_eq!(requests[2].level, ClaimLevel::Optional);
    assert_eq!(requests[2].subscription, ClaimSubscription::None);
    assert_eq!(
        sid_core::models::consent::review_requests(&registered, &["openid".into()], &[]).len(),
        2
    );
}

/// A choice the review did not offer, a missing claim, a repeated one and a
/// claim the client never asked for are refused, naming the claim: an
/// approval cannot broaden or reinterpret the reviewed request
/// (consent-flow.md, submit a decision).
#[test]
fn choices_outside_the_review_are_refused() {
    let refused = |submitted: Vec<(&str, ClaimSharing)>| {
        reviewed_choices(
            &requests(),
            &shown(),
            submitted
                .into_iter()
                .map(|(n, s)| (n.to_owned(), s))
                .collect(),
        )
        .err()
        .map(|e| e.to_string())
    };
    // A required subscription admits only updates.
    assert!(
        refused(vec![
            ("email", ClaimSharing::Static),
            ("phone", ClaimSharing::None)
        ])
        .unwrap()
        .contains("email")
    );
    // A required claim cannot be left unshared in an approval.
    assert!(
        refused(vec![
            ("email", ClaimSharing::None),
            ("phone", ClaimSharing::None)
        ])
        .is_some()
    );
    // Missing phone.
    assert!(
        refused(vec![("email", ClaimSharing::Subscribed)])
            .unwrap()
            .contains("phone")
    );
    // A claim the client did not ask for.
    assert!(
        refused(vec![
            ("email", ClaimSharing::Subscribed),
            ("phone", ClaimSharing::None),
            ("address", ClaimSharing::Static)
        ])
        .unwrap()
        .contains("address")
    );
    // Repeated email.
    assert!(
        refused(vec![
            ("email", ClaimSharing::Subscribed),
            ("email", ClaimSharing::Subscribed),
            ("phone", ClaimSharing::None)
        ])
        .is_some()
    );
}

/// The review offers exactly the choices a request admits.
#[test]
fn allowed_sharing_is_what_the_request_admits() {
    let r = requests();
    assert_eq!(allowed_sharing(&r[0], true), vec![ClaimSharing::Subscribed]);
    assert_eq!(
        allowed_sharing(&r[1], true),
        vec![
            ClaimSharing::None,
            ClaimSharing::Static,
            ClaimSharing::Subscribed
        ]
    );
    // Without a value: only not sharing, and nothing for a required claim.
    assert_eq!(allowed_sharing(&r[1], false), vec![ClaimSharing::None]);
    assert!(allowed_sharing(&r[0], false).is_empty());
}
