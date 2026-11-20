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

/// An approval names each requested claim once, with a sharing it admits;
/// the claim's type comes from the registration, never from the browser.
#[test]
fn choices_follow_the_registered_requests() {
    let choices = reviewed_choices(
        &requests(),
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
    assert_eq!(choices[1].sharing, ClaimSharing::None);
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
    assert_eq!(allowed_sharing(&r[0]), vec![ClaimSharing::Subscribed]);
    assert_eq!(
        allowed_sharing(&r[1]),
        vec![
            ClaimSharing::None,
            ClaimSharing::Static,
            ClaimSharing::Subscribed
        ]
    );
}
