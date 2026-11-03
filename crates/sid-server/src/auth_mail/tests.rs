// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// The link names its session and carries the token as query parameters of
/// the configured page, keeping the page's own path.
#[test]
fn link_carries_session_and_token_on_the_page() {
    let page = url::Url::parse("https://id.sid.example.com/account/verify").unwrap();
    let id = uuid::Uuid::now_v7();
    let link = link(&page, id, "t+/=");

    assert_eq!(link.path(), "/account/verify");
    let query: std::collections::HashMap<_, _> = link.query_pairs().into_owned().collect();
    assert_eq!(query["session"], id.to_string());
    assert_eq!(query["token"], "t+/=");
}

/// A refusal is final, an unknown result is ambiguous, a transport failure
/// is tried again.
#[test]
fn delivery_errors_map_to_their_outcomes() {
    assert!(matches!(
        outcome_of(DeliveryError::Rejected("550".into())),
        WorkOutcome::Permanent(_)
    ));
    assert!(matches!(
        outcome_of(DeliveryError::InvalidRecipient("x".into())),
        WorkOutcome::Permanent(_)
    ));
    assert!(matches!(
        outcome_of(DeliveryError::Ambiguous("timeout".into())),
        WorkOutcome::Ambiguous(_)
    ));
    assert!(matches!(
        outcome_of(DeliveryError::Failed("refused".into())),
        WorkOutcome::Retry(_)
    ));
}
