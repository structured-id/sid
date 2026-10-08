// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn check() -> ContestCheck {
    ContestCheck::new(
        PrincipalType::Email,
        "a@sid.example.com",
        ProfileId::generate(),
    )
}

/// The check owed by a binding is the same work however often the binding
/// is stored, and carries the binding it checks.
#[test]
fn test_contest_check_work_follows_binding() {
    let owed = check();
    let work = owed.work();
    assert_eq!(work.kind.as_str(), PRINCIPAL_CONTEST_CHECK_KIND);
    assert_eq!(work.max_attempts, PRINCIPAL_CONTEST_CHECK_ATTEMPTS);
    assert_eq!(work.id, owed.work().id);
    let back: ContestCheck = serde_json::from_slice(&work.payload).unwrap();
    assert_eq!(back, owed);

    let other_holder = ContestCheck::new(
        owed.principal_type,
        owed.value.clone(),
        ProfileId::generate(),
    );
    assert_ne!(work.id, other_holder.work().id);
}

/// Each other holder is told once, naming the identifier and the new holder.
#[test]
fn test_contested_event_once_per_holder() {
    let owed = check();
    let holder = ProfileId::generate();

    let event = owed.contested_event(holder);
    assert_eq!(event.event_type, event_types::PRINCIPAL_CONTESTED);
    assert_eq!(
        event.subject.as_deref(),
        Some(&*format!("profile/{holder}"))
    );
    assert_eq!(event.data["profile_id"], holder.to_string());
    assert_eq!(event.data["principal_type"], "email");
    assert_eq!(event.data["principal_value"], "a@sid.example.com");
    assert_eq!(
        event.data["new_claimer_profile_id"],
        owed.new_holder.to_string()
    );
    assert_eq!(event.id, owed.contested_event(holder).id);
    assert_ne!(event.id, owed.contested_event(ProfileId::generate()).id);
}
