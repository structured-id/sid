// SPDX-License-Identifier: AGPL-3.0-only
//! Consents: a create never replaces one, a claim decision never brings back
//! a revoked or disconnected consent, and concurrent decisions keep one
//! active grant per claim.

use sid_core::Error;
use sid_core::models::consent::{
    ClaimDecision, ClaimGrantChange, ClaimType, ConsentMode, ConsentRecord, ConsentStatus,
    DisclosedValue, DisclosureUpdate,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::application::grant_resource;
use super::{create_test_profile, test_audit};

/// A stored active consent of a new profile.
async fn active_consent(backend: &dyn StorageBackend) -> ConsentRecord {
    let profile = create_test_profile("consent");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut consent = ConsentRecord::new(profile.id, format!("rp-{}", Uuid::now_v7().simple()));
    consent.grant_claim("email", ClaimType::Data, ConsentMode::Subscribed);
    consent.grants[0].disclosed = Some(value("a@sid.example.com", Some(true)));
    consent.grant_scopes(
        grant_resource(backend).await,
        &["openid".to_owned(), "read".to_owned()],
    );
    consent.as_requested().unwrap().grant();
    backend
        .create_consent(&consent, test_audit())
        .await
        .unwrap();
    consent
}

/// `value` as disclosed.
fn value(value: &str, verified: Option<bool>) -> DisclosedValue {
    DisclosedValue {
        value: value.into(),
        verified,
    }
}

/// A stored active consent sharing a verified email and the name with
/// updates, and the phone as a snapshot.
async fn disclosing_consent(backend: &dyn StorageBackend) -> ConsentRecord {
    let profile = create_test_profile("disclosure");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut consent = ConsentRecord::new(profile.id, format!("rp-{}", Uuid::now_v7().simple()));
    for (name, mode, disclosed) in [
        (
            "email",
            ConsentMode::Subscribed,
            value("a@sid.example.com", Some(true)),
        ),
        ("name", ConsentMode::Subscribed, value("Alice", None)),
        (
            "phone_number",
            ConsentMode::Static,
            value("+380501234567", Some(false)),
        ),
    ] {
        consent.grant_claim(name, ClaimType::Data, mode);
        if let Some(grant) = consent.grants.last_mut() {
            grant.disclosed = Some(disclosed);
        }
    }
    consent.as_requested().unwrap().grant();
    backend
        .create_consent(&consent, test_audit())
        .await
        .unwrap();
    consent
}

/// The value claim `name` of the stored consent `id` discloses.
async fn disclosed(
    backend: &dyn StorageBackend,
    id: sid_core::models::consent::ConsentId,
    name: &str,
) -> Option<DisclosedValue> {
    backend
        .get_consent(id)
        .await
        .unwrap()
        .unwrap()
        .grants
        .into_iter()
        .find(|g| g.claim_name == name)
        .and_then(|g| g.disclosed)
}

fn update(
    name: &str,
    prior: Option<DisclosedValue>,
    next: Option<DisclosedValue>,
) -> DisclosureUpdate {
    DisclosureUpdate {
        claim_name: name.into(),
        prior,
        next,
    }
}

/// A Profile read with its primary contacts is one state of the store: a
/// writer renames the Profile to `i` and then makes `i@…` its primary email,
/// round after round, and every read sees an email no newer than the name
/// and at most one round older. A read of the name and then the email apart
/// can see a newer email beside an older name, a combination that never
/// existed. The interleaving inside one call cannot be forced from outside
/// the trait, so this states the contract under concurrent writes; the
/// guarantee itself is each store's single read transaction.
pub async fn test_profile_with_contacts_reads_one_state(backend: &dyn StorageBackend) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut profile = create_test_profile("contacts-state");
    profile.given_name = Some("0".into());
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let id = profile.id;
    let done = AtomicBool::new(false);
    let writer = async {
        for round in 1..=50_u32 {
            let mut current = backend.get_profile(id).await.unwrap().unwrap();
            current.given_name = Some(round.to_string());
            assert!(
                backend
                    .update_profile(&current, test_audit())
                    .await
                    .unwrap()
            );
            let now = jiff::Timestamp::now();
            let email = sid_core::models::ProfileEmail {
                id: sid_core::models::ProfileEmailId::new(),
                profile_id: id,
                email: format!("{round}-{}@sid.example.com", Uuid::now_v7().simple()),
                label: sid_core::models::EmailLabel::Personal,
                custom_label: None,
                is_primary: true,
                verified: false,
                verified_at: None,
                created_at: now,
                updated_at: now,
            };
            backend
                .create_profile_email(&email, test_audit())
                .await
                .unwrap();
        }
        done.store(true, Ordering::SeqCst);
    };
    let reader = async {
        let mut reads = 0;
        while !done.load(Ordering::SeqCst) || reads == 0 {
            let read = backend
                .get_profile_with_primary_contacts(id)
                .await
                .unwrap()
                .unwrap();
            let name: u32 = read.profile.given_name.unwrap().parse().unwrap();
            let email = read.email.map_or(0, |e| {
                e.email
                    .split('-')
                    .next()
                    .and_then(|round| round.parse().ok())
                    .unwrap()
            });
            assert!(
                email <= name && name <= email + 1,
                "name {name} beside email {email}: no such state"
            );
            reads += 1;
            tokio::task::yield_now().await;
        }
    };
    tokio::join!(writer, reader);
}

/// The consent `id` as stored.
async fn stored(
    backend: &dyn StorageBackend,
    id: sid_core::models::consent::ConsentId,
) -> ConsentRecord {
    backend.get_consent(id).await.unwrap().unwrap()
}

/// A delivery over the consent as read commits the whole replacement and
/// answers exactly what it committed: the new values, a cleared field no
/// longer disclosed, and a later revision.
pub async fn test_subscribed_delivery_commits_over_the_consent_read(backend: &dyn StorageBackend) {
    let consent = disclosing_consent(backend).await;
    let held = stored(backend, consent.id).await;
    let email_b = Some(value("b@sid.example.com", Some(false)));

    let delivered = backend
        .deliver_subscribed(
            &held,
            &[
                update(
                    "email",
                    Some(value("a@sid.example.com", Some(true))),
                    email_b.clone(),
                ),
                update("name", Some(value("Alice", None)), None),
            ],
            test_audit(),
        )
        .await
        .unwrap()
        .expect("delivered over the consent read");
    assert_eq!(delivered, stored(backend, consent.id).await);
    assert!(delivered.updated_at > held.updated_at);
    assert_eq!(disclosed(backend, consent.id, "email").await, email_b);
    assert_eq!(disclosed(backend, consent.id, "name").await, None);
}

/// A decision committed after the consent was read and before the delivery
/// wins: the holder withdrew the name while the email's delivery was
/// planned from the older read, so the delivery writes nothing and the
/// withdrawal stands. An ended consent takes no delivery either.
pub async fn test_subscribed_delivery_yields_to_a_later_decision(backend: &dyn StorageBackend) {
    let consent = disclosing_consent(backend).await;
    let held = stored(backend, consent.id).await;
    let email_a = Some(value("a@sid.example.com", Some(true)));
    let planned = [update(
        "email",
        email_a.clone(),
        Some(value("b@sid.example.com", Some(false))),
    )];

    let withdrawn = backend
        .change_claim_grant(consent.id, "name", ClaimDecision::Revoke, test_audit())
        .await
        .unwrap();
    assert_eq!(withdrawn, ClaimGrantChange::Changed);
    assert_eq!(
        backend
            .deliver_subscribed(&held, &planned, test_audit())
            .await
            .unwrap(),
        None
    );
    let after = stored(backend, consent.id).await;
    assert_eq!(disclosed(backend, consent.id, "email").await, email_a);
    assert!(
        after
            .grants
            .iter()
            .any(|g| g.claim_name == "name" && !g.is_active())
    );

    backend
        .revoke_consents_by_profile(consent.profile_id, test_audit())
        .await
        .unwrap();
    let revoked = stored(backend, consent.id).await;
    let mut as_active = revoked.clone();
    as_active.status = ConsentStatus::Active;
    assert_eq!(
        backend
            .deliver_subscribed(&as_active, &planned, test_audit())
            .await
            .unwrap(),
        None
    );
}

/// Two deliveries planned from the same read race: one commits and the
/// other writes nothing, so a delivery from an older read never overwrites
/// a newer one.
pub async fn test_subscribed_delivery_under_concurrency(backend: &dyn StorageBackend) {
    let consent = disclosing_consent(backend).await;
    let held = stored(backend, consent.id).await;
    let prior = Some(value("Alice", None));
    let first = [update("name", prior.clone(), Some(value("Alicia", None)))];
    let second = [update("name", prior, Some(value("Alison", None)))];
    let (a, b) = tokio::join!(
        backend.deliver_subscribed(&held, &first, test_audit()),
        backend.deliver_subscribed(&held, &second, test_audit()),
    );
    let committed = match (a.unwrap(), b.unwrap()) {
        (Some(won), None) | (None, Some(won)) => won,
        other => panic!("exactly one delivery commits: {other:?}"),
    };
    assert_eq!(committed, stored(backend, consent.id).await);
}

fn active_claims(consent: &ConsentRecord, claim: &str) -> usize {
    consent
        .grants
        .iter()
        .filter(|g| g.claim_name == claim && g.is_active())
        .count()
}

/// A stored consent reads back whole: its claim grants with their update
/// modes and its scope grants per resource, which the consent gate compares
/// a request against.
pub async fn test_consent_reads_back_grants_and_scopes(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;
    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(stored.grants.len(), 1);
    assert_eq!(stored.grants[0].mode, ConsentMode::Subscribed);
    assert_eq!(stored.scope_grants.len(), 1);
    let granted = &consent.scope_grants[0];
    assert_eq!(stored.scope_grants[0].resource_id, granted.resource_id);
    assert_eq!(stored.scope_grants[0].scopes, granted.scopes);
    let email = sid_core::models::ClaimRequest {
        subscription: sid_core::models::ClaimSubscription::Preferred,
        ..sid_core::models::ClaimRequest::required("email", stored.grants[0].claim_type)
    };
    assert!(stored.covers(granted.resource_id, &granted.scopes, &[&email]));

    let by_client = backend
        .get_consent_by_client(consent.profile_id, &consent.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_client.scope_grants, stored.scope_grants);
}

/// Creating a consent never replaces one: not over its id, not for the same
/// profile and client.
pub async fn test_create_consent_never_replaces(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;

    let mut same_id = consent.clone();
    same_id.status = ConsentStatus::Revoked;
    let err = backend
        .create_consent(&same_id, test_audit())
        .await
        .expect_err("a create over an existing consent");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let same_pair = ConsentRecord::new(consent.profile_id, consent.client_id.clone());
    let err = backend
        .create_consent(&same_pair, test_audit())
        .await
        .expect_err("a second consent for one profile and client");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ConsentStatus::Active);
}

/// Granting and revoking a claim change only that claim, and repeating a
/// decision changes nothing.
pub async fn test_change_claim_grant(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;
    let grant = ClaimDecision::Grant(ClaimType::Attestation);

    assert_eq!(
        backend
            .change_claim_grant(consent.id, "age_over_18", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Changed
    );
    assert_eq!(
        backend
            .change_claim_grant(consent.id, "age_over_18", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Unchanged
    );
    assert_eq!(
        backend
            .change_claim_grant(consent.id, "email", ClaimDecision::Revoke, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Changed
    );
    assert_eq!(
        backend
            .change_claim_grant(consent.id, "email", ClaimDecision::Revoke, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Unchanged
    );

    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(active_claims(&stored, "age_over_18"), 1);
    assert_eq!(active_claims(&stored, "email"), 0);
    assert_eq!(stored.status, ConsentStatus::Active);

    // A revoked claim can be granted again, as the one grant of that claim.
    assert_eq!(
        backend
            .change_claim_grant(
                consent.id,
                "email",
                ClaimDecision::Grant(ClaimType::Data),
                test_audit()
            )
            .await
            .unwrap(),
        ClaimGrantChange::Changed
    );
    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(active_claims(&stored, "email"), 1);
    assert_eq!(
        stored
            .grants
            .iter()
            .filter(|g| g.claim_name == "email")
            .count(),
        1
    );
    // A claim granted from account management is a snapshot until the user
    // chooses updates; the renewed claim keeps its earlier mode.
    let mode = |name: &str| {
        stored
            .grants
            .iter()
            .find(|g| g.claim_name == name)
            .unwrap()
            .mode
    };
    assert_eq!(mode("age_over_18"), ConsentMode::Static);
    assert_eq!(mode("email"), ConsentMode::Subscribed);
}

/// A decision on a disconnected consent does not bring it back, and one on
/// a consent revoked with its profile's consents grants nothing: the revoked
/// consent keeps no active grant.
pub async fn test_claim_grant_keeps_ended_consent_ended(backend: &dyn StorageBackend) {
    let grant = ClaimDecision::Grant(ClaimType::Data);

    let disconnected = active_consent(backend).await;
    assert!(
        backend
            .delete_consent(disconnected.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .delete_consent(disconnected.id, test_audit())
            .await
            .unwrap(),
        "a repeated disconnect reported a deletion"
    );
    assert_eq!(
        backend
            .change_claim_grant(disconnected.id, "phone", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::ConsentNotActive
    );
    assert!(
        backend
            .get_consent(disconnected.id)
            .await
            .unwrap()
            .is_none(),
        "a disconnected consent was recreated"
    );

    let revoked = active_consent(backend).await;
    backend
        .revoke_consents_by_profile(revoked.profile_id, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .change_claim_grant(revoked.id, "phone", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::ConsentNotActive
    );
    let stored = backend.get_consent(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ConsentStatus::Revoked);
    assert!(
        !stored.has_active_grants(),
        "a revoked consent kept an active grant"
    );
}

/// Concurrent decisions: two grants of one claim leave one active grant, and
/// grants of two claims both apply.
pub async fn test_claim_grants_under_concurrency(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;
    let grant = ClaimDecision::Grant(ClaimType::Data);

    let (a, b) = tokio::join!(
        backend.change_claim_grant(consent.id, "phone", grant, test_audit()),
        backend.change_claim_grant(consent.id, "phone", grant, test_audit()),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| *o == ClaimGrantChange::Unchanged);
    assert_eq!(
        outcomes,
        [ClaimGrantChange::Changed, ClaimGrantChange::Unchanged]
    );

    let (a, b) = tokio::join!(
        backend.change_claim_grant(consent.id, "name", grant, test_audit()),
        backend.change_claim_grant(consent.id, "address", grant, test_audit()),
    );
    assert_eq!(a.unwrap(), ClaimGrantChange::Changed);
    assert_eq!(b.unwrap(), ClaimGrantChange::Changed);

    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(active_claims(&stored, "phone"), 1);
    assert_eq!(active_claims(&stored, "name"), 1);
    assert_eq!(active_claims(&stored, "address"), 1);
}
