// SPDX-License-Identifier: AGPL-3.0-only
//! Email policy revisions: an email key is written only under the active
//! revision, and keys written before revisions existed stay reserved but
//! route nobody after the cutover.

use sid_core::Error;
use sid_core::models::{
    EmailLabel, INSTALLATION_EMAIL_POLICY_REVISION, Principal, PrincipalEligibility, PrincipalType,
    ProfileEmail, ProfileEmailId, ProfileId, check_principal_eligibility,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, new_email_registration, test_audit};

const CURRENT: Option<i64> = Some(INSTALLATION_EMAIL_POLICY_REVISION);

fn address(tag: &str) -> String {
    format!("{tag}{}@sid.example.com", Uuid::now_v7().simple())
}

/// A key derived under the active revision is stored with it; a key of any
/// other revision, one written without a revision (by a build that does not
/// know revisions) and a revision on a non-email principal are refused as
/// `Fenced`, and nothing is stored.
pub async fn test_email_key_written_only_under_the_active_revision(backend: &dyn StorageBackend) {
    let profile = create_test_profile("email_fence");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let current = address("fence_current");
    backend
        .save_principal(&Principal::new_email(profile.id, &current), test_audit())
        .await
        .unwrap();
    let stored = backend
        .get_principal_by_value(PrincipalType::Email, &current)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(stored.email_policy_revision, CURRENT);

    for (revision, tag) in [
        (Some(INSTALLATION_EMAIL_POLICY_REVISION + 1), "fence_other"),
        (Some(0), "fence_legacy"),
        (None, "fence_none"),
    ] {
        let value = address(tag);
        let mut principal = Principal::new_email(profile.id, &value);
        principal.email_policy_revision = revision;
        let err = backend
            .save_principal(&principal, test_audit())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Fenced(_)), "{revision:?}: {err:?}");
        assert!(
            backend
                .get_principal_by_value(PrincipalType::Email, &value)
                .await
                .unwrap()
                .is_none(),
            "{revision:?}: nothing stored"
        );
    }

    let mut phone = Principal::new(profile.id, PrincipalType::Phone, "+380501112233");
    phone.email_policy_revision = CURRENT;
    let err = backend
        .save_principal(&phone, test_audit())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");

    let mut stale = new_email_registration(&address("fence_register"));
    stale.principal.email_policy_revision = Some(INSTALLATION_EMAIL_POLICY_REVISION + 1);
    let err = backend
        .register_profile(&stale, test_audit())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    assert!(
        backend
            .get_profile(stale.profile.id)
            .await
            .unwrap()
            .is_none()
    );
}

/// A row the email normalizer left behind before policy revisions.
pub struct LegacyRow {
    /// The principal value as stored.
    pub key: String,
    /// The linked contact as stored, if any.
    pub contact: Option<String>,
    pub verified: bool,
}

/// The historical shapes the cutover must not promote: a Cyrillic address
/// whose ASCII skeleton was copied into both principal and contact, a
/// registration whose dots, tag and case were folded into both, a principal
/// with no source contact, a bare `verified`, and an administrator's raw
/// address whose key under the current rules differs from the stored value.
pub fn legacy_rows(domain: &str) -> Vec<LegacyRow> {
    vec![
        LegacyRow {
            key: format!("alice@{domain}"),
            contact: Some(format!("alice@{domain}")),
            verified: false,
        },
        LegacyRow {
            key: format!("annsmith@{domain}"),
            contact: Some(format!("annsmith@{domain}")),
            verified: false,
        },
        LegacyRow {
            key: format!("carol@{domain}"),
            contact: None,
            verified: false,
        },
        LegacyRow {
            key: format!("dave@{domain}"),
            contact: Some(format!("dave@{domain}")),
            verified: true,
        },
        LegacyRow {
            key: format!("Bob.Jones@{domain}"),
            contact: Some(format!("Bob.Jones@{domain}")),
            verified: false,
        },
    ]
}

/// After the cutover every legacy key (`legacy`: stored value and its
/// assigned Profile) is kept with revision 0 and routes nobody, its holder
/// included; it still reserves the handle against a new registration; the
/// accounts are untouched; no key is rewritten into its current form; and a
/// new key under the current revision is written normally.
pub async fn legacy_keys_are_quarantined(
    backend: &dyn StorageBackend,
    legacy: &[(String, ProfileId)],
    domain: &str,
) {
    for (key, profile) in legacy {
        let entity = backend
            .get_principal_by_value(PrincipalType::Email, key)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{key} kept"));
        assert_eq!(entity.email_policy_revision, Some(0), "{key}");
        assert_eq!(entity.assigned_profile_id, Some(*profile), "{key}");
        assert_eq!(
            check_principal_eligibility(&entity, *profile, true, CURRENT),
            PrincipalEligibility::KeyNotCurrent,
            "{key} routes nobody"
        );
        assert!(backend.get_profile(*profile).await.unwrap().is_some());

        let newcomer = new_email_registration(key);
        let err = backend
            .register_profile(&newcomer, test_audit())
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "{key} stays reserved: {err:?}"
        );
    }
    assert!(
        backend
            .get_principal_by_value(PrincipalType::Email, &format!("bobjones@{domain}"))
            .await
            .unwrap()
            .is_none(),
        "a raw address is not rewritten into its current key"
    );

    let fresh = new_email_registration(&format!("fresh@{domain}"));
    backend
        .register_profile(&fresh, test_audit())
        .await
        .unwrap();
    let entity = backend
        .get_principal_by_value(PrincipalType::Email, &format!("fresh@{domain}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entity.email_policy_revision, CURRENT);
}

/// A contact of `profile` at `address`, as an authorized operation
/// establishes it.
fn evidence(profile: ProfileId, address: &str) -> ProfileEmail {
    let now = chrono::Utc::now();
    ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile,
        email: address.to_string(),
        label: EmailLabel::Work,
        custom_label: None,
        is_primary: false,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    }
}

/// Repairing quarantined keys (`legacy`, at least three, after the cutover):
/// the holder's key comes back on its established address, linked to it and
/// routing again; a repeat, another profile and a key no longer quarantined
/// change nothing; evidence that is another profile's contact is refused;
/// of two repairs racing for one key exactly one succeeds.
pub async fn legacy_keys_are_reconciled(
    backend: &dyn StorageBackend,
    legacy: &[(String, ProfileId)],
) {
    let key = |i: usize| -> (&str, ProfileId) { (legacy[i].0.as_str(), legacy[i].1) };
    let entity = |value: &str| {
        let value = value.to_string();
        async move {
            backend
                .get_principal_by_value(PrincipalType::Email, &value)
                .await
                .unwrap()
                .expect("kept")
        }
    };

    // The established address is the mailbox's real spelling, which the
    // folded copies lost; its key is the stored value.
    let (value, holder) = key(0);
    let principal = entity(value).await;
    let contact = evidence(holder, &value.replacen('a', "A", 1));
    assert!(
        backend
            .reconcile_email_key(
                principal.id,
                holder,
                &contact,
                "admin_reconciled",
                test_audit()
            )
            .await
            .unwrap()
    );
    let repaired = entity(value).await;
    assert_eq!(repaired.email_policy_revision, CURRENT);
    assert_eq!(
        check_principal_eligibility(&repaired, holder, true, CURRENT),
        PrincipalEligibility::Eligible
    );
    let claim = backend
        .get_principals_by_profile(holder)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.value == value)
        .unwrap();
    assert_eq!(claim.source_email_id, Some(contact.id));
    assert!(
        backend
            .list_profile_emails(holder)
            .await
            .unwrap()
            .iter()
            .any(|e| e.id == contact.id && e.email == contact.email)
    );
    assert!(
        !backend
            .reconcile_email_key(
                principal.id,
                holder,
                &evidence(holder, value),
                "again",
                test_audit()
            )
            .await
            .unwrap(),
        "no longer quarantined"
    );

    let (value, holder) = key(1);
    let principal = entity(value).await;
    let stranger = create_test_profile("reconcile_stranger");
    backend
        .create_profile(&stranger, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .reconcile_email_key(
                principal.id,
                stranger.id,
                &evidence(stranger.id, value),
                "stranger",
                test_audit()
            )
            .await
            .unwrap(),
        "another profile does not take the key"
    );
    let err = backend
        .reconcile_email_key(
            principal.id,
            holder,
            &evidence(stranger.id, value),
            "foreign evidence",
            test_audit(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(entity(value).await.email_policy_revision, Some(0));

    let (value, holder) = key(2);
    let principal = entity(value).await;
    let (a, b) = (evidence(holder, value), evidence(holder, value));
    let (ra, rb) = tokio::join!(
        backend.reconcile_email_key(principal.id, holder, &a, "race a", test_audit()),
        backend.reconcile_email_key(principal.id, holder, &b, "race b", test_audit()),
    );
    assert_eq!(
        [ra.unwrap(), rb.unwrap()]
            .iter()
            .filter(|won| **won)
            .count(),
        1,
        "exactly one repair wins"
    );
}
