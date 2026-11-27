// SPDX-License-Identifier: AGPL-3.0-only
//! The user directory query contract, run against every backend: the filter
//! is applied before pagination over the whole directory, the total counts
//! every match, a user appears once however many of its values match, a
//! comparison follows the attribute's case rule, a missing value matches no
//! comparison, and retired profiles are never listed.

use jiff::Timestamp;
use sid_core::models::profile_email::EmailLabel;
use sid_core::models::{
    DirectoryAttribute as Attr, DirectoryFilter as F, DirectoryOperator as Op, DirectoryQuery,
    DirectoryUserWrite, DirectoryWriteMode, Principal, PrincipalType, Profile, ProfileEmail,
    ProfileEmailId, ProfileMetadata, ProfileStatus,
};
use sid_plugin::storage::StorageBackend;

use super::test_audit;

/// A domain of this run only, so its corporate logins match nothing else in
/// a shared database.
fn domain() -> String {
    format!("dq-{}.example.com", uuid::Uuid::now_v7().simple())
}

/// A directory user of `domain` with login `user_name`, the given emails and
/// metadata.
async fn add_user(
    backend: &dyn StorageBackend,
    domain: &str,
    user_name: &str,
    emails: &[&str],
    metadata: &[(&str, &str)],
) -> Profile {
    let mut profile = Profile::new(None::<String>);
    profile.given_name = Some(format!("Given {user_name}"));
    let id = profile.id;
    let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Create, profile.clone());
    write.bind.push(Principal::new(
        profile.id,
        PrincipalType::Username,
        format!("{user_name}#{domain}"),
    ));
    let now = Timestamp::now();
    for (i, email) in emails.iter().enumerate() {
        write.add_emails.push(ProfileEmail {
            id: ProfileEmailId::new(),
            profile_id: profile.id,
            email: (*email).to_string(),
            label: EmailLabel::Work,
            custom_label: None,
            is_primary: i == 0,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        });
    }
    for (key, value) in metadata {
        write.set_metadata.push(ProfileMetadata::new(
            profile.id,
            *key,
            serde_json::Value::String((*value).to_string()),
        ));
    }
    backend
        .write_directory_user(&write, test_audit())
        .await
        .expect("a directory user is written");
    // As stored, at the revision a later update must name.
    backend.get_profile(id).await.unwrap().expect("written")
}

/// `filter` over this run's users only: a shared database holds other runs'
/// users, and only this run's have a login of its unique domain.
fn query(domain: &str, filter: F, offset: u64, limit: u64) -> DirectoryQuery {
    DirectoryQuery {
        org_domain: domain.to_string(),
        filter: Some(F::And(
            Box::new(F::Present(Attr::UserName)),
            Box::new(filter),
        )),
        offset,
        limit,
    }
}

fn compare(attribute: Attr, operator: Op, value: &str) -> F {
    F::Compare {
        attribute,
        operator,
        value: value.to_string(),
    }
}

/// The userNames of a page, in its order.
async fn names(backend: &dyn StorageBackend, q: &DirectoryQuery) -> (u64, Vec<String>) {
    let page = backend
        .query_directory(q)
        .await
        .expect("the directory answers");
    let suffix = format!("#{}", q.org_domain);
    let names = page
        .users
        .iter()
        .map(|user| {
            user.principals
                .iter()
                .find(|p| p.principal_type == PrincipalType::Username)
                .and_then(|p| p.value.strip_suffix(&suffix))
                .expect("a directory user of this domain has its login")
                .to_string()
        })
        .collect();
    (page.total, names)
}

/// The profiles a directory must hold before the user that
/// [`test_directory_finds_a_user_beyond_ten_thousand`] looks for.
pub const DIRECTORY_BEYOND: u64 = 10_001;

/// A user created after more than ten thousand others is found by its
/// userName: the whole directory is filtered, not a bounded prefix of it.
/// The harness seeds the [`DIRECTORY_BEYOND`] profiles first, in bulk: only
/// their number matters here.
pub async fn test_directory_finds_a_user_beyond_ten_thousand(backend: &dyn StorageBackend) {
    let existing = backend.count_profiles().await.unwrap();
    assert!(
        existing >= DIRECTORY_BEYOND,
        "the harness seeded {existing} profiles, not {DIRECTORY_BEYOND}"
    );
    let domain = domain();
    add_user(backend, &domain, "late.arrival", &[], &[]).await;

    let (total, found) = names(
        backend,
        &query(
            &domain,
            compare(Attr::UserName, Op::Eq, "late.arrival"),
            0,
            100,
        ),
    )
    .await;
    assert_eq!(found, vec!["late.arrival"]);
    assert_eq!(total, 1);
}

/// The filter is applied before the page: offset and limit count matches
/// only, the total counts all of them on every page (a last, an empty and a
/// total-only one), and a user with several matching emails appears once.
pub async fn test_directory_filters_before_pagination(backend: &dyn StorageBackend) {
    let domain = domain();
    for name in ["ann", "bob", "cid"] {
        add_user(
            backend,
            &domain,
            name,
            &[
                &format!("{name}@{domain}"),
                &format!("{name}.alias@{domain}"),
            ],
            &[],
        )
        .await;
    }
    add_user(backend, &domain, "zed", &["zed@elsewhere.example.com"], &[]).await;
    let by_domain = compare(Attr::Email, Op::EndsWith, &format!("@{domain}"));

    let (total, all) = names(backend, &query(&domain, by_domain.clone(), 0, 10)).await;
    assert_eq!(
        all,
        vec!["ann", "bob", "cid"],
        "once each, in creation order"
    );
    assert_eq!(total, 3);
    let (total, last) = names(backend, &query(&domain, by_domain.clone(), 2, 2)).await;
    assert_eq!((total, last), (3, vec!["cid".to_string()]));
    let (total, empty) = names(backend, &query(&domain, by_domain.clone(), 5, 2)).await;
    assert_eq!((total, empty.len()), (3, 0));
    let (total, none) = names(backend, &query(&domain, by_domain, 0, 0)).await;
    assert_eq!((total, none.len()), (3, 0), "a total-only page");
}

/// Comparisons follow RFC 7644 §3.4.2.2 and RFC 7643 §4.1.1: userName and
/// emails compare case-insensitively, externalId case-exactly; contains,
/// starts-with, ends-with and ordering; `and`/`or`/`not`; a missing value
/// matches no comparison, so `not` of it matches; presence needs a value;
/// a value is data, never SQL.
pub async fn test_directory_comparison_semantics(backend: &dyn StorageBackend) {
    let domain = domain();
    add_user(
        backend,
        &domain,
        "Alice.Smith",
        &[&format!("Alice@{domain}")],
        &[("employee_id", "E-100"), ("department", "Sales")],
    )
    .await;
    add_user(
        backend,
        &domain,
        "bob.jones",
        &[],
        &[("employee_id", "e-200"), ("title", "Engineer")],
    )
    .await;
    let found = async |filter: F| names(backend, &query(&domain, filter, 0, 10)).await.1;

    assert_eq!(
        found(compare(Attr::UserName, Op::Eq, "alice.smith")).await,
        vec!["Alice.Smith"]
    );
    assert_eq!(
        found(compare(
            Attr::Email,
            Op::Eq,
            &format!("alice@{}", domain.to_uppercase())
        ))
        .await,
        vec!["Alice.Smith"]
    );
    assert!(
        found(compare(Attr::ExternalId, Op::Eq, "e-100"))
            .await
            .is_empty(),
        "case-exact"
    );
    assert_eq!(
        found(compare(Attr::ExternalId, Op::Eq, "E-100")).await,
        vec!["Alice.Smith"]
    );
    assert_eq!(
        found(compare(Attr::UserName, Op::Contains, "ICE.SM")).await,
        vec!["Alice.Smith"]
    );
    assert_eq!(
        found(compare(Attr::UserName, Op::StartsWith, "BOB")).await,
        vec!["bob.jones"]
    );
    assert_eq!(
        found(compare(Attr::UserName, Op::EndsWith, ".jones")).await,
        vec!["bob.jones"]
    );
    assert_eq!(
        found(compare(Attr::UserName, Op::Greater, "b")).await,
        vec!["bob.jones"]
    );
    assert_eq!(
        found(compare(Attr::UserName, Op::LessOrEqual, "alice.smith")).await,
        vec!["Alice.Smith"]
    );
    assert_eq!(
        found(F::And(
            Box::new(compare(Attr::Department, Op::Eq, "sales")),
            Box::new(compare(Attr::UserName, Op::StartsWith, "a")),
        ))
        .await,
        vec!["Alice.Smith"]
    );
    assert_eq!(
        found(F::Or(
            Box::new(compare(Attr::Title, Op::Eq, "engineer")),
            Box::new(compare(Attr::Department, Op::Eq, "sales")),
        ))
        .await,
        vec!["Alice.Smith", "bob.jones"]
    );
    // bob has no department: no comparison of it matches, its negation does.
    assert!(
        found(compare(Attr::Department, Op::Ne, "sales"))
            .await
            .is_empty()
    );
    assert_eq!(
        found(F::And(
            Box::new(compare(Attr::UserName, Op::StartsWith, "")),
            Box::new(F::Not(Box::new(compare(Attr::Department, Op::Eq, "sales")))),
        ))
        .await,
        vec!["bob.jones"]
    );
    assert_eq!(found(F::Present(Attr::Title)).await, vec!["bob.jones"]);
    assert_eq!(found(F::Present(Attr::Email)).await, vec!["Alice.Smith"]);
    assert_eq!(
        found(F::Present(Attr::UserName)).await,
        vec!["Alice.Smith", "bob.jones"]
    );
    assert!(
        found(compare(Attr::UserName, Op::Eq, "x' OR '1'='1"))
            .await
            .is_empty(),
        "a value is data"
    );
}

/// A case-insensitive comparison folds case beyond ASCII (`caseExact: false`,
/// RFC 7643 §2.2): `ÉLODIE` finds `élodie` on every engine, in a login, an
/// email, the display name and an extension attribute, by every operator
/// that folds.
pub async fn test_directory_folds_unicode_case(backend: &dyn StorageBackend) {
    let domain = domain();
    add_user(
        backend,
        &domain,
        "élodie",
        &[&format!("élodie@{domain}")],
        &[("title", "Ingénieure")],
    )
    .await;
    add_user(backend, &domain, "zoé", &[], &[]).await;
    let found = async |filter: F| names(backend, &query(&domain, filter, 0, 10)).await.1;

    for filter in [
        compare(Attr::UserName, Op::Eq, "ÉLODIE"),
        compare(Attr::UserName, Op::StartsWith, "ÉL"),
        compare(Attr::Email, Op::Eq, &format!("ÉLODIE@{domain}")),
        compare(Attr::DisplayName, Op::Contains, "ÉLODIE"),
        compare(Attr::Title, Op::Eq, "INGÉNIEURE"),
    ] {
        assert_eq!(found(filter.clone()).await, vec!["élodie"], "{filter:?}");
    }
    assert_eq!(
        found(compare(Attr::UserName, Op::EndsWith, "OÉ")).await,
        vec!["zoé"]
    );

    // Simple case mapping, one code point to one, as on every engine:
    // `İ` folds to `i` (not `i` + combining dot), and a final `Σ` to `σ`
    // (not the contextual `ς`).
    add_user(backend, &domain, "İrem", &[], &[]).await;
    add_user(backend, &domain, "ΟΔΟΣ", &[], &[]).await;
    assert_eq!(
        found(compare(Attr::UserName, Op::Eq, "irem")).await,
        vec!["İrem"]
    );
    assert_eq!(
        found(compare(Attr::UserName, Op::Eq, "οδοσ")).await,
        vec!["ΟΔΟΣ"]
    );
}

/// The page carries each user's own principals, emails and metadata, and
/// `active` follows suspension.
pub async fn test_directory_users_carry_their_attributes(backend: &dyn StorageBackend) {
    let domain = domain();
    let carol = add_user(
        backend,
        &domain,
        "carol",
        &[&format!("carol@{domain}"), &format!("c@{domain}")],
        &[("title", "Lead")],
    )
    .await;
    let dave = add_user(backend, &domain, "dave", &[], &[]).await;
    let mut suspended = dave.clone();
    suspended.status = ProfileStatus::Suspended;
    backend
        .write_directory_user(
            &DirectoryUserWrite::new(DirectoryWriteMode::Update, suspended),
            test_audit(),
        )
        .await
        .unwrap();

    let page = backend
        .query_directory(&query(&domain, F::Present(Attr::UserName), 0, 10))
        .await
        .unwrap();
    let carol_page = page
        .users
        .iter()
        .find(|u| u.profile.id == carol.id)
        .unwrap();
    assert_eq!(carol_page.emails.len(), 2);
    assert!(carol_page.emails.iter().all(|e| e.profile_id == carol.id));
    assert!(
        carol_page
            .principals
            .iter()
            .all(|p| p.profile_id == carol.id)
    );
    assert_eq!(carol_page.metadata.len(), 1);
    let dave_page = page.users.iter().find(|u| u.profile.id == dave.id).unwrap();
    assert!(dave_page.emails.is_empty() && dave_page.metadata.is_empty());

    let (_, inactive) = names(
        backend,
        &query(&domain, compare(Attr::Active, Op::Eq, "false"), 0, 10),
    )
    .await;
    assert_eq!(inactive, vec!["dave"]);
    let (_, active) = names(
        backend,
        &query(&domain, compare(Attr::Active, Op::Ne, "FALSE"), 0, 10),
    )
    .await;
    assert_eq!(active, vec!["carol"]);
    assert!(
        backend
            .query_directory(&query(
                &domain,
                compare(Attr::Active, Op::Greater, "true"),
                0,
                10
            ))
            .await
            .is_err(),
        "a boolean compares by eq or ne only"
    );
}

/// `active` tells whether the account can be used: an account in use or
/// provisioned is active; a suspended one, one under a hold and one being
/// closed are not, whichever of them a deactivation found it in.
pub async fn test_directory_active_follows_use(backend: &dyn StorageBackend) {
    let domain = domain();
    for (name, status) in [
        ("in-use", ProfileStatus::Active),
        ("provisioned", ProfileStatus::Provisioned),
        ("suspended", ProfileStatus::Suspended),
        ("held", ProfileStatus::LegalHold),
        ("closing", ProfileStatus::ClosureRequested),
    ] {
        let mut profile = add_user(backend, &domain, name, &[], &[]).await;
        if profile.status != status {
            profile.status = status;
            backend
                .write_directory_user(
                    &DirectoryUserWrite::new(DirectoryWriteMode::Update, profile),
                    test_audit(),
                )
                .await
                .unwrap();
        }
    }
    let (_, mut active) = names(
        backend,
        &query(&domain, compare(Attr::Active, Op::Eq, "true"), 0, 10),
    )
    .await;
    active.sort();
    assert_eq!(active, vec!["in-use", "provisioned"]);
    let (_, mut inactive) = names(
        backend,
        &query(&domain, compare(Attr::Active, Op::Eq, "false"), 0, 10),
    )
    .await;
    inactive.sort();
    assert_eq!(inactive, vec!["closing", "held", "suspended"]);
}

/// The live resource of `profile`.
async fn resource_of(
    backend: &dyn StorageBackend,
    profile: &Profile,
) -> sid_core::models::DirectoryResource {
    let found = backend.directory_users_of(&[profile.id]).await.unwrap();
    assert_eq!(found.len(), 1, "an account has one live resource");
    found[0]
}

/// Every account gets a directory resource of its own when it is created,
/// whatever path creates it: an identifier that is not the account's, found
/// by itself, and the one the directory lists the user under.
pub async fn test_directory_resource_assigned_with_the_account(backend: &dyn StorageBackend) {
    let domain = domain();
    let listed = add_user(backend, &domain, "listed", &[], &[]).await;
    let plain = Profile::new(None::<String>);
    backend.create_profile(&plain, test_audit()).await.unwrap();

    for profile in [&listed, &plain] {
        let resource = resource_of(backend, profile).await;
        assert_ne!(resource.id.0, profile.id.into_uuid());
        assert_eq!(resource.profile_id, profile.id);
        assert!(resource.is_live());
        assert_eq!(
            backend.find_directory_user(resource.id).await.unwrap(),
            Some(resource)
        );
    }
    assert_ne!(
        resource_of(backend, &listed).await.id,
        resource_of(backend, &plain).await.id
    );
    let page = backend
        .query_directory(&query(&domain, F::Present(Attr::UserName), 0, 10))
        .await
        .unwrap();
    assert_eq!(page.users.len(), 1);
    assert_eq!(page.users[0].id, resource_of(backend, &listed).await.id);
    assert_eq!(
        backend
            .find_directory_user(sid_core::models::DirectoryUserId::new())
            .await
            .unwrap(),
        None,
        "an identifier never assigned names nothing"
    );
}

/// A deletion through the resource commits with the rest of its write: the
/// resource is kept, deleted, and found by no directory read; the account
/// stays as the write left it. Nothing is written through a resource that
/// is deleted, unknown or another account's, and a repeat of the deletion is
/// not found.
pub async fn test_directory_resource_deletion(backend: &dyn StorageBackend) {
    let domain = domain();
    let kept = add_user(backend, &domain, "kept", &[], &[]).await;
    let mut gone = add_user(backend, &domain, "gone", &[], &[]).await;
    let kept_resource = resource_of(backend, &kept).await;
    let resource = resource_of(backend, &gone).await;

    // Another account's resource opens no write on this one.
    let mut stolen = gone.clone();
    stolen.given_name = Some("Stolen".into());
    let refused = backend
        .write_directory_user(
            &DirectoryUserWrite::new(DirectoryWriteMode::Update, stolen).through(kept_resource.id),
            test_audit(),
        )
        .await;
    assert!(
        matches!(refused, Err(sid_core::Error::NotFound(_))),
        "{refused:?}"
    );
    assert_eq!(backend.get_profile(gone.id).await.unwrap().unwrap(), gone);

    gone.status = ProfileStatus::Suspended;
    let mut delete =
        DirectoryUserWrite::new(DirectoryWriteMode::Update, gone.clone()).through(resource.id);
    delete.delete_resource = true;
    backend
        .write_directory_user(&delete, test_audit())
        .await
        .expect("the resource is deleted");

    let stored = backend
        .find_directory_user(resource.id)
        .await
        .unwrap()
        .expect("a deleted resource is kept");
    assert!(!stored.is_live());
    assert_eq!(stored.profile_id, gone.id);
    assert!(stored.revision > resource.revision);
    assert!(
        backend
            .directory_users_of(&[gone.id])
            .await
            .unwrap()
            .is_empty()
    );
    let account = backend.get_profile(gone.id).await.unwrap().expect("kept");
    assert_eq!(account.status, ProfileStatus::Suspended);
    let (total, listed) = names(backend, &query(&domain, F::Present(Attr::UserName), 0, 10)).await;
    assert_eq!((total, listed), (1, vec!["kept".to_string()]));

    // Through the deleted resource nothing is written: neither a change nor
    // a second deletion (the account is read again at its new revision).
    for delete_again in [false, true] {
        let mut later = account.clone();
        later.status = ProfileStatus::Active;
        let mut write =
            DirectoryUserWrite::new(DirectoryWriteMode::Update, later).through(resource.id);
        write.delete_resource = delete_again;
        let refused = backend.write_directory_user(&write, test_audit()).await;
        assert!(
            matches!(refused, Err(sid_core::Error::NotFound(_))),
            "{refused:?}"
        );
    }
    assert_eq!(
        backend.get_profile(gone.id).await.unwrap().unwrap().status,
        ProfileStatus::Suspended
    );
    assert_eq!(
        backend.find_directory_user(resource.id).await.unwrap(),
        Some(stored)
    );

    // A deletion names its resource, and a create is given none.
    let mut unnamed = DirectoryUserWrite::new(DirectoryWriteMode::Update, account.clone());
    unnamed.delete_resource = true;
    assert!(matches!(
        backend.write_directory_user(&unnamed, test_audit()).await,
        Err(sid_core::Error::Validation(_))
    ));
    let created = DirectoryUserWrite::new(DirectoryWriteMode::Create, Profile::new(None::<String>))
        .through(kept_resource.id);
    assert!(matches!(
        backend.write_directory_user(&created, test_audit()).await,
        Err(sid_core::Error::Validation(_))
    ));
}

/// Of a deletion and a change read from the same state, made at once, the
/// resource ends deleted and the change either committed before it or wrote
/// nothing: it is never applied through the deleted resource.
pub async fn test_directory_resource_deletion_races_a_change(backend: &dyn StorageBackend) {
    let domain = domain();
    let user = add_user(backend, &domain, "raced", &[], &[]).await;
    let resource = resource_of(backend, &user).await;

    let mut suspended = user.clone();
    suspended.status = ProfileStatus::Suspended;
    let mut delete =
        DirectoryUserWrite::new(DirectoryWriteMode::Update, suspended).through(resource.id);
    delete.delete_resource = true;
    let mut renamed = user.clone();
    renamed.given_name = Some("Renamed".into());
    let change = DirectoryUserWrite::new(DirectoryWriteMode::Update, renamed).through(resource.id);

    let (deleted, changed) = tokio::join!(
        backend.write_directory_user(&delete, test_audit()),
        backend.write_directory_user(&change, test_audit()),
    );
    // Both read one revision of the account: one of them wins it.
    assert!(
        deleted.is_ok() != changed.is_ok(),
        "{deleted:?} {changed:?}"
    );
    let stored = backend
        .find_directory_user(resource.id)
        .await
        .unwrap()
        .unwrap();
    let account = backend.get_profile(user.id).await.unwrap().unwrap();
    if deleted.is_ok() {
        assert!(!stored.is_live());
        assert_eq!(account.given_name, user.given_name);
        assert_eq!(account.status, ProfileStatus::Suspended);
    } else {
        assert!(stored.is_live());
        assert_eq!(account.given_name.as_deref(), Some("Renamed"));
    }
}

/// A restored account keeps the identifiers its clients know: the resources
/// it had replace the one assigned when it was created, deleted ones
/// included, a repeat changes nothing, and an identifier of another account
/// is refused.
pub async fn test_directory_resources_are_carried(backend: &dyn StorageBackend) {
    use sid_core::models::{DirectoryResource, DirectoryUserId};
    let domain = domain();
    let user = add_user(backend, &domain, "restored", &[], &[]).await;
    let other = add_user(backend, &domain, "other", &[], &[]).await;
    let assigned = resource_of(backend, &user).await;
    let carried = [
        DirectoryResource {
            id: DirectoryUserId::new(),
            profile_id: user.id,
            revision: 3,
            deleted_at: Some(Timestamp::from_second(1_700_000_000).unwrap()),
        },
        DirectoryResource {
            id: DirectoryUserId::new(),
            profile_id: user.id,
            revision: 0,
            deleted_at: None,
        },
    ];
    for _ in 0..2 {
        backend
            .import_directory_users(user.id, &carried, test_audit())
            .await
            .expect("the account takes its resources");
    }
    assert_eq!(
        backend.find_directory_user(assigned.id).await.unwrap(),
        None
    );
    for resource in carried {
        assert_eq!(
            backend.find_directory_user(resource.id).await.unwrap(),
            Some(resource)
        );
    }
    assert_eq!(resource_of(backend, &user).await, carried[1]);
    let exported = backend.export_directory_users().await.unwrap();
    for resource in carried {
        assert!(exported.contains(&resource), "{resource:?} is exported");
    }

    // Another account's identifier, or two live resources, write nothing.
    let foreign = [resource_of(backend, &other).await];
    assert!(
        backend
            .import_directory_users(user.id, &foreign, test_audit())
            .await
            .is_err()
    );
    let taken = [DirectoryResource {
        profile_id: user.id,
        ..resource_of(backend, &other).await
    }];
    assert!(matches!(
        backend
            .import_directory_users(user.id, &taken, test_audit())
            .await,
        Err(sid_core::Error::Conflict(_))
    ));
    let two_live = [
        carried[1],
        DirectoryResource {
            id: DirectoryUserId::new(),
            ..carried[1]
        },
    ];
    assert!(matches!(
        backend
            .import_directory_users(user.id, &two_live, test_audit())
            .await,
        Err(sid_core::Error::Validation(_))
    ));
    assert_eq!(resource_of(backend, &user).await, carried[1]);
    assert_eq!(resource_of(backend, &other).await.profile_id, other.id);
}

/// Closed and purged profiles are retired records, not directory users.
pub async fn test_directory_omits_retired_profiles(backend: &dyn StorageBackend) {
    let domain = domain();
    for (name, status) in [
        ("kept", ProfileStatus::Provisioned),
        ("closed", ProfileStatus::Closed),
        ("purged", ProfileStatus::Purged),
    ] {
        let mut profile = add_user(backend, &domain, name, &[], &[]).await;
        if status != ProfileStatus::Provisioned {
            profile.status = status;
            backend
                .write_directory_user(
                    &DirectoryUserWrite::new(DirectoryWriteMode::Update, profile),
                    test_audit(),
                )
                .await
                .unwrap();
        }
    }
    let (total, listed) = names(backend, &query(&domain, F::Present(Attr::UserName), 0, 10)).await;
    assert_eq!((total, listed), (1, vec!["kept".to_string()]));
}
