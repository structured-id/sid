// SPDX-License-Identifier: AGPL-3.0-only
//! The user directory query contract, run against every backend: the filter
//! is applied before pagination over the whole directory, the total counts
//! every match, a user appears once however many of its values match, a
//! comparison follows the attribute's case rule, a missing value matches no
//! comparison, and retired profiles are never listed.

use chrono::Utc;
use futures::StreamExt;
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
    let now = Utc::now();
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

/// A user created after more than ten thousand others is found by its
/// userName: the whole directory is filtered, not a bounded prefix of it.
pub async fn test_directory_finds_a_user_beyond_ten_thousand(backend: &dyn StorageBackend) {
    let existing = backend.count_profiles().await.unwrap();
    let needed = 10_001u64.saturating_sub(existing);
    futures::stream::iter(0..needed)
        .for_each_concurrent(16, |_| async {
            backend
                .create_profile(&Profile::new(None::<String>), test_audit())
                .await
                .unwrap();
        })
        .await;
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
