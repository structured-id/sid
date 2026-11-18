// SPDX-License-Identifier: AGPL-3.0-only
//! The site over a real store and real certificates: the development
//! platform of `sid_fed::test_support` enrolls it, and the classical
//! recipient verifies what the site holds and signs.

use sid_core::models::{LoginSettings, OfflineLimits, StatusPolicy, StatusRequirement};
use sid_fed::participant::key_of_record;
use sid_fed::recipient::{ClassicalVerdict, Recipient};
use sid_fed::test_support::{PARTICIPANT_SERIAL, enroll, hold_platform};
use uuid::Uuid;

use super::*;
use crate::test_support::{administrator, keys, storage, stored_profile};

const ISSUER: &str = "https://b.sid.example.com";

/// An installation serving its organization under [`ISSUER`], holding the
/// platform set.
struct Installed {
    storage: Arc<dyn StorageBackend>,
    recipient: Arc<Recipient>,
    site: FederationSite,
    organization: OrgId,
    admin: Caller,
    /// The address the installation is entered at: its issuer's exact URL.
    mount: String,
}

async fn installed() -> Installed {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let keys = keys();
    let organization = sid_authn::instance_org::ensure(storage.as_ref(), "b.sid.example.com")
        .await
        .unwrap();
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys.as_ref(),
        &url::Url::parse(ISSUER).unwrap(),
        organization.id,
    )
    .await
    .unwrap();
    let recipient = Arc::new(Recipient::new(storage.clone(), ClassicalVerdict));
    hold_platform(recipient.as_ref(), 1, &[]).await;
    let admin = administrator(stored_profile(storage.as_ref(), "admin").await);
    Installed {
        site: FederationSite::new(storage.clone(), keys, recipient.clone(), organization.id),
        storage,
        recipient,
        organization: organization.id,
        admin,
        mount: issuer.canonical_url,
    }
}

impl Installed {
    /// The platform's certificate for this site's key at `mounts`, for the
    /// organization `organization`.
    async fn certificate(&self, organization: Uuid, mounts: &[&str]) -> Vec<u8> {
        let request = self.site.enrollment_request(&self.admin).await.unwrap();
        enroll(organization, site_id(), &request.public_key, mounts)
    }
}

fn site_id() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0c0c)
}

// The request names the site's key, the record that publishes exactly that
// key and the address the installation is entered at, and asking again
// names the same key. The certificate the platform issues for it is held
// and read back as the site; holding it again changes nothing. Bug
// prevented: a second request drawing a new key under a certificate
// already issued for the first, or a site that cannot be enrolled because
// its request and the platform disagree on its address.
#[tokio::test]
async fn a_site_is_enrolled_with_the_key_it_asked_for() {
    let i = installed().await;
    assert!(i.site.enrolled(&i.admin).await.unwrap().is_none());
    let request = i.site.enrollment_request(&i.admin).await.unwrap();
    assert_eq!(
        key_of_record(&request.key_record).as_deref(),
        Some(request.public_key.as_slice())
    );
    assert_eq!(request.mounts, [Mount::parse(&i.mount).unwrap()]);
    assert_eq!(i.site.enrollment_request(&i.admin).await.unwrap(), request);

    let certificate = i
        .certificate(i.organization.into_uuid(), &[i.mount.as_str()])
        .await;
    let enrolled = i
        .site
        .hold(&i.admin, certificate.clone(), vec![])
        .await
        .unwrap();
    assert_eq!(enrolled.organization, i.organization.into_uuid());
    assert_eq!(enrolled.site, site_id());
    assert_eq!(enrolled.mounts, request.mounts);
    assert_eq!(
        i.site.enrolled(&i.admin).await.unwrap(),
        Some(enrolled.clone())
    );
    assert_eq!(
        i.site.hold(&i.admin, certificate, vec![]).await.unwrap(),
        enrolled
    );
}

// Only this site's own enrollment is held: a certificate for another key,
// for another organization, listing an address this installation does not
// serve, or one no held platform authority issued is refused and nothing is
// held. Only an administrator asks or holds. Bug prevented: an installation
// signing as a site it is not, or stating admissions for an address that
// leads elsewhere.
#[tokio::test]
async fn only_this_sites_own_enrollment_is_held() {
    let i = installed().await;
    let own = i.organization.into_uuid();
    let other_key = SiteKey::read(&SiteKey::generate().unwrap())
        .unwrap()
        .public_key()
        .unwrap();
    let another_key = enroll(own, site_id(), &other_key, &[i.mount.as_str()]);
    assert!(matches!(
        i.site.hold(&i.admin, another_key, vec![]).await,
        Err(FederationSiteError::AnotherKey)
    ));
    let another_organization = i.certificate(Uuid::now_v7(), &[i.mount.as_str()]).await;
    assert!(matches!(
        i.site.hold(&i.admin, another_organization, vec![]).await,
        Err(FederationSiteError::AnotherOrganization)
    ));
    for elsewhere in [
        "https://b.sid.example.com/i/0123456789abcdef0123456789abcdef",
        "https://b.sid.example.com:8443",
        "https://c.sid.example.com",
    ] {
        let listed = i.certificate(own, &[i.mount.as_str(), elsewhere]).await;
        assert!(
            matches!(
                i.site.hold(&i.admin, listed, vec![]).await,
                Err(FederationSiteError::NotAnEntry(named)) if named == elsewhere
            ),
            "{elsewhere}"
        );
    }
    let garbage = i.site.hold(&i.admin, vec![0x30, 0x00], vec![]).await;
    assert!(matches!(garbage, Err(FederationSiteError::Refused(_))));
    assert_eq!(i.storage.site_enrollment().await.unwrap(), None);

    let now = jiff::Timestamp::now().as_second();
    let user = Caller::from_claims(&sid_authn::jwt::AccessTokenClaims {
        sub: i.admin.profile_id.to_string(),
        pid: Some(i.admin.profile_id.to_string()),
        iss: "https://sid.example.com".into(),
        aud: vec!["https://sid.example.com".into()],
        client_id: None,
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: String::new(),
        sid: Uuid::now_v7().to_string(),
        amr: vec!["pwd".into()],
        jti: Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
        credential_kind: None,
    })
    .unwrap();
    assert!(matches!(
        i.site.enrollment_request(&user).await,
        Err(FederationSiteError::Caller(_))
    ));
    let certificate = i.certificate(own, &[i.mount.as_str()]).await;
    assert!(matches!(
        i.site.hold(&user, certificate, vec![]).await,
        Err(FederationSiteError::Caller(_))
    ));
    assert!(matches!(
        i.site
            .admission(&i.admin, &Mount::parse(&i.mount).unwrap())
            .await,
        Err(FederationSiteError::NotEnrolled)
    ));
}

// The site's statement repeats the stored login settings at the moment it
// is made (both switches, the whole set of admitted organizations in order,
// the revision), is accepted by another installation holding only the
// platform set, and is made only for an entry the certificate lists. After
// a change of the settings a new statement states the change; the earlier
// one still states the earlier revision. Bug prevented: a statement that
// admits an organization the settings do not, drops one they do, or hides
// that it is older than a later change.
#[tokio::test]
async fn the_statement_repeats_the_stored_settings() {
    let i = installed().await;
    let own = i.organization.into_uuid();
    let certificate = i.certificate(own, &[i.mount.as_str()]).await;
    i.site.hold(&i.admin, certificate, vec![]).await.unwrap();
    let mount = Mount::parse(&i.mount).unwrap();
    let (low, high) = {
        let mut pair = [OrgId::generate(), OrgId::generate()];
        pair.sort_unstable_by_key(|id| id.into_uuid());
        (pair[0], pair[1])
    };
    let mut held = None;
    let mut settle = async |sources: Vec<OrgId>, revision: u64| {
        let next = LoginSettings {
            allow_personal_profiles: false,
            allow_foreign_corporate_profiles: true,
            admitted_sources: sources.try_into().unwrap(),
            revision,
            ..LoginSettings::default()
        };
        assert!(
            i.storage
                .set_login_settings(
                    &next,
                    held.as_ref(),
                    AuditEntry::system("test", "settings").into()
                )
                .await
                .unwrap()
        );
        held = Some(next);
    };

    // Another installation: it holds the platform set and nothing of B.
    let elsewhere: Arc<dyn StorageBackend> = storage().await;
    let reader = Recipient::new(elsewhere, ClassicalVerdict);
    hold_platform(&reader, 1, &[]).await;
    let read = async |jws: &[u8]| {
        reader
            .accept_admission(jws, &StatusPolicy::default(), SystemTime::now())
            .await
            .unwrap()
            .admission
    };

    settle(vec![high, low], 1).await;
    let first = i.site.admission(&i.admin, &mount).await.unwrap();
    let stated = read(&first).await;
    assert_eq!(stated.recipient_org, own);
    assert_eq!(stated.site, site_id());
    assert_eq!(stated.mount, mount);
    assert_eq!(stated.revision, 1);
    assert!(!stated.allow_personal_profiles);
    assert!(stated.allow_foreign_corporate_profiles);
    assert_eq!(stated.admitted_sources, [low.into_uuid(), high.into_uuid()]);

    settle(vec![high], 2).await;
    let second = read(&i.site.admission(&i.admin, &mount).await.unwrap()).await;
    assert_eq!(second.revision, 2);
    assert!(!second.admits_source(low.into_uuid()));
    assert!(second.admits_source(high.into_uuid()));
    assert_eq!(read(&first).await.revision, 1);

    let unlisted = Mount::parse("https://b.sid.example.com/other").unwrap();
    assert!(matches!(
        i.site.admission(&i.admin, &unlisted).await,
        Err(FederationSiteError::NotAnEntry(_))
    ));
}

// A site whose certificate the platform withdrew is no site: it is not
// read as enrolled and signs no statement, under any status policy. Bug
// prevented: an installation that keeps stating its admissions as a member
// after the platform ended its membership.
#[tokio::test]
async fn a_withdrawn_site_states_nothing() {
    let i = installed().await;
    let certificate = i
        .certificate(i.organization.into_uuid(), &[i.mount.as_str()])
        .await;
    i.site.hold(&i.admin, certificate, vec![]).await.unwrap();
    let mount = Mount::parse(&i.mount).unwrap();
    i.site.admission(&i.admin, &mount).await.unwrap();

    hold_platform(i.recipient.as_ref(), 2, &[PARTICIPANT_SERIAL]).await;
    let relaxed = LoginSettings {
        status_policy: StatusPolicy {
            issuer: StatusRequirement::Offline(OfflineLimits::ANY),
            authorities: StatusRequirement::Offline(OfflineLimits::ANY),
        },
        revision: 1,
        ..LoginSettings::default()
    };
    assert!(
        i.storage
            .set_login_settings(
                &relaxed,
                None,
                AuditEntry::system("test", "settings").into()
            )
            .await
            .unwrap()
    );
    for refused in [
        i.site.enrolled(&i.admin).await.map(|_| ()),
        i.site.admission(&i.admin, &mount).await.map(|_| ()),
    ] {
        let refused = refused.unwrap_err();
        assert!(
            matches!(&refused, FederationSiteError::Refused(_)),
            "{refused:?}"
        );
        assert!(!refused.undecided());
    }
}

mod publication;
