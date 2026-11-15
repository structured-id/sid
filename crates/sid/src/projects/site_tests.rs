// SPDX-License-Identifier: AGPL-3.0-only
//! Registering another organization's federation site at this installation:
//! installation B enrolls its site with the development platform of
//! `sid_fed::test_support` and signs its admission statement; installation A
//! registers B's site as a client from that statement alone.

use sid_core::models::{
    IssuerAuthority, LoginSettings, OfflineLimits, StatusPolicy, StatusRequirement,
};
use sid_fed::participant::Mount;
use sid_fed::recipient::{ClassicalVerdict, Recipient};
use sid_fed::test_support::{PARTICIPANT_SERIAL, enroll, hold_platform};
use uuid::Uuid;

use super::*;
use crate::federation_site::FederationSite;
use crate::test_support::{administrator, keys, operation, storage, stored_profile};

const A: &str = "https://a.sid.example.com";
const B: &str = "https://b.sid.example.com";

/// Installation B, enrolled as a site, entered at its issuer's URL.
struct SiteB {
    org: model::OrgId,
    mount: Mount,
    statement: Vec<u8>,
}

/// B's signed statement for its entry, its site certificate issued by the
/// development platform for `site`.
async fn site_b(site: Uuid) -> SiteB {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let keys = keys();
    let org = sid_authn::instance_org::ensure(storage.as_ref(), "b.sid.example.com")
        .await
        .unwrap();
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys.as_ref(),
        &url::Url::parse(B).unwrap(),
        org.id,
    )
    .await
    .unwrap();
    let recipient = Arc::new(Recipient::new(storage.clone(), ClassicalVerdict));
    hold_platform(recipient.as_ref(), 1, &[]).await;
    let admin = administrator(stored_profile(storage.as_ref(), "b-admin").await);
    let federation = FederationSite::new(storage.clone(), keys, recipient, org.id);
    let request = federation.enrollment_request(&admin).await.unwrap();
    let certificate = enroll(
        org.id.into_uuid(),
        site,
        &request.public_key,
        &[issuer.canonical_url.as_str()],
    );
    federation.hold(&admin, certificate, vec![]).await.unwrap();
    let mount = Mount::parse(&issuer.canonical_url).unwrap();
    let statement = federation.admission(&admin, &mount).await.unwrap();
    SiteB {
        org: org.id,
        mount,
        statement,
    }
}

/// Installation A: its projects register sites with a recipient holding the
/// platform set.
struct InstallationA {
    storage: Arc<dyn StorageBackend>,
    recipient: Arc<Recipient>,
    projects: Projects,
    admin: Caller,
    project: Option<sid_ids_proto::ProjectId>,
}

async fn installation_a() -> InstallationA {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let keys = keys();
    let org = sid_authn::instance_org::ensure(storage.as_ref(), "a.sid.example.com")
        .await
        .unwrap();
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys.as_ref(),
        &url::Url::parse(A).unwrap(),
        org.id,
    )
    .await
    .unwrap();
    let recipient = Arc::new(Recipient::new(storage.clone(), ClassicalVerdict));
    hold_platform(recipient.as_ref(), 1, &[]).await;
    let projects = Projects::new(storage.clone(), issuer).with_site_registrar(SiteRegistrar {
        identities: recipient.clone(),
        keys,
        base: url::Url::parse(A).unwrap(),
    });
    let admin = administrator(stored_profile(storage.as_ref(), "a-admin").await);
    let created = projects
        .create_project(
            &admin,
            operation(storage.as_ref(), "project-1").await,
            CreateProjectRequest {
                name: "Partners".into(),
                description: String::new(),
                owner_profile_id: None,
            },
        )
        .await
        .unwrap();
    InstallationA {
        storage,
        recipient,
        projects,
        admin,
        project: created.id,
    }
}

/// The client settings of a federation site registered from `statement`.
fn site_settings(statement: &[u8]) -> ClientRoleSettings {
    ClientRoleSettings {
        r#type: v1::ApplicationType::Web as i32,
        participant_admission: Some(statement.to_vec()),
        ..ClientRoleSettings::default()
    }
}

impl InstallationA {
    async fn register(
        &self,
        key: &str,
        client: ClientRoleSettings,
        org_id: Option<model::OrgId>,
    ) -> Result<Issued<CreateApplicationResponse>, ProjectError> {
        self.projects
            .create_application(
                &self.admin,
                operation(self.storage.as_ref(), key).await,
                CreateApplicationRequest {
                    project_id: self.project.clone(),
                    name: "Site B".into(),
                    client: Some(client),
                    resource: None,
                    org_id: org_id.map(Into::into),
                },
            )
            .await
    }
}

fn site_id(n: u128) -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0000 | n)
}

// B's site registers at A from its statement alone: the client belongs to
// B, its one redirect URI is the shared callback at B's admitted mount, the
// statement is kept with it, B is held as a reference (never as A's
// instance) and A has its own issuer for B, which the client reports. A
// retry of the same call answers with the same application and creates no
// second client. Bug prevented: a site's client registered under A's own
// organization, with a typed callback, or twice on a lost answer.
#[tokio::test]
async fn a_site_is_registered_from_its_statement() {
    let b = site_b(site_id(1)).await;
    let a = installation_a().await;
    let issued = a
        .register("site-1", site_settings(&b.statement), None)
        .await
        .unwrap();
    let client = issued.response.application.unwrap().client.unwrap();
    assert_eq!(
        client.redirect_uris,
        [b.mount.at(sid_core::models::entry_connection::CALLBACK)]
    );
    let issuer = a
        .storage
        .oidc_issuer_for(IssuerAuthority::Local, b.org)
        .await
        .unwrap()
        .expect("A's issuer for B");
    assert_eq!(client.issuer, issuer.canonical_url);
    assert!(issuer.canonical_url.starts_with(&format!("{A}/i/")));
    let stored = a
        .storage
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.org_id, Some(b.org));
    assert_eq!(
        stored.participant_admission.as_deref(),
        Some(b.statement.as_slice())
    );
    assert_eq!(
        a.storage
            .organization_references()
            .await
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        [b.org]
    );

    let retried = a
        .register("site-1", site_settings(&b.statement), None)
        .await
        .unwrap();
    assert_eq!(
        retried
            .response
            .application
            .unwrap()
            .client
            .unwrap()
            .client_id,
        client.client_id
    );
}

// Two registrations for one organization are two clients under the one
// issuer A keeps for that organization. Bug prevented: a second registration
// replacing the first, or a second issuer and so a second subject for the
// same organization.
#[tokio::test]
async fn two_registrations_of_one_organization_share_its_issuer() {
    let first = site_b(site_id(2)).await;
    let a = installation_a().await;
    let one = a
        .register("site-2a", site_settings(&first.statement), None)
        .await
        .unwrap()
        .response
        .application
        .unwrap()
        .client
        .unwrap();
    let again = a
        .register("site-2b", site_settings(&first.statement), None)
        .await
        .unwrap()
        .response
        .application
        .unwrap()
        .client
        .unwrap();
    assert_ne!(one.client_id, again.client_id);
    assert_eq!(one.issuer, again.issuer);
    let issuers = a.storage.list_oidc_issuers().await.unwrap();
    assert_eq!(
        issuers
            .iter()
            .filter(|i| i.recipient_org == first.org)
            .count(),
        1
    );
}

// What the administrator types never pairs B with another callback or
// organization: a redirect URI, another organization, a public client type
// or a resource role beside the statement is refused, and so is a statement
// that does not verify. Nothing is created: no client, no reference, no
// issuer for B. Bug prevented: a real recipient organization paired with an
// attacker's callback reaching the Binding allocator.
#[tokio::test]
async fn what_the_statement_does_not_settle_is_refused() {
    let b = site_b(site_id(3)).await;
    let a = installation_a().await;
    let typed = ClientRoleSettings {
        redirect_uris: vec!["https://attacker.example.com/cb".into()],
        ..site_settings(&b.statement)
    };
    let public = ClientRoleSettings {
        r#type: v1::ApplicationType::Spa as i32,
        ..site_settings(&b.statement)
    };
    let mut forged = b.statement.clone();
    let last = forged.len() - 3;
    forged[last] ^= 0x01;
    let cases = [
        ("typed-callback", typed, None, "client.redirect_uris"),
        ("public", public, None, "client.participant_admission"),
        (
            "other-org",
            site_settings(&b.statement),
            Some(model::OrgId::generate()),
            "org_id",
        ),
        (
            "forged",
            site_settings(&forged),
            None,
            "client.participant_admission",
        ),
    ];
    for (key, settings, org, field) in cases {
        let refused = a.register(key, settings, org).await;
        assert!(
            matches!(&refused, Err(ProjectError::InvalidField { field: f, .. }) if *f == field),
            "{key}: {:?}",
            refused.err()
        );
    }
    let with_resource = a
        .projects
        .create_application(
            &a.admin,
            operation(a.storage.as_ref(), "with-resource").await,
            CreateApplicationRequest {
                project_id: a.project.clone(),
                name: "Site B".into(),
                client: Some(site_settings(&b.statement)),
                resource: Some(ResourceRoleSettings {
                    indicator: "https://api.a.sid.example.com".into(),
                    scopes: vec!["read".into()],
                }),
                org_id: None,
            },
        )
        .await;
    assert!(matches!(
        with_resource,
        Err(ProjectError::InvalidField {
            field: "resource",
            ..
        })
    ));
    // No refusal left an application behind.
    let clients = a
        .storage
        .list_applications_by_project(wire_id(a.project.as_ref(), "project").unwrap(), 0, 10)
        .await
        .unwrap();
    assert!(clients.is_empty());
}

// The site's callback is never retyped after registration. Bug prevented:
// a registered recipient later pointed at another callback by an edit.
#[tokio::test]
async fn a_sites_callback_is_not_edited() {
    let b = site_b(site_id(4)).await;
    let a = installation_a().await;
    let client = a
        .register("site-4", site_settings(&b.statement), None)
        .await
        .unwrap()
        .response
        .application
        .unwrap()
        .client
        .unwrap();
    let edited = a
        .projects
        .update_client_role(
            &a.admin,
            operation(a.storage.as_ref(), "edit-4").await,
            UpdateClientRoleRequest {
                client_id: client.client_id.clone(),
                redirect_uris: vec!["https://attacker.example.com/cb".into()],
                ..UpdateClientRoleRequest::default()
            },
        )
        .await;
    assert!(matches!(
        edited,
        Err(ProjectError::InvalidField {
            field: "redirect_uris",
            ..
        })
    ));
    let stored = a
        .storage
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.redirect_uris, client.redirect_uris);
}

// A site whose certificate the platform revoked is not registered, under
// any status policy, and the refusal is final rather than a retry. Bug
// prevented: a withdrawn member registered as a recipient.
#[tokio::test]
async fn a_withdrawn_site_is_not_registered() {
    let b = site_b(site_id(5)).await;
    let a = installation_a().await;
    hold_platform(a.recipient.as_ref(), 2, &[PARTICIPANT_SERIAL]).await;
    let relaxed = LoginSettings {
        status_policy: StatusPolicy {
            issuer: StatusRequirement::Offline(OfflineLimits::ANY),
            authorities: StatusRequirement::Offline(OfflineLimits::ANY),
        },
        revision: 1,
        ..LoginSettings::default()
    };
    assert!(
        a.storage
            .set_login_settings(
                &relaxed,
                None,
                AuditEntry::system("test", "settings").into()
            )
            .await
            .unwrap()
    );
    let refused = a
        .register("site-5", site_settings(&b.statement), None)
        .await;
    assert!(matches!(
        refused,
        Err(ProjectError::InvalidField {
            field: "client.participant_admission",
            ..
        })
    ));
}

// A registered site's client stays usable only while its statement stands:
// once the platform revoked the site's certificate it is refused at its next
// use, under any status policy, and an installation verifying no federation
// evidence serves no such client. An ordinary client is not concerned. Bug
// prevented: a withdrawn member keeps receiving Bindings because it was
// registered while it stood.
#[tokio::test]
async fn a_site_client_is_usable_only_while_its_admission_stands() {
    use crate::oauth::{OAuthError, site_admission_stands};
    let b = site_b(site_id(7)).await;
    let a = installation_a().await;
    let client_id = a
        .register("site-7", site_settings(&b.statement), None)
        .await
        .unwrap()
        .response
        .application
        .unwrap()
        .client
        .unwrap()
        .client_id;
    let client = a
        .storage
        .get_oauth2_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    let verifier: &dyn sid_fed::recipient::PresentedIdentities = a.recipient.as_ref();
    site_admission_stands(a.storage.as_ref(), Some(verifier), &client)
        .await
        .unwrap();
    assert!(matches!(
        site_admission_stands(a.storage.as_ref(), None, &client).await,
        Err(OAuthError::ClientRefused)
    ));
    let ordinary = OAuth2Client {
        participant_admission: None,
        ..client.clone()
    };
    site_admission_stands(a.storage.as_ref(), None, &ordinary)
        .await
        .unwrap();

    hold_platform(a.recipient.as_ref(), 2, &[PARTICIPANT_SERIAL]).await;
    let relaxed = LoginSettings {
        status_policy: StatusPolicy {
            issuer: StatusRequirement::Offline(OfflineLimits::ANY),
            authorities: StatusRequirement::Offline(OfflineLimits::ANY),
        },
        revision: 1,
        ..LoginSettings::default()
    };
    assert!(
        a.storage
            .set_login_settings(
                &relaxed,
                None,
                AuditEntry::system("test", "settings").into()
            )
            .await
            .unwrap()
    );
    assert!(matches!(
        site_admission_stands(a.storage.as_ref(), Some(verifier), &client).await,
        Err(OAuthError::ClientRefused)
    ));
}

// An installation that registers no sites refuses the statement instead of
// registering an ordinary client without it. Bug prevented: the evidence
// silently dropped and a typed client created under A's own organization.
#[tokio::test]
async fn an_installation_without_a_registrar_refuses_sites() {
    let b = site_b(site_id(6)).await;
    let a = installation_a().await;
    let plain = Projects::new(
        a.storage.clone(),
        a.storage
            .list_oidc_issuers()
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
    );
    let refused = plain
        .create_application(
            &a.admin,
            operation(a.storage.as_ref(), "plain").await,
            CreateApplicationRequest {
                project_id: a.project.clone(),
                name: "Site B".into(),
                client: Some(site_settings(&b.statement)),
                resource: None,
                org_id: None,
            },
        )
        .await;
    assert!(matches!(
        refused,
        Err(ProjectError::InvalidField {
            field: "client.participant_admission",
            ..
        })
    ));
}
