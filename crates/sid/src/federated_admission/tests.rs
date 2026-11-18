// SPDX-License-Identifier: AGPL-3.0-only
//! Admission over a real store and real passports: the development platform
//! of `sid_fed::test_support` issues them, and the classical recipient
//! verifies them as a self-managed installation does.

use std::sync::Arc;

use jiff::Timestamp;
use sid_core::models::{
    ClientCredential, EntryHandle, IssuerAuthority, IssuerHandle, IssuerId, LoginSettings,
    MutationContext, ProfileType,
};
use sid_fed::allocation::ContextAllocation;
use sid_fed::recipient::{ClassicalVerdict, Recipient};
use sid_fed::test_support::{
    Issued, PASSPORT_SERIAL, corporate, hold_platform, organization_ca, organization_status,
    personal,
};
use sid_plugin::entry_connection::EntryConnectionStore;

use super::*;
use crate::test_support::storage;

const ISSUER: &str = "https://source.sid.example.com/i/0123456789abcdef0123456789abcdef";
const CHALLENGE: &str = "n-0S6_WzA2Mj";

fn audit() -> MutationContext {
    AuditEntry::system("test", "federated_admission").into()
}

/// A recipient installation: its store, the recipient that verifies under
/// the platform set it holds, its issuer and one connection.
struct Installed {
    storage: Arc<dyn StorageBackend>,
    recipient: Recipient,
    issuer: OidcIssuer,
    connection: EntryConnection,
}

async fn installed(owner: ConnectionOwner, source: Option<OrgId>) -> Installed {
    let storage = storage().await;
    let recipient = Recipient::new(storage.clone(), ClassicalVerdict);
    hold_platform(&recipient, 1, &[]).await;
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: OrgId::generate(),
        created_at: Timestamp::now(),
    };
    let handle = EntryHandle::generate();
    let connection = EntryConnection {
        handle,
        owner,
        name: "Source".into(),
        issuer: ISSUER.into(),
        source,
        recipient_issuer: issuer.id,
        callback: format!("{}/auth/federation/{handle}/callback", issuer.canonical_url),
        use_return: None,
        client_id: "recipient-client".into(),
        credential: ClientCredential::SecretBasic(sid_keys::EncryptedField {
            ciphertext: vec![5; 48],
            nonce: [5; 12],
            key_version: 1,
            context: "test".into(),
        }),
        enabled: true,
        revision: 0,
        created_at: Timestamp::from_microsecond(Timestamp::now().as_microsecond()).unwrap(),
        updated_at: Timestamp::from_microsecond(Timestamp::now().as_microsecond()).unwrap(),
    };
    // Admission reads the connection back as the entry used it.
    storage
        .create_entry_connection(&connection, audit())
        .await
        .unwrap();
    Installed {
        storage,
        recipient,
        issuer,
        connection,
    }
}

impl Installed {
    fn organization(&self) -> Uuid {
        self.issuer.recipient_org.into()
    }

    /// Hold the status the authority of `source` publishes, revoking the
    /// passports whose serials are `revoked`.
    async fn status(&self, source: OrgId, number: u8, revoked: &[u32]) {
        let source: Uuid = source.into();
        self.recipient
            .record_issuer_status(
                ContextAllocation::Development,
                source,
                &organization_ca(source),
                &[],
                &organization_status(source, number, revoked),
                SystemTime::now(),
            )
            .await
            .unwrap();
    }

    /// Set the recipient's two admissions and the organizations whose
    /// Corporate Profiles it admits.
    async fn settings(&self, personal: bool, foreign_corporate: bool, sources: &[OrgId]) {
        let held = self.storage.login_settings().await.unwrap();
        let next = LoginSettings {
            allow_personal_profiles: personal,
            allow_foreign_corporate_profiles: foreign_corporate,
            admitted_sources: sources.to_vec().try_into().unwrap(),
            status_policy: held
                .as_ref()
                .map(|held| held.status_policy)
                .unwrap_or_default(),
            revision: held.as_ref().map_or(1, |held| held.revision + 1),
        };
        assert!(
            self.storage
                .set_login_settings(&next, held.as_ref(), audit())
                .await
                .unwrap()
        );
    }

    async fn admit(&self, subject: Uuid, presentation: Option<&[u8]>) -> Result<Record, Refused> {
        admit(
            self.storage.as_ref(),
            &self.recipient,
            self.issuer.recipient_org,
            &self.connection,
            subject,
            Pending {
                presentation,
                challenge: CHALLENGE,
                verifier_context: &self.connection.callback,
            },
            SystemTime::now(),
        )
        .await
        .map(|admitted| admitted.record)
    }

    /// The fence [`admit`] holds the session commit to.
    async fn fence_of(&self, subject: Uuid, presentation: &[u8]) -> Option<ActorFence> {
        admit(
            self.storage.as_ref(),
            &self.recipient,
            self.issuer.recipient_org,
            &self.connection,
            subject,
            Pending {
                presentation: Some(presentation),
                challenge: CHALLENGE,
                verifier_context: &self.connection.callback,
            },
            SystemTime::now(),
        )
        .await
        .unwrap()
        .fence
    }

    fn present(&self, issued: &Issued) -> Vec<u8> {
        issued.presentation(CHALLENGE, &self.connection.callback)
    }

    async fn recorded(&self, subject: Uuid) -> Option<sid_core::models::ProfileId> {
        self.storage
            .get_principal_by_value(
                PrincipalType::FederatedSubject,
                &federated_subject_value(ISSUER, &subject.to_string()),
            )
            .await
            .unwrap()
            .and_then(|principal| principal.assigned_profile_id)
    }
}

// A passport no organization issued is a Personal Profile's; one another
// organization issued is that organization's Corporate Profile's; one the
// recipient's own organization issued is not an outside identity at all.
// Bug prevented: every other organization collapsed into one kind, so
// naming one admitted all, or an own Corporate Profile entering as a
// visitor past its assignment, or a passport naming something that is no
// organization getting an origin.
#[test]
fn the_origin_is_the_organization_the_passport_names() {
    let (own, other) = (OrgId::generate(), OrgId::generate());
    let passport = |source: Option<Uuid>| {
        personal(Uuid::now_v7(), own.into())
            .passport
            .clone()
            .with_source(source)
    };
    assert_eq!(
        origin(&passport(None), own).unwrap(),
        Some(Origin::Personal)
    );
    assert_eq!(
        origin(&passport(Some(other.into())), own).unwrap(),
        Some(Origin::Corporate(other))
    );
    assert_eq!(origin(&passport(Some(own.into())), own).unwrap(), None);
    let no_organization = origin(&passport(Some(Uuid::nil())), own);
    assert!(
        matches!(no_organization, Err(Refused::NotAdmitted)),
        "{no_organization:?}"
    );
}

/// The same passport statement naming `source` as its organization.
trait WithSource {
    fn with_source(self, source: Option<Uuid>) -> Self;
}

impl WithSource for Passport {
    fn with_source(mut self, source: Option<Uuid>) -> Self {
        self.source_org = source;
        self
    }
}

// An organization that admits no outside identity refuses one before
// anything is verified, and one that admits them refuses a sign-in that
// brings only the issuer's token, without the holder's presentation.
// Neither leaves a record. Bug prevented: an account created here for
// anyone the issuer signs in, on the issuer's word alone.
#[tokio::test]
async fn nothing_is_admitted_without_settings_or_presentation() {
    let i = installed(ConnectionOwner::Administration, None).await;
    let subject = Uuid::now_v7();
    let jws = i.present(&personal(subject, i.organization()));

    let closed = i.admit(subject, Some(&jws)).await;
    assert!(matches!(closed, Err(Refused::NotAdmitted)), "{closed:?}");

    i.settings(true, true, &[]).await;
    let bare = i.admit(subject, None).await;
    assert!(matches!(bare, Err(Refused::NoPresentation)), "{bare:?}");
    assert!(!bare.unwrap_err().retryable());
    assert_eq!(i.recorded(subject).await, None);
}

// A visitor with a Personal Profile is admitted only while the Personal
// setting is on, on their own presentation for this very sign-in and as the
// identity the issuer signed in. The first admitted entry creates the
// record, the same one on the next entry. Bug prevented: a presentation
// made for another sign-in or of another identity being accepted, or a
// record per entry.
#[tokio::test]
async fn an_admission_holds_its_session_to_the_settings_it_read() {
    // Bug prevented: an identity admitted under settings an administrator
    // has since tightened still got its session, because nothing tied the
    // session commit to the settings the admission was decided on.
    let i = installed(ConnectionOwner::Administration, None).await;
    let subject = Uuid::now_v7();
    let jws = i.present(&personal(subject, i.organization()));
    i.settings(true, false, &[]).await;
    let first = i.fence_of(subject, &jws).await;
    assert!(
        matches!(first, Some(ActorFence::LoginPolicy { .. })),
        "{first:?}"
    );
    // Unchanged settings, the same fence.
    assert_eq!(i.fence_of(subject, &jws).await, first);
    // A settings write moves it on: a session decided on `first` no longer
    // commits.
    i.settings(true, true, &[OrgId::generate()]).await;
    let second = i.fence_of(subject, &jws).await;
    assert!(second.is_some());
    assert_ne!(second, first);
}

// An entry whose connection an administrator disabled, changed or removed
// after the entry used it admits nobody, and the change moves the epoch a
// session decided before it is fenced on. Bug prevented: a return already
// in flight completing a session through a connection that was withdrawn
// while its code was being exchanged.
#[tokio::test]
async fn a_withdrawn_connection_admits_nobody() {
    let i = installed(ConnectionOwner::Administration, None).await;
    let subject = Uuid::now_v7();
    let jws = i.present(&personal(subject, i.organization()));
    i.settings(true, false, &[]).await;
    let before = i.fence_of(subject, &jws).await;

    let mut disabled = i.connection.clone();
    disabled.enabled = false;
    assert!(
        i.storage
            .update_entry_connection(&disabled, audit())
            .await
            .unwrap()
    );
    let refused = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(refused, Err(Refused::ConnectionChanged)),
        "{refused:?}"
    );
    assert!(!refused.unwrap_err().retryable());
    assert_ne!(
        i.storage
            .export_login_policy_epoch()
            .await
            .unwrap()
            .map(|epoch| ActorFence::LoginPolicy { epoch }),
        before
    );

    assert!(
        i.storage
            .remove_entry_connection(i.connection.handle, 1, audit())
            .await
            .unwrap()
    );
    let removed = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(removed, Err(Refused::ConnectionChanged)),
        "{removed:?}"
    );
}

#[tokio::test]
async fn a_personal_profile_is_admitted_by_its_setting() {
    let i = installed(ConnectionOwner::Administration, None).await;
    let subject = Uuid::now_v7();
    let issued = personal(subject, i.organization());
    let jws = i.present(&issued);

    // Only other organizations' employees are admitted.
    i.settings(false, true, &[OrgId::generate()]).await;
    let other_kind = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(other_kind, Err(Refused::NotAdmitted)),
        "{other_kind:?}"
    );

    i.settings(true, false, &[]).await;
    let replayed = issued.presentation("another-sign-in", &i.connection.callback);
    let refused = i.admit(subject, Some(&replayed)).await;
    assert!(
        matches!(refused, Err(Refused::Presentation(_))),
        "{refused:?}"
    );
    let elsewhere = issued.presentation(CHALLENGE, "https://sid.example.com/other/callback");
    let refused = i.admit(subject, Some(&elsewhere)).await;
    assert!(
        matches!(refused, Err(Refused::Presentation(_))),
        "{refused:?}"
    );
    let another = i.admit(Uuid::now_v7(), Some(&jws)).await;
    assert!(
        matches!(another, Err(Refused::AnotherIdentity)),
        "{another:?}"
    );
    assert_eq!(i.recorded(subject).await, None);

    let first = i.admit(subject, Some(&jws)).await.unwrap();
    assert!(first.created);
    assert_eq!(first.profile.profile_type, ProfileType::Federated);
    assert!(first.profile.roles.is_empty());
    assert_eq!(i.recorded(subject).await, Some(first.profile.id));
    let again = i.admit(subject, Some(&jws)).await.unwrap();
    assert!(!again.created);
    assert_eq!(again.profile.id, first.profile.id);
}

// An employee of organization A signs in at recipient B with the Corporate
// Profile A issued. B admits them only while its settings admit other
// organizations' Corporate Profiles and name A among them. Withdrawing A
// refuses the next entry and keeps the record; a passport A revoked is
// refused though A is named. Bug prevented: the Personal setting admitting
// another company's employee, the kind switch alone admitting every
// organization, an organization B named admitting one it did not, or a
// revoked passport signing in.
#[tokio::test]
async fn another_organizations_corporate_profile_is_admitted_by_its_setting() {
    let i = installed(ConnectionOwner::Administration, None).await;
    let a = OrgId::generate();
    let subject = Uuid::now_v7();
    let issued = corporate(a.into(), subject, i.organization());
    let jws = i.present(&issued);

    // The status A publishes is not held yet: not decided, and retryable.
    i.settings(false, true, &[a]).await;
    let undecided = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(undecided, Err(Refused::Unavailable(_))),
        "{undecided:?}"
    );
    assert!(undecided.unwrap_err().retryable());
    i.status(a, 1, &[]).await;

    // Visitors with a Personal Profile are admitted; employees of other
    // organizations are not, although A is named.
    i.settings(true, false, &[a]).await;
    let other_kind = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(other_kind, Err(Refused::NotAdmitted)),
        "{other_kind:?}"
    );
    // Other organizations' employees are admitted, and nobody is named.
    i.settings(true, true, &[]).await;
    let nobody_named = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(nobody_named, Err(Refused::NotAdmitted)),
        "{nobody_named:?}"
    );
    // Another organization is named, not A.
    i.settings(true, true, &[OrgId::generate()]).await;
    let not_this_one = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(not_this_one, Err(Refused::NotAdmitted)),
        "{not_this_one:?}"
    );
    assert_eq!(i.recorded(subject).await, None);

    // A is named beside another organization; Personal Profiles are not
    // admitted, which decides nothing here.
    i.settings(false, true, &[OrgId::generate(), a]).await;
    let first = i.admit(subject, Some(&jws)).await.unwrap();
    assert!(first.created);
    assert_eq!(first.profile.profile_type, ProfileType::Federated);
    assert_eq!(i.recorded(subject).await, Some(first.profile.id));

    // A is no longer named, the kind still on: the record stays, the next
    // entry is refused.
    i.settings(false, true, &[]).await;
    let withdrawn = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(withdrawn, Err(Refused::NotAdmitted)),
        "{withdrawn:?}"
    );
    assert_eq!(i.recorded(subject).await, Some(first.profile.id));
    // Named again: the same record signs in.
    i.settings(false, true, &[a]).await;
    assert_eq!(
        i.admit(subject, Some(&jws)).await.unwrap().profile.id,
        first.profile.id
    );

    // A revokes the passport: refused, and not for a retry.
    i.status(a, 2, &[PASSPORT_SERIAL]).await;
    let revoked = i.admit(subject, Some(&jws)).await;
    assert!(
        matches!(revoked, Err(Refused::Presentation(_))),
        "{revoked:?}"
    );
    assert!(!revoked.unwrap_err().retryable());
}

// A connection registered for organization A brings in A's Corporate
// Profiles only: an employee of C presenting through it is refused though
// the settings name C too, and a visitor's Personal Profile stays the
// settings' decision. Bug prevented: any issuer the installation is
// registered at signing in the employees of every organization the
// recipient admits.
#[tokio::test]
async fn a_connection_of_one_organization_brings_in_no_other() {
    let (a, c) = (OrgId::generate(), OrgId::generate());
    let i = installed(ConnectionOwner::Administration, Some(a)).await;
    i.settings(true, true, &[a, c]).await;
    i.status(a, 1, &[]).await;
    i.status(c, 1, &[]).await;

    let of_c = Uuid::now_v7();
    let jws = i.present(&corporate(c.into(), of_c, i.organization()));
    let refused = i.admit(of_c, Some(&jws)).await;
    assert!(
        matches!(refused, Err(Refused::AnotherSource)),
        "{refused:?}"
    );
    assert_eq!(i.recorded(of_c).await, None);

    let of_a = Uuid::now_v7();
    let jws = i.present(&corporate(a.into(), of_a, i.organization()));
    assert!(i.admit(of_a, Some(&jws)).await.unwrap().created);

    let visitor = Uuid::now_v7();
    let jws = i.present(&personal(visitor, i.organization()));
    assert!(i.admit(visitor, Some(&jws)).await.unwrap().created);
}

/// A returned entry as the engine hands it over.
fn returned(i: &Installed, subject: &str, presentation: Option<Vec<u8>>) -> Returned {
    use sid_core::models::session::AcceptedEvidence;
    Returned {
        subject: subject.to_owned(),
        evidence: AcceptedEvidence {
            acr: None,
            amr: vec!["pwd".into()],
            auth_time: Timestamp::now(),
        },
        continuation: format!("{}/oauth2/authorize?client_id=app", i.issuer.canonical_url),
        requested: Default::default(),
        operation: "operation".into(),
        deadline: Timestamp::now() + jiff::SignedDuration::from_mins(5),
        presentation,
        challenge: CHALLENGE.into(),
        verifier_context: i.connection.callback.clone(),
    }
}

// A subject the organization assigned to one of its own Profiles signs in
// as that Profile through the provisioned authority, on the issuer's
// evidence alone. The same assignment reached through a connection an
// administrator registered resolves nothing: that entry is an outside
// identity's and needs its presentation. Bug prevented: an administrator's
// connection to some issuer signing in the organization's own Profiles.
#[tokio::test]
async fn own_profiles_resolve_only_through_the_provisioned_authority() {
    use sid_core::models::{NewRegistration, Principal, Profile, SourceRecording};
    let provisioned = installed(ConnectionOwner::Provisioning, None).await;
    let subject = Uuid::now_v7();
    let profile = Profile::new(Some("employee"));
    let registration = NewRegistration {
        principal: Principal::new_federated_subject(profile.id, ISSUER, &subject.to_string()),
        profile: profile.clone(),
        email: None,
        phone: None,
        credential: None,
        source: None,
        instance_claim: None,
        history: None,
        enrollment: None,
        source_recording: SourceRecording::AsGiven,
    };
    provisioned
        .storage
        .register_profile(&registration, audit())
        .await
        .unwrap();
    let subject = subject.to_string();
    let (own, _) = resolved(&provisioned, &provisioned.connection, &subject)
        .await
        .unwrap();
    assert_eq!(own.id, profile.id);

    // The same store and subject, through an administrator's connection.
    let mut administered = provisioned.connection.clone();
    administered.owner = ConnectionOwner::Administration;
    provisioned.settings(true, true, &[]).await;
    let outside = resolved(&provisioned, &administered, &subject).await;
    assert!(
        matches!(outside, Err(Refused::NoPresentation)),
        "{outside:?}"
    );

    // A subject that is no Binding signs nobody in.
    let malformed = resolved(&provisioned, &provisioned.connection, "not-a-binding").await;
    assert!(
        matches!(malformed, Err(Refused::NoBinding)),
        "{malformed:?}"
    );
}

/// What the entry of `subject` returned through `connection`, bringing no
/// presentation, resolves to.
async fn resolved(
    i: &Installed,
    connection: &EntryConnection,
    subject: &str,
) -> Result<(Profile, PrincipalAssignmentFence), Refused> {
    resolve(
        i.storage.as_ref(),
        &i.recipient,
        &i.issuer,
        connection,
        &returned(i, subject, None),
        SystemTime::now(),
    )
    .await
    .map(|resolved| (resolved.profile, resolved.assignment))
}
