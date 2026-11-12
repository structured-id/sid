use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use sid_authn::sign_in_delivery::{CeremonyClient, Delivery};
use sid_core::models::session::{AuthLevel, SessionAuthentication};
use sid_core::models::{PrincipalAssignmentFence, PrincipalId, ProfileStatus};
use sid_plugin::GrantStore as _;
use sid_plugin::storage::StorageBackend as _;

use super::*;
use crate::test_support::{fixed_policy, sign_in, storage, stored_profile};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

fn browser() -> Completer<'static> {
    Completer {
        client: CeremonyClient::Browser,
        client_ip: Some(CLIENT_IP),
        context: AttemptContext::default(),
    }
}

fn evidence() -> SessionAuthentication {
    SessionAuthentication {
        assurance_level: AuthLevel::Standard,
        elevation: None,
        authenticated_at: Utc::now(),
        amr: vec!["pwd".to_string(), "otp".to_string()],
    }
}

fn assignment_of(profile: ProfileId) -> PrincipalAssignmentFence {
    PrincipalAssignmentFence {
        principal: PrincipalId::new(),
        profile,
        revision: 1,
    }
}

// An upstream sign-in records the provider's verification as basic
// assurance without an `amr` method SID did not verify, from the browser's
// address, and delivers the IdP session cookie.
#[tokio::test]
async fn upstream_sign_in_stores_a_basic_session_without_amr() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "alice").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();

    let completed = sign_in
        .upstream_sign_in(&fixed_policy(), &profile, browser())
        .await
        .unwrap();
    assert!(completed.second_factors.is_empty());
    let signed_in = completed.signed_in;

    assert!(matches!(signed_in.delivery, Delivery::Cookie(_)));
    let session = storage
        .get_session(signed_in.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.profile_id, id);
    assert_eq!(session.assurance_level, AuthLevel::Basic);
    assert!(session.amr.is_empty());
    assert_eq!(session.ip_address, Some(CLIENT_IP));
}

// Regression: an account whose enabled protection asks for its second factor
// gets, after the provider's sign-in, the pending context that factor
// completes, with the CSRF token its browser completes it with. Before, the
// owed factor refused the upstream sign-in outright and the account could
// no longer sign in that way at all.
#[tokio::test]
async fn upstream_sign_in_of_a_protected_account_awaits_its_second_factor() {
    use sid_core::models::{AuditEntry, Credential, CredentialData, CredentialType};
    use sid_plugin::CredentialStore as _;
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "erin").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();
    storage
        .create_credential(
            &Credential::new(
                id,
                CredentialType::Totp,
                CredentialData::new(vec![7; 32]),
                None,
            ),
            AuditEntry::system("test", "totp").into(),
        )
        .await
        .unwrap();

    let pending = sign_in
        .upstream_sign_in(&fixed_policy(), &profile, browser())
        .await
        .expect("the pending context, not a refusal");

    assert_eq!(
        pending.second_factors,
        [i32::from(sid_proto::sid::v1::authn::StepUpMethod::Totp)]
    );
    assert!(pending.browser_csrf.is_some());
    let session = storage
        .get_session(pending.signed_in.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(session.awaits_second_factor());
    assert!(session.amr.is_empty());
}

/// A login policy written right after each of its next `writes` reads: the
/// requirements read carry the epoch they were read under, and the write
/// advances it (requiring `then_require` from then on, when set).
struct WrittenAfterRead {
    storage: Arc<sid_storage::sqlite::SqliteBackend>,
    writes: std::sync::Mutex<u32>,
    then_require: std::sync::Mutex<Option<String>>,
    required: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl WrittenAfterRead {
    async fn new(storage: Arc<sid_storage::sqlite::SqliteBackend>, writes: u32) -> Self {
        let policy = Self {
            storage,
            writes: std::sync::Mutex::new(0),
            then_require: std::sync::Mutex::default(),
            required: std::sync::Mutex::default(),
        };
        policy.write().await;
        *policy.writes.lock().unwrap() = writes;
        policy
    }

    async fn write(&self) {
        use sid_storage::sqlite::SqliteBackend;
        let mut tx = SqliteBackend::begin_write_on(self.storage.pool())
            .await
            .unwrap();
        SqliteBackend::advance_login_policy_epoch(&mut tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

#[async_trait::async_trait]
impl LoginPolicySource for WrittenAfterRead {
    async fn requirements(
        &self,
        client_id: Option<&str>,
    ) -> Result<
        sid_authn::login_policy::LoginRequirements,
        sid_authn::login_policy::LoginPolicyUnavailable,
    > {
        let mut requirements = fixed_policy().requirements(client_id).await?;
        let epoch = sid_storage::sqlite::SqliteBackend::login_policy_epoch(self.storage.pool())
            .await
            .unwrap()
            .expect("a policy was written");
        requirements.fence = Some(sid_core::models::ActorFence::LoginPolicy { epoch });
        requirements.required_amr = self.required.lock().unwrap().clone();
        let write = {
            let mut writes = self.writes.lock().unwrap();
            let write = *writes > 0;
            if write {
                *writes -= 1;
            }
            write
        };
        if write {
            self.write().await;
            if let Some(method) = self.then_require.lock().unwrap().take() {
                self.required.lock().unwrap().insert(method);
            }
        }
        Ok(requirements)
    }
}

/// The sign-ins `id` holds that are not pending contexts.
async fn sessions_of(storage: &sid_storage::sqlite::SqliteBackend, id: ProfileId) -> usize {
    storage
        .list_sessions(&id)
        .await
        .unwrap()
        .iter()
        .filter(|s| !s.awaits_second_factor())
        .count()
}

// Regression: a login policy written between a first factor's decision and
// its session's commit fenced the commit, answered as a failed
// authentication. The sign-in is decided again under the policy in force
// and commits once.
#[tokio::test]
async fn a_policy_written_before_the_commit_decides_the_sign_in_again() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "frank").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();
    let policy = WrittenAfterRead::new(storage.clone(), 1).await;

    let signed_in = sign_in
        .upstream_sign_in(&policy, &profile, browser())
        .await
        .expect("decided again under the policy written");
    assert!(
        storage
            .get_session(signed_in.signed_in.session_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(sessions_of(&storage, id).await, 1);
}

// A policy written before the commit that no longer admits the sign-in
// refuses it with what it asks, not as a failed authentication.
#[tokio::test]
async fn a_policy_written_before_the_commit_refuses_with_its_own_reason() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "grace").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();
    let policy = WrittenAfterRead::new(storage.clone(), 1).await;
    *policy.then_require.lock().unwrap() = Some("hwk".to_string());

    let refused = sign_in.upstream_sign_in(&policy, &profile, browser()).await;
    assert!(
        matches!(
            refused,
            Err(SignInError::Rules(
                sid_authn::sign_in_security::SignInRefusal::StepUp(_)
            ))
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!(sessions_of(&storage, id).await, 0);
}

// A policy written again before the second commit is not chased: the
// sign-in stays fenced and commits nothing.
#[tokio::test]
async fn a_policy_written_twice_fences_the_sign_in() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "heidi").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();
    let policy = WrittenAfterRead::new(storage.clone(), 2).await;

    let refused = sign_in.upstream_sign_in(&policy, &profile, browser()).await;
    assert!(
        matches!(refused, Err(SignInError::Fenced)),
        "{:?}",
        refused.err()
    );
    assert_eq!(sessions_of(&storage, id).await, 0);
}

// An account that can no longer authenticate gets no upstream session,
// answered as any failed authentication.
#[tokio::test]
async fn upstream_sign_in_refuses_a_suspended_account() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "bob").await;
    let mut profile = storage.get_profile(id).await.unwrap().unwrap();
    profile.status = ProfileStatus::Suspended;

    let refused = sign_in
        .upstream_sign_in(&fixed_policy(), &profile, browser())
        .await;

    assert!(matches!(refused, Err(SignInError::AuthenticationFailed)));
}

// Admitted evidence signs in only the Profile its assignment resolves: an
// assignment of another Profile admits nothing.
#[tokio::test]
async fn admitted_sign_in_refuses_an_assignment_of_another_profile() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "carol").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();

    let refused = sign_in
        .admitted_sign_in(
            &fixed_policy(),
            &profile,
            assignment_of(ProfileId::generate()),
            &evidence(),
            "app",
            None,
            Some(CLIENT_IP),
            AttemptContext::default(),
        )
        .await;

    assert!(matches!(refused, Err(SignInError::AuthenticationFailed)));
}

// An operation past its deadline admits neither a new sign-in nor a repeat.
#[tokio::test]
async fn admitted_sign_in_refuses_an_operation_past_its_deadline() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let id = stored_profile(storage.as_ref(), "dave").await;
    let profile = storage.get_profile(id).await.unwrap().unwrap();
    let operation = "federated-return-1";

    let refused = sign_in
        .admitted_sign_in(
            &fixed_policy(),
            &profile,
            assignment_of(id),
            &evidence(),
            "app",
            Some(AdmittedCompletion {
                operation,
                deadline: Utc::now() - chrono::Duration::seconds(1),
            }),
            Some(CLIENT_IP),
            AttemptContext::default(),
        )
        .await;

    assert!(matches!(refused, Err(SignInError::AuthenticationFailed)));
}
