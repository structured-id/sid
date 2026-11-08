// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use sid_core::models::{
    AuditEntry, CredentialData, CredentialType, EnforcementMode, MfaEnforcement, MutationContext,
    OperationCompletion, Profile, ProfileId, SignInProof,
};
use sid_plugin::{CeremonyStateStore, InProcessCeremonyState, StorageBackend};
use sid_storage::sqlite::SqliteBackend;

use super::*;
use crate::sign_in_delivery::{BrowserCredential, Delivery};
use crate::test_support::key_manager;

#[derive(Debug)]
struct HostError(PendingError);

impl From<PendingError> for HostError {
    fn from(e: PendingError) -> Self {
        Self(e)
    }
}

/// A host over an in-memory SQLite store with browser delivery only.
struct Host {
    store: SqliteBackend,
    keys: Arc<dyn KeyManager>,
    cookie: BrowserCookie,
    proofs: FirstFactorProofs,
    required_amr: Mutex<BTreeSet<String>>,
    gone: Mutex<HashSet<ProfileId>>,
    completed: Mutex<Vec<ProfileId>>,
}

#[async_trait]
impl PendingSignInHost for Host {
    type Owner = ProfileId;
    type Error = HostError;

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        &self.store
    }
    fn grants(&self) -> &dyn GrantStore<Owner = ProfileId> {
        &self.store
    }
    fn operations(&self) -> &dyn OperationResultStore {
        &self.store
    }
    fn keys(&self) -> &dyn KeyManager {
        self.keys.as_ref()
    }
    fn cookie(&self) -> &BrowserCookie {
        &self.cookie
    }
    fn proofs(&self) -> &FirstFactorProofs {
        &self.proofs
    }
    fn issuer(&self) -> &str {
        "https://sid.example.com"
    }
    async fn requirements(&self, owner: ProfileId) -> Result<LoginRequirements, HostError> {
        let requirements = LoginRequirements {
            min_acr: AuthLevel::Basic,
            required_amr: self.required_amr.lock().unwrap().clone(),
            max_authentication_age: None,
            enforcement: EnforcementMode::Hard,
            new_device: crate::anomaly::RuleReaction::StepUp,
            fence: None,
            mfa: MfaEnforcement::Required,
            passkey_satisfies_mfa: false,
            account_protection: AuthLevel::Basic,
        };
        Ok(requirements
            .for_account(&self.store, owner)
            .await
            .map_err(PendingError::from)?)
    }
    async fn can_sign_in(&self, owner: ProfileId) -> Result<bool, HostError> {
        Ok(!self.gone.lock().unwrap().contains(&owner))
    }
    fn new_session(
        &self,
        owner: ProfileId,
        ip_address: Option<std::net::IpAddr>,
    ) -> Session<ProfileId> {
        Session::new(owner, ip_address, Utc::now() + chrono::Duration::hours(1))
    }
    async fn commit(
        &self,
        completion: Completion<'_, ProfileId>,
    ) -> Result<SignedIn, CommitError<HostError>> {
        let mut session = completion.session;
        let credential = BrowserCredential::bind(&mut session);
        if let Some(csrf) = completion.pending.browser_csrf {
            session.browser_csrf = Some(csrf);
        }
        let mut ctx: MutationContext = AuditEntry::system("test", "complete").into();
        if let Some(retained) = completion.retained {
            let sealed = credential
                .retain(
                    self.keys.as_ref(),
                    &retained.context,
                    &session,
                    retained.deadline,
                )
                .await
                .unwrap();
            ctx = ctx.with_operation(
                OperationCompletion::new(
                    retained.namespace,
                    retained.completion_key,
                    retained.method,
                    &retained.inputs,
                    sealed,
                )
                .retained_until(retained.deadline),
            );
        }
        if let Some(spend) = completion.spend {
            ctx = spend.into_context(ctx);
        }
        match self
            .store
            .complete_pending_session(
                completion.pending.id,
                &completion.end,
                &session,
                0,
                completion.proved_by.as_ref().map(SignInProof::Credential),
                ctx,
            )
            .await
        {
            Ok(_) => Ok(credential.signed_in(&self.cookie, &session)),
            Err(sid_core::Error::Fenced(_)) => Err(CommitError::Fenced),
            Err(e) => Err(CommitError::Other(PendingError::Store(e).into())),
        }
    }
    async fn bearer_deliverable(
        &self,
        _delivery: &RetainedDelivery,
        _session: &Session<ProfileId>,
    ) -> Result<bool, HostError> {
        Ok(true)
    }
    async fn record_completed(&self, owner: ProfileId, _ip: Option<std::net::IpAddr>) {
        self.completed.lock().unwrap().push(owner);
    }
}

async fn host() -> Host {
    let ceremonies: Arc<dyn CeremonyStateStore> = Arc::new(InProcessCeremonyState::new());
    let keys = key_manager();
    Host {
        store: SqliteBackend::new_in_memory().await.unwrap(),
        proofs: FirstFactorProofs::new(
            ceremonies,
            keys.clone(),
            std::time::Duration::from_secs(300),
        ),
        keys,
        cookie: BrowserCookie::default(),
        required_amr: Mutex::default(),
        gone: Mutex::default(),
        completed: Mutex::default(),
    }
}

fn ctx() -> MutationContext {
    AuditEntry::system("test", "pending").into()
}

/// A browser sign-in of a new account whose password proved its first
/// factor and now awaits its second: the stored context and its password.
async fn pending(h: &Host) -> (Session<ProfileId>, CredentialFence) {
    let profile = Profile::new(Some("alice"));
    h.store.create_profile(&profile, ctx()).await.unwrap();
    let password = Credential::new(
        profile.id,
        CredentialType::Opaque,
        CredentialData::new(vec![1, 2, 3]),
        None,
    );
    h.store.create_credential(&password, ctx()).await.unwrap();
    let fence = CredentialFence {
        id: password.id,
        data: password.data.clone(),
    };
    let mut session = Session::new_awaiting_second_factor(
        profile.id,
        None,
        AuthLevel::Basic,
        vec!["pwd".to_string()],
    );
    BrowserCredential::bind(&mut session);
    assert!(h.proofs.keep(&session, Some(&fence)).await.unwrap());
    h.store
        .create_session_atomic(&session, 0, None, ctx())
        .await
        .unwrap();
    (session, fence)
}

fn cookie_secret(signed_in: &SignedIn) -> String {
    match &signed_in.delivery {
        Delivery::Cookie(cookie) => cookie.clone(),
        _ => panic!("a browser delivery"),
    }
}

/// A completion ends the pending context once: the session it commits has
/// the factor's method at standard assurance, and a retry of the same
/// context after a lost reply, or a concurrent completion that lost, gets
/// that same session and credential again rather than a second one.
#[tokio::test]
async fn a_completion_commits_once_and_a_lost_reply_is_answered_again() {
    let h = host().await;
    let (pending, _) = pending(&h).await;
    let signed_in = complete_second_factor(
        &h,
        pending.clone(),
        "otp",
        CeremonyClient::Browser,
        None,
        None,
    )
    .await
    .unwrap();
    let session = h
        .store
        .get_session(signed_in.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!session.is_provisional);
    assert_eq!(session.assurance_level, AuthLevel::Standard);
    assert_eq!(session.amr, vec!["pwd".to_string(), "otp".to_string()]);
    assert_eq!(*h.completed.lock().unwrap(), vec![pending.profile_id]);

    let completed = live_pending(&h.store, pending.clone(), CeremonyClient::Browser, None)
        .await
        .unwrap()
        .expect_err("the context completed");
    let again = redeliver_second_factor(&h, &completed)
        .await
        .unwrap()
        .expect("the committed completion");
    assert_eq!(again.session_id, signed_in.session_id);
    assert_eq!(cookie_secret(&again), cookie_secret(&signed_in));

    let lost = complete_second_factor(&h, pending, "otp", CeremonyClient::Browser, None, None)
        .await
        .unwrap();
    assert_eq!(lost.session_id, signed_in.session_id);
}

/// A completion of the same context presented with another CSRF token is not
/// that client's: nothing is delivered.
#[tokio::test]
async fn a_redelivery_needs_the_same_contexts_token() {
    let h = host().await;
    let (pending, _) = pending(&h).await;
    complete_second_factor(
        &h,
        pending.clone(),
        "otp",
        CeremonyClient::Browser,
        None,
        None,
    )
    .await
    .unwrap();
    let Some(CompletedContext::Browser { secret, .. }) =
        CompletedContext::of(&pending, CeremonyClient::Browser, None)
    else {
        panic!("a browser context");
    };
    let forged = CompletedContext::Browser {
        secret,
        csrf: "another".into(),
    };
    assert!(matches!(
        redeliver_second_factor(&h, &forged).await,
        Err(HostError(PendingError::AuthenticationFailed))
    ));
}

/// A first-factor credential removed since the first factor completes
/// nothing, and the context stays pending.
#[tokio::test]
async fn a_changed_first_factor_fences_the_completion() {
    let h = host().await;
    let (pending, fence) = pending(&h).await;
    h.store.delete_credential(fence.id, ctx()).await.unwrap();
    assert!(matches!(
        complete_second_factor(
            &h,
            pending.clone(),
            "otp",
            CeremonyClient::Browser,
            None,
            None
        )
        .await,
        Err(HostError(PendingError::Fenced))
    ));
    assert!(
        live_pending(&h.store, pending, CeremonyClient::Browser, None)
            .await
            .unwrap()
            .is_ok()
    );
}

/// A factor whose method the requirements do not accept completes nothing:
/// the step-up names what is missing.
#[tokio::test]
async fn an_unaccepted_method_asks_a_step_up() {
    let h = host().await;
    let (pending, _) = pending(&h).await;
    h.required_amr.lock().unwrap().insert("hwk".to_string());
    match complete_second_factor(&h, pending, "otp", CeremonyClient::Browser, None, None).await {
        Err(HostError(PendingError::StepUp(unmet))) => {
            assert_eq!(unmet.amr, vec!["hwk".to_string()])
        }
        other => panic!("expected a step-up, got {:?}", other.err()),
    }
}

/// An account that can no longer sign in completes nothing, and a committed
/// completion is not delivered again to it.
#[tokio::test]
async fn an_account_that_cannot_sign_in_gets_nothing() {
    let h = host().await;
    let (pending, _) = pending(&h).await;
    h.gone.lock().unwrap().insert(pending.profile_id);
    assert!(matches!(
        complete_second_factor(
            &h,
            pending.clone(),
            "otp",
            CeremonyClient::Browser,
            None,
            None
        )
        .await,
        Err(HostError(PendingError::AuthenticationFailed))
    ));

    h.gone.lock().unwrap().clear();
    complete_second_factor(
        &h,
        pending.clone(),
        "otp",
        CeremonyClient::Browser,
        None,
        None,
    )
    .await
    .unwrap();
    h.gone.lock().unwrap().insert(pending.profile_id);
    let completed = CompletedContext::of(&pending, CeremonyClient::Browser, None).unwrap();
    assert!(matches!(
        redeliver_second_factor(&h, &completed).await,
        Err(HostError(PendingError::SessionEnded))
    ));
}

/// A context that never completed has nothing to deliver again.
#[tokio::test]
async fn an_uncompleted_context_has_nothing_to_redeliver() {
    let h = host().await;
    let (pending, _) = pending(&h).await;
    let context = CompletedContext::of(&pending, CeremonyClient::Browser, None).unwrap();
    assert!(
        redeliver_second_factor(&h, &context)
            .await
            .unwrap()
            .is_none()
    );
}
