// SPDX-License-Identifier: AGPL-3.0-only
//! [`GrantStore`] scenarios: sessions, authorization codes and refresh token
//! families with their atomic transitions, for any account type. Every
//! scenario works on records it created under fresh keys, so a harness may run
//! them concurrently against one shared database.

use std::fmt::Debug;

use async_trait::async_trait;
use chrono::{Duration, DurationRound, Utc};
use sid_core::Error;
use sid_core::models::session::{AuthLevel, Elevation};
use sid_core::models::{
    AuditEntry, AuthCodeRedemption, AuthorizationCode, BrowserCsrfToken, BrowserSecretHash,
    MutationContext, RefreshToken, ResourceId, RevocationReason, Session, SessionEnd, SessionId,
};
use uuid::Uuid;

use crate::{CredentialStore, GrantStore};

/// What a backend's harness supplies to the scenarios.
#[async_trait]
pub trait GrantHarness: Send + Sync {
    /// The account type the backend stores sessions and grants for.
    type Owner: Clone + PartialEq + Debug + Send + Sync + 'static;

    fn store(&self) -> &dyn GrantStore<Owner = Self::Owner>;

    /// The same backend's credentials: a session's sign-in proved one.
    fn credentials(&self) -> &dyn CredentialStore<Owner = Self::Owner>;

    /// A new account the store accepts as an owner.
    async fn owner(&self) -> Self::Owner;

    /// A resource grants may be bound to.
    async fn resource(&self) -> ResourceId;
}

/// A backend that holds its owners' status beside their sessions, so a
/// session commits only while its owner can authenticate.
#[async_trait]
pub trait OwnerStatusHarness: GrantHarness {
    /// Suspend `owner` as an administrator does: it can no longer sign in.
    async fn suspend(&self, owner: &Self::Owner);
}

/// An owner suspended after the sign-in's last check and before its session
/// commits gets no session, with or without a session limit or the
/// credential the sign-in proved: the commit itself requires an owner that
/// can authenticate. Nothing is stored for the refused session.
pub async fn session_refused_once_its_owner_is_suspended<H: OwnerStatusHarness>(h: &H) {
    let owner = h.owner().await;
    let admitted = session(owner.clone());
    h.store()
        .create_session_atomic(&admitted, 0, None, ctx())
        .await
        .expect("an active owner signs in");

    h.suspend(&owner).await;
    for limit in [0, 3] {
        let late = session(owner.clone());
        let refused = h
            .store()
            .create_session_atomic(&late, limit, None, ctx())
            .await;
        assert!(
            matches!(refused, Err(Error::Fenced(_))),
            "limit {limit}: {refused:?}"
        );
        assert!(h.store().get_session(late.id).await.unwrap().is_none());
    }
}

/// A backend that commits grants under the installation's login-policy
/// epoch. Not every grant store can: one that cannot refuses every
/// login-policy fence, and a host that fences its policy runs on one that can.
#[async_trait]
pub trait LoginPolicyHarness: GrantHarness {
    /// Advance the installation's login-policy epoch, as a host's policy
    /// write does, and return the new epoch. The scenarios that call it
    /// expect a store of their own: no other scenario advances it meanwhile.
    async fn advance_login_policy(&self) -> i64;
}

fn ctx() -> MutationContext {
    AuditEntry::system("conformance", "grant_store").into()
}

fn end() -> SessionEnd {
    SessionEnd::new(RevocationReason::UserRequested, "conformance")
}

/// A time at millisecond precision, which every store keeps.
fn ms(time: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    time.duration_trunc(Duration::milliseconds(1))
        .expect("a current time truncates")
}

/// A new session of `owner`, its times at the precision every store keeps.
fn session<O>(owner: O) -> Session<O> {
    let mut session = Session::new(owner, "127.0.0.1".into(), Utc::now() + Duration::hours(1));
    session.authenticated_at = ms(session.authenticated_at);
    session.created_at = ms(session.created_at);
    session.expires_at = ms(session.expires_at);
    session
}

/// A hash no other scenario on the same database uses.
fn browser_secret() -> BrowserSecretHash {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    BrowserSecretHash::from_bytes(bytes)
}

/// A code `owner` authorized for `resource` from a stored, stepped-up MFA
/// session, whose authentication the code carries: a code is authorized by a
/// session that exists.
async fn code<H: GrantHarness>(
    h: &H,
    owner: H::Owner,
    resource: ResourceId,
) -> AuthorizationCode<H::Owner> {
    let mut authorizing = session(owner.clone());
    authorizing.authenticated_at = ms(Utc::now() - Duration::minutes(20));
    authorizing.amr = vec!["pwd".into(), "otp".into(), "mfa".into()];
    authorizing.assurance_level = AuthLevel::Standard;
    authorizing.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: ms(Utc::now() + Duration::minutes(10)),
    });
    h.store()
        .create_session_atomic(&authorizing, 0, None, ctx())
        .await
        .unwrap();
    AuthorizationCode {
        code_hash: Uuid::now_v7().as_bytes().to_vec(),
        profile_id: owner,
        client_id: "conformance-client".into(),
        redirect_uri: "https://app.sid.example.com/callback".into(),
        scopes: vec!["openid".into()],
        resource,
        code_challenge: Some("challenge".into()),
        nonce: Some("n-0S6_WzA2Mj".into()),
        authentication: authorizing.grant_authentication(),
        expires_at: Utc::now() + Duration::minutes(5),
        created_at: Utc::now(),
        used: false,
        session_id: None,
    }
}

/// A refresh token of `family` for `session`.
fn refresh<O: Clone>(session: &Session<O>, family: Uuid, resource: ResourceId) -> RefreshToken<O> {
    RefreshToken {
        id: Uuid::now_v7(),
        token_hash: Uuid::now_v7().as_bytes().to_vec(),
        session_id: session.id,
        profile_id: session.profile_id.clone(),
        client_id: "conformance-client".into(),
        scopes: vec!["openid".into()],
        resource,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: family,
        grace_expires_at: None,
        dpop_jkt: None,
    }
}

async fn exists<H: GrantHarness>(h: &H, id: SessionId) -> bool {
    h.store().get_session(id).await.unwrap().is_some()
}

async fn stored_refresh<H: GrantHarness>(
    h: &H,
    token: &RefreshToken<H::Owner>,
) -> Option<RefreshToken<H::Owner>> {
    h.store()
        .get_refresh_token_by_hash(&token.token_hash)
        .await
        .unwrap()
}

/// `session` stored with `token` through a code redemption, the way grants
/// store refresh tokens.
async fn redeemed<H: GrantHarness>(
    h: &H,
    session: &Session<H::Owner>,
    token: &RefreshToken<H::Owner>,
) {
    let code = code(h, session.profile_id.clone(), token.resource).await;
    h.store().create_auth_code(&code, ctx()).await.unwrap();
    assert_eq!(
        h.store()
            .redeem_auth_code(&code.code_hash, session, token, ctx())
            .await
            .unwrap(),
        AuthCodeRedemption::Redeemed
    );
}

/// `owner`'s stored password holding `data`.
async fn stored_password<H: GrantHarness>(
    h: &H,
    owner: H::Owner,
    data: &[u8],
) -> sid_core::models::Credential<H::Owner> {
    use sid_core::models::{Credential, CredentialData, CredentialType};
    let password = Credential::new(
        owner,
        CredentialType::Opaque,
        CredentialData::new(data.to_vec()),
        None,
    );
    h.credentials()
        .create_credential(&password, ctx())
        .await
        .unwrap();
    password
}

fn fence(id: sid_core::models::CredentialId, data: &[u8]) -> sid_core::models::CredentialFence {
    sid_core::models::CredentialFence {
        id,
        data: sid_core::models::CredentialData::new(data.to_vec()),
    }
}

/// A sign-in proved with a password that a reset replaced before the session
/// committed creates no session, with or without a session limit: the session
/// insert requires the exact credential the sign-in used to be current. The
/// replacement password and an unchanged one still sign in.
pub async fn session_refused_after_its_password_changed<H: GrantHarness>(h: &H) {
    use sid_core::models::CredentialData;
    let owner = h.owner().await;
    let before = b"record-before-reset";
    let after = b"record-after-reset";
    let password = stored_password(h, owner.clone(), before).await;
    // The sign-in's last credential check passes.
    assert!(
        h.credentials()
            .mark_credential_used(password.id, ctx())
            .await
            .unwrap()
    );
    // A reset commits before the session does.
    let mut replaced = password.clone();
    replaced.data = CredentialData::new(after.to_vec());
    assert!(
        h.credentials()
            .change_password(password.id, before, &replaced, None, ctx())
            .await
            .unwrap()
    );

    for limit in [0, 5] {
        let late = session(owner.clone());
        let refused = h
            .store()
            .create_session_atomic(&late, limit, Some(&fence(password.id, before)), ctx())
            .await;
        assert!(
            matches!(refused, Err(Error::Fenced(_))),
            "limit {limit}: {refused:?}"
        );
        assert!(!exists(h, late.id).await, "limit {limit}: a session exists");

        // A sign-in with the replacement password commits its session.
        let current = session(owner.clone());
        h.store()
            .create_session_atomic(&current, limit, Some(&fence(password.id, after)), ctx())
            .await
            .unwrap();
        assert!(exists(h, current.id).await, "limit {limit}");
    }

    // An unchanged password signs in; a revoked one does not.
    let other = h.owner().await;
    let kept = stored_password(h, other.clone(), b"kept-record").await;
    let signed_in = session(other.clone());
    h.store()
        .create_session_atomic(&signed_in, 0, Some(&fence(kept.id, b"kept-record")), ctx())
        .await
        .unwrap();
    // A passkey keeps the account usable, so the password can be revoked.
    let passkey = sid_core::models::Credential::new(
        other.clone(),
        sid_core::models::CredentialType::WebAuthn,
        CredentialData::new(b"passkey".to_vec()),
        None,
    );
    h.credentials()
        .create_credential(&passkey, ctx())
        .await
        .unwrap();
    assert_eq!(
        h.credentials()
            .revoke_credential(kept.id, ctx())
            .await
            .unwrap(),
        sid_core::models::CredentialRevocation::Revoked
    );
    let revoked = session(other);
    assert!(matches!(
        h.store()
            .create_session_atomic(&revoked, 0, Some(&fence(kept.id, b"kept-record")), ctx())
            .await,
        Err(Error::Fenced(_))
    ));
    assert!(!exists(h, revoked.id).await);
}

/// A fence names a credential of the session's own owner: another owner's
/// current password admits no session.
pub async fn session_fence_is_the_owners_credential<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let stranger = h.owner().await;
    let theirs = stored_password(h, stranger, b"their-record").await;
    let mine = session(owner);
    assert!(matches!(
        h.store()
            .create_session_atomic(&mine, 0, Some(&fence(theirs.id, b"their-record")), ctx())
            .await,
        Err(Error::Fenced(_))
    ));
    assert!(!exists(h, mine.id).await);
}

/// A reset racing sign-ins: every session that committed was proved by the
/// password that was current then, so after the reset none proved by the old
/// password exists unless it committed before the reset (whose revocation
/// ends it); none commits after.
pub async fn session_fence_serializes_with_a_reset<H: GrantHarness>(h: &H) {
    use sid_core::models::CredentialData;
    let owner = h.owner().await;
    let before = b"racing-before";
    let password = stored_password(h, owner.clone(), before).await;
    let mut replaced = password.clone();
    replaced.data = CredentialData::new(b"racing-after".to_vec());

    let stale = fence(password.id, before);
    let sessions: Vec<_> = (0..6).map(|_| session(owner.clone())).collect();
    let creates = sessions
        .iter()
        .map(|s| h.store().create_session_atomic(s, 0, Some(&stale), ctx()));
    let reset = h
        .credentials()
        .change_password(password.id, before, &replaced, None, ctx());
    let (created, reset) = tokio::join!(futures::future::join_all(creates), reset);
    assert!(reset.unwrap(), "the reset applies");
    for (s, outcome) in sessions.iter().zip(created) {
        match outcome {
            Ok(_) => assert!(exists(h, s.id).await),
            Err(Error::Fenced(_)) => assert!(!exists(h, s.id).await),
            Err(e) => panic!("{e:?}"),
        }
    }
    // After the reset committed, the old password admits nothing.
    let late = session(owner);
    assert!(matches!(
        h.store()
            .create_session_atomic(&late, 0, Some(&stale), ctx())
            .await,
        Err(Error::Fenced(_))
    ));
}

/// A password's revocation racing sign-ins it proved serializes with them:
/// each sign-in either commits before the revocation or is fenced, and
/// neither side fails on storage (no lock-order deadlock).
pub async fn session_fence_serializes_with_a_revocation<H: GrantHarness>(h: &H) {
    use sid_core::models::{Credential, CredentialData, CredentialType};
    for round in 0..10 {
        let owner = h.owner().await;
        let record = format!("revoked-{round}");
        let password = stored_password(h, owner.clone(), record.as_bytes()).await;
        // A passkey keeps the account usable, so the password can be revoked.
        h.credentials()
            .create_credential(
                &Credential::new(
                    owner.clone(),
                    CredentialType::WebAuthn,
                    CredentialData::new(b"passkey".to_vec()),
                    None,
                ),
                ctx(),
            )
            .await
            .unwrap();
        let proved = fence(password.id, record.as_bytes());
        let sessions: Vec<_> = (0..4).map(|_| session(owner.clone())).collect();
        let creates = sessions
            .iter()
            .map(|s| h.store().create_session_atomic(s, 3, Some(&proved), ctx()));
        let revoke = h.credentials().revoke_credential(password.id, ctx());
        let (created, revoked) = tokio::join!(futures::future::join_all(creates), revoke);
        assert_eq!(
            revoked.unwrap(),
            sid_core::models::CredentialRevocation::Revoked,
            "round {round}"
        );
        for outcome in created {
            assert!(
                matches!(outcome, Ok(_) | Err(Error::Fenced(_))),
                "round {round}: {outcome:?}"
            );
        }
    }
}

fn under_policy(epoch: i64) -> MutationContext {
    ctx().fenced_by(sid_core::models::ActorFence::LoginPolicy { epoch })
}

/// Every store, whether or not it keeps the login-policy epoch, refuses a
/// session or code fenced by an epoch that does not hold and stores nothing:
/// a fence is checked or refused, never ignored. No policy write produces a
/// negative epoch.
pub async fn a_login_policy_fence_is_never_ignored<H: GrantHarness>(h: &H) {
    fn refused<T>(outcome: &sid_core::Result<T>) -> bool {
        matches!(outcome, Err(Error::Fenced(_) | Error::Validation(_)))
    }
    let owner = h.owner().await;
    let resource = h.resource().await;

    let session = session(owner.clone());
    let created = h
        .store()
        .create_session_atomic(&session, 0, None, under_policy(-1))
        .await;
    assert!(refused(&created), "{created:?}");
    assert!(h.store().get_session(session.id).await.unwrap().is_none());

    let code = code(h, owner, resource).await;
    let created = h.store().create_auth_code(&code, under_policy(-1)).await;
    assert!(refused(&created), "{created:?}");
    assert!(
        h.store()
            .get_auth_code_by_hash(&code.code_hash)
            .await
            .unwrap()
            .is_none()
    );
}

/// A session decided under a login policy commits only while that policy is
/// current: under the current epoch it commits, with or without a session
/// limit; once a policy write advanced the epoch, the earlier one admits
/// nothing. Before any policy write no epoch holds.
pub async fn session_commits_only_under_the_current_login_policy<H: LoginPolicyHarness>(h: &H) {
    let owner = h.owner().await;
    let unwritten = session(owner.clone());
    assert!(matches!(
        h.store()
            .create_session_atomic(&unwritten, 0, None, under_policy(1))
            .await,
        Err(Error::Fenced(_))
    ));
    assert!(!exists(h, unwritten.id).await);

    let first = h.advance_login_policy().await;
    for limit in [0, 5] {
        let current = session(owner.clone());
        h.store()
            .create_session_atomic(&current, limit, None, under_policy(first))
            .await
            .unwrap();
        assert!(exists(h, current.id).await, "limit {limit}");
    }

    let second = h.advance_login_policy().await;
    assert!(second > first);
    for limit in [0, 5] {
        let stale = session(owner.clone());
        let refused = h
            .store()
            .create_session_atomic(&stale, limit, None, under_policy(first))
            .await;
        assert!(
            matches!(refused, Err(Error::Fenced(_))),
            "limit {limit}: {refused:?}"
        );
        assert!(!exists(h, stale.id).await, "limit {limit}");
    }
}

/// An authorization code decided under a login policy commits only while it
/// is current: a policy write between the decision and the commit refuses
/// the code and stores nothing.
pub async fn auth_code_commits_only_under_the_current_login_policy<H: LoginPolicyHarness>(h: &H) {
    let owner = h.owner().await;
    let resource = h.resource().await;
    let epoch = h.advance_login_policy().await;
    let current = code(h, owner.clone(), resource).await;
    h.store()
        .create_auth_code(&current, under_policy(epoch))
        .await
        .unwrap();
    assert!(
        h.store()
            .get_auth_code_by_hash(&current.code_hash)
            .await
            .unwrap()
            .is_some()
    );

    h.advance_login_policy().await;
    let stale = code(h, owner, resource).await;
    assert!(matches!(
        h.store()
            .create_auth_code(&stale, under_policy(epoch))
            .await,
        Err(Error::Fenced(_))
    ));
    assert!(
        h.store()
            .get_auth_code_by_hash(&stale.code_hash)
            .await
            .unwrap()
            .is_none()
    );
}

/// A policy write racing sessions decided under the policy before it
/// serializes with them: each either commits before the write or is fenced,
/// and none commits under the earlier policy after the write.
pub async fn a_policy_write_serializes_with_its_sessions<H: LoginPolicyHarness>(h: &H) {
    let owner = h.owner().await;
    let epoch = h.advance_login_policy().await;
    let sessions: Vec<_> = (0..6).map(|_| session(owner.clone())).collect();
    let creates = sessions.iter().map(|s| {
        h.store()
            .create_session_atomic(s, 10, None, under_policy(epoch))
    });
    let (created, advanced) =
        tokio::join!(futures::future::join_all(creates), h.advance_login_policy());
    assert!(advanced > epoch);
    for (s, outcome) in sessions.iter().zip(created) {
        match outcome {
            Ok(_) => assert!(exists(h, s.id).await),
            Err(Error::Fenced(_)) => assert!(!exists(h, s.id).await),
            Err(e) => panic!("{e:?}"),
        }
    }
    let late = session(owner);
    assert!(matches!(
        h.store()
            .create_session_atomic(&late, 3, None, under_policy(epoch))
            .await,
        Err(Error::Fenced(_))
    ));
}

/// Creating a session never replaces one: an existing id is `Conflict` with or
/// without a session limit, and the stored session keeps its authentication.
pub async fn session_create_never_replaces<H: GrantHarness>(h: &H) {
    let first = session(h.owner().await);
    h.store()
        .create_session_atomic(&first, 0, None, ctx())
        .await
        .unwrap();
    let mut again = first.clone();
    again.amr = vec!["pwd".into(), "otp".into()];
    again.assurance_level = AuthLevel::Standard;

    for limit in [0, 5] {
        let err = h
            .store()
            .create_session_atomic(&again, limit, None, ctx())
            .await
            .expect_err("a create over an existing session");
        assert!(matches!(err, Error::Conflict(_)), "limit {limit}: {err:?}");
    }
    let stored = h.store().get_session(first.id).await.unwrap().unwrap();
    assert_eq!(stored.profile_id, first.profile_id);
    assert_eq!(stored.authentication(), first.authentication());
}

/// Ending a session removes it; ending it again ends nothing.
pub async fn session_end<H: GrantHarness>(h: &H) {
    let s = session(h.owner().await);
    h.store()
        .create_session_atomic(&s, 0, None, ctx())
        .await
        .unwrap();

    let ended = h.store().delete_session(s.id, &end(), ctx()).await.unwrap();

    assert_eq!(ended, vec![s.id]);
    assert!(!exists(h, s.id).await);
    assert!(
        h.store()
            .delete_session(s.id, &end(), ctx())
            .await
            .unwrap()
            .is_empty(),
        "a session already gone ends nothing"
    );
}

/// An owner's listing holds exactly its stored sessions, newest first, with
/// the expired ones (what is current is the caller's to decide); another
/// owner's sessions and an ended one are not in it.
pub async fn sessions_listed_per_owner<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let other = h.owner().await;
    let mut oldest = session(owner.clone());
    oldest.created_at = ms(Utc::now() - Duration::hours(3));
    oldest.expires_at = ms(Utc::now() - Duration::hours(1));
    let mut ended = session(owner.clone());
    ended.created_at = ms(Utc::now() - Duration::hours(2));
    let mut middle = session(owner.clone());
    middle.created_at = ms(Utc::now() - Duration::hours(1));
    let newest = session(owner.clone());
    let foreign = session(other.clone());
    for s in [&oldest, &ended, &middle, &newest, &foreign] {
        h.store()
            .create_session_atomic(s, 0, None, ctx())
            .await
            .unwrap();
    }
    h.store()
        .delete_session(ended.id, &end(), ctx())
        .await
        .unwrap();

    let listed: Vec<SessionId> = h
        .store()
        .list_sessions(&owner)
        .await
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(listed, vec![newest.id, middle.id, oldest.id]);
    let theirs = h.store().list_sessions(&other).await.unwrap();
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].id, foreign.id);
    assert_eq!(theirs[0].profile_id, other);
}

/// A session redeemed from a grant ends with the session it reuses: ending
/// the redeemed one leaves the other, ending that one (directly or by the
/// session limit) ends what it authenticated and nothing else.
pub async fn session_end_ends_what_it_authenticated<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let dependent_of = |sso: &Session<H::Owner>| {
        session(owner.clone()).with_grant_authentication(&sso.grant_authentication())
    };
    let sso = session(owner.clone());
    let unrelated = session(owner.clone());
    let app = dependent_of(&sso);
    for s in [&sso, &unrelated, &app] {
        h.store()
            .create_session_atomic(s, 0, None, ctx())
            .await
            .unwrap();
    }
    assert_eq!(
        h.store()
            .get_session(app.id)
            .await
            .unwrap()
            .unwrap()
            .authenticated_by,
        Some(sso.id)
    );

    // An application's sign-out does not end the session it reused.
    h.store()
        .delete_session(app.id, &end(), ctx())
        .await
        .unwrap();
    assert!(!exists(h, app.id).await);
    assert!(exists(h, sso.id).await);

    let app = dependent_of(&sso);
    h.store()
        .create_session_atomic(&app, 0, None, ctx())
        .await
        .unwrap();
    let mut ended = h
        .store()
        .delete_session(sso.id, &end(), ctx())
        .await
        .unwrap();
    ended.sort_by_key(SessionId::to_string);
    let mut expected = vec![sso.id, app.id];
    expected.sort_by_key(SessionId::to_string);
    assert_eq!(ended, expected);
    assert!(exists(h, unrelated.id).await);

    // The limit evicting a session evicts what it authenticated too.
    let owner = h.owner().await;
    let mut sso = session(owner.clone());
    sso.created_at = Utc::now() - Duration::minutes(1);
    h.store()
        .create_session_atomic(&sso, 0, None, ctx())
        .await
        .unwrap();
    let mut app = session(owner.clone()).with_grant_authentication(&sso.grant_authentication());
    app.created_at = Utc::now() - Duration::seconds(30);
    h.store()
        .create_session_atomic(&app, 0, None, ctx())
        .await
        .unwrap();
    let newest = session(owner);
    let evicted = h
        .store()
        .create_session_atomic(&newest, 2, None, ctx())
        .await
        .unwrap();
    assert!(
        evicted.contains(&sso.id) && evicted.contains(&app.id),
        "{evicted:?}"
    );
    assert!(!exists(h, app.id).await);
    assert!(exists(h, newest.id).await);
}

/// Ending a session takes its refresh tokens and those of the sessions it
/// authenticated in the same transition: no refresh outlives its session.
pub async fn session_end_takes_refresh_tokens<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let resource = h.resource().await;
    let parent = session(owner.clone());
    let dependent = session(owner).with_grant_authentication(&parent.grant_authentication());
    let mut tokens = Vec::new();
    for s in [&parent, &dependent] {
        let token = refresh(s, Uuid::now_v7(), resource);
        redeemed(h, s, &token).await;
        tokens.push(token);
    }

    let ended = h
        .store()
        .delete_session(parent.id, &end(), ctx())
        .await
        .unwrap();

    assert_eq!(ended.len(), 2);
    for token in &tokens {
        assert!(
            stored_refresh(h, token).await.is_none(),
            "a refresh token outlived its session"
        );
    }
}

/// Creating a session at the owner's limit evicts the oldest; a limit of 0 is
/// unlimited, under the limit nothing is evicted, and concurrent sign-ins
/// never leave more sessions than the limit.
pub async fn session_limit_evicts_oldest<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let mut oldest = session(owner.clone());
    oldest.created_at = Utc::now() - Duration::minutes(2);
    let mut middle = session(owner.clone());
    middle.created_at = Utc::now() - Duration::minutes(1);
    for s in [&oldest, &middle] {
        let evicted = h
            .store()
            .create_session_atomic(s, 0, None, ctx())
            .await
            .unwrap();
        assert!(evicted.is_empty(), "a limit of 0 evicted a session");
    }

    let newest = session(owner);
    let evicted = h
        .store()
        .create_session_atomic(&newest, 2, None, ctx())
        .await
        .unwrap();
    assert_eq!(
        evicted,
        vec![oldest.id],
        "the oldest session was not evicted"
    );
    assert!(!exists(h, oldest.id).await);
    for kept in [&middle, &newest] {
        assert!(exists(h, kept.id).await);
    }

    let under = session(h.owner().await);
    assert!(
        h.store()
            .create_session_atomic(&under, 5, None, ctx())
            .await
            .unwrap()
            .is_empty()
    );

    let racing = h.owner().await;
    let s: Vec<_> = (0..6).map(|_| session(racing.clone())).collect();
    let create = |i: usize| h.store().create_session_atomic(&s[i], 2, None, ctx());
    let (a, b, c, d, e, f) = tokio::join!(
        create(0),
        create(1),
        create(2),
        create(3),
        create(4),
        create(5)
    );
    for result in [a, b, c, d, e, f] {
        result.unwrap();
    }
    let mut left = 0;
    for one in &s {
        left += usize::from(exists(h, one.id).await);
    }
    assert_eq!(left, 2, "concurrent sign-ins exceeded the session limit");
}

/// A session a browser signed in with is found by its secret's hash and only
/// by it, with the CSRF token it was stored with; one hash belongs to one
/// session.
pub async fn session_found_by_browser_secret<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let secret = browser_secret();
    let csrf = BrowserCsrfToken::from_bytes(*browser_secret().as_bytes());
    let mut signed_in = session(owner.clone());
    signed_in.browser_secret_hash = Some(secret);
    signed_in.browser_csrf = Some(csrf);
    h.store()
        .create_session_atomic(&signed_in, 0, None, ctx())
        .await
        .unwrap();
    let native = session(owner.clone());
    h.store()
        .create_session_atomic(&native, 0, None, ctx())
        .await
        .unwrap();

    let found = h
        .store()
        .get_session_by_browser_secret(&secret)
        .await
        .unwrap()
        .expect("the signed-in session");
    assert_eq!(found.id, signed_in.id);
    assert_eq!(found.browser_secret_hash, Some(secret));
    assert_eq!(found.browser_csrf, Some(csrf));
    assert_eq!(
        h.store()
            .get_session(signed_in.id)
            .await
            .unwrap()
            .unwrap()
            .browser_csrf,
        Some(csrf)
    );
    assert!(
        h.store()
            .get_session_by_browser_secret(&browser_secret())
            .await
            .unwrap()
            .is_none()
    );
    let stored_native = h.store().get_session(native.id).await.unwrap().unwrap();
    assert_eq!(stored_native.browser_secret_hash, None);
    assert_eq!(stored_native.browser_csrf, None);

    let mut second = session(owner);
    second.browser_secret_hash = Some(secret);
    assert!(
        h.store()
            .create_session_atomic(&second, 0, None, ctx())
            .await
            .is_err(),
        "a second session with one browser secret"
    );
    assert!(!exists(h, second.id).await);
}

/// Last activity only moves forward: an earlier time does not lower it,
/// concurrent touches keep the latest, and touching an unknown session
/// creates nothing.
pub async fn touch_session_keeps_latest_activity<H: GrantHarness>(h: &H) {
    let s = session(h.owner().await);
    h.store()
        .create_session_atomic(&s, 0, None, ctx())
        .await
        .unwrap();
    let last_activity = || async {
        h.store()
            .get_session(s.id)
            .await
            .unwrap()
            .unwrap()
            .last_activity_at
    };

    let now = ms(Utc::now());
    h.store().touch_session(s.id, now).await.unwrap();
    h.store()
        .touch_session(s.id, now - Duration::minutes(5))
        .await
        .unwrap();
    assert_eq!(last_activity().await, Some(now));

    let at = |seconds| now + Duration::seconds(seconds);
    let (a, b, c, d) = tokio::join!(
        h.store().touch_session(s.id, at(3)),
        h.store().touch_session(s.id, at(1)),
        h.store().touch_session(s.id, at(4)),
        h.store().touch_session(s.id, at(2)),
    );
    for result in [a, b, c, d] {
        result.unwrap();
    }
    assert_eq!(last_activity().await, Some(at(4)));

    let unknown = SessionId::generate();
    h.store().touch_session(unknown, now).await.unwrap();
    assert!(!exists(h, unknown).await);
}

/// A stored code reads back with everything its redemption needs, the
/// authorizing session's step-up included; an unknown hash finds nothing.
pub async fn auth_code_roundtrip<H: GrantHarness>(h: &H) {
    let code = code(h, h.owner().await, h.resource().await).await;
    h.store().create_auth_code(&code, ctx()).await.unwrap();

    let stored = h
        .store()
        .get_auth_code_by_hash(&code.code_hash)
        .await
        .unwrap()
        .expect("stored code");
    assert!(!stored.used);
    assert_eq!(stored.profile_id, code.profile_id);
    assert_eq!(stored.client_id, code.client_id);
    assert_eq!(stored.redirect_uri, code.redirect_uri);
    assert_eq!(stored.scopes, code.scopes);
    assert_eq!(stored.code_challenge, code.code_challenge);
    assert_eq!(stored.nonce, code.nonce);
    assert_eq!(stored.resource, code.resource);
    assert_eq!(stored.authentication, code.authentication);
    assert!(
        h.store()
            .get_auth_code_by_hash(Uuid::now_v7().as_bytes())
            .await
            .unwrap()
            .is_none()
    );
}

/// A code is redeemed once: the redemption stores its session and refresh
/// token and marks the code; a second one stores nothing and names the first
/// session so its tokens can be revoked (RFC 6749 §4.1.2). Issuing the code
/// again never makes it usable.
pub async fn auth_code_redeem_once<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let resource = h.resource().await;
    let code = code(h, owner.clone(), resource).await;
    h.store().create_auth_code(&code, ctx()).await.unwrap();
    let first = session(owner.clone());
    let first_token = refresh(&first, Uuid::now_v7(), resource);

    assert_eq!(
        h.store()
            .redeem_auth_code(&code.code_hash, &first, &first_token, ctx())
            .await
            .unwrap(),
        AuthCodeRedemption::Redeemed
    );
    let used = h
        .store()
        .get_auth_code_by_hash(&code.code_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(used.used);
    assert_eq!(used.session_id, Some(first.id));
    assert!(exists(h, first.id).await);
    assert!(stored_refresh(h, &first_token).await.is_some());

    let again = session(owner);
    let again_token = refresh(&again, Uuid::now_v7(), resource);
    assert_eq!(
        h.store()
            .redeem_auth_code(&code.code_hash, &again, &again_token, ctx())
            .await
            .unwrap(),
        AuthCodeRedemption::AlreadyRedeemed {
            session_id: Some(first.id)
        }
    );
    assert!(
        !exists(h, again.id).await,
        "a refused redemption stored a session"
    );
    assert!(
        stored_refresh(h, &again_token).await.is_none(),
        "a refused redemption stored a refresh token"
    );

    let err = h
        .store()
        .create_auth_code(&code, ctx())
        .await
        .expect_err("issuing an existing code");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    assert!(
        h.store()
            .get_auth_code_by_hash(&code.code_hash)
            .await
            .unwrap()
            .unwrap()
            .used,
        "a redeemed code was made usable again"
    );
}

/// Concurrent redemptions of one code: exactly one gets its session stored.
pub async fn auth_code_concurrent_redeem<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let resource = h.resource().await;
    let code = code(h, owner.clone(), resource).await;
    h.store().create_auth_code(&code, ctx()).await.unwrap();
    let sessions: Vec<_> = (0..4).map(|_| session(owner.clone())).collect();
    let tokens: Vec<_> = sessions
        .iter()
        .map(|s| refresh(s, Uuid::now_v7(), resource))
        .collect();
    let redeem = |i: usize| {
        h.store()
            .redeem_auth_code(&code.code_hash, &sessions[i], &tokens[i], ctx())
    };

    let (a, b, c, d) = tokio::join!(redeem(0), redeem(1), redeem(2), redeem(3));

    let results: Vec<_> = [a, b, c, d].into_iter().map(Result::unwrap).collect();
    let winners: Vec<_> = (0..4)
        .filter(|&i| results[i] == AuthCodeRedemption::Redeemed)
        .collect();
    assert_eq!(winners.len(), 1, "exactly one redemption: {results:?}");
    for (i, s) in sessions.iter().enumerate() {
        assert_eq!(exists(h, s.id).await, i == winners[0]);
    }
}

/// A redeemed refresh token reads back with its owner, family, resource and
/// key binding.
pub async fn refresh_token_roundtrip<H: GrantHarness>(h: &H) {
    let s = session(h.owner().await);
    let mut token = refresh(&s, Uuid::now_v7(), h.resource().await);
    token.scopes = vec!["openid".into(), "profile".into()];
    token.dpop_jkt = Some("IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA".into());
    redeemed(h, &s, &token).await;

    let stored = stored_refresh(h, &token).await.expect("stored token");
    assert_eq!(stored.id, token.id);
    assert_eq!(stored.session_id, s.id);
    assert_eq!(stored.profile_id, s.profile_id);
    assert_eq!(stored.client_id, token.client_id);
    assert_eq!(stored.scopes, token.scopes);
    assert_eq!(stored.resource, token.resource);
    assert_eq!(stored.family_id, token.family_id);
    assert_eq!(stored.dpop_jkt, token.dpop_jkt);
    assert!(!stored.revoked);
    assert!(
        h.store()
            .get_refresh_token_by_hash(Uuid::now_v7().as_bytes())
            .await
            .unwrap()
            .is_none()
    );
}

/// Rotation replaces the presented token in one write: it keeps a grace
/// window for a client retry (a retry inside it rotates again and keeps the
/// window); revoking the family ends every token and window, after which
/// nothing rotates.
pub async fn rotate_refresh_token<H: GrantHarness>(h: &H) {
    let s = session(h.owner().await);
    let resource = h.resource().await;
    let family = Uuid::now_v7();
    let old = refresh(&s, family, resource);
    redeemed(h, &s, &old).await;
    let grace = Utc::now() + Duration::seconds(30);

    let first = refresh(&s, family, resource);
    assert!(
        h.store()
            .rotate_refresh_token(old.id, &first, grace, ctx())
            .await
            .unwrap()
    );
    let replaced = stored_refresh(h, &old).await.unwrap();
    assert!(replaced.revoked);
    assert_eq!(replaced.replaced_by, Some(first.id));
    let window = replaced.grace_expires_at.expect("grace window");
    assert!(!stored_refresh(h, &first).await.unwrap().revoked);

    let retry = refresh(&s, family, resource);
    assert!(
        h.store()
            .rotate_refresh_token(old.id, &retry, Utc::now() + Duration::seconds(300), ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        stored_refresh(h, &old)
            .await
            .unwrap()
            .grace_expires_at
            .map(|t| t.timestamp_millis()),
        Some(window.timestamp_millis()),
        "a retry moved the grace window"
    );

    assert_eq!(
        h.store()
            .revoke_refresh_tokens_by_family(family, ctx())
            .await
            .unwrap(),
        3
    );
    for token in [&old, &first, &retry] {
        let stored = stored_refresh(h, token).await.unwrap();
        assert!(stored.revoked);
        assert!(stored.grace_expires_at.is_none(), "a grace window survived");
    }
    let late = refresh(&s, family, resource);
    assert!(
        !h.store()
            .rotate_refresh_token(old.id, &late, grace, ctx())
            .await
            .unwrap()
    );
    assert!(
        stored_refresh(h, &late).await.is_none(),
        "rotated after revocation"
    );
}

/// Signing out revokes every refresh token of the session, grace windows
/// included: a rotated token cannot be retried afterwards.
pub async fn rotate_after_sign_out_is_refused<H: GrantHarness>(h: &H) {
    let s = session(h.owner().await);
    let resource = h.resource().await;
    let family = Uuid::now_v7();
    let old = refresh(&s, family, resource);
    redeemed(h, &s, &old).await;
    let next = refresh(&s, family, resource);
    h.store()
        .rotate_refresh_token(old.id, &next, Utc::now() + Duration::seconds(30), ctx())
        .await
        .unwrap();

    assert_eq!(
        h.store()
            .revoke_refresh_tokens_by_session(s.id, ctx())
            .await
            .unwrap(),
        2
    );

    let retry = refresh(&s, family, resource);
    assert!(
        !h.store()
            .rotate_refresh_token(old.id, &retry, Utc::now() + Duration::seconds(30), ctx())
            .await
            .unwrap(),
        "a grace window outlived sign-out"
    );
    assert!(stored_refresh(h, &retry).await.is_none());
}

/// Concurrent rotations of one token inside no grace window: the first
/// replaces it, and the others all rotate within the grace window it opened
/// or are refused; the family never forks outside the presented token.
pub async fn concurrent_rotation<H: GrantHarness>(h: &H) {
    let s = session(h.owner().await);
    let resource = h.resource().await;
    let family = Uuid::now_v7();
    let old = refresh(&s, family, resource);
    redeemed(h, &s, &old).await;
    let next: Vec<_> = (0..4).map(|_| refresh(&s, family, resource)).collect();
    let grace = Utc::now() + Duration::seconds(30);
    let rotate = |i: usize| {
        h.store()
            .rotate_refresh_token(old.id, &next[i], grace, ctx())
    };

    let (a, b, c, d) = tokio::join!(rotate(0), rotate(1), rotate(2), rotate(3));

    let rotated: Vec<bool> = [a, b, c, d].into_iter().map(Result::unwrap).collect();
    assert!(rotated.contains(&true), "no concurrent rotation succeeded");
    let replaced = stored_refresh(h, &old).await.unwrap();
    assert!(replaced.revoked);
    for (i, token) in next.iter().enumerate() {
        assert_eq!(
            stored_refresh(h, token).await.is_some(),
            rotated[i],
            "a rotation's result does not match what it stored"
        );
    }
}

/// A sign-in's pending second-factor context of `owner`, as its first factor
/// stores it.
fn pending_context<O>(owner: O) -> Session<O> {
    let mut pending = session(owner);
    pending.is_provisional = true;
    pending.scopes = vec![sid_core::models::session::SECOND_FACTOR_SCOPE.to_string()];
    pending
}

/// Pending sign-ins take no session slot: under a limit of two, one full
/// session and two pending contexts, completing one keeps the full session
/// and the other pending one. Counting them evicted a full session for a
/// sign-in that had not finished.
pub async fn a_pending_context_takes_no_session_slot<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let full = session(owner.clone());
    h.store()
        .create_session_atomic(&full, 2, None, ctx())
        .await
        .unwrap();
    let first = pending_context(owner.clone());
    let second = pending_context(owner.clone());
    for pending in [&first, &second] {
        h.store()
            .create_session_atomic(pending, 2, None, ctx())
            .await
            .unwrap();
    }
    assert!(h.store().get_session(full.id).await.unwrap().is_some());

    let completed = session(owner);
    let evicted = h
        .store()
        .complete_pending_session(first.id, &end(), &completed, 2, None, ctx())
        .await
        .unwrap();

    assert!(evicted.is_empty(), "{evicted:?}");
    assert!(h.store().get_session(full.id).await.unwrap().is_some());
    assert!(h.store().get_session(second.id).await.unwrap().is_some());
    assert!(h.store().get_session(completed.id).await.unwrap().is_some());
    assert!(h.store().get_session(first.id).await.unwrap().is_none());
}

/// A pending context completes once: concurrent completions store one
/// session, and one ended before (completed, or ended with its owner's
/// sessions) completes nothing.
pub async fn a_pending_context_completes_once<H: GrantHarness>(h: &H) {
    let owner = h.owner().await;
    let pending = pending_context(owner.clone());
    h.store()
        .create_session_atomic(&pending, 0, None, ctx())
        .await
        .unwrap();
    let (a, b) = (session(owner.clone()), session(owner.clone()));
    let completion = end();
    let (first, second) = tokio::join!(
        h.store()
            .complete_pending_session(pending.id, &completion, &a, 0, None, ctx()),
        h.store()
            .complete_pending_session(pending.id, &completion, &b, 0, None, ctx()),
    );
    let stored = [
        h.store().get_session(a.id).await.unwrap().is_some(),
        h.store().get_session(b.id).await.unwrap().is_some(),
    ];
    assert_eq!(stored.iter().filter(|s| **s).count(), 1, "{stored:?}");
    let refused = if stored[0] { second } else { first };
    assert!(matches!(refused, Err(Error::Fenced(_))), "{refused:?}");

    let ended = pending_context(owner.clone());
    h.store()
        .create_session_atomic(&ended, 0, None, ctx())
        .await
        .unwrap();
    h.store()
        .delete_session(ended.id, &end(), ctx())
        .await
        .unwrap();
    let late = session(owner);
    let refused = h
        .store()
        .complete_pending_session(ended.id, &end(), &late, 0, None, ctx())
        .await;
    assert!(matches!(refused, Err(Error::Fenced(_))), "{refused:?}");
    assert!(h.store().get_session(late.id).await.unwrap().is_none());
}
