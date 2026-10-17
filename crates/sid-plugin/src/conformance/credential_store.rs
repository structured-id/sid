// SPDX-License-Identifier: AGPL-3.0-only
//! [`CredentialStore`] scenarios: credentials and their atomic transitions,
//! password history and WebAuthn user handles, for any account type. Every
//! scenario works on accounts it created and keys it drew, so a harness may
//! run them concurrently against one shared database, except the history
//! write cutoff scenarios: the cutoff is store-wide, so they run against a
//! store of their own.

use std::fmt::Debug;

use async_trait::async_trait;
use chrono::Utc;
use sid_core::models::credential::CredentialStatus;
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialId, CredentialRevocation, CredentialType,
    HistoryCommit, HistoryEpochDescriptor, HistoryEpochId, HistoryEpochUse, HistoryEvidence,
    HistoryKsf, HistorySuite, MutationContext, PolicyEvidence, WebAuthnUserHandle,
};
use sid_core::{Error, Result};
use uuid::Uuid;

use crate::CredentialStore;

/// What a backend's harness supplies to the scenarios.
#[async_trait]
pub trait CredentialHarness: Send + Sync {
    /// The account type the backend stores credentials for.
    type Owner: Clone + PartialEq + Debug + Send + Sync + 'static;

    fn store(&self) -> &dyn CredentialStore<Owner = Self::Owner>;

    /// A new account the store accepts as an owner.
    async fn owner(&self) -> Self::Owner;

    /// An account the store has never had.
    fn missing_owner(&self) -> Self::Owner;
}

fn ctx() -> MutationContext {
    AuditEntry::system("conformance", "credential_store").into()
}

/// A history epoch's public key: `(n + 1)·G` on Pallas, so each `n` gives a
/// distinct valid point and none is the identity.
fn history_public_key(n: u8) -> [u8; 32] {
    use group::{Curve, Group, GroupEncoding};
    use pasta_curves::pallas;
    (pallas::Point::generator() * pallas::Scalar::from(u64::from(n) + 1))
        .to_affine()
        .to_bytes()
}

/// The current time at the microsecond precision every store keeps.
fn micros_now() -> chrono::DateTime<Utc> {
    chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).expect("a current time")
}

/// A descriptor as the evaluator issues one.
fn descriptor(key: u8) -> HistoryEpochDescriptor {
    HistoryEpochDescriptor {
        id: HistoryEpochId::generate(),
        suite: HistorySuite::PallasPoseidonV1,
        public_key: history_public_key(key),
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [key.wrapping_add(1); 32],
        created_at: micros_now(),
    }
}

/// A commit of one entry under `epochs[0]`, the operation's selection.
fn commit<O>(
    owner: O,
    expected_revision: i64,
    epochs: &[HistoryEpochDescriptor],
    entry: u8,
    depth: u32,
) -> HistoryCommit<O> {
    HistoryCommit {
        owner,
        expected_revision,
        epochs: epochs.to_vec(),
        entries: vec![(epochs[0].id, [entry; 32])],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        depth,
        max_age_days: 0,
    }
}

/// A new account with a stored password `p0`.
async fn owner_with_password<H: CredentialHarness>(h: &H) -> (H::Owner, Credential<H::Owner>) {
    let owner = h.owner().await;
    let password = Credential::new(owner.clone(), CredentialType::Opaque, b"p0".to_vec(), None);
    h.store().create_credential(&password, ctx()).await.unwrap();
    (owner, password)
}

/// `password` changed to `data` with verified policy evidence.
fn next<O: Clone>(password: &Credential<O>, data: &[u8]) -> Credential<O> {
    let mut new = password.clone();
    new.data = CredentialData::new(data.to_vec());
    new.policy_evidence = PolicyEvidence::Verified {
        policy_version: 1,
        artifact: [1; 32],
    };
    new
}

/// Change `password` from `from` to `to` with one entry under `epochs[0]`
/// against the current revision; whether it applied.
async fn change<H: CredentialHarness>(
    h: &H,
    owner: H::Owner,
    password: &Credential<H::Owner>,
    (from, to): (&[u8], &[u8]),
    epochs: &[HistoryEpochDescriptor],
    entry: u8,
    depth: u32,
) -> Result<bool> {
    let revision = h
        .store()
        .get_password_history(owner.clone())
        .await?
        .revision;
    h.store()
        .change_password(
            password.id,
            from,
            &next(password, to),
            Some(&commit(owner, revision, epochs, entry, depth)),
            ctx(),
        )
        .await
}

// ─── Credentials ───

/// An account keeps at least one active primary credential: the last one is
/// not revoked, second factors are always revocable, a revoked credential
/// stays stored (revoked, not deleted), and revoking again changes nothing.
/// Two concurrent revocations of the last two passkeys revoke exactly one.
pub async fn revoke_keeps_last_primary<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let passkey = |n: u8| Credential::new(owner.clone(), CredentialType::WebAuthn, vec![n], None);
    let (first, second) = (passkey(1), passkey(2));
    let totp = Credential::new(owner.clone(), CredentialType::Totp, vec![9], None);
    for c in [&first, &second, &totp] {
        store.create_credential(c, ctx()).await.unwrap();
    }

    assert_eq!(
        store.revoke_credential(totp.id, ctx()).await.unwrap(),
        CredentialRevocation::Revoked,
        "a second factor is always revocable"
    );
    let (a, b) = tokio::join!(
        store.revoke_credential(first.id, ctx()),
        store.revoke_credential(second.id, ctx()),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| *o as u8);
    assert_eq!(
        outcomes,
        [
            CredentialRevocation::Revoked,
            CredentialRevocation::LastPrimary
        ],
        "both of the last two sign-in methods were removed"
    );

    let stored = store.get_credentials_by_profile(owner, None).await.unwrap();
    assert_eq!(stored.len(), 3, "a revocation deleted the record");
    assert_eq!(stored.iter().filter(|c| c.status.is_active()).count(), 1);
    let last = stored.iter().find(|c| c.status.is_active()).unwrap();
    assert_eq!(
        store.revoke_credential(last.id, ctx()).await.unwrap(),
        CredentialRevocation::LastPrimary
    );
    assert_eq!(
        store.revoke_credential(totp.id, ctx()).await.unwrap(),
        CredentialRevocation::AlreadyGone
    );
}

/// Deleting a credential removes that one; the account-wide delete removes
/// every credential of the account, counts them, and leaves another
/// account's.
pub async fn credential_deletion<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let (owner, other) = (h.owner().await, h.owner().await);
    let totp = Credential::new(owner.clone(), CredentialType::Totp, vec![1], None);
    let recovery = Credential::new(owner.clone(), CredentialType::Recovery, vec![2], None);
    let webauthn = Credential::new(owner.clone(), CredentialType::WebAuthn, vec![3], None);
    let foreign = Credential::new(other, CredentialType::Totp, vec![4], None);
    for c in [&totp, &recovery, &webauthn, &foreign] {
        store.create_credential(c, ctx()).await.unwrap();
    }

    store.delete_credential(totp.id, ctx()).await.unwrap();
    assert!(store.get_credential(totp.id).await.unwrap().is_none());
    assert!(store.get_credential(recovery.id).await.unwrap().is_some());

    let removed = store
        .delete_credentials_by_profile(owner.clone(), ctx())
        .await
        .unwrap();
    assert_eq!(removed, 2);
    for id in [recovery.id, webauthn.id] {
        assert!(store.get_credential(id).await.unwrap().is_none());
    }
    assert!(
        store.get_credential(foreign.id).await.unwrap().is_some(),
        "another account's credential was deleted"
    );
    assert_eq!(
        store
            .delete_credentials_by_profile(owner, ctx())
            .await
            .unwrap(),
        0
    );
}

/// An account has one password: a second active OPAQUE credential is
/// refused with Conflict; after the first is revoked a new one may be stored.
pub async fn single_active_password<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let first = Credential::new(owner.clone(), CredentialType::Opaque, vec![1u8; 32], None);
    store.create_credential(&first, ctx()).await.unwrap();

    let second = Credential::new(owner.clone(), CredentialType::Opaque, vec![2u8; 32], None);
    let err = store
        .create_credential(&second, ctx())
        .await
        .expect_err("second active password");
    assert!(
        matches!(err, Error::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    // Another primary method keeps the account reachable, so the password
    // can be revoked.
    let passkey = Credential::new(owner, CredentialType::WebAuthn, vec![3u8; 16], None);
    store.create_credential(&passkey, ctx()).await.unwrap();
    assert_eq!(
        store.revoke_credential(first.id, ctx()).await.unwrap(),
        CredentialRevocation::Revoked
    );
    assert_eq!(
        store
            .get_credential(first.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        CredentialStatus::Revoked
    );
    store
        .create_credential(&second, ctx())
        .await
        .expect("a new password after the old one is revoked");
}

/// Replacing credential data is a compare-and-swap: it applies only over the
/// expected data of an active credential, and of two concurrent writers
/// starting from the same data exactly one wins.
pub async fn replace_credential_data_is_compare_and_swap<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let credential = Credential::new(owner, CredentialType::Recovery, b"v0".to_vec(), None);
    store.create_credential(&credential, ctx()).await.unwrap();

    assert!(
        !store
            .replace_credential_data(credential.id, b"stale", b"lost", ctx())
            .await
            .unwrap(),
        "a write over unexpected data applies"
    );
    assert!(
        store
            .replace_credential_data(credential.id, b"v0", b"v1", ctx())
            .await
            .unwrap()
    );
    let (a, b) = tokio::join!(
        store.replace_credential_data(credential.id, b"v1", b"a", ctx()),
        store.replace_credential_data(credential.id, b"v1", b"b", ctx()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one concurrent writer must win: {a} {b}");
    let stored = store.get_credential(credential.id).await.unwrap().unwrap();
    assert_eq!(stored.data.expose(), if a { b"a" } else { b"b" });
    assert!(stored.last_used_at.is_some());

    assert_eq!(
        store.revoke_credential(credential.id, ctx()).await.unwrap(),
        CredentialRevocation::Revoked
    );
    let current = stored.data.expose().to_vec();
    assert!(
        !store
            .replace_credential_data(credential.id, &current, b"after-revoke", ctx())
            .await
            .unwrap(),
        "a revoked credential's data changed"
    );
}

/// Marking a credential used touches only an active one: a revoked
/// credential stays revoked and unused, an unknown id writes nothing.
pub async fn mark_used_only_when_active<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let active = Credential::new(owner.clone(), CredentialType::Opaque, vec![1u8; 32], None);
    store.create_credential(&active, ctx()).await.unwrap();
    let mut revoked = Credential::new(owner, CredentialType::Totp, vec![2u8; 32], None);
    revoked.status = CredentialStatus::Revoked;
    store.create_credential(&revoked, ctx()).await.unwrap();

    assert!(store.mark_credential_used(active.id, ctx()).await.unwrap());
    assert!(!store.mark_credential_used(revoked.id, ctx()).await.unwrap());
    assert!(
        !store
            .mark_credential_used(CredentialId::new(), ctx())
            .await
            .unwrap()
    );

    let stored = store.get_credential(active.id).await.unwrap().unwrap();
    assert!(stored.last_used_at.is_some());
    assert_eq!(stored.status, CredentialStatus::Active);
    let stored = store.get_credential(revoked.id).await.unwrap().unwrap();
    assert!(stored.last_used_at.is_none());
    assert_eq!(stored.status, CredentialStatus::Revoked);
}

/// Creating a credential never replaces one: a second create with the same id
/// is refused with Conflict and the stored credential keeps its data and
/// status (a create over a revoked factor would revive it).
pub async fn create_never_replaces<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let mut revoked = Credential::new(owner, CredentialType::Totp, b"first".to_vec(), None);
    revoked.status = CredentialStatus::Revoked;
    store.create_credential(&revoked, ctx()).await.unwrap();

    let mut again = revoked.clone();
    again.status = CredentialStatus::Active;
    again.data = CredentialData::new(b"second".to_vec());
    let err = store
        .create_credential(&again, ctx())
        .await
        .expect_err("a create over an existing credential");
    assert!(
        matches!(err, Error::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
    let stored = store.get_credential(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CredentialStatus::Revoked);
    assert_eq!(stored.data.expose(), b"first");
}

/// A label changes only on an active credential; a revoked one keeps its
/// label and stays revoked.
pub async fn label_only_on_active<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let active = Credential::new(
        owner.clone(),
        CredentialType::Totp,
        vec![1],
        Some("old".into()),
    );
    let mut revoked = Credential::new(owner, CredentialType::Totp, vec![2], Some("gone".into()));
    revoked.status = CredentialStatus::Revoked;
    for c in [&active, &revoked] {
        store.create_credential(c, ctx()).await.unwrap();
    }

    assert!(
        store
            .set_credential_label(active.id, Some("new"), ctx())
            .await
            .unwrap()
    );
    assert!(
        !store
            .set_credential_label(revoked.id, Some("revived"), ctx())
            .await
            .unwrap()
    );
    assert!(
        !store
            .set_credential_label(CredentialId::new(), Some("x"), ctx())
            .await
            .unwrap()
    );
    let stored = store.get_credential(active.id).await.unwrap().unwrap();
    assert_eq!(stored.label.as_deref(), Some("new"));
    let stored = store.get_credential(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.label.as_deref(), Some("gone"));
    assert_eq!(stored.status, CredentialStatus::Revoked);
}

/// A password change is a compare-and-swap over the current password of an
/// active credential and stores the new policy evidence with it; of two
/// concurrent changes from one password exactly one applies, and a revoked
/// password is not changed back to use.
pub async fn change_password_is_compare_and_swap<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let password = Credential::new(owner.clone(), CredentialType::Opaque, b"p0".to_vec(), None);
    let passkey = Credential::new(owner, CredentialType::WebAuthn, b"k".to_vec(), None);
    for c in [&password, &passkey] {
        store.create_credential(c, ctx()).await.unwrap();
    }
    let changed_to = |data: &[u8], version: u32| {
        let mut new = password.clone();
        new.data = CredentialData::new(data.to_vec());
        new.policy_evidence = PolicyEvidence::Verified {
            policy_version: version,
            artifact: [version as u8; 32],
        };
        new
    };

    assert!(
        !store
            .change_password(password.id, b"stale", &changed_to(b"lost", 1), None, ctx())
            .await
            .unwrap(),
        "a change over another password applies"
    );
    assert!(
        store
            .change_password(password.id, b"p0", &changed_to(b"p1", 2), None, ctx())
            .await
            .unwrap()
    );
    let stored = store.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(stored.data.expose(), b"p1");
    assert_eq!(
        stored.policy_evidence,
        PolicyEvidence::Verified {
            policy_version: 2,
            artifact: [2; 32],
        },
        "the verdict keeps its policy and artifact"
    );
    assert!(stored.last_used_at.is_some());

    let (to_a, to_b) = (changed_to(b"a", 3), changed_to(b"b", 3));
    let (a, b) = tokio::join!(
        store.change_password(password.id, b"p1", &to_a, None, ctx()),
        store.change_password(password.id, b"p1", &to_b, None, ctx()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one concurrent change must win: {a} {b}");

    let current = store
        .get_credential(password.id)
        .await
        .unwrap()
        .unwrap()
        .data
        .expose()
        .to_vec();
    store.revoke_credential(password.id, ctx()).await.unwrap();
    assert!(
        !store
            .change_password(password.id, &current, &changed_to(b"after", 4), None, ctx())
            .await
            .unwrap(),
        "a revoked password was changed"
    );
    let stored = store.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CredentialStatus::Revoked);
    assert_eq!(stored.data.expose(), current.as_slice());
}

/// Resealing replaces data over the expected value only, whatever the status,
/// and is not a use: status and last use are untouched.
pub async fn reseal_keeps_status<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let mut revoked = Credential::new(owner, CredentialType::Totp, b"plain".to_vec(), None);
    revoked.status = CredentialStatus::Revoked;
    store.create_credential(&revoked, ctx()).await.unwrap();

    assert!(
        !store
            .reseal_credential_data(revoked.id, b"other", b"sealed", ctx())
            .await
            .unwrap()
    );
    assert!(
        store
            .reseal_credential_data(revoked.id, b"plain", b"sealed", ctx())
            .await
            .unwrap()
    );
    let stored = store.get_credential(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.data.expose(), b"sealed");
    assert_eq!(stored.status, CredentialStatus::Revoked);
    assert!(stored.last_used_at.is_none());
}

/// A password replacement removes the account's OPAQUE and legacy-hash
/// credentials, installs the new one, and leaves other factors alone.
pub async fn replace_password_swaps_only_password<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let old = Credential::new(owner.clone(), CredentialType::Opaque, vec![1u8; 32], None);
    let legacy = Credential::new(
        owner.clone(),
        CredentialType::LegacyHash,
        vec![3u8; 32],
        None,
    );
    let totp = Credential::new(owner.clone(), CredentialType::Totp, vec![4u8; 20], None);
    for c in [&old, &legacy, &totp] {
        store.create_credential(c, ctx()).await.unwrap();
    }

    let new = Credential::new(owner.clone(), CredentialType::Opaque, vec![2u8; 32], None);
    store
        .replace_credential(&new, ctx())
        .await
        .expect("replace");

    let opaque = store
        .get_credentials_by_profile(owner.clone(), Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(opaque.len(), 1);
    assert_eq!(opaque[0].id, new.id);
    let legacy_left = store
        .get_credentials_by_profile(owner.clone(), Some(CredentialType::LegacyHash))
        .await
        .unwrap();
    assert!(legacy_left.is_empty(), "legacy hash must be gone");
    let totp_left = store
        .get_credentials_by_profile(owner, Some(CredentialType::Totp))
        .await
        .unwrap();
    assert_eq!(totp_left.len(), 1, "other factors are untouched");

    let err = store
        .replace_credential(&totp, ctx())
        .await
        .expect_err("a second factor is added, not replaced");
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
}

/// A new recovery-code set replaces the old one and nothing else, so the old
/// codes stop working the moment the new ones exist.
pub async fn replace_recovery_codes_swaps_only_the_set<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let password = Credential::new(owner.clone(), CredentialType::Opaque, vec![1u8; 32], None);
    let old = Credential::new(
        owner.clone(),
        CredentialType::Recovery,
        b"[\"a\"]".to_vec(),
        None,
    );
    for c in [&password, &old] {
        store.create_credential(c, ctx()).await.unwrap();
    }

    let new = Credential::new(
        owner.clone(),
        CredentialType::Recovery,
        b"[\"b\"]".to_vec(),
        None,
    );
    store
        .replace_credential(&new, ctx())
        .await
        .expect("replace");

    let sets = store
        .get_credentials_by_profile(owner, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(sets.len(), 1, "{sets:?}");
    assert_eq!(sets[0].id, new.id);
    assert!(store.get_credential(old.id).await.unwrap().is_none());
    assert!(store.get_credential(password.id).await.unwrap().is_some());
}

/// A password's policy evidence (the policy version and the artifact that
/// accepted its proof) reads back as stored, for a verified and for a
/// policy-unverified credential; a version beyond what the store keeps is
/// refused, never truncated into another policy's evidence.
pub async fn policy_evidence_roundtrip<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let evidence = PolicyEvidence::Verified {
        policy_version: 3,
        artifact: [0xa5; 32],
    };
    let mut verified = Credential::new(owner.clone(), CredentialType::Opaque, vec![1u8; 32], None);
    verified.policy_evidence = evidence;
    store.create_credential(&verified, ctx()).await.unwrap();
    let stored = store.get_credential(verified.id).await.unwrap().unwrap();
    assert_eq!(stored.policy_evidence, evidence);

    let unverified = Credential::new(owner.clone(), CredentialType::Opaque, vec![2u8; 32], None);
    store.replace_credential(&unverified, ctx()).await.unwrap();
    let stored = store.get_credential(unverified.id).await.unwrap().unwrap();
    assert_eq!(stored.policy_evidence, PolicyEvidence::Unverified);

    let mut out_of_range = Credential::new(owner, CredentialType::Opaque, vec![3u8; 32], None);
    out_of_range.policy_evidence = PolicyEvidence::Verified {
        policy_version: u32::MAX,
        artifact: [1; 32],
    };
    assert!(
        store
            .replace_credential(&out_of_range, ctx())
            .await
            .is_err()
    );
}

/// An enrolled factor and the recovery codes issued with it are stored
/// together: the new set replaces the old one, and when either write fails
/// neither is stored (a factor without its codes cannot be enrolled again).
pub async fn enroll_stores_factor_with_codes<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let codes =
        |data: &[u8]| Credential::new(owner.clone(), CredentialType::Recovery, data.to_vec(), None);
    let old = codes(b"[\"a\"]");
    store.create_credential(&old, ctx()).await.unwrap();

    let totp = Credential::new(owner.clone(), CredentialType::Totp, vec![7u8; 20], None);
    let set = codes(b"[\"b\"]");
    store
        .enroll_credential(&totp, Some(&set), ctx())
        .await
        .unwrap();
    assert!(store.get_credential(totp.id).await.unwrap().is_some());
    let sets = store
        .get_credentials_by_profile(owner.clone(), Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(sets.iter().map(|c| c.id).collect::<Vec<_>>(), vec![set.id]);

    // The codes cannot be stored (their id is taken): the factor is not stored
    // either, and the stored set stays.
    let second = Credential::new(owner.clone(), CredentialType::Totp, vec![8u8; 20], None);
    let mut clash = codes(b"[\"c\"]");
    clash.id = totp.id;
    assert!(
        store
            .enroll_credential(&second, Some(&clash), ctx())
            .await
            .is_err()
    );
    assert!(
        store.get_credential(second.id).await.unwrap().is_none(),
        "a factor was stored without its recovery codes"
    );
    assert!(store.get_credential(set.id).await.unwrap().is_some());

    let third = Credential::new(owner.clone(), CredentialType::Totp, vec![9u8; 20], None);
    let not_codes = Credential::new(owner, CredentialType::Totp, vec![1u8; 20], None);
    assert!(matches!(
        store
            .enroll_credential(&third, Some(&not_codes), ctx())
            .await,
        Err(Error::Validation(_))
    ));
    assert!(store.get_credential(third.id).await.unwrap().is_none());
}

// ─── Password history ───

/// An owner without history reads as revision 0 with nothing in it: the
/// first commit is made against 0.
pub async fn history_is_empty_until_written<H: CredentialHarness>(h: &H) {
    let (owner, _) = owner_with_password(h).await;
    let history = h.store().get_password_history(owner).await.unwrap();
    assert_eq!(history.revision, 0);
    assert!(history.epochs.is_empty() && history.entries.is_empty());
}

/// A rotation the evaluator prepared is published by the commit that uses
/// it: the new epoch becomes the one active epoch, the replaced one stays
/// comparable while it retains an entry and leaves the required set once
/// retention empties it.
pub async fn history_rotation_is_published_by_its_commit<H: CredentialHarness>(h: &H) {
    let (owner, password) = owner_with_password(h).await;
    let old = descriptor(11);
    assert!(
        change(h, owner.clone(), &password, (b"p0", b"p1"), &[old], 0x11, 2)
            .await
            .unwrap()
    );
    let new = descriptor(12);
    assert!(
        change(
            h,
            owner.clone(),
            &password,
            (b"p1", b"p2"),
            &[new, old],
            0x12,
            2
        )
        .await
        .unwrap()
    );
    let rotated = h.store().get_password_history(owner.clone()).await.unwrap();
    assert_eq!(rotated.active_epoch().map(|e| e.id), Some(new.id));
    assert_eq!(
        rotated
            .required_epochs()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![new.id, old.id],
        "the replaced epoch still holds an entry and stays required"
    );
    assert_eq!(
        rotated
            .epochs
            .iter()
            .find(|e| e.id == old.id)
            .map(|e| e.status),
        Some(HistoryEpochUse::CompareOnly)
    );
    // Depth 1: the next commit's retention removes the old epoch's entry.
    assert!(
        change(
            h,
            owner.clone(),
            &password,
            (b"p2", b"p3"),
            &[new, old],
            0x13,
            1
        )
        .await
        .unwrap()
    );
    let emptied = h.store().get_password_history(owner).await.unwrap();
    assert_eq!(
        emptied
            .required_epochs()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![new.id],
        "an emptied epoch is no longer required"
    );
}

/// A descriptor once recorded never changes: a commit naming its epoch with
/// another public key, salt or KSF, or naming another owner's epoch, is a
/// conflict and writes nothing, credential included.
pub async fn history_descriptor_conflict_writes_nothing<H: CredentialHarness>(h: &H) {
    let (owner, password) = owner_with_password(h).await;
    let first = descriptor(31);
    assert!(
        change(
            h,
            owner.clone(),
            &password,
            (b"p0", b"p1"),
            &[first],
            0x31,
            3
        )
        .await
        .unwrap()
    );
    for tamper in [
        |d: &mut HistoryEpochDescriptor| d.public_key[0] ^= 1,
        |d: &mut HistoryEpochDescriptor| d.ksf_salt[0] ^= 1,
        |d: &mut HistoryEpochDescriptor| d.ksf.passes += 1,
    ] {
        let mut other = first;
        tamper(&mut other);
        let err = change(
            h,
            owner.clone(),
            &password,
            (b"p1", b"p2"),
            &[other],
            0x32,
            3,
        )
        .await
        .expect_err("a conflicting descriptor");
        assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    }
    let (stranger, theirs) = owner_with_password(h).await;
    let foreign = descriptor(33);
    assert!(
        change(h, stranger, &theirs, (b"p0", b"p1"), &[foreign], 0x33, 3)
            .await
            .unwrap()
    );
    let err = change(
        h,
        owner.clone(),
        &password,
        (b"p1", b"p2"),
        &[foreign],
        0x34,
        3,
    )
    .await
    .expect_err("another owner's epoch");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    let stored = h
        .store()
        .get_credential(password.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.data.expose(),
        b"p1",
        "the refused changes kept the password"
    );
    let history = h.store().get_password_history(owner).await.unwrap();
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.epochs.len(), 1);
    assert_eq!(history.epochs[0].descriptor(), first);
}

/// A change whose history read is stale writes nothing, credential
/// included; the one made against the current revision applies. Of two
/// concurrent changes from one revision exactly one applies.
pub async fn history_commit_is_compare_and_swap<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let (owner, password) = owner_with_password(h).await;
    let epoch = descriptor(6);
    let read = store.get_password_history(owner.clone()).await.unwrap();

    let stale = commit(owner.clone(), read.revision + 1, &[epoch], 1, 3);
    assert!(
        !store
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&stale),
                ctx()
            )
            .await
            .unwrap()
    );
    let stored = store.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(
        stored.data.expose(),
        b"p0",
        "a refused history kept the password"
    );
    let empty = store.get_password_history(owner.clone()).await.unwrap();
    assert!(empty.entries.is_empty() && empty.epochs.is_empty());

    let current = commit(owner.clone(), read.revision, &[epoch], 1, 3);
    assert!(
        store
            .change_password(
                password.id,
                b"p0",
                &next(&password, b"p1"),
                Some(&current),
                ctx()
            )
            .await
            .unwrap()
    );
    let after = store.get_password_history(owner.clone()).await.unwrap();
    assert_eq!(after.revision, read.revision + 1);
    assert_eq!(after.entries.len(), 1);
    assert_eq!(after.entries[0].evidence, current.evidence);

    // Two changes from the same credential state and history revision.
    let (to_a, to_b) = (next(&password, b"a"), next(&password, b"b"));
    let (ca, cb) = (
        commit(owner.clone(), after.revision, &[epoch], 2, 3),
        commit(owner.clone(), after.revision, &[epoch], 3, 3),
    );
    let (a, b) = tokio::join!(
        store.change_password(password.id, b"p1", &to_a, Some(&ca), ctx()),
        store.change_password(password.id, b"p1", &to_b, Some(&cb), ctx()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one concurrent change applies: {a} {b}");
    let history = store.get_password_history(owner).await.unwrap();
    assert_eq!(history.entries.len(), 2);
    let winner = if a { [2u8; 32] } else { [3u8; 32] };
    assert_eq!(history.entries[0].entry, winner, "newest first");
}

/// Retention keeps the newest `depth` accepted passwords: five changes with
/// depth 3 leave the last three, newest first.
pub async fn history_retains_depth<H: CredentialHarness>(h: &H) {
    let (owner, password) = owner_with_password(h).await;
    let epoch = descriptor(7);
    let mut current = b"p0".to_vec();
    for i in 1..=5u8 {
        let data = vec![b'p', b'0' + i];
        assert!(
            change(
                h,
                owner.clone(),
                &password,
                (&current, &data),
                &[epoch],
                i,
                3
            )
            .await
            .unwrap()
        );
        current = data;
    }
    let entries: Vec<[u8; 32]> = h
        .store()
        .get_password_history(owner)
        .await
        .unwrap()
        .entries
        .iter()
        .map(|e| e.entry)
        .collect();
    assert_eq!(entries, vec![[5u8; 32], [4u8; 32], [3u8; 32]]);
}

/// History is written only for the credential's own owner.
pub async fn history_of_another_owner_is_refused<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let (owner, password) = owner_with_password(h).await;
    let (other, _) = owner_with_password(h).await;
    let revision = store
        .get_password_history(other.clone())
        .await
        .unwrap()
        .revision;
    let err = store
        .change_password(
            password.id,
            b"p0",
            &next(&password, b"p1"),
            Some(&commit(other, revision, &[descriptor(10)], 1, 1)),
            ctx(),
        )
        .await
        .expect_err("another owner's history");
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        store
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"p0"
    );
    assert!(
        store
            .get_password_history(owner)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
}

/// The history write cutoff fences commits in the owning transaction: an
/// entry under an epoch created before it is refused with the whole change
/// (credential and history) left as it was; a commit made before the cutoff
/// stays; a stale selection cannot make a barred epoch active again;
/// comparison epochs named after the written one are not barred; the cutoff
/// only rises, and a repeated raise is a no-op. Raises the store-wide cutoff.
pub async fn history_write_cutoff_fences_commits<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let at = |offset_ms: i64| micros_now() + chrono::Duration::milliseconds(offset_ms);
    let created = |key: u8, created_at| HistoryEpochDescriptor {
        created_at,
        ..descriptor(key)
    };
    let (owner, password) = owner_with_password(h).await;
    let old = created(61, at(-60_000));
    // Committed before the cutoff: it stays.
    assert!(
        change(h, owner.clone(), &password, (b"p0", b"p1"), &[old], 0x61, 3)
            .await
            .unwrap()
    );
    let cutoff = at(-30_000);
    assert_eq!(
        store
            .raise_history_write_cutoff(cutoff, ctx())
            .await
            .unwrap(),
        cutoff
    );
    // Lost acknowledgement: the same raise again, and an older one, change
    // nothing and report the cutoff in force.
    assert_eq!(
        store
            .raise_history_write_cutoff(cutoff, ctx())
            .await
            .unwrap(),
        cutoff
    );
    assert_eq!(
        store
            .raise_history_write_cutoff(at(-90_000), ctx())
            .await
            .unwrap(),
        cutoff
    );
    // The recorded cutoff reads back as the one in force.
    assert_eq!(store.history_write_cutoff().await.unwrap(), Some(cutoff));
    let before = store.get_password_history(owner.clone()).await.unwrap();

    let err = change(h, owner.clone(), &password, (b"p1", b"p2"), &[old], 0x62, 3)
        .await
        .expect_err("an entry under a barred epoch");
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    assert_eq!(
        store
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"p1",
        "the whole change was refused"
    );
    assert_eq!(
        store.get_password_history(owner.clone()).await.unwrap(),
        before
    );

    // Under an epoch created after the cutoff, comparing with the barred
    // one, the change applies.
    let new = created(63, at(0));
    assert!(
        change(
            h,
            owner.clone(),
            &password,
            (b"p1", b"p2"),
            &[new, old],
            0x63,
            3
        )
        .await
        .unwrap()
    );
    // A stale selection naming the barred epoch first cannot make it active
    // again.
    let err = change(
        h,
        owner.clone(),
        &password,
        (b"p2", b"p3"),
        &[old, new],
        0x64,
        3,
    )
    .await
    .expect_err("reactivating a barred epoch");
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    let history = store.get_password_history(owner).await.unwrap();
    assert_eq!(history.active_epoch().map(|e| e.id), Some(new.id));
}

/// A raise of the cutoff and a commit racing it are serialized: the commit
/// either applied before the cutoff (and stays) or was refused whole; the
/// cutoff is in force either way. Raises the store-wide cutoff.
pub async fn history_write_cutoff_races_a_commit<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let (owner, password) = owner_with_password(h).await;
    let epoch = HistoryEpochDescriptor {
        created_at: micros_now() - chrono::Duration::minutes(1),
        ..descriptor(71)
    };
    let cutoff = micros_now();
    let selection = [epoch];
    let (changed, raised) = tokio::join!(
        change(
            h,
            owner.clone(),
            &password,
            (b"p0", b"p1"),
            &selection,
            0x71,
            3
        ),
        store.raise_history_write_cutoff(cutoff, ctx()),
    );
    assert!(raised.unwrap() >= cutoff);
    let stored = store.get_credential(password.id).await.unwrap().unwrap();
    let history = store.get_password_history(owner.clone()).await.unwrap();
    match changed {
        Ok(true) => {
            assert_eq!(stored.data.expose(), b"p1");
            assert_eq!(history.entries.len(), 1);
        }
        Err(Error::Fenced(_)) => {
            assert_eq!(stored.data.expose(), b"p0");
            assert!(history.entries.is_empty() && history.epochs.is_empty());
        }
        other => panic!("{other:?}"),
    }
    // After the raise no commit under the epoch applies.
    let err = change(
        h,
        owner,
        &password,
        (stored.data.expose(), b"p2"),
        &[epoch],
        0x72,
        3,
    )
    .await
    .expect_err("after the cutoff");
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
}

// ─── WebAuthn user handles ───

/// A relying party of this scenario alone, so runs sharing a database never
/// meet.
fn rp() -> String {
    format!("{}.sid.example.com", Uuid::now_v7().simple())
}

fn handle(byte: u8) -> WebAuthnUserHandle {
    let mut bytes = *Uuid::now_v7().as_bytes();
    bytes[0] = byte;
    WebAuthnUserHandle(bytes)
}

/// The first enrollment stores its candidate; every later one, with any
/// candidate, gets that same handle back: an account keeps one handle for
/// all its passkeys at a relying party.
pub async fn user_handle_is_created_once<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let rp = rp();
    let first = handle(1);
    let stored = store
        .ensure_webauthn_user_handle(owner.clone(), &rp, first, ctx())
        .await
        .unwrap();
    assert_eq!(stored, first);
    let again = store
        .ensure_webauthn_user_handle(owner, &rp, handle(2), ctx())
        .await
        .unwrap();
    assert_eq!(again, first, "a stored handle is never replaced");
}

/// Concurrent first enrollments of one account agree on one stored handle.
pub async fn concurrent_enrollments_agree_on_one_handle<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let rp = rp();
    let (a, b) = (handle(3), handle(4));
    let (ra, rb) = tokio::join!(
        store.ensure_webauthn_user_handle(owner.clone(), &rp, a, ctx()),
        store.ensure_webauthn_user_handle(owner.clone(), &rp, b, ctx()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra, rb, "concurrent enrollments agree on one handle");
    assert!(ra == a || ra == b);
    assert_eq!(
        store
            .get_profile_by_webauthn_user_handle(&rp, ra)
            .await
            .unwrap(),
        Some(owner)
    );
    let loser = if ra == a { b } else { a };
    assert_eq!(
        store
            .get_profile_by_webauthn_user_handle(&rp, loser)
            .await
            .unwrap(),
        None,
        "the losing candidate names nobody"
    );
}

/// A handle names its account only at its own relying party; an unknown
/// handle names nobody.
pub async fn user_handle_resolves_only_at_its_rp<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let owner = h.owner().await;
    let (rp, other_rp) = (rp(), rp());
    let stored = store
        .ensure_webauthn_user_handle(owner.clone(), &rp, handle(5), ctx())
        .await
        .unwrap();
    assert_eq!(
        store
            .get_profile_by_webauthn_user_handle(&rp, stored)
            .await
            .unwrap(),
        Some(owner.clone())
    );
    assert_eq!(
        store
            .get_profile_by_webauthn_user_handle(&other_rp, stored)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_profile_by_webauthn_user_handle(&rp, handle(6))
            .await
            .unwrap(),
        None
    );

    // The same account has an independent handle at another relying party.
    let elsewhere = store
        .ensure_webauthn_user_handle(owner, &other_rp, handle(7), ctx())
        .await
        .unwrap();
    assert_ne!(elsewhere, stored);
}

/// Two accounts cannot share a handle at one relying party: the second is
/// refused and keeps none, so one handle never names two accounts.
pub async fn user_handle_is_unique_per_rp<H: CredentialHarness>(h: &H) {
    let store = h.store();
    let (first, second) = (h.owner().await, h.owner().await);
    let rp = rp();
    let shared = handle(8);
    store
        .ensure_webauthn_user_handle(first.clone(), &rp, shared, ctx())
        .await
        .unwrap();
    let refused = store
        .ensure_webauthn_user_handle(second, &rp, shared, ctx())
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::Conflict(_)), "got {refused:?}");
    assert_eq!(
        store
            .get_profile_by_webauthn_user_handle(&rp, shared)
            .await
            .unwrap(),
        Some(first)
    );
}

/// An account that does not exist gets no handle.
pub async fn user_handle_needs_an_owner<H: CredentialHarness>(h: &H) {
    let refused = h
        .store()
        .ensure_webauthn_user_handle(h.missing_owner(), &rp(), handle(9), ctx())
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::NotFound(_)), "got {refused:?}");
}
