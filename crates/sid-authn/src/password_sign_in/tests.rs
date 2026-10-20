// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_core::models::{CredentialRevocation, Profile, ProfileId};
use sid_opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters,
};
use sid_plugin::cache::{CacheBackend, InMemoryCacheBackend};
use sid_plugin::{CurveId, OpaqueOperations, StorageBackend};
use sid_storage::sqlite::SqliteBackend;

use super::*;
use crate::opaque::{DefaultCipherSuite, RistrettoOpaque};
use crate::test_support::key_manager;

const PASSWORD: &[u8] = b"correct horse battery staple";

#[derive(Debug)]
enum HostError {
    SignIn(PasswordSignInError),
    Locked,
}

impl From<PasswordSignInError> for HostError {
    fn from(e: PasswordSignInError) -> Self {
        Self::SignIn(e)
    }
}

/// A host over an in-memory SQLite store: principals map to Profiles,
/// lockout and failures are recorded in memory.
struct Host {
    store: SqliteBackend,
    router: OpaqueRouter,
    pending: ChallengeStore<PendingSignIn<ProfileId>>,
    principals: Mutex<HashMap<String, ProfileId>>,
    locked: Mutex<HashSet<String>>,
    failures: Mutex<Vec<String>>,
    gone: Mutex<HashSet<ProfileId>>,
    /// Opening a password writes it back in this new stored form, as a
    /// reseal under a newer key version does.
    reseal_to: Mutex<Option<Vec<u8>>>,
    /// The shared cache the sign-in states live in.
    cache: Arc<dyn CacheBackend>,
}

#[async_trait]
impl PasswordSignInHost for Host {
    type Owner = ProfileId;
    type Account = ProfileId;
    type Error = HostError;

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        &self.store
    }
    fn opaque(&self) -> &OpaqueRouter {
        &self.router
    }
    fn pending(&self) -> &ChallengeStore<PendingSignIn<ProfileId>> {
        &self.pending
    }
    async fn resolve(&self, principal: &str) -> Result<Option<ProfileId>, HostError> {
        Ok(self.principals.lock().unwrap().get(principal).copied())
    }
    async fn refuse_if_locked(&self, identity: &str) -> Result<(), HostError> {
        if self.locked.lock().unwrap().contains(identity) {
            return Err(HostError::Locked);
        }
        Ok(())
    }
    async fn record_failure(&self, identity: &str) -> Result<(), HostError> {
        self.failures.lock().unwrap().push(identity.to_string());
        Ok(())
    }
    async fn stored_password(
        &self,
        credential: &Credential<ProfileId>,
    ) -> Result<OpenedPassword, HostError> {
        // A stored password here is a version byte and the record: two forms
        // of one record differ in that byte only, as two sealings do.
        let record = StoredCredential {
            curve: CurveId::Ristretto255,
            data: credential.data.expose()[1..].to_vec(),
        };
        let resealed = self.reseal_to.lock().unwrap().take();
        let stored = match resealed {
            Some(resealed) => {
                assert!(
                    self.store
                        .reseal_credential_data(
                            credential.id,
                            credential.data.expose(),
                            &resealed,
                            ctx()
                        )
                        .await
                        .unwrap()
                );
                CredentialData::new(resealed)
            }
            None => credential.data.clone(),
        };
        Ok(OpenedPassword { record, stored })
    }
    fn opaque_credential_identifier(&self, credential: &Credential<ProfileId>) -> [u8; 16] {
        credential.opaque_credential_identifier()
    }
    async fn account(&self, owner: &ProfileId) -> Result<Option<ProfileId>, HostError> {
        Ok((!self.gone.lock().unwrap().contains(owner)).then_some(*owner))
    }
}

async fn host() -> Host {
    let primary = Box::new(RistrettoOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    Host {
        store: SqliteBackend::new_in_memory().await.unwrap(),
        router: OpaqueRouter::new(primary, verifiers, setup),
        pending: ChallengeStore::new(
            cache.clone(),
            key_manager(),
            "sign-in",
            Duration::from_secs(60),
        ),
        principals: Mutex::default(),
        locked: Mutex::default(),
        failures: Mutex::default(),
        gone: Mutex::default(),
        reseal_to: Mutex::default(),
        cache,
    }
}

fn ctx() -> sid_core::models::MutationContext {
    AuditEntry::system("test", "password_sign_in").into()
}

/// A Profile signing in by `principal`, with nothing stored for it yet.
async fn account(h: &Host, principal: &str) -> ProfileId {
    let profile = Profile::new(Some(principal));
    h.store.create_profile(&profile, ctx()).await.unwrap();
    h.principals
        .lock()
        .unwrap()
        .insert(principal.to_string(), profile.id);
    profile.id
}

/// `record`'s stored form under key `version`.
fn sealed(version: u8, record: &[u8]) -> Vec<u8> {
    [&[version][..], record].concat()
}

/// `owner`'s password, registered through the router as a client would.
async fn with_password(h: &Host, owner: ProfileId) -> Credential<ProfileId> {
    let identifier = *uuid::Uuid::now_v7().as_bytes();
    let mut rng = UnwrapErr(SysRng);
    let client = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, PASSWORD).unwrap();
    let (response, _) = h
        .router
        .registration_start(&client.message.serialize(), &identifier)
        .unwrap();
    let upload = client
        .state
        .finish(
            &mut rng,
            PASSWORD,
            sid_opaque_ke::RegistrationResponse::deserialize(&response).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let stored = h
        .router
        .registration_finish(&upload.message.serialize())
        .unwrap();
    let mut password = Credential::new(
        owner,
        CredentialType::Opaque,
        CredentialData::new(sealed(1, &stored.data)),
        None,
    );
    password.opaque_credential_identifier = Some(identifier);
    h.store.create_credential(&password, ctx()).await.unwrap();
    password
}

/// A client's sign-in with `password`: the start, then the finalization
/// the client derives (garbage when the password does not open the record).
async fn sign_in(
    h: &Host,
    principal: &str,
    password: &[u8],
) -> Result<Verified<ProfileId>, HostError> {
    let mut rng = UnwrapErr(SysRng);
    let client = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let started = start(h, principal, &client.message.serialize()).await?;
    let finalization = sid_opaque_ke::CredentialResponse::deserialize(&started.credential_response)
        .ok()
        .and_then(|response| {
            client
                .state
                .finish(
                    &mut rng,
                    password,
                    response,
                    ClientLoginFinishParameters::default(),
                )
                .ok()
        })
        .map_or_else(|| vec![0u8; 64], |f| f.message.serialize().to_vec());
    finish(h, &started.state_key, &finalization).await
}

fn refused(r: Result<Verified<ProfileId>, HostError>) -> HostError {
    r.err().expect("the sign-in was refused")
}

/// A password written back in a new stored form while its sign-in opened it
/// (a reseal under a newer key version) fences the session on that new form,
/// the one the store holds: the first sign-in after a key rotation is not
/// refused.
#[tokio::test]
async fn a_resealed_password_fences_on_its_new_form() {
    let h = host().await;
    let owner = account(&h, "rotated").await;
    let password = with_password(&h, owner).await;
    *h.reseal_to.lock().unwrap() = Some(b"the same record, sealed anew".to_vec());

    let verified = sign_in(&h, "rotated", PASSWORD).await.unwrap();
    let stored = h.store.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(verified.proved_by.id, password.id);
    assert!(
        verified.proved_by.data == stored.data,
        "the fence holds the stored form"
    );
}

/// A state this build cannot read (stored by an earlier build, without the
/// password's stored form) is answered as an expired sign-in, so the client
/// starts again; no session can be fenced on a form it does not carry.
#[tokio::test]
async fn an_unreadable_state_is_an_expired_sign_in() {
    let h = host().await;
    let owner = account(&h, "upgraded").await;
    let password = with_password(&h, owner).await;
    let earlier: ChallengeStore<serde_json::Value> = ChallengeStore::new(
        h.cache.clone(),
        key_manager(),
        "sign-in",
        Duration::from_secs(60),
    );
    earlier
        .insert(
            "earlier-state",
            &serde_json::json!({ "Password": {
                "state": LoginState(vec![1]),
                "profile_id": owner,
                "credential_id": password.id,
            }}),
        )
        .await
        .unwrap();

    let e = refused(finish(&h, "earlier-state", &[0u8; 64]).await);
    assert!(
        matches!(e, HostError::SignIn(PasswordSignInError::Expired)),
        "{e:?}"
    );
}

/// Another reader reseals the password after this sign-in started (the same
/// record in a new stored form): the sign-in still succeeds and fences its
/// session on the form the store holds now. A password changed after the
/// start keeps the form the start read, which the store no longer holds.
#[tokio::test]
async fn a_password_resealed_after_the_start_fences_on_the_new_form() {
    for change in [false, true] {
        let h = host().await;
        let principal = format!("resealed-{change}");
        let owner = account(&h, &principal).await;
        let password = with_password(&h, owner).await;

        let mut rng = UnwrapErr(SysRng);
        let client = ClientLogin::<DefaultCipherSuite>::start(&mut rng, PASSWORD).unwrap();
        let started = start(&h, &principal, &client.message.serialize())
            .await
            .unwrap();
        let finalization = client
            .state
            .finish(
                &mut rng,
                PASSWORD,
                sid_opaque_ke::CredentialResponse::deserialize(&started.credential_response)
                    .unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .unwrap()
            .message
            .serialize()
            .to_vec();

        let record = &password.data.expose()[1..];
        let rewritten = if change {
            sealed(2, b"another record")
        } else {
            sealed(2, record)
        };
        assert!(
            h.store
                .reseal_credential_data(password.id, password.data.expose(), &rewritten, ctx())
                .await
                .unwrap()
        );

        let verified = finish(&h, &started.state_key, &finalization).await.unwrap();
        let stored = h.store.get_credential(password.id).await.unwrap().unwrap();
        if change {
            assert!(verified.proved_by.data == password.data, "the form read");
            assert!(verified.proved_by.data != stored.data);
        } else {
            assert!(verified.proved_by.data == stored.data, "the store's form");
        }
    }
}

/// The right password signs its account in and marks the password used.
#[tokio::test]
async fn right_password_signs_in() {
    let h = host().await;
    let owner = account(&h, "alice").await;
    let password = with_password(&h, owner).await;

    let verified = sign_in(&h, "alice", PASSWORD).await.unwrap();
    assert_eq!(verified.account, owner);
    // The session it creates is fenced on the password exactly as read.
    assert_eq!(verified.proved_by.id, password.id);
    assert_eq!(verified.proved_by.data, password.data);
    let stored = h.store.get_credential(password.id).await.unwrap().unwrap();
    assert!(
        stored.last_used_at.is_some(),
        "the password was not marked used"
    );
    assert!(h.failures.lock().unwrap().is_empty());
}

/// A wrong password is refused and counted against the account.
#[tokio::test]
async fn wrong_password_counts_against_the_account() {
    let h = host().await;
    let owner = account(&h, "bob").await;
    with_password(&h, owner).await;

    let e = refused(sign_in(&h, "bob", b"wrong password").await);
    assert!(
        matches!(
            e,
            HostError::SignIn(PasswordSignInError::AuthenticationFailed)
        ),
        "{e:?}"
    );
    assert_eq!(*h.failures.lock().unwrap(), vec![owner.to_string()]);
}

/// An unknown principal gets a decoy answered like a real start; the finish
/// is refused and counted against the principal.
#[tokio::test]
async fn unknown_principal_gets_a_decoy() {
    let h = host().await;
    let e = refused(sign_in(&h, "nobody", PASSWORD).await);
    assert!(
        matches!(
            e,
            HostError::SignIn(PasswordSignInError::AuthenticationFailed)
        ),
        "{e:?}"
    );
    assert_eq!(*h.failures.lock().unwrap(), vec!["nobody".to_string()]);
}

/// An account without a password is answered like an unknown principal,
/// its failure counted against the account.
#[tokio::test]
async fn account_without_password_gets_a_decoy() {
    let h = host().await;
    let owner = account(&h, "carol").await;
    let passkey = Credential::new(owner, CredentialType::WebAuthn, vec![1], None);
    h.store.create_credential(&passkey, ctx()).await.unwrap();

    let e = refused(sign_in(&h, "carol", PASSWORD).await);
    assert!(
        matches!(
            e,
            HostError::SignIn(PasswordSignInError::AuthenticationFailed)
        ),
        "{e:?}"
    );
    assert_eq!(*h.failures.lock().unwrap(), vec![owner.to_string()]);
}

/// An account holding only an imported password hash is sent to migration.
#[tokio::test]
async fn imported_hash_requires_migration() {
    let h = host().await;
    let owner = account(&h, "dave").await;
    let imported = Credential::new(owner, CredentialType::LegacyHash, vec![2], None);
    h.store.create_credential(&imported, ctx()).await.unwrap();

    let e = refused(sign_in(&h, "dave", PASSWORD).await);
    assert!(
        matches!(e, HostError::SignIn(PasswordSignInError::MigrationRequired)),
        "{e:?}"
    );
}

/// A lockout refuses the start, and a finish whose start preceded it.
#[tokio::test]
async fn lockout_refuses_start_and_finish() {
    let h = host().await;
    let owner = account(&h, "erin").await;
    with_password(&h, owner).await;
    h.locked.lock().unwrap().insert(owner.to_string());
    assert!(matches!(
        refused(sign_in(&h, "erin", PASSWORD).await),
        HostError::Locked
    ));

    h.locked.lock().unwrap().clear();
    let mut rng = UnwrapErr(SysRng);
    let client = ClientLogin::<DefaultCipherSuite>::start(&mut rng, PASSWORD).unwrap();
    let started = start(&h, "erin", &client.message.serialize())
        .await
        .unwrap();
    h.locked.lock().unwrap().insert(owner.to_string());
    let e = finish(&h, &started.state_key, &[0u8; 64])
        .await
        .err()
        .unwrap();
    assert!(matches!(e, HostError::Locked), "{e:?}");
    assert!(
        h.failures.lock().unwrap().is_empty(),
        "a locked attempt was counted"
    );
}

/// A started sign-in finishes once: a second finish finds it expired.
#[tokio::test]
async fn state_is_taken_once() {
    let h = host().await;
    let owner = account(&h, "frank").await;
    with_password(&h, owner).await;
    let mut rng = UnwrapErr(SysRng);
    let client = ClientLogin::<DefaultCipherSuite>::start(&mut rng, PASSWORD).unwrap();
    let started = start(&h, "frank", &client.message.serialize())
        .await
        .unwrap();
    let response =
        sid_opaque_ke::CredentialResponse::deserialize(&started.credential_response).unwrap();
    let finalization = client
        .state
        .finish(
            &mut rng,
            PASSWORD,
            response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap()
        .message
        .serialize()
        .to_vec();

    finish(&h, &started.state_key, &finalization).await.unwrap();
    let e = finish(&h, &started.state_key, &finalization)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(e, HostError::SignIn(PasswordSignInError::Expired)),
        "{e:?}"
    );
}

/// A password revoked while the sign-in was in flight neither signs in nor
/// comes back to active.
#[tokio::test]
async fn password_revoked_in_flight_signs_nobody_in() {
    let h = host().await;
    let owner = account(&h, "grace").await;
    let password = with_password(&h, owner).await;
    let passkey = Credential::new(owner, CredentialType::WebAuthn, vec![3], None);
    h.store.create_credential(&passkey, ctx()).await.unwrap();

    let mut rng = UnwrapErr(SysRng);
    let client = ClientLogin::<DefaultCipherSuite>::start(&mut rng, PASSWORD).unwrap();
    let started = start(&h, "grace", &client.message.serialize())
        .await
        .unwrap();
    assert_eq!(
        h.store.revoke_credential(password.id, ctx()).await.unwrap(),
        CredentialRevocation::Revoked
    );
    let response =
        sid_opaque_ke::CredentialResponse::deserialize(&started.credential_response).unwrap();
    let finalization = client
        .state
        .finish(
            &mut rng,
            PASSWORD,
            response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap()
        .message
        .serialize()
        .to_vec();

    let e = finish(&h, &started.state_key, &finalization)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            e,
            HostError::SignIn(PasswordSignInError::AuthenticationFailed)
        ),
        "{e:?}"
    );
    let stored = h.store.get_credential(password.id).await.unwrap().unwrap();
    assert!(!stored.status.is_active());
}

/// An account that can no longer sign in when the password is verified
/// signs nobody in, and its password is not marked used.
#[tokio::test]
async fn account_gone_in_flight_signs_nobody_in() {
    let h = host().await;
    let owner = account(&h, "heidi").await;
    let password = with_password(&h, owner).await;
    h.gone.lock().unwrap().insert(owner);

    let e = refused(sign_in(&h, "heidi", PASSWORD).await);
    assert!(
        matches!(
            e,
            HostError::SignIn(PasswordSignInError::AuthenticationFailed)
        ),
        "{e:?}"
    );
    let stored = h.store.get_credential(password.id).await.unwrap().unwrap();
    assert!(stored.last_used_at.is_none());
}

/// A password state is stored under the tag `PasswordFenced`: a build that
/// does not fence its session (it knows only `Password`) cannot read it and
/// so cannot finish it unfenced. The owner keeps its field name `profile_id`.
#[test]
fn a_fenced_state_is_unreadable_to_an_unfenced_build() {
    let json = serde_json::to_value(PendingSignIn::Password {
        state: LoginState(vec![1]),
        owner: ProfileId::generate(),
        credential_id: CredentialId::new(),
        credential_data: sid_core::models::CredentialData::new(vec![2]),
    })
    .unwrap();
    assert!(json.get("Password").is_none(), "{json}");
    assert!(json["PasswordFenced"].get("credential_data").is_some());
    // A decoy moves with it: across builds a real and a decoy state answer
    // alike, so the answer does not tell whether the account exists.
    let decoy = serde_json::to_value(PendingSignIn::<ProfileId>::Decoy {
        identity: "nobody".into(),
    })
    .unwrap();
    assert!(decoy.get("Decoy").is_none(), "{decoy}");
    assert!(decoy.get("DecoyFenced").is_some(), "{decoy}");
}

/// A decoy state stored by an earlier build is answered like an earlier
/// build's password state: an expired sign-in.
#[tokio::test]
async fn an_earlier_decoy_state_is_an_expired_sign_in() {
    let h = host().await;
    let earlier: ChallengeStore<serde_json::Value> = ChallengeStore::new(
        h.cache.clone(),
        key_manager(),
        "sign-in",
        Duration::from_secs(60),
    );
    earlier
        .insert(
            "earlier-decoy",
            &serde_json::json!({ "Decoy": { "identity": "nobody" } }),
        )
        .await
        .unwrap();
    let e = refused(finish(&h, "earlier-decoy", &[0u8; 64]).await);
    assert!(
        matches!(e, HostError::SignIn(PasswordSignInError::Expired)),
        "{e:?}"
    );
}

/// The stored state names the owner `profile_id`, the field name its states
/// have always carried.
#[test]
fn stored_state_names_the_owner_profile_id() {
    let owner = ProfileId::generate();
    let json = serde_json::to_value(PendingSignIn::Password {
        state: LoginState(vec![1]),
        owner,
        credential_id: CredentialId::new(),
        credential_data: sid_core::models::CredentialData::new(vec![2]),
    })
    .unwrap();
    assert_eq!(
        json["PasswordFenced"]["profile_id"],
        serde_json::json!(owner)
    );
}
