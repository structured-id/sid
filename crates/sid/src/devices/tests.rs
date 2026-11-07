use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sid_authn::device_key_proof::DEVICE_KEY_PROOF_TYPE;
use sid_core::models::{OperationKey, Session};

use super::*;
use crate::test_support::{keys, storage, stored_profile};

const ISSUER: &str = "https://sid.example.com";

/// An authority that allows other objects only when told to, and records
/// what it was asked.
#[derive(Default)]
struct TestAccess {
    allow_others: bool,
    owner_calls: usize,
    asked: Vec<String>,
}

#[derive(Debug, PartialEq)]
struct Refused;

#[async_trait::async_trait]
impl DeviceAccess for TestAccess {
    type Error = Refused;

    async fn owner(&mut self) -> Result<(), Refused> {
        self.owner_calls += 1;
        Ok(())
    }

    async fn may(&mut self, object: &str) -> Result<bool, Refused> {
        self.asked.push(object.to_string());
        Ok(self.allow_others)
    }

    async fn require(&mut self, object: &str) -> Result<(), Refused> {
        self.asked.push(object.to_string());
        if self.allow_others {
            Ok(())
        } else {
            Err(Refused)
        }
    }
}

/// A device's signing key and its public JWK.
struct Key {
    alg: Algorithm,
    private: EncodingKey,
    jwk: serde_json::Value,
}

impl Key {
    fn thumbprint(&self) -> String {
        stored_key_thumbprint(&self.jwk.to_string()).unwrap()
    }
}

fn ec_key() -> Key {
    Key {
        alg: Algorithm::ES256,
        private: EncodingKey::from_ec_pem(include_bytes!(
            "../../../sid-authn/tests/fixtures/test_es256_private.pem"
        ))
        .unwrap(),
        jwk: serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
            "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
        }),
    }
}

fn ed_key() -> Key {
    // The raw 32-byte public key is the end of the SPKI DER.
    let pem = include_str!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem");
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(body).unwrap();
    Key {
        alg: Algorithm::EdDSA,
        private: EncodingKey::from_ed_pem(include_bytes!(
            "../../../sid-authn/tests/fixtures/test_ed25519_private.pem"
        ))
        .unwrap(),
        jwk: serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..]),
        }),
    }
}

/// A device-key proof by `signer` over `challenge` for `purpose`, naming
/// `key` as the proposed key.
fn proof(signer: &Key, challenge: &DeviceEnrollmentChallenge, purpose: &str, key: &str) -> String {
    let mut header = Header::new(signer.alg);
    header.typ = Some(DEVICE_KEY_PROOF_TYPE.to_string());
    header.jwk = Some(serde_json::from_value(signer.jwk.clone()).unwrap());
    let device: DeviceId = wire_id(challenge.device_id.as_ref(), "device_id").unwrap();
    let claims = serde_json::json!({
        "chl": URL_SAFE_NO_PAD.encode(&challenge.challenge),
        "purpose": purpose,
        "iss": ISSUER,
        "dev": device.to_string(),
        "key": key,
    });
    encode(&header, &claims, &signer.private).unwrap()
}

struct Fixture {
    keys: DeviceKeys,
    storage: Arc<dyn StorageBackend>,
    profile: ProfileId,
    caller: KeyCaller,
    /// The owner's device without a key.
    device: DeviceId,
}

/// A fresh, sufficient sign-in of `profile`.
async fn signed_in(storage: &dyn StorageBackend, profile: ProfileId) -> KeyCaller {
    let session = Session::new(profile, None, Utc::now() + chrono::Duration::hours(1));
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    KeyCaller {
        profile: Some(profile),
        session: Some(session.id),
        subject: profile.to_string(),
        interactive: true,
    }
}

async fn fixture() -> Fixture {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let profile = stored_profile(storage.as_ref(), "alice").await;
    let device = Device::new(profile, DeviceType::Mobile);
    storage
        .create_device(&device, AuditEntry::system("test", "device").into())
        .await
        .unwrap();
    Fixture {
        keys: DeviceKeys::new(storage.clone(), keys()),
        caller: signed_in(storage.as_ref(), profile).await,
        storage,
        profile,
        device: device.id,
    }
}

/// A fresh operation context of the caller's next keyed call.
async fn operation(storage: &dyn StorageBackend, key: &str) -> Option<OperationContext> {
    let period = storage
        .current_operation_period(Utc::now(), chrono::Duration::hours(1))
        .await
        .unwrap()
        .period;
    Some(OperationContext::new(
        OperationKey::parse(key).unwrap(),
        period,
    ))
}

fn start(
    purpose: DeviceEnrollmentPurpose,
    device: Option<DeviceId>,
) -> StartDeviceEnrollmentRequest {
    StartDeviceEnrollmentRequest {
        purpose: purpose as i32,
        device_id: device.map(Into::into),
        device_type: sid_proto::sid::v1::identity::DeviceType::Desktop as i32,
        display_name: Some("Laptop".into()),
        ..Default::default()
    }
}

fn finish(challenge: &DeviceEnrollmentChallenge, proof: String) -> FinishDeviceEnrollmentRequest {
    FinishDeviceEnrollmentRequest {
        enrollment_id: challenge.enrollment_id.clone(),
        proof,
        format: v1::AttestationFormat::Packed as i32,
        key_storage: v1::KeyStorageType::SecureEnclave as i32,
        attestation_object: Some(vec![0xA1, 0x01]),
        ..Default::default()
    }
}

impl Fixture {
    async fn start(
        &self,
        access: &mut TestAccess,
        purpose: DeviceEnrollmentPurpose,
        device: Option<DeviceId>,
    ) -> DeviceEnrollmentChallenge {
        self.keys
            .start_enrollment(access, &self.caller, ISSUER, start(purpose, device))
            .await
            .unwrap()
    }

    /// Enroll `key` on the owner's keyless device.
    async fn enroll(&self, key: &Key) -> v1::DeviceAttestation {
        let mut access = TestAccess::default();
        let challenge = self
            .start(
                &mut access,
                DeviceEnrollmentPurpose::Enroll,
                Some(self.device),
            )
            .await;
        let jws = proof(key, &challenge, "enroll", &key.thumbprint());
        self.keys
            .finish_enrollment(
                &mut access,
                &self.caller,
                operation(self.storage.as_ref(), "enroll").await,
                finish(&challenge, jws),
            )
            .await
            .unwrap()
    }

    async fn attestation(&self) -> Option<DeviceAttestation> {
        self.storage
            .get_device_attestation_by_device_id(self.device)
            .await
            .unwrap()
    }
}

// A new device is enrolled by its ceremony: the device appears only at the
// finish, with the proven key as its binding. A claimed secure-enclave key
// with an attestation object CE does not verify stays unverified and does
// not mark the device hardware-attested.
#[tokio::test]
async fn a_new_device_is_enrolled_by_its_ceremony() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, None)
        .await;
    let device: DeviceId = wire_id(challenge.device_id.as_ref(), "device_id").unwrap();
    assert!(f.storage.get_device(device).await.unwrap().is_none());

    let key = ec_key();
    let jws = proof(&key, &challenge, "enroll", &key.thumbprint());
    let enrolled = f
        .keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-new").await,
            finish(&challenge, jws),
        )
        .await
        .unwrap();

    let stored = f.storage.get_device(device).await.unwrap().unwrap();
    assert_eq!(stored.profile_id, f.profile);
    assert_eq!(stored.display_name.as_deref(), Some("Laptop"));
    assert!(!stored.hardware_attested);
    assert_eq!(
        stored_key_thumbprint(&enrolled.public_jwk).unwrap(),
        key.thumbprint()
    );
    assert_ne!(enrolled.status, v1::AttestationStatus::Verified as i32);
    // The owner's calls never asked the authority about another object.
    assert!(access.asked.is_empty());
}

// A retry of a committed finish (its response lost) answers with the
// recorded outcome and commits nothing again, even though the ceremony is
// consumed.
#[tokio::test]
async fn a_retried_finish_answers_its_recorded_outcome() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let key = ec_key();
    let req = finish(
        &challenge,
        proof(&key, &challenge, "enroll", &key.thumbprint()),
    );
    let context = operation(f.storage.as_ref(), "k-retry").await;

    let first = f
        .keys
        .finish_enrollment(&mut access, &f.caller, context.clone(), req.clone())
        .await
        .unwrap();
    let retried = f
        .keys
        .finish_enrollment(&mut access, &f.caller, context, req.clone())
        .await
        .unwrap();
    assert_eq!(retried, first);

    // Another operation over the consumed ceremony completes nothing.
    let other = f
        .keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-other").await,
            req,
        )
        .await;
    assert!(matches!(other, Err(DeviceKeyError::CeremonyExpired)));
}

// Two finishes of one ceremony race: exactly one binds the key, the other
// finds the ceremony consumed.
#[tokio::test]
async fn concurrent_finishes_bind_once() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let key = ec_key();
    let req = finish(
        &challenge,
        proof(&key, &challenge, "enroll", &key.thumbprint()),
    );
    let (a, b) = (
        operation(f.storage.as_ref(), "k-a").await,
        operation(f.storage.as_ref(), "k-b").await,
    );
    let (mut first, mut second) = (TestAccess::default(), TestAccess::default());

    let (a, b) = tokio::join!(
        f.keys
            .finish_enrollment(&mut first, &f.caller, a, req.clone()),
        f.keys.finish_enrollment(&mut second, &f.caller, b, req),
    );

    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let refused = a.err().or(b.err()).unwrap();
    assert!(matches!(
        refused,
        DeviceKeyError::CeremonyExpired | DeviceKeyError::Changed
    ));
}

// A device with a live key is not enrolled again: its key is rotated.
#[tokio::test]
async fn a_live_key_is_not_enrolled_twice() {
    let f = fixture().await;
    f.enroll(&ec_key()).await;
    let mut access = TestAccess::default();

    let again = f
        .keys
        .start_enrollment(
            &mut access,
            &f.caller,
            ISSUER,
            start(DeviceEnrollmentPurpose::Enroll, Some(f.device)),
        )
        .await;

    assert!(matches!(again, Err(DeviceKeyError::AlreadyEnrolled(d)) if d == f.device));
}

// Another Profile's device is not found by a ceremony, as an unknown one,
// and the authority is not asked about it.
#[tokio::test]
async fn another_profiles_device_is_not_found() {
    let f = fixture().await;
    let stranger_profile = stored_profile(f.storage.as_ref(), "mallory").await;
    let stranger = signed_in(f.storage.as_ref(), stranger_profile).await;
    let mut access = TestAccess {
        allow_others: true,
        ..Default::default()
    };

    let refused = f
        .keys
        .start_enrollment(
            &mut access,
            &stranger,
            ISSUER,
            start(DeviceEnrollmentPurpose::Enroll, Some(f.device)),
        )
        .await;

    assert!(matches!(refused, Err(DeviceKeyError::DeviceNotFound(d)) if d == f.device));
    assert!(access.asked.is_empty());
}

// A proof over another challenge, of another purpose or naming another key
// than its signer binds nothing; the ceremony stays pending for its proof.
#[tokio::test]
async fn a_proof_of_another_ceremony_binds_nothing() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let other = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let key = ec_key();
    let refused = [
        proof(&key, &other, "enroll", &key.thumbprint()),
        proof(&key, &challenge, "rotate-new", &key.thumbprint()),
        proof(&key, &challenge, "enroll", &ed_key().thumbprint()),
    ];
    for (n, jws) in refused.into_iter().enumerate() {
        let result = f
            .keys
            .finish_enrollment(
                &mut access,
                &f.caller,
                operation(f.storage.as_ref(), &format!("k-bad-{n}")).await,
                finish(&challenge, jws),
            )
            .await;
        assert!(matches!(result, Err(DeviceKeyError::Proof(_))), "{n}");
    }
    assert!(f.attestation().await.is_none());

    let jws = proof(&key, &challenge, "enroll", &key.thumbprint());
    f.keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-good").await,
            finish(&challenge, jws),
        )
        .await
        .unwrap();
}

// An unknown ceremony, and one started under another session of the same
// Profile, are not pending for this caller.
#[tokio::test]
async fn another_sessions_ceremony_is_not_pending() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let key = ec_key();
    let jws = proof(&key, &challenge, "enroll", &key.thumbprint());
    let other_session = signed_in(f.storage.as_ref(), f.profile).await;

    let refused = f
        .keys
        .finish_enrollment(
            &mut access,
            &other_session,
            operation(f.storage.as_ref(), "k-session").await,
            finish(&challenge, jws.clone()),
        )
        .await;
    assert!(matches!(refused, Err(DeviceKeyError::CeremonyExpired)));

    let unknown = f
        .keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-unknown").await,
            FinishDeviceEnrollmentRequest {
                enrollment_id: Some(DeviceEnrollmentId::generate().into()),
                ..finish(&challenge, jws)
            },
        )
        .await;
    assert!(matches!(unknown, Err(DeviceKeyError::CeremonyExpired)));
}

// A rotation binds the proposed key only with the current key's approval
// of that exact replacement; the old binding is retired.
#[tokio::test]
async fn a_rotation_needs_the_current_keys_approval() {
    let f = fixture().await;
    let (current, proposed) = (ec_key(), ed_key());
    f.enroll(&current).await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Rotate, Some(f.device))
        .await;
    let rotate = |approval: String| RotateDeviceKeyRequest {
        enrollment_id: challenge.enrollment_id.clone(),
        new_key_proof: proof(&proposed, &challenge, "rotate-new", &proposed.thumbprint()),
        current_key_proof: approval,
        ..Default::default()
    };

    // An approval of another replacement, or by the proposed key itself,
    // approves nothing.
    for (n, approval) in [
        proof(
            &current,
            &challenge,
            "rotate-current",
            &current.thumbprint(),
        ),
        proof(
            &proposed,
            &challenge,
            "rotate-current",
            &proposed.thumbprint(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = f
            .keys
            .rotate_key(
                &mut access,
                &f.caller,
                operation(f.storage.as_ref(), &format!("k-sub-{n}")).await,
                rotate(approval),
            )
            .await;
        assert!(matches!(refused, Err(DeviceKeyError::Proof(_))), "{n}");
    }

    let approval = proof(
        &current,
        &challenge,
        "rotate-current",
        &proposed.thumbprint(),
    );
    let rotated = f
        .keys
        .rotate_key(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-rotate").await,
            rotate(approval),
        )
        .await
        .unwrap();
    assert_eq!(
        stored_key_thumbprint(&rotated.public_jwk).unwrap(),
        proposed.thumbprint()
    );
    let live = f.attestation().await.unwrap();
    assert_eq!(
        stored_key_thumbprint(&live.public_jwk).unwrap(),
        proposed.thumbprint()
    );
}

// A revocation between a rotation's start and its finish wins: the finish
// completes nothing and the revoked key is not revived. A retry of an
// enrollment committed before the revocation answers its outcome without
// reviving the key either.
#[tokio::test]
async fn a_revocation_overtakes_a_pending_ceremony() {
    let f = fixture().await;
    let current = ec_key();
    let mut access = TestAccess::default();
    let enroll = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let enroll_req = finish(
        &enroll,
        proof(&current, &enroll, "enroll", &current.thumbprint()),
    );
    let enroll_context = operation(f.storage.as_ref(), "k-enroll").await;
    let enrolled = f
        .keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            enroll_context.clone(),
            enroll_req.clone(),
        )
        .await
        .unwrap();
    let rotation = f
        .start(&mut access, DeviceEnrollmentPurpose::Rotate, Some(f.device))
        .await;

    // The revocation's retry answers as it did, not as a device without a
    // key.
    let revoke = RevokeDeviceKeyRequest {
        device_id: Some(f.device.into()),
    };
    let revoke_context = operation(f.storage.as_ref(), "k-revoke").await;
    for _ in 0..2 {
        f.keys
            .revoke_key(
                &mut access,
                &f.caller,
                revoke_context.clone(),
                revoke.clone(),
            )
            .await
            .unwrap();
    }
    let again = f
        .keys
        .revoke_key(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-revoke-again").await,
            revoke,
        )
        .await;
    assert!(matches!(again, Err(DeviceKeyError::NoAttestation(d)) if d == f.device));

    let proposed = ed_key();
    let late = f
        .keys
        .rotate_key(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-late").await,
            RotateDeviceKeyRequest {
                enrollment_id: rotation.enrollment_id.clone(),
                new_key_proof: proof(&proposed, &rotation, "rotate-new", &proposed.thumbprint()),
                current_key_proof: proof(
                    &current,
                    &rotation,
                    "rotate-current",
                    &proposed.thumbprint(),
                ),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(late, Err(DeviceKeyError::Changed)));

    let retried = f
        .keys
        .finish_enrollment(&mut access, &f.caller, enroll_context, enroll_req)
        .await
        .unwrap();
    assert_eq!(retried, enrolled);
    let stored = f.attestation().await;
    assert!(stored.is_none_or(|a| a.status == AttestationStatus::Revoked));

    // The revoked device is enrolled again only by a new ceremony.
    f.enroll(&proposed).await;
    let live = f.attestation().await.unwrap();
    assert_eq!(
        stored_key_thumbprint(&live.public_jwk).unwrap(),
        proposed.thumbprint()
    );
}

// Only the owner's own interactive sign-in starts a ceremony; an
// impersonation and a caller without a session are refused.
#[tokio::test]
async fn only_the_owners_sign_in_starts_a_ceremony() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    for caller in [
        KeyCaller {
            interactive: false,
            ..f.caller.clone()
        },
        KeyCaller {
            session: None,
            ..f.caller.clone()
        },
    ] {
        let refused = f
            .keys
            .start_enrollment(
                &mut access,
                &caller,
                ISSUER,
                start(DeviceEnrollmentPurpose::Enroll, None),
            )
            .await;
        assert!(matches!(refused, Err(DeviceKeyError::Denied)));
    }
    assert_eq!(access.owner_calls, 0);
}

// A provisional session binds no key.
#[tokio::test]
async fn a_provisional_session_binds_no_key() {
    let f = fixture().await;
    let mut session = Session::new(f.profile, None, Utc::now() + chrono::Duration::hours(1));
    session.is_provisional = true;
    f.storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    let caller = KeyCaller {
        session: Some(session.id),
        ..f.caller.clone()
    };

    let refused = f
        .keys
        .start_enrollment(
            &mut TestAccess::default(),
            &caller,
            ISSUER,
            start(DeviceEnrollmentPurpose::Enroll, None),
        )
        .await;

    assert!(matches!(
        refused,
        Err(DeviceKeyError::Enrollment(EnrollmentRefusal::Provisional))
    ));
}

// A keyed finish needs its operation context; a rotation names its device
// and an unknown purpose is refused, before anything is read or written.
#[tokio::test]
async fn malformed_requests_are_refused() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    let challenge = f
        .start(&mut access, DeviceEnrollmentPurpose::Enroll, Some(f.device))
        .await;
    let key = ec_key();
    let without_context = f
        .keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            None,
            finish(
                &challenge,
                proof(&key, &challenge, "enroll", &key.thumbprint()),
            ),
        )
        .await;
    assert!(matches!(
        without_context,
        Err(DeviceKeyError::ContextRequired)
    ));

    let no_device = f
        .keys
        .start_enrollment(
            &mut access,
            &f.caller,
            ISSUER,
            start(DeviceEnrollmentPurpose::Rotate, None),
        )
        .await;
    assert!(matches!(
        no_device,
        Err(DeviceKeyError::MissingField("device_id"))
    ));

    let no_purpose = f
        .keys
        .start_enrollment(
            &mut access,
            &f.caller,
            ISSUER,
            start(DeviceEnrollmentPurpose::Unspecified, None),
        )
        .await;
    assert!(matches!(
        no_purpose,
        Err(DeviceKeyError::InvalidField {
            field: "purpose",
            ..
        })
    ));

    let no_proof = f
        .keys
        .finish_enrollment(
            &mut access,
            &f.caller,
            operation(f.storage.as_ref(), "k-empty").await,
            finish(&challenge, String::new()),
        )
        .await;
    assert!(matches!(
        no_proof,
        Err(DeviceKeyError::MissingField("proof"))
    ));
    assert!(f.attestation().await.is_none());
}

// An unknown device is not found, alike for a caller the authority allows.
#[tokio::test]
async fn an_unknown_device_is_not_found() {
    let f = fixture().await;
    let unknown = DeviceId::generate();
    let mut access = TestAccess {
        allow_others: true,
        ..Default::default()
    };

    let refused = f
        .keys
        .get_attestation(
            &mut access,
            &f.caller,
            GetDeviceAttestationRequest {
                device_id: Some(unknown.into()),
            },
        )
        .await;

    assert!(matches!(refused, Err(DeviceKeyError::DeviceNotFound(d)) if d == unknown));
}

// An allowed administrator reads another Profile's device key; another
// caller does not find it.
#[tokio::test]
async fn reading_anothers_key_follows_the_authority() {
    let f = fixture().await;
    f.enroll(&ec_key()).await;
    let stranger = KeyCaller {
        profile: Some(ProfileId::generate()),
        ..f.caller.clone()
    };
    let get = || GetDeviceAttestationRequest {
        device_id: Some(f.device.into()),
    };

    let mut allowed = TestAccess {
        allow_others: true,
        ..Default::default()
    };
    let read = f
        .keys
        .get_attestation(&mut allowed, &stranger, get())
        .await
        .unwrap();
    assert_eq!(read.profile_id, Some(f.profile.into()));

    let refused = f
        .keys
        .get_attestation(&mut TestAccess::default(), &stranger, get())
        .await;
    assert!(matches!(refused, Err(DeviceKeyError::DeviceNotFound(d)) if d == f.device));
}

// The owner lists its device keys; another caller gets the authority's own
// refusal.
#[tokio::test]
async fn listing_follows_the_profiles_authority() {
    let f = fixture().await;
    f.enroll(&ec_key()).await;
    let mut access = TestAccess::default();
    let list = || ListDeviceAttestationsRequest {
        profile_id: Some(f.profile.into()),
    };

    let own = f
        .keys
        .list_attestations(&mut access, &f.caller, list())
        .await
        .unwrap();
    assert_eq!(own.attestations.len(), 1);

    let stranger = KeyCaller {
        profile: Some(ProfileId::generate()),
        ..f.caller.clone()
    };
    let refused = f
        .keys
        .list_attestations(&mut access, &stranger, list())
        .await;
    assert!(matches!(refused, Err(DeviceKeyError::Access(Refused))));
}

#[test]
fn test_proto_format_mapping() {
    use v1::AttestationFormat as F;
    assert_eq!(format(F::None as i32), DeviceAttestationFormat::None);
    assert_eq!(format(F::Packed as i32), DeviceAttestationFormat::Packed);
    assert_eq!(format(F::Tpm as i32), DeviceAttestationFormat::Tpm);
    assert_eq!(
        format(F::AndroidKey as i32),
        DeviceAttestationFormat::AndroidKey
    );
    assert_eq!(format(F::Apple as i32), DeviceAttestationFormat::Apple);
    assert_eq!(format(F::FidoU2f as i32), DeviceAttestationFormat::FidoU2f);
    assert_eq!(format(999), DeviceAttestationFormat::None);
}

#[test]
fn test_proto_key_storage_mapping() {
    use v1::KeyStorageType as K;
    assert_eq!(key_storage(K::Software as i32), KeyStorageType::Software);
    assert_eq!(key_storage(K::Tpm as i32), KeyStorageType::Tpm);
    assert_eq!(
        key_storage(K::SecureEnclave as i32),
        KeyStorageType::SecureEnclave
    );
    assert_eq!(key_storage(K::Strongbox as i32), KeyStorageType::StrongBox);
    assert_eq!(key_storage(K::Tee as i32), KeyStorageType::Tee);
    assert_eq!(key_storage(999), KeyStorageType::Software);
}

#[test]
fn test_domain_to_proto_roundtrip() {
    let att = DeviceAttestation::new_ce(
        DeviceId::generate(),
        ProfileId::generate(),
        DeviceAttestationFormat::Apple,
        KeyStorageType::SecureEnclave,
        r#"{"kty":"OKP","crv":"Ed25519","x":"AA"}"#.to_string(),
    );
    let proto = attestation_to_proto(&att);
    assert_eq!(proto.format, v1::AttestationFormat::Apple as i32);
    assert_eq!(proto.key_storage, v1::KeyStorageType::SecureEnclave as i32);
    assert_eq!(proto.status, v1::AttestationStatus::Unverified as i32);
    assert_eq!(proto.public_jwk, att.public_jwk);
}
