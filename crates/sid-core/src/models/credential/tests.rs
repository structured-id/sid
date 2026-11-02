// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn test_credential_new_defaults() {
    let cred = Credential::new(
        ProfileId::generate(),
        CredentialType::Opaque,
        vec![1, 2, 3],
        Some("My password".into()),
    );
    assert_eq!(cred.credential_type, CredentialType::Opaque);
    assert_eq!(cred.status, CredentialStatus::Active);
    assert_eq!(cred.data.expose(), &[1, 2, 3]);
    assert_eq!(cred.label.as_deref(), Some("My password"));
    assert!(cred.last_used_at.is_none());
    assert_eq!(cred.policy_evidence, PolicyEvidence::Unverified);
    assert!(!cred.policy_evidence.is_verified());
}

/// Evidence keeps its policy version and artifact through serialization (the
/// transfer archive), and an unverified password carries neither.
#[test]
fn test_policy_evidence_round_trips() {
    for evidence in [
        PolicyEvidence::Unverified,
        PolicyEvidence::Verified {
            policy_version: 2,
            artifact: [7; 32],
        },
    ] {
        let json = serde_json::to_string(&evidence).unwrap();
        assert_eq!(
            serde_json::from_str::<PolicyEvidence>(&json).unwrap(),
            evidence
        );
    }
    assert!(
        serde_json::from_str::<PolicyEvidence>(r#"{"kind":"verified","policy_version":1}"#)
            .is_err(),
        "a verdict without its artifact is refused"
    );
}

/// Stored type and status names read back; any other name is refused, never
/// read as a password or as active.
#[test]
fn test_credential_type_and_status_parse() {
    for t in [
        CredentialType::Opaque,
        CredentialType::WebAuthn,
        CredentialType::Totp,
        CredentialType::Recovery,
        CredentialType::LegacyHash,
    ] {
        assert_eq!(t.as_str().parse::<CredentialType>(), Ok(t));
    }
    for s in [CredentialStatus::Active, CredentialStatus::Revoked] {
        assert_eq!(s.as_str().parse::<CredentialStatus>(), Ok(s));
    }
    assert!("passkey".parse::<CredentialType>().is_err());
    assert!("Revoked".parse::<CredentialStatus>().is_err());
}

#[test]
fn test_credential_new_without_label() {
    let cred = Credential::new(
        ProfileId::generate(),
        CredentialType::WebAuthn,
        vec![],
        None,
    );
    assert!(cred.label.is_none());
    assert_eq!(cred.credential_type, CredentialType::WebAuthn);
}

#[test]
fn test_mark_used() {
    let mut cred = Credential::new(ProfileId::generate(), CredentialType::Totp, vec![42], None);
    assert!(cred.last_used_at.is_none());
    cred.mark_used();
    assert!(cred.last_used_at.is_some());
}

#[test]
fn test_credential_type_as_str() {
    assert_eq!(CredentialType::Opaque.as_str(), "opaque");
    assert_eq!(CredentialType::WebAuthn.as_str(), "webauthn");
    assert_eq!(CredentialType::Totp.as_str(), "totp");
    assert_eq!(CredentialType::Recovery.as_str(), "recovery");
    assert_eq!(CredentialType::LegacyHash.as_str(), "legacy_hash");
}

/// Only a method that signs in on its own is primary; second factors and
/// recovery codes are not.
#[test]
fn test_credential_type_is_primary() {
    assert!(CredentialType::Opaque.is_primary());
    assert!(CredentialType::WebAuthn.is_primary());
    assert!(CredentialType::LegacyHash.is_primary());
    assert!(!CredentialType::Totp.is_primary());
    assert!(!CredentialType::Recovery.is_primary());
}

/// A password takes the place of any password or legacy hash, a recovery-code
/// set of the previous set; passkeys and TOTP are added beside others.
#[test]
fn test_credential_type_replaces() {
    assert_eq!(
        CredentialType::Opaque.replaces(),
        &[CredentialType::Opaque, CredentialType::LegacyHash]
    );
    assert_eq!(
        CredentialType::Recovery.replaces(),
        &[CredentialType::Recovery]
    );
    assert!(CredentialType::WebAuthn.replaces().is_empty());
    assert!(CredentialType::Totp.replaces().is_empty());
    assert!(CredentialType::LegacyHash.replaces().is_empty());
}

#[test]
fn test_legacy_hash_credential() {
    let hash = "$2b$12$LJ3m4ys7Gp8pM3szPbKJRuBb0OGFMfBMRIEGmHiPdF1P3YLzBY8Oe";
    let cred = Credential::new(
        ProfileId::generate(),
        CredentialType::LegacyHash,
        hash.as_bytes().to_vec(),
        Some("Migrated from Keycloak".into()),
    );
    assert_eq!(cred.credential_type, CredentialType::LegacyHash);
    assert_eq!(cred.data.expose(), hash.as_bytes());
    assert!(cred.legacy_algorithm.is_none());

    let mut cred = cred;
    cred.legacy_algorithm = Some("bcrypt".into());
    assert_eq!(cred.legacy_algorithm.as_deref(), Some("bcrypt"));
}

#[test]
fn test_credential_id_unique() {
    let id1 = CredentialId::new();
    let id2 = CredentialId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_credential_data_expose() {
    let data = CredentialData::new(vec![1, 2, 3]);
    assert_eq!(data.expose(), &[1, 2, 3]);
}

#[test]
fn test_credential_data_debug_redacted() {
    let data = CredentialData::new(vec![42]);
    assert_eq!(format!("{:?}", data), "[REDACTED credential data]");
}

#[test]
fn test_credential_data_clone() {
    let data = CredentialData::new(vec![1, 2, 3]);
    let cloned = data.clone();
    assert_eq!(data.expose(), cloned.expose());
}

#[test]
fn test_credential_data_into_inner() {
    let data = CredentialData::new(vec![1, 2, 3]);
    let inner = data.into_inner();
    assert_eq!(inner, vec![1, 2, 3]);
}

#[test]
fn test_credential_data_from_vec() {
    let data: CredentialData = vec![4, 5, 6].into();
    assert_eq!(data.expose(), &[4, 5, 6]);
}

#[test]
fn test_credential_data_serde_roundtrip() {
    let data = CredentialData::new(vec![10, 20, 30]);
    let json = serde_json::to_string(&data).unwrap();
    let restored: CredentialData = serde_json::from_str(&json).unwrap();
    assert_eq!(data.expose(), restored.expose());
}

#[test]
fn test_credential_data_ct_eq() {
    let a = CredentialData::new(vec![1, 2, 3]);
    let b = CredentialData::new(vec![1, 2, 3]);
    let c = CredentialData::new(vec![1, 2, 4]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_credential_status_as_str() {
    assert_eq!(CredentialStatus::Active.as_str(), "active");
    assert_eq!(CredentialStatus::Revoked.as_str(), "revoked");
}

#[test]
fn test_credential_status_display() {
    assert_eq!(format!("{}", CredentialStatus::Active), "active");
    assert_eq!(format!("{}", CredentialStatus::Revoked), "revoked");
}

#[test]
fn test_credential_status_default_is_active() {
    assert_eq!(CredentialStatus::default(), CredentialStatus::Active);
}

#[test]
fn test_active_credential_gateway() {
    let mut cred = Credential::new(ProfileId::generate(), CredentialType::Opaque, vec![1], None);
    assert!(cred.status.is_active());

    // Gateway should succeed for active credential
    let active = cred.as_active();
    assert!(active.is_some());
}

#[test]
fn test_active_credential_revoke() {
    let mut cred = Credential::new(ProfileId::generate(), CredentialType::Opaque, vec![1], None);

    let active = cred.as_active().expect("should be active");
    active.revoke();

    assert_eq!(cred.status, CredentialStatus::Revoked);
    assert!(!cred.status.is_active());
}

#[test]
fn test_revoked_credential_gateway_returns_none() {
    let mut cred = Credential::new(ProfileId::generate(), CredentialType::Opaque, vec![1], None);

    // Revoke it
    cred.as_active().unwrap().revoke();

    // Gateway should return None for revoked credential
    assert!(cred.as_active().is_none());
}
