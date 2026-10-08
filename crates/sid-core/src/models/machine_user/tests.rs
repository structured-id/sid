use super::*;

fn make_machine_user() -> MachineUser {
    MachineUser::new(
        ProjectId::new(),
        "mu_ci_deploy",
        "CI Deploy Bot",
        OwnerType::Profile,
        "owner-profile-id",
    )
}

#[test]
fn test_machine_user_new() {
    let mu = make_machine_user();
    assert_eq!(mu.display_name, "CI Deploy Bot");
    assert_eq!(mu.client_id, "mu_ci_deploy");
    assert_eq!(mu.machine_type, MachineUserType::Service);
    assert_eq!(mu.status, MachineUserStatus::Active);
    assert!(mu.can_authenticate());
    assert!(mu.scopes.is_empty());
}

#[test]
fn test_machine_user_suspend() {
    let mut mu = make_machine_user();
    assert!(mu.can_authenticate());
    mu.as_active().unwrap().suspend();
    assert_eq!(mu.status(), MachineUserStatus::Suspended);
    assert!(!mu.can_authenticate());
}

#[test]
fn test_machine_user_expired() {
    let mut mu = make_machine_user();
    mu.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    assert!(mu.is_expired());
    assert!(!mu.can_authenticate());
}

#[test]
fn test_machine_user_not_expired() {
    let mut mu = make_machine_user();
    mu.expires_at = Some(Utc::now() + chrono::Duration::days(30));
    assert!(!mu.is_expired());
    assert!(mu.can_authenticate());
}

#[test]
fn test_machine_user_type_serde() {
    let t = MachineUserType::Bot;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"bot\"");
    let parsed: MachineUserType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, MachineUserType::Bot);
}

#[test]
fn test_machine_user_status_serde() {
    let s = MachineUserStatus::Suspended;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"suspended\"");
    let parsed: MachineUserStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, MachineUserStatus::Suspended);
}

#[test]
fn test_machine_user_id_unique() {
    let id1 = MachineUserId::generate();
    let id2 = MachineUserId::generate();
    assert_ne!(id1, id2);
}

#[test]
fn test_machine_user_serde_roundtrip() {
    let mu = make_machine_user();
    let json = serde_json::to_string(&mu).unwrap();
    let parsed: MachineUser = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.display_name, "CI Deploy Bot");
    assert_eq!(parsed.client_id, "mu_ci_deploy");
    assert_eq!(parsed.project_id, mu.project_id);
}

// ── Credential tests ────────────────────────────────────────

#[test]
fn test_credential_new() {
    let mu_id = MachineUserId::generate();
    let cred = MachineUserCredential::new(
        mu_id,
        "kid_001",
        MachineCredentialType::ClientSecret,
        "argon2_hash_xxx",
    );
    assert_eq!(cred.kid, "kid_001");
    assert_eq!(cred.machine_user_id, mu_id);
    assert_eq!(cred.credential_type, MachineCredentialType::ClientSecret);
    assert!(!cred.is_expired());
    assert!(!cred.exceeds_max_age());
}

#[test]
fn test_credential_expired() {
    let mut cred = MachineUserCredential::new(
        MachineUserId::generate(),
        "kid_old",
        MachineCredentialType::PrivateKeyJwt,
        "public_key_pem",
    );
    cred.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    assert!(cred.is_expired());
}

#[test]
fn test_credential_type_serde() {
    let t = MachineCredentialType::PrivateKeyJwt;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"private_key_jwt\"");
    let parsed: MachineCredentialType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, MachineCredentialType::PrivateKeyJwt);
}

#[test]
fn test_max_active_credentials() {
    assert_eq!(MAX_ACTIVE_CREDENTIALS, 2);
}

#[test]
fn test_max_credential_age() {
    assert_eq!(MAX_CREDENTIAL_AGE_DAYS, 365);
}

// ── Impersonation tests ──────────────────────────────────────

#[test]
fn test_impersonation_grant_role() {
    let mu_id = MachineUserId::generate();
    let grant = ImpersonationGrant::new(
        mu_id,
        ImpersonationTargetType::Role,
        "employee",
        vec!["documents.read".into(), "approvals.submit".into()],
    );
    assert_eq!(grant.target_type, ImpersonationTargetType::Role);
    assert_eq!(grant.target, "employee");
    assert!(grant.allows_scope("documents.read"));
    assert!(grant.allows_scope("approvals.submit"));
    assert!(!grant.allows_scope("admin.full"));
    assert!(!grant.allows_all_scopes());
}

#[test]
fn test_impersonation_grant_user_wildcard() {
    let grant = ImpersonationGrant::new(
        MachineUserId::generate(),
        ImpersonationTargetType::User,
        "up_01HY_target",
        vec!["*".into()],
    );
    assert_eq!(grant.target_type, ImpersonationTargetType::User);
    assert!(grant.allows_all_scopes());
    assert!(grant.allows_scope("anything"));
}

#[test]
fn test_impersonation_target_type_serde() {
    let t = ImpersonationTargetType::Role;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"role\"");
    let parsed: ImpersonationTargetType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ImpersonationTargetType::Role);
}

#[test]
fn test_impersonation_constants() {
    assert_eq!(CREDENTIAL_ALERT_BEFORE_EXPIRY_DAYS, 30);
    assert_eq!(IMPERSONATION_MAX_LIFETIME_SECONDS, 300);
}

#[test]
fn test_machine_user_max_token_lifetime() {
    let mut mu = make_machine_user();
    assert!(mu.max_token_lifetime.is_none());
    mu.max_token_lifetime = Some(3600);
    assert_eq!(mu.max_token_lifetime, Some(3600));
}

// ── Stored values ────────────────────────────────────────────

/// Every stored value reads back as the variant that wrote it, and a value
/// no variant writes is refused: storage never decodes an unknown owner as a
/// Profile owner or an unknown type as a service.
#[test]
fn test_stored_values_parse_strictly() {
    fn check<T>(variants: &[T])
    where
        T: std::str::FromStr<Err = String> + PartialEq + std::fmt::Debug + Copy,
        T: StoredValue,
    {
        for &v in variants {
            assert_eq!(v.stored().parse::<T>(), Ok(v));
        }
        assert!("unknown".parse::<T>().is_err());
        assert!("".parse::<T>().is_err());
    }
    trait StoredValue {
        fn stored(&self) -> &'static str;
    }
    macro_rules! stored {
        ($($t:ty),*) => {$(
            impl StoredValue for $t {
                fn stored(&self) -> &'static str {
                    self.as_str()
                }
            }
        )*};
    }
    stored!(
        MachineUserType,
        MachineUserStatus,
        MachineCredentialType,
        OwnerType,
        CredentialStatus,
        ImpersonationTargetType
    );

    use MachineUserType as T;
    check(&[T::Service, T::Bot, T::Agent]);
    use MachineUserStatus as S;
    check(&[S::Active, S::Suspended, S::Expired, S::Deleted]);
    use MachineCredentialType as C;
    check(&[
        C::ClientSecret,
        C::PrivateKeyJwt,
        C::Mtls,
        C::WorkloadIdentity,
    ]);
    use OwnerType as O;
    check(&[O::Profile, O::Organization, O::System]);
    use CredentialStatus as R;
    check(&[R::Active, R::GracePeriod, R::Expired, R::Revoked]);
    use ImpersonationTargetType as I;
    check(&[I::Role, I::User]);
}
