// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn ce_rules() -> AccessRules {
    AccessRules::from_descriptors(sid_proto::FILE_DESCRIPTOR_SET).expect("the CE schema declares")
}

/// The rules are read from SID's own schema as its methods declare them:
/// a sign-in ceremony is open, an account read admits an impersonation
/// token while an account change does not, and administration admits only
/// the caller's own session.
#[test]
fn test_rules_are_read_from_the_schema() {
    let rules = ce_rules();
    assert!(matches!(
        rules.rule("/sid.v1.authn.AuthService/OpaqueLoginStart"),
        Some(AccessRule::Open)
    ));

    let read = rules
        .rule("/sid.v1.account.AccountService/ListConsents")
        .expect("declared");
    assert!(read.admits(CredentialKind::Impersonation));
    assert!(read.admits(CredentialKind::AccountApi));
    let AccessRule::Protected { scopes, .. } = read else {
        panic!("protected");
    };
    assert_eq!(scopes.as_ref(), ["account.read"]);

    let change = rules
        .rule("/sid.v1.account.AccountService/UpdateClaimConsent")
        .expect("declared");
    assert!(change.admits(CredentialKind::OwnSession));
    assert!(!change.admits(CredentialKind::Impersonation));

    let admin = rules
        .rule("/sid.v1.identity.IdentityService/ListProfiles")
        .expect("declared");
    assert!(admin.admits(CredentialKind::OwnSession));
    for kind in [
        CredentialKind::AccountApi,
        CredentialKind::Impersonation,
        CredentialKind::Client,
        CredentialKind::PersonalAccessToken,
        CredentialKind::Delegated,
    ] {
        assert!(!admin.admits(kind), "{kind:?}");
    }
}

/// Every method of every service of the schema has a rule, and a service
/// outside it is not declared.
#[test]
fn test_every_ce_method_has_a_rule() {
    let rules = ce_rules();
    let pool = DescriptorPool::decode(sid_proto::FILE_DESCRIPTOR_SET).expect("decodes");
    let mut methods = 0;
    for service in pool.services() {
        assert!(rules.declares(service.full_name()));
        for method in service.methods() {
            let path = format!("/{}/{}", service.full_name(), method.name());
            assert!(rules.rule(&path).is_some(), "{path}");
            methods += 1;
        }
    }
    assert!(methods > 500, "{methods}");
    assert!(!rules.declares("grpc.health.v1.Health"));
}

/// Descriptors without the access option are not the schema this build
/// compiled: they are refused rather than read as having no rules.
#[test]
fn test_descriptors_without_the_option_are_refused() {
    let empty = prost_types::FileDescriptorSet::default();
    let bytes = prost::Message::encode_to_vec(&empty);
    let Err(why) = AccessRules::from_descriptors(&bytes) else {
        panic!("refused");
    };
    assert!(why.contains(ACCESS), "{why}");
}

/// Only a non-empty `Bearer` credential is taken, its scheme in any case
/// (RFC 7235 §2.1); a DPoP-bound presentation is not one (RFC 9449 §7.1).
#[test]
fn test_bearer_scheme() {
    assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
    assert_eq!(bearer(Some("bearer abc ")), Some("abc"));
    assert_eq!(bearer(Some("DPoP abc")), None);
    assert_eq!(bearer(Some("Bearer  ")), None);
    assert_eq!(bearer(Some("abc")), None);
    assert_eq!(bearer(None), None);
}
