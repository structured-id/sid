// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of IdentityService management RPCs: no token is refused, a
//! signed-in user may act only on their own account, an administrator on any,
//! and a personal access token never manages credentials, login handles or
//! sessions.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token, test_profile};
use sid_core::models::{
    AuditEntry, Credential, CredentialType, Principal, PrincipalId, PrincipalType, Profile, Session,
};
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// The victim's account with one credential, one login handle and one session,
/// plus a second, unrelated account.
struct Fixture {
    svc: TestServices,
    victim: Profile,
    attacker: Profile,
    credential: Credential,
    principal: Principal,
    session: Session,
}

async fn fixture() -> Fixture {
    let victim = test_profile();
    let attacker = Profile::new(Some("mallory"));
    let credential = Credential::new(victim.id, CredentialType::Totp, vec![1u8; 20], None);
    let session = Session::new(
        victim.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let storage = MockStorage::new()
        .with_profile(victim.clone())
        .with_profile(attacker.clone())
        .with_credential(credential.clone())
        .with_session(session.clone());
    let svc = TestServices::new(storage);
    let now = chrono::Utc::now();
    let principal = Principal {
        id: PrincipalId::new(),
        profile_id: victim.id,
        principal_type: PrincipalType::Email,
        value: "victim-authz@sid.example.com".to_string(),
        verified: true,
        verified_at: Some(now),
        verification_expires: None,
        assigned_profile_id: Some(victim.id),
        assignment_revision: 1,
        email_policy_revision: Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION),
        is_primary: true,
        source_field: Some("email".to_string()),
        source_email_id: None,
        source_phone_id: None,
        created_at: now,
        updated_at: now,
    };
    svc.storage
        .save_principal(&principal, AuditEntry::system("test", "principal").into())
        .await
        .unwrap();
    Fixture {
        svc,
        victim,
        attacker,
        credential,
        principal,
        session,
    }
}

/// Every management RPC answers UNAUTHENTICATED without a token.
#[tokio::test]
async fn test_identity_rpcs_require_a_token() {
    let f = fixture().await;
    let id = f.victim.id.to_string();
    let s = &f.svc.identity;
    let codes = [
        s.create_profile(Request::new(CreateProfileRequest::default()))
            .await
            .err()
            .map(|e| e.code()),
        s.get_profile(Request::new(GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Id(id.clone())),
        }))
        .await
        .err()
        .map(|e| e.code()),
        s.update_profile(Request::new(UpdateProfileRequest {
            id: id.clone(),
            ..Default::default()
        }))
        .await
        .err()
        .map(|e| e.code()),
        s.delete_profile(Request::new(DeleteProfileRequest { id: id.clone() }))
            .await
            .err()
            .map(|e| e.code()),
        s.list_profiles(Request::new(ListProfilesRequest::default()))
            .await
            .err()
            .map(|e| e.code()),
        s.list_credentials(Request::new(ListCredentialsRequest {
            profile_id: id.clone(),
        }))
        .await
        .err()
        .map(|e| e.code()),
        s.revoke_credential(Request::new(RevokeCredentialRequest {
            credential_id: f.credential.id.0.to_string(),
        }))
        .await
        .err()
        .map(|e| e.code()),
        s.list_principals(Request::new(ListPrincipalsRequest {
            profile_id: id.clone(),
        }))
        .await
        .err()
        .map(|e| e.code()),
        s.list_sessions(Request::new(ListSessionsRequest {
            profile_id: id.clone(),
        }))
        .await
        .err()
        .map(|e| e.code()),
        s.revoke_session(Request::new(RevokeSessionRequest {
            session_id: f.session.id.to_string(),
        }))
        .await
        .err()
        .map(|e| e.code()),
    ];
    for (i, code) in codes.into_iter().enumerate() {
        assert_eq!(code, Some(Code::Unauthenticated), "rpc #{i}");
    }
}

/// Regression (#881, K29): another signed-in user cannot read, change or delete
/// the victim's account, credentials, login handles or sessions, and nothing is
/// changed by trying.
#[tokio::test]
async fn test_identity_rpcs_refuse_a_foreign_target() {
    let f = fixture().await;
    let token = issue_token(&f.svc.jwt, &f.attacker, &["openid".to_string()]);
    let id = f.victim.id.to_string();
    let s = &f.svc.identity;
    let denied = |r: Result<(), tonic::Status>| r.err().map(|e| e.code());

    let results = [
        denied(
            s.create_profile(authed(CreateProfileRequest::default(), &token))
                .await
                .map(|_| ()),
        ),
        denied(
            s.get_profile(authed(
                GetProfileRequest {
                    identifier: Some(get_profile_request::Identifier::Id(id.clone())),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.update_profile(authed(
                UpdateProfileRequest {
                    id: id.clone(),
                    given_name: Some("Owned".to_string()),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.delete_profile(authed(DeleteProfileRequest { id: id.clone() }, &token))
                .await
                .map(|_| ()),
        ),
        denied(
            s.list_profiles(authed(ListProfilesRequest::default(), &token))
                .await
                .map(|_| ()),
        ),
        denied(
            s.list_credentials(authed(
                ListCredentialsRequest {
                    profile_id: id.clone(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.update_credential(authed(
                UpdateCredentialRequest {
                    credential_id: f.credential.id.0.to_string(),
                    label: Some("owned".to_string()),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.revoke_credential(authed(
                RevokeCredentialRequest {
                    credential_id: f.credential.id.0.to_string(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.add_principal(authed(
                AddPrincipalRequest {
                    profile_id: id.clone(),
                    r#type: PrincipalType::Email as i32,
                    value: "attacker@sid.example.com".to_string(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.list_principals(authed(
                ListPrincipalsRequest {
                    profile_id: id.clone(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.remove_principal(authed(
                RemovePrincipalRequest {
                    principal_id: f.principal.id.0.to_string(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.list_sessions(authed(
                ListSessionsRequest {
                    profile_id: id.clone(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
        denied(
            s.revoke_session(authed(
                RevokeSessionRequest {
                    session_id: f.session.id.to_string(),
                },
                &token,
            ))
            .await
            .map(|_| ()),
        ),
    ];
    // A record named by its own id (credential, principal) that is not the
    // caller's is not found, as an unknown one: the refusal does not tell
    // that it exists. A target named by profile id is refused outright.
    const NAMED_BY_RECORD_ID: [usize; 3] = [6, 7, 10];
    for (i, code) in results.into_iter().enumerate() {
        let expected = if NAMED_BY_RECORD_ID.contains(&i) {
            Code::NotFound
        } else {
            Code::PermissionDenied
        };
        assert_eq!(code, Some(expected), "rpc #{i}");
    }

    let victim = f.svc.storage.get_profile(f.victim.id).await.unwrap();
    assert_eq!(
        victim.expect("still exists").given_name,
        f.victim.given_name
    );
    assert!(
        f.svc
            .storage
            .get_credential(f.credential.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        f.svc
            .storage
            .get_principal(f.principal.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        f.svc
            .storage
            .get_session(f.session.id)
            .await
            .unwrap()
            .is_some()
    );
}

/// Regression (#881): another signed-in user cannot revoke the victim's profile
/// (the revocation cascade ends every session and token of the account).
#[tokio::test]
async fn test_revoke_profile_refuses_a_foreign_target() {
    let f = fixture().await;
    let token = issue_token(&f.svc.jwt, &f.attacker, &["openid".to_string()]);
    let err = f
        .svc
        .identity
        .revoke_profile(authed(
            RevokeProfileRequest {
                profile_id: f.victim.id.to_string(),
                reason: "emergency".to_string(),
            },
            &token,
        ))
        .await
        .expect_err("foreign target");
    assert_eq!(err.code(), Code::PermissionDenied);
    let victim = f.svc.storage.get_profile(f.victim.id).await.unwrap();
    assert_eq!(victim.expect("still exists").status, f.victim.status);
    assert!(
        f.svc
            .storage
            .get_session(f.session.id)
            .await
            .unwrap()
            .is_some()
    );
}

/// The owner revokes their own profile only as a user request; the
/// administrative reasons belong to administrators.
#[tokio::test]
async fn test_revoke_profile_owner_cannot_claim_an_admin_reason() {
    let f = fixture().await;
    let token = issue_token(&f.svc.jwt, &f.victim, &["openid".to_string()]);
    let err = f
        .svc
        .identity
        .revoke_profile(authed(
            RevokeProfileRequest {
                profile_id: f.victim.id.to_string(),
                reason: "emergency".to_string(),
            },
            &token,
        ))
        .await
        .expect_err("administrative reason");
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// The owner reads and edits their own account.
#[tokio::test]
async fn test_identity_rpcs_allow_the_owner() {
    let f = fixture().await;
    let token = issue_token(&f.svc.jwt, &f.victim, &["openid".to_string()]);
    let id = f.victim.id.to_string();
    let s = &f.svc.identity;
    s.get_profile(authed(
        GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Id(id.clone())),
        },
        &token,
    ))
    .await
    .expect("own profile");
    s.update_profile(authed(
        UpdateProfileRequest {
            id: id.clone(),
            given_name: Some("Alicia".to_string()),
            ..Default::default()
        },
        &token,
    ))
    .await
    .expect("own update");
    s.list_credentials(authed(
        ListCredentialsRequest {
            profile_id: id.clone(),
        },
        &token,
    ))
    .await
    .expect("own credentials");
    s.list_sessions(authed(ListSessionsRequest { profile_id: id }, &token))
        .await
        .expect("own sessions");
}

/// An administrator lists accounts and acts on another user's account.
#[tokio::test]
async fn test_identity_rpcs_allow_an_administrator() {
    let f = fixture().await;
    let token = issue_admin_token(&f.svc.jwt, f.attacker.id);
    let s = &f.svc.identity;
    s.list_profiles(authed(ListProfilesRequest::default(), &token))
        .await
        .expect("admin lists");
    s.get_profile(authed(
        GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Id(f.victim.id.to_string())),
        },
        &token,
    ))
    .await
    .expect("admin reads");
    s.list_credentials(authed(
        ListCredentialsRequest {
            profile_id: f.victim.id.to_string(),
        },
        &token,
    ))
    .await
    .expect("admin lists credentials");
}

/// A second account's claim on the victim's email; the principal keeps its
/// id, the one entity every claim refers to.
async fn share_victim_email(f: &Fixture) -> Principal {
    let mut shared = f.principal.clone();
    shared.profile_id = f.attacker.id;
    shared.verified = false;
    f.svc
        .storage
        .save_principal(&shared, AuditEntry::system("test", "principal").into())
        .await
        .unwrap();
    shared
}

fn holds(principals: &[Principal], value: &str) -> bool {
    principals.iter().any(|p| p.value == value)
}

/// A user removing an email other accounts also hold drops only their own
/// hold; the other account keeps it.
#[tokio::test]
async fn test_remove_shared_principal_drops_only_own_hold() {
    let f = fixture().await;
    let shared = share_victim_email(&f).await;
    let token = issue_token(&f.svc.jwt, &f.attacker, &["openid".to_string()]);

    f.svc
        .identity
        .remove_principal(authed(
            RemovePrincipalRequest {
                principal_id: shared.id.0.to_string(),
            },
            &token,
        ))
        .await
        .expect("own hold");

    let victim = f
        .svc
        .storage
        .get_principals_by_profile(f.victim.id)
        .await
        .unwrap();
    assert!(
        holds(&victim, &f.principal.value),
        "the other holder lost it"
    );
    let attacker = f
        .svc
        .storage
        .get_principals_by_profile(f.attacker.id)
        .await
        .unwrap();
    assert!(!holds(&attacker, &f.principal.value));
}

/// An administrator cannot tell which of several holders to remove the
/// principal from, so nothing is removed; with a single holder it is removed.
#[tokio::test]
async fn test_admin_remove_principal_needs_a_single_holder() {
    let f = fixture().await;
    let shared = share_victim_email(&f).await;
    let admin = sid_core::models::Profile::new(Some("principal-admin"));
    f.svc
        .storage
        .create_profile(&admin, AuditEntry::system("test", "admin").into())
        .await
        .unwrap();
    let token = issue_admin_token(&f.svc.jwt, admin.id);

    let err = f
        .svc
        .identity
        .remove_principal(authed(
            RemovePrincipalRequest {
                principal_id: f.principal.id.0.to_string(),
            },
            &token,
        ))
        .await
        .expect_err("several holders");
    assert_eq!(err.code(), Code::FailedPrecondition);
    let victim = f
        .svc
        .storage
        .get_principals_by_profile(f.victim.id)
        .await
        .unwrap();
    assert!(holds(&victim, &f.principal.value));

    // The attacker gives it up; the victim is the only holder left.
    let attacker_token = issue_token(&f.svc.jwt, &f.attacker, &["openid".to_string()]);
    f.svc
        .identity
        .remove_principal(authed(
            RemovePrincipalRequest {
                principal_id: shared.id.0.to_string(),
            },
            &attacker_token,
        ))
        .await
        .unwrap();
    f.svc
        .identity
        .remove_principal(authed(
            RemovePrincipalRequest {
                principal_id: f.principal.id.0.to_string(),
            },
            &token,
        ))
        .await
        .expect("single holder");
    let victim = f
        .svc
        .storage
        .get_principals_by_profile(f.victim.id)
        .await
        .unwrap();
    assert!(!holds(&victim, &f.principal.value));
}
