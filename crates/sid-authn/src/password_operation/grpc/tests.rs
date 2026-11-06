//! Each refusal of a password operation keeps the status the services have
//! always answered with: its code, `ErrorInfo` reason, message and details.

use super::super::tests::{manager, split, sqlite};
use super::*;
use sid_core::grpc_error::{extract_error_info, extract_retry_delay};
use sid_core::models::{HistoryEpochId, HistoryKsf, HistorySuite};
use sid_ids::PasswordOperationId;
use sid_proto::sid::v1::authn::PasswordHistoryOwnerKind;
use tonic::Code;
use tonic_types::StatusExt;

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

#[test]
fn refusals_keep_their_code_and_reason() {
    let cases: Vec<(PasswordOperationError, Code, &str)> = vec![
        (
            PasswordOperationError::Unavailable("evaluator"),
            Code::Unavailable,
            "PASSWORD_HISTORY_UNAVAILABLE",
        ),
        (
            PasswordOperationError::Internal,
            Code::Internal,
            "INTERNAL_ERROR",
        ),
        (
            PasswordOperationError::NotPending,
            Code::FailedPrecondition,
            "OPERATION_EXPIRED",
        ),
        (
            PasswordOperationError::StepMissing("the operation has no OPAQUE start"),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            PasswordOperationError::HistoryKeyWithdrawn,
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            PasswordOperationError::PolicyChanged,
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            PasswordOperationError::HistoryChanged,
            Code::Aborted,
            "CONCURRENT_MODIFICATION",
        ),
        (
            PasswordOperationError::InvalidProof,
            Code::InvalidArgument,
            "PASSWORD_PROOF_INVALID",
        ),
        (
            PasswordOperationError::Reused,
            Code::FailedPrecondition,
            "PASSWORD_REUSED",
        ),
        (
            PasswordOperationError::RateLimited,
            Code::ResourceExhausted,
            "RATE_LIMIT_EXCEEDED",
        ),
        (
            PasswordOperationError::Conflict("this operation already evaluated another input"),
            Code::AlreadyExists,
            "OPERATION_KEY_CONFLICT",
        ),
        (
            PasswordOperationError::Required {
                field: "proof",
                message: "a password proof is required",
            },
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            PasswordOperationError::InvalidField {
                field: "blinded_input",
                reason: "not exactly 32 bytes",
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            PasswordOperationError::InvalidOperationId("absent".into()),
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
    ];
    for (error, code, expected) in cases {
        let status = Status::from(error);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(reason(&status), expected, "{status:?}");
    }
}

/// The details a client acts on: when to retry, which precondition failed,
/// which field is wrong.
#[test]
fn refusals_keep_their_details() {
    let unavailable = Status::from(PasswordOperationError::Unavailable("evaluator"));
    assert_eq!(
        unavailable.message(),
        "password history unavailable: evaluator"
    );
    assert_eq!(
        extract_retry_delay(&unavailable),
        Some(Duration::from_secs(5))
    );

    let limited = Status::from(PasswordOperationError::RateLimited);
    assert_eq!(
        extract_retry_delay(&limited),
        Some(super::super::EVALUATION_WINDOW)
    );

    let precondition = |error: PasswordOperationError| {
        let status = Status::from(error);
        let failure = status
            .get_details_precondition_failure()
            .expect("PreconditionFailure");
        let violation = failure.violations.into_iter().next().expect("a violation");
        (violation.r#type, violation.subject, violation.description)
    };
    assert_eq!(
        precondition(PasswordOperationError::StepMissing("no OPAQUE start")),
        (
            "PASSWORD_OPERATION_STEP".into(),
            "password_operation".into(),
            "no OPAQUE start".into()
        )
    );
    assert_eq!(
        precondition(PasswordOperationError::HistoryKeyWithdrawn).0,
        "PASSWORD_HISTORY_WRITE_CUTOFF"
    );
    assert_eq!(
        precondition(PasswordOperationError::PolicyChanged).0,
        "PASSWORD_POLICY_VERSION"
    );

    let field = |error: PasswordOperationError| {
        let status = Status::from(error);
        let request = status.get_details_bad_request().expect("BadRequest");
        let violation = request
            .field_violations
            .into_iter()
            .next()
            .expect("a field violation");
        (violation.field, violation.description)
    };
    assert_eq!(
        field(PasswordOperationError::Required {
            field: "credential_finalization",
            message: "the current-password sign-in needs its finalization",
        }),
        ("credential_finalization".into(), "required".into())
    );
    assert_eq!(
        field(PasswordOperationError::InvalidOperationId("absent".into())),
        ("operation_id".into(), "a password operation id".into())
    );
}

/// A step whose operation is not pending for it reads as expired, whatever
/// the cause, so it tells nothing about operations the caller does not own.
#[test]
fn a_step_without_its_operation_reads_as_expired() {
    let status = Status::from(PasswordOperationError::NotPending);
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(reason(&status), "OPERATION_EXPIRED");
}

/// The evaluator's client listener refuses preparation from anyone, since a
/// caller could otherwise create keys for operations it names; Prepare is
/// served only on the internal listener the deployment keeps internal.
#[tokio::test]
async fn a_client_listener_refuses_preparation() {
    let (_, evaluation) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let service = PasswordHistoryEvaluatorImpl::new(evaluation, Arc::new(ClientListener));
    let status = service
        .prepare_password_history(Request::new(PreparePasswordHistoryRequest {
            operation_id: Some(PasswordOperationId::generate().into()),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
}

/// The internal listener admits preparation: its protection is the
/// deployment's transport, so the request reaches the evaluator's own
/// admission checks (here an empty request is refused as malformed, not as
/// unauthorized).
#[tokio::test]
async fn the_internal_listener_admits_preparation() {
    let (_, evaluation) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let service = PasswordHistoryEvaluatorImpl::new(evaluation, Arc::new(InternalTransport));
    let status = service
        .prepare_password_history(Request::new(PreparePasswordHistoryRequest {
            operation_id: Some(PasswordOperationId::generate().into()),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
}

/// A preparation request is decoded before the evaluator acts on it: an
/// owner domain or live domain that is not 32 bytes, an unspecified owner
/// kind, a missing expiry, a malformed settled operation or more entries than
/// the bounds allow is an invalid argument.
#[test]
fn a_malformed_admission_is_an_invalid_argument() {
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    let good = PreparePasswordHistoryRequest {
        operation_id: Some(PasswordOperationId::generate().into()),
        owner_domain: vec![3; 32],
        owner_kind: PasswordHistoryOwnerKind::Existing as i32,
        expires_at: Some(timestamp(expires_at)),
        charge_key: "charge".into(),
        live_comparison_domains: vec![vec![2; 32], vec![1; 32]],
        history_revision: 4,
        settled_operations: vec![PasswordOperationId::generate().into()],
    };
    let admission = admission_of(&good).unwrap();
    assert_eq!(admission.owner_domain, [3; 32]);
    assert_eq!(admission.kind, OwnerKind::Existing);
    assert_eq!(admission.expires_at, expires_at);
    assert_eq!(admission.live.domains, vec![[1; 32], [2; 32]], "sorted");
    assert_eq!(admission.live.revision, 4);
    assert_eq!(admission.live.settled.len(), 1);

    for bad in [
        PreparePasswordHistoryRequest {
            owner_domain: vec![3; 31],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            owner_kind: PasswordHistoryOwnerKind::Unspecified as i32,
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            expires_at: None,
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            live_comparison_domains: vec![vec![1; 31]],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            live_comparison_domains: vec![vec![1; 32]; MAX_HISTORY_DOMAINS + 1],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            settled_operations: vec![sid_ids_proto::PasswordOperationId { value: vec![1; 3] }],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            history_revision: u64::MAX,
            ..good.clone()
        },
    ] {
        let status = Status::from(admission_of(&bad).unwrap_err());
        assert_eq!(status.code(), Code::InvalidArgument, "{}", status.message());
    }
}

/// A remote evaluator's answer is accepted only when it describes each
/// domain it returns: as many epochs as domains, each domain the one its
/// epoch gives under the shared relation, each description well formed.
#[test]
fn a_remote_selection_must_describe_its_domains() {
    use sid_core::models::HistoryEpochUse;
    let described = sid_core::models::KeyEpoch {
        id: HistoryEpochId::generate(),
        owner_domain: [3; 32],
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [5; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [6; 32],
        status: HistoryEpochUse::Active,
        created_at: chrono::Utc::now(),
    }
    .descriptor();
    let good = PreparePasswordHistoryResponse {
        domains: vec![domain_message(&OperationDomain::of(&described))],
        epochs: vec![descriptor_message(&described)],
    };
    assert_eq!(selection_of(&good), Some(vec![described]));
    let mut other_salt = good.clone();
    other_salt.epochs[0].ksf_salt = vec![7; 32];
    let mut malformed = good.clone();
    malformed.epochs[0].epoch_id = vec![1; 3];
    let mut unknown_suite = good.clone();
    unknown_suite.epochs[0].suite = "pallas-poseidon-v0".into();
    let mut missing = good.clone();
    missing.epochs.clear();
    for refused in [other_salt, malformed, unknown_suite, missing] {
        assert_eq!(selection_of(&refused), None);
    }
}

/// A failure of the ceremony store or the result store keeps the status
/// those stores answer with everywhere else.
#[test]
fn store_failures_keep_their_status() {
    let ceremony = Status::from(PasswordOperationError::Ceremony(
        crate::challenge_store::ChallengeStoreError::Store(sid_core::Error::Internal(
            "down".into(),
        )),
    ));
    assert_eq!(ceremony.code(), Code::Internal);
    let operation = Status::from(PasswordOperationError::Operation(
        crate::operation::OperationError::KeyConflict,
    ));
    assert_eq!(operation.code(), Code::AlreadyExists);
    assert_eq!(reason(&operation), "OPERATION_KEY_CONFLICT");
}
