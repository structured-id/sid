// SPDX-License-Identifier: AGPL-3.0-only
//! Each refusal of a password operation keeps the status the services have
//! always answered with: its code, `ErrorInfo` reason, message and details;
//! and Prepare is served only where the deployment admits it.

use super::*;
use crate::grpc_error::{extract_error_info, extract_retry_delay};
use sid_ids::PasswordOperationId;
use sid_plugin::CeremonyStateStore;
use tonic::Code;
use tonic_types::StatusExt;

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

fn status_of(error: PasswordOperationError) -> Status {
    error.into_status()
}

/// An evaluator over an in-memory store: what serves the listener tests,
/// whose requests are answered before it evaluates anything.
async fn evaluation() -> Arc<HistoryEvaluation> {
    let storage = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let keys: Arc<dyn sid_keys::KeyManager> = Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([3; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1; 32], "test")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    );
    let ceremonies: Arc<dyn CeremonyStateStore> = storage.clone();
    Arc::new(HistoryEvaluation::new(
        Arc::new(storage.history_keys()),
        ceremonies,
        keys,
    ))
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
        let status = status_of(error);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(reason(&status), expected, "{status:?}");
    }
}

/// The details a client acts on: when to retry, which precondition failed,
/// which field is wrong.
#[test]
fn refusals_keep_their_details() {
    let unavailable = status_of(PasswordOperationError::Unavailable("evaluator"));
    assert_eq!(
        unavailable.message(),
        "password history unavailable: evaluator"
    );
    assert_eq!(
        extract_retry_delay(&unavailable),
        Some(Duration::from_secs(5))
    );

    let limited = status_of(PasswordOperationError::RateLimited);
    assert_eq!(extract_retry_delay(&limited), Some(EVALUATION_WINDOW));

    let precondition = |error: PasswordOperationError| {
        let status = status_of(error);
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
        let status = status_of(error);
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
    let status = status_of(PasswordOperationError::NotPending);
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(reason(&status), "OPERATION_EXPIRED");
}

/// The evaluator's client listener refuses preparation from anyone, since a
/// caller could otherwise create keys for operations it names; Prepare is
/// served only on the internal listener the deployment keeps internal.
#[tokio::test]
async fn a_client_listener_refuses_preparation() {
    let service = PasswordHistoryEvaluatorImpl::new(evaluation().await, Arc::new(ClientListener));
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
    let service =
        PasswordHistoryEvaluatorImpl::new(evaluation().await, Arc::new(InternalTransport));
    let status = service
        .prepare_password_history(Request::new(PreparePasswordHistoryRequest {
            operation_id: Some(PasswordOperationId::generate().into()),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
}

/// A failure of the ceremony store or the result store keeps the status
/// those stores answer with everywhere else.
#[test]
fn store_failures_keep_their_status() {
    let ceremony = status_of(PasswordOperationError::Ceremony(
        sid_authn::challenge_store::ChallengeStoreError::Store(sid_core::Error::Internal(
            "down".into(),
        )),
    ));
    assert_eq!(ceremony.code(), Code::Internal);
    let operation = status_of(PasswordOperationError::Operation(
        sid_authn::operation::OperationError::KeyConflict,
    ));
    assert_eq!(operation.code(), Code::AlreadyExists);
    assert_eq!(reason(&operation), "OPERATION_KEY_CONFLICT");
}
