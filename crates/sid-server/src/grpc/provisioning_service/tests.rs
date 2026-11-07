// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{ConnectorState, ProvisioningConnectorId, ProvisioningCredentialId};
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Provisioning refusals answer with the code and reason clients branch on.
#[test]
fn refusals_keep_their_status() {
    let connector = ProvisioningConnectorId::generate();
    for (refused, code, expected) in [
        (
            ProvisioningError::ConnectorNotFound(connector),
            Code::NotFound,
            "PROVISIONING_CONNECTOR_NOT_FOUND",
        ),
        (
            ProvisioningError::CredentialNotFound(ProvisioningCredentialId::generate()),
            Code::NotFound,
            "CREDENTIAL_NOT_FOUND",
        ),
        (
            ProvisioningError::Outbound(connector),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProvisioningError::ConnectorState {
                id: connector,
                state: ConnectorState::Retired,
                change: "renamed".into(),
            },
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProvisioningError::CredentialStatus {
                id: ProvisioningCredentialId::generate(),
                status: "revoked",
            },
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProvisioningError::QuotaReached(connector),
            Code::ResourceExhausted,
            "QUOTA_EXCEEDED",
        ),
        (
            ProvisioningError::InvalidField {
                field: "kind",
                reason: "scim_bearer or client_secret",
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            ProvisioningError::Internal,
            Code::Internal,
            "INTERNAL_ERROR",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
    let concurrent = refusal(ProvisioningError::ChangedConcurrently);
    let expected = changed_concurrently();
    assert_eq!(concurrent.code(), expected.code());
    assert_eq!(
        extract_error_info(&concurrent).expect("ErrorInfo").0,
        extract_error_info(&expected).expect("ErrorInfo").0
    );
}
