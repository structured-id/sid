// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use tonic::Code;

/// A label is trimmed; an empty or overlong one is refused.
#[test]
fn a_display_name_is_one_to_two_hundred_characters() {
    assert_eq!(display_name("  HR sync ").unwrap(), "HR sync");
    for bad in ["", "   ", &"x".repeat(201)] {
        assert_eq!(display_name(bad).unwrap_err().code(), Code::InvalidArgument);
    }
    assert!(display_name(&"é".repeat(200)).is_ok());
}

/// An expiry is a time in the future; a past one or one with invalid nanos
/// is refused, never replaced.
#[test]
fn an_expiry_is_a_future_time() {
    assert_eq!(future_expiry(None).unwrap(), None);
    let future = prost_types::Timestamp {
        seconds: Utc::now().timestamp() + 3600,
        nanos: 0,
    };
    assert!(future_expiry(Some(future)).unwrap().is_some());
    for bad in [
        prost_types::Timestamp {
            seconds: Utc::now().timestamp() - 60,
            nanos: 0,
        },
        prost_types::Timestamp {
            seconds: Utc::now().timestamp() + 3600,
            nanos: -1,
        },
        prost_types::Timestamp {
            seconds: Utc::now().timestamp() + 3600,
            nanos: 2_000_000_000,
        },
    ] {
        assert_eq!(
            future_expiry(Some(bad)).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
}

/// Only the three lifecycle states are targets; UNSPECIFIED and unknown
/// numbers are refused.
#[test]
fn a_target_state_is_named() {
    for (proto, domain) in [
        (
            pb::ProvisioningConnectorState::Active,
            ConnectorState::Active,
        ),
        (
            pb::ProvisioningConnectorState::Disabled,
            ConnectorState::Disabled,
        ),
        (
            pb::ProvisioningConnectorState::Retired,
            ConnectorState::Retired,
        ),
    ] {
        assert_eq!(state_from_proto(proto.into()).unwrap(), domain);
        assert_eq!(state_to_proto(domain), proto);
    }
    for bad in [0, 99] {
        assert_eq!(
            state_from_proto(bad).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
}

/// An issued credential carries the prefix of its kind and matches its
/// verifier; the result recorded for retries holds no secret.
#[test]
fn an_issued_secret_is_never_recorded() {
    let connector = ProvisioningConnectorId::generate();
    for kind in [
        ConnectorCredentialKind::ScimBearer,
        ConnectorCredentialKind::ClientSecret,
    ] {
        let (credential, secret, recorded) = issue(connector, kind, None);
        assert!(secret.starts_with(kind.secret_prefix()), "{secret}");
        assert!(bearer_secret::matches(&secret, &credential.verifier));
        assert_eq!(credential.connector_id, connector);
        assert_eq!(credential.kind, kind);
        assert_eq!(credential.status, CredentialStatus::Active);
        assert!(recorded.secret.is_empty());
        let recorded = recorded.credential.unwrap();
        assert_eq!(
            recorded.id,
            Some(ids::ProvisioningCredentialId::from(credential.id))
        );
        assert_eq!(recorded.kind, kind_to_proto(kind) as i32);
    }
}

/// A credential's kind is named; UNSPECIFIED and unknown numbers are
/// refused.
#[test]
fn a_credential_kind_is_named() {
    for kind in [
        ConnectorCredentialKind::ScimBearer,
        ConnectorCredentialKind::ClientSecret,
    ] {
        assert_eq!(kind_from_proto(kind_to_proto(kind).into()).unwrap(), kind);
    }
    for bad in [0, 99] {
        assert_eq!(
            kind_from_proto(bad).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
}

/// A connector or credential identifier that is absent or not 16 bytes of a
/// UUIDv7 is refused before any lookup.
#[test]
fn identifiers_are_checked() {
    assert_eq!(
        connector_id(None).unwrap_err().code(),
        Code::InvalidArgument
    );
    let short = ids::ProvisioningConnectorId { value: vec![1; 15] };
    assert_eq!(
        connector_id(Some(&short)).unwrap_err().code(),
        Code::InvalidArgument
    );
    let id = ProvisioningConnectorId::generate();
    assert_eq!(connector_id(Some(&id.into())).unwrap(), id);
    assert_eq!(
        credential_id(None).unwrap_err().code(),
        Code::InvalidArgument
    );
    let cred = ProvisioningCredentialId::generate();
    assert_eq!(credential_id(Some(&cred.into())).unwrap(), cred);
}
