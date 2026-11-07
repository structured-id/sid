// SPDX-License-Identifier: AGPL-3.0-only
use sid_authn::password_operation::OperationPurpose as _;
use sid_core::models::{CredentialId, ProfileId, ResetSessionId};

use super::OperationPurpose;

fn change() -> OperationPurpose {
    OperationPurpose::Change {
        profile_id: ProfileId::generate(),
        credential_id: CredentialId(uuid::Uuid::now_v7()),
        password: [5; 16],
    }
}

/// Every purpose names the method of its durable result: a registration, a
/// change and a reset are different commands under one operation key.
#[test]
fn every_purpose_names_its_method() {
    assert_eq!(change().method(), "change");
    assert_eq!(
        OperationPurpose::Reset {
            session: ResetSessionId(uuid::Uuid::now_v7()),
        }
        .method(),
        "reset"
    );
}
