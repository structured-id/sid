// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// Unset pins nothing; a mode's name pins it; anything else stops the start
/// instead of leaving registration open by accident.
#[test]
fn test_pinned_mode_setting() {
    assert_eq!(
        pinned_mode_setting(Err(std::env::VarError::NotPresent)).unwrap(),
        None
    );
    assert_eq!(
        pinned_mode_setting(Ok("admin_only".into())).unwrap(),
        Some(EnrollmentMode::AdminOnly)
    );
    assert!(pinned_mode_setting(Ok("closed".into())).is_err());
    assert!(pinned_mode_setting(Ok(String::new())).is_err());
    assert!(
        pinned_mode_setting(Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::new()
        )))
        .is_err()
    );
}
