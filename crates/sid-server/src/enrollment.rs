// SPDX-License-Identifier: AGPL-3.0-only
//! The enrollment mode a deployment pins over the stored one
//! (auth/enrollment-policy.md); the policy itself lives in
//! [`sid::enrollment`].

use sid_core::models::EnrollmentMode;

/// The variable that pins the enrollment mode.
pub const PIN_VARIABLE: &str = "SID_ENROLLMENT_MODE";

/// `SID_ENROLLMENT_MODE` as read: unset pins nothing; a value that is not a
/// mode's name stops the start, never read as unset.
pub fn pinned_mode_setting(
    read: Result<String, std::env::VarError>,
) -> anyhow::Result<Option<EnrollmentMode>> {
    crate::init::setting(PIN_VARIABLE, read)?
        .map(|value| {
            value
                .parse()
                .map_err(|e| anyhow::anyhow!("{PIN_VARIABLE}: {e}"))
        })
        .transpose()
}

#[cfg(test)]
mod tests;
