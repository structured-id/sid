// SPDX-License-Identifier: AGPL-3.0-only
//! Which platform a build is made for, from what its builder gave. Shared
//! by the build script and the crate's tests.

/// The production platform's public origin.
pub const PRODUCTION: &str = "https://structured.id";

/// The development platform's public origin.
pub const DEVELOPMENT: &str = "https://dev.structured.id";

/// The platform origin a build is made for.
///
/// `origin` is `SID_BUILD_PLATFORM`, the origin itself, as the build of an
/// official delivery gives it. `dev` is `SID_BUILD_PLATFORM_DEV`, the one
/// flag of a local publication made for the platform: `false` selects
/// production and `true` development. Neither given: a build for no
/// platform. Both given must agree: a build never names two platforms.
pub fn selected(origin: Option<&str>, dev: Option<&str>) -> Result<Option<String>, String> {
    let flagged = match dev {
        None => None,
        Some("false") => Some(PRODUCTION),
        Some("true") => Some(DEVELOPMENT),
        Some(other) => {
            return Err(format!(
                "SID_BUILD_PLATFORM_DEV is {other:?}: it takes true (the development \
                 platform) or false (production)"
            ));
        }
    };
    match (origin, flagged) {
        (Some(origin), Some(flagged)) if origin != flagged => Err(format!(
            "SID_BUILD_PLATFORM names {origin} and SID_BUILD_PLATFORM_DEV selects {flagged}: \
             give one of them"
        )),
        (Some(origin), _) => Ok(Some(origin.to_owned())),
        (None, flagged) => Ok(flagged.map(str::to_owned)),
    }
}
