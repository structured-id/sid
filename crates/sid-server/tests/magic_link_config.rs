// SPDX-License-Identifier: AGPL-3.0-only
//! Instance setting that enables magic links (`SID_MAGIC_LINKS_ENABLED`).

use sid_core::models::{AuthLevel, SecurityPolicy};
use sid_server::init::magic_links_enabled;

/// Magic links stay off when the setting is absent or false.
#[test]
fn magic_links_off_by_default() {
    let policy = SecurityPolicy::ce_default();
    assert!(!magic_links_enabled(None, &policy).unwrap());
    assert!(!magic_links_enabled(Some("false"), &policy).unwrap());
}

/// `true` enables them on a basic-assurance site.
#[test]
fn magic_links_enabled_on_basic_site() {
    let policy = SecurityPolicy::ce_default();
    assert!(policy.permits_magic_links());
    assert!(magic_links_enabled(Some("true"), &policy).unwrap());
}

/// An unrecognised value is a configuration error, not a silent default.
#[test]
fn magic_links_reject_unknown_value() {
    let policy = SecurityPolicy::ce_default();
    for value in ["1", "yes", "TRUE", ""] {
        assert!(
            magic_links_enabled(Some(value), &policy).is_err(),
            "{value:?}"
        );
    }
}

/// A site requiring more than basic assurance cannot enable magic links.
#[test]
fn magic_links_refused_above_basic_assurance() {
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = AuthLevel::Standard;
    assert!(!policy.permits_magic_links());
    assert!(magic_links_enabled(Some("true"), &policy).is_err());
    assert!(!magic_links_enabled(Some("false"), &policy).unwrap());
}
