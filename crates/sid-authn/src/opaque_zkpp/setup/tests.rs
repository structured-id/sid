// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// Proofs are required unless explicitly skipped: unset, false or 0 keep
/// them; an empty or unknown value is refused rather than read as either.
#[test]
fn proofs_are_required_unless_explicitly_skipped() {
    let settings = ZkppSettings::parse(None, None, None).unwrap();
    assert!(settings.enabled);
    assert!(settings.config.require_proof);
    assert_eq!(settings.config.policy_version, 1);
    for skip in ["true", "1"] {
        let settings = ZkppSettings::parse(None, Some(skip), None).unwrap();
        assert!(settings.enabled && !settings.config.require_proof);
    }
    for keep in ["false", "0"] {
        assert!(
            ZkppSettings::parse(None, Some(keep), None)
                .unwrap()
                .config
                .require_proof
        );
    }
    for unclear in ["", " ", "yes", "TRUE", "off"] {
        assert_eq!(
            ZkppSettings::parse(None, Some(unclear), None).unwrap_err(),
            ZkppSettingsError::NotBoolean("SID_ZKPP_SKIP_PROOF"),
            "{unclear:?}"
        );
        assert_eq!(
            ZkppSettings::parse(Some(unclear), None, None).unwrap_err(),
            ZkppSettingsError::NotBoolean("SID_ZKPP_ENABLED"),
            "{unclear:?}"
        );
    }
}

/// Without verifiers no proof can be checked: that is accepted only with an
/// explicit skip, never by turning the verifiers off alone.
#[test]
fn disabled_verifiers_need_an_explicit_skip() {
    for skip in [None, Some("false")] {
        assert_eq!(
            ZkppSettings::parse(Some("false"), skip, None).unwrap_err(),
            ZkppSettingsError::ProofsWithoutVerifiers
        );
    }
    let settings = ZkppSettings::parse(Some("false"), Some("true"), None).unwrap();
    assert!(!settings.enabled && !settings.config.require_proof);
}

/// A policy version is an unsigned number naming a known policy; anything
/// else is refused, never silently replaced by another policy.
#[test]
fn the_policy_version_must_name_a_known_policy() {
    for malformed in ["", "garbage", "-1", "4294967296"] {
        assert_eq!(
            ZkppSettings::parse(None, None, Some(malformed)).unwrap_err(),
            ZkppSettingsError::MalformedPolicyVersion,
            "{malformed:?}"
        );
    }
    for unknown in ["0", "2"] {
        assert_eq!(
            ZkppSettings::parse(None, None, Some(unknown)).unwrap_err(),
            ZkppSettingsError::UnknownPolicyVersion,
            "{unknown:?}"
        );
    }
    assert_eq!(
        ZkppSettings::parse(None, None, Some("1"))
            .unwrap()
            .config
            .policy_version,
        1
    );
}
