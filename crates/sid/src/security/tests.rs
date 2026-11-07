use super::*;

fn violation() -> pb::PolicyViolation {
    pb::PolicyViolation {
        requirement: "r".into(),
        current: "c".into(),
        required: "q".into(),
    }
}

fn action(kind: &str) -> pb::PolicyRequiredAction {
    pb::PolicyRequiredAction {
        action_type: kind.into(),
        description: String::new(),
    }
}

/// No violation allows under every mode; with violations audit allows, soft
/// grants grace, and hard steps up only when a step-up alone clears them.
#[test]
fn test_enforcement_action() {
    for mode in [
        EnforcementMode::Audit,
        EnforcementMode::Soft,
        EnforcementMode::Hard,
    ] {
        assert_eq!(
            enforcement_action(mode, &[], &[]),
            pb::EnforcementAction::Allow
        );
    }
    let v = [violation()];
    assert_eq!(
        enforcement_action(EnforcementMode::Audit, &v, &[action("enroll_mfa")]),
        pb::EnforcementAction::Allow
    );
    assert_eq!(
        enforcement_action(EnforcementMode::Soft, &v, &[action("enroll_mfa")]),
        pb::EnforcementAction::Grace
    );
    assert_eq!(
        enforcement_action(EnforcementMode::Hard, &v, &[action("step_up_auth")]),
        pb::EnforcementAction::StepUp
    );
    assert_eq!(
        enforcement_action(
            EnforcementMode::Hard,
            &v,
            &[action("step_up_auth"), action("enroll_mfa")]
        ),
        pb::EnforcementAction::Block
    );
}

/// An address is a single-host block; anything else that is not a CIDR
/// block is refused on its field.
#[test]
fn test_parse_cidr() {
    assert_eq!(parse_cidr("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
    assert_eq!(parse_cidr("192.0.2.1").unwrap().to_string(), "192.0.2.1/32");
    assert_eq!(
        parse_cidr("2001:db8::1").unwrap().to_string(),
        "2001:db8::1/128"
    );
    for bad in ["", "10.0.0.0/33", "example.com", "10.0.0"] {
        assert!(
            matches!(
                parse_cidr(bad),
                Err(SecurityError::InvalidField { field: "cidr", .. })
            ),
            "{bad:?} accepted"
        );
    }
}

/// The reported CE policy is read-only and carries the fixed limits.
#[test]
fn test_ce_policy_report() {
    let policy = ce_security_policy_response();
    assert!(policy.read_only);
    assert_eq!(policy.password_min_length, CE_PASSWORD_MIN_LENGTH as i32);
    assert!(policy.network.is_some());
    assert_eq!(ce_password_policy().rules.len(), 6);
    let rules = ce_anomaly_rules();
    assert_eq!(rules.len(), 8);
    let mut ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 8, "rule ids are unique");
}
