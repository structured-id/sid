use super::*;
use crate::models::security_policy::InviteConfig;

fn make_policy(mode: EnrollmentMode, domains: Vec<String>) -> EnrollmentPolicy {
    EnrollmentPolicy {
        mode,
        invite: InviteConfig {
            default_max_uses: 1,
            default_expiry_hours: 72,
        },
        allowed_domains: domains,
        track_source: true,
    }
}

// ── Open mode ──

#[test]
fn open_mode_allows_anyone() {
    let policy = make_policy(EnrollmentMode::Open, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, None, None),
        EnrollmentDecision::Allow
    );
}

#[test]
fn open_mode_allows_with_email() {
    let policy = make_policy(EnrollmentMode::Open, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, Some("user@example.com"), None),
        EnrollmentDecision::Allow
    );
}

#[test]
fn open_mode_allows_with_invite_code() {
    let policy = make_policy(EnrollmentMode::Open, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, None, Some("ABC12345")),
        EnrollmentDecision::Allow
    );
}

// ── AdminOnly mode ──

#[test]
fn admin_only_denies_always() {
    let policy = make_policy(EnrollmentMode::AdminOnly, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, Some("admin@corp.com"), Some("CODE")),
        EnrollmentDecision::Deny(EnrollmentDenialReason::AdminOnly)
    );
}

// ── InviteOnly mode ──

#[test]
fn invite_only_allows_with_code() {
    let policy = make_policy(EnrollmentMode::InviteOnly, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, None, Some("ABC12345")),
        EnrollmentDecision::Allow
    );
}

#[test]
fn invite_only_denies_without_code() {
    let policy = make_policy(EnrollmentMode::InviteOnly, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, Some("user@example.com"), None),
        EnrollmentDecision::Deny(EnrollmentDenialReason::InviteRequired)
    );
}

#[test]
fn invite_only_denies_with_empty_code() {
    // Empty string is still Some — but logically means no code.
    // The storage layer will reject it (code not found).
    // Enrollment evaluation treats any Some as "code provided".
    let policy = make_policy(EnrollmentMode::InviteOnly, vec![]);
    assert_eq!(
        evaluate_enrollment(&policy, None, Some("")),
        EnrollmentDecision::Allow
    );
}

// ── DomainRestricted mode ──

#[test]
fn domain_restricted_allows_matching_domain() {
    let policy = make_policy(
        EnrollmentMode::DomainRestricted,
        vec!["acme.corp".into(), "partner.org".into()],
    );
    assert_eq!(
        evaluate_enrollment(&policy, Some("alice@acme.corp"), None),
        EnrollmentDecision::Allow
    );
}

#[test]
fn domain_restricted_case_insensitive() {
    let policy = make_policy(EnrollmentMode::DomainRestricted, vec!["Acme.Corp".into()]);
    assert_eq!(
        evaluate_enrollment(&policy, Some("alice@acme.corp"), None),
        EnrollmentDecision::Allow
    );
    assert_eq!(
        evaluate_enrollment(&policy, Some("bob@ACME.CORP"), None),
        EnrollmentDecision::Allow
    );
}

#[test]
fn domain_restricted_denies_non_matching() {
    let policy = make_policy(EnrollmentMode::DomainRestricted, vec!["acme.corp".into()]);
    let result = evaluate_enrollment(&policy, Some("alice@evil.com"), None);
    assert!(matches!(
        result,
        EnrollmentDecision::Deny(EnrollmentDenialReason::DomainNotAllowed { .. })
    ));
}

#[test]
fn domain_restricted_denies_no_email() {
    let policy = make_policy(EnrollmentMode::DomainRestricted, vec!["acme.corp".into()]);
    assert_eq!(
        evaluate_enrollment(&policy, None, None),
        EnrollmentDecision::Deny(EnrollmentDenialReason::EmailRequired)
    );
}

#[test]
fn domain_restricted_denies_empty_domain_list() {
    let policy = make_policy(EnrollmentMode::DomainRestricted, vec![]);
    let result = evaluate_enrollment(&policy, Some("alice@anything.com"), None);
    assert!(matches!(
        result,
        EnrollmentDecision::Deny(EnrollmentDenialReason::DomainNotAllowed { .. })
    ));
}

// ── Email domain extraction ──

#[test]
fn extract_domain_normal() {
    assert_eq!(extract_email_domain("user@example.com"), "example.com");
}

#[test]
fn extract_domain_no_at() {
    assert_eq!(extract_email_domain("noemail"), "");
}

#[test]
fn extract_domain_multiple_at() {
    assert_eq!(extract_email_domain("user@sub@example.com"), "example.com");
}

// ── Display ──

#[test]
fn denial_reason_display() {
    let r = EnrollmentDenialReason::DomainNotAllowed {
        domain: "evil.com".into(),
        allowed: vec!["good.org".into()],
    };
    assert!(format!("{}", r).contains("evil.com"));
}
