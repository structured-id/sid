use super::*;
use sid_core::models::ProfileId;

fn session(level: AuthLevel, authenticated_minutes_ago: i64) -> Session {
    let now = Utc::now();
    let mut session = Session::new(
        ProfileId::generate(),
        "127.0.0.1".into(),
        now + chrono::Duration::hours(24),
    );
    session.assurance_level = level;
    session.authenticated_at = now - chrono::Duration::minutes(authenticated_minutes_ago);
    session
}

fn credentials(types: &[CredentialType]) -> Vec<Credential> {
    let pid = ProfileId::generate();
    types
        .iter()
        .map(|t| Credential::new(pid, *t, vec![1], None))
        .collect()
}

/// A password-only account enrolls its first stronger factor after its
/// password login: no factor it never had is demanded.
#[test]
fn password_only_account_enrolls_first_strong_factor() {
    let account = credentials(&[CredentialType::Opaque]);
    for new in [CredentialType::WebAuthn, CredentialType::Totp] {
        assert_eq!(
            check_enrollment(
                &session(AuthLevel::Basic, 5),
                &account,
                new,
                true,
                Utc::now()
            ),
            Ok(())
        );
    }
}

/// An account protected by a passkey refuses a new passkey or TOTP from a
/// password-only session (the email-reset → password → passkey bypass).
#[test]
fn strong_account_refuses_password_session() {
    let account = credentials(&[CredentialType::Opaque, CredentialType::WebAuthn]);
    for new in [CredentialType::WebAuthn, CredentialType::Totp] {
        assert_eq!(
            check_enrollment(
                &session(AuthLevel::Basic, 5),
                &account,
                new,
                true,
                Utc::now()
            ),
            Err(EnrollmentRefusal::Insufficient {
                required: AuthLevel::Standard
            })
        );
    }
    // A password change needs only the password's own level.
    assert_eq!(
        check_enrollment(
            &session(AuthLevel::Basic, 5),
            &account,
            CredentialType::Opaque,
            true,
            Utc::now()
        ),
        Ok(())
    );
}

/// A fresh sufficient authentication is reused: no duplicate ceremony.
#[test]
fn fresh_sufficient_session_enrolls() {
    let account = credentials(&[CredentialType::Opaque, CredentialType::Totp]);
    assert_eq!(
        check_enrollment(
            &session(AuthLevel::Standard, 10),
            &account,
            CredentialType::WebAuthn,
            true,
            Utc::now()
        ),
        Ok(())
    );
}

/// An authentication older than the freshness window must be repeated.
#[test]
fn stale_session_refuses() {
    let account = credentials(&[CredentialType::Opaque, CredentialType::Totp]);
    assert_eq!(
        check_enrollment(
            &session(AuthLevel::Standard, 61),
            &account,
            CredentialType::WebAuthn,
            true,
            Utc::now()
        ),
        Err(EnrollmentRefusal::Stale {
            required: AuthLevel::Standard
        })
    );
}

/// Mailbox possession never binds a credential, whatever the account holds.
#[test]
fn provisional_session_refuses() {
    let mut provisional = Session::new_provisional(ProfileId::generate(), "127.0.0.1".into());
    provisional.assurance_level = AuthLevel::Critical;
    for account in [
        credentials(&[]),
        credentials(&[CredentialType::Opaque]),
        credentials(&[CredentialType::WebAuthn]),
    ] {
        assert_eq!(
            check_enrollment(
                &provisional,
                &account,
                CredentialType::WebAuthn,
                true,
                Utc::now()
            ),
            Err(EnrollmentRefusal::Provisional)
        );
    }
}

fn change(
    session: &Session,
    rule: CurrentPasswordRule,
    proven: bool,
) -> Result<(), EnrollmentRefusal> {
    check_password_change(
        session,
        &credentials(&[CredentialType::Opaque]),
        true,
        rule,
        proven,
        Utc::now(),
    )
}

/// By default every change proves the current password: a fresh session
/// alone does not replace it (OWASP ASVS V6.2.3).
#[test]
fn always_rule_requires_the_current_password() {
    let fresh = session(AuthLevel::Basic, 0);
    let now = Utc::now();
    assert_eq!(
        current_password_required_in(&fresh, CurrentPasswordRule::Always, now),
        chrono::Duration::zero()
    );
    assert_eq!(
        change(&fresh, CurrentPasswordRule::Always, false),
        Err(EnrollmentRefusal::CurrentPasswordRequired)
    );
    assert_eq!(change(&fresh, CurrentPasswordRule::Always, true), Ok(()));
}

/// A relaxed rule skips the current password while the session's last
/// authentication is recent, and says exactly how long that lasts.
#[test]
fn relaxed_rule_counts_down_from_the_last_authentication() {
    let rule = CurrentPasswordRule::AfterMinutes(5);
    let recent = session(AuthLevel::Basic, 2);
    let now = Utc::now();
    let left = current_password_required_in(&recent, rule, now);
    assert_eq!(
        left,
        recent.authenticated_at + chrono::Duration::minutes(5) - now
    );
    assert!(left > chrono::Duration::minutes(2));
    assert_eq!(change(&recent, rule, false), Ok(()));

    let older = session(AuthLevel::Basic, 6);
    assert_eq!(
        current_password_required_in(&older, rule, Utc::now()),
        chrono::Duration::zero()
    );
    assert_eq!(
        change(&older, rule, false),
        Err(EnrollmentRefusal::CurrentPasswordRequired)
    );
    assert_eq!(change(&older, rule, true), Ok(()));
}

/// A relaxed rule never outlasts the credential-binding freshness window.
#[test]
fn relaxed_rule_is_bounded_by_the_freshness_window() {
    let rule = CurrentPasswordRule::AfterMinutes(180);
    let stale = session(AuthLevel::Basic, 70);
    assert_eq!(
        current_password_required_in(&stale, rule, Utc::now()),
        chrono::Duration::zero()
    );
    assert_eq!(
        change(&stale, rule, false),
        Err(EnrollmentRefusal::CurrentPasswordRequired)
    );
    // The proof is itself a fresh authentication.
    assert_eq!(change(&stale, rule, true), Ok(()));
}

/// A proof sent while none was required is accepted: client and server
/// clocks may disagree slightly, and the stronger request is never refused.
#[test]
fn proof_is_accepted_when_not_required() {
    let recent = session(AuthLevel::Basic, 1);
    assert_eq!(
        change(&recent, CurrentPasswordRule::AfterMinutes(5), true),
        Ok(())
    );
}

/// The current password lifts no other condition: mailbox possession still
/// changes nothing.
#[test]
fn proof_does_not_lift_a_provisional_session() {
    let provisional = Session::new_provisional(ProfileId::generate(), "127.0.0.1".into());
    assert_eq!(
        change(&provisional, CurrentPasswordRule::Always, true),
        Err(EnrollmentRefusal::Provisional)
    );
}

/// A passkey counts as a second factor only where policy says so.
#[test]
fn passkey_assurance_follows_policy() {
    assert_eq!(
        credential_assurance(CredentialType::WebAuthn, true),
        AuthLevel::Standard
    );
    assert_eq!(
        credential_assurance(CredentialType::WebAuthn, false),
        AuthLevel::Basic
    );
    assert_eq!(
        established_assurance(&credentials(&[CredentialType::WebAuthn]), false),
        AuthLevel::Basic
    );
    assert_eq!(established_assurance(&[], true), AuthLevel::Basic);
}
