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
