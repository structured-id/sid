// SPDX-License-Identifier: AGPL-3.0-only
//! DNS TXT record verification for Level 1 federation site registration.
//!
//! Verifies domain ownership by checking for a TXT record at
//! `_sid-fed.<domain>` containing `v=sid1; token=<expected_token>`.

use sid_core::models::site_registration::{
    DNS_TXT_PREFIX, DNS_TXT_VERSION, SiteRegistration, VerificationStatus,
};

/// Result of a DNS verification check.
#[derive(Debug)]
pub enum DnsVerifyResult {
    /// Token matched, domain ownership verified.
    Verified,
    /// TXT record found but token did not match.
    TokenMismatch,
    /// No matching TXT record found at the expected name.
    RecordNotFound,
    /// Registration has expired or exceeded max attempts.
    RegistrationExpired,
}

/// Parse DNS TXT record value to extract the token.
///
/// Expected format: `v=sid1; token=<token_value>`
pub fn parse_dns_txt_token(txt_value: &str) -> Option<String> {
    let trimmed = txt_value.trim();

    // Must start with version tag.
    if !trimmed.starts_with(DNS_TXT_VERSION) {
        return None;
    }

    // Find the token= part.
    let remainder = &trimmed[DNS_TXT_VERSION.len()..];
    let remainder = remainder.trim_start_matches(';').trim();

    if let Some(token_value) = remainder.strip_prefix("token=") {
        let token = token_value.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }

    None
}

/// Verify a site registration against a set of DNS TXT record values.
///
/// `txt_records` should contain the TXT record values found at
/// `_sid-fed.<domain>` (already looked up by the caller).
pub fn verify_site_dns(
    registration: &mut SiteRegistration,
    txt_records: &[String],
) -> DnsVerifyResult {
    // Check if registration can still be verified.
    if !registration.can_attempt_verification() {
        if registration.verification_status == VerificationStatus::Verified {
            return DnsVerifyResult::Verified;
        }
        return DnsVerifyResult::RegistrationExpired;
    }

    if registration.is_deadline_expired() {
        registration.mark_expired();
        return DnsVerifyResult::RegistrationExpired;
    }

    if txt_records.is_empty() {
        registration.mark_failed();
        return DnsVerifyResult::RecordNotFound;
    }

    // Check each TXT record for a matching token.
    for txt in txt_records {
        if registration.verify_dns_txt_value(txt) {
            registration.mark_verified();
            return DnsVerifyResult::Verified;
        }
    }

    // Records found but no token match.
    registration.mark_failed();
    DnsVerifyResult::TokenMismatch
}

/// Format the DNS record name to query.
pub fn dns_query_name(domain: &str) -> String {
    format!("{}{}", DNS_TXT_PREFIX, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reg(domain: &str, token: &str) -> SiteRegistration {
        SiteRegistration::new(domain.to_string(), token.to_string())
    }

    #[test]
    fn test_parse_dns_txt_token_valid() {
        let token = parse_dns_txt_token("v=sid1; token=abc123");
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_dns_txt_token_with_whitespace() {
        let token = parse_dns_txt_token("  v=sid1; token=abc123  ");
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_dns_txt_token_wrong_version() {
        let token = parse_dns_txt_token("v=sid2; token=abc123");
        assert_eq!(token, None);
    }

    #[test]
    fn test_parse_dns_txt_token_missing_token() {
        let token = parse_dns_txt_token("v=sid1;");
        assert_eq!(token, None);
    }

    #[test]
    fn test_parse_dns_txt_token_garbage() {
        assert_eq!(parse_dns_txt_token("garbage"), None);
        assert_eq!(parse_dns_txt_token(""), None);
    }

    #[test]
    fn test_verify_site_dns_success() {
        let mut reg = make_reg("example.com", "secret_token");
        let records = vec!["v=sid1; token=secret_token".to_string()];
        let result = verify_site_dns(&mut reg, &records);
        assert!(matches!(result, DnsVerifyResult::Verified));
        assert_eq!(reg.verification_status, VerificationStatus::Verified);
    }

    #[test]
    fn test_verify_site_dns_wrong_token() {
        let mut reg = make_reg("example.com", "secret_token");
        let records = vec!["v=sid1; token=wrong_token".to_string()];
        let result = verify_site_dns(&mut reg, &records);
        assert!(matches!(result, DnsVerifyResult::TokenMismatch));
        assert_eq!(reg.failed_attempts, 1);
    }

    #[test]
    fn test_verify_site_dns_no_records() {
        let mut reg = make_reg("example.com", "secret_token");
        let records: Vec<String> = vec![];
        let result = verify_site_dns(&mut reg, &records);
        assert!(matches!(result, DnsVerifyResult::RecordNotFound));
        assert_eq!(reg.failed_attempts, 1);
    }

    #[test]
    fn test_verify_site_dns_multiple_records_one_match() {
        let mut reg = make_reg("example.com", "secret_token");
        let records = vec![
            "some-other-txt-record".to_string(),
            "v=sid1; token=secret_token".to_string(),
        ];
        let result = verify_site_dns(&mut reg, &records);
        assert!(matches!(result, DnsVerifyResult::Verified));
    }

    #[test]
    fn test_verify_idempotent_after_verified() {
        let mut reg = make_reg("example.com", "token");
        reg.mark_verified();
        let records = vec!["v=sid1; token=token".to_string()];
        let result = verify_site_dns(&mut reg, &records);
        assert!(matches!(result, DnsVerifyResult::Verified));
    }

    #[test]
    fn test_dns_query_name() {
        assert_eq!(dns_query_name("login.acme.com"), "_sid-fed.login.acme.com");
    }
}
