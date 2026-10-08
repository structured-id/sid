// SPDX-License-Identifier: AGPL-3.0-only
//! Access-token lifetime: five minutes by default, configurable from one to
//! sixty minutes, nothing outside that range.

use sid_authn::jwt::{AccessTokenTtl, JwtService};

fn jwt() -> JwtService {
    JwtService::new(
        include_bytes!("fixtures/test_ed25519_private.pem"),
        include_bytes!("fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".to_string(),
    )
    .expect("JWT service")
}

#[test]
fn default_lifetime_is_five_minutes() {
    assert_eq!(jwt().access_token_ttl_secs(), 300);
}

#[test]
fn configured_lifetime_within_range_applies() {
    for minutes in [1, 15, 60] {
        let ttl = AccessTokenTtl::from_minutes(minutes).unwrap();
        assert_eq!(
            jwt().with_access_token_ttl(ttl).access_token_ttl_secs(),
            i64::from(minutes) * 60
        );
    }
}

#[test]
fn lifetime_outside_range_is_refused() {
    for minutes in [0, 61, 1440, u32::MAX] {
        assert!(
            AccessTokenTtl::from_minutes(minutes).is_err(),
            "{minutes} minutes accepted"
        );
    }
}
