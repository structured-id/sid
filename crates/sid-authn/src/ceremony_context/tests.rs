// SPDX-License-Identifier: AGPL-3.0-only
//! A context continues only for the client and transport that opened it,
//! by its own secret and, for the browser, its own CSRF token.

use chrono::Duration;

use super::*;

fn cookie() -> BrowserCookie {
    BrowserCookie::new("__Host-sid_registration").unwrap()
}

/// A browser context: the secret its cookie holds and its CSRF token, as the
/// start delivered them.
fn browser() -> (BrowserSecret, String, CeremonyBinding) {
    let (context, binding) = CeremonyContext::open(CeremonyClient::Browser);
    let headers = context.headers(&cookie(), Utc::now() + Duration::minutes(10));
    let [("set-cookie", set), (CSRF_HEADER, csrf)] = headers.as_slice() else {
        panic!("a browser gets its cookie and CSRF token: {headers:?}");
    };
    let pair = set.split(';').next().unwrap();
    (cookie().secret([pair]).unwrap(), csrf.clone(), binding)
}

fn native() -> (BrowserSecret, CeremonyBinding) {
    let (context, binding) = CeremonyContext::open(CeremonyClient::Native);
    let headers = context.headers(&cookie(), Utc::now() + Duration::minutes(10));
    let [("authorization", bearer)] = headers.as_slice() else {
        panic!("a native client gets its bearer: {headers:?}");
    };
    let secret = bearer.strip_prefix("Bearer ").unwrap();
    (BrowserSecret::decode(secret).unwrap(), binding)
}

/// The browser that started continues with its secret and CSRF token; a
/// native client with its secret.
#[test]
fn the_starting_client_continues() {
    let (secret, csrf, binding) = browser();
    binding
        .admit(CeremonyClient::Browser, Some(secret), [csrf.as_str()])
        .unwrap();
    let (secret, binding) = native();
    binding
        .admit(CeremonyClient::Native, Some(secret), [])
        .unwrap();
}

/// Another context's secret or none is not held; the browser's secret
/// without its own token, once, is refused for the token.
#[test]
fn a_foreign_secret_or_token_is_refused() {
    let (secret, csrf, binding) = browser();
    let (other, other_csrf, _) = browser();
    assert_eq!(
        binding.admit(CeremonyClient::Browser, Some(other), [csrf.as_str()]),
        Err(CeremonyRefusal::NotHeld)
    );
    assert_eq!(
        binding.admit(CeremonyClient::Browser, None, [csrf.as_str()]),
        Err(CeremonyRefusal::NotHeld)
    );
    for sent in [
        vec![],
        vec![other_csrf.as_str()],
        vec![csrf.as_str(), csrf.as_str()],
    ] {
        assert_eq!(
            binding.admit(
                CeremonyClient::Browser,
                BrowserSecret::decode(secret.encode().as_str()),
                sent.clone()
            ),
            Err(CeremonyRefusal::Csrf),
            "{sent:?}"
        );
    }
}

/// A context continues only over the transport it was opened for.
#[test]
fn the_transport_must_match() {
    let (secret, _, binding) = browser();
    assert_eq!(
        binding.admit(CeremonyClient::Native, Some(secret), []),
        Err(CeremonyRefusal::NotHeld)
    );
    let (secret, binding) = native();
    assert_eq!(
        binding.admit(CeremonyClient::Browser, Some(secret), []),
        Err(CeremonyRefusal::NotHeld)
    );
}

/// The binding survives storage with its operation and keeps checking; its
/// debug output shows neither hash nor token.
#[test]
fn binding_round_trips_and_redacts() {
    let (secret, csrf, binding) = browser();
    let stored: CeremonyBinding =
        serde_json::from_str(&serde_json::to_string(&binding).unwrap()).unwrap();
    stored
        .admit(CeremonyClient::Browser, Some(secret), [csrf.as_str()])
        .unwrap();
    assert_eq!(
        format!("{stored:?}"),
        "CeremonyBinding { browser: true, .. }"
    );
}
