use super::*;

fn test_secret() -> [u8; 32] {
    [42u8; 32]
}

// ── SID PoW tests ──

#[test]
fn pow_challenge_roundtrip() {
    let provider = SidPowProvider::new(test_secret(), 8, 300);
    let challenge = provider.create_challenge();

    assert_eq!(challenge.provider, "sid_pow");
    assert_eq!(challenge.difficulty, Some(8));
    assert!(!challenge.challenge_id.is_empty());

    // Parse should succeed
    let (prefix, difficulty, _) = provider
        .parse_challenge_token(&challenge.challenge_id)
        .unwrap();
    assert_eq!(difficulty, 8);
    assert!(!prefix.is_empty());
}

#[test]
fn pow_invalid_signature() {
    let provider = SidPowProvider::new(test_secret(), 8, 300);
    let challenge = provider.create_challenge();

    // Tamper with challenge
    let tampered = format!("{}X", challenge.challenge_id);
    assert!(matches!(
        provider.parse_challenge_token(&tampered),
        Err(CaptchaError::InvalidSignature)
    ));
}

#[test]
fn pow_expired_challenge() {
    // TTL = 0 seconds → expires = current second
    let provider = SidPowProvider::new(test_secret(), 8, 0);
    let challenge = provider.create_challenge();

    // Wait until next second so now > expires
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(matches!(
        provider.parse_challenge_token(&challenge.challenge_id),
        Err(CaptchaError::Expired)
    ));
}

#[test]
fn pow_verify_valid_solution() {
    // Use low difficulty (4 bits) for fast test
    let provider = SidPowProvider::new(test_secret(), 4, 300);
    let challenge = provider.create_challenge();
    let (prefix_hex, _, _) = provider
        .parse_challenge_token(&challenge.challenge_id)
        .unwrap();

    // Brute-force find a valid nonce (4 bits = avg 16 attempts)
    let mut nonce = 0u64;
    loop {
        let nonce_str = nonce.to_string();
        if SidPowProvider::verify_pow(&prefix_hex, &nonce_str, 4) {
            // Verify via the provider
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = rt.block_on(provider.verify(&challenge.challenge_id, &nonce_str, None));
            assert!(result.is_ok());
            assert!(result.unwrap().success);
            return;
        }
        nonce += 1;
        if nonce > 10000 {
            panic!("Could not find valid nonce in 10000 attempts for 4-bit difficulty");
        }
    }
}

/// Two replicas over one store load one PoW key, so a challenge issued by
/// one is accepted by the other (each process once drew its own random key,
/// and a challenge failed its signature on every other replica).
#[tokio::test]
async fn challenge_from_one_replica_verifies_on_another() {
    let storage = sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .unwrap();
    let keys = crate::test_support::key_manager();
    let key_a = load_or_create_pow_key(&storage, keys.as_ref())
        .await
        .unwrap();
    let key_b = load_or_create_pow_key(&storage, keys.as_ref())
        .await
        .unwrap();
    let a = SidPowProvider::new(key_a, 4, 300);
    let b = SidPowProvider::new(key_b, 4, 300);

    let challenge = a.create_challenge();
    let (prefix_hex, _, _) = a.parse_challenge_token(&challenge.challenge_id).unwrap();
    let nonce = (0u64..)
        .map(|n| n.to_string())
        .find(|n| SidPowProvider::verify_pow(&prefix_hex, n, 4))
        .unwrap();
    let verification = b
        .verify(&challenge.challenge_id, &nonce, None)
        .await
        .unwrap();
    assert!(verification.success);
}

#[test]
fn pow_reject_invalid_solution() {
    let provider = SidPowProvider::new(test_secret(), 32, 300);
    let challenge = provider.create_challenge();

    // "0" is almost certainly not a valid solution for 32-bit difficulty
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(provider.verify(&challenge.challenge_id, "0", None));
    assert!(matches!(result, Err(CaptchaError::InvalidSolution)));
}

#[test]
fn pow_verify_hash_correctness() {
    // Known hash: SHA256("test0") should have specific leading bits
    let _hash = Sha256::digest(b"test0");
    // Just verify the function counts bits correctly
    assert!(SidPowProvider::verify_pow("test", "0", 0));
    // 256 zero bits would require all zeros — impossible
    assert!(!SidPowProvider::verify_pow("test", "0", 256));
}

// ── Captcha gate tests ──

/// Two replicas over one shared cache and one master key.
fn gates() -> (CaptchaGate, CaptchaGate) {
    let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let keys = crate::test_support::key_manager();
    (
        CaptchaGate::new(cache.clone(), keys.clone()),
        CaptchaGate::new(cache, keys),
    )
}

fn subject(ip: &str) -> CaptchaSubject {
    CaptchaSubject {
        profile_id: sid_core::models::ProfileId::generate(),
        client_ip: Some(ip.parse().unwrap()),
    }
}

/// A challenge asked on one replica, solved on another and redeemed on the
/// first satisfies the sign-in it was asked for.
#[tokio::test]
async fn pass_satisfies_the_sign_in_it_was_asked_for() {
    let (a, b) = gates();
    let who = subject("198.51.100.7");
    a.asked("challenge-1", &who).await.unwrap();

    let pass = b.solved("challenge-1").await.unwrap().expect("pass");
    assert!(a.redeem(&pass, &who).await.unwrap());
}

/// A pass satisfies one requirement: a second use is refused.
#[tokio::test]
async fn pass_is_single_use() {
    let (a, b) = gates();
    let who = subject("198.51.100.7");
    a.asked("challenge-1", &who).await.unwrap();
    let pass = a.solved("challenge-1").await.unwrap().unwrap();

    assert!(b.redeem(&pass, &who).await.unwrap());
    assert!(!a.redeem(&pass, &who).await.unwrap());
}

/// One solution earns one pass: the solved challenge cannot be exchanged
/// again (the PoW challenge itself stays valid for its whole TTL).
#[tokio::test]
async fn solution_is_exchanged_once() {
    let (a, b) = gates();
    a.asked("challenge-1", &subject("198.51.100.7"))
        .await
        .unwrap();

    assert!(a.solved("challenge-1").await.unwrap().is_some());
    assert_eq!(b.solved("challenge-1").await.unwrap(), None);
}

/// A challenge this deployment never asked earns nothing.
#[tokio::test]
async fn unasked_challenge_earns_no_pass() {
    let (a, _) = gates();
    assert_eq!(a.solved("made-up").await.unwrap(), None);
}

/// A pass does not transfer to another profile or another client address,
/// and a refused attempt spends it.
#[tokio::test]
async fn pass_is_bound_to_profile_and_client() {
    let (a, _) = gates();
    let who = subject("198.51.100.7");

    let other_profile = CaptchaSubject {
        profile_id: sid_core::models::ProfileId::generate(),
        ..who.clone()
    };
    let other_client = CaptchaSubject {
        client_ip: Some("203.0.113.9".parse().unwrap()),
        ..who.clone()
    };
    for stranger in [other_profile, other_client] {
        a.asked("challenge-1", &who).await.unwrap();
        let pass = a.solved("challenge-1").await.unwrap().unwrap();
        assert!(!a.redeem(&pass, &stranger).await.unwrap());
        assert!(!a.redeem(&pass, &who).await.unwrap());
    }
}

/// A made-up pass is refused.
#[tokio::test]
async fn unknown_pass_is_refused() {
    let (a, _) = gates();
    assert!(!a.redeem("00ff", &subject("198.51.100.7")).await.unwrap());
}

// ── Factory tests ──

fn settings(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

/// With nothing configured the built-in proof of work is used.
#[test]
fn factory_default_is_pow() {
    let provider = captcha_provider_from(settings(&[]), &test_secret()).unwrap();
    assert_eq!(provider.provider_id(), "sid_pow");
}

/// A third-party provider asked for without its keys stops startup; it used
/// to fall back to the PoW provider with only a warning.
#[test]
fn factory_provider_without_keys_is_an_error() {
    for (name, expected) in [("hcaptcha", "hcaptcha"), ("turnstile", "turnstile")] {
        let err = captcha_provider_from(
            settings(&[
                ("SID_CAPTCHA_PROVIDER", name),
                ("SID_CAPTCHA_SITE_KEY", "site"),
            ]),
            &test_secret(),
        )
        .err()
        .expect("missing secret key");
        assert_eq!(err, CaptchaConfigError::MissingKeys(expected));
    }
}

/// A provider name that matches nothing is an error, not the PoW provider.
#[test]
fn factory_unknown_provider_is_an_error() {
    let err = captcha_provider_from(
        settings(&[("SID_CAPTCHA_PROVIDER", "recaptcha")]),
        &test_secret(),
    )
    .err()
    .expect("unknown provider");
    assert_eq!(err, CaptchaConfigError::UnknownProvider("recaptcha".into()));
}

/// A configured provider with its keys is the one built.
#[test]
fn factory_builds_configured_provider() {
    let provider = captcha_provider_from(
        settings(&[
            ("SID_CAPTCHA_PROVIDER", "turnstile"),
            ("SID_CAPTCHA_SITE_KEY", "site"),
            ("SID_CAPTCHA_SECRET_KEY", "secret"),
        ]),
        &test_secret(),
    )
    .unwrap();
    assert_eq!(provider.provider_id(), "turnstile");
}

/// An unreadable PoW difficulty is refused instead of replaced by 18, and so
/// is one that asks no work (0) or cannot be met (more bits than SHA-256 has).
#[test]
fn factory_invalid_difficulty_is_an_error() {
    for bad in ["hard", "0", "257"] {
        let err = captcha_provider_from(
            settings(&[("SID_CAPTCHA_POW_DIFFICULTY", bad)]),
            &test_secret(),
        )
        .err()
        .expect("bad difficulty");
        assert_eq!(err, CaptchaConfigError::InvalidDifficulty(bad.into()));
    }
}
