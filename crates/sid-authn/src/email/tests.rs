use super::*;

fn global(input: &str) -> Result<EmailHandle, EmailError> {
    parse(input, &EmailPolicy::GLOBAL_PERSONAL)
}

fn local(input: &str) -> Result<EmailHandle, EmailError> {
    parse(input, &EmailPolicy::LOCAL)
}

/// The documented example: case, dots and tag fold into the key while the
/// delivery address keeps the spelling that was validated.
#[test]
fn personal_key_and_delivery() {
    let handle = global("Ann.Smith+work@Example.COM").unwrap();
    assert_eq!(handle.key, "annsmith@example.com");
    assert_eq!(handle.delivery, "Ann.Smith+work@example.com");
    assert_eq!(handle.revision, EmailPolicy::GLOBAL_PERSONAL.revision);
}

/// An installation's keys carry the revision its storage accepts.
#[test]
fn local_keys_carry_the_installation_revision() {
    assert_eq!(
        local("ann@example.com").unwrap().revision,
        sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION
    );
}

/// Every case/dot/tag spelling of one Personal mailbox has one key.
#[test]
fn personal_variants_share_one_key() {
    let keys: Vec<String> = [
        "annsmith@example.com",
        "Ann.Smith@example.com",
        "a.n.n.s.m.i.t.h@example.com",
        "annsmith+news@example.com",
        "ANN.SMITH+news+more@EXAMPLE.com",
    ]
    .iter()
    .map(|input| global(input).unwrap().key)
    .collect();
    assert!(keys.iter().all(|k| k == "annsmith@example.com"), "{keys:?}");
}

/// Domain dots stay; no provider alias is invented.
#[test]
fn personal_keeps_the_domain() {
    assert_eq!(
        global("a.b@mail.example.co.uk").unwrap().key,
        "ab@mail.example.co.uk"
    );
    assert_eq!(global("a@googlemail.com").unwrap().key, "a@googlemail.com");
}

/// The global Personal namespace admits ASCII only and no IDN in either
/// spelling; nothing is transliterated into an admitted address.
#[test]
fn global_personal_refuses_unicode_and_idn() {
    assert_eq!(
        global("\u{0430}lice@example.com"),
        Err(EmailError::NonAscii)
    );
    assert_eq!(global("alice@münchen.de"), Err(EmailError::NonAscii));
    assert_eq!(
        global("alice@xn--mnchen-3ya.de"),
        Err(EmailError::InternationalizedDomain)
    );
    assert_eq!(
        global("alice@XN--MNCHEN-3YA.de"),
        Err(EmailError::InternationalizedDomain)
    );
}

/// Malformed input is refused, never repaired.
#[test]
fn invalid_addresses_are_refused() {
    for input in [
        "",
        "alice",
        "alice@",
        "@example.com",
        "a..b@example.com",
        ".a@example.com",
        "a b@example.com",
        "Alice <alice@example.com>",
        "alice(comment)@example.com",
        " alice@example.com",
        "alice@[192.0.2.1]",
        "alice@-example.com",
    ] {
        assert!(
            matches!(global(input), Err(EmailError::Invalid(_))),
            "{input:?}: {:?}",
            global(input)
        );
    }
}

/// A leading `+` leaves nothing of the local part: refused, not keyed as an
/// empty handle.
#[test]
fn an_empty_key_is_refused() {
    assert_eq!(global("+tag@example.com"), Err(EmailError::EmptyKey));
    assert_eq!(local("\"...\"@example.com"), Err(EmailError::EmptyKey));
}

/// The whole input is validated before the tag goes: a local part too long
/// with its tag is refused even though its key would be short.
#[test]
fn length_is_checked_before_folding() {
    let long = format!("{}+tag@example.com", "a".repeat(62));
    assert!(matches!(global(&long), Err(EmailError::Invalid(_))));
    let fits = format!("{}+t@example.com", "a".repeat(62));
    assert_eq!(
        global(&fits).unwrap().key,
        format!("{}@example.com", "a".repeat(62))
    );
}

/// A quoted local part is keyed by its semantic content under the same rules,
/// and a key that is not a dot-atom serializes quoted, so distinct keys stay
/// distinct.
#[test]
fn quoted_local_parts() {
    let handle = global("\"A.B+c\"@example.com").unwrap();
    assert_eq!(handle.key, "ab@example.com");
    assert_eq!(
        global("\"a b\"@example.com").unwrap().key,
        "\"a b\"@example.com"
    );
    assert_eq!(
        global("\"a\\\"b\"@example.com").unwrap().key,
        "\"a\\\"b\"@example.com"
    );
    assert_ne!(
        global("\"a b\"@example.com").unwrap().key,
        global("ab@example.com").unwrap().key
    );
}

/// The global namespace requires a public suffix; an installation's own
/// namespace admits internal mail domains.
#[test]
fn public_suffix_only_in_the_global_namespace() {
    assert!(matches!(
        global("alice@example.notarealtld"),
        Err(EmailError::Invalid(_))
    ));
    assert!(matches!(
        global("admin@printer"),
        Err(EmailError::Invalid(_))
    ));
    assert_eq!(local("admin@printer").unwrap().key, "admin@printer");
    assert_eq!(
        local("alice@corp.internal").unwrap().key,
        "alice@corp.internal"
    );
}

/// An installation's own accounts keep internationalized handles under the
/// Personal equality: lowercase, not a confusable skeleton; IDN domains in
/// their A-label form; invalid IDNA refused.
#[test]
fn local_internationalized_handles() {
    let handle = local("\u{00C5}lice.B+x@m\u{00FC}nchen.de").unwrap();
    assert_eq!(handle.key, "\u{00E5}liceb@xn--mnchen-3ya.de");
    assert_eq!(handle.delivery, "\u{00C5}lice.B+x@xn--mnchen-3ya.de");
    assert_ne!(
        local("\u{0430}lice@example.com").unwrap().key,
        local("alice@example.com").unwrap().key,
        "a Cyrillic look-alike is another handle, not its ASCII skeleton"
    );
    assert!(matches!(
        local("alice@\u{200D}.example.com"),
        Err(EmailError::Invalid(_))
    ));
}

/// The Corporate baseline folds like Personal and admits like it, but takes
/// an internal mail domain the global namespace refuses.
#[test]
fn corporate_baseline() {
    let corporate = |input| parse(input, &EmailPolicy::CORPORATE_BASELINE);
    assert_eq!(
        corporate("Ann.Smith+x@corp.internal").unwrap().key,
        "annsmith@corp.internal"
    );
    assert_eq!(
        corporate("\u{00E5}ke@corp.example"),
        Err(EmailError::NonAscii)
    );
    assert_eq!(
        corporate("a@xn--mnchen-3ya.de"),
        Err(EmailError::InternationalizedDomain)
    );
}

/// Each Corporate equality flag works on its own: all eight combinations.
#[test]
fn corporate_flags_are_independent() {
    for bits in 0..8u8 {
        let equality = Equality {
            lowercase_local: bits & 1 != 0,
            ignore_dots: bits & 2 != 0,
            ignore_tag: bits & 4 != 0,
        };
        let policy = EmailPolicy {
            equality,
            admission: EmailPolicy::LOCAL.admission,
            revision: 1,
        };
        let key = parse("Ann.Smith+work@Corp.Example", &policy).unwrap().key;
        let mut local = "Ann.Smith+work".to_string();
        if equality.lowercase_local {
            local = local.to_lowercase();
        }
        if equality.ignore_tag {
            local = local.split('+').next().unwrap().to_string();
        }
        if equality.ignore_dots {
            local = local.replace('.', "");
        }
        assert_eq!(key, format!("{local}@corp.example"), "{equality:?}");
    }
}
