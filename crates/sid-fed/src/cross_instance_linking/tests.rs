use super::*;

fn ids() -> (BindingId, BindingId, OrgId) {
    (
        BindingId::generate(),
        BindingId::generate(),
        OrgId::generate(),
    )
}

fn proof(nonce: &str) -> CrossInstanceLinkingProof {
    let (a, b, org) = ids();
    create_linking_proof(
        a,
        b,
        org,
        Timestamp::now(),
        true,
        nonce.to_owned(),
        vec![1, 2, 3],
        vec![4, 5, 6],
    )
}

// The statement names both Bindings, the recipient OrgId, the time, the
// revocable flag and the length-prefixed nonce, in that order.
#[test]
fn the_statement_covers_every_field() {
    let (a, b, org) = ids();
    let at = Timestamp::new(1_700_000_000, 123_000_000).unwrap();
    assert_eq!(
        build_linking_statement(&a, &b, &org, &at, false, "n:1"),
        format!("sid:cross-link:v1\n{a}\n{b}\n{org}\n2023-11-14T22:13:20.123Z\n0\n3:n:1")
    );
}

// The signed time is RFC 3339 UTC with the shortest exact fraction: no
// fraction for a whole second, trailing zeros dropped. These are the bytes
// both Bindings sign, so a change of this form fails here instead of
// silently making the stored statements unverifiable.
#[test]
fn the_signed_time_has_one_exact_form() {
    for (nanos, form) in [
        (0, "2023-11-14T22:13:20Z"),
        (500_000_000, "2023-11-14T22:13:20.5Z"),
        (1, "2023-11-14T22:13:20.000000001Z"),
    ] {
        let at = Timestamp::new(1_700_000_000, nanos).unwrap();
        assert_eq!(time(&at), form, "{nanos}");
    }
}

// A nonce carrying the separators cannot reproduce another field tuple: the
// length prefix fixes where it ends.
#[test]
fn free_text_is_unambiguous() {
    let (a, b, org) = ids();
    let at = Timestamp::now();
    assert_ne!(
        build_linking_statement(&a, &b, &org, &at, true, "x\n1"),
        build_linking_statement(&a, &b, &org, &at, true, "x")
    );
    assert_ne!(
        build_linking_statement(&a, &b, &org, &at, true, "n"),
        build_linking_statement(&a, &b, &org, &at, false, "n")
    );
}

// A proof whose outer fields disagree with its signed statement is refused,
// whichever field was changed.
#[test]
fn a_changed_field_breaks_the_statement() {
    let original = proof("nonce");
    assert!(verify_proof_statement(&original));

    let mut changed = original.clone();
    changed.binding_a = BindingId::generate();
    assert!(!verify_proof_statement(&changed));

    let mut changed = original.clone();
    changed.recipient_org = OrgId::generate();
    assert!(!verify_proof_statement(&changed));

    let mut changed = original.clone();
    changed.revocable = false;
    assert!(!verify_proof_statement(&changed));

    let mut changed = original.clone();
    changed.created_at += jiff::SignedDuration::from_nanos(1);
    assert!(!verify_proof_statement(&changed));

    let mut changed = original;
    changed.nonce = "other".into();
    assert!(!verify_proof_statement(&changed));
}

// A link is for its own recipient organization only.
#[test]
fn a_proof_is_for_its_recipient_only() {
    let proof = proof("nonce");
    assert!(verify_proof_recipient(&proof, &proof.recipient_org));
    assert!(!verify_proof_recipient(&proof, &OrgId::generate()));
}

// Either linked Binding can revoke; a third Binding cannot sign a revocation.
#[test]
fn only_a_party_revokes() {
    let (a, b, org) = ids();
    let at = Timestamp::now();
    let revocation =
        create_link_revocation(a, b, org, b, "user_requested".into(), at, vec![7]).unwrap();
    assert_eq!(
        revocation_statement(&revocation),
        format!(
            "sid:cross-unlink:v1\n{a}\n{b}\n{org}\n{b}\n{}\n14:user_requested",
            at
        )
    );
    assert_eq!(
        create_link_revocation(
            a,
            b,
            org,
            BindingId::generate(),
            "user_requested".into(),
            at,
            vec![7]
        )
        .err(),
        Some(LinkingError::NotAParty)
    );
}

#[test]
fn test_link_status_serde() {
    let status = LinkStatus::Active;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"active\"");
    let parsed: LinkStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, LinkStatus::Active);
}

// A proof survives serialization with its statement still matching.
#[test]
fn a_proof_round_trips() {
    let proof = proof("nonce");
    let json = serde_json::to_string(&proof).unwrap();
    let parsed: CrossInstanceLinkingProof = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.recipient_org, proof.recipient_org);
    assert!(verify_proof_statement(&parsed));
}
