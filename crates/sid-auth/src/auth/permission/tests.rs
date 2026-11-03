use super::*;

/// A confirmation names the proof's key, method and `htu` without query or
/// fragment (RFC 9449 §4.2), identifies the request with 16 bytes, carries
/// the proof's `jti` and `iat` for the issuer to admit, and is usable for its
/// short window only, never past the token's expiry.
#[test]
fn test_dpop_confirmation() {
    use sid_proto::sid::v1::authn::SenderProofProfile;
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let proof = sid_authn::dpop::VerifiedProof {
        jti: "proof-1".into(),
        iat: now.timestamp() - 2,
    };
    let c = dpop_confirmation(
        "jkt-1",
        "GET",
        "https://orders.example/read/1?page=2#top",
        now.timestamp() + 3600,
        &proof,
        now,
    );
    assert_eq!(c.profile, i32::from(SenderProofProfile::Dpop));
    assert_eq!(c.jkt, "jkt-1");
    assert_eq!(c.method, "GET");
    assert_eq!(c.uri, "https://orders.example/read/1");
    assert_eq!(c.request_id.len(), 16);
    assert_eq!(c.proof_jti, "proof-1");
    assert_eq!(c.proof_iat.unwrap().seconds, now.timestamp() - 2);
    let verified = c.verified_at.unwrap().seconds;
    assert_eq!(verified, now.timestamp());
    assert_eq!(c.valid_until.unwrap().seconds, verified + 30);

    let expiring = dpop_confirmation(
        "jkt-1",
        "GET",
        "https://o.example/",
        verified + 10,
        &proof,
        now,
    );
    assert_eq!(expiring.valid_until.unwrap().seconds, verified + 10);
    assert_ne!(
        c.request_id, expiring.request_id,
        "each incoming request gets its own identifier"
    );
}
