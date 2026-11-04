// SPDX-License-Identifier: AGPL-3.0-only
//! A native client renewing its session (native_session.proto): SID native
//! proofs signed by the test ES256 key, and the refresh generation a
//! response delivers.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use prost::Message;
use sid_proto::sid::v1::NativeCredentialSet;
use tonic::Request;

/// The installation's public origin.
pub const ORIGIN: &str = "https://sid.example.com";

/// The direct gRPC URI of `method` on the AuthService, as a proof names it.
pub fn rpc_uri(method: &str) -> String {
    format!("{ORIGIN}/sid.v1.authn.AuthService/{method}")
}

/// The SID claims a proof binds.
pub enum Binds<'a> {
    /// A ceremony completion echoing `reference`.
    Ceremony(&'a [u8]),
    /// A refresh presenting `credential` in `exchange`.
    Refresh {
        credential: &'a str,
        exchange: &'a [u8],
    },
}

/// A SID native proof for `POST htu`, signed by the test ES256 key.
pub fn proof(htu: &str, binds: Binds<'_>) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
        "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(sid_authn::dpop::NATIVE_PROOF_TYPE.into());
    header.jwk = Some(jwk);
    let mut claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "POST",
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
    });
    match binds {
        Binds::Ceremony(reference) => {
            claims["sid_cer"] = sid_authn::dpop::native_digest(reference).into();
        }
        Binds::Refresh {
            credential,
            exchange,
        } => {
            claims["sid_rt"] = sid_authn::dpop::native_digest(credential.as_bytes()).into();
            claims["sid_ex"] = URL_SAFE_NO_PAD.encode(exchange).into();
        }
    }
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &claims, &key).unwrap()
}

/// `message` carrying `proof` in its native proof metadata.
pub fn with_proof<T>(message: T, proof: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        sid_authn::native_session::PROOF_METADATA,
        proof.parse().unwrap(),
    );
    request
}

/// The refresh generation `response` delivers, if any.
pub fn generation<T>(response: &tonic::Response<T>) -> Option<NativeCredentialSet> {
    response
        .metadata()
        .get_bin(sid_authn::native_session::CREDENTIALS_METADATA)
        .map(|value| NativeCredentialSet::decode(value.to_bytes().unwrap().as_ref()).unwrap())
}
