// SPDX-License-Identifier: AGPL-3.0-only
//! What a resource reads of a gRPC request for its sender proof.

use tonic::metadata::MetadataValue;

use super::*;

fn request(authorization: Option<&str>, dpop: &[&[u8]]) -> Request<()> {
    let mut request = Request::new(());
    if let Some(value) = authorization {
        request
            .metadata_mut()
            .insert("authorization", value.parse().unwrap());
    }
    for value in dpop {
        request
            .metadata_mut()
            .append("dpop", MetadataValue::try_from(*value).unwrap());
    }
    request
}

/// Both schemes are recognised case-insensitively (RFC 7235 §2.1); anything
/// else, an empty token or no header is no presentation.
#[test]
fn presented_reads_the_scheme() {
    for (header, expected) in [
        ("Bearer t", Some((Scheme::Bearer, "t"))),
        ("bearer t", Some((Scheme::Bearer, "t"))),
        ("DPoP t", Some((Scheme::DPoP, "t"))),
        ("dpop t", Some((Scheme::DPoP, "t"))),
        ("Basic dXNlcjpwYXNz", None),
        ("Bearer ", None),
        ("Bearer", None),
    ] {
        assert_eq!(presented(&request(Some(header), &[])), expected, "{header}");
    }
    assert_eq!(presented(&request(None, &[])), None);
}

/// Every `dpop` value counts, readable or not: a second, unreadable value
/// must not leave the request looking like it carries a single proof.
#[test]
fn proofs_keep_every_value() {
    assert!(proofs(&request(None, &[])).is_empty());
    assert_eq!(proofs(&request(None, &[b"a.b.c"])), ["a.b.c"]);
    let two = request(None, &[b"a.b.c", b"\x80bad"]);
    assert_eq!(proofs(&two).len(), 2);
}

/// A transcoded call is checked against the HTTP request it was made from;
/// a gRPC call against itself, a POST to its RPC path. Scheme and authority
/// always come from the configured origin.
#[test]
fn the_request_target_is_the_request_as_received() {
    const RPC: &str = "/sid.v1.AuthService/OAuth2Token";
    let native = Request::new(());
    assert_eq!(
        request_target(&native, "https://sid.example.com/", RPC),
        RequestTarget {
            method: "POST".into(),
            uri: "https://sid.example.com/sid.v1.AuthService/OAuth2Token".into(),
        }
    );
    let mut transcoded = Request::new(());
    transcoded
        .extensions_mut()
        .insert(TranscodedRequest::new("GET", "/auth/i/abc/oauth2/userinfo"));
    assert_eq!(
        request_target(&transcoded, "https://sid.example.com", RPC),
        RequestTarget {
            method: "GET".into(),
            uri: "https://sid.example.com/auth/i/abc/oauth2/userinfo".into(),
        }
    );
}
