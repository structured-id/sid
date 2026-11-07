use super::*;

/// Only OIDC and OAuth2 are protocols; unspecified or unknown is refused.
#[test]
fn test_protocol_proto_roundtrip() {
    for protocol in [DomainUpstreamProtocol::Oidc, DomainUpstreamProtocol::OAuth2] {
        assert_eq!(
            protocol_from_proto(protocol_to_proto(protocol)).unwrap(),
            protocol
        );
    }
    for bad in [0, 99] {
        assert!(matches!(
            protocol_from_proto(bad),
            Err(UpstreamError::InvalidField {
                field: "protocol",
                ..
            })
        ));
    }
}

/// Every trust category maps both ways; unspecified is social.
#[test]
fn test_trust_proto_roundtrip() {
    for category in [
        ProviderTrustCategory::Social,
        ProviderTrustCategory::Corporate,
        ProviderTrustCategory::Government,
        ProviderTrustCategory::Financial,
    ] {
        assert_eq!(trust_from_proto(trust_to_proto(category)), category);
    }
    assert_eq!(trust_from_proto(0), ProviderTrustCategory::Social);
}

#[test]
fn test_optional() {
    assert_eq!(optional(""), None);
    assert_eq!(optional("x"), Some("x".to_string()));
}

/// The answer and the sign-in page show a provider without its secret.
#[test]
fn test_provider_views_carry_no_secret() {
    let secret = sid_keys::EncryptedField {
        ciphertext: vec![7; 32],
        nonce: [3; 12],
        key_version: 1,
        context: "upstream:test".into(),
    };
    let mut provider =
        DomainUpstreamProvider::new("Example", DomainUpstreamProtocol::Oidc, "client", secret);
    provider.logo_url = Some("https://sid.example.com/logo.svg".into());
    let proto = provider_to_proto(&provider);
    assert_eq!(proto.client_id, "client");
    assert_eq!(proto.protocol, v1::UpstreamProtocol::Oidc as i32);
    assert_eq!(proto.logo_url, "https://sid.example.com/logo.svg");
    let public = provider_to_enabled_info(&provider);
    assert_eq!(public.name, "Example");
    assert_eq!(public.id, proto.id);
}
