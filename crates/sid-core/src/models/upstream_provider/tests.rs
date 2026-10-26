use super::*;

fn make_encrypted_secret() -> EncryptedField {
    EncryptedField {
        ciphertext: vec![1, 2, 3],
        nonce: [0; 12],
        key_version: 1,
        context: "upstream:test".into(),
    }
}

#[test]
fn test_provider_new_defaults() {
    let provider = UpstreamProvider::new(
        "Google",
        UpstreamProtocol::Oidc,
        "client123",
        make_encrypted_secret(),
    );
    assert_eq!(provider.name, "Google");
    assert_eq!(provider.protocol, UpstreamProtocol::Oidc);
    assert_eq!(provider.client_id, "client123");
    assert!(provider.enabled);
    assert_eq!(provider.trust_category, ProviderTrustCategory::Social);
    assert_eq!(provider.scopes, vec!["openid", "profile", "email"]);
    assert!(provider.show_on_login);
    assert_eq!(provider.display_order, 0);
    assert!(provider.discovery_url.is_none());
    assert!(provider.logo_url.is_none());
}

#[test]
fn test_provider_with_discovery() {
    let provider = UpstreamProvider::new(
        "Okta",
        UpstreamProtocol::Oidc,
        "okta-client",
        make_encrypted_secret(),
    )
    .with_discovery_url("https://sid.example.com/.well-known/openid-configuration");

    assert!(provider.uses_discovery());
    assert_eq!(
        provider.discovery_url.as_deref(),
        Some("https://sid.example.com/.well-known/openid-configuration")
    );
}

#[test]
fn test_provider_without_discovery() {
    let provider = UpstreamProvider::new(
        "GitHub",
        UpstreamProtocol::OAuth2,
        "gh-client",
        make_encrypted_secret(),
    );
    assert!(!provider.uses_discovery());
}

#[test]
fn test_provider_with_trust_category() {
    let provider = UpstreamProvider::new(
        "Azure AD",
        UpstreamProtocol::Oidc,
        "az-client",
        make_encrypted_secret(),
    )
    .with_trust_category(ProviderTrustCategory::Corporate);

    assert_eq!(provider.trust_category, ProviderTrustCategory::Corporate);
}

#[test]
fn test_trust_category_assurance_mapping() {
    assert_eq!(
        ProviderTrustCategory::Social.default_assurance(),
        AssuranceLevel::Loa1
    );
    assert_eq!(
        ProviderTrustCategory::Corporate.default_assurance(),
        AssuranceLevel::Loa2
    );
    assert_eq!(
        ProviderTrustCategory::Financial.default_assurance(),
        AssuranceLevel::Loa3
    );
    assert_eq!(
        ProviderTrustCategory::Government.default_assurance(),
        AssuranceLevel::Loa4
    );
}

#[test]
fn test_trust_category_default() {
    let cat = ProviderTrustCategory::default();
    assert_eq!(cat, ProviderTrustCategory::Social);
}

#[test]
fn test_protocol_as_str() {
    assert_eq!(UpstreamProtocol::Oidc.as_str(), "oidc");
    assert_eq!(UpstreamProtocol::OAuth2.as_str(), "oauth2");
}

#[test]
fn test_trust_category_as_str() {
    assert_eq!(ProviderTrustCategory::Social.as_str(), "social");
    assert_eq!(ProviderTrustCategory::Corporate.as_str(), "corporate");
    assert_eq!(ProviderTrustCategory::Government.as_str(), "government");
    assert_eq!(ProviderTrustCategory::Financial.as_str(), "financial");
}

#[test]
fn test_protocol_serde_roundtrip() {
    let p = UpstreamProtocol::Oidc;
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(json, "\"oidc\"");
    let parsed: UpstreamProtocol = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, UpstreamProtocol::Oidc);

    let p2 = UpstreamProtocol::OAuth2;
    let json2 = serde_json::to_string(&p2).unwrap();
    assert_eq!(json2, "\"oauth2\"");
    let parsed2: UpstreamProtocol = serde_json::from_str(&json2).unwrap();
    assert_eq!(parsed2, UpstreamProtocol::OAuth2);
}

#[test]
fn test_trust_category_serde_roundtrip() {
    for cat in [
        ProviderTrustCategory::Social,
        ProviderTrustCategory::Corporate,
        ProviderTrustCategory::Government,
        ProviderTrustCategory::Financial,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: ProviderTrustCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cat);
    }
}

#[test]
fn test_provider_id_unique() {
    let id1 = UpstreamProviderId::new();
    let id2 = UpstreamProviderId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_provider_id_display() {
    let id = UpstreamProviderId(Uuid::nil());
    assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000000");
}

// The stored form secrets were sealed under: changing it would make every
// existing client secret unreadable.
#[test]
fn test_client_secret_context_names_the_provider() {
    let id = UpstreamProviderId(Uuid::nil());
    assert_eq!(
        id.client_secret_context(),
        "upstream:00000000-0000-0000-0000-000000000000"
    );
    assert_ne!(
        UpstreamProviderId::new().client_secret_context(),
        UpstreamProviderId::new().client_secret_context()
    );
}
