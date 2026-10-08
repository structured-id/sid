// SPDX-License-Identifier: AGPL-3.0-only
//! OIDC issuers of this installation.
//!
//! Tokens for an organization's applications are issued under that
//! organization's logical issuer: its stored canonical URL is `iss`, and they
//! are signed with the issuer's own key, never the installation's session key.
//! The issuer and its first key are created once, by whichever replica starts
//! first, and read back by every later start.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rand::RngCore;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use sid_core::models::{
    AuditEntry, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey, OidcIssuer, OrgId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::KeyManager;
use sid_plugin::StorageBackend;
use url::Url;
use zeroize::Zeroizing;

use crate::jwt::{
    ACCESS_TOKEN_TYP, AccessTokenClaims, BACKCHANNEL_LOGOUT_EVENT, Jwk, JwkSet, LogoutTokenClaims,
};
use crate::sealed_secret;

/// The issuer URL of `handle` under `base`, the deployment's public URL:
/// `{base}/i/{handle}`.
///
/// OIDC Discovery 1.0 §3 and RFC 8414 §2: an issuer is an `https` URL
/// without query or fragment. Plain `http` is accepted only on a loopback
/// host, for local development.
pub fn issuer_url(base: &Url, handle: &IssuerHandle) -> SidResult<String> {
    let loopback = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match base.scheme() {
        "https" => {}
        "http" if loopback => {}
        other => {
            return Err(SidError::Validation(format!(
                "issuer URL must use https, not {other}"
            )));
        }
    }
    if base.query().is_some() || base.fragment().is_some() {
        return Err(SidError::Validation(
            "issuer URL must not have a query or fragment".into(),
        ));
    }
    Ok(format!(
        "{}/i/{}",
        base.as_str().trim_end_matches('/'),
        handle.as_str()
    ))
}

/// The installation's own issuer for `org`, created with its first signing
/// key under `base` on the first start. A later start keeps the stored one,
/// whatever `base` it is given: the issuer URL changes only by migration.
pub async fn ensure_local_issuer(
    storage: &dyn StorageBackend,
    keys: &dyn KeyManager,
    base: &Url,
    org: OrgId,
) -> SidResult<OidcIssuer> {
    if let Some(issuer) = storage.oidc_issuer_for(IssuerAuthority::Local, org).await? {
        return Ok(issuer);
    }
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id: sid_core::models::IssuerId::generate(),
        canonical_url: issuer_url(base, &handle)?,
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org,
        created_at: chrono::Utc::now(),
    };
    let first_key = new_signing_key(keys, &issuer, 1).await?;
    // Replicas starting together race here: the first insert is kept and
    // every one of them reads that one back below.
    storage
        .insert_oidc_issuer(
            &issuer,
            &first_key,
            AuditEntry::system("oidc_issuer.created", issuer.id.to_string()).into(),
        )
        .await?;
    storage
        .oidc_issuer_for(IssuerAuthority::Local, org)
        .await?
        .ok_or_else(|| SidError::Storage("oidc issuer missing right after it was stored".into()))
}

/// The UserInfo endpoint of the issuer at `issuer_url`, advertised in its
/// discovery document; also the resource indicator of its UserInfo resource.
pub fn userinfo_endpoint(issuer_url: &str) -> String {
    format!("{issuer_url}/userinfo")
}

/// The token endpoint of the issuer at `issuer_url`, advertised in its
/// discovery document; also the audience of client assertions for it
/// (RFC 7523 §3).
pub fn token_endpoint(issuer_url: &str) -> String {
    format!("{issuer_url}/oauth2/token")
}

/// Scopes the UserInfo resource understands (OIDC Core 1.0 §5.4).
const USERINFO_SCOPES: [&str; 5] = ["openid", "profile", "email", "phone", "address"];

/// The registered UserInfo resource of `issuer`, created on first use in the
/// system project. An OIDC-only client selects it explicitly as its token
/// target; its existence gives no client access (auth/oauth-resource-model.md).
pub async fn ensure_userinfo_resource(
    storage: &dyn StorageBackend,
    issuer: &OidcIssuer,
) -> SidResult<sid_core::models::ProtectedResource> {
    ensure_issuer_resource(
        storage,
        issuer,
        "OIDC UserInfo",
        &userinfo_endpoint(&issuer.canonical_url),
        &USERINFO_SCOPES,
        "userinfo_resource.created",
    )
    .await
}

/// The SCIM 2.0 base URL of the issuer at `issuer_url` (RFC 7644 §3.13):
/// also the resource indicator of its SCIM directory resource.
pub fn scim_endpoint(issuer_url: &str) -> String {
    format!("{issuer_url}/scim/v2")
}

/// The registered SCIM directory resource of `issuer`, created on first use
/// in the system project. Provisioning connectors hold their roles on it, and
/// a connector's token targets it; its scopes are the SCIM actions.
pub async fn ensure_scim_resource(
    storage: &dyn StorageBackend,
    issuer: &OidcIssuer,
) -> SidResult<sid_core::models::ProtectedResource> {
    ensure_issuer_resource(
        storage,
        issuer,
        "SCIM directory",
        &scim_endpoint(&issuer.canonical_url),
        &sid_core::models::SCIM_ACTIONS,
        "scim_resource.created",
    )
    .await
}

/// The authorization API of the issuer at `issuer_url`: the resource
/// indicator a permission checker's own token targets (D054).
pub fn authorization_api_endpoint(issuer_url: &str) -> String {
    format!("{issuer_url}/authz")
}

/// The registered authorization API resource of `issuer`, created on first
/// use in the system project. A service asking about others' permissions
/// authenticates with a token for it; its existence grants nobody anything,
/// the checker role on each target resource does.
pub async fn ensure_authorization_api_resource(
    storage: &dyn StorageBackend,
    issuer: &OidcIssuer,
) -> SidResult<sid_core::models::ProtectedResource> {
    ensure_issuer_resource(
        storage,
        issuer,
        "Authorization API",
        &authorization_api_endpoint(&issuer.canonical_url),
        &[sid_core::models::AUTHZ_CHECK],
        "authorization_api_resource.created",
    )
    .await
}

/// The resource of `issuer` at `endpoint`, registered with `scopes` under a
/// system application named `name` when it does not exist yet.
async fn ensure_issuer_resource(
    storage: &dyn StorageBackend,
    issuer: &OidcIssuer,
    name: &str,
    endpoint: &str,
    scopes: &[&str],
    audit_action: &str,
) -> SidResult<sid_core::models::ProtectedResource> {
    use sid_core::models::{
        Application, ApplicationId, ProjectId, ProtectedResource, ResourceId, ResourceIndicator,
        ResourceState,
    };
    let indicator = ResourceIndicator::parse(endpoint).map_err(|e| {
        SidError::Internal(format!("{name} endpoint is no resource indicator: {e}"))
    })?;
    if let Some(stored) = storage
        .protected_resource_by_indicator(issuer.id, &indicator)
        .await?
    {
        return Ok(stored);
    }
    let now = chrono::Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: name.to_owned(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer.id,
        indicator: indicator.clone(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    storage
        .ensure_system_project(AuditEntry::system("project.ensure", "system").into())
        .await?;
    // Replicas starting together race here: the first registration is kept
    // and every one of them reads that one back below.
    match storage
        .create_application(
            &app,
            None,
            Some(&resource),
            AuditEntry::system(audit_action, issuer.id.to_string()).into(),
        )
        .await
    {
        Ok(()) | Err(SidError::Conflict(_)) => {}
        Err(e) => return Err(e),
    }
    storage
        .protected_resource_by_indicator(issuer.id, &indicator)
        .await?
        .ok_or_else(|| {
            SidError::Storage(format!("{name} resource missing right after it was stored"))
        })
}

/// A fresh Ed25519 key for `issuer`, generation `generation`, its private
/// half sealed under `keys`.
async fn new_signing_key(
    keys: &dyn KeyManager,
    issuer: &OidcIssuer,
    generation: u32,
) -> SidResult<IssuerSigningKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let sealed_private_key = sealed_secret::seal(
        keys,
        &IssuerSigningKey::sealing_context(issuer.id, generation),
        seed.as_ref(),
    )
    .await
    .map_err(|e| SidError::Internal(format!("sealing issuer signing key: {e}")))?;
    Ok(IssuerSigningKey {
        issuer_id: issuer.id,
        generation,
        key_id: key_id(&public_key),
        public_key,
        sealed_private_key,
        created_at: chrono::Utc::now(),
    })
}

/// The JWS `kid` of a public key: its SHA-256 thumbprint, base64url.
fn key_id(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

/// Signs tokens as one issuer, with its current key, and publishes the
/// issuer's public keys.
pub struct IssuerSigner {
    issuer: OidcIssuer,
    generation: u32,
    key_id: String,
    encoding_key: EncodingKey,
    jwks: JwkSet,
}

impl std::fmt::Debug for IssuerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerSigner")
            .field("issuer", &self.issuer.canonical_url)
            .field("key_id", &self.key_id)
            .field("encoding_key", &"[REDACTED]")
            .finish()
    }
}

impl IssuerSigner {
    /// The signer of `issuer`, opening its highest-generation key.
    ///
    /// Fails when the issuer has no key or its key cannot be opened (a
    /// restore without the master key): no replacement key is created, so
    /// no token is ever signed by a key the issuer's published set lacks.
    pub async fn load(
        storage: &dyn StorageBackend,
        keys: &dyn KeyManager,
        issuer: OidcIssuer,
    ) -> SidResult<Self> {
        let stored = storage.oidc_issuer_signing_keys(issuer.id).await?;
        Self::open(keys, issuer, &stored).await
    }

    /// The signer of `issuer` over its `stored` keys, oldest generation first.
    async fn open(
        keys: &dyn KeyManager,
        issuer: OidcIssuer,
        stored: &[IssuerSigningKey],
    ) -> SidResult<Self> {
        let current = stored.last().ok_or_else(|| {
            SidError::Internal(format!("issuer {} has no signing key", issuer.id))
        })?;
        let opened = sealed_secret::open(
            keys,
            &IssuerSigningKey::sealing_context(issuer.id, current.generation),
            &current.sealed_private_key,
        )
        .await
        .map_err(|e| {
            SidError::Internal(format!(
                "cannot open signing key {} of issuer {}: {e}",
                current.generation, issuer.id
            ))
        })?;
        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(opened.secret.as_slice().try_into().map_err(|_| {
                SidError::Internal(format!("issuer {} signing key is not 32 bytes", issuer.id))
            })?);
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().to_bytes() != current.public_key {
            return Err(SidError::Internal(format!(
                "issuer {} signing key does not match its stored public key",
                issuer.id
            )));
        }
        let der = signing_key
            .to_pkcs8_der()
            .map_err(|e| SidError::Internal(format!("encoding issuer signing key: {e}")))?;
        let jwks = JwkSet {
            keys: stored
                .iter()
                .map(|key| Jwk {
                    kty: "OKP".into(),
                    use_field: "sig".into(),
                    alg: "EdDSA".into(),
                    kid: key.key_id.clone(),
                    crv: "Ed25519".into(),
                    x: URL_SAFE_NO_PAD.encode(key.public_key),
                })
                .collect(),
        };
        Ok(Self {
            generation: current.generation,
            key_id: current.key_id.clone(),
            encoding_key: EncodingKey::from_ed_der(der.as_bytes()),
            jwks,
            issuer,
        })
    }

    pub fn issuer(&self) -> &OidcIssuer {
        &self.issuer
    }

    /// The issuer's public keys, every generation, for its JWKS endpoint.
    pub fn jwks(&self) -> &JwkSet {
        &self.jwks
    }

    /// Sign `claims` with the current key, naming it in `kid`; `typ` sets the
    /// JWS type (`logout+jwt` for a logout token).
    pub fn sign<T: Serialize>(&self, typ: Option<&str>, claims: &T) -> SidResult<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());
        if let Some(typ) = typ {
            header.typ = Some(typ.to_owned());
        }
        encode(&header, claims, &self.encoding_key)
            .map_err(|e| SidError::Internal(format!("signing token as issuer: {e}")))
    }
}

impl crate::jwt::TokenSigner for IssuerSigner {
    fn iss(&self) -> &str {
        &self.issuer.canonical_url
    }

    fn sign_claims<T: Serialize>(&self, typ: Option<&str>, claims: &T) -> SidResult<String> {
        self.sign(typ, claims)
    }
}

/// Verifies tokens of one issuer: its exact `iss` and only its own keys,
/// chosen by `kid`. A key of any other issuer is unknown here.
pub struct IssuerVerifier {
    issuer: String,
    keys: Vec<(String, DecodingKey)>,
}

impl std::fmt::Debug for IssuerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerVerifier")
            .field("issuer", &self.issuer)
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl IssuerVerifier {
    /// A verifier for `issuer` (its exact identifier) holding `keys` as
    /// (`kid`, Ed25519 public key) pairs.
    pub fn new(issuer: String, keys: impl IntoIterator<Item = (String, [u8; 32])>) -> Self {
        let keys = keys
            .into_iter()
            .map(|(kid, public_key)| (kid, DecodingKey::from_ed_der(&public_key)))
            .collect();
        Self { issuer, keys }
    }

    /// The issuer identifier this verifier accepts.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Whether this verifier holds the key named `kid`.
    pub fn knows(&self, kid: &str) -> bool {
        self.keys.iter().any(|(known, _)| known == kid)
    }

    /// Validate an access token this issuer gave an application and return
    /// its claims: typed `at+jwt`, naming its client, whose `aud` includes
    /// that client (RFC 9068 §2.1, §2.2, §4). Another token of this issuer
    /// (an ID or logout token) is refused. Whether the token was issued to a
    /// particular receiver is the receiver's check against `aud`.
    pub fn validate_access_token(&self, token: &str) -> SidResult<AccessTokenClaims> {
        let refused = |why: &str| SidError::AuthenticationFailed(format!("Invalid token: {why}"));
        // RFC 9068 §4: `at+jwt` or `application/at+jwt`; media types compare
        // case-insensitively (RFC 2045 §5.1).
        let typ = decode_header(token)
            .map_err(|e| refused(&e.to_string()))?
            .typ
            .unwrap_or_default();
        let typ = typ.strip_prefix("application/").unwrap_or(&typ);
        if !typ.eq_ignore_ascii_case(ACCESS_TOKEN_TYP) {
            return Err(refused("not an access token"));
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["sub", "iss", "exp", "iat", "aud"]);
        let claims: AccessTokenClaims = self.decode(token, &validation)?;
        // RFC 9068 §2.2: an audience and the requesting client, which is no
        // audience of the token by requesting it.
        if claims.aud.is_empty() {
            return Err(refused("names no audience"));
        }
        if claims.client_id.is_none() {
            return Err(refused("names no client"));
        }
        Ok(claims)
    }

    /// A token of this issuer as the resource `audience` accepts it: an
    /// access token (see [`Self::validate_access_token`]) whose `aud` names
    /// that resource (RFC 9068 §4). A token for another resource is refused.
    pub fn validate_access_token_for(
        &self,
        token: &str,
        audience: &str,
    ) -> SidResult<AccessTokenClaims> {
        let claims = self.validate_access_token(token)?;
        if !claims.aud.iter().any(|aud| aud == audience) {
            return Err(SidError::AuthenticationFailed(
                "Invalid token: issued for another resource".into(),
            ));
        }
        Ok(claims)
    }

    /// Verify a token of this issuer into `T`: signature by one of its keys,
    /// exact `iss`, expiry, `sub`. The audience is the caller's to check,
    /// since it depends on who receives the token.
    pub fn verify_claims<T: DeserializeOwned>(&self, token: &str) -> SidResult<T> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        self.decode(token, &validation)
    }

    /// An ID token of this issuer given back as `id_token_hint` (OIDC
    /// RP-Initiated Logout 1.0 §2): its signature, exact `iss`, audience and
    /// session, and a JWT of the ID token's type rather than an access or
    /// logout token. An expired one is accepted, as §2 asks: it names a
    /// session and a client, and authenticates nobody.
    pub fn validate_id_token_hint(&self, token: &str) -> SidResult<crate::jwt::IdTokenClaims> {
        let refused = |why: &str| SidError::AuthenticationFailed(format!("Invalid token: {why}"));
        let typ = decode_header(token)
            .map_err(|e| refused(&e.to_string()))?
            .typ
            .unwrap_or_default();
        if !typ.is_empty() && !typ.eq_ignore_ascii_case("JWT") {
            return Err(refused("not an ID token"));
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["iss", "sub", "aud"]);
        let claims: crate::jwt::IdTokenClaims = self.decode(token, &validation)?;
        if claims.sid.is_none() {
            return Err(refused("names no session"));
        }
        Ok(claims)
    }

    /// The ID token of `client_id`'s own code redemption, as that client
    /// validates it (OIDC Core 1.0 §3.1.3.7): signed by this issuer with its
    /// exact `iss`, live, of the ID token's type, for exactly this client,
    /// and carrying the `nonce` the client sent, which binds it to that
    /// sign-in (§3.1.2.1).
    pub fn validate_id_token(
        &self,
        token: &str,
        client_id: &str,
        nonce: &str,
    ) -> SidResult<crate::jwt::IdTokenClaims> {
        let refused = |why: &str| SidError::AuthenticationFailed(format!("Invalid token: {why}"));
        let typ = decode_header(token)
            .map_err(|e| refused(&e.to_string()))?
            .typ
            .unwrap_or_default();
        if !typ.is_empty() && !typ.eq_ignore_ascii_case("JWT") {
            return Err(refused("not an ID token"));
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
        let claims: crate::jwt::IdTokenClaims = self.decode(token, &validation)?;
        if claims.nonce.as_deref() != Some(nonce) {
            return Err(refused("nonce of another sign-in"));
        }
        Ok(claims)
    }

    /// Whether this verifier holds the key named `kid`.
    pub fn knows_key(&self, kid: &str) -> bool {
        self.keys.iter().any(|(id, _)| id == kid)
    }

    /// Validate a back-channel logout token of this issuer, as its relying
    /// party does: signature, exact `iss`, and the logout event (Back-Channel
    /// Logout 1.0 §2.6). The audience is the receiving client's to check.
    pub fn validate_logout_token(&self, token: &str) -> SidResult<LogoutTokenClaims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["sub", "iss", "iat", "exp", "jti"]);
        let claims: LogoutTokenClaims = self.decode(token, &validation)?;
        if claims.events.get(BACKCHANNEL_LOGOUT_EVENT).is_none() {
            return Err(SidError::AuthenticationFailed(
                "logout token without the back-channel logout event".into(),
            ));
        }
        Ok(claims)
    }

    /// Decode `token` with the key its `kid` names; a token naming no key, or
    /// a key this issuer does not hold, is refused.
    fn decode<T: DeserializeOwned>(&self, token: &str, validation: &Validation) -> SidResult<T> {
        let refused = |e: String| SidError::AuthenticationFailed(format!("Invalid token: {e}"));
        let header = decode_header(token).map_err(|e| refused(e.to_string()))?;
        let kid = header.kid.ok_or_else(|| refused("no key id".into()))?;
        let (_, key) = self
            .keys
            .iter()
            .find(|(id, _)| *id == kid)
            .ok_or_else(|| refused("unknown key".into()))?;
        decode::<T>(token, key, validation)
            .map(|data| data.claims)
            .map_err(|e| refused(e.to_string()))
    }
}

/// The installation's issuers, looked up by handle, with their signers
/// opened once per key generation.
///
/// Holds only values derived from stored, never-changing rows (an issuer and
/// one generation of its key), so every replica computes the same ones.
pub struct IssuerRegistry {
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn KeyManager>,
    signers: DashMap<IssuerId, Arc<IssuerSigner>>,
}

impl std::fmt::Debug for IssuerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerRegistry")
            .field("signers", &self.signers.len())
            .finish_non_exhaustive()
    }
}

impl IssuerRegistry {
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn KeyManager>) -> Self {
        Self {
            storage,
            keys,
            signers: DashMap::new(),
        }
    }

    /// The issuer named by `handle` as it appears in a request path; text
    /// that is not a stored handle names no issuer.
    pub async fn by_handle(&self, handle: &str) -> SidResult<Option<OidcIssuer>> {
        let Ok(handle) = IssuerHandle::parse(handle) else {
            return Ok(None);
        };
        self.storage.oidc_issuer_by_handle(&handle).await
    }

    /// The base issuer of `org`, if it has one.
    pub async fn of_org(&self, org: OrgId) -> SidResult<Option<OidcIssuer>> {
        self.storage
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
    }

    /// The signer of `issuer` with its current key.
    pub async fn signer(&self, issuer: &OidcIssuer) -> SidResult<Arc<IssuerSigner>> {
        let stored = self.storage.oidc_issuer_signing_keys(issuer.id).await?;
        let current = stored.last().map(|key| key.generation);
        if let Some(signer) = self.signers.get(&issuer.id)
            && Some(signer.generation) == current
        {
            return Ok(signer.clone());
        }
        let signer =
            Arc::new(IssuerSigner::open(self.keys.as_ref(), issuer.clone(), &stored).await?);
        self.signers.insert(issuer.id, signer.clone());
        Ok(signer)
    }

    /// Every stored public key of `issuer` as (`kid`, Ed25519 key), oldest
    /// generation first.
    pub async fn public_keys(&self, issuer: &OidcIssuer) -> SidResult<Vec<(String, [u8; 32])>> {
        let stored = self.storage.oidc_issuer_signing_keys(issuer.id).await?;
        Ok(stored
            .into_iter()
            .map(|key| (key.key_id, key.public_key))
            .collect())
    }

    /// A verifier holding every stored key of `issuer`.
    pub async fn verifier(&self, issuer: &OidcIssuer) -> SidResult<IssuerVerifier> {
        Ok(IssuerVerifier::new(
            issuer.canonical_url.clone(),
            self.public_keys(issuer).await?,
        ))
    }
}

#[cfg(test)]
mod tests;
