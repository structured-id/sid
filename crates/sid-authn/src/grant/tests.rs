// SPDX-License-Identifier: AGPL-3.0-only
//! The grants over an account that is not a local Profile, with a grant store
//! kept in memory.

use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use sid_core::models::{
    AuthorizationCode, BrowserSecretHash, GrantAuthentication, IssuerId, MutationContext,
    ProtectedResource, RefreshToken, ResourceAccess, ResourceIndicator, ResourceState, SessionEnd,
};
use uuid::Uuid;

use super::*;
use crate::jwt::JwtService;
use crate::oauth2::compute_s256_challenge;

const ORDERS: &str = "https://resources.example/orders";
const REDIRECT: &str = "https://cabinet.example/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// An account of another host: no Profile behind it, and not `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Account(u64);

impl Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "account-{}", self.0)
    }
}

#[derive(Default)]
struct Grants {
    codes: Vec<AuthorizationCode<Account>>,
    sessions: Vec<Session<Account>>,
    refresh: Vec<RefreshToken<Account>>,
}

/// The grant store of a host whose accounts are [`Account`]s.
#[derive(Default)]
struct MemoryGrants(Mutex<Grants>);

impl MemoryGrants {
    fn with<T>(&self, f: impl FnOnce(&mut Grants) -> T) -> T {
        f(&mut self.0.lock().expect("grant state"))
    }
}

#[async_trait]
impl GrantStore for MemoryGrants {
    type Owner = Account;

    async fn create_session_atomic(
        &self,
        session: &Session<Account>,
        _max_sessions: u32,
        _ctx: MutationContext,
    ) -> sid_core::Result<Vec<SessionId>> {
        self.with(|g| g.sessions.push(session.clone()));
        Ok(vec![])
    }

    async fn get_session(&self, id: SessionId) -> sid_core::Result<Option<Session<Account>>> {
        Ok(self.with(|g| g.sessions.iter().find(|s| s.id == id).cloned()))
    }

    async fn get_session_by_browser_secret(
        &self,
        _hash: &BrowserSecretHash,
    ) -> sid_core::Result<Option<Session<Account>>> {
        Ok(None)
    }

    async fn touch_session(&self, _id: SessionId, _at: DateTime<Utc>) -> sid_core::Result<()> {
        Ok(())
    }

    async fn delete_session(
        &self,
        id: SessionId,
        _end: &SessionEnd,
        _ctx: MutationContext,
    ) -> sid_core::Result<Vec<SessionId>> {
        Ok(self.with(|g| {
            let ended: Vec<SessionId> = g
                .sessions
                .iter()
                .filter(|s| s.id == id || s.authenticated_by == Some(id))
                .map(|s| s.id)
                .collect();
            g.sessions.retain(|s| !ended.contains(&s.id));
            g.refresh.retain(|t| !ended.contains(&t.session_id));
            ended
        }))
    }

    async fn get_refresh_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> sid_core::Result<Option<RefreshToken<Account>>> {
        Ok(self.with(|g| {
            g.refresh
                .iter()
                .find(|t| t.token_hash == token_hash)
                .cloned()
        }))
    }

    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: SessionId,
        _ctx: MutationContext,
    ) -> sid_core::Result<u64> {
        Ok(self.with(|g| revoke(&mut g.refresh, |t| t.session_id == session_id)))
    }

    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: Uuid,
        _ctx: MutationContext,
    ) -> sid_core::Result<u64> {
        Ok(self.with(|g| revoke(&mut g.refresh, |t| t.family_id == family_id)))
    }

    async fn rotate_refresh_token(
        &self,
        old_id: Uuid,
        new: &RefreshToken<Account>,
        grace_expires_at: DateTime<Utc>,
        _ctx: MutationContext,
    ) -> sid_core::Result<bool> {
        Ok(self.with(|g| {
            let Some(old) = g.refresh.iter_mut().find(|t| t.id == old_id) else {
                return false;
            };
            if old.revoked && !old.is_within_grace_window() {
                return false;
            }
            old.revoked = true;
            old.replaced_by = Some(new.id);
            old.grace_expires_at.get_or_insert(grace_expires_at);
            g.refresh.push(new.clone());
            true
        }))
    }

    async fn create_auth_code(
        &self,
        code: &AuthorizationCode<Account>,
        _ctx: MutationContext,
    ) -> sid_core::Result<()> {
        self.with(|g| g.codes.push(code.clone()));
        Ok(())
    }

    async fn get_auth_code_by_hash(
        &self,
        code_hash: &[u8],
    ) -> sid_core::Result<Option<AuthorizationCode<Account>>> {
        Ok(self.with(|g| g.codes.iter().find(|c| c.code_hash == code_hash).cloned()))
    }

    async fn redeem_auth_code(
        &self,
        code_hash: &[u8],
        session: &Session<Account>,
        refresh_token: &RefreshToken<Account>,
        _ctx: MutationContext,
    ) -> sid_core::Result<AuthCodeRedemption> {
        Ok(self.with(|g| {
            let code = g
                .codes
                .iter_mut()
                .find(|c| c.code_hash == code_hash)
                .expect("redeemed code exists");
            if code.used {
                return AuthCodeRedemption::AlreadyRedeemed {
                    session_id: code.session_id,
                };
            }
            code.used = true;
            code.session_id = Some(session.id);
            g.sessions.push(session.clone());
            g.refresh.push(refresh_token.clone());
            AuthCodeRedemption::Redeemed
        }))
    }
}

/// Revoke the tokens `matches` selects, grace windows included.
fn revoke(
    tokens: &mut [RefreshToken<Account>],
    matches: impl Fn(&RefreshToken<Account>) -> bool,
) -> u64 {
    let mut count = 0;
    for token in tokens.iter_mut().filter(|t| matches(t)) {
        token.revoked = true;
        token.grace_expires_at = None;
        count += 1;
    }
    count
}

fn client() -> OAuth2Client {
    use sid_core::models::*;
    OAuth2Client {
        client_id: "cabinet".into(),
        project_id: ProjectId::system(),
        application_id: ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec![REDIRECT.into()],
        allowed_scopes: vec!["account".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: "Cabinet".into(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 0,
        created_at: Utc::now(),
    }
}

fn target(client: &OAuth2Client) -> Target {
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: None,
        issuer_id: IssuerId::generate(),
        indicator: ResourceIndicator::parse(ORDERS).unwrap(),
        scopes: vec!["account".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let access = ResourceAccess {
        client_id: client.client_id.clone(),
        resource_id: resource.id,
        scopes: vec!["account".into()],
        created_at: Utc::now(),
    };
    Target::from_parts(resource, access)
}

/// A host of [`Account`]s answering one request.
struct Host {
    grants: MemoryGrants,
    oauth2: OAuth2Server,
    issuers: crate::issuer::IssuerRegistry,
    issuer: OidcIssuer,
    client: OAuth2Client,
    target: Target,
    /// Accounts that no longer exist.
    gone: Vec<Account>,
    /// Sessions ended as compromised, with the replay that ended them.
    ended: Mutex<Vec<(SessionId, &'static str)>>,
}

impl Host {
    async fn new() -> Self {
        let jwt = Arc::new(
            JwtService::new(
                include_bytes!("../../tests/fixtures/test_ed25519_private.pem"),
                include_bytes!("../../tests/fixtures/test_ed25519_public.pem"),
                "https://sid.example.com".to_string(),
            )
            .expect("JWT service"),
        );
        let (issuers, issuer) = crate::test_support::installation_issuer().await;
        let client = client();
        let target = target(&client);
        Self {
            grants: MemoryGrants::default(),
            oauth2: OAuth2Server::new(jwt),
            issuers,
            issuer,
            client,
            target,
            gone: vec![],
            ended: Mutex::new(vec![]),
        }
    }

    /// A code `account` authorized for the cabinet; returns the raw code.
    fn authorize(&self, account: Account) -> String {
        let raw = format!("code-{}", Uuid::now_v7());
        self.grants.with(|g| {
            g.codes.push(AuthorizationCode {
                code_hash: OAuth2Server::hash_token(&raw),
                owner: account,
                client_id: self.client.client_id.clone(),
                redirect_uri: REDIRECT.into(),
                scopes: vec!["account".into()],
                resource: self.target.resource_id(),
                code_challenge: Some(compute_s256_challenge(VERIFIER)),
                nonce: None,
                expires_at: Utc::now() + Duration::minutes(5),
                created_at: Utc::now(),
                used: false,
                session_id: None,
                authentication: GrantAuthentication {
                    session: SessionId::generate(),
                    authenticated_at: Utc::now(),
                    amr: vec!["pwd".into()],
                    assurance_level: sid_core::models::AuthLevel::Basic,
                    elevation: None,
                },
            })
        });
        raw
    }

    fn ended(&self) -> Vec<(SessionId, &'static str)> {
        self.ended.lock().unwrap().clone()
    }
}

#[async_trait]
impl GrantHost for Host {
    type Owner = Account;
    type Account = Account;
    type Error = &'static str;

    fn store(&self) -> &dyn GrantStore<Owner = Account> {
        &self.grants
    }

    fn oauth2(&self) -> &OAuth2Server {
        &self.oauth2
    }

    async fn client(&self) -> Result<(OAuth2Client, OidcIssuer), &'static str> {
        Ok((self.client.clone(), self.issuer.clone()))
    }

    async fn resume_target(
        &self,
        _issuer: &OidcIssuer,
        _client: &OAuth2Client,
        bound: ResourceId,
    ) -> Result<Target, &'static str> {
        if bound == self.target.resource_id() {
            Ok(self.target.clone())
        } else {
            Err("another resource")
        }
    }

    async fn proof(&self) -> Result<Option<DPopBinding>, &'static str> {
        Ok(None)
    }

    async fn account(&self, owner: &Account) -> Result<Option<Account>, &'static str> {
        Ok((!self.gone.contains(owner)).then(|| owner.clone()))
    }

    async fn claims(
        &self,
        account: &Account,
        _issuer: &OidcIssuer,
        _client: &OAuth2Client,
        _scopes: &[String],
    ) -> Result<AccountClaims, &'static str> {
        Ok(AccountClaims {
            sub: format!("ref-{}", account.0),
            roles: vec![],
            id_token: None,
            custom_claims: None,
        })
    }

    async fn signer(&self, issuer: &OidcIssuer) -> Result<Arc<IssuerSigner>, &'static str> {
        self.issuers.signer(issuer).await.map_err(|_| "no signer")
    }

    async fn end_compromised_session(
        &self,
        session: SessionId,
        action: &'static str,
    ) -> Result<(), &'static str> {
        self.ended.lock().unwrap().push((session, action));
        Ok(())
    }

    fn session_address(&self) -> String {
        "test".into()
    }
}

fn code_grant(code: &str) -> CodeGrant<'_> {
    CodeGrant {
        code: Some(code),
        redirect_uri: Some(REDIRECT),
        code_verifier: Some(VERIFIER),
    }
}

fn refused<E: std::fmt::Debug>(failure: GrantFailure<E>) -> (TokenError, String) {
    match failure {
        GrantFailure::Refused(error, description) => (error, description.into_owned()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// A code an account that is not a Profile authorized is redeemed for tokens
// carrying the host's subject and no `pid`; the session and refresh token are
// the account's.
#[tokio::test]
async fn test_code_is_redeemed_for_a_non_profile_account() {
    let host = Host::new().await;
    let code = host.authorize(Account(7));

    let response = redeem_code(&host, code_grant(&code)).await.unwrap();

    assert!(response.id_token.is_none());
    let claims = host
        .issuers
        .verifier(&host.issuer)
        .await
        .unwrap()
        .validate_access_token_for(&response.access_token, ORDERS)
        .unwrap();
    assert_eq!(claims.sub, "ref-7");
    assert!(claims.pid.is_none());
    host.grants.with(|g| {
        assert_eq!(g.sessions.len(), 1);
        assert_eq!(g.sessions[0].owner, Account(7));
        assert_eq!(g.sessions[0].client_id.as_deref(), Some("cabinet"));
        assert_eq!(g.refresh.len(), 1);
        assert_eq!(g.refresh[0].owner, Account(7));
        assert!(g.codes[0].used);
    });
}

// A code used a second time is refused and the session of its first use
// ends (RFC 6749 §4.1.2).
#[tokio::test]
async fn test_reused_code_ends_its_first_session() {
    let host = Host::new().await;
    let code = host.authorize(Account(7));
    redeem_code(&host, code_grant(&code)).await.unwrap();
    let first = host.grants.with(|g| g.sessions[0].id);

    let (error, _) = refused(redeem_code(&host, code_grant(&code)).await.unwrap_err());

    assert_eq!(error, TokenError::InvalidGrant);
    assert_eq!(host.ended(), vec![(first, "auth_code.reuse")]);
}

// A code without its parameters is an `invalid_request` naming the missing
// one, before the client is even looked at.
#[tokio::test]
async fn test_code_grant_names_the_missing_parameter() {
    let host = Host::new().await;
    let failure = redeem_code(
        &host,
        CodeGrant {
            code: Some("x"),
            redirect_uri: Some(""),
            code_verifier: None,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        failure,
        GrantFailure::MissingParameter("redirect_uri")
    ));
}

// The tokens are refused, and nothing is stored, when the code's account no
// longer exists.
#[tokio::test]
async fn test_code_of_a_gone_account_is_refused() {
    let mut host = Host::new().await;
    host.gone.push(Account(7));
    let code = host.authorize(Account(7));

    let (error, _) = refused(redeem_code(&host, code_grant(&code)).await.unwrap_err());

    assert_eq!(error, TokenError::InvalidGrant);
    host.grants.with(|g| {
        assert!(g.sessions.is_empty());
        assert!(!g.codes[0].used);
    });
}

// A refresh rotates the token within its family: the new one is the
// account's and continues the family, the presented one is replaced.
#[tokio::test]
async fn test_refresh_rotates_within_the_family() {
    let host = Host::new().await;
    let code = host.authorize(Account(7));
    let first = redeem_code(&host, code_grant(&code)).await.unwrap();
    let presented = first.refresh_token.unwrap();

    let second = refresh(&host, Some(&presented)).await.unwrap();

    let new = second.refresh_token.unwrap();
    host.grants.with(|g| {
        let old = g
            .refresh
            .iter()
            .find(|t| t.token_hash == OAuth2Server::hash_token(&presented))
            .unwrap();
        let rotated = g
            .refresh
            .iter()
            .find(|t| t.token_hash == OAuth2Server::hash_token(&new))
            .unwrap();
        assert!(old.revoked);
        assert_eq!(old.replaced_by, Some(rotated.id));
        assert_eq!(rotated.family_id, old.family_id);
        assert_eq!(rotated.owner, Account(7));
        assert_eq!(rotated.session_id, old.session_id);
    });
}

// A rotated token presented after its grace window revokes its whole family
// and ends its session.
#[tokio::test]
async fn test_reused_refresh_token_ends_family_and_session() {
    let host = Host::new().await;
    let code = host.authorize(Account(7));
    let first = redeem_code(&host, code_grant(&code)).await.unwrap();
    let presented = first.refresh_token.unwrap();
    let second = refresh(&host, Some(&presented)).await.unwrap();
    host.grants.with(|g| {
        for token in &mut g.refresh {
            if token.replaced_by.is_some() {
                token.grace_expires_at = Some(Utc::now() - Duration::seconds(1));
            }
        }
    });

    let (error, _) = refused(refresh(&host, Some(&presented)).await.unwrap_err());

    assert_eq!(error, TokenError::InvalidGrant);
    let session = host.grants.with(|g| g.sessions[0].id);
    assert_eq!(host.ended(), vec![(session, "token.reuse")]);
    let (error, _) = refused(
        refresh(&host, second.refresh_token.as_deref())
            .await
            .unwrap_err(),
    );
    assert_eq!(error, TokenError::InvalidGrant, "the family is revoked");
}

// A refresh whose session has ended is refused.
#[tokio::test]
async fn test_refresh_after_session_end_is_refused() {
    let host = Host::new().await;
    let code = host.authorize(Account(7));
    let first = redeem_code(&host, code_grant(&code)).await.unwrap();
    host.grants.with(|g| g.sessions.clear());

    let (error, description) = refused(
        refresh(&host, first.refresh_token.as_deref())
            .await
            .unwrap_err(),
    );

    assert_eq!(error, TokenError::InvalidGrant);
    assert_eq!(description, "session ended");
}
