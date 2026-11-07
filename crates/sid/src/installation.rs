// SPDX-License-Identifier: AGPL-3.0-only
//! Opening an installation on its store: the state every engine of the
//! installation shares, created on first start and reopened afterwards. The
//! host supplies the store and typed settings; nothing is read from the
//! environment, and no provider is installed globally.

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretString;
use sid_authn::issuer::IssuerRegistry;
use sid_authn::jwt::AccessTokenTtl;
use sid_authn::opaque::OpaqueRouter;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{
    AuditEntry, BootstrapPolicy, CentralAdoption, OidcIssuer, Organization, ProtectedResource,
};
use sid_crypto::CryptoPrimitives;
use sid_keys::KeyManager;
use sid_plugin::StorageBackend;
use sid_plugin::cache::CacheBackend;
use url::Url;

/// What a host decides about an installation it opens.
pub struct InstallationSettings {
    /// The installation's issuer URL. Its host names the installation's
    /// organization, so it must have one.
    pub issuer: Url,
    /// The master key file the field-encryption key versions open under; it
    /// lives outside the store, so a copy of the store alone opens no secret.
    pub master_key: PathBuf,
    /// The cryptographic primitives the host selected for key management.
    pub crypto: Arc<dyn CryptoPrimitives>,
    /// The shared cache that carries revocations to the other replicas.
    pub cache: Arc<dyn CacheBackend>,
    /// The longest access token lifetime: a revocation is kept that long.
    pub access_token_ttl: AccessTokenTtl,
    /// Who manages the installation; `None` keeps what is recorded.
    pub management: Option<Management>,
}

/// Who manages an installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Management {
    /// Managed centrally: it offers no local administrator claim.
    Central,
    /// Managed by its own administrator, claimed locally.
    SelfManaged,
}

/// An opened installation: its keys, organization, issuer and the shared
/// components built on them.
pub struct Installation {
    pub storage: Arc<dyn StorageBackend>,
    /// Field encryption of every stored secret.
    pub key_manager: Arc<dyn KeyManager>,
    /// The installation's organization.
    pub organization: Organization,
    /// The organization's OIDC issuer.
    pub issuer: OidcIssuer,
    /// The authorization API resource a permission checker's token targets.
    pub authorization_api: ProtectedResource,
    /// The enrollment API resource an invite-issuing service's token targets.
    pub enrollment_api: ProtectedResource,
    /// The installation's issuers and their signers.
    pub issuers: Arc<IssuerRegistry>,
    /// OPAQUE on the installation's server setups.
    pub opaque_router: Arc<OpaqueRouter>,
    /// Revocations committed in the store, carried to the other replicas.
    pub revocation_cache: Arc<RevocationCache>,
    /// The key every replica signs and checks proof-of-work challenges with.
    pub captcha_pow_key: [u8; 32],
}

/// Why an installation does not open. Nothing is served from a store that
/// refused one of these steps.
#[derive(Debug, thiserror::Error)]
pub enum InstallationError {
    #[error("{step}: {source}")]
    Store {
        step: &'static str,
        #[source]
        source: sid_core::Error,
    },
    #[error("field-encryption key manager: {0}")]
    FieldKeys(#[source] sid_authn::field_keys::FieldKeyError),
    #[error("{step}: {source}")]
    InstanceSecret {
        step: &'static str,
        #[source]
        source: sid_authn::instance_secret::InstanceSecretError<core::convert::Infallible>,
    },
    #[error("OPAQUE server setup: {0}")]
    Opaque(#[source] sid_authn::opaque::server_setup::ServerSetupError),
    #[error("the issuer {0} has no host to name the installation's organization")]
    IssuerHost(Url),
    #[error("the installation has a local administrator: it is self-managed")]
    LocalAdministrator,
    #[error("the installation is centrally managed and never returns to a local claim")]
    CentrallyManaged,
}

fn store(step: &'static str) -> impl FnOnce(sid_core::Error) -> InstallationError {
    move |source| InstallationError::Store { step, source }
}

impl Installation {
    /// Open the installation on `storage`. Every step is idempotent, so
    /// replicas opening it together reach the same state.
    pub async fn open(
        storage: Arc<dyn StorageBackend>,
        settings: InstallationSettings,
    ) -> Result<Self, InstallationError> {
        let domain = settings
            .issuer
            .host_str()
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| InstallationError::IssuerHost(settings.issuer.clone()))?;
        storage
            .ensure_system_project(AuditEntry::system("project.ensure_system", "system").into())
            .await
            .map_err(store("system project"))?;
        let key_manager = sid_authn::field_keys::field_key_manager(
            storage.as_ref(),
            &settings.master_key,
            settings.crypto,
        )
        .await
        .map_err(InstallationError::FieldKeys)?;
        let captcha_pow_key =
            sid_authn::captcha::load_or_create_pow_key(storage.as_ref(), key_manager.as_ref())
                .await
                .map_err(|source| InstallationError::InstanceSecret {
                    step: "CAPTCHA key",
                    source,
                })?;
        let opaque_router = Arc::new(
            sid_authn::opaque::server_setup::router(storage.as_ref(), key_manager.as_ref())
                .await
                .map_err(InstallationError::Opaque)?,
        );
        let revocation_cache = Arc::new(RevocationCache::recorded_in(
            settings
                .access_token_ttl
                .duration()
                .to_std()
                .expect("access token lifetime is positive"),
            settings.cache,
            storage.clone(),
        ));
        revocation_cache.listen().await;
        apply_management(storage.as_ref(), settings.management).await?;

        let organization = sid_authn::instance_org::ensure(storage.as_ref(), &domain)
            .await
            .map_err(store("installation organization"))?;
        let assigned = storage
            .assign_unowned_clients(
                organization.id,
                AuditEntry::system(
                    "application.organization_assigned",
                    organization.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(store(
                "assign applications to the installation organization",
            ))?;
        if assigned > 0 {
            tracing::info!(assigned, org = %organization.id, "applications assigned to the installation organization");
        }

        // The issuer's key must open under this installation's master key, or
        // the open fails rather than signing with a key its published set lacks.
        let issuer = sid_authn::issuer::ensure_local_issuer(
            storage.as_ref(),
            key_manager.as_ref(),
            &settings.issuer,
            organization.id,
        )
        .await
        .map_err(store("installation OIDC issuer"))?;
        // The token target OIDC-only clients select.
        sid_authn::issuer::ensure_userinfo_resource(storage.as_ref(), &issuer)
            .await
            .map_err(store("installation UserInfo resource"))?;
        let authorization_api =
            sid_authn::issuer::ensure_authorization_api_resource(storage.as_ref(), &issuer)
                .await
                .map_err(store("installation authorization API resource"))?;
        let enrollment_api =
            sid_authn::issuer::ensure_enrollment_api_resource(storage.as_ref(), &issuer)
                .await
                .map_err(store("installation enrollment API resource"))?;
        sid_authz::builtin::ensure_token_inspector_role(storage.as_ref())
            .await
            .map_err(store("token inspector role"))?;
        sid_authz::builtin::ensure_scim_provisioner_role(storage.as_ref())
            .await
            .map_err(store("SCIM provisioner role"))?;
        sid_authz::builtin::ensure_permission_checker_role(storage.as_ref())
            .await
            .map_err(store("permission checker role"))?;
        sid_authz::builtin::ensure_invite_issuer_role(storage.as_ref())
            .await
            .map_err(store("invite issuer role"))?;
        let issuers = Arc::new(IssuerRegistry::new(storage.clone(), key_manager.clone()));
        issuers
            .signer(&issuer)
            .await
            .map_err(store("installation OIDC issuer signing key"))?;

        Ok(Self {
            storage,
            key_manager,
            organization,
            issuer,
            authorization_api,
            enrollment_api,
            issuers,
            opaque_router,
            revocation_cache,
            captcha_pow_key,
        })
    }

    /// The administrator claim token while the claim is open, for the host
    /// to hand to its operator.
    pub async fn admin_claim(&self) -> Result<Option<SecretString>, InstallationError> {
        sid_authn::admin_claim::open_claim(self.storage.as_ref(), self.key_manager.as_ref())
            .await
            .map_err(|source| InstallationError::InstanceSecret {
                step: "administrator claim",
                source,
            })
    }
}

/// Record `management`: central management is refused once a local
/// administrator exists, self-management once the installation is centrally
/// managed, which never returns to a local claim.
async fn apply_management(
    storage: &dyn StorageBackend,
    management: Option<Management>,
) -> Result<(), InstallationError> {
    match management {
        Some(Management::Central) => match storage
            .adopt_central_management(
                AuditEntry::system("installation.centrally_managed", "bootstrap_policy").into(),
            )
            .await
            .map_err(store("bootstrap policy"))?
        {
            CentralAdoption::Adopted => {
                tracing::info!("installation recorded centrally managed: it offers no local claim");
                Ok(())
            }
            CentralAdoption::AlreadyCentral => Ok(()),
            CentralAdoption::LocalAdministrator => Err(InstallationError::LocalAdministrator),
        },
        Some(Management::SelfManaged) => {
            if storage
                .bootstrap_policy()
                .await
                .map_err(store("bootstrap policy"))?
                == BootstrapPolicy::CentrallyManaged
            {
                return Err(InstallationError::CentrallyManaged);
            }
            Ok(())
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
