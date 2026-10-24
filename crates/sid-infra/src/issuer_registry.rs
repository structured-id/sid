// SPDX-License-Identifier: AGPL-3.0-only
//! The SID server's issuer registry over gRPC, as the source of an
//! [`IssuerDirectory`](sid_authn::issuer_directory::IssuerDirectory).

use sid_authn::issuer_directory::{
    IssuerRecord, IssuerSource, RegistryUnavailable, ResourceRecord,
};
use sid_proto::sid::v1::oidc_issuer_service_client::OidcIssuerServiceClient;
use sid_proto::sid::v1::{GetOidcIssuerRequest, GetProtectedResourceRequest};

use crate::deadline::IssuerChannel;

/// The registry of the SID server, over gRPC.
pub struct GrpcIssuerSource {
    channel: IssuerChannel,
}

impl GrpcIssuerSource {
    pub fn new(channel: IssuerChannel) -> Self {
        Self { channel }
    }
}

#[async_trait::async_trait]
impl IssuerSource for GrpcIssuerSource {
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable> {
        let answer = match OidcIssuerServiceClient::new(self.channel.clone())
            .get_oidc_issuer(GetOidcIssuerRequest {
                handle: handle.to_owned(),
            })
            .await
        {
            Ok(answer) => answer.into_inner(),
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(status) => return Err(RegistryUnavailable(status.message().to_owned())),
        };
        let keys = answer
            .keys
            .into_iter()
            .map(|key| {
                let public_key: [u8; 32] = key.public_key.as_slice().try_into().map_err(|_| {
                    RegistryUnavailable("the registry answered a key that is not Ed25519".into())
                })?;
                Ok((key.key_id, public_key))
            })
            .collect::<Result<_, RegistryUnavailable>>()?;
        Ok(Some(IssuerRecord {
            issuer: answer.issuer,
            keys,
        }))
    }

    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
        match OidcIssuerServiceClient::new(self.channel.clone())
            .get_protected_resource(GetProtectedResourceRequest {
                issuer_handle: handle.to_owned(),
                resource: resource.to_owned(),
            })
            .await
        {
            Ok(answer) => {
                let answer = answer.into_inner();
                // A registry answer names its resource; one that does not is
                // no answer.
                let id = answer
                    .id
                    .as_ref()
                    .and_then(|id| sid_core::models::ResourceId::try_from(id).ok())
                    .ok_or_else(|| {
                        RegistryUnavailable("the registry answer names no resource".into())
                    })?;
                Ok(Some(ResourceRecord {
                    issuer: answer.issuer,
                    resource: answer.resource,
                    active: answer.active,
                    id,
                }))
            }
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(RegistryUnavailable(status.message().to_owned())),
        }
    }
}
