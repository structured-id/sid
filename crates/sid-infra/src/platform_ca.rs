// SPDX-License-Identifier: AGPL-3.0-only
//! The client of the platform's public CA publication
//! (`GET /.well-known/sid-ca/index.json`, `sid.v1.federation.PlatformCaService`):
//! the admitted platform CA set as the platform last published it, fetched
//! from the one endpoint the deployment configured.
//!
//! The client transports and decodes. It follows no redirect and takes no
//! endpoint from what it receives, and it bounds the time and the size of an
//! answer. Whether the set is admitted (its revision, narrowing and
//! withdrawal) is decided by the holder that applies it.

use std::time::Duration;

use prost::Message;
use sid_proto::sid::v1::PlatformCas;

pub mod discovery;

/// The proto file the publication's message is defined in.
const PUBLICATION_FILE: &str = "sid/v1/federation/platform_ca.proto";
/// The publication's message.
const MESSAGE: &str = "sid.v1.federation.PlatformCas";
/// The longest answer read: a few generations of hybrid certificates and
/// their Roots, with ample room.
pub const MAX_BODY: usize = 1 << 20;
/// The longest wait for a connection, and for the whole answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(15);

/// Why the publication was not read.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    /// The configured endpoint is not an HTTPS URL.
    #[error("the platform CA publication endpoint must be an https URL")]
    NotHttps,
    /// No HTTP client could be built (no TLS provider installed).
    #[error("no HTTP client for the platform CA publication: {0}")]
    Client(String),
    /// The endpoint did not answer: connection, TLS or time.
    #[error("the platform CA publication did not answer: {0}")]
    Unreachable(String),
    /// The endpoint answered with a status other than success; a redirect
    /// is one of them.
    #[error("the platform CA publication answered {0}")]
    Status(u16),
    /// The answer is larger than [`MAX_BODY`].
    #[error("the platform CA publication is larger than {MAX_BODY} bytes")]
    TooLarge,
    /// The answer is not the publication's JSON.
    #[error("the platform CA publication is malformed: {0}")]
    Malformed(String),
}

/// The platform CA publication at one configured endpoint.
pub struct PlatformCaPublication {
    client: reqwest::Client,
    endpoint: url::Url,
    message: prost_reflect::MessageDescriptor,
}

impl PlatformCaPublication {
    /// The publication at `endpoint`, which must be an `https` URL.
    pub fn new(endpoint: url::Url) -> Result<Self, PublicationError> {
        if endpoint.scheme() != "https" {
            return Err(PublicationError::NotHttps);
        }
        let client = sid_plugin::client_builder()
            .map_err(|e| PublicationError::Client(e.to_string()))?
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| PublicationError::Client(e.to_string()))?;
        Self::with_client(client, endpoint)
    }

    /// The publication at `endpoint` over `client`, whose bounds and
    /// redirect policy are the caller's.
    fn with_client(client: reqwest::Client, endpoint: url::Url) -> Result<Self, PublicationError> {
        let pool = prost_reflect::DescriptorPool::decode(
            sid_proto::descriptor_set_of(|file| file == PUBLICATION_FILE).as_slice(),
        )
        .map_err(|e| PublicationError::Malformed(e.to_string()))?;
        let message = pool
            .get_message_by_name(MESSAGE)
            .ok_or_else(|| PublicationError::Malformed(format!("no {MESSAGE} descriptor")))?;
        Ok(Self {
            client,
            endpoint,
            message,
        })
    }

    /// The configured endpoint.
    pub fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }

    /// Fetch the publication: the set as the platform last published it.
    pub async fn fetch(&self) -> Result<PlatformCas, PublicationError> {
        let mut response = self
            .client
            .get(self.endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| PublicationError::Unreachable(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(PublicationError::Status(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY as u64)
        {
            return Err(PublicationError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| PublicationError::Unreachable(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(PublicationError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        self.decode(&body)
    }

    /// The publication's JSON `body` read as its message, by the proto3 JSON
    /// mapping the transcoder writes it with.
    fn decode(&self, body: &[u8]) -> Result<PlatformCas, PublicationError> {
        let mut json = serde_json::Deserializer::from_slice(body);
        let message = prost_reflect::DynamicMessage::deserialize(self.message.clone(), &mut json)
            .map_err(|e| PublicationError::Malformed(e.to_string()))?;
        json.end()
            .map_err(|e| PublicationError::Malformed(e.to_string()))?;
        PlatformCas::decode(message.encode_to_vec().as_slice())
            .map_err(|e| PublicationError::Malformed(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
