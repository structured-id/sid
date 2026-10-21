// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's public UI settings, served with the deployment's
//! configuration of a bundle that follows them.
//!
//! The served configuration lives in a `watch` channel: a reader sees the
//! latest one only, and a replacement swaps bytes and entity tag together.
//! Within one source stream a revision that is not newer than the served one
//! is ignored; a new stream starts from the source's current state.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderValue;
use serde_json::{Map, Value};
use sid_proto::sid::v1::identity::PrincipalType;
use sid_proto::sid::v1::ui::PublicUiSettings;
use sid_proto::sid::v1::ui::public_ui_settings_service_client::PublicUiSettingsServiceClient;
use tokio::sync::watch;

/// The key of the settings object in the served configuration.
pub(crate) const SETTINGS_KEY: &str = "settings";

/// The longest username an installation admits, in code points.
const USERNAME_MAX_LENGTH: u32 = 32;

/// One configuration as served: its bytes and their strong entity tag.
#[derive(Debug)]
pub(crate) struct Served {
    pub(crate) bytes: Arc<[u8]>,
    /// Quoted (RFC 9110 §8.8.3), derived from the bytes.
    pub(crate) tag: HeaderValue,
}

impl Served {
    pub(crate) fn of(bytes: Vec<u8>) -> Arc<Self> {
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&bytes);
        let tag = HeaderValue::from_str(&format!("\"{}\"", hex::encode(digest)))
            .expect("a quoted hex digest is a valid header value");
        Arc::new(Self {
            bytes: bytes.into(),
            tag,
        })
    }
}

/// The served configuration as the routes read it: `None` until a bundle
/// that follows its installation has received a first projection.
pub(crate) type ServedConfig = watch::Receiver<Option<Arc<Served>>>;

/// Why a projection is not served; the one served before stays.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsRejected {
    #[error("revision {offered} is not newer than the served {served}")]
    Stale { offered: u64, served: u64 },
    #[error("registration admits usernames with a minimum length of {0}, not 1 to 32")]
    UsernameMinimum(u32),
}

/// Where a live bundle's settings arrive. One feeder owns it: [`follow`], or
/// an embedding application applying its own installation's settings.
#[derive(Debug)]
pub struct SettingsSink {
    base: Map<String, Value>,
    served: watch::Sender<Option<Arc<Served>>>,
}

impl SettingsSink {
    pub(crate) fn new(base: Map<String, Value>) -> (Self, ServedConfig) {
        let (served, receiver) = watch::channel(None);
        (Self { base, served }, receiver)
    }

    /// One source stream: its projections are served in revision order.
    pub fn stream(&self) -> SettingsStream<'_> {
        SettingsStream {
            sink: self,
            served: None,
        }
    }

    /// Whether no bundle serves this sink's configuration any more.
    pub fn is_closed(&self) -> bool {
        self.served.is_closed()
    }

    fn serve(&self, settings: &PublicUiSettings) -> Result<(), SettingsRejected> {
        let mut config = self.base.clone();
        config.insert(SETTINGS_KEY.to_owned(), projection(settings)?);
        let bytes = serde_json::to_vec(&Value::Object(config))
            .expect("a JSON map of strings, numbers and arrays serializes");
        self.served.send_replace(Some(Served::of(bytes)));
        Ok(())
    }
}

/// The projections of one source stream, applied in revision order.
#[derive(Debug)]
pub struct SettingsStream<'a> {
    sink: &'a SettingsSink,
    served: Option<u64>,
}

impl SettingsStream<'_> {
    /// Serves `settings` unless this stream already served the same or a newer
    /// revision, or the projection is not usable.
    pub fn apply(&mut self, settings: &PublicUiSettings) -> Result<(), SettingsRejected> {
        if let Some(served) = self.served
            && settings.revision <= served
        {
            return Err(SettingsRejected::Stale {
                offered: settings.revision,
                served,
            });
        }
        self.sink.serve(settings)?;
        self.served = Some(settings.revision);
        Ok(())
    }
}

/// The settings object a browser reads: only the principal types a UI
/// offers, under the names the UI uses.
fn projection(settings: &PublicUiSettings) -> Result<Value, SettingsRejected> {
    let registration = type_names(&settings.registration_principal_types);
    let mut object = Map::new();
    if registration.contains(&"username") {
        let minimum = settings.registration_username_min_length;
        if !(1..=USERNAME_MAX_LENGTH).contains(&minimum) {
            return Err(SettingsRejected::UsernameMinimum(minimum));
        }
        object.insert("registrationUsernameMinLength".into(), minimum.into());
    }
    object.insert("registrationPrincipalTypes".into(), registration.into());
    object.insert(
        "signInPrincipalTypes".into(),
        type_names(&settings.sign_in_principal_types).into(),
    );
    Ok(Value::Object(object))
}

fn type_names(types: &[i32]) -> Vec<&'static str> {
    let mut names = Vec::new();
    for value in types {
        let name = match PrincipalType::try_from(*value) {
            Ok(PrincipalType::Email) => "email",
            Ok(PrincipalType::Phone) => "phone",
            Ok(PrincipalType::Username) => "username",
            // No UI field enters another type; an unknown value is newer
            // than this host.
            _ => continue,
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// A source of the installation's public UI settings.
pub trait SettingsSource: Send {
    type Updates: SettingsUpdates;

    /// A stream whose first projection is the current one.
    fn subscribe(&mut self) -> impl Future<Output = Result<Self::Updates, tonic::Status>> + Send;
}

/// The projections of one subscription.
pub trait SettingsUpdates: Send {
    /// The next projection; `None` when the stream ended.
    fn next(
        &mut self,
    ) -> impl Future<Output = Result<Option<PublicUiSettings>, tonic::Status>> + Send;
}

/// The installation's `PublicUiSettingsService`, read over gRPC.
#[derive(Debug, Clone)]
pub struct GrpcSettingsSource {
    client: PublicUiSettingsServiceClient<tonic::transport::Channel>,
}

impl GrpcSettingsSource {
    /// A source at `endpoint`; it connects on the first subscription and
    /// again after each failure.
    pub fn new(endpoint: tonic::transport::Endpoint) -> Self {
        Self {
            client: PublicUiSettingsServiceClient::new(endpoint.connect_lazy()),
        }
    }
}

impl SettingsSource for GrpcSettingsSource {
    type Updates = tonic::Streaming<PublicUiSettings>;

    async fn subscribe(&mut self) -> Result<Self::Updates, tonic::Status> {
        Ok(self.client.watch_public_ui_settings(()).await?.into_inner())
    }
}

impl SettingsUpdates for tonic::Streaming<PublicUiSettings> {
    async fn next(&mut self) -> Result<Option<PublicUiSettings>, tonic::Status> {
        self.message().await
    }
}

/// How long [`follow`] waits before subscribing again: doubling from
/// `first` up to `longest`, from `first` again once a projection arrived.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub first: Duration,
    pub longest: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            first: Duration::from_millis(500),
            longest: Duration::from_secs(30),
        }
    }
}

/// Feeds `sink` from `source` until no bundle serves it: subscribes, serves
/// each projection in revision order, and after a failure or the end of a
/// stream subscribes again, while the last projection stays served. Whatever
/// it waits for (a subscription, the next projection, a retry), it ends with
/// the last bundle, so the upstream subscription goes with it.
pub async fn follow<S: SettingsSource>(sink: SettingsSink, source: S, retry: Retry) {
    tokio::select! {
        () = sink.served.closed() => {}
        () = feed(&sink, source, retry) => {}
    }
}

async fn feed<S: SettingsSource>(sink: &SettingsSink, mut source: S, retry: Retry) {
    let mut wait = retry.first;
    loop {
        match source.subscribe().await {
            Ok(mut updates) => {
                let mut stream = sink.stream();
                loop {
                    match updates.next().await {
                        Ok(Some(settings)) => match stream.apply(&settings) {
                            Ok(()) => wait = retry.first,
                            Err(e) => tracing::warn!("public UI settings not served: {e}"),
                        },
                        Ok(None) => {
                            tracing::info!("public UI settings stream ended");
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("public UI settings stream failed: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("public UI settings subscription failed: {e}"),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(retry.longest);
    }
}
