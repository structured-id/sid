// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's public UI settings over gRPC
//! (`sid.v1.ui.PublicUiSettingsService`): answered from the engine's
//! in-memory projection, never from the store. Public: only effective
//! choices, nothing about any account.

use std::pin::Pin;
use std::sync::Arc;

use sid::public_settings::PublicSettings;
use sid_proto::sid::v1::ui::PublicUiSettings;
use sid_proto::sid::v1::ui::public_ui_settings_service_server::PublicUiSettingsService;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

pub struct PublicUiSettingsServiceImpl {
    settings: Arc<PublicSettings>,
}

impl PublicUiSettingsServiceImpl {
    pub fn new(settings: Arc<PublicSettings>) -> Self {
        Self { settings }
    }
}

#[tonic::async_trait]
impl PublicUiSettingsService for PublicUiSettingsServiceImpl {
    async fn get_public_ui_settings(
        &self,
        _request: Request<()>,
    ) -> Result<Response<PublicUiSettings>, Status> {
        Ok(Response::new(self.settings.current()))
    }

    type WatchPublicUiSettingsStream =
        Pin<Box<dyn Stream<Item = Result<PublicUiSettings, Status>> + Send>>;

    /// The current projection first, then each newer one; a reader that
    /// falls behind receives the latest.
    async fn watch_public_ui_settings(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::WatchPublicUiSettingsStream>, Status> {
        let projections = WatchStream::new(self.settings.subscribe()).map(Ok);
        Ok(Response::new(Box::pin(projections)))
    }
}
