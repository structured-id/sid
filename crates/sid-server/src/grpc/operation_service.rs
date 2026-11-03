// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC OperationService: the period a new keyed command is named with,
//! issued by the store that owns the operation.

use std::sync::Arc;

use sid_core::grpc_error::refuse::storage_failure;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::operation_service_server::OperationService;
use sid_proto::sid::v1::{GetOperationPeriodRequest, OperationPeriod};
use tonic::{Request, Response, Status};

use super::convert::to_timestamp;

pub struct OperationServiceImpl {
    storage: Arc<dyn StorageBackend>,
}

impl OperationServiceImpl {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }
}

#[tonic::async_trait]
impl OperationService for OperationServiceImpl {
    /// Open to every caller: a period conveys no permission, and the store
    /// issues at most one per acceptance interval, however often it is asked.
    async fn get_operation_period(
        &self,
        _: Request<GetOperationPeriodRequest>,
    ) -> Result<Response<OperationPeriod>, Status> {
        let policy = self
            .storage
            .operation_period_policy()
            .await
            .map_err(storage_failure)?;
        let issued = self
            .storage
            .current_operation_period(chrono::Utc::now(), policy.acceptance)
            .await
            .map_err(storage_failure)?;
        Ok(Response::new(OperationPeriod {
            period: issued.period.get(),
            accepted_until: Some(to_timestamp(issued.accepted_until)),
        }))
    }
}

#[cfg(test)]
mod tests;
