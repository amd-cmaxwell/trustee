use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use kbs_types::Tee;
use key_value_storage::KeyValueStorage;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;

use super::backend::launch_policy::LaunchPolicyHandler;
use super::backend::snp::measurement::MeasurementHandler as SnpMeasurementHandler;

#[async_trait::async_trait]
pub trait RequestHandler: Send {
    async fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>>;
}

pub enum MeasurementHandler {
    Snp(SnpMeasurementHandler),
}

#[async_trait::async_trait]
impl RequestHandler for MeasurementHandler {
    async fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Snp(h) => h.handle(body).await,
        }
    }
}

pub fn get_request_handler(
    req_type: &str,
    tee: Tee,
    ovmf_file: &Path,
    policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
) -> Result<MeasurementHandler> {
    match (req_type, tee) {
        ("measurement", Tee::Snp) => Ok(MeasurementHandler::Snp(SnpMeasurementHandler::new(
            ovmf_file.to_path_buf(),
            policy_engine,
            storage,
        ))),
        ("measurement", other) => Err(anyhow!("unsupported TEE type for measurement: {other:?}")),
        _ => Err(anyhow!("unsupported request type: {req_type}")),
    }
}

pub fn get_launch_policy_handler(
    policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
) -> LaunchPolicyHandler {
    LaunchPolicyHandler::new(policy_engine, storage)
}
