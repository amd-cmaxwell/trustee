use std::path::Path;

use anyhow::{anyhow, Result};
use kbs_types::Tee;

use super::backend::launch_policy::LaunchPolicyHandler;
use super::backend::snp::measurement::MeasurementHandler as SnpMeasurementHandler;

pub trait RequestHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>>;
}

pub enum MeasurementHandler {
    Snp(SnpMeasurementHandler),
}

impl RequestHandler for MeasurementHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Snp(h) => h.handle(body),
        }
    }
}

pub fn get_request_handler(
    req_type: &str,
    tee: Tee,
    ovmf_file: &Path,
) -> Result<MeasurementHandler> {
    match (req_type, tee) {
        ("measurement", Tee::Snp) => Ok(MeasurementHandler::Snp(SnpMeasurementHandler::new(
            ovmf_file.to_path_buf(),
        ))),
        ("measurement", other) => Err(anyhow!("unsupported TEE type for measurement: {other:?}")),
        _ => Err(anyhow!("unsupported request type: {req_type}")),
    }
}

pub fn get_launch_policy_handler() -> LaunchPolicyHandler {
    LaunchPolicyHandler
}
