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

pub enum SamsHandler {
    Measurement(MeasurementHandler),
    LaunchPolicy(LaunchPolicyHandler),
}

impl SamsHandler {
    pub fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Measurement(h) => h.handle(body),
            Self::LaunchPolicy(h) => h.handle(body),
        }
    }
}

pub fn get_request_handler(req_type: &str, tee: Option<Tee>) -> Result<SamsHandler> {
    match req_type {
        "measurement" => {
            let tee = tee.ok_or_else(|| anyhow!("measurement endpoint requires a TEE type"))?;
            let handler = match tee {
                Tee::Snp => MeasurementHandler::Snp(SnpMeasurementHandler),
                other => return Err(anyhow!("unsupported TEE type for measurement: {other:?}")),
            };
            Ok(SamsHandler::Measurement(handler))
        }
        "launch-policy" => Ok(SamsHandler::LaunchPolicy(LaunchPolicyHandler)),
        _ => Err(anyhow!("unsupported request type: {req_type}")),
    }
}
