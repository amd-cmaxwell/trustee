use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::super::api::RequestHandler;

#[derive(Deserialize)]
pub struct MeasurementRequest {
    pub vcpus: u32,
    pub ovmf_hash: Option<String>,
    pub kernel_hash: Option<String>,
    pub initrd_hash: Option<String>,
    pub append: Option<String>,
}

#[derive(Serialize)]
pub struct MeasurementResponse {
    pub digest: String,
}

pub struct MeasurementHandler;

impl RequestHandler for MeasurementHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let _req: MeasurementRequest = serde_json::from_slice(body)?;
        // TODO: convert request fields to SnpMeasurementArgs and call snp_calc_launch_digest
        Err(anyhow::anyhow!("SNP measurement not yet implemented"))
    }
}
