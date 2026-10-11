use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sev::measurement::idblock_types::{FamilyId, IdBlock, ImageId};
use sev::measurement::snp::SnpLaunchDigest;
use sev::parser::ByteParser;

use super::super::super::api::RequestHandler;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SnpMeasurementRequest {
    pub vcpus: u32,
    pub vcpu_type: String,
    #[serde(default)]
    pub vmm_type: Option<String>,
    pub guest_features: u64,
    pub ovmf_hash_str: String,
    #[serde(default)]
    pub kernel_hash_str: Option<String>,
    #[serde(default)]
    pub initrd_hash_str: Option<String>,
    #[serde(default)]
    pub append: Option<String>,
    #[serde(default)]
    pub family_id: Option<String>,
    #[serde(default)]
    pub image_id: Option<String>,
}

#[derive(Serialize)]
pub struct SnpMeasurementResponse {
    pub measurement: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "id-block")]
    pub id_block: Option<String>,
}

fn parse_id_bytes(hex_str: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("invalid hex for id field: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("id field must be exactly 16 bytes"))
}

pub struct MeasurementHandler;

impl RequestHandler for MeasurementHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let req: SnpMeasurementRequest = serde_json::from_slice(body)?;

        // TODO: compute real launch digest via snp_calc_launch_digest once
        // the sev crate's hash-from-string path is wired up end-to-end.
        let digest = SnpLaunchDigest::default();
        let digest_bytes = digest
            .to_bytes()
            .map_err(|e| anyhow!("failed to serialize launch digest: {e}"))?;
        let measurement = hex::encode(digest_bytes);

        let id_block = match (&req.family_id, &req.image_id) {
            (Some(fam), Some(img)) => {
                let family_id = FamilyId::new(parse_id_bytes(fam)?);
                let image_id = ImageId::new(parse_id_bytes(img)?);

                let block = IdBlock::new(
                    Some(digest),
                    Some(family_id),
                    Some(image_id),
                    Some(0), // placeholder GUEST_SVN until RVPS integration
                    None,
                )?;

                let block_bytes = block
                    .to_bytes()
                    .map_err(|e| anyhow!("failed to serialize IdBlock: {e}"))?;
                Some(STANDARD.encode(block_bytes.as_ref()))
            }
            _ => None,
        };

        let resp = SnpMeasurementResponse {
            measurement,
            id_block,
        };
        Ok(serde_json::to_vec(&resp)?)
    }
}
