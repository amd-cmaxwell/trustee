use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sev::firmware::guest::GuestPolicy;
use sev::measurement::idblock_types::{FamilyId, IdBlock, ImageId};
use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
use sev::measurement::vcpu_types::CpuType;
use sev::measurement::vmsa::{GuestFeatures, VMMType};
use sev::parser::ByteParser;

use super::super::super::api::RequestHandler;

#[derive(Deserialize)]
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
    pub guest_policy: Option<u64>,
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

pub struct MeasurementHandler {
    ovmf_file: PathBuf,
}

impl MeasurementHandler {
    pub fn new(ovmf_file: PathBuf) -> Self {
        Self { ovmf_file }
    }
}

impl RequestHandler for MeasurementHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let req: SnpMeasurementRequest = serde_json::from_slice(body)?;

        let vcpu_type = CpuType::try_from(req.vcpu_type.as_str())
            .map_err(|e| anyhow!("invalid vcpu_type: {e}"))?;

        let vmm_type = req
            .vmm_type
            .as_deref()
            .map(VMMType::from_str)
            .transpose()
            .map_err(|e| anyhow!("invalid vmm_type: {e}"))?;

        let guest_features = GuestFeatures(req.guest_features);

        let args = SnpMeasurementArgs {
            vcpus: req.vcpus,
            vcpu_type,
            ovmf_file: self.ovmf_file.clone(),
            guest_features,
            kernel_file: None,
            initrd_file: None,
            append: req.append.as_deref(),
            ovmf_hash_str: Some(req.ovmf_hash_str.as_str()),
            vmm_type,
            kernel_hash_str: req.kernel_hash_str.as_deref(),
            initrd_hash_str: req.initrd_hash_str.as_deref(),
        };

        let digest = snp_calc_launch_digest(args)
            .map_err(|e| anyhow!("measurement calculation failed: {e}"))?;

        let digest_bytes = digest
            .to_bytes()
            .map_err(|e| anyhow!("failed to serialize launch digest: {e}"))?;
        let measurement = hex::encode(digest_bytes);

        let id_block = match (&req.family_id, &req.image_id) {
            (Some(fam), Some(img)) => {
                let family_id = FamilyId::new(parse_id_bytes(fam)?);
                let image_id = ImageId::new(parse_id_bytes(img)?);

                let policy = req.guest_policy.map(GuestPolicy);

                let block = IdBlock::new(
                    Some(digest),
                    Some(family_id),
                    Some(image_id),
                    Some(0), // placeholder GUEST_SVN until RVPS integration
                    policy,
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
