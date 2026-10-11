use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Context, Result};

use crate::plugins::plugin_manager::PluginHttpError;
use base64::{engine::general_purpose::STANDARD, Engine};
use key_value_storage::KeyValueStorage;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use openssl::sha::sha256;
use policy_engine::policy::rego::Regorus;
use policy_engine::policy::rego::RegorusExtension;
use policy_engine::PolicyEngine;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::GuestPolicy;
use sev::measurement::idblock_types::{
    FamilyId, IdAuth, IdBlock, ImageId, SevEcdsaPubKey, DEFAULT_KEY_ALGO,
};
use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
use sev::measurement::vcpu_types::CpuType;
use sev::measurement::vmsa::{GuestFeatures, VMMType};
use sev::parser::ByteParser;

use super::super::super::api::RequestHandler;

const LAUNCH_POLICY_ID: &str = "launch-policy";
const MAGS_KEY: &str = "mags";
const POLICY_RULE: &str = "data.policy.authorized";

#[derive(Deserialize, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none", rename = "id-auth")]
    pub id_auth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "id-key")]
    pub id_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "author-key")]
    pub author_key: Option<String>,
}

fn parse_id_bytes(hex_str: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("invalid hex for id field: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("id field must be exactly 16 bytes"))
}

async fn read_mags(storage: &dyn KeyValueStorage) -> Result<u32> {
    match storage.get(MAGS_KEY).await? {
        Some(bytes) => {
            let val: u32 = serde_json::from_slice(&bytes)?;
            Ok(val)
        }
        None => Ok(0),
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth_value = headers.get("authorization")?.to_str().ok()?;
    let token = auth_value.strip_prefix("Bearer ")?;
    Some(token.to_string())
}

fn hash_key(data: &str) -> String {
    hex::encode(sha256(data.as_bytes()))
}

#[derive(Deserialize)]
struct StoredKeypair {
    #[allow(dead_code)]
    pubkey: String,
    privkey: String,
}

pub struct MeasurementHandler {
    ovmf_file: PathBuf,
    id_key: EcKey<Private>,
    is_auth: bool,
    rvps_address: Option<String>,
    policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
    secret_storage: Arc<dyn KeyValueStorage>,
}

impl MeasurementHandler {
    pub fn new(
        ovmf_file: PathBuf,
        id_key: EcKey<Private>,
        is_auth: bool,
        rvps_address: Option<String>,
        policy_engine: PolicyEngine<Regorus>,
        storage: Arc<dyn KeyValueStorage>,
        secret_storage: Arc<dyn KeyValueStorage>,
    ) -> Self {
        Self {
            ovmf_file,
            id_key,
            is_auth,
            rvps_address,
            policy_engine,
            storage,
            secret_storage,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for MeasurementHandler {
    async fn handle(&mut self, body: &[u8], headers: &HeaderMap) -> Result<Vec<u8>> {
        let req: SnpMeasurementRequest = serde_json::from_slice(body)?;

        if self.is_auth
            && (req.family_id.is_none() || req.image_id.is_none() || req.guest_policy.is_none())
        {
            return Err(PluginHttpError::bad_request(
                "auth endpoint requires family_id, image_id, and guest_policy",
            ));
        }

        let guest_owner_cert = if self.is_auth {
            extract_bearer_token(headers)
        } else {
            None
        };

        if self.is_auth {
            if let Ok(policy) = self.policy_engine.get_policy(LAUNCH_POLICY_ID).await {
                let mut input_value = serde_json::to_value(&req)?;
                if let Some(cert) = &guest_owner_cert {
                    input_value["guest_owner_cert"] = serde_json::Value::String(cert.clone());
                }
                let input = serde_json::to_string(&input_value)?;

                let mut extensions = vec![];
                if let Some(addr) = &self.rvps_address {
                    let addr = addr.clone();
                    let extension = RegorusExtension {
                        name: "query_reference_value".to_string(),
                        id: 1,
                        extension: Box::new(move |params: Vec<regorus::Value>| {
                            let param = params
                                .first()
                                .context("query_reference_value requires a parameter")?;
                            let id = param.as_string().map(|s| s.to_string()).map_err(|_| {
                                anyhow!("query_reference_value parameter must be a string")
                            })?;
                            let addr = addr.clone();
                            let result = tokio::runtime::Handle::current().block_on(async {
                                reference_value_provider_service::client::query(addr, id).await
                            })?;
                            match result {
                                Some(v) => Ok(serde_json::from_str::<regorus::Value>(&v)?),
                                None => Ok(regorus::Value::Null),
                            }
                        }),
                    };
                    extensions.push(extension);
                }

                let result = self
                    .policy_engine
                    .engine
                    .evaluate(
                        None,
                        input,
                        policy,
                        vec![POLICY_RULE.to_string()],
                        extensions,
                    )
                    .await?;

                let authorized = result
                    .eval_rules_result
                    .get(POLICY_RULE)
                    .and_then(|v| v.as_ref())
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !authorized {
                    return Err(PluginHttpError::forbidden(
                        "launch params rejected by SAMS policy",
                    ));
                }
            }
        }

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

        let mut id_block_b64 = None;
        let mut id_auth_b64 = None;
        let mut id_key_b64 = None;
        let mut author_key_b64 = None;

        if let (Some(fam), Some(img)) = (&req.family_id, &req.image_id) {
            let family_id = FamilyId::new(parse_id_bytes(fam)?);
            let image_id = ImageId::new(parse_id_bytes(img)?);
            let policy = req.guest_policy.map(GuestPolicy);
            let guest_svn = read_mags(&*self.storage).await?;

            let block = IdBlock::new(
                Some(digest),
                Some(family_id),
                Some(image_id),
                Some(guest_svn),
                policy,
            )?;

            let block_bytes = block
                .to_bytes()
                .map_err(|e| anyhow!("failed to serialize IdBlock: {e}"))?;
            id_block_b64 = Some(STANDARD.encode(block_bytes.as_ref()));

            if self.is_auth {
                let mut id_auth = IdAuth::default()
                    .sign_id_block(DEFAULT_KEY_ALGO, self.id_key.clone(), &block)
                    .map_err(|e| anyhow!("failed to sign IdBlock: {e}"))?;

                if let Some(cert) = &guest_owner_cert {
                    let cert_hash = hash_key(cert);
                    let keypair_bytes =
                        self.secret_storage.get(&cert_hash).await?.ok_or_else(|| {
                            PluginHttpError::unauthorized(
                                "guest-owner certificate is unknown to SAMS",
                            )
                        })?;

                    let keypair: StoredKeypair = serde_json::from_slice(&keypair_bytes)?;
                    let guest_owner_priv_key =
                        EcKey::private_key_from_pem(keypair.privkey.as_bytes())
                            .map_err(|e| anyhow!("invalid guest-owner private key: {e}"))?;

                    id_auth = id_auth
                        .sign_id_key(DEFAULT_KEY_ALGO, guest_owner_priv_key.clone())
                        .map_err(|e| anyhow!("failed to sign IDKey with guest-owner key: {e}"))?;

                    let guest_owner_pub_key = SevEcdsaPubKey::try_from(&guest_owner_priv_key)
                        .map_err(|e| anyhow!("failed to extract guest-owner public key: {e}"))?;
                    let guest_owner_pub_key_bytes = guest_owner_pub_key
                        .to_bytes()
                        .map_err(|e| anyhow!("failed to serialize guest-owner public key: {e}"))?;
                    author_key_b64 = Some(STANDARD.encode(guest_owner_pub_key_bytes.as_ref()));
                }

                let auth_bytes = id_auth
                    .to_bytes()
                    .map_err(|e| anyhow!("failed to serialize IdAuth: {e}"))?;
                id_auth_b64 = Some(STANDARD.encode(auth_bytes.as_ref()));

                let pub_key = SevEcdsaPubKey::try_from(&self.id_key)
                    .map_err(|e| anyhow!("failed to extract SAMS public key: {e}"))?;
                let key_bytes = pub_key
                    .to_bytes()
                    .map_err(|e| anyhow!("failed to serialize SAMS public key: {e}"))?;
                id_key_b64 = Some(STANDARD.encode(key_bytes.as_ref()));
            }
        }

        let resp = SnpMeasurementResponse {
            measurement,
            id_block: id_block_b64,
            id_auth: id_auth_b64,
            id_key: id_key_b64,
            author_key: author_key_b64,
        };
        Ok(serde_json::to_vec(&resp)?)
    }
}
