use std::collections::HashMap;
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
use policy_engine::policy::rego::Regorus;
use policy_engine::policy::rego::RegorusExtension;
use policy_engine::PolicyEngine;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::GuestPolicy;
use sev::measurement::idblock::get_key_digest;
use sev::measurement::idblock_types::{
    FamilyId, IdAuth, IdBlock, ImageId, SevEcdsaPubKey, DEFAULT_KEY_ALGO,
};
use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
use sev::measurement::vcpu_types::CpuType;
use sev::measurement::vmsa::{GuestFeatures, VMMType};
use sev::parser::ByteParser;

use super::super::super::api::RequestHandler;
use super::super::signing::{hash_cert, signing_policy_id};

const AUTH_POLICY_ID: &str = "auth-policy";
const MAGS_KEY: &str = "mags";
const AUTH_POLICY_RULE: &str = "data.policy.authorized";
const SIGNING_POLICY_PUBKEY_RULE: &str = "data.policy.pubkey";
const SIGNING_POLICY_PRIVKEY_RULE: &str = "data.policy.privkey";
const RVPS_GUEST_OWNER_CERTS_KEY: &str = "guest-owner-certs";

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

#[derive(Deserialize)]
struct GuestOwnerJwtClaims {
    certificate: String,
}

fn extract_guest_owner_cert(headers: &HeaderMap) -> Option<String> {
    let auth_value = headers.get("authorization")?.to_str().ok()?;
    let jwt = auth_value.strip_prefix("Bearer ")?;
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_b64 = parts.get(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: GuestOwnerJwtClaims = serde_json::from_slice(&payload_bytes).ok()?;
    Some(claims.certificate)
}

fn compute_auth_key_digest(privkey_pem: &str) -> Result<String> {
    let ec_key = EcKey::private_key_from_pem(privkey_pem.as_bytes())
        .map_err(|e| anyhow!("invalid guest-owner private key: {e}"))?;
    let sev_pub_key = SevEcdsaPubKey::try_from(&ec_key)
        .map_err(|e| anyhow!("failed to convert to SevEcdsaPubKey: {e}"))?;
    let digest =
        get_key_digest(sev_pub_key).map_err(|e| anyhow!("failed to compute AuthKeyDigest: {e}"))?;
    let digest_bytes = digest
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize AuthKeyDigest: {e}"))?;
    Ok(hex::encode(digest_bytes))
}

pub fn build_rvps_message(certs_map: &HashMap<String, String>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_GUEST_OWNER_CERTS_KEY: certs_map });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

pub async fn read_rvps_certs_map(addr: &str) -> Result<HashMap<String, String>> {
    let result = reference_value_provider_service::client::query(
        addr.to_string(),
        RVPS_GUEST_OWNER_CERTS_KEY.to_string(),
    )
    .await?;

    match result {
        Some(json_str) => {
            let map: HashMap<String, String> = serde_json::from_str(&json_str)?;
            Ok(map)
        }
        None => Ok(HashMap::new()),
    }
}

pub struct MeasurementHandler {
    ovmf_file: PathBuf,
    id_key: EcKey<Private>,
    is_auth: bool,
    rvps_address: Option<String>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
}

impl MeasurementHandler {
    pub fn new(
        ovmf_file: PathBuf,
        id_key: EcKey<Private>,
        is_auth: bool,
        rvps_address: Option<String>,
        auth_policy_engine: PolicyEngine<Regorus>,
        signing_policy_engine: PolicyEngine<Regorus>,
        storage: Arc<dyn KeyValueStorage>,
    ) -> Self {
        Self {
            ovmf_file,
            id_key,
            is_auth,
            rvps_address,
            auth_policy_engine,
            signing_policy_engine,
            storage,
        }
    }
}

struct SigningKeys {
    privkey: EcKey<Private>,
    privkey_pem: String,
}

async fn evaluate_signing_policy(
    signing_policy_engine: &PolicyEngine<Regorus>,
    cert_hash: &str,
    input: &str,
) -> Result<SigningKeys> {
    let policy_id = signing_policy_id(cert_hash);
    let policy = signing_policy_engine
        .get_policy(&policy_id)
        .await
        .map_err(|_| {
            PluginHttpError::unauthorized("guest-owner signing policy not found in SAMS")
        })?;

    let result = signing_policy_engine
        .engine
        .evaluate(
            None,
            input.to_string(),
            policy,
            vec![
                SIGNING_POLICY_PUBKEY_RULE.to_string(),
                SIGNING_POLICY_PRIVKEY_RULE.to_string(),
            ],
            vec![],
        )
        .await
        .map_err(|e| anyhow!("signing policy evaluation failed: {e}"))?;

    let privkey_pem = result
        .eval_rules_result
        .get(SIGNING_POLICY_PRIVKEY_RULE)
        .and_then(|v| v.as_ref())
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PluginHttpError::forbidden(
                "signing policy did not produce a valid privkey for these launch params",
            )
        })?
        .to_string();

    let privkey = EcKey::private_key_from_pem(privkey_pem.as_bytes())
        .map_err(|e| anyhow!("signing policy produced an invalid private key PEM: {e}"))?;

    Ok(SigningKeys {
        privkey,
        privkey_pem,
    })
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
            extract_guest_owner_cert(headers)
        } else {
            None
        };

        if self.is_auth {
            if let Ok(policy) = self.auth_policy_engine.get_policy(AUTH_POLICY_ID).await {
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
                    .auth_policy_engine
                    .engine
                    .evaluate(
                        None,
                        input,
                        policy,
                        vec![AUTH_POLICY_RULE.to_string()],
                        extensions,
                    )
                    .await?;

                let authorized = result
                    .eval_rules_result
                    .get(AUTH_POLICY_RULE)
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
                    let cert_hash = hash_cert(cert);
                    let input = serde_json::to_string(&serde_json::to_value(&req)?)?;

                    let signing_keys =
                        evaluate_signing_policy(&self.signing_policy_engine, &cert_hash, &input)
                            .await?;

                    id_auth = id_auth
                        .sign_id_key(DEFAULT_KEY_ALGO, signing_keys.privkey.clone())
                        .map_err(|e| anyhow!("failed to sign IDKey with guest-owner key: {e}"))?;

                    let guest_owner_pub_key = SevEcdsaPubKey::try_from(&signing_keys.privkey)
                        .map_err(|e| anyhow!("failed to extract guest-owner public key: {e}"))?;
                    let guest_owner_pub_key_bytes = guest_owner_pub_key
                        .to_bytes()
                        .map_err(|e| anyhow!("failed to serialize guest-owner public key: {e}"))?;
                    author_key_b64 = Some(STANDARD.encode(guest_owner_pub_key_bytes.as_ref()));

                    if let Some(addr) = &self.rvps_address {
                        let auth_key_digest = compute_auth_key_digest(&signing_keys.privkey_pem)?;
                        let mut certs_map = read_rvps_certs_map(addr).await?;
                        certs_map.insert(auth_key_digest, cert.clone());
                        let message = build_rvps_message(&certs_map)?;
                        reference_value_provider_service::client::register(addr.clone(), message)
                            .await?;
                    }
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
