pub mod auth;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Context, Result};

use crate::plugins::implementations::sams::rvps_client::RvpsClient;
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
use sev::measurement::idblock_types::{
    FamilyId, IdAuth, IdBlock, ImageId, SevEcdsaPubKey, DEFAULT_KEY_ALGO,
};
use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
use sev::measurement::vcpu_types::CpuType;
use sev::measurement::vmsa::{GuestFeatures, VMMType};
use sev::parser::ByteParser;
use tokio::sync::Mutex;

use super::super::super::api::RequestHandler;
use super::super::authorization::{AUTH_POLICY_ID, MAGS_KEY};
use super::super::signing::hash_cert;

use auth::{
    compute_auth_key_digest, evaluate_signing_policy, extract_guest_owner_cert, parse_x509_to_json,
    AUTH_POLICY_RULE,
};

const RVPS_GUEST_OWNER_CERTS_KEY: &str = "guest-owner-certs";
const RVPS_GUEST_OWNER_PUBKEYS_KEY: &str = "guest-owner-pubkeys";

#[derive(Deserialize, Serialize)]
pub struct SnpMeasurementRequest {
    pub vcpus: u32,
    pub vcpu_type: CpuType,
    #[serde(default)]
    pub vmm_type: Option<VMMType>,
    pub guest_features: GuestFeatures,
    pub ovmf_hash_str: String,
    #[serde(default)]
    pub kernel_hash_str: Option<String>,
    #[serde(default)]
    pub initrd_hash_str: Option<String>,
    #[serde(default)]
    pub append: Option<String>,
    #[serde(default)]
    pub guest_policy: Option<GuestPolicy>,
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

pub fn build_rvps_message(certs_map: &HashMap<String, Vec<String>>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_GUEST_OWNER_CERTS_KEY: certs_map });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

pub async fn read_rvps_certs_map(client: &dyn RvpsClient) -> Result<HashMap<String, Vec<String>>> {
    let result = client.query(RVPS_GUEST_OWNER_CERTS_KEY.to_string()).await?;

    match result {
        Some(json_str) => {
            let map: HashMap<String, Vec<String>> = serde_json::from_str(&json_str)?;
            Ok(map)
        }
        None => Ok(HashMap::new()),
    }
}

pub fn build_rvps_pubkeys_message(pubkeys_map: &HashMap<String, String>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_GUEST_OWNER_PUBKEYS_KEY: pubkeys_map });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

pub async fn read_rvps_pubkeys_map(client: &dyn RvpsClient) -> Result<HashMap<String, String>> {
    let result = client
        .query(RVPS_GUEST_OWNER_PUBKEYS_KEY.to_string())
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
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
}

impl MeasurementHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ovmf_file: PathBuf,
        id_key: EcKey<Private>,
        is_auth: bool,
        rvps_client: Option<Arc<dyn RvpsClient>>,
        rvps_certs_lock: Arc<Mutex<()>>,
        auth_policy_engine: PolicyEngine<Regorus>,
        signing_policy_engine: PolicyEngine<Regorus>,
        storage: Arc<dyn KeyValueStorage>,
    ) -> Self {
        Self {
            ovmf_file,
            id_key,
            is_auth,
            rvps_client,
            rvps_certs_lock,
            auth_policy_engine,
            signing_policy_engine,
            storage,
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
            extract_guest_owner_cert(headers)
        } else {
            None
        };

        if self.is_auth {
            if let Ok(policy) = self.auth_policy_engine.get_policy(AUTH_POLICY_ID).await {
                let mut input_value = serde_json::to_value(&req)?;
                if let Some(cert) = &guest_owner_cert {
                    if let Ok(parsed) = parse_x509_to_json(cert) {
                        input_value["guest_owner_cert"] = parsed;
                    }
                }
                let input = serde_json::to_string(&input_value)?;

                let mut extensions = vec![];
                if let Some(client) = &self.rvps_client {
                    let client = client.clone();
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
                            let client = client.clone();
                            let result = tokio::runtime::Handle::current()
                                .block_on(async { client.query(id).await })?;
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

        let args = SnpMeasurementArgs {
            vcpus: req.vcpus,
            vcpu_type: req.vcpu_type,
            ovmf_file: self.ovmf_file.clone(),
            guest_features: req.guest_features,
            kernel_file: None,
            initrd_file: None,
            append: req.append.as_deref(),
            ovmf_hash_str: Some(req.ovmf_hash_str.as_str()),
            vmm_type: req.vmm_type,
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
            let policy = req.guest_policy;
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

                    if let Some(client) = &self.rvps_client {
                        let _guard = self.rvps_certs_lock.lock().await;
                        let auth_key_digest = compute_auth_key_digest(&signing_keys.privkey_pem)?;

                        let mut certs_map = read_rvps_certs_map(client.as_ref()).await?;
                        let certs = certs_map.entry(auth_key_digest.clone()).or_default();
                        if !certs.contains(cert) {
                            certs.push(cert.clone());
                        }
                        let message = build_rvps_message(&certs_map)?;
                        client.register(message).await?;

                        let mut pubkeys_map = read_rvps_pubkeys_map(client.as_ref()).await?;
                        pubkeys_map
                            .entry(auth_key_digest)
                            .or_insert_with(|| author_key_b64.clone().unwrap());
                        let message = build_rvps_pubkeys_message(&pubkeys_map)?;
                        client.register(message).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::implementations::sams::rvps_client::test_support::MockRvpsClient;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use policy_engine::policy::rego::Regorus;
    use policy_engine::PolicyEngine;
    use rstest::rstest;

    fn memory_storage() -> Arc<dyn key_value_storage::KeyValueStorage> {
        Arc::new(MemoryKeyValueStorage::default())
    }

    fn memory_policy_engine() -> PolicyEngine<Regorus> {
        PolicyEngine::<Regorus>::new(memory_storage())
    }

    fn test_ec_key() -> EcKey<Private> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        EcKey::generate(&group).unwrap()
    }

    // --- parse_id_bytes ---

    #[test]
    fn test_parse_id_bytes_valid() {
        let result = parse_id_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            result,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_parse_id_bytes_invalid_hex() {
        let err = parse_id_bytes("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap_err();
        assert!(err.to_string().contains("invalid hex"), "unexpected: {err}");
    }

    #[rstest]
    #[case("0001")]
    #[case("")]
    #[case("000102030405060708090a0b0c0d0e0f00")]
    fn test_parse_id_bytes_wrong_length(#[case] input: &str) {
        let err = parse_id_bytes(input).unwrap_err();
        assert!(
            err.to_string().contains("exactly 16 bytes"),
            "unexpected: {err}"
        );
    }

    // --- build/read RVPS messages ---

    #[test]
    fn test_build_rvps_message_roundtrip() {
        let mut map = HashMap::new();
        map.insert(
            "digest-1".to_string(),
            vec!["cert-a".to_string(), "cert-b".to_string()],
        );

        let message = build_rvps_message(&map).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&message).unwrap();
        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["type"], "sample");

        let payload_b64 = parsed["payload"].as_str().unwrap();
        let payload_bytes = STANDARD.decode(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let certs = payload[RVPS_GUEST_OWNER_CERTS_KEY]["digest-1"]
            .as_array()
            .unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_build_rvps_message_empty_map() {
        let map = HashMap::new();
        let message = build_rvps_message(&map).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&message).unwrap();
        let payload_bytes = STANDARD
            .decode(parsed["payload"].as_str().unwrap())
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let certs_map = payload[RVPS_GUEST_OWNER_CERTS_KEY].as_object().unwrap();
        assert!(certs_map.is_empty());
    }

    #[test]
    fn test_build_rvps_pubkeys_message_roundtrip() {
        let mut map = HashMap::new();
        map.insert("digest-1".to_string(), "pubkey-data".to_string());

        let message = build_rvps_pubkeys_message(&map).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&message).unwrap();
        let payload_bytes = STANDARD
            .decode(parsed["payload"].as_str().unwrap())
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(
            payload[RVPS_GUEST_OWNER_PUBKEYS_KEY]["digest-1"],
            "pubkey-data"
        );
    }

    #[tokio::test]
    async fn test_read_rvps_certs_map_empty() {
        let client = MockRvpsClient::new();
        let result = read_rvps_certs_map(&client).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_read_rvps_certs_map_after_register() {
        let client = MockRvpsClient::new();

        let mut expected = HashMap::new();
        expected.insert("key-1".to_string(), vec!["cert-1".to_string()]);

        let message = build_rvps_message(&expected).unwrap();
        client.register(message).await.unwrap();

        let result = read_rvps_certs_map(&client).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_read_rvps_pubkeys_map_empty() {
        let client = MockRvpsClient::new();
        let result = read_rvps_pubkeys_map(&client).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_read_rvps_pubkeys_map_after_register() {
        let client = MockRvpsClient::new();

        let mut expected = HashMap::new();
        expected.insert("key-1".to_string(), "pubkey-1".to_string());

        let message = build_rvps_pubkeys_message(&expected).unwrap();
        client.register(message).await.unwrap();

        let result = read_rvps_pubkeys_map(&client).await.unwrap();
        assert_eq!(result, expected);
    }

    // --- SnpMeasurementRequest/Response serde ---

    #[test]
    fn test_snp_measurement_request_deserialize_minimal() {
        let json = serde_json::json!({
            "vcpus": 4,
            "vcpu_type": "EpycV4",
            "guest_features": 1,
            "ovmf_hash_str": "abcdef0123456789"
        });
        let req: SnpMeasurementRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.vcpus, 4);
        assert_eq!(req.ovmf_hash_str, "abcdef0123456789");
        assert!(req.vmm_type.is_none());
        assert!(req.kernel_hash_str.is_none());
        assert!(req.initrd_hash_str.is_none());
        assert!(req.append.is_none());
        assert!(req.guest_policy.is_none());
        assert!(req.family_id.is_none());
        assert!(req.image_id.is_none());
    }

    #[test]
    fn test_snp_measurement_request_deserialize_full() {
        let json = serde_json::json!({
            "vcpus": 8,
            "vcpu_type": "EpycV4",
            "vmm_type": "QEMU",
            "guest_features": 1,
            "ovmf_hash_str": "abcdef",
            "kernel_hash_str": "112233",
            "initrd_hash_str": "445566",
            "append": "console=ttyS0",
            "guest_policy": 196608,
            "family_id": "000102030405060708090a0b0c0d0e0f",
            "image_id": "0f0e0d0c0b0a09080706050403020100"
        });
        let req: SnpMeasurementRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.vcpus, 8);
        assert!(req.vmm_type.is_some());
        assert!(req.kernel_hash_str.is_some());
        assert!(req.initrd_hash_str.is_some());
        assert!(req.append.is_some());
        assert!(req.guest_policy.is_some());
        assert!(req.family_id.is_some());
        assert!(req.image_id.is_some());
    }

    #[test]
    fn test_snp_measurement_response_serialization_partial() {
        let resp = SnpMeasurementResponse {
            measurement: "deadbeef".to_string(),
            id_block: None,
            id_auth: None,
            id_key: None,
            author_key: None,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["measurement"], "deadbeef");
        assert!(json.get("id-block").is_none());
        assert!(json.get("id-auth").is_none());
        assert!(json.get("id-key").is_none());
        assert!(json.get("author-key").is_none());
    }

    #[test]
    fn test_snp_measurement_response_serialization_full() {
        let resp = SnpMeasurementResponse {
            measurement: "deadbeef".to_string(),
            id_block: Some("block".to_string()),
            id_auth: Some("auth".to_string()),
            id_key: Some("key".to_string()),
            author_key: Some("author".to_string()),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["measurement"], "deadbeef");
        assert_eq!(json["id-block"], "block");
        assert_eq!(json["id-auth"], "auth");
        assert_eq!(json["id-key"], "key");
        assert_eq!(json["author-key"], "author");
    }

    // --- read_mags ---

    #[tokio::test]
    async fn test_read_mags_empty_returns_zero() {
        let storage = memory_storage();
        let result = read_mags(&*storage).await.unwrap();
        assert_eq!(result, 0);
    }

    // --- MeasurementHandler ---

    #[tokio::test]
    async fn test_measurement_handler_auth_missing_required_fields() {
        let id_key = test_ec_key();
        let storage = memory_storage();
        let mut handler = MeasurementHandler::new(
            PathBuf::from("/dev/null"),
            id_key,
            true,
            None,
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
            storage,
        );

        let req = serde_json::json!({
            "vcpus": 4,
            "vcpu_type": "EpycV4",
            "guest_features": 1,
            "ovmf_hash_str": "abcdef0123456789"
        });
        let body = serde_json::to_vec(&req).unwrap();
        let headers = actix_web::http::header::HeaderMap::new();

        let err = handler.handle(&body, &headers).await.unwrap_err();
        assert!(
            err.to_string().contains("auth endpoint requires"),
            "unexpected error: {err}"
        );
    }
}
