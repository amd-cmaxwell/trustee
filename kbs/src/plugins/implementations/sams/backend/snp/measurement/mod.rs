pub mod auth;

use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use actix_web::http::Method;
use anyhow::{anyhow, Context, Result};

use crate::plugins::implementations::sams::rvps_client::RvpsClient;
use crate::plugins::plugin_manager::PluginHttpError;
use base64::{engine::general_purpose::STANDARD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
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
use sev::measurement::ovmf::OvmfMeasurement;
use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
use sev::measurement::vcpu_types::CpuType;
use sev::measurement::vmsa::{GuestFeatures, VMMType};
use sev::parser::ByteParser;
use tokio::sync::Mutex;

use super::super::super::api::RequestHandler;
use super::super::authorization::AUTH_POLICY_ID;
use super::super::rvps_helpers::{
    build_rvps_message, build_rvps_pubkeys_message, ensure_salt_for_mage, read_mage,
    read_rvps_certs_map, read_rvps_pubkeys_map, read_sage_salts,
};
use super::super::signing::hash_cert;

use auth::{
    compute_auth_key_digest, evaluate_signing_policy, extract_guest_owner_cert, parse_x509_to_json,
    AUTH_POLICY_RULE,
};

#[derive(Deserialize, Serialize)]
pub struct SnpMeasurementRequest {
    pub vcpus: u32,
    pub vcpu_type: CpuType,
    #[serde(default)]
    pub vmm_type: Option<VMMType>,
    pub guest_features: GuestFeatures,
    pub ovmf_measurement: OvmfMeasurement,
    #[serde(default)]
    pub kernel_hash_str: Option<String>,
    #[serde(default)]
    pub initrd_hash_str: Option<String>,
    #[serde(default)]
    pub append: Option<String>,
    #[serde(default)]
    pub guest_policy: Option<GuestPolicy>,
    #[serde(default)]
    pub guest_svn: Option<u32>,
    #[serde(default)]
    pub family_id: Option<String>,
    #[serde(default)]
    pub image_id: Option<String>,
}

#[derive(Serialize)]
pub struct CageTokenClaims {
    pub id_block: serde_json::Value,
    pub id_auth: serde_json::Value,
    pub mage: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_owner_key: Option<String>,
    pub sams_key: String,
    pub salted_hash: String,
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
    #[serde(skip_serializing_if = "Option::is_none", rename = "cage-token")]
    pub cage_token: Option<String>,
}

fn parse_id_bytes(hex_str: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("invalid hex for id field: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("id field must be exactly 16 bytes"))
}

fn compute_salted_hash(claims_without_hash: &serde_json::Value, salt: &str) -> String {
    let canonical = serde_json::to_vec(claims_without_hash).expect("claims must serialize");
    let mut input = canonical;
    input.extend_from_slice(salt.as_bytes());
    hex::encode(openssl::sha::sha384(&input))
}

#[allow(clippy::too_many_arguments)]
fn sign_cage_token(
    id_key: &EcKey<Private>,
    mage: u32,
    id_block: &IdBlock,
    id_auth: &IdAuth,
    salt: &str,
    certificate: Option<&str>,
    guest_owner_key: Option<&str>,
    sams_key: &str,
) -> Result<String> {
    let partial = serde_json::json!({
        "id_block": serde_json::to_value(id_block)?,
        "id_auth": serde_json::to_value(id_auth)?,
        "mage": mage,
        "certificate": certificate,
        "guest_owner_key": guest_owner_key,
        "sams_key": sams_key,
    });
    let salted_hash = compute_salted_hash(&partial, salt);

    let claims = CageTokenClaims {
        id_block: serde_json::to_value(id_block)?,
        id_auth: serde_json::to_value(id_auth)?,
        mage,
        certificate: certificate.map(String::from),
        guest_owner_key: guest_owner_key.map(String::from),
        sams_key: sams_key.to_string(),
        salted_hash,
    };

    let pkey = openssl::pkey::PKey::from_ec_key(id_key.clone())
        .map_err(|e| anyhow!("failed to create PKey from SAMS id_key: {e}"))?;
    let pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| anyhow!("failed to serialize SAMS id_key to PEM: {e}"))?;
    let encoding_key = EncodingKey::from_ec_pem(&pem)
        .map_err(|e| anyhow!("failed to create JWT encoding key: {e}"))?;

    encode(&Header::new(Algorithm::ES384), &claims, &encoding_key)
        .map_err(|e| anyhow!("failed to sign CAGE token: {e}"))
}

pub struct MeasurementGetHandler {
    signing_requested: bool,
}

impl MeasurementGetHandler {
    pub fn new(signing_requested: bool) -> Self {
        Self { signing_requested }
    }
}

#[async_trait::async_trait]
impl RequestHandler for MeasurementGetHandler {
    async fn handle(&mut self, _body: &[u8], _headers: &HeaderMap) -> Result<Vec<u8>> {
        if self.signing_requested {
            Err(PluginHttpError::method_not_allowed_with_allow(
                "GET is not supported for this endpoint. \
                 Use POST /kbs/v0/sams/measurement/snp/signed with a JSON body containing: \
                 vcpus (u32), vcpu_type (CpuType), guest_features (GuestFeatures), \
                 ovmf_measurement (OvmfMeasurement), and required fields: \
                 family_id (hex string, 16 bytes), image_id (hex string, 16 bytes), \
                 guest_policy (GuestPolicy). Optional fields: vmm_type (VMMType), \
                 kernel_hash_str, initrd_hash_str, append. \
                 A guest-owner certificate may be included via an Authorization: Bearer <JWT> \
                 header, where the JWT payload contains a \"certificate\" claim with the \
                 PEM-encoded client certificate.",
                &[Method::POST],
            ))
        } else {
            Err(PluginHttpError::method_not_allowed_with_allow(
                "GET is not supported for this endpoint. \
                 Use POST /kbs/v0/sams/measurement/snp with a JSON body containing: \
                 vcpus (u32), vcpu_type (CpuType), guest_features (GuestFeatures), \
                 ovmf_measurement (OvmfMeasurement). Optional fields: vmm_type (VMMType), \
                 kernel_hash_str, initrd_hash_str, append, guest_policy (GuestPolicy), \
                 family_id (hex string, 16 bytes), image_id (hex string, 16 bytes).",
                &[Method::POST],
            ))
        }
    }
}

pub struct MeasurementPostHandler {
    id_key: EcKey<Private>,
    signing_requested: bool,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    mage_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
}

impl MeasurementPostHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id_key: EcKey<Private>,
        signing_requested: bool,
        rvps_client: Option<Arc<dyn RvpsClient>>,
        rvps_certs_lock: Arc<Mutex<()>>,
        mage_lock: Arc<Mutex<()>>,
        auth_policy_engine: PolicyEngine<Regorus>,
        signing_policy_engine: PolicyEngine<Regorus>,
    ) -> Self {
        Self {
            id_key,
            signing_requested,
            rvps_client,
            rvps_certs_lock,
            mage_lock,
            auth_policy_engine,
            signing_policy_engine,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for MeasurementPostHandler {
    async fn handle(&mut self, body: &[u8], headers: &HeaderMap) -> Result<Vec<u8>> {
        let req: SnpMeasurementRequest = serde_json::from_slice(body)?;
        let guest_owner_cert = extract_guest_owner_cert(headers);
        let signing_requested = self.signing_requested;

        if signing_requested
            && (req.family_id.is_none() || req.image_id.is_none() || req.guest_policy.is_none())
        {
            return Err(PluginHttpError::bad_request(
                "auth endpoint requires family_id, image_id, and guest_policy",
            ));
        }

        if signing_requested {
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
            ovmf_file: None,
            guest_features: req.guest_features,
            kernel_file: None,
            initrd_file: None,
            append: req.append.as_deref(),
            ovmf_hash_str: None,
            vmm_type: req.vmm_type,
            kernel_hash_str: req.kernel_hash_str.as_deref(),
            initrd_hash_str: req.initrd_hash_str.as_deref(),
            ovmf_measurement: Some(req.ovmf_measurement.clone()),
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

        let mut cage_token_out = None;

        if let (Some(fam), Some(img)) = (&req.family_id, &req.image_id) {
            let family_id = FamilyId::new(parse_id_bytes(fam)?);
            let image_id = ImageId::new(parse_id_bytes(img)?);
            let policy = req.guest_policy;
            let guest_svn = req.guest_svn.unwrap_or(0);

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

            if signing_requested {
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

                let (mage, salt) = {
                    let client = self.rvps_client.as_ref().ok_or_else(|| {
                        anyhow!("RVPS is required for MAGE and CAGE salt on auth endpoints")
                    })?;
                    let _guard = self.mage_lock.lock().await;
                    let mage = read_mage(client.as_ref()).await?;
                    ensure_salt_for_mage(client.as_ref(), mage).await?;
                    let salts = read_sage_salts(client.as_ref()).await?;
                    let salt = salts
                        .get(&mage.to_string())
                        .cloned()
                        .expect("salt must exist after ensure_salt_for_mage");
                    (mage, salt)
                };
                cage_token_out = Some(sign_cage_token(
                    &self.id_key,
                    mage,
                    &block,
                    &id_auth,
                    &salt,
                    guest_owner_cert.as_deref(),
                    author_key_b64.as_deref(),
                    id_key_b64.as_ref().unwrap(),
                )?);
            }
        }

        let resp = SnpMeasurementResponse {
            measurement,
            id_block: id_block_b64,
            id_auth: id_auth_b64,
            id_key: id_key_b64,
            author_key: author_key_b64,
            cage_token: cage_token_out,
        };
        Ok(serde_json::to_vec(&resp)?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::rvps_helpers::{
        RVPS_GUEST_OWNER_CERTS_KEY, RVPS_GUEST_OWNER_PUBKEYS_KEY,
    };
    use super::*;
    use crate::plugins::implementations::sams::rvps_client::test_support::MockRvpsClient;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use policy_engine::policy::rego::Regorus;
    use policy_engine::PolicyEngine;
    use rstest::rstest;
    use std::collections::HashMap;

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
            "ovmf_measurement": dummy_ovmf_measurement_b64()
        });
        let req: SnpMeasurementRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.vcpus, 4);
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
            "ovmf_measurement": dummy_ovmf_measurement_b64(),
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
            cage_token: None,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["measurement"], "deadbeef");
        assert!(json.get("id-block").is_none());
        assert!(json.get("id-auth").is_none());
        assert!(json.get("id-key").is_none());
        assert!(json.get("author-key").is_none());
        assert!(json.get("cage-token").is_none());
    }

    #[test]
    fn test_snp_measurement_response_serialization_full() {
        let resp = SnpMeasurementResponse {
            measurement: "deadbeef".to_string(),
            id_block: Some("block".to_string()),
            id_auth: Some("auth".to_string()),
            id_key: Some("key".to_string()),
            author_key: Some("author".to_string()),
            cage_token: Some("eyJhbGciOiJFUzM4NCJ9.test.sig".to_string()),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["measurement"], "deadbeef");
        assert_eq!(json["id-block"], "block");
        assert_eq!(json["id-auth"], "auth");
        assert_eq!(json["id-key"], "key");
        assert_eq!(json["author-key"], "author");
        assert_eq!(
            json["cage-token"], "eyJhbGciOiJFUzM4NCJ9.test.sig",
            "cage-token should be a JWT string"
        );
    }

    // --- sign_cage_token ---

    fn test_id_block() -> IdBlock {
        IdBlock::new(None, None, None, Some(0), None).unwrap()
    }

    fn test_id_auth(key: &EcKey<Private>, block: &IdBlock) -> IdAuth {
        IdAuth::default()
            .sign_id_block(DEFAULT_KEY_ALGO, key.clone(), block)
            .unwrap()
    }

    fn test_sams_key_b64(key: &EcKey<Private>) -> String {
        let pub_key = SevEcdsaPubKey::try_from(key).unwrap();
        let key_bytes = pub_key.to_bytes().unwrap();
        STANDARD.encode(key_bytes.as_ref())
    }

    #[test]
    fn test_sign_cage_token() {
        let key = test_ec_key();
        let block = test_id_block();
        let id_auth = test_id_auth(&key, &block);
        let sams_key = test_sams_key_b64(&key);

        let token = sign_cage_token(
            &key, 42, &block, &id_auth, "aabbccdd", None, None, &sams_key,
        )
        .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");

        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims["mage"], 42);
        assert!(claims.get("id_block").is_some());
        assert!(claims.get("id_auth").is_some());
        assert!(claims.get("sams_key").is_some());
        assert!(claims.get("salted_hash").is_some());
        assert_eq!(claims["salted_hash"].as_str().unwrap().len(), 96);
    }

    #[test]
    fn test_sign_cage_token_verifiable() {
        use jsonwebtoken::{decode, DecodingKey, Validation};

        let key = test_ec_key();
        let block = test_id_block();
        let id_auth = test_id_auth(&key, &block);
        let sams_key = test_sams_key_b64(&key);

        let token =
            sign_cage_token(&key, 1, &block, &id_auth, "salt", None, None, &sams_key).unwrap();

        let pkey = openssl::pkey::PKey::from_ec_key(key).unwrap();
        let pub_pem = pkey.public_key_to_pem().unwrap();
        let decoding_key = DecodingKey::from_ec_pem(&pub_pem).unwrap();
        let mut validation = Validation::new(Algorithm::ES384);
        validation.required_spec_claims.clear();

        let decoded = decode::<serde_json::Value>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded.claims["mage"], 1);
    }

    #[test]
    fn test_sign_cage_token_bound_to_id_block() {
        let key = test_ec_key();
        let block_a = test_id_block();
        let mut block_b = test_id_block();
        block_b.guest_svn = 99;
        let auth_a = test_id_auth(&key, &block_a);
        let auth_b = test_id_auth(&key, &block_b);
        let sams_key = test_sams_key_b64(&key);

        let token_a =
            sign_cage_token(&key, 7, &block_a, &auth_a, "salt", None, None, &sams_key).unwrap();
        let token_b =
            sign_cage_token(&key, 7, &block_b, &auth_b, "salt", None, None, &sams_key).unwrap();
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn test_sign_cage_token_bound_to_salt() {
        let key = test_ec_key();
        let block = test_id_block();
        let id_auth = test_id_auth(&key, &block);
        let sams_key = test_sams_key_b64(&key);

        let token_a =
            sign_cage_token(&key, 7, &block, &id_auth, "salt-a", None, None, &sams_key).unwrap();
        let token_b =
            sign_cage_token(&key, 7, &block, &id_auth, "salt-b", None, None, &sams_key).unwrap();

        let decode_claims = |t: &str| -> serde_json::Value {
            let parts: Vec<&str> = t.split('.').collect();
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        let claims_a = decode_claims(&token_a);
        let claims_b = decode_claims(&token_b);
        assert_ne!(
            claims_a["salted_hash"], claims_b["salted_hash"],
            "different salts must produce different salted_hash"
        );
    }

    #[test]
    fn test_sign_cage_token_includes_certificate() {
        let key = test_ec_key();
        let block = test_id_block();
        let id_auth = test_id_auth(&key, &block);
        let sams_key = test_sams_key_b64(&key);

        let token = sign_cage_token(
            &key,
            0,
            &block,
            &id_auth,
            "salt",
            Some("PEM-CERT-DATA"),
            Some("guest-owner-key-b64"),
            &sams_key,
        )
        .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims["certificate"], "PEM-CERT-DATA");
        assert_eq!(claims["guest_owner_key"], "guest-owner-key-b64");
    }

    // --- MeasurementHandler ---

    fn dummy_ovmf_measurement_b64() -> String {
        use base64::Engine;
        STANDARD.encode([0u8, 0, 0, 0, 0])
    }

    fn dummy_bearer_jwt() -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"certificate": "dummy"})).unwrap());
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        format!("Bearer {header}.{payload}.{sig}")
    }

    #[tokio::test]
    async fn test_measurement_handler_auth_missing_required_fields() {
        let id_key = test_ec_key();
        let mut handler = MeasurementPostHandler::new(
            id_key,
            true,
            None,
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
        );

        let req = serde_json::json!({
            "vcpus": 4,
            "vcpu_type": "EpycV4",
            "guest_features": 1,
            "ovmf_measurement": dummy_ovmf_measurement_b64()
        });
        let body = serde_json::to_vec(&req).unwrap();
        let mut headers = actix_web::http::header::HeaderMap::new();
        headers.insert(
            actix_web::http::header::AUTHORIZATION,
            dummy_bearer_jwt().parse().unwrap(),
        );

        let err = handler.handle(&body, &headers).await.unwrap_err();
        assert!(
            err.to_string().contains("auth endpoint requires"),
            "unexpected error: {err}"
        );
    }

    // --- MeasurementGetHandler ---

    #[tokio::test]
    async fn test_get_handler_non_auth_path() {
        let headers = actix_web::http::header::HeaderMap::new();
        let mut handler = MeasurementGetHandler::new(false);
        let err = handler.handle(&[], &headers).await.unwrap_err();
        let plugin_err = err.downcast_ref::<PluginHttpError>().unwrap();
        assert_eq!(plugin_err.status, 405);
        assert!(plugin_err.message.contains("Use POST"));
        assert!(plugin_err.message.contains("/measurement/snp"));
        assert!(!plugin_err.message.contains("/auth"));
        assert_eq!(
            plugin_err.headers,
            vec![("Allow".to_string(), "POST".to_string())]
        );
    }

    #[tokio::test]
    async fn test_get_handler_auth_path() {
        let headers = actix_web::http::header::HeaderMap::new();
        let mut handler = MeasurementGetHandler::new(true);
        let err = handler.handle(&[], &headers).await.unwrap_err();
        let plugin_err = err.downcast_ref::<PluginHttpError>().unwrap();
        assert_eq!(plugin_err.status, 405);
        assert!(plugin_err.message.contains("Use POST"));
        assert!(plugin_err.message.contains("/measurement/snp/signed"));
        assert!(plugin_err.message.contains("family_id"));
        assert!(plugin_err.message.contains("certificate"));
        assert_eq!(
            plugin_err.headers,
            vec![("Allow".to_string(), "POST".to_string())]
        );
    }
}
