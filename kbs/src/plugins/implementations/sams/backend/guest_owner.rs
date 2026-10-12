use std::collections::HashMap;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use key_value_storage::{KeyValueStorage, SetParameters};
use openssl::ec::EcKey;
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};
use sev::measurement::idblock::get_key_digest;
use sev::measurement::idblock_types::SevEcdsaPubKey;
use sev::parser::ByteParser;

const CLIENT_CERT_HEADER: &str = "x-client-cert";
const RVPS_GUEST_OWNER_CERTS_KEY: &str = "guest-owner-certs";

#[derive(Deserialize)]
pub struct GuestOwnerRequest {
    pub pubkey: String,
    pub privkey: String,
}

#[derive(Serialize, Deserialize)]
struct StoredKeypair {
    pubkey: String,
    privkey: String,
}

pub struct GuestOwnerHandler {
    secret_storage: Arc<dyn KeyValueStorage>,
    rvps_address: Option<String>,
}

fn extract_client_cert(headers: &HeaderMap) -> Result<String> {
    let cert_value = headers
        .get(CLIENT_CERT_HEADER)
        .ok_or_else(|| anyhow!("missing {CLIENT_CERT_HEADER} header (mTLS proxy required)"))?
        .to_str()
        .map_err(|e| anyhow!("invalid {CLIENT_CERT_HEADER} header: {e}"))?;

    Ok(cert_value.to_string())
}

fn hash_key(data: &str) -> String {
    hex::encode(sha256(data.as_bytes()))
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

fn build_rvps_message(certs_map: &HashMap<String, String>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_GUEST_OWNER_CERTS_KEY: certs_map });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

async fn read_rvps_certs_map(addr: &str) -> Result<HashMap<String, String>> {
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

impl GuestOwnerHandler {
    pub fn new(secret_storage: Arc<dyn KeyValueStorage>, rvps_address: Option<String>) -> Self {
        Self {
            secret_storage,
            rvps_address,
        }
    }

    pub async fn register(&self, headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;
        let req: GuestOwnerRequest = serde_json::from_slice(body)?;

        let auth_key_digest = compute_auth_key_digest(&req.privkey)?;
        let cert_hash = hash_key(&client_cert);

        let keypair = StoredKeypair {
            pubkey: req.pubkey,
            privkey: req.privkey,
        };
        let keypair_bytes = serde_json::to_vec(&keypair)?;

        self.secret_storage
            .set(
                &cert_hash,
                &keypair_bytes,
                SetParameters { overwrite: true },
            )
            .await?;

        if let Some(addr) = &self.rvps_address {
            let mut certs_map = read_rvps_certs_map(addr).await?;
            certs_map.insert(auth_key_digest, client_cert);
            let message = build_rvps_message(&certs_map)?;
            reference_value_provider_service::client::register(addr.clone(), message).await?;
        }

        Ok(b"{}".to_vec())
    }

    pub async fn revoke(&self, headers: &HeaderMap) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;
        let cert_hash = hash_key(&client_cert);

        let keypair_bytes = self
            .secret_storage
            .get(&cert_hash)
            .await?
            .ok_or_else(|| anyhow!("no keypair found for this guest owner"))?;

        let keypair: StoredKeypair = serde_json::from_slice(&keypair_bytes)?;
        let auth_key_digest = compute_auth_key_digest(&keypair.privkey)?;

        self.secret_storage
            .delete(&cert_hash)
            .await
            .map_err(|e| anyhow!("failed to delete guest owner keypair: {e}"))?;

        if let Some(addr) = &self.rvps_address {
            let mut certs_map = read_rvps_certs_map(addr).await?;
            certs_map.remove(&auth_key_digest);
            let message = build_rvps_message(&certs_map)?;
            reference_value_provider_service::client::register(addr.clone(), message).await?;
        }

        Ok(b"{}".to_vec())
    }
}
