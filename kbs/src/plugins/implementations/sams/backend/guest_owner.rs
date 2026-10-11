use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use key_value_storage::{KeyValueStorage, SetParameters};
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};

const CLIENT_CERT_HEADER: &str = "x-client-cert";

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
    storage: Arc<dyn KeyValueStorage>,
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

fn build_rvps_message(name: &str, value: &str) -> Result<String> {
    let payload = serde_json::json!({ name: value });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

impl GuestOwnerHandler {
    pub fn new(
        storage: Arc<dyn KeyValueStorage>,
        secret_storage: Arc<dyn KeyValueStorage>,
        rvps_address: Option<String>,
    ) -> Self {
        Self {
            storage,
            secret_storage,
            rvps_address,
        }
    }

    pub async fn register(&self, headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;
        let req: GuestOwnerRequest = serde_json::from_slice(body)?;

        let pubkey_hash = hash_key(&req.pubkey);
        let cert_hash = hash_key(&client_cert);

        let keypair = StoredKeypair {
            pubkey: req.pubkey,
            privkey: req.privkey,
        };
        let keypair_bytes = serde_json::to_vec(&keypair)?;

        self.storage
            .set(
                &pubkey_hash,
                client_cert.as_bytes(),
                SetParameters { overwrite: true },
            )
            .await?;

        self.secret_storage
            .set(
                &cert_hash,
                &keypair_bytes,
                SetParameters { overwrite: true },
            )
            .await?;

        if let Some(addr) = &self.rvps_address {
            let message = build_rvps_message(&pubkey_hash, &client_cert)?;
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
        let pubkey_hash = hash_key(&keypair.pubkey);

        self.storage
            .delete(&pubkey_hash)
            .await
            .map_err(|e| anyhow!("failed to delete guest owner cert: {e}"))?;

        self.secret_storage
            .delete(&cert_hash)
            .await
            .map_err(|e| anyhow!("failed to delete guest owner keypair: {e}"))?;

        if let Some(addr) = &self.rvps_address {
            reference_value_provider_service::client::delete(addr.clone(), pubkey_hash).await?;
        }

        Ok(b"{}".to_vec())
    }
}
