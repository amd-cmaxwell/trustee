use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use key_value_storage::{KeyValueStorage, SetParameters};
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};

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
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String> {
    let auth_value = headers
        .get("authorization")
        .ok_or_else(|| anyhow!("missing Authorization header"))?
        .to_str()
        .map_err(|e| anyhow!("invalid Authorization header: {e}"))?;

    let token = auth_value
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow!("Authorization header must use Bearer scheme"))?;

    Ok(token.to_string())
}

fn hash_key(data: &str) -> String {
    hex::encode(sha256(data.as_bytes()))
}

impl GuestOwnerHandler {
    pub fn new(storage: Arc<dyn KeyValueStorage>) -> Self {
        Self { storage }
    }

    pub async fn register(&self, headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>> {
        let jwt = extract_bearer_token(headers)?;
        let req: GuestOwnerRequest = serde_json::from_slice(body)?;

        let pubkey_hash = hash_key(&req.pubkey);
        let jwt_hash = hash_key(&jwt);

        let keypair = StoredKeypair {
            pubkey: req.pubkey,
            privkey: req.privkey,
        };
        let keypair_bytes = serde_json::to_vec(&keypair)?;

        self.storage
            .set(
                &pubkey_hash,
                jwt.as_bytes(),
                SetParameters { overwrite: true },
            )
            .await?;

        self.storage
            .set(&jwt_hash, &keypair_bytes, SetParameters { overwrite: true })
            .await?;

        Ok(b"{}".to_vec())
    }

    pub async fn revoke(&self, headers: &HeaderMap) -> Result<Vec<u8>> {
        let jwt = extract_bearer_token(headers)?;
        let jwt_hash = hash_key(&jwt);

        let keypair_bytes = self
            .storage
            .get(&jwt_hash)
            .await?
            .ok_or_else(|| anyhow!("no keypair found for this guest owner"))?;

        let keypair: StoredKeypair = serde_json::from_slice(&keypair_bytes)?;
        let pubkey_hash = hash_key(&keypair.pubkey);

        self.storage
            .delete(&pubkey_hash)
            .await
            .map_err(|e| anyhow!("failed to delete guest owner JWT: {e}"))?;

        self.storage
            .delete(&jwt_hash)
            .await
            .map_err(|e| anyhow!("failed to delete guest owner keypair: {e}"))?;

        Ok(b"{}".to_vec())
    }
}
