use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use key_value_storage::{KeyValueStorage, SetParameters};
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::super::api::RequestHandler;

pub const AUTH_POLICY_ID: &str = "auth-policy";
pub const MAGS_KEY: &str = "mags";

#[derive(Deserialize)]
pub struct AuthorizationPolicyRequest {
    pub policy: String,
    #[serde(default)]
    pub incr_gsvn: bool,
}

#[derive(Serialize)]
pub struct AuthorizationPolicyResponse {
    pub gsvn: u32,
}

pub struct AuthorizationPolicyHandler {
    policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
    mags_lock: Arc<Mutex<()>>,
}

impl AuthorizationPolicyHandler {
    pub fn new(
        policy_engine: PolicyEngine<Regorus>,
        storage: Arc<dyn KeyValueStorage>,
        mags_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            policy_engine,
            storage,
            mags_lock,
        }
    }
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

async fn write_mags(storage: &dyn KeyValueStorage, value: u32) -> Result<()> {
    let bytes = serde_json::to_vec(&value)?;
    storage
        .set(MAGS_KEY, &bytes, SetParameters { overwrite: true })
        .await?;
    Ok(())
}

#[async_trait::async_trait]
impl RequestHandler for AuthorizationPolicyHandler {
    async fn handle(
        &mut self,
        body: &[u8],
        _headers: &actix_web::http::header::HeaderMap,
    ) -> Result<Vec<u8>> {
        let req: AuthorizationPolicyRequest = serde_json::from_slice(body)?;

        let rego = String::from_utf8(
            STANDARD
                .decode(&req.policy)
                .map_err(|e| anyhow!("invalid base64 in policy field: {e}"))?,
        )
        .map_err(|e| anyhow!("policy is not valid UTF-8: {e}"))?;

        self.policy_engine
            .set_policy(AUTH_POLICY_ID, &rego, true)
            .await?;

        let gsvn = {
            let _guard = self.mags_lock.lock().await;
            if req.incr_gsvn {
                let current = read_mags(&*self.storage).await?;
                write_mags(&*self.storage, current + 1).await?;
            }
            read_mags(&*self.storage).await?
        };
        let resp = AuthorizationPolicyResponse { gsvn };
        Ok(serde_json::to_vec(&resp)?)
    }
}
