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
pub const MAGS_KEY: &str = "snp_minimum_acceptable_guest_svn";

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::HeaderMap;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use policy_engine::policy::rego::Regorus;
    use policy_engine::PolicyEngine;

    fn memory_storage() -> Arc<dyn key_value_storage::KeyValueStorage> {
        Arc::new(MemoryKeyValueStorage::default())
    }

    fn memory_policy_engine() -> PolicyEngine<Regorus> {
        PolicyEngine::<Regorus>::new(memory_storage())
    }

    #[test]
    fn test_authorization_policy_request_deserialize() {
        let json = r#"{"policy":"dGVzdA==","incr_gsvn":true}"#;
        let req: AuthorizationPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy, "dGVzdA==");
        assert!(req.incr_gsvn);
    }

    #[test]
    fn test_authorization_policy_request_incr_gsvn_defaults_false() {
        let json = r#"{"policy":"dGVzdA=="}"#;
        let req: AuthorizationPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy, "dGVzdA==");
        assert!(!req.incr_gsvn);
    }

    #[test]
    fn test_authorization_policy_response_serialize() {
        let resp = AuthorizationPolicyResponse { gsvn: 42 };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"gsvn":42}"#);
    }

    #[tokio::test]
    async fn test_read_mags_empty_returns_zero() {
        let storage = memory_storage();
        let val = read_mags(&*storage).await.unwrap();
        assert_eq!(val, 0);
    }

    #[tokio::test]
    async fn test_write_then_read_mags() {
        let storage = memory_storage();
        write_mags(&*storage, 5).await.unwrap();
        let val = read_mags(&*storage).await.unwrap();
        assert_eq!(val, 5);
    }

    #[tokio::test]
    async fn test_handle_sets_policy_and_returns_gsvn() {
        let rego = "package policy\ndefault authorized = true";
        let encoded = STANDARD.encode(rego);
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": encoded,
            "incr_gsvn": false,
        }))
        .unwrap();

        let storage = memory_storage();
        let mut handler = AuthorizationPolicyHandler::new(
            memory_policy_engine(),
            storage,
            Arc::new(Mutex::new(())),
        );

        let result = handler.handle(&body, &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["gsvn"], 0);
    }

    #[tokio::test]
    async fn test_handle_incr_gsvn() {
        let rego = "package policy\ndefault authorized = true";
        let encoded = STANDARD.encode(rego);
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": encoded,
            "incr_gsvn": true,
        }))
        .unwrap();

        let storage = memory_storage();
        let mags_lock = Arc::new(Mutex::new(()));
        let mut handler = AuthorizationPolicyHandler::new(
            memory_policy_engine(),
            Arc::clone(&storage),
            Arc::clone(&mags_lock),
        );

        let result = handler.handle(&body, &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["gsvn"], 1);

        let result = handler.handle(&body, &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["gsvn"], 2);
    }

    #[tokio::test]
    async fn test_handle_invalid_base64_policy() {
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": "!!!not-base64!!!",
            "incr_gsvn": false,
        }))
        .unwrap();

        let storage = memory_storage();
        let mut handler = AuthorizationPolicyHandler::new(
            memory_policy_engine(),
            storage,
            Arc::new(Mutex::new(())),
        );

        let err = handler.handle(&body, &HeaderMap::new()).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid base64"),
            "expected 'invalid base64' in error, got: {err}"
        );
    }
}
