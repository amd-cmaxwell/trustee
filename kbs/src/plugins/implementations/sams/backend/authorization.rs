use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::super::api::RequestHandler;
use super::super::rvps_client::RvpsClient;
use super::rvps_helpers::{ensure_salt_for_mage, read_mage, write_mage};

pub const AUTH_POLICY_ID: &str = "auth-policy";

#[derive(Deserialize)]
pub struct AuthorizationPolicyPostRequest {
    pub policy: String,
    #[serde(default)]
    pub incr_mage: bool,
}

#[derive(Serialize)]
pub struct AuthorizationPolicyPostResponse {
    pub mage: u32,
}

pub struct AuthorizationPolicyPostHandler {
    policy_engine: PolicyEngine<Regorus>,
    mage_lock: Arc<Mutex<()>>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
}

impl AuthorizationPolicyPostHandler {
    pub fn new(
        policy_engine: PolicyEngine<Regorus>,
        mage_lock: Arc<Mutex<()>>,
        rvps_client: Option<Arc<dyn RvpsClient>>,
    ) -> Self {
        Self {
            policy_engine,
            mage_lock,
            rvps_client,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for AuthorizationPolicyPostHandler {
    async fn handle(
        &mut self,
        body: &[u8],
        _headers: &actix_web::http::header::HeaderMap,
    ) -> Result<Vec<u8>> {
        let req: AuthorizationPolicyPostRequest = serde_json::from_slice(body)?;

        let rego = String::from_utf8(
            STANDARD
                .decode(&req.policy)
                .map_err(|e| anyhow!("invalid base64 in policy field: {e}"))?,
        )
        .map_err(|e| anyhow!("policy is not valid UTF-8: {e}"))?;

        let mage = {
            let client = self
                .rvps_client
                .as_ref()
                .ok_or_else(|| anyhow!("RVPS is required to manage the MAGE counter"))?;
            let _guard = self.mage_lock.lock().await;

            self.policy_engine
                .set_policy(AUTH_POLICY_ID, &rego, true)
                .await?;

            if req.incr_mage {
                let current = read_mage(client.as_ref()).await?;
                let new_mage = current + 1;
                write_mage(client.as_ref(), new_mage).await?;
                ensure_salt_for_mage(client.as_ref(), new_mage).await?;
            }
            let current = read_mage(client.as_ref()).await?;
            ensure_salt_for_mage(client.as_ref(), current).await?;
            current
        };
        let resp = AuthorizationPolicyPostResponse { mage };
        Ok(serde_json::to_vec(&resp)?)
    }
}

#[derive(Serialize)]
pub struct AuthorizationPolicyGetResponse {
    pub policy: Option<String>,
    pub mage: u32,
}

pub struct AuthorizationPolicyGetHandler {
    policy_engine: PolicyEngine<Regorus>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
}

impl AuthorizationPolicyGetHandler {
    pub fn new(
        policy_engine: PolicyEngine<Regorus>,
        rvps_client: Option<Arc<dyn RvpsClient>>,
    ) -> Self {
        Self {
            policy_engine,
            rvps_client,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for AuthorizationPolicyGetHandler {
    async fn handle(
        &mut self,
        _body: &[u8],
        _headers: &actix_web::http::header::HeaderMap,
    ) -> Result<Vec<u8>> {
        let policy = self.policy_engine.get_policy(AUTH_POLICY_ID).await.ok();

        let mage = if let Some(client) = &self.rvps_client {
            read_mage(client.as_ref()).await?
        } else {
            0
        };

        let resp = AuthorizationPolicyGetResponse {
            policy: policy.map(|p| STANDARD.encode(p)),
            mage,
        };
        Ok(serde_json::to_vec(&resp)?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::rvps_helpers::read_sage_salts;
    use super::*;
    use actix_web::http::header::HeaderMap;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use policy_engine::policy::rego::Regorus;
    use policy_engine::PolicyEngine;

    use crate::plugins::implementations::sams::rvps_client::test_support::MockRvpsClient;

    fn memory_storage() -> Arc<dyn key_value_storage::KeyValueStorage> {
        Arc::new(MemoryKeyValueStorage::default())
    }

    fn memory_policy_engine() -> PolicyEngine<Regorus> {
        PolicyEngine::<Regorus>::new(memory_storage())
    }

    #[test]
    fn test_authorization_policy_request_deserialize() {
        let json = r#"{"policy":"dGVzdA==","incr_mage":true}"#;
        let req: AuthorizationPolicyPostRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy, "dGVzdA==");
        assert!(req.incr_mage);
    }

    #[test]
    fn test_authorization_policy_request_incr_mage_defaults_false() {
        let json = r#"{"policy":"dGVzdA=="}"#;
        let req: AuthorizationPolicyPostRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy, "dGVzdA==");
        assert!(!req.incr_mage);
    }

    #[test]
    fn test_authorization_policy_response_serialize() {
        let resp = AuthorizationPolicyPostResponse { mage: 42 };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"mage":42}"#);
    }

    #[tokio::test]
    async fn test_read_mage_empty_returns_zero() {
        let client = MockRvpsClient::new();
        let val = read_mage(&client).await.unwrap();
        assert_eq!(val, 0);
    }

    #[tokio::test]
    async fn test_write_then_read_mage() {
        let client = MockRvpsClient::new();
        write_mage(&client, 5).await.unwrap();
        let val = read_mage(&client).await.unwrap();
        assert_eq!(val, 5);
    }

    #[tokio::test]
    async fn test_handle_sets_policy_and_returns_mage() {
        let rego = "package policy\ndefault authorized = true";
        let encoded = STANDARD.encode(rego);
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": encoded,
            "incr_mage": false,
        }))
        .unwrap();

        let rvps = Arc::new(MockRvpsClient::new());
        let mut handler = AuthorizationPolicyPostHandler::new(
            memory_policy_engine(),
            Arc::new(Mutex::new(())),
            Some(rvps),
        );

        let result = handler.handle(&body, &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["mage"], 0);
    }

    #[tokio::test]
    async fn test_handle_incr_mage() {
        let rego = "package policy\ndefault authorized = true";
        let encoded = STANDARD.encode(rego);
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": encoded,
            "incr_mage": true,
        }))
        .unwrap();

        let mage_lock = Arc::new(Mutex::new(()));
        let rvps = Arc::new(MockRvpsClient::new());
        let mut handler = AuthorizationPolicyPostHandler::new(
            memory_policy_engine(),
            Arc::clone(&mage_lock),
            Some(rvps.clone()),
        );

        let result = handler.handle(&body, &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["mage"], 1);

        let salts = read_sage_salts(rvps.as_ref()).await.unwrap();
        assert!(salts.contains_key("1"), "salt for MAGE=1 should exist");
        assert_eq!(
            salts["1"].len(),
            64,
            "salt should be 64 hex chars (32 bytes)"
        );

        let result = handler.handle(&body, &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["mage"], 2);
    }

    #[tokio::test]
    async fn test_handle_invalid_base64_policy() {
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": "!!!not-base64!!!",
            "incr_mage": false,
        }))
        .unwrap();

        let mut handler = AuthorizationPolicyPostHandler::new(
            memory_policy_engine(),
            Arc::new(Mutex::new(())),
            None,
        );

        let err = handler.handle(&body, &HeaderMap::new()).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid base64"),
            "expected 'invalid base64' in error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_get_handler_no_policy_set() {
        let rvps = Arc::new(MockRvpsClient::new());
        let mut handler = AuthorizationPolicyGetHandler::new(memory_policy_engine(), Some(rvps));

        let result = handler.handle(&[], &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(resp["policy"].is_null());
        assert_eq!(resp["mage"], 0);
    }

    #[tokio::test]
    async fn test_get_handler_after_post() {
        let rvps = Arc::new(MockRvpsClient::new());
        let policy_engine = memory_policy_engine();

        let rego = "package policy\ndefault authorized = true";
        let encoded = STANDARD.encode(rego);
        let body = serde_json::to_vec(&serde_json::json!({
            "policy": encoded,
            "incr_mage": true,
        }))
        .unwrap();

        let mut post_handler = AuthorizationPolicyPostHandler::new(
            policy_engine.clone(),
            Arc::new(Mutex::new(())),
            Some(rvps.clone()),
        );
        post_handler.handle(&body, &HeaderMap::new()).await.unwrap();

        let mut get_handler = AuthorizationPolicyGetHandler::new(policy_engine, Some(rvps));
        let result = get_handler.handle(&[], &HeaderMap::new()).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(resp["policy"].is_string());
        assert_eq!(resp["mage"], 1);
    }
}
