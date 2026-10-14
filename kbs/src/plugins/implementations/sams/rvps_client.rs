use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use reference_value_provider_service::Rvps;
use tokio::sync::RwLock;

#[async_trait]
pub trait RvpsClient: Send + Sync {
    async fn register(&self, message: String) -> Result<()>;
    async fn query(&self, id: String) -> Result<Option<String>>;
}

pub struct GrpcRvpsClient {
    address: String,
}

impl GrpcRvpsClient {
    pub fn new(address: String) -> Self {
        Self { address }
    }
}

#[async_trait]
impl RvpsClient for GrpcRvpsClient {
    async fn register(&self, message: String) -> Result<()> {
        reference_value_provider_service::client::register(self.address.clone(), message).await
    }

    async fn query(&self, id: String) -> Result<Option<String>> {
        reference_value_provider_service::client::query(self.address.clone(), id).await
    }
}

pub struct BuiltinRvpsClient {
    rvps: Arc<RwLock<Rvps>>,
}

impl BuiltinRvpsClient {
    pub fn new(rvps: Rvps) -> Self {
        Self {
            rvps: Arc::new(RwLock::new(rvps)),
        }
    }
}

#[async_trait]
impl RvpsClient for BuiltinRvpsClient {
    async fn register(&self, message: String) -> Result<()> {
        self.rvps.write().await.verify_and_extract(&message).await
    }

    async fn query(&self, id: String) -> Result<Option<String>> {
        let value = self.rvps.read().await.query_reference_value(&id).await?;
        Ok(value.map(|v| v.to_string()))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    pub struct MockRvpsClient {
        store: RwLock<HashMap<String, String>>,
    }

    impl MockRvpsClient {
        pub fn new() -> Self {
            Self {
                store: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl RvpsClient for MockRvpsClient {
        async fn register(&self, message: String) -> Result<()> {
            use base64::Engine;

            let msg: serde_json::Value = serde_json::from_str(&message)?;
            let payload_b64 = msg["payload"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing payload"))?;
            let payload_bytes = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
            let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;
            let mut store = self.store.write().await;
            if let Some(obj) = payload.as_object() {
                for (key, value) in obj {
                    store.insert(key.clone(), value.to_string());
                }
            }
            Ok(())
        }

        async fn query(&self, id: String) -> Result<Option<String>> {
            Ok(self.store.read().await.get(&id).cloned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockRvpsClient;
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use key_value_storage::memory::MemoryKeyValueStorage;

    #[tokio::test]
    async fn test_mock_rvps_register_and_query() {
        let client = MockRvpsClient::new();

        let payload = serde_json::json!({"my-key": "my-value"});
        let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload).unwrap());
        let message = serde_json::json!({
            "version": "0.1.0",
            "payload": payload_b64,
            "type": "sample"
        });

        client
            .register(serde_json::to_string(&message).unwrap())
            .await
            .unwrap();

        let result = client.query("my-key".to_string()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "\"my-value\"");
    }

    #[tokio::test]
    async fn test_mock_rvps_query_missing_key() {
        let client = MockRvpsClient::new();
        let result = client.query("nonexistent".to_string()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_builtin_rvps_client_register_and_query() {
        let storage = Arc::new(MemoryKeyValueStorage::default())
            as key_value_storage::KeyValueStorageInstance;
        let rvps = reference_value_provider_service::Rvps::new_with_storage(None, storage)
            .await
            .unwrap();
        let client = BuiltinRvpsClient::new(rvps);

        let payload = serde_json::json!({"test-ref-value": "expected"});
        let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload).unwrap());
        let message = serde_json::json!({
            "version": "0.1.0",
            "payload": payload_b64,
            "type": "sample"
        });

        client
            .register(serde_json::to_string(&message).unwrap())
            .await
            .unwrap();

        let result = client.query("test-ref-value".to_string()).await.unwrap();
        assert!(result.is_some());
    }
}
