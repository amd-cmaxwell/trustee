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
