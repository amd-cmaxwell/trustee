use std::path::Path;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use kbs_types::Tee;
use key_value_storage::KeyValueStorage;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;

use super::backend::authorization::AuthorizationPolicyHandler;
use super::backend::snp::measurement::MeasurementHandler as SnpMeasurementHandler;

#[async_trait::async_trait]
pub trait RequestHandler: Send {
    async fn handle(&mut self, body: &[u8], headers: &HeaderMap) -> Result<Vec<u8>>;
}

pub enum MeasurementHandler {
    Snp(SnpMeasurementHandler),
}

#[async_trait::async_trait]
impl RequestHandler for MeasurementHandler {
    async fn handle(&mut self, body: &[u8], headers: &HeaderMap) -> Result<Vec<u8>> {
        match self {
            Self::Snp(h) => h.handle(body, headers).await,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn get_request_handler(
    req_type: &str,
    tee: Tee,
    ovmf_file: &Path,
    id_key: EcKey<Private>,
    is_auth: bool,
    rvps_address: Option<String>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
) -> Result<MeasurementHandler> {
    match (req_type, tee) {
        ("measurement", Tee::Snp) => Ok(MeasurementHandler::Snp(SnpMeasurementHandler::new(
            ovmf_file.to_path_buf(),
            id_key,
            is_auth,
            rvps_address,
            auth_policy_engine,
            signing_policy_engine,
            storage,
        ))),
        ("measurement", other) => Err(anyhow!("unsupported TEE type for measurement: {other:?}")),
        _ => Err(anyhow!("unsupported request type: {req_type}")),
    }
}

pub fn get_auth_policy_handler(
    policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
) -> AuthorizationPolicyHandler {
    AuthorizationPolicyHandler::new(policy_engine, storage)
}
