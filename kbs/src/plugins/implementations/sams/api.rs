use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use kbs_types::Tee;
use key_value_storage::KeyValueStorage;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use tokio::sync::Mutex;

use super::backend::authorization::AuthorizationPolicyHandler;
use super::backend::snp::measurement::MeasurementHandler as SnpMeasurementHandler;
use super::rvps_client::RvpsClient;

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
    id_key: EcKey<Private>,
    is_auth: bool,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
) -> Result<MeasurementHandler> {
    match (req_type, tee) {
        ("measurement", Tee::Snp) => Ok(MeasurementHandler::Snp(SnpMeasurementHandler::new(
            id_key,
            is_auth,
            rvps_client,
            rvps_certs_lock,
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
    mags_lock: Arc<Mutex<()>>,
) -> AuthorizationPolicyHandler {
    AuthorizationPolicyHandler::new(policy_engine, storage, mags_lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use rstest::rstest;

    fn memory_storage() -> Arc<dyn KeyValueStorage> {
        Arc::new(MemoryKeyValueStorage::default())
    }

    fn memory_policy_engine() -> PolicyEngine<Regorus> {
        PolicyEngine::<Regorus>::new(memory_storage())
    }

    fn test_ec_key() -> EcKey<openssl::pkey::Private> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        EcKey::generate(&group).unwrap()
    }

    #[test]
    fn test_get_request_handler_snp() {
        let result = get_request_handler(
            "measurement",
            Tee::Snp,
            test_ec_key(),
            false,
            None,
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
            memory_storage(),
        );
        if let Err(e) = result {
            panic!("expected Ok, got Err: {e}");
        }
    }

    #[rstest]
    #[case(Tee::Tdx)]
    #[case(Tee::Sgx)]
    #[case(Tee::Cca)]
    fn test_get_request_handler_unsupported_tee(#[case] tee: Tee) {
        let result = get_request_handler(
            "measurement",
            tee,
            test_ec_key(),
            false,
            None,
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
            memory_storage(),
        );
        match result {
            Err(e) => assert!(
                e.to_string().contains("unsupported TEE type"),
                "unexpected: {e}"
            ),
            Ok(_) => panic!("expected error for unsupported TEE type"),
        }
    }

    #[test]
    fn test_get_request_handler_unsupported_type() {
        let result = get_request_handler(
            "unknown",
            Tee::Snp,
            test_ec_key(),
            false,
            None,
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
            memory_storage(),
        );
        match result {
            Err(e) => assert!(
                e.to_string().contains("unsupported request type"),
                "unexpected: {e}"
            ),
            Ok(_) => panic!("expected error for unsupported request type"),
        }
    }
}
