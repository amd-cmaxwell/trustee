use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use actix_web::http::Method;
use anyhow::{anyhow, Result};
use kbs_types::Tee;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use tokio::sync::Mutex;

use super::super::api::RequestHandler;
use super::super::rvps_client::RvpsClient;

cfg_if::cfg_if! {
    if #[cfg(feature = "sams-snp")] {
        use super::snp::measurement::{
            MeasurementGetHandler as SnpMeasurementGetHandler,
            MeasurementPostHandler as SnpMeasurementPostHandler,
        };
    }
}

enum MeasurementHandler {
    #[cfg(feature = "sams-snp")]
    SnpPost(SnpMeasurementPostHandler),
    #[cfg(feature = "sams-snp")]
    SnpGet(SnpMeasurementGetHandler),
}

#[async_trait::async_trait]
impl RequestHandler for MeasurementHandler {
    async fn handle(&mut self, _body: &[u8], _headers: &HeaderMap) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "sams-snp")]
            Self::SnpPost(h) => h.handle(_body, _headers).await,
            #[cfg(feature = "sams-snp")]
            Self::SnpGet(h) => h.handle(_body, _headers).await,
            #[allow(unreachable_patterns)]
            _ => Err(anyhow!("no measurement backends enabled")),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn get_measurement_handler(
    tee: Tee,
    path: &[&str],
    method: &Method,
    id_key: EcKey<Private>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    mage_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
) -> Result<Box<dyn RequestHandler>> {
    match (tee, method) {
        (Tee::Snp, _) => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "sams-snp")] {
                    let is_auth = path.last() == Some(&"auth");
                    match method {
                        &Method::GET => Ok(Box::new(MeasurementHandler::SnpGet(
                            SnpMeasurementGetHandler::new(is_auth),
                        ))),
                        &Method::POST => Ok(Box::new(MeasurementHandler::SnpPost(SnpMeasurementPostHandler::new(
                            id_key,
                            is_auth,
                            rvps_client,
                            rvps_certs_lock,
                            mage_lock,
                            auth_policy_engine,
                            signing_policy_engine,
                        )))),
                        _ => Err(anyhow!("unsupported SNP measurement method: {:?}", method))
                    }
                } else {
                    let _ = (id_key, rvps_client, rvps_certs_lock, mage_lock,
                             auth_policy_engine, signing_policy_engine);
                    Err(anyhow!(
                        "SNP measurement support requires the `sams-snp` feature"
                    ))
                }
            }
        }
        (other, _) => Err(anyhow!("unsupported TEE type for measurement: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use key_value_storage::KeyValueStorage;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    #[cfg(feature = "sams-snp")]
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

    #[cfg(feature = "sams-snp")]
    #[test]
    fn test_get_measurement_handler_snp_post() {
        let result = get_measurement_handler(
            Tee::Snp,
            &["measurement", "snp"],
            &Method::POST,
            test_ec_key(),
            None,
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "sams-snp")]
    #[test]
    fn test_get_measurement_handler_snp_get() {
        let result = get_measurement_handler(
            Tee::Snp,
            &["measurement", "snp"],
            &Method::GET,
            test_ec_key(),
            None,
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
        );
        assert!(result.is_ok());
    }

    #[cfg(not(feature = "sams-snp"))]
    #[test]
    fn test_get_measurement_handler_snp_without_feature() {
        let result = get_measurement_handler(
            Tee::Snp,
            &["measurement", "snp"],
            &Method::POST,
            test_ec_key(),
            None,
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
        );
        match result {
            Err(e) => assert!(e.to_string().contains("sams-snp"), "unexpected: {e}"),
            Ok(_) => panic!("expected error when sams-snp is disabled"),
        }
    }

    #[cfg(feature = "sams-snp")]
    #[rstest]
    #[case(Tee::Tdx)]
    #[case(Tee::Sgx)]
    #[case(Tee::Cca)]
    fn test_get_measurement_handler_unsupported_tee(#[case] tee: Tee) {
        let result = get_measurement_handler(
            tee,
            &["measurement", "other"],
            &Method::POST,
            test_ec_key(),
            None,
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
        );
        match result {
            Err(e) => assert!(
                e.to_string().contains("unsupported TEE type"),
                "unexpected: {e}"
            ),
            Ok(_) => panic!("expected error for unsupported TEE type"),
        }
    }
}
