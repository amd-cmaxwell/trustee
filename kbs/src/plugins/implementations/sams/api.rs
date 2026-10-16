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

use super::backend::authorization::{
    AuthorizationPolicyGetHandler, AuthorizationPolicyPostHandler,
};
use super::backend::measurement::get_measurement_handler;
use super::backend::signing::{
    IdentityProviderGetHandler, SigningKeyDeleteHandler, SigningPolicyDeleteHandler,
    SigningPolicyPostHandler,
};
use super::rvps_client::RvpsClient;

#[async_trait::async_trait]
pub trait RequestHandler: Send {
    async fn handle(&mut self, body: &[u8], headers: &HeaderMap) -> Result<Vec<u8>>;
}

#[allow(clippy::too_many_arguments)]
pub fn get_request_handler(
    req_type: &str,
    tee: Option<Tee>,
    path: &[&str],
    method: &Method,
    id_key: EcKey<Private>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    mage_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    identity_provider_url: Option<String>,
) -> Result<Box<dyn RequestHandler>> {
    match req_type {
        "measurement" => {
            let tee = tee.ok_or_else(|| anyhow!("measurement requests require a TEE type"))?;
            get_measurement_handler(
                tee,
                path,
                method,
                id_key,
                rvps_client,
                rvps_certs_lock,
                mage_lock,
                auth_policy_engine,
                signing_policy_engine,
            )
        }
        "authorization" => match method {
            &Method::GET => Ok(Box::new(AuthorizationPolicyGetHandler::new(
                auth_policy_engine,
                rvps_client,
            ))),
            &Method::POST => Ok(Box::new(AuthorizationPolicyPostHandler::new(
                auth_policy_engine,
                mage_lock,
                rvps_client,
            ))),
            _ => Err(anyhow!("unsupported authorization endpoint: {}", path.join("/"))),
        },
        "signing" => match (method, path) {
            (&Method::GET, [.., "identity-provider"]) => Ok(Box::new(IdentityProviderGetHandler::new(
                identity_provider_url
            ))),
            (&Method::POST, [.., "policy"]) => Ok(Box::new(SigningPolicyPostHandler::new(
                signing_policy_engine,
                rvps_client,
                rvps_certs_lock,
            ))),
            (&Method::DELETE, [.., "policy"]) => Ok(Box::new(SigningPolicyDeleteHandler::new(
                signing_policy_engine,
                rvps_client,
                rvps_certs_lock,
            ))),
            (&Method::DELETE, [.., "key", digest]) => {
                Ok(Box::new(SigningKeyDeleteHandler::new(
                    signing_policy_engine,
                    rvps_client,
                    rvps_certs_lock,
                    digest,
                )))
            }
            _ => Err(anyhow!("unsupported signing endpoint: {}", path.join("/"))),
        },
        _ => Err(anyhow!("unsupported request type: {req_type}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use key_value_storage::KeyValueStorage;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;

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
    fn test_get_request_handler_unsupported_type() {
        let result = get_request_handler(
            "unknown",
            Some(Tee::Snp),
            &["measurement", "snp"],
            &Method::POST,
            test_ec_key(),
            None,
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(())),
            memory_policy_engine(),
            memory_policy_engine(),
            None,
        );
        match result {
            Err(e) => assert!(e.to_string().contains("unsupported"), "unexpected: {e}"),
            Ok(_) => panic!("expected error for unsupported request type"),
        }
    }
}
