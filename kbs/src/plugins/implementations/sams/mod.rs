// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use actix_web::http::Method;
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::Tee;
use key_value_storage::{KeyValueStorageType, StorageProvider};
use openssl::ec::EcKey;
use openssl::pkey::Private;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use reference_value_provider_service::{Rvps, REFERENCE_VALUE_STORAGE_NAMESPACE};
use serde::Deserialize;
use sev::measurement::idblock::load_priv_key;
use sev::measurement::idblock_types::SevEcdsaPubKey;
use sev::parser::ByteParser;
use tokio::sync::Mutex;

use super::super::plugin_manager::{AuthMode, ClientPlugin};

mod api;
use api::RequestHandler;
mod backend;
use backend::signing::SigningPolicyHandler;
pub mod rvps_client;
use rvps_client::{BuiltinRvpsClient, GrpcRvpsClient, RvpsClient};

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum SamsRvpsConfig {
    Grpc {
        address: String,
    },
    Builtin {
        #[serde(default)]
        storage_type: Option<KeyValueStorageType>,
    },
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SamsConfig {
    pub ovmf_file: PathBuf,
    pub id_key_file: PathBuf,
    #[serde(default)]
    pub rvps: Option<SamsRvpsConfig>,
}

pub struct Sams {
    ovmf_file: PathBuf,
    id_key: EcKey<Private>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    mags_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn key_value_storage::KeyValueStorage>,
}

impl Sams {
    pub async fn new(
        config: SamsConfig,
        storage_provider: Arc<dyn StorageProvider>,
    ) -> Result<Self> {
        let storage = storage_provider.get_or_register("sams").await?;
        let signing_policy_storage = storage_provider
            .get_or_register("sams-signing-policies")
            .await?;
        let policy_engine = PolicyEngine::<Regorus>::new(storage.clone());
        let signing_policy_engine = PolicyEngine::<Regorus>::new(signing_policy_storage);
        let id_key = load_priv_key(config.id_key_file)?;

        let rvps_client: Option<Arc<dyn RvpsClient>> = match config.rvps {
            Some(SamsRvpsConfig::Grpc { address }) => Some(Arc::new(GrpcRvpsClient::new(address))),
            Some(SamsRvpsConfig::Builtin { storage_type }) => {
                let storage_type = storage_type.unwrap_or(KeyValueStorageType::LocalFs);
                let rvps_storage = storage_provider
                    .get_or_register_with_type(REFERENCE_VALUE_STORAGE_NAMESPACE, storage_type)
                    .await?;
                let rvps = Rvps::new_with_storage(None, rvps_storage).await?;
                Some(Arc::new(BuiltinRvpsClient::new(rvps)))
            }
            None => None,
        };

        if let Some(client) = &rvps_client {
            let pub_key = SevEcdsaPubKey::try_from(&id_key)
                .map_err(|e| anyhow!("failed to extract SAMS public key: {e}"))?;
            let key_bytes = pub_key
                .to_bytes()
                .map_err(|e| anyhow!("failed to serialize SAMS public key: {e}"))?;
            let key_b64 = STANDARD.encode(key_bytes.as_ref());

            let payload = serde_json::json!({ "sams-id-key": key_b64 });
            let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
            let message = serde_json::json!({
                "version": "0.1.0",
                "payload": payload_b64,
                "type": "sample"
            });
            client.register(serde_json::to_string(&message)?).await?;
        }

        Ok(Self {
            ovmf_file: config.ovmf_file,
            id_key,
            rvps_client,
            rvps_certs_lock: Arc::new(Mutex::new(())),
            mags_lock: Arc::new(Mutex::new(())),
            auth_policy_engine: policy_engine,
            signing_policy_engine,
            storage,
        })
    }
}

fn tee_from_path(tee_str: &str) -> Result<Tee> {
    match tee_str {
        "snp" => Ok(Tee::Snp),
        other => bail!("unsupported TEE type: {other}"),
    }
}

impl Sams {
    async fn dispatch(
        &self,
        endpoint: &str,
        tee: Tee,
        is_auth: bool,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<Vec<u8>> {
        let mut handler = api::get_request_handler(
            endpoint,
            tee,
            &self.ovmf_file,
            self.id_key.clone(),
            is_auth,
            self.rvps_client.clone(),
            self.rvps_certs_lock.clone(),
            self.auth_policy_engine.clone(),
            self.signing_policy_engine.clone(),
            self.storage.clone(),
        )?;
        handler.handle(body, headers).await
    }
}

#[async_trait::async_trait]
impl ClientPlugin for Sams {
    async fn handle(
        &self,
        body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        _init_data: Option<&serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let empty_headers = HeaderMap::new();
        match (method.as_str(), path) {
            // --- Handlers that do NOT examine HTTP headers ---
            ("POST", ["measurement", tee_str]) => {
                let tee = tee_from_path(tee_str)?;
                self.dispatch("measurement", tee, false, body, &empty_headers)
                    .await
            }
            ("POST", ["authorization", "policy", ..]) => {
                let mut handler = api::get_auth_policy_handler(
                    self.auth_policy_engine.clone(),
                    self.storage.clone(),
                    self.mags_lock.clone(),
                );
                handler.handle(body, &empty_headers).await
            }
            _ => bail!("unsupported: {} /kbs/v0/sams/{}", method, path.join("/")),
        }
    }

    async fn handle_with_headers(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        headers: &HeaderMap,
        init_data: Option<&serde_json::Value>,
    ) -> Result<Vec<u8>> {
        match (method.as_str(), path) {
            // --- Handlers that examine HTTP headers ---
            // Bearer JWT (guest-owner cert in "certificate" claim)
            ("POST", ["measurement", tee_str, "auth"]) => {
                let tee = tee_from_path(tee_str)?;
                self.dispatch("measurement", tee, true, body, headers).await
            }
            // mTLS (x-client-cert header from reverse proxy)
            ("POST", ["signing", "policy"]) => {
                let handler = SigningPolicyHandler::new(
                    self.signing_policy_engine.clone(),
                    self.rvps_client.clone(),
                    self.rvps_certs_lock.clone(),
                );
                handler.register_signing_policy(headers, body).await
            }
            ("DELETE", ["signing", "policy"]) => {
                let handler = SigningPolicyHandler::new(
                    self.signing_policy_engine.clone(),
                    self.rvps_client.clone(),
                    self.rvps_certs_lock.clone(),
                );
                handler.revoke_signing_policy(headers).await
            }
            ("DELETE", ["signing", "key", digest]) => {
                let handler = SigningPolicyHandler::new(
                    self.signing_policy_engine.clone(),
                    self.rvps_client.clone(),
                    self.rvps_certs_lock.clone(),
                );
                handler.revoke_signing_key(headers, digest).await
            }
            _ => self.handle(body, query, path, method, init_data).await,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn auth_mode(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        _method: &Method,
    ) -> Result<AuthMode> {
        match path {
            ["measurement", ..] | ["signing", ..] => Ok(AuthMode::Plugin),
            _ => Ok(AuthMode::Admin),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_tee_from_path_snp() {
        let tee = tee_from_path("snp").unwrap();
        assert!(matches!(tee, Tee::Snp));
    }

    #[rstest]
    #[case("tdx")]
    #[case("sgx")]
    #[case("cca")]
    #[case("unknown")]
    #[case("")]
    fn test_tee_from_path_unsupported(#[case] input: &str) {
        let err = tee_from_path(input).unwrap_err();
        assert!(
            err.to_string().contains("unsupported TEE type"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_sams_config_minimal_toml() {
        let toml_str = r#"
            ovmf_file = "/path/to/ovmf.fd"
            id_key_file = "/path/to/id.pem"
        "#;
        let cfg: SamsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.ovmf_file, PathBuf::from("/path/to/ovmf.fd"));
        assert_eq!(cfg.id_key_file, PathBuf::from("/path/to/id.pem"));
        assert!(cfg.rvps.is_none());
    }

    #[test]
    fn test_sams_config_grpc_rvps() {
        let toml_str = r#"
            ovmf_file = "/path/to/ovmf.fd"
            id_key_file = "/path/to/id.pem"

            [rvps]
            type = "Grpc"
            address = "http://localhost:50004"
        "#;
        let cfg: SamsConfig = toml::from_str(toml_str).unwrap();
        match cfg.rvps.unwrap() {
            SamsRvpsConfig::Grpc { address } => {
                assert_eq!(address, "http://localhost:50004");
            }
            other => panic!("expected Grpc, got {other:?}"),
        }
    }

    #[test]
    fn test_sams_config_builtin_rvps_default_storage() {
        let toml_str = r#"
            ovmf_file = "/path/to/ovmf.fd"
            id_key_file = "/path/to/id.pem"

            [rvps]
            type = "Builtin"
        "#;
        let cfg: SamsConfig = toml::from_str(toml_str).unwrap();
        match cfg.rvps.unwrap() {
            SamsRvpsConfig::Builtin { storage_type } => {
                assert!(storage_type.is_none());
            }
            other => panic!("expected Builtin, got {other:?}"),
        }
    }

    #[test]
    fn test_sams_config_missing_required_field() {
        let toml_str = r#"
            id_key_file = "/path/to/id.pem"
        "#;
        assert!(toml::from_str::<SamsConfig>(toml_str).is_err());
    }

    #[tokio::test]
    async fn test_auth_mode_measurement_path() {
        let sams = build_test_sams().await;
        let body = b"";
        let query = HashMap::new();
        let method = Method::POST;

        let mode = sams
            .auth_mode(body, &query, &["measurement", "snp"], &method)
            .await
            .unwrap();
        assert!(matches!(mode, AuthMode::Plugin));

        let mode = sams
            .auth_mode(body, &query, &["signing", "policy"], &method)
            .await
            .unwrap();
        assert!(matches!(mode, AuthMode::Plugin));

        let mode = sams
            .auth_mode(body, &query, &["other"], &method)
            .await
            .unwrap();
        assert!(matches!(mode, AuthMode::Admin));
    }

    #[tokio::test]
    async fn test_validate_auth_always_true() {
        let sams = build_test_sams().await;
        let result = sams
            .validate_auth(b"", &HashMap::new(), &["anything"], &Method::GET)
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_encrypted_always_false() {
        let sams = build_test_sams().await;
        let result = sams
            .encrypted(b"", &HashMap::new(), &["anything"], &Method::GET)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_handle_unsupported_route() {
        let sams = build_test_sams().await;
        let err = sams
            .handle(b"{}", &HashMap::new(), &["unknown"], &Method::GET, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported"), "unexpected: {err}");
    }

    async fn build_test_sams() -> Sams {
        use key_value_storage::memory::MemoryKeyValueStorage;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use policy_engine::policy::rego::Regorus;
        use policy_engine::PolicyEngine;

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let id_key = EcKey::generate(&group).unwrap();

        let storage = Arc::new(MemoryKeyValueStorage::default())
            as key_value_storage::KeyValueStorageInstance;
        let policy_engine = PolicyEngine::<Regorus>::new(storage.clone());
        let signing_policy_engine =
            PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));

        Sams {
            ovmf_file: PathBuf::from("/dev/null"),
            id_key,
            rvps_client: None,
            rvps_certs_lock: Arc::new(Mutex::new(())),
            mags_lock: Arc::new(Mutex::new(())),
            auth_policy_engine: policy_engine,
            signing_policy_engine,
            storage,
        }
    }
}
