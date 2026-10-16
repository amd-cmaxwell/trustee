// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use actix_web::http::Method;
use anyhow::{anyhow, bail, Result};
use kbs_types::Tee;
use key_value_storage::{KeyValueStorageType, StorageProvider};
use openssl::ec::EcKey;
use openssl::pkey::Private;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use reference_value_provider_service::{Rvps, REFERENCE_VALUE_STORAGE_NAMESPACE};
use serde::Deserialize;
use tokio::sync::Mutex;

use openssl::x509::X509;

use super::super::plugin_manager::{AuthMode, ClientPlugin, PluginHttpError};

mod api;
use api::RequestHandler;
mod backend;
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
    pub id_key_file: PathBuf,
    #[serde(default)]
    pub rvps: Option<SamsRvpsConfig>,
    #[serde(default)]
    pub identity_provider_url: Option<String>,
}

pub struct Sams {
    id_key: EcKey<Private>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
    mage_lock: Arc<Mutex<()>>,
    auth_policy_engine: PolicyEngine<Regorus>,
    signing_policy_engine: PolicyEngine<Regorus>,
    identity_provider_url: Option<String>,
}

impl Sams {
    pub async fn new(
        config: SamsConfig,
        storage_provider: Arc<dyn StorageProvider>,
        client_ca_cert: Option<&std::path::Path>,
    ) -> Result<Self> {
        let storage = storage_provider.get_or_register("sams").await?;
        let signing_policy_storage = storage_provider
            .get_or_register("sams-signing-policies")
            .await?;
        let policy_engine = PolicyEngine::<Regorus>::new(storage.clone());
        let signing_policy_engine = PolicyEngine::<Regorus>::new(signing_policy_storage);
        let id_key = load_ec_p384_privkey(&config.id_key_file)?;

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
            backend::rvps_helpers::register_sams_pubkey(client.as_ref(), &id_key).await?;
        }

        let identity_provider_url = config.identity_provider_url.or_else(|| {
            let pem = std::fs::read(client_ca_cert?).ok()?;
            let cert = X509::from_pem(&pem).ok()?;
            extract_ca_issuers_url(&cert)
        });

        Ok(Self {
            id_key,
            rvps_client,
            rvps_certs_lock: Arc::new(Mutex::new(())),
            mage_lock: Arc::new(Mutex::new(())),
            auth_policy_engine: policy_engine,
            signing_policy_engine,
            identity_provider_url,
        })
    }
}

fn load_ec_p384_privkey(path: &std::path::Path) -> Result<EcKey<Private>> {
    let key_data =
        std::fs::read(path).map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
    let ec_key = EcKey::private_key_from_pem(&key_data)
        .or_else(|_| EcKey::private_key_from_der(&key_data))
        .map_err(|e| anyhow!("failed to parse {}: {e}", path.display()))?;
    ec_key
        .check_key()
        .map_err(|e| anyhow!("invalid EC key in {}: {e}", path.display()))?;
    if ec_key.group().curve_name() != Some(openssl::nid::Nid::SECP384R1) {
        bail!("{} must be a P-384 (secp384r1) EC key", path.display());
    }
    Ok(ec_key)
}

fn extract_ca_issuers_url(cert: &X509) -> Option<String> {
    let aia = cert.authority_info()?;
    aia.iter()
        .find(|ad| ad.method().to_string() == "CA Issuers")
        .and_then(|ad| ad.location().uri().map(String::from))
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
        tee: Option<Tee>,
        path: &[&str],
        method: &Method,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<Vec<u8>> {
        let mut handler = api::get_request_handler(
            endpoint,
            tee,
            path,
            method,
            self.id_key.clone(),
            self.rvps_client.clone(),
            self.rvps_certs_lock.clone(),
            self.mage_lock.clone(),
            self.auth_policy_engine.clone(),
            self.signing_policy_engine.clone(),
            self.identity_provider_url.clone(),
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
        bail!("unsupported: {} /kbs/v0/sams/{}", method, path.join("/"))
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
            ("POST" | "GET", ["measurement", tee_str, ..]) => {
                let tee = tee_from_path(tee_str)?;
                self.dispatch("measurement", Some(tee), path, method, body, headers)
                    .await
            }
            ("POST" | "GET" | "DELETE", ["signing", ..]) => {
                self.dispatch("signing", None, path, method, body, headers)
                    .await
            }
            ("POST" | "GET", ["authorization", "policy", ..]) => {
                self.dispatch("authorization", None, path, method, body, headers)
                    .await
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
        method: &Method,
    ) -> Result<AuthMode> {
        match (method.as_str(), path) {
            ("POST" | "GET", ["measurement", ..])
            | ("POST" | "GET" | "DELETE", ["signing", ..]) => Ok(AuthMode::Plugin),
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
            id_key_file = "/path/to/id.pem"
        "#;
        let cfg: SamsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.id_key_file, PathBuf::from("/path/to/id.pem"));
        assert!(cfg.rvps.is_none());
        assert!(cfg.identity_provider_url.is_none());
    }

    #[test]
    fn test_sams_config_grpc_rvps() {
        let toml_str = r#"
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
            identity_provider_url = "https://ca.example.com"
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

    #[cfg(feature = "sams-snp")]
    #[tokio::test]
    async fn test_get_measurement_snp_returns_method_not_allowed() {
        let sams = build_test_sams().await;
        let headers = HeaderMap::new();
        let err = sams
            .handle_with_headers(
                b"",
                &HashMap::new(),
                &["measurement", "snp"],
                &Method::GET,
                &headers,
                None,
            )
            .await
            .unwrap_err();
        let plugin_err = err.downcast_ref::<PluginHttpError>().unwrap();
        assert_eq!(plugin_err.status, 405);
        assert!(
            plugin_err.message.contains("Use POST"),
            "unexpected: {}",
            plugin_err.message
        );
    }

    #[cfg(feature = "sams-snp")]
    #[tokio::test]
    async fn test_get_measurement_snp_auth_returns_method_not_allowed() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let sams = build_test_sams().await;
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"certificate": "dummy"})).unwrap());
        let jwt = format!(
            "Bearer {}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(b"sig"),
        );
        let mut headers = HeaderMap::new();
        headers.insert(actix_web::http::header::AUTHORIZATION, jwt.parse().unwrap());
        let err = sams
            .handle_with_headers(
                b"",
                &HashMap::new(),
                &["measurement", "snp", "auth"],
                &Method::GET,
                &headers,
                None,
            )
            .await
            .unwrap_err();
        let plugin_err = err.downcast_ref::<PluginHttpError>().unwrap();
        assert_eq!(plugin_err.status, 405);
        assert!(
            plugin_err.message.contains("Use POST"),
            "unexpected: {}",
            plugin_err.message
        );
        assert!(
            plugin_err.message.contains("family_id"),
            "should mention required auth fields: {}",
            plugin_err.message
        );
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
            id_key,
            rvps_client: None,
            rvps_certs_lock: Arc::new(Mutex::new(())),
            mage_lock: Arc::new(Mutex::new(())),
            auth_policy_engine: policy_engine,
            signing_policy_engine,
            identity_provider_url: None,
        }
    }

    async fn build_test_sams_with_idp(url: &str) -> Sams {
        let mut sams = build_test_sams().await;
        sams.identity_provider_url = Some(url.to_string());
        sams
    }

    #[test]
    fn test_extract_ca_issuers_url_no_aia() {
        let cert = generate_self_signed_cert(None);
        assert!(extract_ca_issuers_url(&cert).is_none());
    }

    #[test]
    fn test_extract_ca_issuers_url_with_aia() {
        let cert = generate_self_signed_cert(Some("https://ca.example.com/issuer"));
        let url = extract_ca_issuers_url(&cert).unwrap();
        assert_eq!(url, "https://ca.example.com/issuer");
    }

    #[allow(deprecated)]
    fn generate_self_signed_cert(ca_issuers_uri: Option<&str>) -> X509 {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(key).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "test-ca").unwrap();
        let name = name_builder.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();

        if let Some(uri) = ca_issuers_uri {
            let value = format!("caIssuers;URI:{uri}");
            let ext = X509Extension::new(None, None, "authorityInfoAccess", &value).unwrap();
            builder.append_extension(ext).unwrap();
        }

        builder.sign(&pkey, MessageDigest::sha384()).unwrap();
        builder.build()
    }

    #[test]
    fn test_sams_config_with_identity_provider() {
        let toml_str = r#"
            id_key_file = "/path/to/id.pem"
            identity_provider_url = "https://ca.example.com/v1/sign"
        "#;
        let cfg: SamsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.identity_provider_url.as_deref(),
            Some("https://ca.example.com/v1/sign")
        );
    }

    #[tokio::test]
    async fn test_handle_identity_provider_configured() {
        let sams = build_test_sams_with_idp("https://ca.example.com").await;
        let result = sams
            .handle_with_headers(
                b"",
                &HashMap::new(),
                &["signing", "identity-provider"],
                &Method::GET,
                &HeaderMap::new(),
                None,
            )
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(resp["certificate_authority_url"], "https://ca.example.com");
    }

    #[tokio::test]
    async fn test_handle_identity_provider_not_configured() {
        let sams = build_test_sams().await;
        let err = sams
            .handle_with_headers(
                b"",
                &HashMap::new(),
                &["signing", "identity-provider"],
                &Method::GET,
                &HeaderMap::new(),
                None,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not configured"),
            "unexpected: {err}"
        );
    }
}
