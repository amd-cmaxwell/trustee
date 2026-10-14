use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::sha::sha384;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::Deserialize;

use tokio::sync::Mutex;

use crate::plugins::implementations::sams::rvps_client::RvpsClient;
use crate::plugins::plugin_manager::PluginHttpError;

use super::snp::measurement::{
    build_rvps_message, build_rvps_pubkeys_message, read_rvps_certs_map, read_rvps_pubkeys_map,
};

const CLIENT_CERT_HEADER: &str = "x-client-cert";
const SIGNING_POLICY_PREFIX: &str = "signing-policy-";

#[derive(Deserialize)]
pub struct SigningPolicyRequest {
    pub signing_policy: String,
}

fn extract_client_cert(headers: &HeaderMap) -> Result<String> {
    let cert_value = headers
        .get(CLIENT_CERT_HEADER)
        .ok_or_else(|| anyhow!("missing {CLIENT_CERT_HEADER} header (mTLS proxy required)"))?
        .to_str()
        .map_err(|e| anyhow!("invalid {CLIENT_CERT_HEADER} header: {e}"))?;

    Ok(cert_value.to_string())
}

pub fn signing_policy_id(cert_hash: &str) -> String {
    format!("{SIGNING_POLICY_PREFIX}{cert_hash}")
}

pub fn hash_cert(data: &str) -> String {
    hex::encode(sha384(data.as_bytes()))
}

pub struct SigningPolicyHandler {
    signing_policy_engine: PolicyEngine<Regorus>,
    rvps_client: Option<Arc<dyn RvpsClient>>,
    rvps_certs_lock: Arc<Mutex<()>>,
}

impl SigningPolicyHandler {
    pub fn new(
        signing_policy_engine: PolicyEngine<Regorus>,
        rvps_client: Option<Arc<dyn RvpsClient>>,
        rvps_certs_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            signing_policy_engine,
            rvps_client,
            rvps_certs_lock,
        }
    }

    pub async fn register_signing_policy(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;
        let req: SigningPolicyRequest = serde_json::from_slice(body)?;

        let rego = String::from_utf8(
            STANDARD
                .decode(&req.signing_policy)
                .map_err(|e| anyhow!("invalid base64 in signing_policy field: {e}"))?,
        )
        .map_err(|e| anyhow!("signing_policy is not valid UTF-8: {e}"))?;

        let cert_hash = hash_cert(&client_cert);
        let policy_id = signing_policy_id(&cert_hash);

        self.signing_policy_engine
            .set_policy(&policy_id, &rego, true)
            .await
            .map_err(|e| anyhow!("failed to store signing policy: {e}"))?;

        Ok(b"{}".to_vec())
    }

    pub async fn revoke_signing_policy(&self, headers: &HeaderMap) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;
        let cert_hash = hash_cert(&client_cert);
        let policy_id = signing_policy_id(&cert_hash);

        let storage_key = format!("{policy_id}.rego");
        self.signing_policy_engine
            .storage
            .delete(&storage_key)
            .await
            .map_err(|e| anyhow!("failed to delete signing policy: {e}"))?;

        if let Some(client) = &self.rvps_client {
            let _guard = self.rvps_certs_lock.lock().await;
            let mut certs_map = read_rvps_certs_map(client.as_ref()).await?;
            for certs in certs_map.values_mut() {
                certs.retain(|c| c != &client_cert);
            }
            certs_map.retain(|_, certs| !certs.is_empty());
            let message = build_rvps_message(&certs_map)?;
            client.register(message).await?;
        }

        Ok(b"{}".to_vec())
    }

    pub async fn revoke_signing_key(
        &self,
        headers: &HeaderMap,
        auth_key_digest_b64: &str,
    ) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;

        let auth_key_digest = String::from_utf8(
            STANDARD
                .decode(auth_key_digest_b64)
                .map_err(|e| anyhow!("invalid base64 in AuthKeyDigest path segment: {e}"))?,
        )
        .map_err(|e| anyhow!("AuthKeyDigest is not valid UTF-8: {e}"))?;

        let client = self
            .rvps_client
            .as_ref()
            .ok_or_else(|| anyhow!("RVPS is not configured"))?;

        let _guard = self.rvps_certs_lock.lock().await;
        let mut certs_map = read_rvps_certs_map(client.as_ref()).await?;

        if let Some(certs) = certs_map.get_mut(&auth_key_digest) {
            if !certs.contains(&client_cert) {
                return Err(PluginHttpError::forbidden(
                    "mTLS certificate does not match any certificate stored for this AuthKeyDigest",
                ));
            }

            certs.retain(|c| c != &client_cert);
            let key_fully_revoked = certs.is_empty();
            if key_fully_revoked {
                certs_map.remove(&auth_key_digest);
            }
            let message = build_rvps_message(&certs_map)?;
            client.register(message).await?;

            if key_fully_revoked {
                let mut pubkeys_map = read_rvps_pubkeys_map(client.as_ref()).await?;
                pubkeys_map.remove(&auth_key_digest);
                let message = build_rvps_pubkeys_message(&pubkeys_map)?;
                client.register(message).await?;
            }
        }

        Ok(b"{}".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use key_value_storage::memory::MemoryKeyValueStorage;
    use policy_engine::policy::rego::Regorus;
    use policy_engine::PolicyEngine;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn test_hash_cert_deterministic() {
        let input = "some-certificate-data";
        let h1 = hash_cert(input);
        let h2 = hash_cert(input);
        assert_eq!(h1, h2);
        // SHA-384 produces 48 bytes = 96 hex characters
        assert_eq!(h1.len(), 96);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_cert_different_inputs() {
        let h_a = hash_cert("a");
        let h_b = hash_cert("b");
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn test_signing_policy_id_format() {
        let result = signing_policy_id("abc");
        assert_eq!(result, "signing-policy-abc");
    }

    #[test]
    fn test_extract_client_cert_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-client-cert"),
            HeaderValue::from_static("my-cert-value"),
        );
        let result = extract_client_cert(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-cert-value");
    }

    #[test]
    fn test_extract_client_cert_missing() {
        let headers = HeaderMap::new();
        let result = extract_client_cert(&headers);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing"),
            "expected error to contain 'missing', got: {err_msg}"
        );
    }

    #[test]
    fn test_signing_policy_request_deserialize() {
        let json = r#"{"signing_policy": "cG9saWN5"}"#;
        let req: SigningPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.signing_policy, "cG9saWN5");
    }

    #[tokio::test]
    async fn test_register_signing_policy_success() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let engine = PolicyEngine::<Regorus>::new(storage);
        let handler = SigningPolicyHandler::new(engine, None, Arc::new(Mutex::new(())));

        let rego = "package policy\ndefault allow = true";
        let encoded = STANDARD.encode(rego);
        let body = serde_json::to_vec(&serde_json::json!({
            "signing_policy": encoded
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-client-cert"),
            HeaderValue::from_static("test-cert"),
        );

        let result = handler.register_signing_policy(&headers, &body).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"{}");
    }

    #[tokio::test]
    async fn test_register_signing_policy_missing_header() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let engine = PolicyEngine::<Regorus>::new(storage);
        let handler = SigningPolicyHandler::new(engine, None, Arc::new(Mutex::new(())));

        let body = b"{}";
        let headers = HeaderMap::new();

        let result = handler.register_signing_policy(&headers, body).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing"),
            "expected error to contain 'missing', got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_revoke_signing_key_no_rvps() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let engine = PolicyEngine::<Regorus>::new(storage);
        let handler = SigningPolicyHandler::new(engine, None, Arc::new(Mutex::new(())));

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-client-cert"),
            HeaderValue::from_static("test-cert"),
        );

        let result = handler.revoke_signing_key(&headers, "dGVzdA==").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("RVPS is not configured"),
            "expected error to contain 'RVPS is not configured', got: {err_msg}"
        );
    }
}
