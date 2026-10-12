use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::sha::sha384;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::Deserialize;

use crate::plugins::plugin_manager::PluginHttpError;

use super::snp::measurement::{build_rvps_message, read_rvps_certs_map};

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
    rvps_address: Option<String>,
}

impl SigningPolicyHandler {
    pub fn new(signing_policy_engine: PolicyEngine<Regorus>, rvps_address: Option<String>) -> Self {
        Self {
            signing_policy_engine,
            rvps_address,
        }
    }

    pub async fn register(&self, headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>> {
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

    pub async fn revoke(&self, headers: &HeaderMap) -> Result<Vec<u8>> {
        let client_cert = extract_client_cert(headers)?;
        let cert_hash = hash_cert(&client_cert);
        let policy_id = signing_policy_id(&cert_hash);

        let storage_key = format!("{policy_id}.rego");
        self.signing_policy_engine
            .storage
            .delete(&storage_key)
            .await
            .map_err(|e| anyhow!("failed to delete signing policy: {e}"))?;

        if let Some(addr) = &self.rvps_address {
            let mut certs_map = read_rvps_certs_map(addr).await?;
            certs_map.retain(|_digest, cert| cert != &client_cert);
            let message = build_rvps_message(&certs_map)?;
            reference_value_provider_service::client::register(addr.clone(), message).await?;
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

        let addr = self
            .rvps_address
            .as_ref()
            .ok_or_else(|| anyhow!("RVPS is not configured"))?;

        let mut certs_map = read_rvps_certs_map(addr).await?;

        if let Some(stored_cert) = certs_map.get(&auth_key_digest) {
            if stored_cert != &client_cert {
                return Err(PluginHttpError::forbidden(
                    "mTLS certificate does not match the certificate stored for this AuthKeyDigest",
                ));
            }

            certs_map.remove(&auth_key_digest);
            let message = build_rvps_message(&certs_map)?;
            reference_value_provider_service::client::register(addr.clone(), message).await?;
        }

        Ok(b"{}".to_vec())
    }
}
