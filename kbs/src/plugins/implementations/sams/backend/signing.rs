use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::sha::sha384;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::Deserialize;

use crate::plugins::implementations::sams::rvps_client::RvpsClient;
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
    rvps_client: Option<Arc<dyn RvpsClient>>,
}

impl SigningPolicyHandler {
    pub fn new(
        signing_policy_engine: PolicyEngine<Regorus>,
        rvps_client: Option<Arc<dyn RvpsClient>>,
    ) -> Self {
        Self {
            signing_policy_engine,
            rvps_client,
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

        let mut certs_map = read_rvps_certs_map(client.as_ref()).await?;

        if let Some(certs) = certs_map.get_mut(&auth_key_digest) {
            if !certs.contains(&client_cert) {
                return Err(PluginHttpError::forbidden(
                    "mTLS certificate does not match any certificate stored for this AuthKeyDigest",
                ));
            }

            certs.retain(|c| c != &client_cert);
            if certs.is_empty() {
                certs_map.remove(&auth_key_digest);
            }
            let message = build_rvps_message(&certs_map)?;
            client.register(message).await?;
        }

        Ok(b"{}".to_vec())
    }
}
