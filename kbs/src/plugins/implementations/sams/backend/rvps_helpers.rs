use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::ec::EcKey;
use openssl::pkey::Private;

use crate::plugins::implementations::sams::rvps_client::RvpsClient;

pub const RVPS_GUEST_OWNER_CERTS_KEY: &str = "guest-owner-certs";
pub const RVPS_GUEST_OWNER_PUBKEYS_KEY: &str = "guest-owner-pubkeys";
pub const MAGE_KEY: &str = "minimum_authorized_generation_epoch";
const RVPS_SAGE_SALTS_KEY: &str = "sage-salts";

pub fn build_rvps_message(certs_map: &HashMap<String, Vec<String>>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_GUEST_OWNER_CERTS_KEY: certs_map });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

pub async fn read_rvps_certs_map(client: &dyn RvpsClient) -> Result<HashMap<String, Vec<String>>> {
    let result = client.query(RVPS_GUEST_OWNER_CERTS_KEY.to_string()).await?;

    match result {
        Some(json_str) => {
            let map: HashMap<String, Vec<String>> = serde_json::from_str(&json_str)?;
            Ok(map)
        }
        None => Ok(HashMap::new()),
    }
}

pub fn build_rvps_pubkeys_message(pubkeys_map: &HashMap<String, String>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_GUEST_OWNER_PUBKEYS_KEY: pubkeys_map });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

pub async fn read_rvps_pubkeys_map(client: &dyn RvpsClient) -> Result<HashMap<String, String>> {
    let result = client
        .query(RVPS_GUEST_OWNER_PUBKEYS_KEY.to_string())
        .await?;

    match result {
        Some(json_str) => {
            let map: HashMap<String, String> = serde_json::from_str(&json_str)?;
            Ok(map)
        }
        None => Ok(HashMap::new()),
    }
}

fn generate_salt() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    hex::encode(bytes)
}

pub async fn read_sage_salts(client: &dyn RvpsClient) -> Result<HashMap<String, String>> {
    match client.query(RVPS_SAGE_SALTS_KEY.to_string()).await? {
        Some(json_str) => Ok(serde_json::from_str(&json_str)?),
        None => Ok(HashMap::new()),
    }
}

fn build_sage_salts_message(salts: &HashMap<String, String>) -> Result<String> {
    let payload = serde_json::json!({ RVPS_SAGE_SALTS_KEY: salts });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    Ok(serde_json::to_string(&message)?)
}

pub async fn ensure_salt_for_mage(client: &dyn RvpsClient, mage: u32) -> Result<()> {
    let mut salts = read_sage_salts(client).await?;
    let key = mage.to_string();
    if let std::collections::hash_map::Entry::Vacant(e) = salts.entry(key) {
        e.insert(generate_salt());
        let message = build_sage_salts_message(&salts)?;
        client.register(message).await?;
    }
    Ok(())
}

pub async fn read_mage(client: &dyn RvpsClient) -> Result<u32> {
    match client.query(MAGE_KEY.to_string()).await? {
        Some(json_str) => {
            let val: u32 = serde_json::from_str(&json_str)?;
            Ok(val)
        }
        None => Ok(0),
    }
}

pub async fn write_mage(client: &dyn RvpsClient, value: u32) -> Result<()> {
    let payload = serde_json::json!({ MAGE_KEY: value });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    client.register(serde_json::to_string(&message)?).await
}

pub async fn register_sams_pubkey(client: &dyn RvpsClient, id_key: &EcKey<Private>) -> Result<()> {
    let pkey = openssl::pkey::PKey::from_ec_key(id_key.clone())
        .map_err(|e| anyhow!("failed to create PKey from SAMS id_key: {e}"))?;
    let pub_der = pkey
        .public_key_to_der()
        .map_err(|e| anyhow!("failed to serialize SAMS public key: {e}"))?;
    let key_b64 = STANDARD.encode(&pub_der);

    let payload = serde_json::json!({ "sams-id-key": key_b64 });
    let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload)?);
    let message = serde_json::json!({
        "version": "0.1.0",
        "payload": payload_b64,
        "type": "sample"
    });
    client.register(serde_json::to_string(&message)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::implementations::sams::rvps_client::test_support::MockRvpsClient;

    #[test]
    fn test_generate_salt_format() {
        let salt = generate_salt();
        assert_eq!(salt.len(), 64);
        assert!(salt.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_ensure_salt_idempotent() {
        let client = MockRvpsClient::new();
        ensure_salt_for_mage(&client, 0).await.unwrap();
        let salts1 = read_sage_salts(&client).await.unwrap();
        let salt_0 = salts1["0"].clone();

        ensure_salt_for_mage(&client, 0).await.unwrap();
        let salts2 = read_sage_salts(&client).await.unwrap();
        assert_eq!(salts2["0"], salt_0, "salt should not change on second call");
    }
}
