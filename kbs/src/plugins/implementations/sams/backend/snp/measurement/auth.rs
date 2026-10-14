use actix_web::http::header::HeaderMap;
use anyhow::{anyhow, Context, Result};
use base64::Engine;

use crate::plugins::plugin_manager::PluginHttpError;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use openssl::x509::X509;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::Deserialize;
use sev::measurement::idblock::get_key_digest;
use sev::measurement::idblock_types::SevEcdsaPubKey;
use sev::parser::ByteParser;

use super::super::super::signing::signing_policy_id;

pub const AUTH_POLICY_RULE: &str = "data.policy.authorized";
const SIGNING_POLICY_PUBKEY_RULE: &str = "data.policy.pubkey";
const SIGNING_POLICY_PRIVKEY_RULE: &str = "data.policy.privkey";

#[derive(Deserialize)]
struct GuestOwnerJwtClaims {
    certificate: String,
}

pub fn extract_guest_owner_cert(headers: &HeaderMap) -> Option<String> {
    let auth_value = headers.get("authorization")?.to_str().ok()?;
    let jwt = auth_value.strip_prefix("Bearer ")?;
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_b64 = parts.get(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: GuestOwnerJwtClaims = serde_json::from_slice(&payload_bytes).ok()?;
    Some(claims.certificate)
}

pub fn compute_auth_key_digest(privkey_pem: &str) -> Result<String> {
    let ec_key = EcKey::private_key_from_pem(privkey_pem.as_bytes())
        .map_err(|e| anyhow!("invalid guest-owner private key: {e}"))?;
    let sev_pub_key = SevEcdsaPubKey::try_from(&ec_key)
        .map_err(|e| anyhow!("failed to convert to SevEcdsaPubKey: {e}"))?;
    let digest =
        get_key_digest(sev_pub_key).map_err(|e| anyhow!("failed to compute AuthKeyDigest: {e}"))?;
    let digest_bytes = digest
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize AuthKeyDigest: {e}"))?;
    Ok(hex::encode(digest_bytes))
}

fn x509_name_to_json(name: &openssl::x509::X509NameRef) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("unknown");
        let val = entry.data().to_string().unwrap_or_default();
        map.insert(key.to_string(), serde_json::Value::String(val));
    }
    serde_json::Value::Object(map)
}

pub fn parse_x509_to_json(pem: &str) -> Result<serde_json::Value> {
    let cert = X509::from_pem(pem.as_bytes()).context("failed to parse guest-owner cert PEM")?;
    let subject = x509_name_to_json(cert.subject_name());
    let issuer = x509_name_to_json(cert.issuer_name());
    let serial = cert
        .serial_number()
        .to_bn()
        .map(|bn| bn.to_hex_str().map(|s| s.to_string()))
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let mut extensions = serde_json::Map::new();
    if let Some(san) = cert.subject_alt_names() {
        let names: Vec<String> = san
            .iter()
            .filter_map(|n| {
                n.dnsname()
                    .map(String::from)
                    .or_else(|| n.email().map(String::from))
                    .or_else(|| n.uri().map(String::from))
                    .or_else(|| n.ipaddress().map(|ip| format!("{ip:?}")))
            })
            .collect();
        if !names.is_empty() {
            extensions.insert(
                "subject_alt_names".to_string(),
                serde_json::Value::Array(
                    names.into_iter().map(serde_json::Value::String).collect(),
                ),
            );
        }
    }

    Ok(serde_json::json!({
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
        "extensions": extensions,
    }))
}

pub struct SigningKeys {
    pub privkey: EcKey<Private>,
    pub privkey_pem: String,
}

pub async fn evaluate_signing_policy(
    signing_policy_engine: &PolicyEngine<Regorus>,
    cert_hash: &str,
    input: &str,
) -> Result<SigningKeys> {
    let policy_id = signing_policy_id(cert_hash);
    let policy = signing_policy_engine
        .get_policy(&policy_id)
        .await
        .map_err(|_| {
            PluginHttpError::unauthorized("guest-owner signing policy not found in SAMS")
        })?;

    let result = signing_policy_engine
        .engine
        .evaluate(
            None,
            input.to_string(),
            policy,
            vec![
                SIGNING_POLICY_PUBKEY_RULE.to_string(),
                SIGNING_POLICY_PRIVKEY_RULE.to_string(),
            ],
            vec![],
        )
        .await
        .map_err(|e| anyhow!("signing policy evaluation failed: {e}"))?;

    let privkey_pem = result
        .eval_rules_result
        .get(SIGNING_POLICY_PRIVKEY_RULE)
        .and_then(|v| v.as_ref())
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PluginHttpError::forbidden(
                "signing policy did not produce a valid privkey for these launch params",
            )
        })?
        .to_string();

    let privkey = EcKey::private_key_from_pem(privkey_pem.as_bytes())
        .map_err(|e| anyhow!("signing policy produced an invalid private key PEM: {e}"))?;

    Ok(SigningKeys {
        privkey,
        privkey_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use policy_engine::policy::rego::Regorus;
    use policy_engine::PolicyEngine;
    use std::sync::Arc;

    #[test]
    fn test_extract_guest_owner_cert_valid_jwt() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"certificate":"TEST-CERT-PEM"}"#);
        let sig = URL_SAFE_NO_PAD.encode("fakesig");
        let token = format!("{header}.{payload}.{sig}");

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let result = extract_guest_owner_cert(&headers);
        assert_eq!(result, Some("TEST-CERT-PEM".to_string()));
    }

    #[test]
    fn test_extract_guest_owner_cert_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_guest_owner_cert(&headers), None);
    }

    #[test]
    fn test_extract_guest_owner_cert_not_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Basic dGVzdA=="),
        );
        assert_eq!(extract_guest_owner_cert(&headers), None);
    }

    #[test]
    fn test_extract_guest_owner_cert_missing_claim() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"other":"field"}"#);
        let sig = URL_SAFE_NO_PAD.encode("fakesig");
        let token = format!("{header}.{payload}.{sig}");

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        assert_eq!(extract_guest_owner_cert(&headers), None);
    }

    #[test]
    fn test_parse_x509_to_json_self_signed() {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(key).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "test-sams")
            .unwrap();
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
            .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha384())
            .unwrap();
        let cert = builder.build();
        let pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();

        let json = parse_x509_to_json(&pem).unwrap();
        assert!(json.get("subject").is_some());
        assert!(json.get("issuer").is_some());
        assert!(json.get("serial").is_some());
        assert!(json.get("not_before").is_some());
        assert!(json.get("not_after").is_some());
        assert!(json.get("extensions").is_some());
        assert_eq!(json["subject"]["CN"], "test-sams");
    }

    #[test]
    fn test_parse_x509_to_json_invalid_pem() {
        let err = parse_x509_to_json("not-valid-pem").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to parse"),
            "expected 'failed to parse' in: {msg}"
        );
    }

    #[test]
    fn test_compute_auth_key_digest_valid_key() {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pem = String::from_utf8(key.private_key_to_pem().unwrap()).unwrap();

        let hex_string = compute_auth_key_digest(&pem).unwrap();
        assert!(!hex_string.is_empty());
        assert!(
            hex_string.chars().all(|c| c.is_ascii_hexdigit()),
            "expected all hex chars, got: {hex_string}"
        );
    }

    #[test]
    fn test_compute_auth_key_digest_deterministic() {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pem = String::from_utf8(key.private_key_to_pem().unwrap()).unwrap();

        let first = compute_auth_key_digest(&pem).unwrap();
        let second = compute_auth_key_digest(&pem).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn test_compute_auth_key_digest_invalid_pem() {
        let err = compute_auth_key_digest("not-a-pem").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid"), "expected 'invalid' in: {msg}");
    }

    #[tokio::test]
    async fn test_evaluate_signing_policy_no_policy() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let engine = PolicyEngine {
            storage,
            engine: Regorus {},
        };

        let result = evaluate_signing_policy(&engine, "nonexistent", "{}").await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error, got Ok"),
        };
        let plugin_err = err
            .downcast_ref::<crate::plugins::plugin_manager::PluginHttpError>()
            .unwrap();
        assert_eq!(plugin_err.status, 401);
    }
}
