// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use actix_web::http::Method;
use anyhow::{bail, Result};
use kbs_types::Tee;
use key_value_storage::{KeyValueStorage, StorageProvider};
use openssl::ec::EcKey;
use openssl::pkey::Private;
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::Deserialize;
use sev::measurement::idblock::load_priv_key;

use super::super::plugin_manager::{AuthMode, ClientPlugin};

mod api;
use api::RequestHandler;
mod backend;

use backend::guest_owner::GuestOwnerHandler;

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SamsConfig {
    pub ovmf_file: PathBuf,
    pub id_key_file: PathBuf,
}

pub struct Sams {
    ovmf_file: PathBuf,
    id_key: EcKey<Private>,
    policy_engine: PolicyEngine<Regorus>,
    storage: Arc<dyn KeyValueStorage>,
}

impl Sams {
    pub async fn new(
        config: SamsConfig,
        storage_provider: Arc<dyn StorageProvider>,
    ) -> Result<Self> {
        let storage = storage_provider.get_or_register("sams").await?;
        let policy_engine = PolicyEngine::<Regorus>::new(storage.clone());
        let id_key = load_priv_key(config.id_key_file)?;
        Ok(Self {
            ovmf_file: config.ovmf_file,
            id_key,
            policy_engine,
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
    ) -> Result<Vec<u8>> {
        let mut handler = api::get_request_handler(
            endpoint,
            tee,
            &self.ovmf_file,
            self.id_key.clone(),
            is_auth,
            self.policy_engine.clone(),
            self.storage.clone(),
        )?;
        handler.handle(body).await
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
        match (method.as_str(), path) {
            ("POST", ["measurement", tee_str]) => {
                let tee = tee_from_path(tee_str)?;
                self.dispatch("measurement", tee, false, body).await
            }
            ("POST", ["measurement", tee_str, "auth"]) => {
                let tee = tee_from_path(tee_str)?;
                self.dispatch("measurement", tee, true, body).await
            }
            ("POST", ["launch-policy", ..]) => {
                let mut handler = api::get_launch_policy_handler(
                    self.policy_engine.clone(),
                    self.storage.clone(),
                );
                handler.handle(body).await
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
            ("POST", ["guest-owner"]) => {
                let handler = GuestOwnerHandler::new(self.storage.clone());
                handler.register(headers, body).await
            }
            ("DELETE", ["guest-owner"]) => {
                let handler = GuestOwnerHandler::new(self.storage.clone());
                handler.revoke(headers).await
            }
            _ => self.handle(body, query, path, method, init_data).await,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        match path {
            ["measurement", ..] => Ok(false),
            _ => Ok(true),
        }
    }

    async fn auth_mode(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        _method: &Method,
    ) -> Result<AuthMode> {
        match path {
            ["guest-owner"] => Ok(AuthMode::Plugin),
            ["measurement", ..] => Ok(AuthMode::Attestation),
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
