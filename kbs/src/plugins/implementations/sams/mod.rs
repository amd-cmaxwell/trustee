// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::Method;
use anyhow::{bail, Result};
use kbs_types::Tee;
use key_value_storage::{KeyValueStorage, StorageProvider};
use policy_engine::policy::rego::Regorus;
use policy_engine::PolicyEngine;
use serde::Deserialize;

use super::super::plugin_manager::ClientPlugin;

mod api;
use api::RequestHandler;
mod backend;

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SamsConfig {
    pub ovmf_file: PathBuf,
}

pub struct Sams {
    ovmf_file: PathBuf,
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
        Ok(Self {
            ovmf_file: config.ovmf_file,
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
    async fn dispatch(&self, endpoint: &str, tee: Tee, body: &[u8]) -> Result<Vec<u8>> {
        let mut handler = api::get_request_handler(
            endpoint,
            tee,
            &self.ovmf_file,
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
            ("POST", ["measurement", tee_str, ..]) => {
                let tee = tee_from_path(tee_str)?;
                self.dispatch("measurement", tee, body).await
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

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        match (method.as_str(), path) {
            ("POST", ["measurement", ..]) => Ok(false),
            _ => Ok(true),
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
