// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use actix_web::http::Method;
use anyhow::{bail, Result};
use kbs_types::Tee;
use serde::Deserialize;

use super::super::plugin_manager::ClientPlugin;

mod api;
mod backend;

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SamsConfig {
    pub item: String,
}

pub struct Sams {
    _item: String,
}

impl TryFrom<SamsConfig> for Sams {
    type Error = anyhow::Error;

    fn try_from(value: SamsConfig) -> anyhow::Result<Self> {
        Ok(Self { _item: value.item })
    }
}

#[derive(Deserialize)]
struct TeeHint {
    tee: Option<String>,
}

fn tee_from_body(body: &[u8]) -> Option<Tee> {
    let hint: TeeHint = serde_json::from_slice(body).ok()?;
    match hint.tee.as_deref() {
        Some("snp") => Some(Tee::Snp),
        _ => None,
    }
}

impl Sams {
    fn dispatch(&self, endpoint: &str, body: &[u8]) -> Result<Vec<u8>> {
        let tee = tee_from_body(body);
        let mut handler = api::get_request_handler(endpoint, tee)?;
        handler.handle(body)
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
        match (method.as_str(), path.first().copied()) {
            ("POST", Some("measurement")) => self.dispatch("measurement", body),
            ("POST", Some("launch-policy")) => self.dispatch("launch-policy", body),
            _ => bail!(
                "unsupported: {} /kbs/v0/sams/{}",
                method,
                path.join("/")
            ),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        match (method.as_str(), path.first().copied()) {
            ("POST", Some("measurement")) => Ok(false),
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
