use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::api::RequestHandler;

#[derive(Deserialize)]
pub struct LaunchPolicyRequest {
    pub policy: String,
}

#[derive(Serialize)]
pub struct LaunchPolicyResponse {
    pub accepted: bool,
}

pub struct LaunchPolicyHandler;

impl RequestHandler for LaunchPolicyHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let _req: LaunchPolicyRequest = serde_json::from_slice(body)?;
        todo!()
    }
}
