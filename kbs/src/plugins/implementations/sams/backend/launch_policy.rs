use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::api::RequestHandler;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct LaunchPolicyRequest {
    pub policy: String,
    #[serde(default)]
    pub incr_gsvn: bool,
}

#[derive(Serialize)]
#[allow(dead_code)]
pub struct LaunchPolicyResponse {
    pub gsvn: u32,
}

pub struct LaunchPolicyHandler;

impl RequestHandler for LaunchPolicyHandler {
    fn handle(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let _req: LaunchPolicyRequest = serde_json::from_slice(body)?;
        todo!()
    }
}
