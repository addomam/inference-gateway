//! Traffic-alignment harnesses.
//!
//! Each first-party client is one module under this tree. A harness describes
//! the upstream API base and the headers that must match a recording. The
//! replay test sends a fixture's client request through infer and compares the
//! upstream call with [`align`]. Recording is a separate manual command.

pub mod codex;
mod harness;
mod normalize;
mod record;
mod scrub;

pub use codex::{CODEX, package_filename, pinned_digest, verify_artifact, verify_sums_manifest};
pub use harness::Harness;
pub use normalize::align;
pub use record::{CapturedExchange, RecordingProxy};
pub use scrub::{assert_clean, findings, scrub_value};

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// How a committed fixture was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    /// Built by reading the pinned client source. Not a packet capture.
    SourceDerived,
    /// Scrubbed capture from the official client.
    Recorded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceNote {
    pub repository: String,
    pub commit: String,
    pub release: String,
    pub release_commit: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fixture {
    pub harness: String,
    pub scenario: String,
    pub provenance: Provenance,
    pub source: SourceNote,
    /// Request the replay test sends to infer.
    pub client: ClientCall,
    /// Upstream exchanges, in order. `compare: false` keeps a call in the file
    /// without requiring infer to make it.
    pub exchanges: Vec<Exchange>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientCall {
    pub method: String,
    pub path: String,
    pub headers: Map<String, Value>,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exchange {
    #[serde(default = "compare_default")]
    pub compare: bool,
    pub request: ObservedRequest,
    pub response: ObservedResponse,
}

fn compare_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedRequest {
    pub method: String,
    /// Path relative to the harness API base. `/responses`, not the origin path.
    pub path: String,
    #[serde(default)]
    pub query: String,
    pub headers: Map<String, Value>,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedResponse {
    pub status: u16,
    pub headers: Map<String, Value>,
    /// UTF-8 response body. Mutually exclusive with `body_base64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

impl ObservedResponse {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        match (&self.body, &self.body_base64) {
            (Some(body), None) => Ok(body.as_bytes().to_vec()),
            (None, Some(encoded)) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .context("fixture response body_base64")
            }
            _ => bail!("fixture response needs exactly one of body or body_base64"),
        }
    }
}

/// One upstream call observed during replay, before normalization.
#[derive(Debug, Clone, PartialEq)]
pub struct ActualRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Map<String, Value>,
    pub body: Vec<u8>,
}

pub fn load_fixture(path: &Path) -> Result<Fixture> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub fn fixtures_in(dir: &Path) -> Result<Vec<(std::path::PathBuf, Fixture)>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().is_some_and(|ext| ext == "json"));
    paths.sort();
    paths
        .into_iter()
        .map(|path| load_fixture(&path).map(|fixture| (path, fixture)))
        .collect()
}
