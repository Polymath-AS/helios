use anyhow::{Context, bail};
use http::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::Server;
use crate::transport::{self, Body};

pub struct Client {
    http: transport::Client,
    token: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PathSpec {
    pub store_path: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deriver: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Uploaded {
    pub file_hash: String,
    pub file_size: u64,
    pub nar_hash: String,
    pub nar_size: u64,
}

pub enum Publish {
    Done { published: u64 },
    MissingNars(Vec<String>),
}

fn error_text(status: StatusCode, body: &[u8]) -> String {
    let msg = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    format!("{status}: {msg}")
}

impl Client {
    pub fn new(server: &Server) -> anyhow::Result<Self> {
        Ok(Self { http: transport::Client::new(server.server.trim_end_matches('/'))?, token: server.token.clone() })
    }

    async fn call<T: DeserializeOwned>(&self, method: Method, path: &str, content_type: Option<&str>, body: Body) -> anyhow::Result<T> {
        let (status, bytes) = self.http.send(method, &format!("/_api/v2{path}"), &self.token, content_type, body).await?;
        if !status.is_success() {
            bail!("{}", error_text(status, &bytes));
        }
        serde_json::from_slice(&bytes).with_context(|| format!("decoding response from {path}"))
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> anyhow::Result<T> {
        self.call(Method::POST, path, Some("application/json"), transport::full(serde_json::to_vec(body)?)).await
    }

    pub async fn missing(&self, cache: &str, hashes: &[&str]) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct R {
            missing: Vec<String>,
        }
        let r: R = self.post(&format!("/caches/{cache}/missing"), &json!({ "hashes": hashes })).await?;
        Ok(r.missing)
    }

    pub async fn known(&self, cache: &str, nar_hashes: &[&str]) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct R {
            known: Vec<String>,
        }
        let r: R = self.post(&format!("/caches/{cache}/nars/known"), &json!({ "narHashes": nar_hashes })).await?;
        Ok(r.known)
    }

    pub async fn upload(&self, cache: &str, body: Body) -> anyhow::Result<Uploaded> {
        self.call(Method::PUT, &format!("/caches/{cache}/nar?compression=zstd"), Some("application/x-nix-nar"), body).await
    }

    pub async fn publish(&self, cache: &str, paths: &[PathSpec]) -> anyhow::Result<Publish> {
        let body = transport::full(serde_json::to_vec(&json!({ "paths": paths }))?);
        let (status, bytes) =
            self.http.send(Method::POST, &format!("/_api/v2/caches/{cache}/paths"), &self.token, Some("application/json"), body).await?;
        if status == StatusCode::CONFLICT {
            let v: Value = serde_json::from_slice(&bytes)?;
            if v["error"] == "nar_required" {
                let missing = v["missing"].as_array().context("missing list")?.iter().filter_map(|m| m.as_str().map(str::to_owned)).collect();
                return Ok(Publish::MissingNars(missing));
            }
            bail!("publish conflict: {}", v["error"]);
        }
        if !status.is_success() {
            bail!("{}", error_text(status, &bytes));
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        Ok(Publish::Done { published: v["published"].as_u64().unwrap_or(0) })
    }

    pub async fn admin_get(&self, path: &str) -> anyhow::Result<Value> {
        self.call(Method::GET, path, None, transport::full(Bytes::new())).await
    }

    pub async fn admin_post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.post(path, &body).await
    }
}

use bytes::Bytes;
