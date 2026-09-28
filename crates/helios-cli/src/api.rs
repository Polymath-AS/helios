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

    pub async fn pin(&self, cache: &str, store_paths: &[String]) -> anyhow::Result<Value> {
        self.post(&format!("/caches/{cache}/pins"), &json!({ "storePaths": store_paths })).await
    }

    pub async fn unpin(&self, cache: &str, store_path: &str) -> anyhow::Result<Value> {
        let base = store_path.strip_prefix("/nix/store/").unwrap_or(store_path);
        self.call(Method::DELETE, &format!("/caches/{cache}/pins/{base}"), None, transport::full(Bytes::new())).await
    }

    pub async fn pins(&self, cache: &str) -> anyhow::Result<Value> {
        self.call(Method::GET, &format!("/caches/{cache}/pins"), None, transport::full(Bytes::new())).await
    }

    pub async fn cache_info(&self, cache: &str) -> anyhow::Result<crate::substituter::CacheInfo> {
        self.call(Method::GET, &format!("/caches/{cache}"), None, transport::full(Bytes::new())).await
    }

    /// Starts a chunked upload; returns its id.
    pub async fn upload_create(&self, cache: &str) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct R {
            id: String,
        }
        let r: R = self.call(Method::POST, &format!("/caches/{cache}/uploads?compression=zstd"), None, transport::full(Bytes::new())).await?;
        Ok(r.id)
    }

    /// Appends `chunk` at `offset`, retrying transient failures. After a
    /// failed request the chunk may or may not have landed; the server's
    /// offset says which, and a chunk is never appended twice.
    pub async fn upload_append(&self, cache: &str, id: &str, offset: u64, chunk: Bytes) -> anyhow::Result<u64> {
        #[derive(Deserialize)]
        struct R {
            offset: u64,
        }
        let end = offset + chunk.len() as u64;
        let path = format!("/_api/v2/caches/{cache}/uploads/{id}");
        let mut delay = std::time::Duration::from_millis(250);
        for attempt in 1.. {
            let failure =
                match self.http.send(Method::PATCH, &format!("{path}?offset={offset}"), &self.token, None, transport::full(chunk.clone())).await {
                    Ok((status, bytes)) if status.is_success() => return Ok(serde_json::from_slice::<R>(&bytes)?.offset),
                    Ok((status, bytes)) if status == StatusCode::CONFLICT => {
                        let at = serde_json::from_slice::<Value>(&bytes).ok().and_then(|v| v["offset"].as_u64());
                        match at {
                            Some(at) if at == end => return Ok(end),
                            _ => bail!("{}", error_text(status, &bytes)),
                        }
                    }
                    Ok((status, bytes)) if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS => error_text(status, &bytes),
                    Ok((status, bytes)) => bail!("{}", error_text(status, &bytes)),
                    Err(e) => format!("{e:#}"),
                };
            if attempt == 5 {
                bail!("uploading a chunk at offset {offset}: {failure}");
            }
            tracing::warn!("uploading a chunk at offset {offset} failed, retrying in {delay:?}: {failure}");
            tokio::time::sleep(delay).await;
            delay *= 2;
            // The request may have landed before the failure; if so, move on.
            if let Ok(r) = self.call::<R>(Method::GET, &format!("/caches/{cache}/uploads/{id}"), None, transport::full(Bytes::new())).await {
                match r.offset {
                    at if at == end => return Ok(end),
                    at if at == offset => {}
                    at => bail!("server is at offset {at}, expected {offset} or {end}"),
                }
            }
        }
        unreachable!()
    }

    pub async fn upload_complete(&self, cache: &str, id: &str) -> anyhow::Result<Uploaded> {
        self.call(Method::POST, &format!("/caches/{cache}/uploads/{id}/complete"), None, transport::full(Bytes::new())).await
    }

    pub async fn upload_abort(&self, cache: &str, id: &str) {
        let _ =
            self.http.send(Method::DELETE, &format!("/_api/v2/caches/{cache}/uploads/{id}"), &self.token, None, transport::full(Bytes::new())).await;
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
