use anyhow::{Context, bail};
use reqwest::{Body, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::Server;

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
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

async fn error_text(resp: Response) -> String {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let msg = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or(body);
    format!("{status}: {msg}")
}

impl Client {
    pub fn new(server: &Server) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("helios-cli/", env!("CARGO_PKG_VERSION")))
            .tcp_nodelay(true)
            .pool_max_idle_per_host(64)
            .build()?;
        Ok(Self { http, base: server.server.trim_end_matches('/').to_owned(), token: server.token.clone() })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/_api/v2{path}", self.base)
    }

    async fn json<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> anyhow::Result<T> {
        let resp = req.bearer_auth(&self.token).send().await?;
        if !resp.status().is_success() {
            bail!("{}", error_text(resp).await);
        }
        Ok(resp.json().await?)
    }

    pub async fn missing(&self, cache: &str, hashes: &[&str]) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct R {
            missing: Vec<String>,
        }
        let r: R = self.json(self.http.post(self.url(&format!("/caches/{cache}/missing"))).json(&json!({ "hashes": hashes }))).await?;
        Ok(r.missing)
    }

    pub async fn known(&self, cache: &str, nar_hashes: &[&str]) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct R {
            known: Vec<String>,
        }
        let r: R = self
            .json(self.http.post(self.url(&format!("/caches/{cache}/nars/known"))).json(&json!({ "narHashes": nar_hashes })))
            .await?;
        Ok(r.known)
    }

    pub async fn upload(&self, cache: &str, body: Body) -> anyhow::Result<Uploaded> {
        self.json(
            self.http
                .put(self.url(&format!("/caches/{cache}/nar?compression=zstd")))
                .header("content-type", "application/x-nix-nar")
                .body(body),
        )
        .await
    }

    pub async fn publish(&self, cache: &str, paths: &[PathSpec]) -> anyhow::Result<Publish> {
        let resp = self
            .http
            .post(self.url(&format!("/caches/{cache}/paths")))
            .bearer_auth(&self.token)
            .json(&json!({ "paths": paths }))
            .send()
            .await?;
        if resp.status() == StatusCode::CONFLICT {
            let v: Value = resp.json().await?;
            if v["error"] == "nar_required" {
                let missing = v["missing"].as_array().context("missing list")?.iter().filter_map(|m| m.as_str().map(str::to_owned)).collect();
                return Ok(Publish::MissingNars(missing));
            }
            bail!("publish conflict: {}", v["error"]);
        }
        if !resp.status().is_success() {
            bail!("{}", error_text(resp).await);
        }
        let v: Value = resp.json().await?;
        Ok(Publish::Done { published: v["published"].as_u64().unwrap_or(0) })
    }

    pub async fn admin_get(&self, path: &str) -> anyhow::Result<Value> {
        self.json(self.http.get(self.url(path))).await
    }

    pub async fn admin_post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.json(self.http.post(self.url(path)).json(&body)).await
    }
}
