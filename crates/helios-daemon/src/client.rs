//! Client for helios-server's maintenance API on its Unix socket. Requests
//! are rare (minutes apart), so each one gets a fresh connection.

use std::path::PathBuf;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::net::UnixStream;

use crate::io::Io;

#[derive(Clone)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    async fn call<T: DeserializeOwned>(&self, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<T> {
        let stream = UnixStream::connect(&self.socket).await.with_context(|| format!("connecting to {}", self.socket.display()))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(Io(stream)).await?;
        tokio::spawn(conn);
        let mut req = Request::builder().method(method).uri(path).header(header::HOST, "helios");
        let payload = match body {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Bytes::from(serde_json::to_vec(&v)?)
            }
            None => Bytes::new(),
        };
        let resp = sender.send_request(req.body(Full::new(payload))?).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            bail!("{path}: {status}: {}", String::from_utf8_lossy(&bytes));
        }
        serde_json::from_slice(&bytes).with_context(|| format!("decoding {path}"))
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        self.call(Method::GET, path, None).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        self.call(Method::POST, path, Some(body)).await
    }
}
