//! A small HTTP/1.1 client for one Helios server: hyper over TCP, rustls
//! (ring) for https, system CA roots, and a keep-alive connection pool.
//! It replaces reqwest, which pulled in URL/IDNA handling, proxy support
//! and aws-lc-rs that a CLI talking to one configured server never needs.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use anyhow::{Context as _, bail};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, header};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1::SendRequest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub type Body = UnsyncBoxBody<Bytes, io::Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed_unsync()
}

pub fn stream<S>(s: S) -> Body
where
    S: futures_util::Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    use futures_util::StreamExt;
    StreamBody::new(s.map(|r| r.map(Frame::data))).boxed_unsync()
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
    /// Path prefix without a trailing slash, e.g. "" or "/helios".
    prefix: String,
}

fn parse_base(url: &str) -> anyhow::Result<Target> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("server URL must start with http:// or https://: {url}");
    };
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').context("unterminated IPv6 address")?;
        (h.to_owned(), after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (authority.to_owned(), None),
        }
    };
    if host.is_empty() {
        bail!("server URL has no host: {url}");
    }
    let port = match port {
        Some(p) => p.parse().with_context(|| format!("invalid port in {url}"))?,
        None if tls => 443,
        None => 80,
    };
    let prefix = format!("/{}", path.trim_matches('/'));
    Ok(Target { tls, host, port, prefix: if prefix == "/" { String::new() } else { prefix } })
}

fn tls_config() -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        bail!("no CA certificates found (set SSL_CERT_FILE or NIX_SSL_CERT_FILE)");
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// hyper's I/O traits over a tokio stream.
struct Io<T>(T);

impl<T: AsyncRead + Unpin> hyper::rt::Read for Io<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> Poll<io::Result<()>> {
        // SAFETY: tokio's ReadBuf only writes initialised bytes into the
        // uninitialised tail, and we advance by exactly what was filled.
        let filled = unsafe {
            let mut rb = ReadBuf::uninit(buf.as_mut());
            match Pin::new(&mut self.0).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                other => return other,
            }
        };
        unsafe { buf.advance(filled) };
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for Io<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub struct Client {
    target: Target,
    host_header: HeaderValue,
    tls: Option<Arc<rustls::ClientConfig>>,
    idle: Mutex<Vec<SendRequest<Body>>>,
}

impl Client {
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let target = parse_base(base)?;
        let default_port = if target.tls { 443 } else { 80 };
        let host = if target.host.contains(':') { format!("[{}]", target.host) } else { target.host.clone() };
        let host_header = if target.port == default_port { host } else { format!("{host}:{}", target.port) };
        let tls = if target.tls { Some(tls_config()?) } else { None };
        Ok(Self { host_header: HeaderValue::from_str(&host_header)?, target, tls, idle: Mutex::new(Vec::new()) })
    }

    pub fn path(&self, p: &str) -> String {
        format!("{}{p}", self.target.prefix)
    }

    async fn connect(&self) -> anyhow::Result<SendRequest<Body>> {
        let tcp = TcpStream::connect((self.target.host.as_str(), self.target.port))
            .await
            .with_context(|| format!("connecting to {}:{}", self.target.host, self.target.port))?;
        tcp.set_nodelay(true)?;
        let sender = match &self.tls {
            None => {
                let (sender, conn) = hyper::client::conn::http1::handshake(Io(tcp)).await?;
                tokio::spawn(conn);
                sender
            }
            Some(config) => {
                let name = match self.target.host.parse::<IpAddr>() {
                    Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
                    Err(_) => rustls::pki_types::ServerName::try_from(self.target.host.clone())?,
                };
                let tls = tokio_rustls::TlsConnector::from(config.clone()).connect(name, tcp).await?;
                let (sender, conn) = hyper::client::conn::http1::handshake(Io(tls)).await?;
                tokio::spawn(conn);
                sender
            }
        };
        Ok(sender)
    }

    fn checkout(&self) -> Option<SendRequest<Body>> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(s) = idle.pop() {
            if !s.is_closed() {
                return Some(s);
            }
        }
        None
    }

    /// Sends a request and reads the whole response body.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        token: &str,
        content_type: Option<&str>,
        body: Body,
    ) -> anyhow::Result<(http::StatusCode, Bytes)> {
        let mut req = Request::builder()
            .method(method)
            .uri(self.path(path))
            .header(header::HOST, self.host_header.clone())
            .header(header::USER_AGENT, concat!("helios-cli/", env!("CARGO_PKG_VERSION")))
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        let req = req.body(body)?;
        let mut sender = match self.checkout() {
            Some(s) => s,
            None => self.connect().await?,
        };
        sender.ready().await?;
        let resp: Response<Incoming> = sender.send_request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !sender.is_closed() {
            self.idle.lock().unwrap_or_else(PoisonError::into_inner).push(sender);
        }
        Ok((status, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_base;

    #[test]
    fn parses_base_urls() {
        let t = parse_base("https://cache.example.com").unwrap();
        assert!(t.tls && t.host == "cache.example.com" && t.port == 443 && t.prefix.is_empty());
        let t = parse_base("http://127.0.0.1:8080/helios/").unwrap();
        assert!(!t.tls && t.host == "127.0.0.1" && t.port == 8080 && t.prefix == "/helios");
        let t = parse_base("https://[::1]:9443").unwrap();
        assert!(t.host == "::1" && t.port == 9443);
        assert!(parse_base("ftp://x").is_err());
        assert!(parse_base("https://:80").is_err());
    }
}
