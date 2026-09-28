//! Audit logging off the request path: events go through a channel and are
//! inserted in batched transactions.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use rusqlite::params;
use tokio::sync::mpsc;

use crate::auth::Identity;
use crate::db::Db;
use crate::state::Shared;

pub struct AuditEvent {
    ts: i64,
    actor: String,
    action: &'static str,
    cache: Option<String>,
    detail: String,
    ip: Option<String>,
    status: u16,
}

/// Request extractor carrying the client IP for audit events.
pub struct Audit {
    ip: Option<IpAddr>,
}

impl FromRequestParts<Shared> for Audit {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, st: &Shared) -> Result<Self, Self::Rejection> {
        let forwarded =
            st.cfg.trust_proxy.then(|| parts.headers.get("x-forwarded-for")?.to_str().ok()?.split(',').next()?.trim().parse().ok()).flatten();
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
        Ok(Self { ip: forwarded.or(peer) })
    }
}

impl Audit {
    pub fn log(&self, st: &Shared, who: &Identity, action: &'static str, cache: Option<&str>, status: StatusCode, detail: serde_json::Value) {
        let _ = st.audit.send(AuditEvent {
            ts: crate::db::now(),
            actor: who.actor().to_owned(),
            action,
            cache: cache.map(str::to_owned),
            detail: detail.to_string(),
            ip: self.ip.map(|ip| ip.to_string()),
            status: status.as_u16(),
        });
    }
}

pub async fn run(db: Db, mut rx: mpsc::UnboundedReceiver<AuditEvent>) {
    let mut batch = Vec::with_capacity(256);
    loop {
        if rx.recv_many(&mut batch, 1024).await == 0 {
            return;
        }
        // Coalesce bursts into one transaction.
        tokio::time::sleep(Duration::from_millis(200)).await;
        while let Ok(ev) = rx.try_recv() {
            batch.push(ev);
        }
        let events = std::mem::take(&mut batch);
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            db.write(|conn| -> rusqlite::Result<()> {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx
                        .prepare_cached("INSERT INTO audit_log (ts, actor, action, cache, detail, ip, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")?;
                    for e in &events {
                        stmt.execute(params![e.ts, e.actor, e.action, e.cache, e.detail, e.ip, e.status])?;
                    }
                }
                tx.commit()
            })
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "writing audit log"),
            Err(e) => tracing::error!(error = %e, "audit writer panicked"),
        }
    }
}
