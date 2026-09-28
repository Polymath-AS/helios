//! Prometheus text exposition on `--metrics-listen`: the server's counters
//! (fetched per scrape over the admin socket), the daemon's own, and disk
//! space of the data filesystem.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::{Response, StatusCode, header};
use http_body_util::Full;
use hyper::service::service_fn;
use serde_json::Value;

use crate::io::Io;
use crate::log;
use crate::state::Daemon;

fn line(out: &mut String, name: &str, kind: &str, help: &str, samples: &[(&str, u64)]) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    for (labels, v) in samples {
        let _ = writeln!(out, "{name}{labels} {v}");
    }
}

fn get(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

pub async fn render(d: &Daemon) -> String {
    let mut out = String::new();
    let server: Option<Value> = d.client.get("/v1/stats").await.ok();
    line(&mut out, "helios_up", "gauge", "Whether helios-server answered on the admin socket.", &[("", u64::from(server.is_some()))]);
    if let Some(s) = &server {
        let n = |v: &Value| v.as_u64().unwrap_or(0);
        let caches: Vec<(String, u64)> = s["caches"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| (format!("{{cache=\"{}\"}}", c["name"].as_str().unwrap_or("")), n(&c["paths"])))
            .collect();
        let caches: Vec<(&str, u64)> = caches.iter().map(|(l, v)| (l.as_str(), *v)).collect();
        line(&mut out, "helios_cache_paths", "gauge", "Published paths per cache.", &caches);
        line(&mut out, "helios_blobs", "gauge", "Stored NAR files.", &[("", n(&s["blobs"]["count"]))]);
        line(&mut out, "helios_blob_bytes", "gauge", "Bytes of stored NAR files.", &[("", n(&s["blobs"]["bytes"]))]);
        let r = &s["requests"];
        line(
            &mut out,
            "helios_narinfo_requests_total",
            "counter",
            "Narinfo lookups since the server started.",
            &[("{result=\"hit\"}", n(&r["narinfoHits"])), ("{result=\"miss\"}", n(&r["narinfoMisses"]))],
        );
        line(&mut out, "helios_nar_requests_total", "counter", "NAR download requests.", &[("", n(&r["nars"]))]);
        line(&mut out, "helios_uploads_total", "counter", "Verified NAR uploads.", &[("", n(&r["uploads"]))]);
        line(&mut out, "helios_upload_bytes_total", "counter", "Bytes of verified NAR uploads.", &[("", n(&r["uploadBytes"]))]);
        line(&mut out, "helios_published_paths_total", "counter", "Paths published.", &[("", n(&r["publishedPaths"]))]);
    }
    if let Ok((free, total)) = crate::state::disk_space(&d.data_dir) {
        line(&mut out, "helios_disk_free_bytes", "gauge", "Free bytes on the data filesystem.", &[("", free)]);
        line(&mut out, "helios_disk_size_bytes", "gauge", "Size of the data filesystem.", &[("", total)]);
    }
    let m = &d.metrics;
    line(&mut out, "helios_gc_runs_total", "counter", "Auto-GC checks.", &[("", get(&m.gc_runs))]);
    line(&mut out, "helios_gc_evicted_paths_total", "counter", "Paths evicted by auto-GC.", &[("", get(&m.gc_evicted_paths))]);
    line(&mut out, "helios_gc_freed_bytes_total", "counter", "NAR bytes freed by auto-GC.", &[("", get(&m.gc_freed_bytes))]);
    line(&mut out, "helios_gc_last_run_timestamp_seconds", "gauge", "Last auto-GC check.", &[("", get(&m.gc_last_run))]);
    line(
        &mut out,
        "helios_scrub_blobs_total",
        "counter",
        "Blobs checked by the integrity scrub.",
        &[("{result=\"ok\"}", get(&m.scrub_ok)), ("{result=\"corrupt\"}", get(&m.scrub_corrupt)), ("{result=\"missing\"}", get(&m.scrub_missing))],
    );
    line(&mut out, "helios_scrub_bytes_total", "counter", "Bytes read by the integrity scrub.", &[("", get(&m.scrub_bytes))]);
    line(&mut out, "helios_scrub_last_complete_timestamp_seconds", "gauge", "End of the last full scrub pass.", &[("", get(&m.scrub_last_complete))]);
    line(&mut out, "helios_db_checkpoints_total", "counter", "WAL checkpoints.", &[("", get(&m.db_checkpoints))]);
    line(&mut out, "helios_db_backups_total", "counter", "Database backups.", &[("", get(&m.db_backups))]);
    line(&mut out, "helios_db_last_backup_timestamp_seconds", "gauge", "Last database backup.", &[("", get(&m.db_last_backup))]);
    line(
        &mut out,
        "helios_maintenance_errors_total",
        "counter",
        "Failed maintenance runs.",
        &[("{task=\"gc\"}", get(&m.errors_gc)), ("{task=\"scrub\"}", get(&m.errors_scrub)), ("{task=\"db\"}", get(&m.errors_db))],
    );
    out
}

pub async fn serve(d: Arc<Daemon>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("metrics on http://{addr}/metrics");
    loop {
        let (stream, _) = listener.accept().await?;
        let d = d.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                let d = d.clone();
                async move {
                    if req.uri().path() == "/metrics" {
                        Response::builder().header(header::CONTENT_TYPE, "text/plain; version=0.0.4").body(Full::new(Bytes::from(render(&d).await)))
                    } else {
                        Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::from_static(b"not found\n")))
                    }
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(Io(stream), svc).await;
        });
    }
}
