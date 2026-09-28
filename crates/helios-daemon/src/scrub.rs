//! Integrity scrub: re-reads every blob, decompresses and re-hashes it, and
//! compares the file hash, NAR hash and NAR size with the database. A blob
//! that is missing or corrupt is quarantined, which unpublishes its paths
//! so clients never download bad data. Reads are rate limited.

use std::io::Read;
use std::time::{Duration, Instant};

use helios_core::{Compression, Verifier};
use serde::Deserialize;
use serde_json::json;

use crate::log;
use crate::state::{Daemon, add, now, set};

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Blob {
    id: i64,
    file_hash: String,
    compression: String,
    file_size: u64,
    nar_hash: String,
    nar_size: u64,
    path: Option<String>,
}

#[derive(Deserialize)]
struct Page {
    blobs: Vec<Blob>,
}

enum Verdict {
    Ok,
    Missing,
    Corrupt(String),
}

fn check(data_dir: &std::path::Path, b: &Blob) -> anyhow::Result<Verdict> {
    let (Some(rel), Some(compression)) = (&b.path, Compression::parse(&b.compression)) else {
        return Ok(Verdict::Corrupt(format!("unsupported compression {}", b.compression)));
    };
    let mut file = match std::fs::File::open(data_dir.join(rel)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Verdict::Missing),
        Err(e) => return Err(e.into()),
    };
    let mut v = Verifier::new(compression)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if let Err(e) = v.update(&buf[..n]) {
            return Ok(Verdict::Corrupt(format!("undecodable: {e}")));
        }
    }
    let d = match v.finish() {
        Ok(d) => d,
        Err(e) => return Ok(Verdict::Corrupt(format!("undecodable: {e}"))),
    };
    let problems: Vec<&str> = [
        (d.file_size != b.file_size, "file size"),
        (helios_core::nix32_encode(&d.file_hash) != b.file_hash, "file hash"),
        (helios_core::nix32_encode(&d.nar_hash) != b.nar_hash, "NAR hash"),
        (d.nar_size != b.nar_size, "NAR size"),
    ]
    .into_iter()
    .filter_map(|(bad, what)| bad.then_some(what))
    .collect();
    Ok(if problems.is_empty() { Verdict::Ok } else { Verdict::Corrupt(format!("{} mismatch", problems.join(", "))) })
}

/// One full pass over every blob. `rate` is bytes per second (0 = unlimited).
pub async fn run(d: &Daemon, rate: u64) -> anyhow::Result<()> {
    let started = Instant::now();
    let (mut after, mut bytes, mut blobs) = (0i64, 0u64, 0u64);
    loop {
        let page: Page = d.client.get(&format!("/v1/blobs?after={after}&limit=500")).await?;
        let Some(last) = page.blobs.last() else { break };
        after = last.id;
        for b in page.blobs {
            let dir = d.data_dir.clone();
            let blob = b.clone();
            let verdict = tokio::task::spawn_blocking(move || check(&dir, &blob)).await??;
            blobs += 1;
            bytes += b.file_size;
            add(&d.metrics.scrub_bytes, b.file_size);
            let reason = match verdict {
                Verdict::Ok => {
                    add(&d.metrics.scrub_ok, 1);
                    None
                }
                Verdict::Missing => {
                    add(&d.metrics.scrub_missing, 1);
                    Some("file missing".to_owned())
                }
                Verdict::Corrupt(why) => {
                    add(&d.metrics.scrub_corrupt, 1);
                    Some(why)
                }
            };
            if let Some(reason) = reason {
                log::error!("scrub: blob {} is bad ({reason}); quarantining", b.file_hash);
                // A blob GC removed since it was listed is already gone.
                if let Err(e) = d.client.post::<serde_json::Value>("/v1/quarantine", json!({ "fileHash": b.file_hash, "reason": reason })).await
                    && !e.to_string().contains("404")
                {
                    return Err(e);
                }
            }
            if rate > 0 {
                let due = Duration::from_secs_f64(bytes as f64 / rate as f64);
                if let Some(wait) = due.checked_sub(started.elapsed()) {
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
    set(&d.metrics.scrub_last_complete, now());
    log::info!("scrub: checked {blobs} blobs ({bytes} bytes) in {:.0?}", started.elapsed());
    Ok(())
}
