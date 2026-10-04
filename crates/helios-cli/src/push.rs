//! `helios push`: NARs are serialised and compressed by libhelios and
//! streamed straight into the upload request, with no temp files and no
//! `nix store dump-path | zstd` subprocesses. The server hashes what it
//! receives, so the client does not hash again.

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, bail};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use helios_core::{DumpOptions, HL_E_UNSUPPORTED_OS};
use tokio::sync::mpsc;

use crate::api::{Client, PathSpec, Publish, Uploaded};
use crate::nix::{self, PathInfo};

const QUERY_BATCH: usize = 50_000;
const PUBLISH_BATCH: usize = 1_000;

#[derive(Clone, Copy)]
pub struct Options {
    pub jobs: usize,
    pub level: i32,
    /// zstd window for long-distance matching (10-27), or 0 for the level's.
    pub window_log: i32,
    pub closure: bool,
    /// Bytes per chunked-upload request; 0 streams each NAR in one request.
    pub chunk_size: usize,
}

fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if let Some(b64) = s.strip_prefix("sha256-") {
        return base64::engine::general_purpose::STANDARD.decode(b64).ok()?.try_into().ok();
    }
    helios_core::nix32_decode::<32>(s.strip_prefix("sha256:")?)
}

fn name(path: &str) -> &str {
    path.strip_prefix("/nix/store/").and_then(|b| b.get(33..)).unwrap_or(path)
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[unit]) }
}

/// Produce the compressed NAR on a blocking thread, feeding `tx`.
fn produce(path: &str, opts: DumpOptions, tx: mpsc::Sender<Result<Bytes, std::io::Error>>) -> anyhow::Result<helios_core::Digest> {
    let send = |chunk: &[u8]| tx.blocking_send(Ok(Bytes::copy_from_slice(chunk))).is_ok();
    match helios_core::dump_nar(Path::new(path), &opts, send) {
        Err(e) if e.code == HL_E_UNSUPPORTED_OS => {}
        other => return other.with_context(|| format!("serialising {path}")),
    }
    // Non-Linux: let Nix serialise, libhelios compresses.
    use std::io::Read;
    let mut child = std::process::Command::new("nix-store")
        .args(["--dump", path])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("running nix-store --dump")?;
    let mut stdout = child.stdout.take().context("nix-store stdout")?;
    let mut compressor = helios_core::Compressor::new(&opts, send)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = stdout.read(&mut buf)?;
        if n == 0 {
            break;
        }
        compressor.update(&buf[..n])?;
    }
    if !child.wait()?.success() {
        bail!("nix-store --dump {path} failed");
    }
    Ok(compressor.finish()?)
}

/// Sends the compressed NAR arriving on `rx` in `chunk_size` pieces, or in
/// one request if it fits in one chunk.
async fn send_chunked(
    client: &Client,
    cache: &str,
    compression: &str,
    rx: &mut mpsc::Receiver<Result<Bytes, std::io::Error>>,
    chunk_size: usize,
) -> anyhow::Result<Uploaded> {
    let mut buf = BytesMut::new();
    let mut session: Option<String> = None;
    let mut offset = 0u64;
    let result = async {
        loop {
            let done = match rx.recv().await {
                Some(chunk) => {
                    buf.extend_from_slice(&chunk?);
                    false
                }
                None => true,
            };
            if done && session.is_none() && buf.len() <= chunk_size {
                return client.upload(cache, compression, crate::transport::full(buf.split().freeze())).await;
            }
            while buf.len() >= chunk_size || (done && !buf.is_empty()) {
                let chunk = buf.split_to(buf.len().min(chunk_size)).freeze();
                let id = match &session {
                    Some(id) => id.clone(),
                    None => session.insert(client.upload_create(cache, compression).await?).clone(),
                };
                offset = client.upload_append(cache, &id, offset, chunk).await?;
            }
            if done {
                let id = session.as_deref().context("chunked upload without a session")?;
                return client.upload_complete(cache, id).await;
            }
        }
    }
    .await;
    if let (Err(_), Some(id)) = (&result, &session) {
        client.upload_abort(cache, id).await;
    }
    result
}

async fn upload_one(client: &Client, cache: &str, info: &PathInfo, opts: DumpOptions, chunk_size: usize) -> anyhow::Result<u64> {
    let compression = if opts.level == 0 { "none" } else { "zstd" };
    let (tx, mut rx) = mpsc::channel(8);
    let path = info.path.clone();
    // Also reports whether the upload had already stopped reading, which
    // tells a cause (local serialisation failure) from an effect.
    let producer = tokio::task::spawn_blocking(move || {
        let digest = produce(&path, opts, tx.clone());
        (digest, tx.is_closed())
    });
    let uploaded = if chunk_size == 0 {
        let chunks = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|c| (c, rx)) });
        client.upload(cache, compression, crate::transport::stream(chunks)).await
    } else {
        let uploaded = send_chunked(client, cache, compression, &mut rx, chunk_size).await;
        drop(rx); // Stops the producer if the upload gave up early.
        uploaded
    };
    let (digest, upload_stopped) = producer.await?;
    // A failed upload aborts the producer, so then the upload's error is
    // the cause; a failed producer cuts the stream short, and the server's
    // complaint about it is only the effect.
    let (uploaded, digest) = match (uploaded, digest) {
        (Err(e), Err(_)) if upload_stopped => return Err(e),
        (_, Err(e)) => return Err(e),
        (uploaded, Ok(digest)) => (uploaded?, digest),
    };

    // The NAR is not hashed here: the server hashes what it received, and
    // that is checked against the Nix database, which still catches a
    // corrupt local store (the NAR is then never published).
    let verified = parse_sha256(&uploaded.nar_hash);
    if verified.is_none() || verified != parse_sha256(&info.nar_hash) {
        bail!("{}: NAR hash {} differs from the Nix database ({})", info.path, uploaded.nar_hash, info.nar_hash);
    }
    if uploaded.nar_size != digest.nar_size || uploaded.file_size != digest.file_size {
        bail!("{}: server verified different content than was sent", info.path);
    }
    Ok(uploaded.file_size)
}

/// Uploads `paths`, returning the bytes sent and the paths that failed.
async fn upload_all(client: &Client, cache: &str, paths: &[&PathInfo], opts: &Options) -> (u64, HashSet<String>) {
    let total = paths.len();
    let threads = (std::thread::available_parallelism().map_or(4, |n| n.get()) / opts.jobs.max(1)).max(1) as i32;
    let mut done = 0usize;
    let mut bytes = 0u64;
    let mut failures = HashSet::new();
    let mut results = futures_util::stream::iter(paths.iter().map(|info| async move {
        let dump = DumpOptions { level: opts.level, threads, nar_size: info.nar_size, window_log: opts.window_log, hash: false };
        let started = Instant::now();
        (info, upload_one(client, cache, info, dump, opts.chunk_size).await, started.elapsed())
    }))
    .buffer_unordered(opts.jobs.max(1));
    while let Some((info, result, took)) = results.next().await {
        done += 1;
        match result {
            Ok(size) => {
                bytes += size;
                tracing::info!("[{done}/{total}] {} {} → {} ({:.2}s)", name(&info.path), human(info.nar_size), human(size), took.as_secs_f64());
            }
            Err(e) => {
                tracing::error!("[{done}/{total}] {} failed: {e:#}", name(&info.path));
                failures.insert(info.path.clone());
            }
        }
    }
    (bytes, failures)
}

/// Drops from `batch` the paths in `bad` and those referring to one,
/// adding the latter to `bad`. `batch` comes dependencies first, so one
/// pass reaches every dependent, here and in later batches.
fn without_bad<'a>(batch: &'a [PathInfo], bad: &mut HashSet<String>) -> Vec<&'a PathInfo> {
    let mut kept = Vec::with_capacity(batch.len());
    for info in batch {
        if bad.contains(&info.path) || info.references.iter().any(|r| *r != info.path && bad.contains(r)) {
            bad.insert(info.path.clone());
        } else {
            kept.push(info);
        }
    }
    kept
}

pub async fn push(client: &Client, cache: &str, installables: &[String], opts: Options) -> anyhow::Result<()> {
    let infos = nix::path_infos(installables, opts.closure).await?;
    // Outputs of content-addressed derivations need build traces as well,
    // or Nix cannot tell which paths a CA derivation produced.
    let derivers: Vec<String> =
        infos.iter().filter(|i| i.ca.is_some()).filter_map(|i| i.deriver.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let mut paths: HashSet<String> = infos.iter().map(|i| i.path.clone()).collect();
    let total = paths.len();
    let unpublished = push_infos(client, cache, infos, opts).await?;
    paths.retain(|p| !unpublished.contains(p));
    if !derivers.is_empty() {
        push_build_traces(client, cache, &derivers, &paths).await?;
    }
    if !unpublished.is_empty() {
        bail!("{} of {total} paths not pushed: they, or paths they refer to, failed to upload", unpublished.len());
    }
    Ok(())
}

async fn push_build_traces(client: &Client, cache: &str, derivers: &[String], pushed: &HashSet<String>) -> anyhow::Result<()> {
    let entries = match nix::build_traces(derivers).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!("not pushing build traces: {e:#}");
            return Ok(());
        }
    };
    // Only outputs this push published; the server refuses the rest.
    let entries: Vec<serde_json::Value> = entries
        .into_iter()
        .filter(|e| {
            // `value.outPath` from Nix 2.35 on, `outPath` before.
            e["value"]["outPath"]
                .as_str()
                .or(e["outPath"].as_str())
                .is_some_and(|p| pushed.contains(&if p.starts_with('/') { p.to_owned() } else { format!("/nix/store/{p}") }))
        })
        .collect();
    let mut published = 0;
    for chunk in entries.chunks(PUBLISH_BATCH) {
        published += client.publish_build_traces(cache, chunk).await?["published"].as_u64().unwrap_or(0);
    }
    if !entries.is_empty() {
        tracing::info!("published {published} build traces to '{cache}' ({} already there)", entries.len() as u64 - published);
    }
    Ok(())
}

/// Uploads and publishes what is missing. A path that fails to upload is
/// left out with everything referring to it, and the rest is published;
/// returns the paths left out.
async fn push_infos(client: &Client, cache: &str, infos: Vec<PathInfo>, opts: Options) -> anyhow::Result<HashSet<String>> {
    let started = Instant::now();
    let total = infos.len();

    let mut missing: HashSet<String> = HashSet::new();
    let hashes: Vec<&str> = infos.iter().map(|i| i.hash.as_str()).collect();
    for chunk in hashes.chunks(QUERY_BATCH) {
        missing.extend(client.missing(cache, chunk).await?);
    }
    let todo: Vec<PathInfo> = infos.into_iter().filter(|i| missing.contains(&i.hash)).collect();
    if todo.is_empty() {
        tracing::info!("all {total} paths already in '{cache}'");
        return Ok(HashSet::new());
    }

    // Paths whose NAR the server already holds (from any cache) skip the upload.
    let mut known: HashSet<String> = HashSet::new();
    let nar_hashes: Vec<&str> = todo.iter().map(|i| i.nar_hash.as_str()).collect();
    for chunk in nar_hashes.chunks(QUERY_BATCH) {
        known.extend(client.known(cache, chunk).await?);
    }
    let uploads: Vec<&PathInfo> = todo.iter().filter(|i| !known.contains(&i.nar_hash)).collect();
    tracing::info!("{total} paths, {} missing from '{cache}': uploading {}, reusing {} NARs", todo.len(), uploads.len(), todo.len() - uploads.len());
    let (mut uploaded_bytes, mut bad) = upload_all(client, cache, &uploads, &opts).await;

    let ordered = nix::topo_order(todo);
    let mut published = 0u64;
    for batch in ordered.chunks(PUBLISH_BATCH) {
        let mut retried = false;
        loop {
            let kept = without_bad(batch, &mut bad);
            if kept.is_empty() {
                break;
            }
            let specs: Vec<PathSpec> = kept
                .iter()
                .map(|i| PathSpec {
                    store_path: i.path.clone(),
                    nar_hash: i.nar_hash.clone(),
                    nar_size: i.nar_size,
                    references: i.references.clone(),
                    deriver: i.deriver.clone(),
                })
                .collect();
            match client.publish(cache, &specs).await? {
                Publish::Done { published: n } => {
                    published += n;
                    break;
                }
                // A NAR vanished between the check and the publish (e.g. GC); upload and retry once.
                Publish::MissingNars(paths) if !retried => {
                    retried = true;
                    let wanted: HashSet<&str> = paths.iter().map(String::as_str).collect();
                    let redo: Vec<&PathInfo> = kept.into_iter().filter(|i| wanted.contains(i.path.as_str())).collect();
                    let (bytes, failed) = upload_all(client, cache, &redo, &opts).await;
                    uploaded_bytes += bytes;
                    bad.extend(failed);
                }
                Publish::MissingNars(paths) => {
                    let wanted: HashSet<String> = paths.into_iter().collect();
                    let lacking: Vec<String> = kept.iter().filter(|i| wanted.contains(&i.path)).map(|i| i.path.clone()).collect();
                    // Each round drops at least one path, so this ends.
                    if lacking.is_empty() {
                        bail!("server lacks NARs for {} paths not in this batch", wanted.len());
                    }
                    tracing::error!("server still lacks NARs for {} paths; leaving them out", lacking.len());
                    bad.extend(lacking);
                }
            }
        }
    }

    let secs = started.elapsed().as_secs_f64();
    tracing::info!(
        "published {published} paths to '{cache}', uploaded {} in {secs:.2}s ({}/s)",
        human(uploaded_bytes),
        human((uploaded_bytes as f64 / secs.max(1e-3)) as u64)
    );
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str, refs: &[&str]) -> PathInfo {
        PathInfo {
            path: name.to_owned(),
            hash: String::new(),
            nar_hash: String::new(),
            nar_size: 0,
            references: refs.iter().map(|r| (*r).to_owned()).collect(),
            deriver: None,
            ca: None,
        }
    }

    #[test]
    fn failed_paths_hold_back_their_dependents() {
        let first = [info("libc", &["libc"]), info("lib", &["libc"]), info("other", &[])];
        let second = [info("app", &["lib", "other"]), info("tool", &["other"])];
        let mut bad: HashSet<String> = ["lib".to_owned()].into();
        let names = |v: Vec<&PathInfo>| v.into_iter().map(|i| i.path.clone()).collect::<Vec<_>>();
        assert_eq!(names(without_bad(&first, &mut bad)), ["libc", "other"]);
        assert_eq!(names(without_bad(&second, &mut bad)), ["tool"]);
        assert!(bad.contains("app"));
    }
}
