//! `helios push`: NARs are serialised, compressed and hashed by libhelios
//! and streamed straight into the upload request, with no temp files and no
//! `nix store dump-path | zstd` subprocesses.

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, bail};
use base64::Engine;
use bytes::Bytes;
use futures_util::StreamExt;
use helios_core::{DumpOptions, HL_E_UNSUPPORTED_OS};
use tokio::sync::mpsc;

use crate::api::{Client, PathSpec, Publish};
use crate::nix::{self, PathInfo};

const QUERY_BATCH: usize = 50_000;
const PUBLISH_BATCH: usize = 1_000;

#[derive(Clone, Copy)]
pub struct Options {
    pub jobs: usize,
    pub level: i32,
    pub closure: bool,
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
    // Non-Linux: let Nix serialise, libhelios compresses and hashes.
    use std::io::Read;
    let mut child = std::process::Command::new("nix-store")
        .args(["--dump", path])
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

async fn upload_one(client: &Client, cache: &str, info: &PathInfo, opts: DumpOptions) -> anyhow::Result<u64> {
    let (tx, rx) = mpsc::channel(8);
    let path = info.path.clone();
    let producer = tokio::task::spawn_blocking(move || produce(&path, opts, tx));
    let chunks = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|c| (c, rx)) });
    let body = crate::transport::stream(chunks);
    let uploaded = client.upload(cache, body).await;
    let digest = producer.await?;
    // An upload failure aborts the producer; report the upload's error.
    let uploaded = uploaded?;
    let digest = digest?;

    let ours = format!("sha256:{}", helios_core::nix32_encode(&digest.nar_hash));
    if parse_sha256(&info.nar_hash) != Some(digest.nar_hash) {
        bail!("{}: NAR hash {ours} differs from the Nix database ({})", info.path, info.nar_hash);
    }
    if uploaded.nar_hash != ours || uploaded.file_hash != helios_core::nix32_encode(&digest.file_hash) || uploaded.nar_size != digest.nar_size {
        bail!("{}: server verified different content than was sent", info.path);
    }
    Ok(uploaded.file_size)
}

async fn upload_all(client: &Client, cache: &str, paths: &[&PathInfo], opts: &Options) -> anyhow::Result<u64> {
    let total = paths.len();
    let threads = (std::thread::available_parallelism().map_or(4, |n| n.get()) / opts.jobs.max(1)).max(1) as i32;
    let mut done = 0usize;
    let mut bytes = 0u64;
    let mut failures = Vec::new();
    let mut results = futures_util::stream::iter(paths.iter().map(|info| async move {
        let dump = DumpOptions { level: opts.level, threads, size_hint: info.nar_size };
        let started = Instant::now();
        (info, upload_one(client, cache, info, dump).await, started.elapsed())
    }))
    .buffer_unordered(opts.jobs.max(1));
    while let Some((info, result, took)) = results.next().await {
        done += 1;
        match result {
            Ok(size) => {
                bytes += size;
                eprintln!("[{done}/{total}] {} {} → {} ({:.2}s)", name(&info.path), human(info.nar_size), human(size), took.as_secs_f64());
            }
            Err(e) => {
                eprintln!("[{done}/{total}] {} FAILED: {e:#}", name(&info.path));
                failures.push(info.path.clone());
            }
        }
    }
    if !failures.is_empty() {
        bail!("{} of {total} uploads failed", failures.len());
    }
    Ok(bytes)
}

pub async fn push(client: &Client, cache: &str, installables: &[String], opts: Options) -> anyhow::Result<()> {
    let started = Instant::now();
    let infos = nix::path_infos(installables, opts.closure).await?;
    let total = infos.len();

    let mut missing: HashSet<String> = HashSet::new();
    let hashes: Vec<&str> = infos.iter().map(|i| i.hash.as_str()).collect();
    for chunk in hashes.chunks(QUERY_BATCH) {
        missing.extend(client.missing(cache, chunk).await?);
    }
    let todo: Vec<PathInfo> = infos.into_iter().filter(|i| missing.contains(&i.hash)).collect();
    if todo.is_empty() {
        eprintln!("all {total} paths already in '{cache}'");
        return Ok(());
    }

    // Paths whose NAR the server already holds (from any cache) skip the upload.
    let mut known: HashSet<String> = HashSet::new();
    let nar_hashes: Vec<&str> = todo.iter().map(|i| i.nar_hash.as_str()).collect();
    for chunk in nar_hashes.chunks(QUERY_BATCH) {
        known.extend(client.known(cache, chunk).await?);
    }
    let uploads: Vec<&PathInfo> = todo.iter().filter(|i| !known.contains(&i.nar_hash)).collect();
    eprintln!(
        "{total} paths, {} missing from '{cache}': uploading {}, reusing {} NARs",
        todo.len(),
        uploads.len(),
        todo.len() - uploads.len()
    );
    let mut uploaded_bytes = upload_all(client, cache, &uploads, &opts).await?;

    let ordered = nix::topo_order(todo);
    let mut published = 0u64;
    for batch in ordered.chunks(PUBLISH_BATCH) {
        let specs: Vec<PathSpec> = batch
            .iter()
            .map(|i| PathSpec {
                store_path: i.path.clone(),
                nar_hash: i.nar_hash.clone(),
                nar_size: i.nar_size,
                references: i.references.clone(),
                deriver: i.deriver.clone(),
            })
            .collect();
        let mut retried = false;
        loop {
            match client.publish(cache, &specs).await? {
                Publish::Done { published: n } => {
                    published += n;
                    break;
                }
                // A NAR vanished between the check and the publish (e.g. GC); upload and retry once.
                Publish::MissingNars(paths) if !retried => {
                    retried = true;
                    let wanted: HashSet<&str> = paths.iter().map(String::as_str).collect();
                    let redo: Vec<&PathInfo> = batch.iter().filter(|i| wanted.contains(i.path.as_str())).collect();
                    uploaded_bytes += upload_all(client, cache, &redo, &opts).await?;
                }
                Publish::MissingNars(paths) => bail!("server still lacks NARs for {} paths", paths.len()),
            }
        }
    }

    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "published {published} paths to '{cache}', uploaded {} in {secs:.2}s ({}/s)",
        human(uploaded_bytes),
        human((uploaded_bytes as f64 / secs.max(1e-3)) as u64)
    );
    Ok(())
}

