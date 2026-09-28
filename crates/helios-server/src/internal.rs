//! Maintenance API for helios-daemon, served only on a Unix socket
//! (`--admin-socket`) whose file permissions are the access control.
//!
//! The server stays the only process that changes the database, so its
//! in-memory index and narinfo cache always agree with it; the daemon
//! decides what to do and asks.

use std::path::PathBuf;

use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::routing::{get, post};
use axum::{Json, Router};
use helios_core::Compression;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::{Locked, PathKey, Shared};

pub fn router(st: Shared) -> Router {
    Router::new()
        .route("/v1/stats", get(stats))
        .route("/v1/lru", get(lru))
        .route("/v1/evict", post(evict))
        .route("/v1/blobs", get(blobs))
        .route("/v1/quarantine", post(quarantine))
        .route("/v1/gc", post(gc))
        .route("/v1/db/checkpoint", post(checkpoint))
        .route("/v1/db/optimize", post(optimize))
        .route("/v1/db/backup", post(backup))
        .with_state(st)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> ApiResult<T> + Send + 'static) -> ApiResult<T> {
    tokio::task::spawn_blocking(f).await?
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// A numeric query parameter (the public API has no query strings to speak of).
fn param<T: std::str::FromStr>(uri: &Uri, name: &str) -> Option<T> {
    uri.query()?.split('&').find_map(|kv| kv.strip_prefix(name)?.strip_prefix('=')?.parse().ok())
}

async fn stats(State(st): State<Shared>) -> ApiResult<Json<Value>> {
    let db_st = st.clone();
    let (caches, blob_count, blob_bytes, unreferenced) = blocking(move || {
        db_st
            .db
            .read(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT c.name, c.is_public, count(p.id) FROM caches c LEFT JOIN paths p ON p.cache_id = c.id GROUP BY c.id ORDER BY c.name",
                )?;
                let caches: Vec<Value> = stmt
                    .query_map([], |r| Ok(json!({ "name": r.get::<_, String>(0)?, "public": r.get::<_, bool>(1)?, "paths": r.get::<_, u64>(2)? })))?
                    .collect::<rusqlite::Result<_>>()?;
                let (count, bytes): (u64, u64) =
                    conn.query_row("SELECT count(*), coalesce(sum(file_size), 0) FROM blobs", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
                // Blobs no path uses: GC deletes them once their upload grace ends.
                let unreferenced: u64 = conn.query_row(
                    "SELECT coalesce(sum(file_size), 0) FROM blobs b WHERE NOT EXISTS (SELECT 1 FROM paths p WHERE p.blob_id = b.id)",
                    [],
                    |r| r.get(0),
                )?;
                Ok((caches, count, bytes, unreferenced))
            })
            .map_err(internal)
    })
    .await?;
    let c = &st.counters;
    Ok(Json(json!({
        "caches": caches,
        "blobs": { "count": blob_count, "bytes": blob_bytes, "unreferencedBytes": unreferenced },
        "indexedPaths": st.index.rd().len(),
        "narinfoCacheEntries": st.narinfo.len(),
        "requests": {
            "narinfoHits": c.narinfo_hits.get(),
            "narinfoMisses": c.narinfo_misses.get(),
            "nars": c.nar_requests.get(),
            "uploads": c.uploads.get(),
            "uploadBytes": c.upload_bytes.get(),
            "publishedPaths": c.published_paths.get(),
        },
    })))
}

/// Least recently accessed paths first, with the size of their NAR.
async fn lru(State(st): State<Shared>, uri: Uri) -> ApiResult<Json<Value>> {
    let limit = param(&uri, "limit").unwrap_or(500).clamp(1, 10_000);
    let paths = blocking(move || {
        // Pending hits must count before anything is chosen for eviction.
        crate::gc::flush_access(&st).map_err(internal)?;
        st.db
            .read(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT p.cache_id, p.hash, p.store_path, p.accessed_at, b.file_size
                     FROM paths p JOIN blobs b ON b.id = p.blob_id ORDER BY p.accessed_at, p.id LIMIT ?1",
                )?;
                stmt.query_map([limit], |r| {
                    let hash: Vec<u8> = r.get(1)?;
                    Ok(json!({
                        "cache": r.get::<_, u32>(0)?,
                        "hash": helios_core::nix32_encode(&hash),
                        "storePath": r.get::<_, String>(2)?,
                        "accessedAt": r.get::<_, i64>(3)?,
                        "narBytes": r.get::<_, u64>(4)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(internal)
    })
    .await?;
    Ok(Json(json!({ "paths": paths })))
}

#[derive(Deserialize)]
struct EvictPath {
    cache: u32,
    hash: String,
}

#[derive(Deserialize)]
struct EvictReq {
    paths: Vec<EvictPath>,
}

fn forget(st: &Shared, keys: &[PathKey]) {
    let mut index = st.index.wr();
    for k in keys {
        index.remove(k);
        st.narinfo.remove(k);
    }
}

/// Deletes paths, then any blobs that no longer back a path.
async fn evict(State(st): State<Shared>, Json(req): Json<EvictReq>) -> ApiResult<Json<Value>> {
    let keys: Vec<PathKey> = req
        .paths
        .iter()
        .map(|p| helios_core::nix32_decode::<20>(&p.hash).map(|hash| PathKey { cache: p.cache, hash }))
        .collect::<Option<_>>()
        .ok_or_else(|| ApiError::bad_request("invalid path hash"))?;
    blocking(move || {
        let evicted = st.db.write(|conn| -> rusqlite::Result<usize> {
            let tx = conn.transaction()?;
            let mut n = 0;
            {
                let mut del = tx.prepare_cached("DELETE FROM paths WHERE cache_id = ?1 AND hash = ?2")?;
                for k in &keys {
                    n += del.execute(params![k.cache, &k.hash[..]])?;
                }
            }
            tx.commit()?;
            Ok(n)
        });
        let evicted = evicted.map_err(internal)?;
        // Stop serving before the files go.
        forget(&st, &keys);
        let (blobs, bytes) = crate::gc::collect_blobs(&st).map_err(internal)?;
        tracing::info!(paths = evicted, blobs, bytes, "evicted");
        Ok(Json(json!({ "evicted": evicted, "freedBlobs": blobs, "freedBytes": bytes })))
    })
    .await
}

/// Blobs in id order, for the integrity scrub.
async fn blobs(State(st): State<Shared>, uri: Uri) -> ApiResult<Json<Value>> {
    let after: i64 = param(&uri, "after").unwrap_or(0);
    let limit = param(&uri, "limit").unwrap_or(1000).clamp(1, 10_000);
    let data_dir = st.cfg.data_dir.clone();
    let blobs = blocking(move || {
        st.db
            .read(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, file_hash, compression, file_size, nar_hash, nar_size FROM blobs WHERE id > ?1 ORDER BY id LIMIT ?2",
                )?;
                stmt.query_map(params![after, limit], |r| {
                    let file_hash: Vec<u8> = r.get(1)?;
                    let nar_hash: Vec<u8> = r.get(4)?;
                    let compression: String = r.get(2)?;
                    let path = <[u8; 32]>::try_from(file_hash.as_slice())
                        .ok()
                        .zip(Compression::parse(&compression))
                        .map(|(h, c)| st.nar_path(&h, c).strip_prefix(&data_dir).map(PathBuf::from).unwrap_or_default());
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?,
                        "fileHash": helios_core::nix32_encode(&file_hash),
                        "compression": compression,
                        "fileSize": r.get::<_, u64>(3)?,
                        "narHash": helios_core::nix32_encode(&nar_hash),
                        "narSize": r.get::<_, u64>(5)?,
                        "path": path,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(internal)
    })
    .await?;
    Ok(Json(json!({ "blobs": blobs })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuarantineReq {
    file_hash: String,
    reason: String,
}

/// Takes a corrupt or missing blob out of service: every path it backs is
/// unpublished, and its file is moved aside for inspection.
async fn quarantine(State(st): State<Shared>, Json(req): Json<QuarantineReq>) -> ApiResult<Json<Value>> {
    let file_hash = helios_core::nix32_decode::<32>(&req.file_hash).ok_or_else(|| ApiError::bad_request("invalid file hash"))?;
    blocking(move || {
        let found = st.db.write(|conn| -> rusqlite::Result<Option<(Vec<PathKey>, String)>> {
            let tx = conn.transaction()?;
            let Some((id, compression)) = tx
                .query_row("SELECT id, compression FROM blobs WHERE file_hash = ?1", [&file_hash[..]], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })
                .optional()?
            else {
                return Ok(None);
            };
            let keys: Vec<PathKey> = {
                let mut stmt = tx.prepare_cached("SELECT cache_id, hash FROM paths WHERE blob_id = ?1")?;
                stmt.query_map([id], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)))?
                    .filter_map(|row| row.ok().and_then(|(cache, h)| <[u8; 20]>::try_from(h.as_slice()).ok().map(|hash| PathKey { cache, hash })))
                    .collect()
            };
            tx.execute("DELETE FROM paths WHERE blob_id = ?1", [id])?;
            tx.execute("DELETE FROM blobs WHERE id = ?1", [id])?;
            tx.commit()?;
            Ok(Some((keys, compression)))
        });
        let Some((keys, compression)) = found.map_err(internal)? else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "blob not found"));
        };
        forget(&st, &keys);
        if let Some(compression) = Compression::parse(&compression) {
            let src = st.nar_path(&file_hash, compression);
            let dir = st.cfg.data_dir.join("quarantine");
            let moved = std::fs::create_dir_all(&dir).and_then(|()| std::fs::rename(&src, dir.join(src.file_name().unwrap_or_default())));
            if let Err(e) = moved
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(error = %e, "moving quarantined blob");
            }
        }
        tracing::warn!(blob = %req.file_hash, reason = %req.reason, unpublished = keys.len(), "quarantined blob");
        Ok(Json(json!({ "pathsRemoved": keys.len() })))
    })
    .await
}

async fn gc(State(st): State<Shared>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let stats = crate::gc::collect(&st).map_err(internal)?;
        Ok(Json(serde_json::to_value(stats).map_err(internal)?))
    })
    .await
}

async fn checkpoint(State(st): State<Shared>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let (busy, log, done) = st
            .db
            .write(|conn| {
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))
            })
            .map_err(internal)?;
        Ok(Json(json!({ "busy": busy != 0, "walPages": log, "checkpointedPages": done })))
    })
    .await
}

async fn optimize(State(st): State<Shared>) -> ApiResult<Json<Value>> {
    blocking(move || {
        st.db.write(|conn| conn.execute_batch("PRAGMA optimize;")).map_err(internal)?;
        Ok(Json(json!({ "optimized": true })))
    })
    .await
}

#[derive(Deserialize)]
struct BackupReq {
    /// Backups to retain, newest first.
    keep: usize,
}

/// A consistent online copy of the database under `<data>/backups`, via
/// VACUUM INTO on a read connection so writers are not blocked.
async fn backup(State(st): State<Shared>, Json(req): Json<BackupReq>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let dir = st.cfg.data_dir.join("backups");
        std::fs::create_dir_all(&dir).map_err(internal)?;
        let dest = dir.join(format!("helios-{}.db", crate::db::now()));
        let dest_str = dest.to_str().ok_or_else(|| internal("backup path is not UTF-8"))?.to_owned();
        st.db.read(|conn| conn.execute("VACUUM INTO ?1", [&dest_str])).map_err(internal)?;
        let bytes = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);

        let mut existing: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(internal)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("helios-") && n.ends_with(".db")))
            .collect();
        existing.sort();
        let mut removed = 0;
        while existing.len() > req.keep.max(1) {
            if std::fs::remove_file(existing.remove(0)).is_ok() {
                removed += 1;
            }
        }
        Ok(Json(json!({ "path": dest, "bytes": bytes, "removed": removed })))
    })
    .await
}
