//! The push API.
//!
//! 1. `POST /_api/v2/caches/{cache}/missing` → which store paths are absent (memory only).
//! 2. `POST /_api/v2/caches/{cache}/nars/known` → which NAR hashes already have a blob.
//! 3. `PUT  /_api/v2/caches/{cache}/nar?compression=zstd` → stream a compressed NAR.
//!    The server hashes and decompresses it on the fly and records the verified
//!    NAR hash; clients cannot claim content they did not upload.
//! 4. `POST /_api/v2/caches/{cache}/paths` → publish a batch in one transaction.

use std::io::Write;
use std::rc::Rc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use base64::Engine;
use bytes::Bytes;
use futures_util::StreamExt;
use helios_core::{Compression, NarinfoInput, Verifier};
use rusqlite::types::Value;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::Locked;
use crate::audit::Audit;
use crate::auth::Perm;
use crate::error::{ApiError, ApiResult};
use crate::state::{CacheInfo, PathKey, Shared};

const MAX_MISSING_BATCH: usize = 100_000;
const MAX_PUBLISH_BATCH: usize = 5_000;
const STORE_DIR: &str = "/nix/store/";

fn cache_for(st: &Shared, name: &str) -> ApiResult<CacheInfo> {
    st.cache(name).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "cache not found"))
}

// ── Missing paths ──

#[derive(Deserialize)]
pub struct MissingReq {
    hashes: Vec<String>,
}

pub async fn missing(
    State(st): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(req): Json<MissingReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let cache = cache_for(&st, &name)?;
    st.authorize(&headers, &name, Perm::Push)?;
    if req.hashes.len() > MAX_MISSING_BATCH {
        return Err(ApiError::bad_request(format!("at most {MAX_MISSING_BATCH} hashes per request")));
    }
    let index = st.index.rd();
    let missing: Vec<&String> = req
        .hashes
        .iter()
        .filter(|h| match helios_core::nix32_decode::<20>(h) {
            Some(hash) => !index.contains(&PathKey { cache: cache.id, hash }),
            None => true,
        })
        .collect();
    Ok(Json(json!({ "missing": missing })))
}

// ── Known NARs ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownReq {
    nar_hashes: Vec<String>,
}

pub async fn known(
    State(st): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(req): Json<KnownReq>,
) -> ApiResult<Json<serde_json::Value>> {
    cache_for(&st, &name)?;
    st.authorize(&headers, &name, Perm::Push)?;
    if req.nar_hashes.len() > MAX_MISSING_BATCH {
        return Err(ApiError::bad_request(format!("at most {MAX_MISSING_BATCH} hashes per request")));
    }
    let parsed: Vec<Option<[u8; 32]>> = req.nar_hashes.iter().map(|h| parse_sha256(h)).collect();
    let db = st.db.clone();
    let values: Vec<Value> = parsed.iter().flatten().map(|h| Value::Blob(h.to_vec())).collect();
    let found = tokio::task::spawn_blocking(move || {
        db.read(|conn| {
            let mut stmt = conn.prepare_cached("SELECT DISTINCT nar_hash FROM blobs WHERE nar_hash IN rarray(?1)")?;
            let rows = stmt.query_map([Rc::new(values)], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<rusqlite::Result<std::collections::HashSet<Vec<u8>>>>()
        })
    })
    .await??;
    let known: Vec<&String> = req
        .nar_hashes
        .iter()
        .zip(&parsed)
        .filter(|(_, h)| h.is_some_and(|h| found.contains(&h[..])))
        .map(|(s, _)| s)
        .collect();
    Ok(Json(json!({ "known": known })))
}

// ── Upload ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResp {
    file_hash: String,
    file_size: u64,
    nar_hash: String,
    nar_size: u64,
}

pub async fn upload(
    State(st): State<Shared>,
    Path(name): Path<String>,
    uri: Uri,
    audit: Audit,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<UploadResp>)> {
    cache_for(&st, &name)?;
    let identity = st.authorize(&headers, &name, Perm::Push)?;
    let requested = uri.query().unwrap_or("").split('&').find_map(|kv| kv.strip_prefix("compression=")).unwrap_or("zstd");
    let compression = Compression::parse(requested)
        .ok_or_else(|| ApiError::bad_request("compression must be zstd or none"))?;

    let tmp = st.tmp_dir().join(helios_core::uuid_v4());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(32);
    let worker_tmp = tmp.clone();
    // Disk writes, hashing and decompression happen off the async runtime.
    let worker = tokio::task::spawn_blocking(move || -> Result<helios_core::Digest, String> {
        let file = std::fs::File::create_new(&worker_tmp).map_err(|e| e.to_string())?;
        let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
        let mut verifier = Verifier::new(compression).map_err(|e| e.to_string())?;
        while let Some(chunk) = rx.blocking_recv() {
            verifier.update(&chunk).map_err(|e| format!("invalid NAR stream: {e}"))?;
            out.write_all(&chunk).map_err(|e| e.to_string())?;
        }
        let file = out.into_inner().map_err(|e| e.to_string())?;
        file.sync_data().map_err(|e| e.to_string())?;
        verifier.finish().map_err(|e| format!("invalid NAR stream: {e}"))
    });

    let mut stream = body.into_data_stream();
    let mut received: u64 = 0;
    let mut failure: Option<ApiError> = None;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                failure = Some(ApiError::bad_request(format!("reading body: {e}")));
                break;
            }
        };
        received += chunk.len() as u64;
        if received > st.cfg.max_upload_bytes {
            failure = Some(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "upload too large"));
            break;
        }
        if tx.send(chunk).await.is_err() {
            break; // Worker failed; its error is reported below.
        }
    }
    drop(tx);
    let result = worker.await?;

    let digest = match (failure, result) {
        (Some(err), _) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            audit.log(&st, &identity, "nar.upload", Some(&name), err.status, json!({ "error": err.message }));
            return Err(err);
        }
        (None, Err(msg)) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            let err = ApiError::bad_request(msg);
            audit.log(&st, &identity, "nar.upload", Some(&name), err.status, json!({ "error": err.message }));
            return Err(err);
        }
        (None, Ok(d)) => d,
    };

    let dest = st.nar_path(&digest.file_hash, compression);
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || -> ApiResult<()> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(ApiError::internal)?;
        }
        // Rename and row upsert happen under the writer lock so GC can never
        // delete the file between them. Renaming over an existing blob is
        // harmless: the content is identical by hash.
        st2.db.write(|conn| -> ApiResult<()> {
            std::fs::rename(&tmp, &dest).map_err(ApiError::internal)?;
            conn.prepare_cached(
                "INSERT INTO blobs (file_hash, file_size, compression, nar_hash, nar_size, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (file_hash) DO UPDATE SET created_at = excluded.created_at",
            )?
            .execute(params![
                &digest.file_hash[..],
                digest.file_size,
                compression.as_str(),
                &digest.nar_hash[..],
                digest.nar_size,
                crate::db::now()
            ])?;
            Ok(())
        })?;
        Ok(())
    })
    .await??;

    let resp = UploadResp {
        file_hash: helios_core::nix32_encode(&digest.file_hash),
        file_size: digest.file_size,
        nar_hash: format!("sha256:{}", helios_core::nix32_encode(&digest.nar_hash)),
        nar_size: digest.nar_size,
    };
    st.counters.uploads.inc();
    st.counters.upload_bytes.add(resp.file_size);
    audit.log(&st, &identity, "nar.upload", Some(&name), StatusCode::CREATED, json!({ "fileHash": resp.file_hash, "size": resp.file_size }));
    Ok((StatusCode::CREATED, Json(resp)))
}

// ── Publish ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathSpec {
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    #[serde(default)]
    references: Vec<String>,
    deriver: Option<String>,
    system: Option<String>,
    /// Pin a specific uploaded blob (nix32 file hash); otherwise any blob
    /// with a matching verified NAR hash is used.
    file_hash: Option<String>,
}

#[derive(Deserialize)]
pub struct PublishReq {
    paths: Vec<PathSpec>,
}

/// Accepts `sha256:<nix32>`, `sha256:<hex>` and SRI `sha256-<base64>`.
pub fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if let Some(b64) = s.strip_prefix("sha256-") {
        return base64::engine::general_purpose::STANDARD.decode(b64).ok()?.try_into().ok();
    }
    let h = s.strip_prefix("sha256:").unwrap_or(s);
    match h.len() {
        52 => helios_core::nix32_decode::<32>(h),
        64 => {
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
            }
            Some(out)
        }
        _ => None,
    }
}

fn basename(s: &str) -> &str {
    s.strip_prefix(STORE_DIR).unwrap_or(s)
}

struct Prepared {
    key: PathKey,
    store_path: String,
    nar_hash: [u8; 32],
    nar_size: u64,
    file_hash: Option<[u8; 32]>,
    references: String,
    deriver: String,
    system: String,
}

struct Rendered {
    key: PathKey,
    store_path: String,
    blob_id: i64,
    narinfo: Vec<u8>,
}

fn prepare(cache: CacheInfo, spec: PathSpec) -> Result<Prepared, String> {
    let base = spec
        .store_path
        .strip_prefix(STORE_DIR)
        .filter(|b| helios_core::store_basename_valid(b))
        .ok_or_else(|| format!("invalid store path: {}", spec.store_path))?;
    let hash = helios_core::nix32_decode::<20>(&base[..32]).ok_or("invalid store path hash")?;
    let nar_hash = parse_sha256(&spec.nar_hash).ok_or_else(|| format!("{}: invalid narHash", spec.store_path))?;
    let file_hash = match &spec.file_hash {
        Some(h) => Some(parse_sha256(h).ok_or_else(|| format!("{}: invalid fileHash", spec.store_path))?),
        None => None,
    };
    let mut references = String::new();
    for r in &spec.references {
        let r = basename(r);
        if !helios_core::store_basename_valid(r) {
            return Err(format!("{}: invalid reference {r}", spec.store_path));
        }
        if !references.is_empty() {
            references.push(' ');
        }
        references.push_str(r);
    }
    Ok(Prepared {
        key: PathKey { cache: cache.id, hash },
        store_path: spec.store_path,
        nar_hash,
        nar_size: spec.nar_size,
        file_hash,
        references,
        deriver: spec.deriver.as_deref().map(basename).unwrap_or_default().to_owned(),
        system: spec.system.unwrap_or_default(),
    })
}

pub async fn publish(
    State(st): State<Shared>,
    Path(name): Path<String>,
    audit: Audit,
    headers: HeaderMap,
    Json(req): Json<PublishReq>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let cache = cache_for(&st, &name)?;
    let identity = st.authorize(&headers, &name, Perm::Push)?;
    if req.paths.len() > MAX_PUBLISH_BATCH {
        return Err(ApiError::bad_request(format!("at most {MAX_PUBLISH_BATCH} paths per request")));
    }

    let mut prepared = Vec::with_capacity(req.paths.len());
    let mut already = 0usize;
    {
        let index = st.index.rd();
        for spec in req.paths {
            let p = prepare(cache, spec).map_err(ApiError::bad_request)?;
            if index.contains(&p.key) {
                already += 1;
            } else {
                prepared.push(p);
            }
        }
    }

    let st2 = st.clone();
    let outcome = tokio::task::spawn_blocking(move || render_and_insert(&st2, prepared)).await??;
    let (rendered_keys, missing) = match outcome {
        Outcome::Published(keys) => (keys, Vec::new()),
        Outcome::MissingNars(missing) => (Vec::new(), missing),
    };
    if !missing.is_empty() {
        let err = ApiError::new(StatusCode::CONFLICT, "nar_required").with(json!({ "missing": missing }));
        audit.log(&st, &identity, "path.publish", Some(&name), err.status, json!({ "missingNars": missing.len() }));
        return Err(err);
    }

    let published = rendered_keys.len();
    st.counters.published_paths.add(published as u64);
    {
        let mut index = st.index.wr();
        for key in rendered_keys {
            index.insert(key);
        }
    }
    audit.log(&st, &identity, "path.publish", Some(&name), StatusCode::CREATED, json!({ "published": published, "alreadyExisted": already }));
    Ok((StatusCode::CREATED, Json(json!({ "published": published, "alreadyExisted": already }))))
}

enum Outcome {
    Published(Vec<PathKey>),
    MissingNars(Vec<String>),
}

struct Blob {
    id: i64,
    file_hash: [u8; 32],
    file_size: u64,
    compression: String,
    nar_size: u64,
}

fn render_and_insert(st: &Shared, prepared: Vec<Prepared>) -> ApiResult<Outcome> {
    // Resolve blobs on a read connection, outside the writer lock.
    let blobs: Vec<Option<Blob>> = st.db.read(|conn| {
        let mut by_nar = conn.prepare_cached(
            "SELECT id, file_hash, file_size, compression, nar_size FROM blobs
             WHERE nar_hash = ?1 ORDER BY compression = 'zstd' DESC, id LIMIT 1",
        )?;
        let mut by_file = conn.prepare_cached(
            "SELECT id, file_hash, file_size, compression, nar_size FROM blobs WHERE file_hash = ?1 AND nar_hash = ?2",
        )?;
        let row = |r: &rusqlite::Row<'_>| {
            Ok(Blob {
                id: r.get(0)?,
                file_hash: r.get::<_, Vec<u8>>(1)?.try_into().unwrap_or([0; 32]),
                file_size: r.get(2)?,
                compression: r.get(3)?,
                nar_size: r.get(4)?,
            })
        };
        prepared
            .iter()
            .map(|p| match &p.file_hash {
                Some(fh) => by_file.query_row(params![&fh[..], &p.nar_hash[..]], row).optional(),
                None => by_nar.query_row(params![&p.nar_hash[..]], row).optional(),
            })
            .collect()
    })?;

    let missing: Vec<String> = prepared.iter().zip(&blobs).filter(|(_, b)| b.is_none()).map(|(p, _)| p.store_path.clone()).collect();
    if !missing.is_empty() {
        return Ok(Outcome::MissingNars(missing));
    }

    // Render and sign in parallel; Ed25519 dominates the cost of a publish.
    let work: Vec<(Prepared, Blob)> = prepared.into_iter().zip(blobs.into_iter().map(Option::unwrap)).collect();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(work.len().div_ceil(64).max(1));
    let chunk = work.len().div_ceil(threads).max(1);
    let rendered: Vec<Result<Rendered, ApiError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = work
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().map(|(p, b)| render(st, p, b)).collect::<Vec<_>>()))
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("render thread panicked")).collect()
    });
    let rendered: Vec<Rendered> = rendered.into_iter().collect::<Result<_, _>>()?;

    let now = crate::db::now();
    let keys = st.db.write(|conn| {
        let tx = conn.transaction()?;
        let mut keys = Vec::with_capacity(rendered.len());
        {
            let mut blob_exists = tx.prepare_cached("SELECT 1 FROM blobs WHERE id = ?1")?;
            let mut insert = tx.prepare_cached(
                "INSERT INTO paths (cache_id, hash, blob_id, store_path, narinfo, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (cache_id, hash) DO NOTHING",
            )?;
            for r in &rendered {
                // Re-checked under the writer lock: GC may have collected the blob.
                if !blob_exists.exists([r.blob_id])? {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                if insert.execute(params![r.key.cache, &r.key.hash[..], r.blob_id, r.store_path, r.narinfo, now])? > 0 {
                    keys.push(r.key);
                }
            }
        }
        tx.commit()?;
        Ok(keys)
    });
    match keys {
        Ok(keys) => Ok(Outcome::Published(keys)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(ApiError::new(StatusCode::CONFLICT, "blob was garbage collected; retry")),
        Err(e) => Err(e.into()),
    }
}

fn render(st: &Shared, p: &Prepared, b: &Blob) -> ApiResult<Rendered> {
    if b.nar_size != p.nar_size {
        return Err(ApiError::bad_request(format!("{}: narSize {} does not match uploaded NAR ({})", p.store_path, p.nar_size, b.nar_size)));
    }
    let narinfo = helios_core::render_narinfo(
        &NarinfoInput {
            store_path: &p.store_path,
            nar_hash: &p.nar_hash,
            nar_size: b.nar_size,
            file_hash: &b.file_hash,
            file_size: b.file_size,
            compression: &b.compression,
            references: &p.references,
            deriver: &p.deriver,
            system: &p.system,
        },
        st.signer.as_ref(),
    )
    .map_err(|e| ApiError::bad_request(format!("{}: {e}", p.store_path)))?;
    Ok(Rendered { key: p.key, store_path: p.store_path.clone(), blob_id: b.id, narinfo })
}
