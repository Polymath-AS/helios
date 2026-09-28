//! Chunked uploads, for NARs larger than a proxy in front of the server
//! accepts in one request (Cloudflare's free plan stops at 100 MB, Cloud
//! Run at 32 MiB).
//!
//! 1. `POST   /_api/v2/caches/{cache}/uploads?compression=zstd` → `{id, offset: 0}`
//! 2. `PATCH  /_api/v2/caches/{cache}/uploads/{id}?offset=N` with the next
//!    chunk as the body → `{offset}`. A chunk is appended whole or not at
//!    all, so after a failed request the client asks for the offset and
//!    resends from there; a stale offset gets 409 with the current one.
//! 3. `GET    /_api/v2/caches/{cache}/uploads/{id}` → `{offset}`
//! 4. `POST   /_api/v2/caches/{cache}/uploads/{id}/complete` → as `PUT /nar`
//! 5. `DELETE /_api/v2/caches/{cache}/uploads/{id}` abandons the upload.
//!
//! Chunks are verified as they arrive, as in a single-request upload.
//! Sessions live in memory: after a server restart the client starts the
//! NAR again. An idle session is dropped after an hour, and GC removes its
//! file.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use bytes::Bytes;
use helios_core::{Compression, Verifier};
use serde_json::json;

use crate::audit::Audit;
use crate::auth::{Identity, Perm};
use crate::error::{ApiError, ApiResult};
use crate::push::{UploadResp, cache_for, store_blob};
use crate::state::Shared;

const MAX_SESSIONS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

pub struct Session {
    cache: Box<str>,
    actor: String,
    compression: Compression,
    tmp: PathBuf,
    file: std::fs::File,
    /// `None` once the stream is found invalid or the upload is finished.
    verifier: Option<Verifier>,
    offset: u64,
    touched: Instant,
}

pub type Sessions = Mutex<std::collections::HashMap<Box<str>, Arc<Mutex<Session>>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn query<'a>(uri: &'a Uri, key: &str) -> Option<&'a str> {
    uri.query()?.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "upload not found; it expired or the server restarted, so start the NAR again")
}

/// The session `id`, if it belongs to `cache` and to whoever is asking.
fn session(st: &Shared, cache: &str, id: &str, who: &Identity) -> ApiResult<Arc<Mutex<Session>>> {
    let s = lock(&st.uploads).get(id).cloned().ok_or_else(not_found)?;
    {
        let g = lock(&s);
        if &*g.cache != cache || g.actor != who.actor() {
            return Err(not_found());
        }
    }
    Ok(s)
}

fn drop_session(st: &Shared, id: &str) {
    if let Some(s) = lock(&st.uploads).remove(id) {
        let _ = std::fs::remove_file(&lock(&s).tmp);
    }
}

pub async fn create(
    State(st): State<Shared>,
    Path(name): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    cache_for(&st, &name)?;
    let who = st.authorize(&headers, &name, Perm::Push)?;
    let compression =
        Compression::parse(query(&uri, "compression").unwrap_or("zstd")).ok_or_else(|| ApiError::bad_request("compression must be zstd or none"))?;

    let id = helios_core::uuid_v4();
    let tmp = st.tmp_dir().join(format!("upload-{id}"));
    let file = std::fs::File::create_new(&tmp).map_err(ApiError::internal)?;
    let verifier = Verifier::new(compression).map_err(ApiError::internal)?;
    let new = Session {
        cache: name.into(),
        actor: who.actor().to_owned(),
        compression,
        tmp,
        file,
        verifier: Some(verifier),
        offset: 0,
        touched: Instant::now(),
    };

    let mut sessions = lock(&st.uploads);
    let expired: Vec<Box<str>> =
        sessions.iter().filter(|(_, s)| s.try_lock().is_ok_and(|g| g.touched.elapsed() > IDLE_TIMEOUT)).map(|(id, _)| id.clone()).collect();
    for old in expired {
        if let Some(s) = sessions.remove(&old) {
            let _ = std::fs::remove_file(&lock(&s).tmp);
        }
    }
    if sessions.len() >= MAX_SESSIONS {
        let _ = std::fs::remove_file(&new.tmp);
        return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "too many uploads in progress"));
    }
    sessions.insert(id.as_str().into(), Arc::new(Mutex::new(new)));
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "offset": 0 }))))
}

pub async fn append(
    State(st): State<Shared>,
    Path((name, id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let at: u64 = query(&uri, "offset").and_then(|o| o.parse().ok()).ok_or_else(|| ApiError::bad_request("offset is required"))?;
    let who = st.authorize(&headers, &name, Perm::Push)?;
    let s = session(&st, &name, &id, &who)?;
    let max = st.cfg.max_upload_bytes;
    let result = tokio::task::spawn_blocking(move || -> ApiResult<u64> {
        let mut g = lock(&s);
        let g = &mut *g;
        g.touched = Instant::now();
        if at != g.offset {
            return Err(ApiError::new(StatusCode::CONFLICT, "offset mismatch").with(json!({ "offset": g.offset })));
        }
        if g.offset + body.len() as u64 > max {
            return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "upload too large"));
        }
        let verifier = g.verifier.as_mut().ok_or_else(|| ApiError::bad_request("upload is no longer accepting data"))?;
        if let Err(e) = verifier.update(&body) {
            g.verifier = None;
            return Err(ApiError::bad_request(format!("invalid NAR stream: {e}")));
        }
        // A short write leaves the file ahead of the offset; later chunks
        // would then land in the wrong place, so give up on the upload.
        if let Err(e) = g.file.write_all(&body) {
            g.verifier = None;
            return Err(ApiError::internal(e));
        }
        g.offset += body.len() as u64;
        Ok(g.offset)
    })
    .await?;
    match result {
        Ok(offset) => Ok(Json(json!({ "offset": offset }))),
        Err(e) => {
            if e.status != StatusCode::CONFLICT {
                drop_session(&st, &id);
            }
            Err(e)
        }
    }
}

pub async fn status(State(st): State<Shared>, Path((name, id)): Path<(String, String)>, headers: HeaderMap) -> ApiResult<Json<serde_json::Value>> {
    let who = st.authorize(&headers, &name, Perm::Push)?;
    let s = session(&st, &name, &id, &who)?;
    let offset = lock(&s).offset;
    Ok(Json(json!({ "offset": offset })))
}

pub async fn complete(
    State(st): State<Shared>,
    Path((name, id)): Path<(String, String)>,
    audit: Audit,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<UploadResp>)> {
    let who = st.authorize(&headers, &name, Perm::Push)?;
    let s = session(&st, &name, &id, &who)?;
    // Taken out of the map first, so a concurrent chunk cannot extend it.
    lock(&st.uploads).remove(id.as_str());
    let (tmp, compression, digest) = tokio::task::spawn_blocking(move || {
        let mut g = lock(&s);
        let digest = match g.verifier.take() {
            Some(v) => v.finish().map_err(|e| ApiError::bad_request(format!("invalid NAR stream: {e}"))),
            None => Err(ApiError::bad_request("upload is no longer accepting data")),
        }
        .and_then(|d| g.file.sync_data().map(|()| d).map_err(ApiError::internal));
        (g.tmp.clone(), g.compression, digest)
    })
    .await?;
    let digest = match digest {
        Ok(d) => d,
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            audit.log(&st, &who, "nar.upload", Some(&name), err.status, json!({ "error": err.message, "chunked": true }));
            return Err(err);
        }
    };
    let resp = store_blob(&st, tmp, digest, compression).await?;
    audit.log(
        &st,
        &who,
        "nar.upload",
        Some(&name),
        StatusCode::CREATED,
        json!({ "fileHash": resp.file_hash, "size": resp.file_size, "chunked": true }),
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn abort(State(st): State<Shared>, Path((name, id)): Path<(String, String)>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let who = st.authorize(&headers, &name, Perm::Push)?;
    session(&st, &name, &id, &who)?;
    drop_session(&st, &id);
    Ok(StatusCode::NO_CONTENT)
}
