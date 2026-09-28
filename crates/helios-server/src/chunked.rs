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
//! NAR again. A session idle for an hour is dropped with its file; until
//! then, GC leaves the file alone.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

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
/// Per token, so one client cannot take every slot.
const MAX_SESSIONS_PER_ACTOR: usize = 32;
const IDLE_TIMEOUT_SECS: i64 = 3600;
const FILE_PREFIX: &str = "upload-";

pub struct Session {
    cache: Box<str>,
    actor: String,
    compression: Compression,
    tmp: PathBuf,
    /// Bytes appended so far; read without waiting for a chunk in progress.
    offset: AtomicU64,
    /// Unix time of the last request.
    touched: AtomicI64,
    io: Mutex<Io>,
}

struct Io {
    file: std::fs::File,
    /// `None` once the stream is found invalid or the upload is finished.
    verifier: Option<Verifier>,
}

impl Session {
    fn idle(&self, now: i64) -> bool {
        now - self.touched.load(Ordering::Relaxed) > IDLE_TIMEOUT_SECS
    }
}

pub type Sessions = Mutex<std::collections::HashMap<Box<str>, Arc<Session>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn query<'a>(uri: &'a Uri, key: &str) -> Option<&'a str> {
    uri.query()?.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "upload not found; it expired or the server restarted, so start the NAR again")
}

/// Drops idle sessions and their files. Returns how many.
pub fn expire(st: &Shared) -> usize {
    let now = crate::db::now();
    let expired: Vec<Arc<Session>> = {
        let mut sessions = lock(&st.uploads);
        let ids: Vec<Box<str>> = sessions.iter().filter(|(_, s)| s.idle(now)).map(|(id, _)| id.clone()).collect();
        ids.iter().filter_map(|id| sessions.remove(id)).collect()
    };
    for s in &expired {
        let _ = std::fs::remove_file(&s.tmp);
    }
    expired.len()
}

/// Whether a file in the tmp directory belongs to a live upload, which GC
/// must leave alone however old its mtime.
pub fn is_live(st: &Shared, file_name: &str) -> bool {
    file_name.strip_prefix(FILE_PREFIX).is_some_and(|id| lock(&st.uploads).contains_key(id))
}

/// The session `id`, if it belongs to `cache` and to whoever is asking and
/// has not gone idle.
fn session(st: &Shared, cache: &str, id: &str, who: &Identity) -> ApiResult<Arc<Session>> {
    let s = lock(&st.uploads).get(id).cloned().ok_or_else(not_found)?;
    if &*s.cache != cache || s.actor != who.actor() {
        return Err(not_found());
    }
    let now = crate::db::now();
    if s.idle(now) {
        drop_session(st, id);
        return Err(not_found());
    }
    s.touched.store(now, Ordering::Relaxed);
    Ok(s)
}

fn drop_session(st: &Shared, id: &str) {
    if let Some(s) = lock(&st.uploads).remove(id) {
        let _ = std::fs::remove_file(&s.tmp);
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
    expire(&st);
    {
        let sessions = lock(&st.uploads);
        if sessions.len() >= MAX_SESSIONS {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "too many uploads in progress"));
        }
        if sessions.values().filter(|s| s.actor == who.actor()).count() >= MAX_SESSIONS_PER_ACTOR {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                format!("at most {MAX_SESSIONS_PER_ACTOR} uploads in progress per token; complete or abandon one"),
            ));
        }
    }

    let id = helios_core::uuid_v4();
    let tmp = st.tmp_dir().join(format!("{FILE_PREFIX}{id}"));
    let verifier = Verifier::new(compression).map_err(ApiError::internal)?;
    let file = tokio::task::spawn_blocking({
        let tmp = tmp.clone();
        move || std::fs::File::create_new(tmp)
    })
    .await?
    .map_err(ApiError::internal)?;
    let new = Session {
        cache: name.into(),
        actor: who.actor().to_owned(),
        compression,
        tmp,
        offset: AtomicU64::new(0),
        touched: AtomicI64::new(crate::db::now()),
        io: Mutex::new(Io { file, verifier: Some(verifier) }),
    };
    lock(&st.uploads).insert(id.as_str().into(), Arc::new(new));
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
        let mut io = lock(&s.io);
        let io = &mut *io;
        let offset = s.offset.load(Ordering::Acquire);
        if at != offset {
            return Err(ApiError::new(StatusCode::CONFLICT, "offset mismatch").with(json!({ "offset": offset })));
        }
        if offset + body.len() as u64 > max {
            return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "upload too large"));
        }
        let verifier = io.verifier.as_mut().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "upload is completing or was abandoned"))?;
        if let Err(e) = verifier.update(&body) {
            io.verifier = None;
            return Err(ApiError::bad_request(format!("invalid NAR stream: {e}")));
        }
        // A short write leaves the file ahead of the offset; later chunks
        // would then land in the wrong place, so give up on the upload.
        if let Err(e) = io.file.write_all(&body) {
            io.verifier = None;
            return Err(ApiError::internal(e));
        }
        let offset = offset + body.len() as u64;
        s.offset.store(offset, Ordering::Release);
        Ok(offset)
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
    Ok(Json(json!({ "offset": s.offset.load(Ordering::Acquire) })))
}

pub async fn complete(
    State(st): State<Shared>,
    Path((name, id)): Path<(String, String)>,
    audit: Audit,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<UploadResp>)> {
    let cache_id = cache_for(&st, &name)?.id;
    let who = st.authorize(&headers, &name, Perm::Push)?;
    let s = session(&st, &name, &id, &who)?;
    // Taken out of the map first, so a concurrent chunk cannot extend it.
    lock(&st.uploads).remove(id.as_str());
    let (tmp, compression) = (s.tmp.clone(), s.compression);
    let digest = tokio::task::spawn_blocking(move || {
        let mut io = lock(&s.io);
        match io.verifier.take() {
            Some(v) => v.finish().map_err(|e| ApiError::bad_request(format!("invalid NAR stream: {e}"))),
            None => Err(ApiError::bad_request("upload is no longer accepting data")),
        }
        .and_then(|d| io.file.sync_data().map(|()| d).map_err(ApiError::internal))
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
    let resp = store_blob(&st, cache_id, tmp, digest, compression).await?;
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
