//! The substituter read path: `/<cache>/nix-cache-info`,
//! `/<cache>/<hash>.narinfo`, `/<cache>/nar/<file hash>.nar[.zst]` and
//! `/<cache>/build-trace-v2/<drv>/<output>.doi` (or `realisations/<id>.doi`).
//! URLs are parsed by hand, without allocating.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use helios_core::Compression;
use rusqlite::{OptionalExtension, params};

use crate::error::{ApiError, ApiResult};
use crate::state::Locked;
use crate::state::{PathKey, Shared};

const NIX_CACHE_INFO: &str = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n";
const IMMUTABLE: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");
const PRIVATE: HeaderValue = HeaderValue::from_static("private, max-age=3600");
/// Most narinfo requests are misses (Nix asks every substituter about every
/// path). Let proxies cache them briefly; new paths still appear quickly.
const NEGATIVE: HeaderValue = HeaderValue::from_static("public, max-age=60");

enum Route<'a> {
    CacheInfo,
    Narinfo(&'a str),
    Nar(&'a str, Compression),
    /// `build-trace-v2/...` or `realisations/...`
    BuildTrace(&'a str),
}

fn route(rest: &str) -> Option<Route<'_>> {
    if rest == "nix-cache-info" {
        return Some(Route::CacheInfo);
    }
    if rest.starts_with("build-trace-v2/") || rest.starts_with("realisations/") {
        return Some(Route::BuildTrace(rest));
    }
    if let Some(hash) = rest.strip_suffix(".narinfo") {
        return (hash.len() == 32).then_some(Route::Narinfo(hash));
    }
    let file = rest.strip_prefix("nar/")?;
    if let Some(hash) = file.strip_suffix(".nar.zst") {
        return Some(Route::Nar(hash, Compression::Zstd));
    }
    file.strip_suffix(".nar").map(|hash| Route::Nar(hash, Compression::None))
}

fn not_found(cache_control: HeaderValue) -> Response {
    (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, cache_control)], "not found").into_response()
}

pub async fn handle(State(st): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    match serve(st, method, uri, headers).await {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    }
}

async fn serve(st: Shared, method: Method, uri: Uri, headers: HeaderMap) -> ApiResult<Response> {
    if method != Method::GET && method != Method::HEAD {
        return Ok((StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "GET, HEAD")]).into_response());
    }
    let path = uri.path().trim_start_matches('/');
    let Some((name, rest)) = path.split_once('/') else {
        return Ok(not_found(NEGATIVE));
    };
    let Some(route) = route(rest) else {
        return Ok(not_found(NEGATIVE));
    };
    let Some(cache) = st.cache(name) else {
        return Ok(not_found(NEGATIVE));
    };
    st.authorize_read(&headers, name, cache)?;
    let cache_control = if cache.public { IMMUTABLE } else { PRIVATE };

    match route {
        Route::CacheInfo => Ok(([(header::CONTENT_TYPE, "text/x-nix-cache-info")], NIX_CACHE_INFO).into_response()),
        Route::BuildTrace(id) => Ok(match crate::traces::lookup(&st, cache.id, id) {
            Some(body) => {
                ([(header::CONTENT_TYPE, HeaderValue::from_static("application/json")), (header::CACHE_CONTROL, cache_control)], body).into_response()
            }
            None => not_found(if cache.public { NEGATIVE } else { PRIVATE }),
        }),
        Route::Narinfo(hash) => {
            let Some(hash) = helios_core::nix32_decode::<20>(hash) else {
                return Ok(not_found(NEGATIVE));
            };
            let key = PathKey { cache: cache.id, hash };
            if !st.index.rd().contains(&key) {
                st.counters.narinfo_misses.inc();
                return Ok(not_found(if cache.public { NEGATIVE } else { PRIVATE }));
            }
            st.counters.narinfo_hits.inc();
            st.access.touch(key);
            let body = match st.narinfo.get(&key) {
                Some(body) => body,
                None => {
                    let db = st.db.clone();
                    let loaded = tokio::task::spawn_blocking(move || {
                        db.read(|conn| {
                            conn.prepare_cached("SELECT narinfo FROM paths WHERE cache_id = ?1 AND hash = ?2")?
                                .query_row(params![key.cache, &key.hash[..]], |r| r.get::<_, Vec<u8>>(0))
                                .optional()
                        })
                    })
                    .await??;
                    let Some(text) = loaded else {
                        return Ok(not_found(NEGATIVE));
                    };
                    let body = Bytes::from(text);
                    st.narinfo.insert(key, body.clone());
                    body
                }
            };
            Ok(([(header::CONTENT_TYPE, HeaderValue::from_static("text/x-nix-narinfo")), (header::CACHE_CONTROL, cache_control)], body)
                .into_response())
        }
        Route::Nar(hash, compression) => {
            st.counters.nar_requests.inc();
            let Some(file_hash) = helios_core::nix32_decode::<32>(hash) else {
                return Ok(not_found(NEGATIVE));
            };
            let db = st.db.clone();
            let cache_id = cache.id;
            // Content-addressed, but only served from caches that publish it.
            let size = tokio::task::spawn_blocking(move || {
                db.read(|conn| {
                    conn.prepare_cached(
                        "SELECT b.file_size FROM blobs b WHERE b.file_hash = ?1 AND b.compression = ?2
                         AND EXISTS (SELECT 1 FROM paths p WHERE p.blob_id = b.id AND p.cache_id = ?3)",
                    )?
                    .query_row(params![&file_hash[..], compression.as_str(), cache_id], |r| r.get::<_, u64>(0))
                    .optional()
                })
            })
            .await??;
            let Some(size) = size else {
                return Ok(not_found(NEGATIVE));
            };
            nar_response(&st, &file_hash, compression, size, &method, cache_control).await
        }
    }
}

async fn nar_response(
    st: &Shared,
    file_hash: &[u8; 32],
    compression: Compression,
    size: u64,
    method: &Method,
    cache_control: HeaderValue,
) -> ApiResult<Response> {
    let mut builder = Response::builder().header(header::CONTENT_TYPE, "application/x-nix-nar").header(header::CACHE_CONTROL, cache_control);

    if let Some(prefix) = &st.cfg.accel_redirect {
        let name = helios_core::nix32_encode(file_hash);
        let location = format!("{prefix}/{}/{name}{}", &name[..2], compression.extension());
        builder = builder.header("x-accel-redirect", location);
        return builder.body(Body::empty()).map_err(ApiError::internal);
    }

    builder = builder.header(header::CONTENT_LENGTH, size);
    if method == Method::HEAD {
        return builder.body(Body::empty()).map_err(ApiError::internal);
    }
    let file = match tokio::fs::File::open(st.nar_path(file_hash, compression)).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(not_found(NEGATIVE)),
        Err(e) => return Err(ApiError::internal(e)),
    };
    // 512 KiB reads; the stream ends after EOF or the first error.
    let stream = futures_util::stream::unfold(Some(file), |file| async move {
        use tokio::io::AsyncReadExt;
        let mut file = file?;
        let mut buf = bytes::BytesMut::with_capacity(512 * 1024);
        match file.read_buf(&mut buf).await {
            Ok(0) => None,
            Ok(_) => Some((Ok(buf.freeze()), Some(file))),
            Err(e) => Some((Err(e), None)),
        }
    });
    builder.body(Body::from_stream(stream)).map_err(ApiError::internal)
}

/// `GET /_api/v2/caches/{cache}`: what a client needs to substitute from the
/// cache. Readable by whoever can read the cache itself.
pub async fn cache_info(
    State(st): State<Shared>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let cache = st.cache(&name).ok_or_else(ApiError::not_found)?;
    st.authorize_read(&headers, &name, cache)?;
    let public_key = st.signer.as_ref().map(helios_core::Signer::public_key);
    Ok(axum::Json(serde_json::json!({ "name": name, "public": cache.public, "publicKey": public_key })))
}
