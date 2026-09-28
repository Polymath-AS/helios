//! Pins: store paths auto-GC must not evict, with their closures in the
//! cache. A pinned system is no use without its dependencies, so a pin
//! protects everything it references, directly or not, including
//! dependencies pushed after the pin.
//!
//! - `GET    /_api/v2/caches/{cache}/pins` (pull)
//! - `POST   /_api/v2/caches/{cache}/pins` `{"storePaths": [...]}` (push)
//! - `DELETE /_api/v2/caches/{cache}/pins/{store path basename}` (push)
//!
//! Pins only hold back eviction. A path the integrity scrub finds corrupt
//! is still unpublished.

use std::collections::HashSet;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::Audit;
use crate::auth::Perm;
use crate::error::{ApiError, ApiResult};
use crate::push::cache_for;
use crate::state::{Locked, PathKey, Shared};

const MAX_PINS_PER_REQUEST: usize = 1000;
/// Each eviction walks every pinned closure under the writer lock.
const MAX_PINS_PER_CACHE: i64 = 10_000;

/// `/nix/store/<hash>-<name>` or its basename, as (hash, basename).
fn parse_path(s: &str) -> Option<([u8; 20], &str)> {
    let base = s.strip_prefix("/nix/store/").unwrap_or(s);
    if !helios_core::store_basename_valid(base) {
        return None;
    }
    Some((helios_core::nix32_decode::<20>(&base[..32])?, base))
}

/// Every path a pin protects: pinned paths and their closures, following
/// the References of each narinfo within its cache.
pub fn protected(conn: &Connection) -> rusqlite::Result<HashSet<PathKey>> {
    let mut seen = HashSet::new();
    let mut todo: Vec<PathKey> = conn
        .prepare_cached("SELECT cache_id, hash FROM pins")?
        .query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)))?
        .filter_map(|row| row.ok().and_then(|(cache, hash)| Some(PathKey { cache, hash: hash.try_into().ok()? })))
        .collect();
    let mut narinfo = conn.prepare_cached("SELECT narinfo FROM paths WHERE cache_id = ?1 AND hash = ?2")?;
    while let Some(key) = todo.pop() {
        if !seen.insert(key) {
            continue;
        }
        let text: Option<Vec<u8>> = match narinfo.query_row(params![key.cache, &key.hash[..]], |r| r.get(0)) {
            Ok(t) => Some(t),
            Err(rusqlite::Error::QueryReturnedNoRows) => None, // Pinned before it was pushed.
            Err(e) => return Err(e),
        };
        let Some(text) = text else { continue };
        let refs = std::str::from_utf8(&text).unwrap_or("").lines().find_map(|l| l.strip_prefix("References:")).unwrap_or("");
        for r in refs.split_ascii_whitespace() {
            if let Some((hash, _)) = parse_path(r) {
                todo.push(PathKey { cache: key.cache, hash });
            }
        }
    }
    Ok(seen)
}

pub async fn list(State(st): State<Shared>, Path(name): Path<String>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let cache = cache_for(&st, &name)?;
    st.authorize(&headers, &name, Perm::Pull)?;
    let pins = tokio::task::spawn_blocking(move || {
        st.db.read(|conn| {
            conn.prepare_cached("SELECT store_path, created_at, created_by FROM pins WHERE cache_id = ?1 ORDER BY store_path")?
                .query_map([cache.id], |r| {
                    Ok(json!({ "storePath": format!("/nix/store/{}", r.get::<_, String>(0)?), "createdAt": r.get::<_, i64>(1)?, "createdBy": r.get::<_, String>(2)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    })
    .await??;
    Ok(Json(json!({ "pins": pins })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddReq {
    store_paths: Vec<String>,
}

pub async fn add(
    State(st): State<Shared>,
    Path(name): Path<String>,
    audit: Audit,
    headers: HeaderMap,
    Json(req): Json<AddReq>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let cache = cache_for(&st, &name)?;
    let who = st.authorize(&headers, &name, Perm::Push)?;
    if req.store_paths.is_empty() || req.store_paths.len() > MAX_PINS_PER_REQUEST {
        return Err(ApiError::bad_request(format!("storePaths must hold 1-{MAX_PINS_PER_REQUEST} store paths")));
    }
    let parsed: Vec<([u8; 20], String)> = req
        .store_paths
        .iter()
        .map(|p| parse_path(p).map(|(h, base)| (h, base.to_owned())).ok_or_else(|| ApiError::bad_request(format!("invalid store path: {p}"))))
        .collect::<ApiResult<_>>()?;
    // Only published paths: a pin stops at what the cache lacks, so pinning
    // ahead of the push would protect less than it seems to.
    let missing: Vec<String> = {
        let index = st.index.rd();
        parsed.iter().filter(|(hash, _)| !index.contains(&PathKey { cache: cache.id, hash: *hash })).map(|(_, b)| format!("/nix/store/{b}")).collect()
    };
    if !missing.is_empty() {
        return Err(
            ApiError::new(StatusCode::CONFLICT, "pin paths after pushing them; these are not in the cache").with(json!({ "missing": missing }))
        );
    }
    let actor = who.actor().to_owned();
    let st2 = st.clone();
    let added = tokio::task::spawn_blocking(move || {
        st2.db.write(|conn| -> ApiResult<usize> {
            let tx = conn.transaction()?;
            let pinned: i64 = tx.query_row("SELECT count(*) FROM pins WHERE cache_id = ?1", [cache.id], |r| r.get(0))?;
            if pinned + parsed.len() as i64 > MAX_PINS_PER_CACHE {
                return Err(ApiError::bad_request(format!("a cache holds at most {MAX_PINS_PER_CACHE} pins; it has {pinned}")));
            }
            let mut n = 0;
            {
                let mut insert = tx.prepare_cached(
                    "INSERT INTO pins (cache_id, hash, store_path, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (cache_id, hash) DO NOTHING",
                )?;
                for (hash, base) in &parsed {
                    n += insert.execute(params![cache.id, &hash[..], base, crate::db::now(), actor])?;
                }
            }
            tx.commit()?;
            Ok(n)
        })
    })
    .await??;
    audit.log(&st, &who, "pin.add", Some(&name), StatusCode::CREATED, json!({ "pinned": added, "requested": req.store_paths.len() }));
    Ok((StatusCode::CREATED, Json(json!({ "pinned": added, "alreadyPinned": req.store_paths.len() - added }))))
}

pub async fn remove(
    State(st): State<Shared>,
    Path((name, path)): Path<(String, String)>,
    audit: Audit,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let cache = cache_for(&st, &name)?;
    let who = st.authorize(&headers, &name, Perm::Push)?;
    let (hash, _) = parse_path(&path).ok_or_else(|| ApiError::bad_request(format!("invalid store path: {path}")))?;
    let st2 = st.clone();
    let removed = tokio::task::spawn_blocking(move || {
        st2.db.write(|conn| conn.execute("DELETE FROM pins WHERE cache_id = ?1 AND hash = ?2", params![cache.id, &hash[..]]))
    })
    .await??;
    if removed == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not pinned"));
    }
    audit.log(&st, &who, "pin.remove", Some(&name), StatusCode::OK, json!({ "storePath": path }));
    Ok(Json(json!({ "unpinned": removed })))
}
