//! Build traces ("realisations"): which output path a content-addressed
//! derivation produced, so Nix can substitute CA derivations instead of
//! building them (compare zhaofengli/attic#188).
//!
//! Nix has two formats, and a cache serves whichever its pushers produce:
//!
//! - Nix 2.35 and later: `/<cache>/build-trace-v2/<drv>/<output>.doi`,
//!   keyed by derivation path, with structured signatures.
//! - Before 2.35: `/<cache>/realisations/sha256:<hex>!<output>.doi`, keyed by
//!   the derivation's hash modulo, which only Nix computes.
//!
//! CA derivations are experimental in Nix, and so are both formats.
//!
//! `POST /_api/v2/caches/{cache}/build-traces` takes entries as `nix store
//! build-trace info --json` (or the older `nix realisation info --json`)
//! prints them. Each output path must already be published in the cache.
//! Client signatures are dropped and the entry is signed with the cache's
//! key, as narinfo is; entries are rendered and signed once, at publish
//! time, and served from memory.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::Audit;
use crate::auth::Perm;
use crate::error::{ApiError, ApiResult};
use crate::push::cache_for;
use crate::state::{Locked, PathKey, Shared};

const MAX_ENTRIES: usize = 5_000;

/// An entry's file name without `.doi`: `<drv>/<output>` for the current
/// format, `sha256:<hex>!<output>` for the old one. The two cannot collide.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TraceKey {
    pub cache: u32,
    pub id: Box<str>,
}

pub struct Trace {
    /// The output path, which must still be published for the entry to be
    /// served.
    pub out: PathKey,
    pub body: Bytes,
}

pub type Traces = HashMap<TraceKey, Trace>;

fn out_key(cache: u32, out: &str) -> Option<PathKey> {
    let hash = helios_core::store_basename_valid(out).then(|| helios_core::nix32_decode::<20>(&out[..32])).flatten()?;
    Some(PathKey { cache, hash })
}

pub fn load(conn: &rusqlite::Connection) -> rusqlite::Result<Traces> {
    let mut traces = Traces::new();
    let mut stmt = conn.prepare("SELECT cache_id, id, out_path, body FROM build_traces")?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let cache: u32 = r.get(0)?;
        let (id, out): (String, String) = (r.get(1)?, r.get(2)?);
        if let Some(key) = out_key(cache, &out) {
            traces.insert(TraceKey { cache, id: id.into() }, Trace { out: key, body: Bytes::from(r.get::<_, Vec<u8>>(3)?) });
        }
    }
    Ok(traces)
}

/// Nix output names: the characters of store path names.
fn output_name_valid(s: &str) -> bool {
    (1..=255).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"+-._?=".contains(&c))
}

fn basename(s: &str) -> &str {
    s.strip_prefix("/nix/store/").unwrap_or(s)
}

/// An entry in either format, validated.
enum Parsed {
    /// `<drv basename>`, `<output>`.
    Current(String, String),
    /// `sha256:<hex>!<output>`.
    Legacy(String),
}

impl Parsed {
    fn id(&self) -> String {
        match self {
            Parsed::Current(drv, output) => format!("{drv}/{output}"),
            Parsed::Legacy(id) => id.clone(),
        }
    }
}

fn legacy_id_valid(id: &str) -> bool {
    let Some((hash, output)) = id.split_once('!') else { return false };
    hash.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
        && output_name_valid(output)
}

/// The signed file body. The signature covers what Nix's
/// `UnkeyedRealisation::fingerprint` produces for the format: the entry's
/// JSON with keys sorted and the signatures removed. Every value is limited
/// to store path and hash characters, so no JSON escaping is involved.
fn render(st: &Shared, entry: &Parsed, out: &str) -> Vec<u8> {
    let sign = |fingerprint: String| st.signer.as_ref().map(|s| s.sign(fingerprint.as_bytes()));
    let body = match entry {
        Parsed::Current(drv, output) => {
            let sig = sign(format!(r#"{{"key":{{"drvPath":"{drv}","outputName":"{output}"}},"value":{{"outPath":"{out}"}}}}"#));
            let signatures: Vec<Value> = sig
                .iter()
                .map(|s| {
                    let (name, sig) = s.split_once(':').expect("signatures are name:base64");
                    json!({ "keyName": name, "sig": sig })
                })
                .collect();
            json!({ "outPath": out, "signatures": signatures })
        }
        Parsed::Legacy(id) => {
            let sig = sign(format!(r#"{{"dependentRealisations":{{}},"id":"{id}","outPath":"{out}"}}"#));
            json!({ "dependentRealisations": {}, "id": id, "outPath": out, "signatures": sig.into_iter().collect::<Vec<_>>() })
        }
    };
    serde_json::to_vec(&body).expect("serialisable")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryKey {
    drv_path: String,
    output_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryValue {
    out_path: String,
}

/// `{"key": {...}, "value": {...}}` (Nix 2.35+) or `{"id", "outPath"}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Entry {
    #[serde(rename_all = "camelCase")]
    Current { key: EntryKey, value: EntryValue },
    #[serde(rename_all = "camelCase")]
    Legacy { id: String, out_path: String },
}

#[derive(Deserialize)]
pub struct PublishReq {
    entries: Vec<Entry>,
}

pub async fn publish(
    State(st): State<Shared>,
    Path(name): Path<String>,
    audit: Audit,
    headers: HeaderMap,
    Json(req): Json<PublishReq>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let cache = cache_for(&st, &name)?;
    let who = st.authorize(&headers, &name, Perm::Push)?;
    if req.entries.len() > MAX_ENTRIES {
        return Err(ApiError::bad_request(format!("at most {MAX_ENTRIES} entries per request")));
    }

    let mut rows = Vec::with_capacity(req.entries.len());
    let mut missing = Vec::new();
    {
        let index = st.index.rd();
        for e in &req.entries {
            let (parsed, out) = match e {
                Entry::Current { key, value } => {
                    let drv = basename(&key.drv_path);
                    if !(helios_core::store_basename_valid(drv) && drv.ends_with(".drv")) {
                        return Err(ApiError::bad_request(format!("invalid derivation path: {}", key.drv_path)));
                    }
                    if !output_name_valid(&key.output_name) {
                        return Err(ApiError::bad_request(format!("invalid output name: {}", key.output_name)));
                    }
                    (Parsed::Current(drv.to_owned(), key.output_name.clone()), basename(&value.out_path))
                }
                Entry::Legacy { id, out_path } => {
                    if !legacy_id_valid(id) {
                        return Err(ApiError::bad_request(format!("invalid build trace id: {id}")));
                    }
                    (Parsed::Legacy(id.clone()), basename(out_path))
                }
            };
            let key = out_key(cache.id, out).ok_or_else(|| ApiError::bad_request(format!("invalid output path: {out}")))?;
            if !index.contains(&key) {
                missing.push(format!("/nix/store/{out}"));
                continue;
            }
            // Signed later, off the index lock.
            rows.push((parsed, out.to_owned(), key));
        }
    }
    if !missing.is_empty() {
        return Err(ApiError::new(StatusCode::CONFLICT, "output paths are not published in this cache").with(json!({ "missing": missing })));
    }

    let st2 = st.clone();
    let inserted = tokio::task::spawn_blocking(move || -> ApiResult<Vec<(TraceKey, Trace)>> {
        let rendered: Vec<_> = rows.into_iter().map(|(parsed, out, key)| (parsed.id(), render(&st2, &parsed, &out), out, key)).collect();
        let now = crate::db::now();
        st2.db
            .write(|conn| -> rusqlite::Result<Vec<(TraceKey, Trace)>> {
                let tx = conn.transaction()?;
                let mut inserted = Vec::new();
                {
                    let mut upsert = tx.prepare_cached(
                        "INSERT INTO build_traces (cache_id, id, out_path, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT (cache_id, id) DO UPDATE SET out_path = excluded.out_path, body = excluded.body, created_at = excluded.created_at",
                    )?;
                    let (traces, index) = (st2.traces.rd(), st2.index.rd());
                    for (id, body, out, key) in rendered {
                        let trace_key = TraceKey { cache: cache.id, id: id.as_str().into() };
                        // The first entry for an output wins while its path is
                        // served, so a non-deterministic build cannot flip it;
                        // once that path is gone, a newer build may take over.
                        if traces.get(&trace_key).is_some_and(|t| index.contains(&t.out)) {
                            continue;
                        }
                        upsert.execute(params![cache.id, id, out, body, now])?;
                        inserted.push((trace_key, Trace { out: key, body: body.into() }));
                    }
                }
                tx.commit()?;
                Ok(inserted)
            })
            .map_err(ApiError::from)
    })
    .await??;

    let published = inserted.len();
    {
        let mut traces = st.traces.wr();
        for (k, v) in inserted {
            traces.insert(k, v);
        }
    }
    let already = req.entries.len() - published;
    audit.log(&st, &who, "build_trace.publish", Some(&name), StatusCode::CREATED, json!({ "published": published, "alreadyExisted": already }));
    Ok((StatusCode::CREATED, Json(json!({ "published": published, "alreadyExisted": already }))))
}

/// The body for a request path below the cache, if it names a build trace
/// whose output is still published.
pub fn lookup(st: &Shared, cache: u32, rest: &str) -> Option<Bytes> {
    let (current, id) = match rest.strip_prefix("build-trace-v2/") {
        Some(id) => (true, id),
        None => (false, rest.strip_prefix("realisations/")?),
    };
    let id = id.strip_suffix(".doi")?;
    // Old clients may percent-encode the `:` and `!` of a hash-keyed id.
    let id = if current { id.to_owned() } else { id.replace("%3A", ":").replace("%3a", ":").replace("%21", "!") };
    if current == legacy_id_valid(&id) {
        return None; // Each format only under its own prefix.
    }
    let traces = st.traces.rd();
    let trace = traces.get(&TraceKey { cache, id: id.into() })?;
    st.index.rd().contains(&trace.out).then(|| trace.body.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_ids() {
        let hex = "a".repeat(64);
        assert!(legacy_id_valid(&format!("sha256:{hex}!out")));
        assert!(!legacy_id_valid(&format!("sha256:{hex}")));
        assert!(!legacy_id_valid(&format!("sha1:{hex}!out")));
        assert!(!legacy_id_valid(&format!("sha256:{}!out", "A".repeat(64))));
        assert!(!legacy_id_valid(&format!("sha256:{hex}!bad/name")));
    }

    #[test]
    fn both_entry_shapes_parse() {
        let current: Entry =
            serde_json::from_str(r#"{"key":{"drvPath":"x.drv","outputName":"out"},"value":{"outPath":"y","signatures":[]}}"#).unwrap();
        assert!(matches!(current, Entry::Current { .. }));
        let legacy: Entry = serde_json::from_str(r#"{"id":"sha256:ab!out","outPath":"y","signatures":[],"dependentRealisations":{}}"#).unwrap();
        assert!(matches!(legacy, Entry::Legacy { .. }));
    }
}
