//! Periodic garbage collection: stale temp uploads, unreferenced blobs past
//! a grace period, expired tokens, and old audit log entries. Also flushes
//! recorded narinfo hits to `paths.accessed_at` for LRU eviction.

use std::time::{Duration, SystemTime};

use helios_core::Compression;
use rusqlite::params;

use crate::state::Locked;
use crate::state::Shared;

const TMP_MAX_AGE: Duration = Duration::from_secs(3600);
const BLOB_BATCH: usize = 1000;
const ACCESS_FLUSH: Duration = Duration::from_secs(60);

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcStats {
    pub tmp_files: usize,
    pub blobs: usize,
    pub bytes: u64,
    pub tokens: usize,
    pub audit_rows: usize,
}

pub async fn run_forever(st: Shared) {
    tokio::time::sleep(Duration::from_secs(60)).await;
    let mut interval = tokio::time::interval(st.cfg.gc_interval);
    loop {
        interval.tick().await;
        let st2 = st.clone();
        match tokio::task::spawn_blocking(move || collect(&st2)).await {
            Ok(Ok(stats)) => tracing::info!(?stats, "gc finished"),
            Ok(Err(e)) => tracing::error!(error = %e, "gc failed"),
            Err(e) => tracing::error!(error = %e, "gc panicked"),
        }
    }
}

pub fn collect(st: &Shared) -> anyhow::Result<GcStats> {
    let mut stats = GcStats::default();
    let now = crate::db::now();

    if let Ok(entries) = std::fs::read_dir(st.tmp_dir()) {
        for entry in entries.flatten() {
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() > TMP_MAX_AGE)
                .unwrap_or(false);
            if stale && std::fs::remove_file(entry.path()).is_ok() {
                stats.tmp_files += 1;
            }
        }
    }

    (stats.blobs, stats.bytes) = collect_blobs(st)?;

    stats.tokens = st.db.write(|conn| conn.execute("DELETE FROM tokens WHERE expires_at < ?1", [now]))?;
    st.tokens.wr().retain(|_, t| t.expires_at >= now);

    let audit_cutoff = now - st.cfg.audit_retention.as_secs() as i64;
    stats.audit_rows = st.db.write(|conn| conn.execute("DELETE FROM audit_log WHERE ts < ?1", [audit_cutoff]))?;
    Ok(stats)
}

/// Deletes blobs no path references, once past the upload grace period, so
/// a push that uploads first and publishes afterwards is never raced.
/// Returns (blobs, bytes) removed.
pub fn collect_blobs(st: &Shared) -> anyhow::Result<(usize, u64)> {
    let cutoff = crate::db::now() - st.cfg.upload_grace.as_secs() as i64;
    let (mut total, mut freed) = (0usize, 0u64);
    loop {
        // Row delete and unlink share the writer lock with upload's
        // rename+upsert, so a re-uploaded blob can never lose its file.
        let n = st.db.write(|conn| -> anyhow::Result<usize> {
            let tx = conn.transaction()?;
            let victims: Vec<(i64, Vec<u8>, String, u64)> = {
                let mut stmt = tx.prepare_cached(
                    "SELECT id, file_hash, compression, file_size FROM blobs b WHERE created_at <= ?1
                     AND NOT EXISTS (SELECT 1 FROM paths p WHERE p.blob_id = b.id) LIMIT ?2",
                )?;
                stmt.query_map(params![cutoff, BLOB_BATCH], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<rusqlite::Result<_>>()?
            };
            {
                let mut del = tx.prepare_cached("DELETE FROM blobs WHERE id = ?1")?;
                for (id, ..) in &victims {
                    del.execute([id])?;
                }
            }
            tx.commit()?;
            for (_, hash, compression, size) in &victims {
                let (Ok(hash), Some(compression)) = (<[u8; 32]>::try_from(hash.as_slice()), Compression::parse(compression)) else {
                    continue;
                };
                match std::fs::remove_file(st.nar_path(&hash, compression)) {
                    Ok(()) => freed += size,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!(error = %e, "removing blob file"),
                }
            }
            Ok(victims.len())
        })?;
        total += n;
        if n < BLOB_BATCH {
            return Ok((total, freed));
        }
    }
}

/// Writes recorded narinfo hits to `paths.accessed_at` in one transaction.
pub fn flush_access(st: &Shared) -> rusqlite::Result<usize> {
    let keys = st.access.drain();
    if keys.is_empty() {
        return Ok(0);
    }
    let now = crate::db::now();
    st.db.write(|conn| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("UPDATE paths SET accessed_at = ?1 WHERE cache_id = ?2 AND hash = ?3")?;
            for k in &keys {
                stmt.execute(params![now, k.cache, &k.hash[..]])?;
            }
        }
        tx.commit()?;
        Ok(keys.len())
    })
}

pub async fn run_access_flush(st: Shared) {
    let mut interval = tokio::time::interval(ACCESS_FLUSH);
    loop {
        interval.tick().await;
        let st2 = st.clone();
        match tokio::task::spawn_blocking(move || flush_access(&st2)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "flushing access times"),
            Err(e) => tracing::error!(error = %e, "access flush panicked"),
        }
    }
}
