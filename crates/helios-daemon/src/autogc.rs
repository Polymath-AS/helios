//! Keeps the cache under a byte quota (and optionally the disk above a
//! free-space floor) by evicting least-recently-used paths.
//!
//! Eviction starts above the high watermark and stops at the low one, so
//! it runs in occasional batches rather than on every upload.

use serde::Deserialize;
use serde_json::json;

use crate::log;
use crate::state::{Daemon, add, now, set};

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Target NAR bytes; 0 disables the quota.
    pub quota: u64,
    pub high: f64,
    pub low: f64,
    /// Keep at least this much free on the data filesystem; 0 disables.
    pub min_free: u64,
}

#[derive(Deserialize)]
struct Stats {
    blobs: Blobs,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Blobs {
    bytes: u64,
    /// NARs no path uses any more; GC deletes them once their upload
    /// grace period ends, so they no longer count against the quota.
    unreferenced_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Candidate {
    cache: u32,
    hash: String,
    nar_bytes: u64,
}

#[derive(Deserialize)]
struct Lru {
    paths: Vec<Candidate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Evicted {
    evicted: u64,
    freed_bytes: u64,
}

/// Bytes to free now, or 0 when within policy.
pub fn to_free(policy: &Policy, used: u64, free_disk: u64) -> u64 {
    let over_quota =
        if policy.quota > 0 && used as f64 > policy.quota as f64 * policy.high { used - (policy.quota as f64 * policy.low) as u64 } else { 0 };
    let short_disk = if policy.min_free > 0 && free_disk < policy.min_free {
        // Overshoot a little so the next upload does not trigger it again.
        (policy.min_free as f64 * 1.1) as u64 - free_disk
    } else {
        0
    };
    over_quota.max(short_disk)
}

/// Upper bound on eviction rounds per run, as a backstop.
const MAX_ROUNDS: usize = 10_000;

/// Referenced NAR bytes and bytes to free, from fresh server stats.
async fn measure(d: &Daemon, policy: &Policy) -> anyhow::Result<(u64, u64)> {
    let stats: Stats = d.client.get("/v1/stats").await?;
    let referenced = stats.blobs.bytes.saturating_sub(stats.blobs.unreferenced_bytes);
    let free_disk = crate::state::disk_space(&d.data_dir).map(|(free, _)| free).unwrap_or(u64::MAX);
    // Unreferenced NARs will be deleted soon; count them as free already.
    let free_soon = free_disk.saturating_add(stats.blobs.unreferenced_bytes);
    Ok((referenced, to_free(policy, referenced, free_soon)))
}

pub async fn run(d: &Daemon, policy: &Policy) -> anyhow::Result<()> {
    add(&d.metrics.gc_runs, 1);
    set(&d.metrics.gc_last_run, now());
    let (referenced, mut need) = measure(d, policy).await?;
    if need == 0 {
        return Ok(());
    }
    log::info!("auto-gc: {referenced} bytes of NARs in use, freeing {need}");
    let (mut evicted, mut freed) = (0u64, 0u64);
    for _ in 0..MAX_ROUNDS {
        let lru: Lru = d.client.get("/v1/lru?limit=500").await?;
        // Enough of the oldest paths to cover what is left, by NAR size.
        let mut batch = Vec::new();
        let mut planned = 0u64;
        for c in lru.paths {
            planned += c.nar_bytes;
            batch.push(json!({ "cache": c.cache, "hash": c.hash }));
            if planned >= need {
                break;
            }
        }
        if batch.is_empty() {
            break;
        }
        let r: Evicted = d.client.post("/v1/evict", json!({ "paths": batch })).await?;
        if r.evicted == 0 {
            break;
        }
        evicted += r.evicted;
        freed += r.freed_bytes;
        // NARs shared with paths still in use stay; re-measure rather than
        // trusting the plan.
        need = measure(d, policy).await?.1;
        if need == 0 {
            break;
        }
    }
    add(&d.metrics.gc_evicted_paths, evicted);
    add(&d.metrics.gc_freed_bytes, freed);
    log::info!("auto-gc: evicted {evicted} paths, {freed} bytes deleted now (the rest after the upload grace period)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn watermarks() {
        let p = Policy { quota: 100 * GIB, high: 0.9, low: 0.8, min_free: 0 };
        assert_eq!(to_free(&p, 89 * GIB, u64::MAX), 0);
        assert_eq!(to_free(&p, 95 * GIB, u64::MAX), 15 * GIB);
    }

    #[test]
    fn free_space_floor() {
        let p = Policy { quota: 0, high: 0.9, low: 0.8, min_free: 10 * GIB };
        assert_eq!(to_free(&p, 1, 20 * GIB), 0);
        assert_eq!(to_free(&p, 1, 5 * GIB), 6 * GIB);
    }
}
