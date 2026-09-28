use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::client::Client;

/// Daemon-side counters, exported on /metrics.
#[derive(Default)]
pub struct Metrics {
    pub gc_runs: AtomicU64,
    pub gc_evicted_paths: AtomicU64,
    pub gc_freed_bytes: AtomicU64,
    pub gc_last_run: AtomicU64,
    pub scrub_ok: AtomicU64,
    pub scrub_corrupt: AtomicU64,
    pub scrub_missing: AtomicU64,
    pub scrub_bytes: AtomicU64,
    pub scrub_last_complete: AtomicU64,
    pub db_checkpoints: AtomicU64,
    pub db_backups: AtomicU64,
    pub db_last_backup: AtomicU64,
    pub errors_gc: AtomicU64,
    pub errors_scrub: AtomicU64,
    pub errors_db: AtomicU64,
}

pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

pub fn set(counter: &AtomicU64, v: u64) {
    counter.store(v, Ordering::Relaxed);
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub struct Daemon {
    pub client: Client,
    pub data_dir: PathBuf,
    pub metrics: Metrics,
}

/// Free and total bytes of the filesystem holding `path`.
// statvfs fields are c_ulong: the casts matter on 32-bit targets.
#[allow(clippy::unnecessary_cast)]
pub fn disk_space(path: &std::path::Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let frag = s.f_frsize as u64;
    Ok((s.f_bavail as u64 * frag, s.f_blocks as u64 * frag))
}
