//! Integrity scrub: re-reads every blob, decompresses and re-hashes it, and
//! compares the file hash, NAR hash and NAR size with the database. A blob
//! that is missing or corrupt is quarantined, which unpublishes its paths
//! so clients never download bad data. Reads are rate limited, and a pass
//! cut short resumes where it stopped.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use helios_core::{Compression, Verifier};
use serde::Deserialize;
use serde_json::json;

use crate::state::{Daemon, add, now, set};

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Blob {
    id: i64,
    file_hash: String,
    compression: String,
    file_size: u64,
    nar_hash: String,
    nar_size: u64,
    path: Option<String>,
}

#[derive(Deserialize)]
struct Page {
    blobs: Vec<Blob>,
}

enum Verdict {
    Ok,
    Missing,
    Corrupt(String),
    /// The file is there but reading it failed (EIO, EACCES): not proof of
    /// corruption, so it is counted and reported rather than quarantined.
    Unreadable(String),
    /// The daemon is shutting down.
    Stopped,
}

/// Holds reads to `rate` bytes per second (0 = unlimited) over a pass.
struct Throttle {
    rate: u64,
    started: Instant,
    bytes: AtomicU64,
}

impl Throttle {
    /// Accounts for `n` bytes read, sleeping until they are due; false
    /// once the daemon is stopping.
    fn take(&self, n: u64, stopping: &AtomicBool) -> bool {
        let total = self.bytes.fetch_add(n, Ordering::Relaxed) + n;
        loop {
            if stopping.load(Ordering::Relaxed) {
                return false;
            }
            if self.rate == 0 {
                return true;
            }
            let due = Duration::from_secs_f64(total as f64 / self.rate as f64);
            match due.checked_sub(self.started.elapsed()) {
                Some(wait) if !wait.is_zero() => std::thread::sleep(wait.min(Duration::from_millis(100))),
                _ => return true,
            }
        }
    }
}

fn check(data_dir: &Path, b: &Blob, throttle: &Throttle, stopping: &AtomicBool) -> anyhow::Result<Verdict> {
    let (Some(rel), Some(compression)) = (&b.path, Compression::parse(&b.compression)) else {
        return Ok(Verdict::Corrupt(format!("unsupported compression {}", b.compression)));
    };
    let mut file = match std::fs::File::open(data_dir.join(rel)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Verdict::Missing),
        Err(e) => return Ok(Verdict::Unreadable(format!("opening: {e}"))),
    };
    let mut v = Verifier::new(compression)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Ok(Verdict::Unreadable(format!("reading: {e}"))),
        };
        if let Err(e) = v.update(&buf[..n]) {
            return Ok(Verdict::Corrupt(format!("undecodable: {e}")));
        }
        if !throttle.take(n as u64, stopping) {
            return Ok(Verdict::Stopped);
        }
    }
    let d = match v.finish() {
        Ok(d) => d,
        Err(e) => return Ok(Verdict::Corrupt(format!("undecodable: {e}"))),
    };
    let problems: Vec<&str> = [
        (d.file_size != b.file_size, "file size"),
        (helios_core::nix32_encode(&d.file_hash) != b.file_hash, "file hash"),
        (helios_core::nix32_encode(&d.nar_hash) != b.nar_hash, "NAR hash"),
        (d.nar_size != b.nar_size, "NAR size"),
    ]
    .into_iter()
    .filter_map(|(bad, what)| bad.then_some(what))
    .collect();
    Ok(if problems.is_empty() { Verdict::Ok } else { Verdict::Corrupt(format!("{} mismatch", problems.join(", "))) })
}

/// The id of the last blob checked in the current pass, so a pass cut
/// short (by a restart, or a server that stayed away) resumes where it
/// stopped. Kept in the state directory when there is one.
static CURSOR: AtomicI64 = AtomicI64::new(0);
const CURSOR_FILE: &str = "scrub-cursor";

fn load_cursor(d: &Daemon) -> i64 {
    let Some(dir) = &d.state_dir else { return CURSOR.load(Ordering::Relaxed) };
    match std::fs::read_to_string(dir.join(CURSOR_FILE)) {
        Ok(text) => text.trim().parse().unwrap_or(0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            tracing::warn!(error = %e, "reading the scrub position failed; starting over");
            0
        }
    }
}

fn save_cursor(d: &Daemon, id: i64) {
    CURSOR.store(id, Ordering::Relaxed);
    let Some(dir) = &d.state_dir else { return };
    let tmp = dir.join(format!(".{CURSOR_FILE}"));
    if let Err(e) = std::fs::write(&tmp, format!("{id}\n")).and_then(|()| std::fs::rename(&tmp, dir.join(CURSOR_FILE))) {
        tracing::warn!(error = %e, dir = %dir.display(), "saving the scrub position failed");
    }
}

/// Whether a pass was cut short and should resume now rather than after a
/// full interval.
pub fn resuming(d: &Daemon) -> bool {
    load_cursor(d) > 0
}

/// Retries `f` through a short server outage (a restart) before giving up.
async fn retrying<T, F, Fut>(what: &str, mut f: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let mut delay = Duration::from_secs(2);
    for attempt in 1.. {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < ATTEMPTS => {
                tracing::warn!(error = format!("{e:#}"), retry_in = ?delay, "{what} failed");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

const ATTEMPTS: u32 = 5;
const SAVE_EVERY: Duration = Duration::from_secs(10);

/// One full pass over every blob, resuming one cut short. `rate` is bytes
/// per second (0 = unlimited).
pub async fn run(d: &Daemon, rate: u64) -> anyhow::Result<()> {
    let started = Instant::now();
    let throttle = Arc::new(Throttle { rate, started, bytes: AtomicU64::new(0) });
    let mut after = load_cursor(d);
    if after > 0 {
        tracing::info!(after, "resuming the scrub");
    }
    let (mut bytes, mut blobs, mut saved) = (0u64, 0u64, Instant::now());
    loop {
        let path = format!("/v1/blobs?after={after}&limit=500");
        let page: Page = retrying("listing blobs", || d.client.get(&path)).await?;
        if page.blobs.is_empty() {
            break;
        }
        for b in page.blobs {
            let (dir, blob, throttle, stopping) = (d.data_dir.clone(), b.clone(), throttle.clone(), d.stopping.clone());
            let verdict = tokio::task::spawn_blocking(move || check(&dir, &blob, &throttle, &stopping)).await??;
            let reason = match verdict {
                Verdict::Stopped => return Ok(()),
                Verdict::Ok => {
                    add(&d.metrics.scrub_ok, 1);
                    None
                }
                Verdict::Missing => {
                    add(&d.metrics.scrub_missing, 1);
                    Some("file missing".to_owned())
                }
                Verdict::Corrupt(why) => {
                    add(&d.metrics.scrub_corrupt, 1);
                    Some(why)
                }
                Verdict::Unreadable(why) => {
                    add(&d.metrics.scrub_unreadable, 1);
                    tracing::warn!(blob = %b.file_hash, reason = %why, "unreadable blob, skipping");
                    None
                }
            };
            blobs += 1;
            bytes += b.file_size;
            add(&d.metrics.scrub_bytes, b.file_size);
            if let Some(reason) = reason {
                tracing::error!(blob = %b.file_hash, %reason, "bad blob, quarantining");
                let body = json!({ "fileHash": b.file_hash, "reason": reason });
                // A blob GC removed since it was listed is already gone.
                retrying("quarantining", || async {
                    match d.client.post::<serde_json::Value>("/v1/quarantine", body.clone()).await {
                        Err(e) if e.to_string().contains("404") => Ok(()),
                        r => r.map(drop),
                    }
                })
                .await?;
            }
            after = b.id;
            if saved.elapsed() >= SAVE_EVERY {
                save_cursor(d, after);
                saved = Instant::now();
            }
        }
        save_cursor(d, after);
    }
    save_cursor(d, 0);
    set(&d.metrics.scrub_last_complete, now());
    tracing::info!(blobs, bytes, elapsed = ?started.elapsed(), "scrub finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(path: &str) -> Blob {
        Blob {
            id: 1,
            file_hash: String::new(),
            compression: "zstd".into(),
            file_size: 0,
            nar_hash: String::new(),
            nar_size: 0,
            path: Some(path.into()),
        }
    }

    #[test]
    fn read_errors_are_not_corruption() {
        let dir = std::env::temp_dir().join(format!("helios-scrub-{}", helios_core::uuid_v4()));
        std::fs::create_dir_all(dir.join("nar")).unwrap();
        let throttle = Throttle { rate: 0, started: Instant::now(), bytes: AtomicU64::new(0) };
        let stopping = AtomicBool::new(false);
        // Reading a directory fails with EISDIR.
        assert!(matches!(check(&dir, &blob("nar"), &throttle, &stopping).unwrap(), Verdict::Unreadable(_)));
        assert!(matches!(check(&dir, &blob("gone"), &throttle, &stopping).unwrap(), Verdict::Missing));
        std::fs::write(dir.join("junk"), b"not zstd").unwrap();
        assert!(matches!(check(&dir, &blob("junk"), &throttle, &stopping).unwrap(), Verdict::Corrupt(_)));
        stopping.store(true, Ordering::Relaxed);
        assert!(!throttle.take(1, &stopping));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_scrub_position_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("helios-scrub-{}", helios_core::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = Daemon {
            client: crate::client::Client::new(dir.join("sock")),
            data_dir: dir.clone(),
            state_dir: Some(dir.clone()),
            metrics: Default::default(),
            stopping: Default::default(),
        };
        assert!(!resuming(&d));
        save_cursor(&d, 42);
        CURSOR.store(0, Ordering::Relaxed);
        assert_eq!(load_cursor(&d), 42);
        assert!(resuming(&d));
        save_cursor(&d, 0);
        assert!(!resuming(&d));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
