//! Push-on-build. Nix's post-build-hook runs `helios queue-paths`, which
//! drops the built paths into a spool directory and returns at once, so
//! builds never wait on the network. `helios watch-store` drains the spool
//! and pushes each batch's closure, retrying with backoff while the
//! server is unreachable.
//!
//! Spool entries are files of newline-separated store paths, written to a
//! temporary name and renamed into place so readers never see half a file.
//! A batch that fails while the server is reachable is retried one entry
//! at a time, so one bad entry cannot hold up the rest; an entry that keeps
//! failing on its own moves to `failed/` in the spool.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

use crate::api::Client;
use crate::push;

const POLL: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Paths named by one batch (each with its closure); an entry naming more
/// goes alone.
const MAX_BATCH_PATHS: usize = 1_000;
/// Failed pushes of an entry on its own, with the server reachable, before
/// it is set aside.
const MAX_STRIKES: u32 = 5;
const FAILED_DIR: &str = "failed";

fn valid(path: &str) -> bool {
    path.strip_prefix("/nix/store/").is_some_and(helios_core::store_basename_valid)
}

/// Writes `paths` (whitespace-separated, as in $OUT_PATHS) as one spool entry.
pub fn queue(spool: &Path, paths: &str) -> anyhow::Result<usize> {
    let paths: Vec<&str> = paths.split_whitespace().filter(|p| valid(p)).collect();
    if paths.is_empty() {
        return Ok(0);
    }
    std::fs::create_dir_all(spool).with_context(|| format!("creating {}", spool.display()))?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let name = format!("{stamp:020}-{}", std::process::id());
    let tmp = spool.join(format!(".{name}"));
    std::fs::write(&tmp, paths.join("\n") + "\n")?;
    std::fs::rename(&tmp, spool.join(name))?;
    Ok(paths.len())
}

/// Spool entries in arrival order, skipping ones still being written.
fn pending(spool: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(spool) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| !n.starts_with('.')))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    entries.sort();
    Ok(entries)
}

/// Moves an entry out of the queue into `failed/`, for a person to look at.
fn set_aside(spool: &Path, entry: &Path, why: &str) {
    let dir = spool.join(FAILED_DIR);
    let moved = std::fs::create_dir_all(&dir).and_then(|()| std::fs::rename(entry, dir.join(entry.file_name().unwrap_or_default())));
    match moved {
        Ok(()) => tracing::warn!(entry = %entry.display(), to = %dir.display(), "{why}; set the entry aside"),
        Err(e) => tracing::error!(entry = %entry.display(), error = %e, "{why}; could not set the entry aside"),
    }
}

/// The oldest entries and their paths, up to `MAX_BATCH_PATHS` paths (at
/// least one entry). Unreadable entries are set aside.
fn next_batch(spool: &Path, entries: &[PathBuf]) -> Vec<(PathBuf, Vec<String>)> {
    let mut batch = Vec::new();
    let mut count = 0;
    for entry in entries {
        let text = match std::fs::read_to_string(entry) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                set_aside(spool, entry, &format!("unreadable spool entry: {e}"));
                continue;
            }
        };
        let paths: Vec<String> = text.lines().filter(|p| valid(p)).map(str::to_owned).collect();
        if !batch.is_empty() && count + paths.len() > MAX_BATCH_PATHS {
            break;
        }
        count += paths.len();
        batch.push((entry.clone(), paths));
    }
    batch
}

async fn push_paths(client: &Client, cache: &str, paths: impl Iterator<Item = &String>, opts: push::Options) -> anyhow::Result<()> {
    let mut paths: Vec<String> = paths.cloned().collect();
    paths.sort();
    paths.dedup();
    // Paths garbage-collected since they were built cannot be pushed.
    paths.retain(|p| Path::new(p).exists());
    if paths.is_empty() {
        return Ok(());
    }
    push::push(client, cache, &paths, push::Options { closure: true, ..opts }).await
}

/// Whether the server answers this client, so a failure is the entry's
/// fault rather than the network's or the server's.
async fn reachable(client: &Client, cache: &str) -> bool {
    client.missing(cache, &[]).await.is_ok()
}

pub async fn watch(client: &Client, cache: &str, spool: &Path, opts: push::Options) -> anyhow::Result<()> {
    tracing::info!(spool = %spool.display(), cache, "watching for paths to push");
    let mut backoff = POLL;
    let mut strikes: HashMap<PathBuf, u32> = HashMap::new();
    loop {
        let entries = pending(spool)?;
        let batch = next_batch(spool, &entries);
        if batch.is_empty() {
            tokio::time::sleep(POLL).await;
            continue;
        }
        let Err(e) = push_paths(client, cache, batch.iter().flat_map(|(_, p)| p), opts).await else {
            for (entry, _) in &batch {
                let _ = std::fs::remove_file(entry);
                strikes.remove(entry);
            }
            backoff = POLL;
            continue;
        };
        tracing::warn!(entries = batch.len(), error = format!("{e:#}"), "push failed");
        // With the server reachable, find the entries at fault and push the others.
        if reachable(client, cache).await {
            for (entry, paths) in &batch {
                if batch.len() > 1 {
                    match push_paths(client, cache, paths.iter(), opts).await {
                        Ok(()) => {
                            let _ = std::fs::remove_file(entry);
                            strikes.remove(entry);
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(entry = %entry.display(), error = format!("{e:#}"), "push of one entry failed");
                            if !reachable(client, cache).await {
                                break;
                            }
                        }
                    }
                }
                let n = strikes.entry(entry.clone()).or_default();
                *n += 1;
                if *n >= MAX_STRIKES {
                    strikes.remove(entry);
                    set_aside(spool, entry, &format!("push failed {MAX_STRIKES} times"));
                }
            }
        }
        tracing::info!(retry_in = ?backoff, "retrying failed pushes");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_writes_valid_paths_atomically() {
        let dir = std::env::temp_dir().join(format!("helios-spool-{}", helios_core::uuid_v4()));
        let n = queue(&dir, "/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello /etc/passwd\n/nix/store/bad").unwrap();
        assert_eq!(n, 1);
        let entries = pending(&dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(std::fs::read_to_string(&entries[0]).unwrap(), "/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello\n");
        assert_eq!(queue(&dir, "").unwrap(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn batches_are_bounded_and_skip_unreadable_entries() {
        let dir = std::env::temp_dir().join(format!("helios-spool-{}", helios_core::uuid_v4()));
        let path = "/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello";
        let many = vec![path; MAX_BATCH_PATHS].join(" ");
        queue(&dir, path).unwrap();
        // A directory where an entry should be: reading it fails.
        std::fs::create_dir_all(dir.join("00000000000000000000-0")).unwrap();
        queue(&dir, &many).unwrap();
        queue(&dir, path).unwrap();
        let entries = pending(&dir).unwrap();
        assert_eq!(entries.len(), 3, "directories are not entries");
        let mut unreadable = entries.clone();
        unreadable.insert(0, dir.join("00000000000000000000-0"));
        let batch = next_batch(&dir, &unreadable);
        assert_eq!(batch.len(), 1, "the large entry waits for the next batch");
        assert!(dir.join(FAILED_DIR).join("00000000000000000000-0").exists(), "unreadable entry set aside");
        std::fs::remove_file(&batch[0].0).unwrap();
        let batch = next_batch(&dir, &pending(&dir).unwrap());
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1.len(), MAX_BATCH_PATHS);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
