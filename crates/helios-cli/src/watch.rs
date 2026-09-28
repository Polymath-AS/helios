//! Push-on-build. Nix's post-build-hook runs `helios queue-paths`, which
//! drops the built paths into a spool directory and returns at once, so
//! builds never wait on the network. `helios watch-store` drains the spool
//! and pushes each batch's closure, retrying with backoff while the
//! server is unreachable.
//!
//! Spool entries are files of newline-separated store paths, written to a
//! temporary name and renamed into place so readers never see half a file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

use crate::api::Client;
use crate::push;

const POLL: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

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
        Ok(rd) => rd.flatten().map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| !n.starts_with('.'))).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    entries.sort();
    Ok(entries)
}

pub async fn watch(client: &Client, cache: &str, spool: &Path, opts: push::Options) -> anyhow::Result<()> {
    eprintln!("watching {} for paths to push to '{cache}'", spool.display());
    let mut backoff = POLL;
    loop {
        let entries = pending(spool)?;
        if entries.is_empty() {
            tokio::time::sleep(POLL).await;
            continue;
        }
        let mut paths: Vec<String> = Vec::new();
        for e in &entries {
            let text = std::fs::read_to_string(e).unwrap_or_default();
            paths.extend(text.lines().filter(|p| valid(p)).map(str::to_owned));
        }
        paths.sort();
        paths.dedup();
        // Paths garbage-collected since they were built cannot be pushed.
        paths.retain(|p| Path::new(p).exists());
        let result = if paths.is_empty() { Ok(()) } else { push::push(client, cache, &paths, push::Options { closure: true, ..opts }).await };
        match result {
            Ok(()) => {
                for e in &entries {
                    let _ = std::fs::remove_file(e);
                }
                backoff = POLL;
            }
            Err(e) => {
                eprintln!("push failed, retrying in {}s: {e:#}", backoff.as_secs());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
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
}
